// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! An example showing how a TURN client can be implemented.
//!
//! ## Requirements
//!  - A TURN server e.g. [coturn](https://github.com/coturn/coturn)
//!  - A peer to send data to e.g `netcat`
//!
//! ## Example
//!
//! Shell 1 (`netcat`):
//! ```sh
//! # listen for udp data on the specified address and port. Once the first packet is received by
//! # `nc`, data can be sent back to the TURN server which will be displayed in this example in Shell 3.
//! $ nc -lu 127.0.0.1 9100
//! # or
//! $ nc -lu ::1 9100
//! ```
//!
//! Shell 2 (`coturn`)
//! ```sh
//! # only needs to be completed once to add the relevant TURN username and password
//! turnadmin \
//!   --userdb userdb.sqlite \
//!   --add \
//!   --user coturn \
//!   --realm realm \
//!   --password password
//! # Do not use in production, adapt for your use case
//! turnserver \
//!   --user not-important \
//!   --cli-password not-important \
//!   --realm realm \
//!   --lt-cred-mech \
//!   --userdb userdb.sqlite \
//!   -v \
//!   --allow-loopback-peers \
//!   --listening-ip 127.0.0.1 \
//!   --listening-ip '[::1]' \
//!   --relay-ip 127.0.0.1 \
//!   --relay-ip '[::1]'
//! ```
//!
//! Shell 3 (this example)
//! ```sh
//! ./turn \
//!   --transport udp \
//!   --server 127.0.0.1:3478 \
//!   --user coturn \
//!   --password password \
//!   --peer 127.0.0.1:9100 \
//!   --count 2
//!   --delay 5
//! ```

#![cfg(not(tarpaulin))]

use rustls::pki_types::ServerName;
use rustls::ClientConfig;
use rustls_platform_verifier::ConfigVerifierExt;
use turn_client_proto::api::TcpConnectError;
use turn_client_proto::client::TurnClient;
use turn_client_proto::openssl::TurnClientOpensslTls;
use turn_client_proto::prelude::*;
use turn_client_proto::rustls::TurnClientRustls;
use turn_client_proto::tcp::TurnClientTcp;
use turn_client_proto::types::TurnCredentials;
use turn_client_proto::udp::{
    CreatePermissionError, SendError, TurnClientUdp, TurnEvent, TurnPollRet, TurnRecvRet,
};

use stun_proto::agent::Transmit;
use turn_types::stun::data::Data;
use turn_types::stun::TransportType;
use turn_types::AddressFamily;

use clap::{Parser, ValueEnum};

use sans_io_time::Instant;
use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::mpsc::SyncSender;
use std::sync::{Arc, Condvar, Mutex};

use std::net::UdpSocket;

use tracing::error;

fn init_logs() {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::Layer;

    let level_filter = std::env::var("TURN_LOG")
        .ok()
        .and_then(|var| var.parse::<tracing_subscriber::filter::Targets>().ok())
        .unwrap_or(tracing_subscriber::filter::Targets::new().with_default(tracing::Level::ERROR));
    let registry = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_file(true)
            .with_line_number(true)
            .with_level(true)
            .with_target(false)
            .with_test_writer()
            .with_filter(level_filter),
    );
    tracing::subscriber::set_global_default(registry).unwrap();
}

trait Client<T: AsRef<[u8]> + std::fmt::Debug> {
    fn close(&self);
    fn create_permission(
        &self,
        transport: TransportType,
        peer_addr: IpAddr,
    ) -> Result<(), CreatePermissionError>;
    fn send(
        &self,
        transport: TransportType,
        peer_addr: SocketAddr,
        data: T,
    ) -> Result<(), SendError>;
    fn tcp_connect(&self, peer_addr: SocketAddr) -> Result<(), TcpConnectError>;
}

#[derive(Clone, Debug)]
struct ClientUdp {
    base_instant: std::time::Instant,
    socket: Arc<UdpSocket>,
    inner: Arc<(Mutex<TurnClient>, Condvar)>,
}

fn udp_recv_thread(
    base_instant: std::time::Instant,
    socket: Arc<UdpSocket>,
    inner: Arc<(Mutex<TurnClient>, Condvar)>,
) {
    std::thread::spawn(move || loop {
        let mut data = [0; 2048];
        let Ok((size, from)) = socket.recv_from(&mut data) else {
            break;
        };
        {
            let mut client = inner.0.lock().unwrap();
            let now = Instant::from_std(base_instant);
            let ret = client.recv(
                Transmit::new(
                    &data[..size],
                    TransportType::Udp,
                    from,
                    socket.local_addr().unwrap(),
                ),
                now,
            );
            match ret {
                TurnRecvRet::Ignored(_) => continue,
                TurnRecvRet::Handled => {
                    inner.1.notify_one();
                    continue;
                }
                TurnRecvRet::PeerData(peer_data) => {
                    let data = peer_data.data();
                    let len = data.len();
                    let s = match std::str::from_utf8(data) {
                        Ok(s) => s.to_string(),
                        Err(_e) => format!("{:x?}", data),
                    };
                    println!(
                        "received {len} bytes from {:?} using {:?}: {s:?}",
                        peer_data.peer, peer_data.transport
                    );
                    continue;
                }
                TurnRecvRet::PeerIcmp {
                    transport,
                    peer,
                    icmp_type,
                    icmp_code,
                    icmp_data,
                } => {
                    println!(
                        "received ICMP type {icmp_type} code {icmp_code} data {icmp_data} from {peer:?} using {transport:?}",
                    );
                    continue;
                }
            }
        }
    });
}

fn udp_send_thread(
    base_instant: std::time::Instant,
    socket: Arc<UdpSocket>,
    events_sender: SyncSender<TurnEvent>,
    inner: Arc<(Mutex<TurnClient>, Condvar)>,
) {
    std::thread::spawn(move || loop {
        let now = Instant::from_std(base_instant);
        let mut client = inner.0.lock().unwrap();
        let lowest_wait = match client.poll(now) {
            TurnPollRet::WaitUntil(wait) => wait,
            TurnPollRet::Closed => {
                break;
            }
            TurnPollRet::TcpClose {
                local_addr: _,
                remote_addr: _,
            }
            | TurnPollRet::AllocateTcpSocket {
                id: _,
                socket: _,
                peer_addr: _,
            } => {
                // UDP connections to the TURN server cannot create TCP allocations/sockets.
                unreachable!();
            }
        };

        if let Some(event) = client.poll_event() {
            events_sender.send(event).unwrap();
        }
        let mut sent = false;
        while let Some(transmit) = client.poll_transmit(now) {
            sent = true;
            socket.send_to(&transmit.data, transmit.to).unwrap();
        }
        if sent {
            continue;
        }
        let _ = inner.1.wait_timeout(client, lowest_wait - now);
    });
}

impl ClientUdp {
    fn new(
        socket: UdpSocket,
        to: SocketAddr,
        credentials: TurnCredentials,
        allocation_families: &[AddressFamily],
        events_sender: SyncSender<TurnEvent>,
    ) -> Self {
        let base_instant = std::time::Instant::now();
        let local_addr = socket.local_addr().unwrap();
        let client = TurnClientUdp::allocate(local_addr, to, credentials, allocation_families);
        let inner = Arc::new((Mutex::new(client.into()), Condvar::new()));
        let socket = Arc::new(socket);

        udp_recv_thread(base_instant, socket.clone(), inner.clone());
        udp_send_thread(base_instant, socket.clone(), events_sender, inner.clone());

        Self {
            base_instant,
            socket,
            inner,
        }
    }

    fn new_openssl(
        socket: UdpSocket,
        to: SocketAddr,
        credentials: TurnCredentials,
        allocation_families: &[AddressFamily],
        events_sender: SyncSender<TurnEvent>,
        insecure_tls: bool,
    ) -> Self {
        let base_instant = std::time::Instant::now();
        let local_addr = socket.local_addr().unwrap();
        let remote_addr = to;
        let mut ssl_context =
            openssl::ssl::SslContext::builder(openssl::ssl::SslMethod::dtls_client()).unwrap();
        if insecure_tls {
            ssl_context.set_verify_callback(
                openssl::ssl::SslVerifyMode::FAIL_IF_NO_PEER_CERT,
                |_ok, _verify| true,
            );
        }
        let client = TurnClientOpensslTls::allocate(
            TransportType::Udp,
            local_addr,
            remote_addr,
            credentials,
            TransportType::Udp,
            allocation_families,
            ssl_context.build(),
        );
        let inner = Arc::new((Mutex::new(client.into()), Condvar::new()));
        let socket = Arc::new(socket);

        udp_recv_thread(base_instant, socket.clone(), inner.clone());
        udp_send_thread(base_instant, socket.clone(), events_sender, inner.clone());

        Self {
            base_instant,
            socket,
            inner,
        }
    }
}

impl<T: AsRef<[u8]> + std::fmt::Debug> Client<T> for ClientUdp {
    fn close(&self) {
        let mut client = self.inner.0.lock().unwrap();
        let now = Instant::from_std(self.base_instant);
        let _ = client.delete(now);
        self.inner.1.notify_one();
    }

    fn create_permission(
        &self,
        transport: TransportType,
        peer_addr: IpAddr,
    ) -> Result<(), CreatePermissionError> {
        let mut client = self.inner.0.lock().unwrap();
        let now = Instant::from_std(self.base_instant);
        client.create_permission(transport, peer_addr, now)?;
        self.inner.1.notify_one();
        Ok(())
    }

    fn send(
        &self,
        transport: TransportType,
        peer_addr: SocketAddr,
        data: T,
    ) -> Result<(), SendError> {
        let transmit = {
            let mut client = self.inner.0.lock().unwrap();
            let transmit = client
                .send_to(
                    transport,
                    peer_addr,
                    data,
                    Instant::from_std(self.base_instant),
                )?
                .unwrap();
            Transmit::new(
                transmit.data.build(),
                transmit.transport,
                transmit.from,
                transmit.to,
            )
        };
        self.socket.send_to(&transmit.data, transmit.to).unwrap();
        Ok(())
    }

    fn tcp_connect(&self, peer_addr: SocketAddr) -> Result<(), TcpConnectError> {
        let mut inner = self.inner.0.lock().unwrap();
        inner.tcp_connect(peer_addr, Instant::from_std(self.base_instant))
    }
}

#[derive(Clone, Debug)]
struct ClientTcp {
    base_instant: std::time::Instant,
    inner: Arc<(Mutex<ClientTcpInner>, Condvar)>,
}

fn tcp_recv_thread(
    base_instant: std::time::Instant,
    mut tcp: TcpStream,
    inner: Arc<(Mutex<ClientTcpInner>, Condvar)>,
) {
    std::thread::spawn(move || loop {
        let mut data = [0; 2048];
        let Ok(size) = tcp.read(&mut data) else {
            break;
        };
        {
            let mut inner_guard = inner.0.lock().unwrap();
            let now = Instant::from_std(base_instant);
            let ret = inner_guard.client.recv(
                Transmit::new(
                    &data[..size],
                    TransportType::Tcp,
                    tcp.peer_addr().unwrap(),
                    tcp.local_addr().unwrap(),
                ),
                now,
            );
            match ret {
                TurnRecvRet::Ignored(_) => continue,
                TurnRecvRet::Handled => {
                    inner.1.notify_one();
                    continue;
                }
                TurnRecvRet::PeerData(peer_data) => {
                    let data = peer_data.data();
                    let len = data.len();
                    let s = match std::str::from_utf8(data) {
                        Ok(s) => s.to_string(),
                        Err(_e) => format!("{:x?}", data),
                    };
                    println!(
                        "received {len} bytes from {:?} using {:?}: {s:?}",
                        peer_data.peer, peer_data.transport
                    );
                    continue;
                }
                TurnRecvRet::PeerIcmp {
                    transport,
                    peer,
                    icmp_type,
                    icmp_code,
                    icmp_data,
                } => {
                    println!(
                        "received ICMP type {icmp_type} code {icmp_code} data {icmp_data} from {peer:?} using {transport:?}",
                    );
                    continue;
                }
            }
        }
    });
}

fn tcp_send_thread(mut socket: TcpStream) -> SyncSender<Data<'static>> {
    let (send_sender, send_recv) = std::sync::mpsc::sync_channel::<Data<'static>>(8);
    std::thread::spawn(move || loop {
        while let Ok(recv) = send_recv.recv() {
            let socket = &mut socket;
            socket.write_all(&recv).unwrap();
        }
    });

    send_sender
}

#[derive(Debug)]
struct ClientTcpInner {
    client: TurnClient,
    socket_senders: BTreeMap<SocketAddr, SyncSender<Data<'static>>>,
}

fn tcp_send_loop(
    base_instant: std::time::Instant,
    events_sender: SyncSender<TurnEvent>,
    inner: Arc<(Mutex<ClientTcpInner>, Condvar)>,
) {
    let inner_s = inner.clone();
    std::thread::spawn(move || loop {
        let now = Instant::from_std(base_instant);
        let mut inner = inner_s.0.lock().unwrap();
        let lowest_wait = match inner.client.poll(now) {
            TurnPollRet::WaitUntil(wait) => wait,
            TurnPollRet::Closed => {
                break;
            }
            TurnPollRet::TcpClose {
                local_addr,
                remote_addr: _,
            } => {
                if let Some(sender) = inner.socket_senders.remove(&local_addr) {
                    sender
                        .send(Data::Owned(Vec::new().into_boxed_slice().into()))
                        .unwrap();
                }
                continue;
            }
            TurnPollRet::AllocateTcpSocket {
                id,
                socket,
                peer_addr,
            } => {
                // TODO: palm this off to a separate thread so polling the client is not blocked
                let tcp = TcpStream::connect_timeout(&socket.to, std::time::Duration::from_secs(5))
                    .inspect_err(|e| {
                        eprintln!("Failed to open TCP connection to {peer_addr}: {e:?}")
                    })
                    .ok();
                let local_addr = tcp.as_ref().and_then(|s| s.local_addr().ok());
                if let Some((tcp, local_addr)) = tcp.zip(local_addr) {
                    tcp_recv_thread(base_instant, tcp.try_clone().unwrap(), inner_s.clone());
                    let sender = tcp_send_thread(tcp);
                    inner.socket_senders.insert(local_addr, sender);
                }
                inner
                    .client
                    .allocated_tcp_socket(
                        id,
                        socket,
                        peer_addr,
                        local_addr,
                        Instant::from_std(base_instant),
                    )
                    .unwrap();
                continue;
            }
        };

        if let Some(event) = inner.client.poll_event() {
            events_sender.send(event).unwrap();
        }
        let mut sent = false;
        while let Some(transmit) = inner.client.poll_transmit(now) {
            let Some(sender) = inner.socket_senders.get(&transmit.from) else {
                continue;
            };
            sent = true;
            sender.send(transmit.data.into_owned()).unwrap();
        }
        if sent {
            continue;
        }
        let _ = inner_s.1.wait_timeout(inner, lowest_wait - now);
    });
}

impl ClientTcp {
    fn new(
        socket: TcpStream,
        to: SocketAddr,
        credentials: TurnCredentials,
        allocation_transport: TransportType,
        allocation_families: &[AddressFamily],
        events_sender: SyncSender<TurnEvent>,
    ) -> Self {
        let base_instant = std::time::Instant::now();
        let local_addr = socket.local_addr().unwrap();
        let remote_addr = to;
        let client = TurnClientTcp::allocate(
            local_addr,
            remote_addr,
            credentials,
            allocation_transport,
            allocation_families,
        );
        let socket_clone = socket.try_clone().unwrap();
        let local_addr = socket.local_addr().unwrap();
        let send_sender = tcp_send_thread(socket);
        let inner = Arc::new((
            Mutex::new(ClientTcpInner {
                client: client.into(),
                socket_senders: BTreeMap::from([(local_addr, send_sender.clone())]),
            }),
            Condvar::new(),
        ));

        tcp_recv_thread(base_instant, socket_clone, inner.clone());
        tcp_send_loop(base_instant, events_sender, inner.clone());

        Self {
            base_instant,
            inner,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn new_rustls(
        socket: TcpStream,
        to: SocketAddr,
        credentials: TurnCredentials,
        allocation_transport: TransportType,
        allocation_families: &[AddressFamily],
        server_name: ServerName<'static>,
        events_sender: SyncSender<TurnEvent>,
        insecure_tls: bool,
    ) -> Self {
        let base_instant = std::time::Instant::now();
        let local_addr = socket.local_addr().unwrap();
        let remote_addr = to;
        let config = if insecure_tls {
            ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(danger::NoCertificateVerification::new(
                    crypto_provider::default_provider(),
                )))
                .with_no_client_auth()
        } else {
            ClientConfig::with_platform_verifier().unwrap()
        };
        let client = TurnClientRustls::allocate(
            local_addr,
            remote_addr,
            credentials,
            allocation_transport,
            allocation_families,
            server_name,
            Arc::new(config),
        );
        let socket_clone = socket.try_clone().unwrap();
        let local_addr = socket.local_addr().unwrap();
        let send_sender = tcp_send_thread(socket);
        let inner = Arc::new((
            Mutex::new(ClientTcpInner {
                client: client.into(),
                socket_senders: BTreeMap::from([(local_addr, send_sender.clone())]),
            }),
            Condvar::new(),
        ));

        tcp_recv_thread(base_instant, socket_clone, inner.clone());
        tcp_send_loop(base_instant, events_sender, inner.clone());

        Self {
            base_instant,
            inner,
        }
    }

    fn new_openssl(
        socket: TcpStream,
        to: SocketAddr,
        credentials: TurnCredentials,
        allocation_transport: TransportType,
        allocation_families: &[AddressFamily],
        events_sender: SyncSender<TurnEvent>,
        insecure_tls: bool,
    ) -> Self {
        let base_instant = std::time::Instant::now();
        let local_addr = socket.local_addr().unwrap();
        let remote_addr = to;
        let mut ssl_context =
            openssl::ssl::SslContext::builder(openssl::ssl::SslMethod::tls_client()).unwrap();
        if insecure_tls {
            ssl_context.set_verify_callback(
                openssl::ssl::SslVerifyMode::FAIL_IF_NO_PEER_CERT,
                |_ok, _verify| true,
            );
        }
        let client = TurnClientOpensslTls::allocate(
            TransportType::Tcp,
            local_addr,
            remote_addr,
            credentials,
            allocation_transport,
            allocation_families,
            ssl_context.build(),
        );
        let socket_clone = socket.try_clone().unwrap();
        let local_addr = socket.local_addr().unwrap();
        let send_sender = tcp_send_thread(socket);
        let inner = Arc::new((
            Mutex::new(ClientTcpInner {
                client: client.into(),
                socket_senders: BTreeMap::from([(local_addr, send_sender.clone())]),
            }),
            Condvar::new(),
        ));

        tcp_recv_thread(base_instant, socket_clone, inner.clone());
        tcp_send_loop(base_instant, events_sender, inner.clone());

        Self {
            base_instant,
            inner,
        }
    }
}

impl<T: AsRef<[u8]> + std::fmt::Debug> Client<T> for ClientTcp {
    fn close(&self) {
        let mut inner = self.inner.0.lock().unwrap();
        let _ = inner.client.delete(Instant::from_std(self.base_instant));

        self.inner.1.notify_one();
        // TODO: actually close the TCP connection.
    }

    fn create_permission(
        &self,
        transport: TransportType,
        peer_addr: IpAddr,
    ) -> Result<(), CreatePermissionError> {
        let mut inner = self.inner.0.lock().unwrap();
        inner.client.create_permission(
            transport,
            peer_addr,
            Instant::from_std(self.base_instant),
        )?;
        self.inner.1.notify_one();
        Ok(())
    }

    fn send(
        &self,
        transport: TransportType,
        peer_addr: SocketAddr,
        data: T,
    ) -> Result<(), SendError> {
        let (transmit, sender) = {
            let mut inner = self.inner.0.lock().unwrap();
            let transmit = inner
                .client
                .send_to(
                    transport,
                    peer_addr,
                    data,
                    Instant::from_std(self.base_instant),
                )?
                .unwrap();
            let Some(sender) = inner.socket_senders.get(&transmit.from) else {
                return Ok(());
            };
            let transmit = Transmit::new(
                Data::from(transmit.data.build().into_boxed_slice()).into_owned(),
                transmit.transport,
                transmit.from,
                transmit.to,
            );
            (transmit, sender.clone())
        };
        sender.send(transmit.data.into_owned()).unwrap();
        Ok(())
    }

    fn tcp_connect(&self, peer_addr: SocketAddr) -> Result<(), TcpConnectError> {
        let mut inner = self.inner.0.lock().unwrap();
        inner
            .client
            .tcp_connect(peer_addr, Instant::from_std(self.base_instant))
    }
}

use rustls::crypto::aws_lc_rs as crypto_provider;
mod danger {
    use rustls::client::danger::HandshakeSignatureValid;
    use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::DigitallySignedStruct;

    #[derive(Debug)]
    pub struct NoCertificateVerification(CryptoProvider);

    impl NoCertificateVerification {
        pub fn new(provider: CryptoProvider) -> Self {
            Self(provider)
        }
    }

    impl rustls::client::danger::ServerCertVerifier for NoCertificateVerification {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp: &[u8],
            _now: UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            verify_tls12_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            verify_tls13_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            self.0.signature_verification_algorithms.supported_schemes()
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, ValueEnum)]
enum Transport {
    Udp,
    Tcp,
}

impl From<Transport> for TransportType {
    fn from(value: Transport) -> Self {
        match value {
            Transport::Udp => Self::Udp,
            Transport::Tcp => Self::Tcp,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, ValueEnum)]
enum TlsApi {
    Rustls,
    Openssl,
}

#[derive(Parser, Debug)]
#[command(version, about)]
struct Cli {
    #[arg(
        short,
        long,
        value_enum,
        default_value = "udp",
        help = "The network transport to use when connecting to the TURN server"
    )]
    transport: Transport,
    #[arg(
        long,
        help = "Whether to encrypt the communication with the TURN server using (D)TLS"
    )]
    use_tls: bool,
    #[arg(
        long,
        value_enum,
        default_value = "rustls",
        help = "The TLS Api to use when accessing the server using (D)TLS"
    )]
    tls_api: TlsApi,
    #[arg(
        short,
        long,
        required = true,
        help = "The network address of the turn server to connect to"
    )]
    server: String,
    #[arg(
        long,
        value_enum,
        default_value = "udp",
        help = "The network transport to use when connecting to the TURN server"
    )]
    allocation_transport: Transport,
    #[arg(
        short,
        long,
        required = true,
        help = "The user name for access to the TURN server"
    )]
    user: String,
    #[arg(
        short,
        long,
        required = true,
        help = "The password for access to the TURN server"
    )]
    password: String,
    #[arg(
        short = 'a',
        long,
        required = true,
        help = "The network address of the peer to send data to through the TURN server"
    )]
    peer: SocketAddr,
    #[arg(long, default_value = "1", help = "Number of messages to send")]
    count: u64,
    #[arg(
        short,
        long,
        default_value = "10",
        help = "number of seconds to wait between messages"
    )]
    delay: u64,
    #[arg(long, default_value = "false", help = "Insecure TLS")]
    insecure_tls: bool,
    #[arg(long, default_value = "false", help = "Also allocate an IPv4 address")]
    ipv4: bool,
    #[arg(long, default_value = "false", help = "Also allocate an IPv6 address")]
    ipv6: bool,
}

fn send_loop(
    client: &dyn Client<String>,
    transport: TransportType,
    peer: SocketAddr,
    count: u64,
    delay: u64,
) {
    for i in 0..count {
        let data = format!("Hello from turn {}s.\n", i * delay);
        println!("sending {data:?} to {peer}");
        client.send(transport, peer, data).unwrap();
        if i + 1 != count {
            std::thread::sleep(std::time::Duration::from_secs(delay));
        }
    }
}

fn main() -> io::Result<()> {
    init_logs();

    let cli = Cli::parse();
    let use_tls = cli.use_tls;
    let transport: TransportType = cli.transport.into();
    let credentials = TurnCredentials::new(&cli.user, &cli.password);
    let (events_sender, events_recv) = std::sync::mpsc::sync_channel(8);

    let mut address_families = vec![];
    if cli.ipv4 || cli.peer.is_ipv4() {
        address_families.push(AddressFamily::IPV4);
    }
    if cli.ipv6 || cli.peer.is_ipv6() {
        address_families.push(AddressFamily::IPV6);
    }
    let mut was_dns = false;
    let server = cli.server.parse::<SocketAddr>().unwrap_or_else(|_| {
        was_dns = true;
        cli.server.to_socket_addrs().unwrap().next().unwrap()
    });

    if cli.allocation_transport == Transport::Tcp && cli.transport != Transport::Tcp {
        panic!("TURN-TCP allocations can only be created with a TCP based connection to the TURN server. Use `--transport tcp`.");
    }

    let client = match transport {
        TransportType::Udp => {
            let socket = if server.is_ipv4() {
                UdpSocket::bind("0.0.0.0:0").unwrap()
            } else {
                UdpSocket::bind("[::]:0").unwrap()
            };
            println!(
                "Allocated UDP socket with local address {}",
                socket.local_addr().unwrap()
            );
            if use_tls {
                match cli.tls_api {
                    TlsApi::Rustls => panic!("DTLS over UDP is not currently supported using Rustls. Use openssl instead"),
                    TlsApi::Openssl => {
                        let client = ClientUdp::new_openssl(
                            socket,
                            server,
                            credentials,
                            &address_families,
                            events_sender,
                            cli.insecure_tls,
                        );
                        Box::new(client) as Box<dyn Client<_>>
                    }
                }
            } else {
                let client = ClientUdp::new(
                    socket,
                    server,
                    credentials,
                    &address_families,
                    events_sender,
                );
                Box::new(client) as Box<dyn Client<_>>
            }
        }
        TransportType::Tcp => {
            let socket = TcpStream::connect(server).unwrap();
            if use_tls {
                let server_name = if was_dns {
                    let dns_name = cli.server.split(":").next().unwrap().to_string();
                    dns_name.try_into().unwrap()
                } else {
                    server.ip().into()
                };
                match cli.tls_api {
                    TlsApi::Rustls => {
                        let client = ClientTcp::new_rustls(
                            socket,
                            server,
                            credentials,
                            cli.allocation_transport.into(),
                            &address_families,
                            server_name,
                            events_sender,
                            cli.insecure_tls,
                        );
                        Box::new(client) as Box<dyn Client<_>>
                    }
                    TlsApi::Openssl => {
                        let client = ClientTcp::new_openssl(
                            socket,
                            server,
                            credentials,
                            cli.allocation_transport.into(),
                            &address_families,
                            //server_name,
                            events_sender,
                            cli.insecure_tls,
                        );
                        Box::new(client) as Box<dyn Client<_>>
                    }
                }
            } else {
                let client = ClientTcp::new(
                    socket,
                    server,
                    credentials,
                    cli.allocation_transport.into(),
                    &address_families,
                    events_sender,
                );
                Box::new(client) as Box<dyn Client<_>>
            }
        }
    };

    let peer_addr = cli.peer;

    while let Ok(event) = events_recv.recv() {
        match event {
            TurnEvent::AllocationCreated(relayed_transport, relayed) => {
                if relayed.is_ipv4() == peer_addr.is_ipv4() {
                    client
                        .create_permission(relayed_transport, peer_addr.ip())
                        .unwrap();
                }
            }
            TurnEvent::AllocationCreateFailed(family) => {
                error!("Failed to create allocation for family {family}");
                if (family == AddressFamily::IPV4) == peer_addr.is_ipv4() {
                    client.close();
                }
            }
            TurnEvent::PermissionCreated(transport, _peer_addr) => match cli.allocation_transport {
                Transport::Tcp => {
                    client.tcp_connect(peer_addr).unwrap();
                }
                Transport::Udp => {
                    send_loop(client.as_ref(), transport, peer_addr, cli.count, cli.delay);
                    client.close();
                }
            },
            TurnEvent::PermissionCreateFailed(transport, peer_addr) => {
                error!("Permission create failed for {transport:?}, {peer_addr}");
                client.close()
            }
            TurnEvent::ChannelCreated(transport, peer_addr) => {
                println!("Channel created failed for {transport:?}, {peer_addr}");
            }
            TurnEvent::ChannelCreateFailed(transport, peer_addr) => {
                error!("Channel create failed for {transport:?}, {peer_addr}");
                client.close();
            }
            TurnEvent::TcpConnected(peer_addr) => {
                println!("TCP data connection to {peer_addr} has been completed");
                send_loop(client.as_ref(), transport, peer_addr, cli.count, cli.delay);
                client.close();
            }
            TurnEvent::TcpConnectFailed(peer_addr) => {
                error!("TCP data connection to {peer_addr} has failed");
                client.close();
            }
        }
    }
    Ok(())
}
