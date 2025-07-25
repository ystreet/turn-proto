// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

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
//! ```
//!
//! Shell 2 (`coturn`)
//! ```sh
//! # only needs to be completed once to add the relevant TURN username and password
//! turnadmin --userdb userdb.sqlite --add --user coturn --realm realm --password password
//! # Do not use in production, adapt for your use case
//! turnserver --user not-important --cli-password not-important --realm realm --lt-cred-mech --userdb userdb.sqlite -v --allow-loopback-peers --listening-ip 127.0.0.1 --relay-ip 127.0.0.1
//! ```
//!
//! Shell 3 (this example)
//! ```sh
//! ./turn --transport udp --server 127.0.0.1:3478 --user coturn --password password --peer 127.0.0.1:9100 --count 2 --delay 5
//! ```

#![cfg(not(tarpaulin))]

use rustls::ClientConfig;
use rustls_platform_verifier::ConfigVerifierExt;
use turn_client_proto::prelude::*;
use turn_client_proto::rustls::TurnClientTls;
use turn_client_proto::tcp::TurnClientTcp;
use turn_client_proto::types::TurnCredentials;
use turn_client_proto::udp::{
    CreatePermissionError, SendError, TurnClientUdp, TurnEvent, TurnPollRet, TurnRecvRet,
};

use stun_proto::agent::Transmit;
use turn_types::stun::data::Data;
use turn_types::stun::TransportType;

use clap::{Parser, ValueEnum};

use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::mpsc::SyncSender;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Instant;

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
}

#[derive(Clone, Debug)]
struct ClientUdp {
    socket: Arc<UdpSocket>,
    inner: Arc<(Mutex<ClientUdpInner>, Condvar)>,
}

impl ClientUdp {
    fn new(
        socket: UdpSocket,
        to: SocketAddr,
        credentials: TurnCredentials,
        events_sender: SyncSender<TurnEvent>,
    ) -> Self {
        let local_addr = socket.local_addr().unwrap();
        let client = TurnClientUdp::allocate(local_addr, to, credentials);
        let inner = Arc::new((Mutex::new(ClientUdpInner { client }), Condvar::new()));
        let socket = Arc::new(socket);

        let socket_clone = socket.clone();
        let inner_s = inner.clone();
        std::thread::spawn(move || loop {
            let mut data = [0; 2048];
            let Ok((size, from)) = socket_clone.recv_from(&mut data) else {
                break;
            };
            {
                let mut inner = inner_s.0.lock().unwrap();
                let now = Instant::now();
                let ret = inner.client.recv(
                    Transmit::new(&data[..size], TransportType::Udp, from, local_addr),
                    now,
                );
                println!("recv ret {ret:?}");
                match ret {
                    TurnRecvRet::Ignored(_) => continue,
                    TurnRecvRet::Handled => {
                        inner_s.1.notify_one();
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
                }
            }
        });

        let inner_s = inner.clone();
        let socket_clone = socket.clone();
        std::thread::spawn(move || loop {
            let now = Instant::now();
            let mut inner = inner_s.0.lock().unwrap();
            let lowest_wait = match inner.client.poll(now) {
                TurnPollRet::WaitUntil(wait) => wait,
                TurnPollRet::Closed => {
                    break;
                }
            };

            if let Some(event) = inner.client.poll_event() {
                events_sender.send(event).unwrap();
            }
            let mut sent = false;
            while let Some(transmit) = inner.client.poll_transmit(now) {
                sent = true;
                socket_clone.send_to(&transmit.data, transmit.to).unwrap();
            }
            if sent {
                continue;
            }
            let _ = inner_s.1.wait_timeout(inner, lowest_wait - now);
        });
        Self { socket, inner }
    }
}

impl<T: AsRef<[u8]> + std::fmt::Debug> Client<T> for ClientUdp {
    fn close(&self) {
        let mut inner = self.inner.0.lock().unwrap();
        let now = Instant::now();
        let _ = inner.client.delete(now);
        self.inner.1.notify_one();
    }

    fn create_permission(
        &self,
        transport: TransportType,
        peer_addr: IpAddr,
    ) -> Result<(), CreatePermissionError> {
        let mut inner = self.inner.0.lock().unwrap();
        let now = Instant::now();
        inner.client.create_permission(transport, peer_addr, now)?;
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
            let mut inner = self.inner.0.lock().unwrap();
            let transmit = inner
                .client
                .send_to(transport, peer_addr, data, Instant::now())?
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
}

#[derive(Debug)]
struct ClientUdpInner {
    client: TurnClientUdp,
}

#[derive(Clone, Debug)]
struct ClientTcp {
    send_sender: SyncSender<Data<'static>>,
    inner: Arc<(Mutex<ClientTcpInner>, Condvar)>,
}

impl ClientTcp {
    fn new(
        mut socket: TcpStream,
        to: SocketAddr,
        credentials: TurnCredentials,
        events_sender: SyncSender<TurnEvent>,
    ) -> Self {
        let local_addr = socket.local_addr().unwrap();
        let remote_addr = to;
        let client = TurnClientTcp::allocate(local_addr, remote_addr, credentials);
        let inner = Arc::new((Mutex::new(ClientTcpInner { client }), Condvar::new()));

        let mut socket_clone = socket.try_clone().unwrap();
        let inner_s = inner.clone();
        std::thread::spawn(move || loop {
            let mut data = [0; 2048];
            let Ok(size) = socket_clone.read(&mut data) else {
                break;
            };
            {
                let mut inner = inner_s.0.lock().unwrap();
                let now = Instant::now();
                let ret = inner.client.recv(
                    Transmit::new(&data[..size], TransportType::Tcp, remote_addr, local_addr),
                    now,
                );
                println!("recv ret {ret:?}");
                match ret {
                    TurnRecvRet::Ignored(_) => continue,
                    TurnRecvRet::Handled => {
                        inner_s.1.notify_one();
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
                }
            }
        });

        let (send_sender, send_recv) = std::sync::mpsc::sync_channel::<Data<'static>>(8);
        std::thread::spawn(move || loop {
            while let Ok(recv) = send_recv.recv() {
                let socket = &mut socket;
                socket.write_all(&recv).unwrap();
            }
        });

        let inner_s = inner.clone();
        let sender = send_sender.clone();
        std::thread::spawn(move || loop {
            let now = Instant::now();
            let mut inner = inner_s.0.lock().unwrap();
            let lowest_wait = match inner.client.poll(now) {
                TurnPollRet::WaitUntil(wait) => wait,
                TurnPollRet::Closed => {
                    break;
                }
            };

            if let Some(event) = inner.client.poll_event() {
                events_sender.send(event).unwrap();
            }
            let mut sent = false;
            while let Some(transmit) = inner.client.poll_transmit(now) {
                sent = true;
                sender.send(transmit.data.into_owned()).unwrap();
            }
            if sent {
                continue;
            }
            let _ = inner_s.1.wait_timeout(inner, lowest_wait - now);
        });
        Self { send_sender, inner }
    }
}

impl<T: AsRef<[u8]> + std::fmt::Debug> Client<T> for ClientTcp {
    fn close(&self) {
        let mut inner = self.inner.0.lock().unwrap();
        let _ = inner.client.delete(Instant::now());

        self.inner.1.notify_one();
        // TODO: actually close the TCP connection.
    }

    fn create_permission(
        &self,
        transport: TransportType,
        peer_addr: IpAddr,
    ) -> Result<(), CreatePermissionError> {
        let mut inner = self.inner.0.lock().unwrap();
        inner
            .client
            .create_permission(transport, peer_addr, Instant::now())?;
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
            let mut inner = self.inner.0.lock().unwrap();
            let transmit = inner
                .client
                .send_to(transport, peer_addr, data, Instant::now())?
                .unwrap();
            Transmit::new(
                Data::from(transmit.data.build().into_boxed_slice()).into_owned(),
                transmit.transport,
                transmit.from,
                transmit.to,
            )
        };
        self.send_sender.send(transmit.data).unwrap();
        Ok(())
    }
}

#[derive(Debug)]
struct ClientTcpInner {
    client: TurnClientTcp,
}

#[derive(Clone, Debug)]
struct ClientTls {
    send_sender: SyncSender<Data<'static>>,
    inner: Arc<(Mutex<ClientTlsInner>, Condvar)>,
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

impl ClientTls {
    fn new(
        mut socket: TcpStream,
        to: SocketAddr,
        credentials: TurnCredentials,
        events_sender: SyncSender<TurnEvent>,
        insecure_tls: bool,
    ) -> Self {
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
            ClientConfig::with_platform_verifier()
        };
        let client = TurnClientTls::allocate(
            local_addr,
            remote_addr,
            credentials,
            remote_addr.ip().into(),
            Arc::new(config),
        );
        let inner = Arc::new((Mutex::new(ClientTlsInner { client }), Condvar::new()));

        let mut socket_clone = socket.try_clone().unwrap();
        let inner_s = inner.clone();
        std::thread::spawn(move || loop {
            let mut data = [0; 2048];
            let Ok(size) = socket_clone.read(&mut data) else {
                break;
            };
            {
                let mut inner = inner_s.0.lock().unwrap();
                let now = Instant::now();
                let ret = inner.client.recv(
                    Transmit::new(&data[..size], TransportType::Tcp, remote_addr, local_addr),
                    now,
                );
                println!("recv ret {ret:?}");
                match ret {
                    TurnRecvRet::Ignored(_) => continue,
                    TurnRecvRet::Handled => {
                        inner_s.1.notify_one();
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
                }
            }
        });

        let (send_sender, send_recv) = std::sync::mpsc::sync_channel::<Data<'static>>(8);
        std::thread::spawn(move || loop {
            while let Ok(recv) = send_recv.recv() {
                let socket = &mut socket;
                socket.write_all(&recv).unwrap();
            }
        });

        let inner_s = inner.clone();
        let sender = send_sender.clone();
        std::thread::spawn(move || loop {
            let now = Instant::now();
            let mut inner = inner_s.0.lock().unwrap();
            let lowest_wait = match inner.client.poll(now) {
                TurnPollRet::WaitUntil(wait) => wait,
                TurnPollRet::Closed => {
                    break;
                }
            };

            if let Some(event) = inner.client.poll_event() {
                events_sender.send(event).unwrap();
            }
            let mut sent = false;
            while let Some(transmit) = inner.client.poll_transmit(now) {
                sent = true;
                sender.send(transmit.data.into_owned()).unwrap();
            }
            if sent {
                continue;
            }
            let _ = inner_s.1.wait_timeout(inner, lowest_wait - now);
        });
        Self { send_sender, inner }
    }
}

impl<T: AsRef<[u8]> + std::fmt::Debug> Client<T> for ClientTls {
    fn close(&self) {
        let mut inner = self.inner.0.lock().unwrap();
        let _ = inner.client.delete(Instant::now());

        self.inner.1.notify_one();
        // TODO: actually close the TCP connection.
    }

    fn create_permission(
        &self,
        transport: TransportType,
        peer_addr: IpAddr,
    ) -> Result<(), CreatePermissionError> {
        let mut inner = self.inner.0.lock().unwrap();
        inner
            .client
            .create_permission(transport, peer_addr, Instant::now())?;
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
            let mut inner = self.inner.0.lock().unwrap();
            let transmit = inner
                .client
                .send_to(transport, peer_addr, data, Instant::now())?
                .unwrap();
            Transmit::new(
                Data::from(transmit.data.build().into_boxed_slice()).into_owned(),
                transmit.transport,
                transmit.from,
                transmit.to,
            )
        };
        self.send_sender.send(transmit.data).unwrap();
        Ok(())
    }
}

#[derive(Debug)]
struct ClientTlsInner {
    client: TurnClientTls,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, ValueEnum)]
enum Transport {
    Udp,
    Tcp,
    Tls,
}

impl Transport {
    fn is_tls(&self) -> bool {
        matches!(self, Self::Tls)
    }
}

impl From<Transport> for TransportType {
    fn from(value: Transport) -> Self {
        match value {
            Transport::Udp => Self::Udp,
            Transport::Tcp => Self::Tcp,
            Transport::Tls => Self::Tcp,
        }
    }
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
        short,
        long,
        required = true,
        help = "The network address of the turn server to connect to"
    )]
    server: SocketAddr,
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
}

fn main() -> io::Result<()> {
    init_logs();

    let cli = Cli::parse();
    let is_tls = cli.transport.is_tls();
    let transport: TransportType = cli.transport.into();
    let credentials = TurnCredentials::new(&cli.user, &cli.password);
    let (events_sender, events_recv) = std::sync::mpsc::sync_channel(8);

    let client = match transport {
        TransportType::Udp => {
            let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
            let client = ClientUdp::new(socket, cli.server, credentials, events_sender);
            Box::new(client) as Box<dyn Client<_>>
        }
        TransportType::Tcp => {
            let socket = TcpStream::connect(cli.server).unwrap();
            if is_tls {
                let client = ClientTls::new(
                    socket,
                    cli.server,
                    credentials,
                    events_sender,
                    cli.insecure_tls,
                );
                Box::new(client) as Box<dyn Client<_>>
            } else {
                let client = ClientTcp::new(socket, cli.server, credentials, events_sender);
                Box::new(client) as Box<dyn Client<_>>
            }
        }
    };

    let peer_addr = cli.peer;

    while let Ok(event) = events_recv.recv() {
        match event {
            TurnEvent::AllocationCreated(_, _) => {
                client
                    .create_permission(TransportType::Udp, peer_addr.ip())
                    .unwrap();
            }
            TurnEvent::AllocationCreateFailed => {
                error!("Failed to create allocation");
                client.close();
            }
            TurnEvent::PermissionCreated(transport, _peer_addr) => {
                for i in 0..cli.count {
                    let data = format!("Hello from turn {}s.\n", i * cli.delay);
                    println!("sending {data:?} to {peer_addr}");
                    client.send(transport, peer_addr, data).unwrap();
                    if i + 1 != cli.count {
                        std::thread::sleep(std::time::Duration::from_secs(cli.delay));
                    }
                }
                client.close();
            }
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
        }
    }
    Ok(())
}
