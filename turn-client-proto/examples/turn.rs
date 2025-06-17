// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! An example showing how a TURN client can be implemented.

use turn_client_proto::types::TurnCredentials;
use turn_client_proto::{CreatePermissionError, TurnClient, TurnEvent, TurnPollRet, TurnRecvRet};

use stun_proto::agent::{DelayedTransmitBuild, StunError, Transmit};
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
    ) -> Result<(), StunError>;
}

#[derive(Clone, Debug)]
struct TurnClientUdp {
    socket: Arc<UdpSocket>,
    inner: Arc<(Mutex<TurnClientUdpInner>, Condvar)>,
}

impl TurnClientUdp {
    fn new(
        socket: UdpSocket,
        to: SocketAddr,
        credentials: TurnCredentials,
        events_sender: SyncSender<TurnEvent>,
    ) -> Self {
        let local_addr = socket.local_addr().unwrap();
        let client = TurnClient::allocate(TransportType::Udp, local_addr, to, credentials);
        let inner = Arc::new((Mutex::new(TurnClientUdpInner { client }), Condvar::new()));
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
                    TurnRecvRet::PeerData {
                        data,
                        transport,
                        peer,
                    } => {
                        println!(
                            "received {} bytes from {peer:?} using {transport:?}",
                            data.len()
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
            let _ = inner_s.1.wait_timeout(inner, now - lowest_wait);
        });
        Self { socket, inner }
    }
}

impl<T: AsRef<[u8]> + std::fmt::Debug> Client<T> for TurnClientUdp {
    fn close(&self) {
        let transmit = {
            let mut inner = self.inner.0.lock().unwrap();
            inner.client.delete(Instant::now())
        };

        if let Some(transmit) = transmit {
            self.socket.send_to(&transmit.data, transmit.to).unwrap();
        }
    }

    fn create_permission(
        &self,
        transport: TransportType,
        peer_addr: IpAddr,
    ) -> Result<(), CreatePermissionError> {
        let transmit = {
            let mut inner = self.inner.0.lock().unwrap();
            inner
                .client
                .create_permission(transport, peer_addr, Instant::now())?
        };
        self.socket.send_to(&transmit.data, transmit.to).unwrap();
        Ok(())
    }

    fn send(
        &self,
        transport: TransportType,
        peer_addr: SocketAddr,
        data: T,
    ) -> Result<(), StunError> {
        let transmit = {
            let mut inner = self.inner.0.lock().unwrap();
            let transmit = inner
                .client
                .send_to(transport, peer_addr, data, Instant::now())?;
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
struct TurnClientUdpInner {
    client: TurnClient,
}

#[derive(Clone, Debug)]
struct TurnClientTcp {
    send_sender: SyncSender<Data<'static>>,
    inner: Arc<(Mutex<TurnClientTcpInner>, Condvar)>,
}

impl TurnClientTcp {
    fn new(
        mut socket: TcpStream,
        to: SocketAddr,
        credentials: TurnCredentials,
        events_sender: SyncSender<TurnEvent>,
    ) -> Self {
        let local_addr = socket.local_addr().unwrap();
        let remote_addr = to;
        let client = TurnClient::allocate(TransportType::Tcp, local_addr, remote_addr, credentials);
        let inner = Arc::new((Mutex::new(TurnClientTcpInner { client }), Condvar::new()));

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
                    TurnRecvRet::PeerData {
                        data,
                        transport,
                        peer,
                    } => {
                        println!(
                            "received {} bytes from {peer:?} using {transport:?}",
                            data.len()
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
            let _ = inner_s.1.wait_timeout(inner, now - lowest_wait);
        });
        Self { send_sender, inner }
    }
}

impl<T: AsRef<[u8]> + std::fmt::Debug> Client<T> for TurnClientTcp {
    fn close(&self) {
        let transmit = {
            let mut inner = self.inner.0.lock().unwrap();
            inner.client.delete(Instant::now())
        };

        if let Some(transmit) = transmit {
            self.send_sender.send(transmit.data.into_owned()).unwrap();
        }
        // TODO: actually close the TCP connection.
    }

    fn create_permission(
        &self,
        transport: TransportType,
        peer_addr: IpAddr,
    ) -> Result<(), CreatePermissionError> {
        let transmit = {
            let mut inner = self.inner.0.lock().unwrap();
            inner
                .client
                .create_permission(transport, peer_addr, Instant::now())?
        };
        self.send_sender.send(transmit.data.into_owned()).unwrap();
        Ok(())
    }

    fn send(
        &self,
        transport: TransportType,
        peer_addr: SocketAddr,
        data: T,
    ) -> Result<(), StunError> {
        let transmit = {
            let mut inner = self.inner.0.lock().unwrap();
            let transmit = inner
                .client
                .send_to(transport, peer_addr, data, Instant::now())?;
            Transmit::new(
                Data::from(transmit.data.build().as_ref()).into_owned(),
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
struct TurnClientTcpInner {
    client: TurnClient,
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

#[derive(Parser, Debug)]
#[command(version, about)]
struct Cli {
    #[arg(short, long, value_enum)]
    transport: Transport,
    #[arg(short, long)]
    server: SocketAddr,
    #[arg(short, long)]
    user: String,
    #[arg(short, long)]
    password: String,
    #[arg(short = 'a', long)]
    peer: SocketAddr,
}

fn main() -> io::Result<()> {
    init_logs();

    let cli = Cli::parse();
    let transport: TransportType = cli.transport.into();
    let credentials = TurnCredentials::new(&cli.user, &cli.password);
    let (events_sender, events_recv) = std::sync::mpsc::sync_channel(8);

    let client = match transport {
        TransportType::Udp => {
            let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
            let client = TurnClientUdp::new(socket, cli.server, credentials, events_sender);
            Box::new(client) as Box<dyn Client<_>>
        }
        TransportType::Tcp => {
            let socket = TcpStream::connect(cli.server).unwrap();
            let client = TurnClientTcp::new(socket, cli.server, credentials, events_sender);
            Box::new(client) as Box<dyn Client<_>>
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
                let data = b"Hello from turn.\n";
                client.send(transport, peer_addr, data).unwrap();
                client.close();
            }
            TurnEvent::PermissionCreateFailed(transport, peer_addr) => {
                error!("Permission create failed for {transport:?}, {peer_addr}");
                client.close()
            }
        }
    }
    Ok(())
}
