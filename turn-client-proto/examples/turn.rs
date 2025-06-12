// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! An example showing how a TURN client can be implemented.

use turn_client_proto::types::TurnCredentials;
use turn_client_proto::{
    CreatePermissionError, TurnClient as Client, TurnEvent, TurnPollRet, TurnRecvRet,
};

use stun_proto::agent::{DelayedTransmitBuild, StunError, Transmit};
use turn_types::stun::TransportType;

use std::io;
use std::net::{IpAddr, SocketAddr};
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

#[derive(Debug)]
struct TurnClient {
    socket: Arc<UdpSocket>,
    inner: Arc<(Mutex<ClientInner>, Condvar)>,
}

impl TurnClient {
    fn new_udp(
        socket: UdpSocket,
        to: SocketAddr,
        credentials: TurnCredentials,
        events_sender: SyncSender<TurnEvent>,
    ) -> Self {
        let local_addr = socket.local_addr().unwrap();
        let client = Client::allocate(TransportType::Udp, local_addr, to, credentials);
        let inner = Arc::new((Mutex::new(ClientInner { client }), Condvar::new()));
        let weak_inner = Arc::downgrade(&inner);
        let socket = Arc::new(socket);

        let socket_clone = socket.clone();
        let inner_s = inner.clone();
        let recv_task = std::thread::spawn(move || loop {
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
        let poll_task = std::thread::spawn(move || loop {
            let now = Instant::now();
            let mut inner = inner_s.0.lock().unwrap();
            let lowest_wait = match inner.client.poll(now) {
                TurnPollRet::WaitUntil(wait) => wait,
                TurnPollRet::Closed => {
                    break;
                }
            };

            if let Some(event) = inner.client.poll_event() {
                events_sender.send(event);
            }
            let mut sent = false;
            while let Some(transmit) = inner.client.poll_transmit(now) {
                sent = true;
                socket_clone.send_to(&transmit.data, transmit.to).unwrap();
            }
            if sent {
                continue;
            }
            inner_s.1.wait_timeout(inner, now - lowest_wait);
        });
        Self { socket, inner }
    }

    pub fn close(&self) {
        let transmit = {
            let mut inner = self.inner.0.lock().unwrap();
            inner.client.delete(Instant::now())
        };

        if let Some(transmit) = transmit {
            self.socket.send_to(&transmit.data, transmit.to).unwrap();
        }
    }

    pub fn create_permission(
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

    pub fn send<T: AsRef<[u8]> + std::fmt::Debug>(
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
struct ClientInner {
    client: Client,
}

fn main() -> io::Result<()> {
    init_logs();
    let turn_server = "127.0.0.1:3478".parse().unwrap();
    let credentials = TurnCredentials::new("coturn", "password");
    let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
    let (events_sender, events_recv) = std::sync::mpsc::sync_channel(8);

    let client = TurnClient::new_udp(socket, turn_server, credentials, events_sender);

    let peer_addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();

    while let Ok(event) = events_recv.recv() {
        match event {
            TurnEvent::AllocationCreated(_, _) => {
                client.create_permission(TransportType::Udp, peer_addr.ip());
            }
            TurnEvent::AllocationCreateFailed => {
                error!("Failed to create allocation");
                client.close();
            }
            TurnEvent::PermissionCreated(transport, _peer_addr) => {
                let data = b"Hello from turn.\n";
                client.send(transport, peer_addr, data);
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
