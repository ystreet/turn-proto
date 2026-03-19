// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A TURN server that can handle TLS client connections.

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::net::SocketAddr;
use core::time::Duration;
use turn_types::prelude::DelayedTransmitBuild;
use turn_types::transmit::TransmitBuild;
use turn_types::AddressFamily;

use stun_proto::agent::Transmit;
use stun_proto::Instant;
use tracing::{info, trace, warn};
use turn_types::stun::TransportType;

use crate::api::{
    DelayedMessageOrChannelSend, SocketAllocateError, TurnServerApi, TurnServerPollRet,
};
use crate::server::TurnServer;

/// A TURN server that can handle TLS connections.
#[derive(Debug)]
pub struct DimplTurnServer {
    server: TurnServer,
    config: Arc<dimpl::Config>,
    certificate: dimpl::DtlsCertificate,
    clients: Vec<Client>,
}

#[derive(Debug)]
struct Client {
    client_addr: SocketAddr,
    dtls: dimpl::Dtls,
    base_instant: std::time::Instant,
    base_now: Instant,
    connected: bool,
    pending_encrypted: VecDeque<Vec<u8>>,
    pending_incoming_plaintext: VecDeque<Vec<u8>>,
}

impl Client {
    fn poll(&mut self, now: Instant) -> Option<Instant> {
        let _ = self.dtls.handle_timeout(
            Instant::from_nanos((now - self.base_now).as_nanos() as i64).to_std(self.base_instant),
        );
        let mut out = [0; 2048];
        let mut earliest_wait = None;
        loop {
            match self.dtls.poll_output(&mut out) {
                dimpl::Output::Packet(p) => {
                    self.pending_encrypted.push_back(p.to_vec());
                    earliest_wait = Some(now);
                }
                dimpl::Output::Timeout(time) => {
                    let wait = Instant::from_nanos((time - self.base_instant).as_nanos() as i64);
                    if wait == now {
                        let _ = self.dtls.handle_timeout(time);
                        continue;
                    }
                    if earliest_wait.map_or(true, |earliest| earliest > wait) {
                        earliest_wait = Some(wait);
                    }
                    break;
                }
                dimpl::Output::Connected => self.connected = true,
                // TODO: validate certificate
                dimpl::Output::PeerCert(_peer_cert) => (),
                dimpl::Output::KeyingMaterial(_key, _srtp_profile) => (),
                dimpl::Output::ApplicationData(app_data) => {
                    self.pending_incoming_plaintext.push_back(app_data.to_vec());
                }
                _ => (),
            }
        }
        earliest_wait
    }

    fn poll_plaintext(&mut self) -> Option<Vec<u8>> {
        self.pending_incoming_plaintext.pop_front()
    }

    fn poll_encrypted(&mut self) -> Option<Vec<u8>> {
        self.pending_encrypted.pop_front()
    }
}

impl DimplTurnServer {
    /// Construct a now Turn server that can handle TLS connections.
    pub fn new(
        transport: TransportType,
        listen_addr: SocketAddr,
        realm: String,
        config: Arc<dimpl::Config>,
        certificate: dimpl::DtlsCertificate,
    ) -> Self {
        Self {
            server: TurnServer::new(transport, listen_addr, realm),
            config,
            certificate,
            clients: vec![],
        }
    }
}

impl TurnServerApi for DimplTurnServer {
    /// Add a user credentials that would be accepted by this [`TurnServer`].
    fn add_user(&mut self, username: String, password: String) {
        self.server.add_user(username, password)
    }

    /// The address that the [`TurnServer`] is listening on for incoming client connections.
    fn listen_address(&self) -> SocketAddr {
        self.server.listen_address()
    }

    /// Set the amount of time that a Nonce (used for authentication) will expire and a new Nonce
    /// will need to be acquired by a client.
    fn set_nonce_expiry_duration(&mut self, expiry_duration: Duration) {
        self.server.set_nonce_expiry_duration(expiry_duration)
    }

    /// Provide received data to the [`TurnServer`].
    ///
    /// Any returned Transmit should be forwarded to the appropriate socket.
    #[tracing::instrument(
        name = "turn_server_dimpl_recv",
        skip(self, transmit, now),
        fields(
            from = ?transmit.from,
            data_len = transmit.data.as_ref().len()
        )
    )]
    fn recv<T: AsRef<[u8]> + core::fmt::Debug>(
        &mut self,
        transmit: Transmit<T>,
        now: Instant,
    ) -> Option<TransmitBuild<DelayedMessageOrChannelSend<T>>> {
        let listen_address = self.listen_address();
        if transmit.to == listen_address {
            trace!("receiving TLS data: {:x?}", transmit.data.as_ref());
            // incoming client
            let client = match self
                .clients
                .iter_mut()
                .find(|client| client.client_addr == transmit.from)
            {
                Some(client) => client,
                None => {
                    let len = self.clients.len();
                    let base_instant = std::time::Instant::now();
                    let mut dtls = dimpl::Dtls::new_auto(
                        self.config.clone(),
                        self.certificate.clone(),
                        base_instant,
                    );
                    dtls.set_active(false);
                    let mut client = Client {
                        client_addr: transmit.from,
                        dtls,
                        base_instant,
                        base_now: now,
                        connected: false,
                        pending_encrypted: VecDeque::default(),
                        pending_incoming_plaintext: VecDeque::default(),
                    };
                    // start with poll to ensure that initial setup completes
                    client.poll(now);
                    self.clients.push(client);
                    info!(
                        "new connection from {} {}",
                        transmit.transport, transmit.from
                    );
                    &mut self.clients[len]
                }
            };
            match client.dtls.handle_packet(transmit.data.as_ref()) {
                Ok(_) => (),
                Err(e) => {
                    warn!("error accepting TLS: {e}");
                    return None;
                }
            };

            client.poll(now);
            while let Some(plaintext) = client.poll_plaintext() {
                let Some(transmit) = self.server.recv(
                    Transmit::new(plaintext, transmit.transport, transmit.from, transmit.to),
                    now,
                ) else {
                    continue;
                };

                if transmit.from == listen_address && transmit.to == client.client_addr {
                    client
                        .dtls
                        .send_application_data(&transmit.data.build())
                        .unwrap();
                    client.poll(now);
                    let Some(data) = client.poll_encrypted() else {
                        continue;
                    };
                    return Some(TransmitBuild::new(
                        DelayedMessageOrChannelSend::Owned(data),
                        transmit.transport,
                        listen_address,
                        client.client_addr,
                    ));
                } else {
                    let transmit = transmit.build();
                    return Some(TransmitBuild::new(
                        DelayedMessageOrChannelSend::Owned(transmit.data),
                        transmit.transport,
                        transmit.from,
                        transmit.to,
                    ));
                }
            }
            None
        } else if let Some(transmit) = self.server.recv(transmit, now) {
            // incoming allocated address
            if transmit.from == listen_address {
                let Some(client) = self
                    .clients
                    .iter_mut()
                    .find(|client| transmit.to == client.client_addr)
                else {
                    return Some(transmit);
                };

                let _ = client.dtls.send_application_data(&transmit.data.build());
                client.poll(now);
                client.poll_encrypted().map(|encrypted| {
                    TransmitBuild::new(
                        DelayedMessageOrChannelSend::Owned(encrypted),
                        transmit.transport,
                        listen_address,
                        client.client_addr,
                    )
                })
            } else {
                Some(transmit)
            }
        } else {
            None
        }
    }

    fn recv_icmp<T: AsRef<[u8]>>(
        &mut self,
        family: AddressFamily,
        bytes: T,
        now: Instant,
    ) -> Option<Transmit<Vec<u8>>> {
        let transmit = self.server.recv_icmp(family, bytes, now)?;
        // incoming allocated address
        let listen_address = self.listen_address();
        if transmit.from == listen_address {
            let Some(client) = self
                .clients
                .iter_mut()
                .find(|client| transmit.to == client.client_addr)
            else {
                return Some(transmit);
            };

            client.dtls.send_application_data(&transmit.data).unwrap();
            client.poll(now);
            client.poll_encrypted().map(|encrypted| {
                Transmit::new(
                    encrypted,
                    transmit.transport,
                    listen_address,
                    client.client_addr,
                )
            })
        } else {
            Some(transmit)
        }
    }

    /// Poll the [`TurnServer`] in order to make further progress.
    ///
    /// The returned value indicates what the caller should do.
    fn poll(&mut self, now: Instant) -> TurnServerPollRet {
        let protocol_ret = self.server.poll(now);
        let mut have_pending = false;
        for client in self.clients.iter_mut() {
            client.poll(now);
            if !client.pending_encrypted.is_empty() {
                have_pending = true;
                continue;
            }
        }
        if have_pending {
            return TurnServerPollRet::WaitUntil(now);
        }
        protocol_ret
    }

    /// Poll for a new Transmit to send over a socket.
    fn poll_transmit(&mut self, now: Instant) -> Option<Transmit<Vec<u8>>> {
        let listen_address = self.listen_address();

        for client in self.clients.iter_mut() {
            if let Some(data) = client.poll_encrypted() {
                return Some(Transmit::new(
                    data,
                    TransportType::Udp,
                    listen_address,
                    client.client_addr,
                ));
            }
        }

        while let Some(transmit) = self.server.poll_transmit(now) {
            let Some(client) = self
                .clients
                .iter_mut()
                .find(|client| transmit.to == client.client_addr)
            else {
                warn!("return transmit: {transmit:?}");
                return Some(transmit);
            };
            client.dtls.send_application_data(&transmit.data).unwrap();
            client.poll(now);

            if let Some(data) = client.poll_encrypted() {
                return Some(Transmit::new(
                    data,
                    TransportType::Udp,
                    listen_address,
                    client.client_addr,
                ));
            }
        }
        None
    }

    /// Notify the [`TurnServer`] that a socket has been allocated (or an error) in response to
    /// [TurnServerPollRet::AllocateSocket].
    fn allocated_socket(
        &mut self,
        transport: TransportType,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        allocation_transport: TransportType,
        family: AddressFamily,
        socket_addr: Result<SocketAddr, SocketAllocateError>,
        now: Instant,
    ) {
        self.server.allocated_socket(
            transport,
            local_addr,
            remote_addr,
            allocation_transport,
            family,
            socket_addr,
            now,
        )
    }

    fn tcp_connected(
        &mut self,
        relayed_addr: SocketAddr,
        peer_addr: SocketAddr,
        listen_addr: SocketAddr,
        client_addr: SocketAddr,
        socket_addr: Result<SocketAddr, crate::api::TcpConnectError>,
        now: Instant,
    ) {
        self.server.tcp_connected(
            relayed_addr,
            peer_addr,
            listen_addr,
            client_addr,
            socket_addr,
            now,
        )
    }
}
