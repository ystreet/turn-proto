// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! A TURN server that can handle TLS client connections.

use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::{ServerConfig, ServerConnection};
use stun_proto::agent::{StunError, Transmit};
use tracing::{info, trace, warn};
use turn_types::stun::TransportType;

use crate::api::{TurnServerApi, TurnServerPollRet};
use crate::server::TurnServer;

/// A TURN server that can handle TLS connections.
#[derive(Debug)]
pub struct RustlsTurnServer {
    server: TurnServer,
    config: Arc<ServerConfig>,
    connections: Vec<(SocketAddr, ServerConnection)>,
}

impl RustlsTurnServer {
    /// Construct a now Turn server that can handle TLS connections.
    pub fn new(listen_addr: SocketAddr, realm: String, config: Arc<ServerConfig>) -> Self {
        Self {
            server: TurnServer::new(TransportType::Tcp, listen_addr, realm),
            config,
            connections: vec![],
        }
    }
}

impl TurnServerApi for RustlsTurnServer {
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
        name = "turn_server_rustls_recv",
        skip(self, transmit, now),
        fields(
            from = ?transmit.from,
            data_len = transmit.data.as_ref().len()
        )
    )]
    fn recv<T: AsRef<[u8]>>(
        &mut self,
        transmit: Transmit<T>,
        now: Instant,
    ) -> Result<Option<Transmit<Vec<u8>>>, StunError> {
        let listen_address = self.listen_address();
        if transmit.transport == TransportType::Tcp && transmit.to == listen_address {
            trace!("receiving TLS data: {:x?}", transmit.data.as_ref());
            // incoming client
            let (client_addr, conn) = match self
                .connections
                .iter_mut()
                .find(|(client_addr, _conn)| *client_addr == transmit.from)
            {
                Some((client_addr, conn)) => (*client_addr, conn),
                None => {
                    let len = self.connections.len();
                    self.connections.push((
                        transmit.from,
                        ServerConnection::new(self.config.clone()).unwrap(),
                    ));
                    info!("new connection from {}", transmit.from);
                    let ret = &mut self.connections[len];
                    (ret.0, &mut ret.1)
                }
            };
            let mut input = std::io::Cursor::new(transmit.data.as_ref());
            let io_state = match conn.read_tls(&mut input) {
                Ok(_written) => match conn.process_new_packets() {
                    Ok(io_state) => io_state,
                    Err(e) => {
                        warn!("Error processing incoming TLS: {e:?}");
                        return Ok(None);
                    }
                },
                Err(e) => {
                    warn!("Error receiving data: {e:?}");
                    return Err(StunError::ProtocolViolation);
                }
            };
            if io_state.plaintext_bytes_to_read() == 0 {
                return Ok(None);
            }
            let mut vec = vec![0; 2048];
            let n = match conn.reader().read(&mut vec) {
                Ok(n) => n,
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        return Ok(None);
                    } else {
                        warn!("TLS error: {e:?}");
                        return Err(StunError::ProtocolViolation);
                    }
                }
            };
            tracing::error!("io_state: {io_state:?}, n: {n}");
            vec.resize(n, 0);
            let Some(transmit) = self.server.recv(
                Transmit::new(vec, transmit.transport, transmit.from, transmit.to),
                now,
            )?
            else {
                return Ok(None);
            };
            if transmit.transport == TransportType::Tcp
                && transmit.from == listen_address
                && transmit.to == client_addr
            {
                conn.writer().write_all(&transmit.data).unwrap();
                let mut out = vec![];
                conn.write_tls(&mut out).unwrap();
                Ok(Some(Transmit::new(
                    out,
                    TransportType::Tcp,
                    listen_address,
                    client_addr,
                )))
            } else {
                Ok(Some(transmit))
            }
        } else if let Some(transmit) = self.server.recv(transmit, now)? {
            // incoming allocated address
            if transmit.transport == TransportType::Tcp && transmit.from == listen_address {
                let Some((client_addr, conn)) = self
                    .connections
                    .iter_mut()
                    .find(|(client_addr, _conn)| transmit.to == *client_addr)
                else {
                    return Ok(Some(transmit));
                };
                conn.writer().write_all(&transmit.data).unwrap();
                let mut out = vec![];
                conn.write_tls(&mut out).unwrap();
                Ok(Some(Transmit::new(
                    out,
                    TransportType::Tcp,
                    listen_address,
                    *client_addr,
                )))
            } else {
                Ok(Some(transmit))
            }
        } else {
            Ok(None)
        }
    }

    /// Poll the [`TurnServer`] in order to make further progress.
    ///
    /// The returned value indicates what the caller should do.
    fn poll(&mut self, now: Instant) -> TurnServerPollRet {
        let protocol_ret = self.server.poll(now);
        let mut have_pending = false;
        for (_client_addr, conn) in self.connections.iter_mut() {
            let io_state = match conn.process_new_packets() {
                Ok(io_state) => io_state,
                Err(e) => {
                    warn!("Error processing TLS: {e:?}");
                    continue;
                }
            };
            if io_state.tls_bytes_to_write() > 0 {
                have_pending = true;
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

        while let Some(transmit) = self.server.poll_transmit(now) {
            let Some((_client_addr, conn)) = self
                .connections
                .iter_mut()
                .find(|(client_addr, _conn)| transmit.to == *client_addr)
            else {
                warn!("return transmit: {transmit:?}");
                return Some(transmit);
            };
            conn.writer().write_all(&transmit.data).unwrap();
        }

        for (client_addr, conn) in self.connections.iter_mut() {
            if !conn.wants_write() {
                continue;
            }
            let mut vec = vec![];
            let n = match conn.write_tls(&mut vec) {
                Ok(n) => n,
                Err(e) => {
                    warn!("error writing TLS: {e:?}");
                    continue;
                }
            };
            vec.resize(n, 0);
            warn!("return transmit: {vec:x?}");
            return Some(Transmit::new(
                vec,
                TransportType::Tcp,
                listen_address,
                *client_addr,
            ));
        }
        None
    }

    /// Notify the [`TurnServer`] that a UDP socket has been allocated (or an error) in response to
    /// [TurnServerPollRet::AllocateSocketUdp].
    fn allocated_udp_socket(
        &mut self,
        transport: TransportType,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        socket_addr: Result<SocketAddr, ()>,
        now: Instant,
    ) {
        self.server
            .allocated_udp_socket(transport, local_addr, remote_addr, socket_addr, now)
    }
}
