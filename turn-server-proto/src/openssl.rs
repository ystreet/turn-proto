// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! A TURN server that can handle TLS client connections.

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::net::SocketAddr;
use core::time::Duration;
use std::io::{Read, Write};
use turn_types::prelude::DelayedTransmitBuild;
use turn_types::transmit::TransmitBuild;
use turn_types::AddressFamily;

use openssl::ssl::{HandshakeError, MidHandshakeSslStream, Ssl, SslContext, SslStream};
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
pub struct OpensslTurnServer {
    server: TurnServer,
    ssl_context: SslContext,
    connections: Vec<(SocketAddr, HandshakeState)>,
}

#[derive(Debug)]
enum HandshakeState {
    Init(Ssl, OsslBio),
    Handshaking(MidHandshakeSslStream<OsslBio>),
    Done(SslStream<OsslBio>),
    Nothing,
}

impl HandshakeState {
    fn complete(&mut self) -> Result<&mut SslStream<OsslBio>, std::io::Error> {
        if let Self::Done(s) = self {
            return Ok(s);
        }
        let taken = core::mem::replace(self, Self::Nothing);

        let ret = match taken {
            Self::Init(ssl, bio) => ssl.accept(bio),
            Self::Handshaking(mid) => mid.handshake(),
            Self::Done(_) | Self::Nothing => unreachable!(),
        };

        match ret {
            Ok(s) => {
                info!(
                    "SSL handshake completed with version {} cipher: {:?}",
                    s.ssl().version_str(),
                    s.ssl().current_cipher()
                );
                *self = Self::Done(s);
                Ok(self.complete()?)
            }
            Err(HandshakeError::WouldBlock(mid)) => {
                *self = Self::Handshaking(mid);
                Err(std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    "Would Block",
                ))
            }
            Err(HandshakeError::SetupFailure(e)) => {
                warn!("Error during ssl setup: {e}");
                Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    e,
                ))
            }
            Err(HandshakeError::Failure(mid)) => {
                warn!("Failure during ssl setup: {}", mid.error());
                *self = Self::Handshaking(mid);
                Err(std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    "Would Block",
                ))
            }
        }
    }
    fn inner_mut(&mut self) -> &mut OsslBio {
        match self {
            Self::Init(_ssl, stream) => stream,
            Self::Handshaking(mid) => mid.get_mut(),
            Self::Done(stream) => stream.get_mut(),
            Self::Nothing => unreachable!(),
        }
    }
}

#[derive(Debug, Default)]
struct OsslBio {
    incoming: Vec<u8>,
    outgoing: VecDeque<Vec<u8>>,
}

impl OsslBio {
    fn push_incoming(&mut self, buf: &[u8]) {
        self.incoming.extend_from_slice(buf)
    }

    fn pop_outgoing(&mut self) -> Option<Vec<u8>> {
        self.outgoing.pop_front()
    }
}

impl std::io::Write for OsslBio {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.outgoing.push_back(buf.to_vec());
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl std::io::Read for OsslBio {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let len = self.incoming.len();
        let max = buf.len().min(len);

        if len == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "Would Block",
            ));
        }

        buf[..max].copy_from_slice(&self.incoming[..max]);
        if max == len {
            self.incoming.truncate(0);
        } else {
            self.incoming.drain(..max);
        }

        Ok(max)
    }
}

impl OpensslTurnServer {
    /// Construct a now Turn server that can handle TLS connections.
    pub fn new(
        transport: TransportType,
        listen_addr: SocketAddr,
        realm: String,
        ssl_context: SslContext,
    ) -> Self {
        Self {
            server: TurnServer::new(transport, listen_addr, realm),
            ssl_context,
            connections: vec![],
        }
    }
}

impl TurnServerApi for OpensslTurnServer {
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
        name = "turn_server_openssl_recv",
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
                    let ssl = Ssl::new(&self.ssl_context).expect("Cannot create ssl structure");
                    self.connections
                        .push((transmit.from, HandshakeState::Init(ssl, OsslBio::default())));
                    info!("new connection from {}", transmit.from);
                    let ret = &mut self.connections[len];
                    (ret.0, &mut ret.1)
                }
            };
            conn.inner_mut().push_incoming(transmit.data.as_ref());
            let stream = match conn.complete() {
                Ok(s) => s,
                Err(e) => {
                    if e.kind() != std::io::ErrorKind::WouldBlock {
                        warn!("error accepting TLS: {e}");
                    }
                    return None;
                }
            };

            let mut plaintext = vec![0; 2048];
            let len = match stream.read(&mut plaintext) {
                Ok(len) => len,
                Err(e) => {
                    if e.kind() != std::io::ErrorKind::WouldBlock {
                        tracing::warn!("Error: {e}");
                    }
                    return None;
                }
            };
            plaintext.resize(len, 0);

            let transmit = self.server.recv(
                Transmit::new(plaintext, transmit.transport, transmit.from, transmit.to),
                now,
            )?;

            if transmit.transport == TransportType::Tcp
                && transmit.from == listen_address
                && transmit.to == client_addr
            {
                let plaintext = transmit.data.build();
                stream.write_all(&plaintext).unwrap();
                stream.get_mut().pop_outgoing().map(|data| {
                    TransmitBuild::new(
                        DelayedMessageOrChannelSend::Owned(data),
                        TransportType::Tcp,
                        listen_address,
                        client_addr,
                    )
                })
            } else {
                let transmit = transmit.build();
                Some(TransmitBuild::new(
                    DelayedMessageOrChannelSend::Owned(transmit.data),
                    transmit.transport,
                    transmit.from,
                    transmit.to,
                ))
            }
        } else if let Some(transmit) = self.server.recv(transmit, now) {
            // incoming allocated address
            if transmit.transport == TransportType::Tcp && transmit.from == listen_address {
                let Some((client_addr, conn)) = self
                    .connections
                    .iter_mut()
                    .find(|(client_addr, _conn)| transmit.to == *client_addr)
                else {
                    return Some(transmit);
                };

                let plaintext = transmit.data.build();
                let stream = match conn.complete() {
                    Ok(s) => s,
                    Err(e) => {
                        if e.kind() != std::io::ErrorKind::WouldBlock {
                            warn!("error accepting TLS: {e}");
                        }
                        return None;
                    }
                };
                stream.write_all(&plaintext).unwrap();
                stream.get_mut().pop_outgoing().map(|data| {
                    TransmitBuild::new(
                        DelayedMessageOrChannelSend::Owned(data),
                        TransportType::Tcp,
                        listen_address,
                        *client_addr,
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
        if transmit.transport == TransportType::Tcp && transmit.from == listen_address {
            let Some((client_addr, conn)) = self
                .connections
                .iter_mut()
                .find(|(client_addr, _conn)| transmit.to == *client_addr)
            else {
                return Some(transmit);
            };
            let stream = match conn.complete() {
                Ok(s) => s,
                Err(e) => {
                    if e.kind() != std::io::ErrorKind::WouldBlock {
                        warn!("error accepting TLS: {e}");
                    }
                    return None;
                }
            };
            stream.write_all(&transmit.data).unwrap();
            stream
                .get_mut()
                .pop_outgoing()
                .map(|data| Transmit::new(data, TransportType::Tcp, listen_address, *client_addr))
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
        for (_client_addr, conn) in self.connections.iter_mut() {
            let stream = match conn.complete() {
                Ok(s) => s,
                Err(_) => continue,
            };
            if !stream.get_mut().outgoing.is_empty() {
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

        for (client_addr, conn) in self.connections.iter_mut() {
            if let Some(data) = conn.inner_mut().pop_outgoing() {
                return Some(Transmit::new(
                    data,
                    TransportType::Tcp,
                    listen_address,
                    *client_addr,
                ));
            }
        }

        while let Some(transmit) = self.server.poll_transmit(now) {
            let Some((client_addr, conn)) = self
                .connections
                .iter_mut()
                .find(|(client_addr, _conn)| transmit.to == *client_addr)
            else {
                warn!("return transmit: {transmit:?}");
                return Some(transmit);
            };
            let stream = match conn.complete() {
                Ok(s) => s,
                // FIXME: how to deal with early data
                Err(_) => continue,
            };
            stream.write_all(&transmit.data).unwrap();

            if let Some(data) = conn.inner_mut().pop_outgoing() {
                return Some(Transmit::new(
                    data,
                    TransportType::Tcp,
                    listen_address,
                    *client_addr,
                ));
            }
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
        family: AddressFamily,
        socket_addr: Result<SocketAddr, SocketAllocateError>,
        now: Instant,
    ) {
        self.server.allocated_udp_socket(
            transport,
            local_addr,
            remote_addr,
            family,
            socket_addr,
            now,
        )
    }
}
