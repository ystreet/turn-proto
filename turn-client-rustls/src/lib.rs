// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! #turn-client-rustls
//!
//! TLS TURN client using Rustls.
//!
//! An implementation of a TURN client suitable for TLS over TCP connections connections.
//!
//! ## Crypto providers
//!
//! `turn-client-rustls` does not enable any cryptographic providers on rustls.
//! It is the user's responsibility (library or application) to enable and use
//! the relevant cryptographic provider (ring, aws-lc-rs, RustCrypto, etc),
//! that they wish to use.

#![deny(missing_debug_implementations)]
#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(clippy::std_instead_of_core)]
#![deny(clippy::std_instead_of_alloc)]
#![no_std]

extern crate alloc;

#[cfg(any(feature = "std", test))]
extern crate std;

pub use rustls;

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::net::{IpAddr, SocketAddr};
use core::time::Duration;
use std::io::{Read, Write};

use turn_client_proto::types::Instant;
use turn_client_proto::types::TransportType;

pub use turn_client_proto as proto;
pub use turn_client_proto::api::*;

use turn_client_proto::tcp::TurnClientTcp;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection};

use tracing::{debug, trace, warn};

/// A TURN client that communicates over TLS.
#[derive(Debug)]
pub struct TurnClientRustls {
    protocol: TurnClientTcp,
    tls_config: Arc<ClientConfig>,
    server_name: ServerName<'static>,
    pending_allocates: Vec<(u32, Socket5Tuple, SocketAddr)>,
    sockets: Vec<Socket>,
}

#[derive(Debug)]
struct Socket {
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    tls: ClientConnection,
    peer_closed: bool,
    local_closed: bool,
}

impl TurnClientRustls {
    /// Allocate an address on a TURN server to relay data to and from peers.
    #[allow(clippy::too_many_arguments)]
    pub fn allocate(
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        config: TurnConfig,
        server_name: ServerName<'static>,
        tls_config: Arc<ClientConfig>,
    ) -> Self {
        Self {
            protocol: TurnClientTcp::allocate(local_addr, remote_addr, config),
            sockets: vec![Socket {
                local_addr,
                remote_addr,
                tls: ClientConnection::new(tls_config.clone(), server_name.clone()).unwrap(),
                local_closed: false,
                peer_closed: false,
            }],
            tls_config,
            server_name,
            pending_allocates: vec![],
        }
    }

    fn empty_transmit_queue(&mut self, now: Instant) {
        while let Some(transmit) = self.protocol.poll_transmit(now) {
            let Some(socket) = self.sockets.iter_mut().find(|socket| {
                socket.local_addr == transmit.from && socket.remote_addr == transmit.to
            }) else {
                warn!(
                    "no socket for transmit from {} to {}",
                    transmit.from, transmit.to
                );
                continue;
            };
            socket.tls.writer().write_all(&transmit.data).unwrap();
        }
    }
}

impl TurnClientApi for TurnClientRustls {
    fn transport(&self) -> TransportType {
        self.protocol.transport()
    }

    fn local_addr(&self) -> SocketAddr {
        self.protocol.local_addr()
    }

    fn remote_addr(&self) -> SocketAddr {
        self.protocol.remote_addr()
    }

    fn poll(&mut self, now: Instant) -> TurnPollRet {
        let mut is_handshaking = false;
        let mut protocol_ret = TurnPollRet::Closed;
        for (idx, socket) in self.sockets.iter_mut().enumerate() {
            let io_state = match socket.tls.process_new_packets() {
                Ok(io_state) => io_state,
                Err(e) => {
                    warn!("Error processing TLS: {e:?}");
                    if socket.local_addr == self.protocol.local_addr()
                        && socket.remote_addr == self.protocol.remote_addr()
                    {
                        self.protocol.protocol_error();
                        return TurnPollRet::Closed;
                    } else {
                        // TODO: remove socket?
                        continue;
                    }
                }
            };
            if io_state.peer_has_closed() {
                socket.peer_closed = true;
                if !socket.local_closed {
                    socket.tls.send_close_notify();
                    socket.local_closed = true;
                    trace!("sending close notify");
                    return TurnPollRet::WaitUntil(now);
                }
            }
            let tls_write_bytes = io_state.tls_bytes_to_write();
            if tls_write_bytes > 0 {
                trace!("have {tls_write_bytes} bytes to write");
                return TurnPollRet::WaitUntil(now);
            }
            if socket.peer_closed && socket.local_closed && !socket.tls.wants_write() {
                let socket = self.sockets.remove(idx);
                return TurnPollRet::TcpClose {
                    local_addr: socket.local_addr,
                    remote_addr: socket.remote_addr,
                };
            }
            if socket.local_addr == self.protocol.local_addr()
                && socket.remote_addr == self.protocol.remote_addr()
            {
                protocol_ret = self.protocol.poll(now);
            }
            is_handshaking |= socket.tls.is_handshaking();
        }
        match protocol_ret {
            TurnPollRet::Closed => {
                debug!("Closed");
                return protocol_ret;
            }
            TurnPollRet::AllocateTcpSocket {
                id,
                socket,
                peer_addr,
            } => {
                self.pending_allocates.push((id, socket, peer_addr));
            }
            _ => (),
        }
        if is_handshaking {
            debug!("Currently handshaking, waiting for reply");
            return TurnPollRet::WaitUntil(now + Duration::from_secs(60));
        }
        protocol_ret
    }

    fn relayed_addresses(&self) -> impl Iterator<Item = (TransportType, SocketAddr)> + '_ {
        self.protocol.relayed_addresses()
    }

    fn permissions(
        &self,
        transport: TransportType,
        relayed: SocketAddr,
    ) -> impl Iterator<Item = IpAddr> + '_ {
        self.protocol.permissions(transport, relayed)
    }

    fn poll_transmit(&mut self, now: Instant) -> Option<Transmit<Data<'static>>> {
        let client_transport = self.transport();
        for socket in self.sockets.iter_mut() {
            if socket.tls.is_handshaking() {
                if socket.tls.wants_write() {
                    // TODO: avoid this allocation
                    let mut out = vec![];
                    match socket.tls.write_tls(&mut out) {
                        Ok(_written) => {
                            return Some(Transmit::new(
                                Data::from(out.into_boxed_slice()),
                                client_transport,
                                socket.local_addr,
                                socket.remote_addr,
                            ))
                        }
                        Err(e) => {
                            warn!("error during handshake: {e:?}");
                            if socket.local_addr == self.protocol.local_addr()
                                && socket.remote_addr == self.protocol.remote_addr()
                            {
                                self.protocol.protocol_error();
                                return None;
                            } else {
                                // TODO: remove socket?
                                continue;
                            }
                        }
                    }
                }
                if socket.local_addr == self.protocol.local_addr()
                    && socket.remote_addr == self.protocol.remote_addr()
                {
                    return None;
                }
            }
        }
        self.empty_transmit_queue(now);

        for socket in self.sockets.iter_mut() {
            if socket.tls.wants_write() {
                // TODO: avoid this allocation
                let mut out = vec![];
                match socket.tls.write_tls(&mut out) {
                    Ok(_written) => {
                        return Some(Transmit::new(
                            Data::from(out.into_boxed_slice()),
                            client_transport,
                            socket.local_addr,
                            socket.remote_addr,
                        ))
                    }
                    Err(e) => {
                        warn!("error writing TLS: {e:?}");
                        if socket.local_addr == self.protocol.local_addr()
                            && socket.remote_addr == self.protocol.remote_addr()
                        {
                            self.protocol.protocol_error();
                        } else {
                            // TODO: remove socket?
                            continue;
                        }
                    }
                }
            }
        }
        None
    }

    fn poll_event(&mut self) -> Option<TurnEvent> {
        match self.protocol.poll_event()? {
            TurnEvent::TcpConnected(peer_addr) => Some(TurnEvent::TcpConnected(peer_addr)),
            TurnEvent::TcpConnectFailed(peer_addr) => Some(TurnEvent::TcpConnectFailed(peer_addr)),
            event => Some(event),
        }
    }

    fn delete(&mut self, now: Instant) -> Result<(), DeleteError> {
        self.protocol.delete(now)?;

        self.empty_transmit_queue(now);
        Ok(())
    }

    fn create_permission(
        &mut self,
        transport: TransportType,
        peer_addr: IpAddr,
        now: Instant,
    ) -> Result<(), CreatePermissionError> {
        self.protocol.create_permission(transport, peer_addr, now)?;

        self.empty_transmit_queue(now);

        Ok(())
    }

    fn have_permission(&self, transport: TransportType, to: IpAddr) -> bool {
        self.protocol.have_permission(transport, to)
    }

    fn bind_channel(
        &mut self,
        transport: TransportType,
        peer_addr: SocketAddr,
        now: Instant,
    ) -> Result<(), BindChannelError> {
        self.protocol.bind_channel(transport, peer_addr, now)?;

        self.empty_transmit_queue(now);

        Ok(())
    }

    fn tcp_connect(&mut self, peer_addr: SocketAddr, now: Instant) -> Result<(), TcpConnectError> {
        self.protocol.tcp_connect(peer_addr, now)?;

        self.empty_transmit_queue(now);

        Ok(())
    }

    fn allocated_tcp_socket(
        &mut self,
        id: u32,
        five_tuple: Socket5Tuple,
        peer_addr: SocketAddr,
        local_addr: Option<SocketAddr>,
        now: Instant,
    ) -> Result<(), TcpAllocateError> {
        self.protocol
            .allocated_tcp_socket(id, five_tuple, peer_addr, local_addr, now)?;

        if let Some(local_addr) = local_addr {
            if let Some(idx) = self
                .pending_allocates
                .iter()
                .position(|pending| pending.1 == five_tuple)
            {
                self.pending_allocates.swap_remove(idx);
                self.sockets.push(Socket {
                    local_addr,
                    remote_addr: self.remote_addr(),
                    tls: ClientConnection::new(self.tls_config.clone(), self.server_name.clone())
                        .unwrap(),
                    local_closed: false,
                    peer_closed: false,
                });
            }
        }

        self.empty_transmit_queue(now);
        Ok(())
    }

    fn tcp_closed(&mut self, local_addr: SocketAddr, remote_addr: SocketAddr, now: Instant) {
        let Some(socket) = self
            .sockets
            .iter_mut()
            .find(|socket| socket.local_addr == local_addr && socket.remote_addr == remote_addr)
        else {
            warn!(
                "Unknown socket local:{}, remote:{}",
                local_addr, remote_addr
            );
            return;
        };
        self.protocol.tcp_closed(local_addr, remote_addr, now);
        socket.tls.send_close_notify();
        socket.local_closed = true;
    }

    fn send_to<T: AsRef<[u8]> + core::fmt::Debug>(
        &mut self,
        transport: TransportType,
        to: SocketAddr,
        data: T,
        now: Instant,
    ) -> Result<Option<TransmitBuild<DelayedMessageOrChannelSend<T>>>, SendError> {
        if let Some(transmit) = self.protocol.send_to(transport, to, data, now)? {
            let client_transport = self.transport();
            let transmit = transmit.build();
            let Some(socket) = self.sockets.iter_mut().find(|socket| {
                socket.local_addr == transmit.from
                    && socket.remote_addr == transmit.to
                    && !socket.local_closed
            }) else {
                warn!(
                    "no socket for transmit from {} to {}",
                    transmit.from, transmit.to
                );
                return Err(SendError::NoTcpSocket);
            };
            if let Err(e) = socket.tls.writer().write_all(&transmit.data) {
                warn!("Error when writing plaintext: {e:?}");
                if socket.local_addr == self.protocol.local_addr()
                    && socket.remote_addr == self.protocol.remote_addr()
                {
                    self.protocol.protocol_error();
                    return Err(SendError::NoAllocation);
                } else {
                    return Err(SendError::NoTcpSocket);
                }
            }

            if socket.tls.wants_write() {
                let mut out = vec![];
                match socket.tls.write_tls(&mut out) {
                    Ok(_n) => {
                        return Ok(Some(TransmitBuild::new(
                            DelayedMessageOrChannelSend::OwnedData(out),
                            client_transport,
                            socket.local_addr,
                            socket.remote_addr,
                        )))
                    }
                    Err(e) => {
                        warn!("Error when writing TLS records: {e:?}");
                        if socket.local_addr == self.protocol.local_addr()
                            && socket.remote_addr == self.protocol.remote_addr()
                        {
                            self.protocol.protocol_error();
                            return Err(SendError::NoAllocation);
                        } else {
                            return Err(SendError::NoTcpSocket);
                        }
                    }
                }
            }
        }

        Ok(None)
    }

    #[tracing::instrument(
        name = "turn_rustls_recv",
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
    ) -> TurnRecvRet<T> {
        /* is this data for our client? */
        if self.transport() != transmit.transport {
            return TurnRecvRet::Ignored(transmit);
        }
        let Some(socket) = self
            .sockets
            .iter_mut()
            .find(|socket| socket.local_addr == transmit.to && socket.remote_addr == transmit.from)
        else {
            trace!(
                "received data not directed at us ({:?}) but for {:?}!",
                self.local_addr(),
                transmit.to
            );
            return TurnRecvRet::Ignored(transmit);
        };
        let mut data = std::io::Cursor::new(transmit.data.as_ref());

        let io_state = match socket.tls.read_tls(&mut data) {
            Ok(_written) => match socket.tls.process_new_packets() {
                Ok(io_state) => io_state,
                Err(e) => {
                    self.protocol.protocol_error();
                    warn!("Error processing TLS: {e:?}");
                    return TurnRecvRet::Ignored(transmit);
                }
            },
            Err(e) => {
                warn!("Error receiving data: {e:?}");
                self.protocol.protocol_error();
                return TurnRecvRet::Ignored(transmit);
            }
        };
        if io_state.plaintext_bytes_to_read() > 0 {
            let mut out = vec![0; 2048];
            let n = match socket.tls.reader().read(&mut out) {
                Ok(n) => n,
                Err(e) => {
                    warn!("Error receiving data: {e:?}");
                    self.protocol.protocol_error();
                    return TurnRecvRet::Ignored(transmit);
                }
            };
            out.resize(n, 0);
            let transmit = Transmit::new(out, transmit.transport, transmit.from, transmit.to);

            return match self.protocol.recv(transmit, now) {
                TurnRecvRet::Ignored(_) => unreachable!(),
                TurnRecvRet::PeerData(peer_data) => TurnRecvRet::PeerData(peer_data.into_owned()),
                TurnRecvRet::Handled => TurnRecvRet::Handled,
                TurnRecvRet::PeerIcmp {
                    transport,
                    peer,
                    icmp_type,
                    icmp_code,
                    icmp_data,
                } => TurnRecvRet::PeerIcmp {
                    transport,
                    peer,
                    icmp_type,
                    icmp_code,
                    icmp_data,
                },
            };
        }

        TurnRecvRet::Handled
    }

    fn poll_recv(&mut self, now: Instant) -> Option<TurnPeerData<Vec<u8>>> {
        self.protocol.poll_recv(now)
    }

    fn protocol_error(&mut self) {
        self.protocol.protocol_error()
    }
}
