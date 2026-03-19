// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! #turn-client-openssl
//!
//! TLS TURN client using OpenSSL.
//!
//! An implementation of a TURN client suitable for TLS over TCP connections and DTLS over UDP
//! connections.

#![deny(missing_debug_implementations)]
#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(clippy::std_instead_of_core)]
#![deny(clippy::std_instead_of_alloc)]
#![no_std]

extern crate alloc;

pub use openssl;

#[cfg(any(feature = "std", test))]
extern crate std;

pub use turn_client_proto::api;

use std::io::{Read, Write};

use alloc::collections::VecDeque;
use alloc::vec;
use alloc::vec::Vec;

use core::net::{IpAddr, SocketAddr};
use core::time::Duration;

use turn_client_proto::types::Instant;
use turn_client_proto::types::TransportType;

use tracing::{info, trace, warn};

use turn_client_proto::api::*;
use turn_client_proto::tcp::TurnClientTcp;
use turn_client_proto::udp::TurnClientUdp;

use openssl::ssl::{
    HandshakeError, MidHandshakeSslStream, ShutdownResult, ShutdownState, Ssl, SslContext,
    SslStream,
};

turn_client_proto::impl_client!(TcpOrUdp, (Udp, TurnClientUdp), (Tcp, TurnClientTcp));

/// A TURN client that communicates over TLS.
#[derive(Debug)]
pub struct TurnClientOpensslTls {
    protocol: TcpOrUdp,
    ssl_context: SslContext,
    sockets: Vec<Socket>,
}

#[derive(Debug)]
struct Socket {
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    handshake: HandshakeState,
    pending_write: VecDeque<Data<'static>>,
    shutdown: ShutdownState,
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
            Self::Init(ssl, bio) => ssl.connect(bio),
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
                    std::io::ErrorKind::ConnectionRefused,
                    "Failure to setup SSL parameters",
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

impl TurnClientOpensslTls {
    /// Allocate an address on a TURN server to relay data to and from peers.
    pub fn allocate(
        transport: TransportType,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        config: TurnConfig,
        ssl_context: SslContext,
    ) -> Self {
        let ssl = Ssl::new(&ssl_context).expect("Cannot create ssl structure");

        Self {
            protocol: match transport {
                TransportType::Udp => {
                    if config.allocation_transport() != TransportType::Udp {
                        panic!("Cannot create a TCP allocation with a UDP connection to the TURN server")
                    }
                    TcpOrUdp::Udp(TurnClientUdp::allocate(local_addr, remote_addr, config))
                }
                TransportType::Tcp => {
                    TcpOrUdp::Tcp(TurnClientTcp::allocate(local_addr, remote_addr, config))
                }
            },
            ssl_context,
            sockets: vec![Socket {
                local_addr,
                remote_addr,
                handshake: HandshakeState::Init(ssl, OsslBio::default()),
                pending_write: VecDeque::default(),
                shutdown: ShutdownState::empty(),
            }],
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
            match socket.handshake.complete() {
                Ok(stream) => {
                    for data in socket.pending_write.drain(..) {
                        warn!("write early data, {} bytes", data.len());
                        stream.write_all(&data).unwrap()
                    }
                    stream.write_all(&transmit.data).unwrap()
                }
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        warn!("early data ({} bytes), storing", transmit.data.len());
                        socket.pending_write.push_back(transmit.data);
                    } else {
                        warn!("Failure to send data: {e:?}");
                        continue;
                    }
                }
            }
        }
    }
}

impl TurnClientApi for TurnClientOpensslTls {
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
        let mut have_outgoing = false;
        for (idx, socket) in self.sockets.iter_mut().enumerate() {
            let stream = match socket.handshake.complete() {
                Ok(stream) => stream,
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        is_handshaking = true;
                        continue;
                    } else {
                        warn!("Openssl produced error: {e:?}");
                        return TurnPollRet::Closed;
                    }
                }
            };
            socket.shutdown = stream.get_shutdown();
            if !socket.handshake.inner_mut().outgoing.is_empty() {
                have_outgoing = true;
                continue;
            }
            if socket
                .shutdown
                .contains(ShutdownState::SENT | ShutdownState::RECEIVED)
            {
                let socket = self.sockets.swap_remove(idx);
                if self.transport() == TransportType::Tcp {
                    return TurnPollRet::TcpClose {
                        local_addr: socket.local_addr,
                        remote_addr: socket.remote_addr,
                    };
                } else {
                    have_outgoing = true;
                    break;
                }
            }
        }
        if have_outgoing {
            return TurnPollRet::WaitUntil(now);
        }
        if is_handshaking {
            // FIXME: try to determine a more appropriate timeout for an in progress handshake.
            return TurnPollRet::WaitUntil(now + Duration::from_millis(200));
        }
        let protocol_ret = self.protocol.poll(now);
        if let TurnPollRet::TcpClose {
            local_addr,
            remote_addr,
        } = protocol_ret
        {
            if let Some((idx, socket)) =
                self.sockets.iter_mut().enumerate().find(|(_idx, socket)| {
                    socket.local_addr == local_addr && socket.remote_addr == remote_addr
                })
            {
                if let Ok(stream) = socket.handshake.complete() {
                    let _ = stream.shutdown();
                    socket.shutdown = stream.get_shutdown();
                } else {
                    self.sockets.swap_remove(idx);
                }
                return TurnPollRet::WaitUntil(now);
            }
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
            if let Some(outgoing) = socket.handshake.inner_mut().pop_outgoing() {
                return Some(Transmit::new(
                    outgoing.into_boxed_slice().into(),
                    client_transport,
                    socket.local_addr,
                    socket.remote_addr,
                ));
            }

            let stream = match socket.handshake.complete() {
                Ok(stream) => stream,
                Err(e) => {
                    warn!("handshake error: {e:?}");
                    if let Some(outgoing) = socket.handshake.inner_mut().pop_outgoing() {
                        return Some(Transmit::new(
                            outgoing.into_boxed_slice().into(),
                            client_transport,
                            socket.local_addr,
                            socket.remote_addr,
                        ));
                    } else {
                        return None;
                    }
                }
            };
            for data in socket.pending_write.drain(..) {
                warn!("write early data, {} bytes", data.len());
                stream.write_all(&data).unwrap()
            }
        }
        self.empty_transmit_queue(now);
        for socket in self.sockets.iter_mut() {
            if let Some(outgoing) = socket.handshake.inner_mut().pop_outgoing() {
                return Some(Transmit::new(
                    outgoing.into_boxed_slice().into(),
                    client_transport,
                    socket.local_addr,
                    socket.remote_addr,
                ));
            }
        }
        None
    }

    fn poll_event(&mut self) -> Option<TurnEvent> {
        self.protocol.poll_event()
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
            self.sockets.push(Socket {
                local_addr,
                remote_addr: self.remote_addr(),
                handshake: HandshakeState::Init(
                    Ssl::new(&self.ssl_context).expect("Failed to create SSL"),
                    OsslBio::default(),
                ),
                pending_write: VecDeque::default(),
                shutdown: ShutdownState::empty(),
            });
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
        if let Ok(stream) = socket.handshake.complete() {
            socket.shutdown |= match stream.shutdown() {
                Ok(ShutdownResult::Sent) => ShutdownState::SENT,
                Ok(ShutdownResult::Received) => ShutdownState::RECEIVED,
                Err(e) => {
                    warn!("Failed to close TLS connection: {e:?}");
                    return;
                }
            }
        }
    }

    fn send_to<T: AsRef<[u8]> + core::fmt::Debug>(
        &mut self,
        transport: TransportType,
        to: SocketAddr,
        data: T,
        now: Instant,
    ) -> Result<Option<TransmitBuild<DelayedMessageOrChannelSend<T>>>, SendError> {
        let client_transport = self.transport();
        if let Some(transmit) = self.protocol.send_to(transport, to, data, now)? {
            let Some(socket) = self.sockets.iter_mut().find(|socket| {
                socket.local_addr == transmit.from
                    && socket.remote_addr == transmit.to
                    && !socket.shutdown.contains(ShutdownState::SENT)
            }) else {
                warn!(
                    "no socket for transmit from {} to {}",
                    transmit.from, transmit.to
                );
                return Err(SendError::NoTcpSocket);
            };
            let stream = socket.handshake.complete().expect("No TLS connection yet");
            let transmit = transmit.build();
            for data in socket.pending_write.drain(..) {
                stream.write_all(&data).unwrap()
            }
            if let Err(e) = stream.write_all(&transmit.data) {
                self.protocol.protocol_error();
                warn!("Error when writing plaintext: {e:?}");
                return Err(SendError::NoAllocation);
            }

            if let Some(outgoing) = stream.get_mut().pop_outgoing() {
                return Ok(Some(TransmitBuild::new(
                    DelayedMessageOrChannelSend::OwnedData(outgoing),
                    client_transport,
                    socket.local_addr,
                    socket.remote_addr,
                )));
            }
        }

        Ok(None)
    }

    #[tracing::instrument(
        name = "turn_openssl_recv",
        skip(self, transmit, now),
        fields(
            transport = %transmit.transport,
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
                "received data not directed at us ({} {:?}) but for {} {:?}!",
                self.transport(),
                self.local_addr(),
                transmit.transport,
                transmit.to,
            );
            return TurnRecvRet::Ignored(transmit);
        };

        socket
            .handshake
            .inner_mut()
            .push_incoming(transmit.data.as_ref());

        let stream = match socket.handshake.complete() {
            Ok(stream) => stream,
            Err(e) => {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    return TurnRecvRet::Handled;
                }
                return TurnRecvRet::Ignored(transmit);
            }
        };

        let mut out = vec![0; 2048];
        let len = match stream.read(&mut out) {
            Ok(len) => len,
            Err(e) => {
                if e.kind() != std::io::ErrorKind::WouldBlock {
                    self.protocol.protocol_error();
                    tracing::warn!("Error: {e}");
                }
                return TurnRecvRet::Ignored(transmit);
            }
        };
        out.resize(len, 0);

        let transmit = Transmit::new(out, transmit.transport, transmit.from, transmit.to);

        match self.protocol.recv(transmit, now) {
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
        }
    }

    fn poll_recv(&mut self, now: Instant) -> Option<TurnPeerData<Vec<u8>>> {
        self.protocol.poll_recv(now)
    }

    fn protocol_error(&mut self) {
        self.protocol.protocol_error()
    }
}
