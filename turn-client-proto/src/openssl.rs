// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! TLS TURN client using OpenSSL.
//!
//! An implementation of a TURN client suitable for TLS over TCP connections and DTLS over UDP
//! connections.

use alloc::collections::VecDeque;
use alloc::vec;
use alloc::vec::Vec;
use core::net::{IpAddr, SocketAddr};
use core::time::Duration;
use openssl::ssl::{
    HandshakeError, MidHandshakeSslStream, ShutdownResult, ShutdownState, Ssl, SslContext,
    SslStream,
};
use std::io::{Read, Write};

use stun_proto::agent::Transmit;
use stun_proto::types::data::Data;
use stun_proto::Instant;

use stun_proto::types::TransportType;

use turn_types::AddressFamily;
use turn_types::TurnCredentials;

use tracing::{info, trace, warn};

use crate::api::{
    DelayedMessageOrChannelSend, Socket5Tuple, TcpAllocateError, TcpConnectError, TransmitBuild,
    TurnClientApi, TurnPeerData,
};

pub use crate::api::{
    BindChannelError, CreatePermissionError, DeleteError, SendError, TurnEvent, TurnPollRet,
    TurnRecvRet,
};
use crate::tcp::TurnClientTcp;
use crate::udp::TurnClientUdp;

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

crate::client::impl_client!(TcpOrUdp, (Udp, TurnClientUdp), (Tcp, TurnClientTcp));

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
        credentials: TurnCredentials,
        allocation_transport: TransportType,
        allocation_families: &[AddressFamily],
        ssl_context: SslContext,
    ) -> Self {
        let ssl = Ssl::new(&ssl_context).expect("Cannot create ssl structure");

        Self {
            protocol: match transport {
                TransportType::Udp => {
                    if allocation_transport != TransportType::Udp {
                        panic!("Cannot create a TCP allocation with a UDP connection to the TURN server")
                    }
                    TcpOrUdp::Udp(TurnClientUdp::allocate(
                        local_addr,
                        remote_addr,
                        credentials,
                        allocation_families,
                    ))
                }
                TransportType::Tcp => TcpOrUdp::Tcp(TurnClientTcp::allocate(
                    local_addr,
                    remote_addr,
                    credentials,
                    allocation_transport,
                    allocation_families,
                )),
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

#[cfg(test)]
mod tests {
    use alloc::string::{String, ToString};
    use core::time::Duration;
    use openssl::ssl::SslMethod;
    use tracing::debug;
    use turn_server_proto::openssl::OpensslTurnServer;

    use crate::api::tests::{transmit_send_build, TurnTest};
    use crate::client::TurnClient;
    use turn_types::message::CREATE_PERMISSION;
    use turn_types::stun::message::{Message, MessageType, MessageWriteVec, TransactionId};
    use turn_types::stun::prelude::MessageWrite;

    use super::*;

    use rcgen::CertifiedKey;
    use turn_server_proto::api::{TurnServerApi, TurnServerPollRet};

    fn test_ssl_context(transport: TransportType) -> SslContext {
        let method = match transport {
            TransportType::Udp => SslMethod::dtls_client(),
            TransportType::Tcp => SslMethod::tls_client(),
        };
        let mut builder = SslContext::builder(method).unwrap();
        builder.set_cipher_list("HIGH+TLSv1.2:!aNULL:!MD5").unwrap();
        builder.build()
    }

    fn test_openssl_server_config(transport: TransportType) -> SslContext {
        let CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let method = match transport {
            TransportType::Udp => SslMethod::dtls_server(),
            TransportType::Tcp => SslMethod::tls_server(),
        };
        let mut builder = SslContext::builder(method).unwrap();
        let cert = openssl::x509::X509::from_der(cert.der()).unwrap();
        builder.set_certificate(&cert).unwrap();
        let pkey = openssl::pkey::PKey::private_key_from_der(signing_key.serialized_der()).unwrap();
        builder.set_private_key(&pkey).unwrap();
        builder.set_verify_callback(openssl::ssl::SslVerifyMode::NONE, |_ok, _store| true);
        builder.set_client_hello_callback(|ssl, _alert| {
            if let Some(ciphers) = ssl.client_hello_ciphers() {
                debug!(
                    "hello cipher list: {:?}",
                    ssl.bytes_to_cipher_list(ciphers, false).unwrap()
                );
            }
            Ok(openssl::ssl::ClientHelloResponse::SUCCESS)
        });
        builder.set_cipher_list("HIGH+TLSv1.2:!aNULL:!MD5").unwrap();
        builder.build()
    }

    fn turn_openssl_new(
        transport: TransportType,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        credentials: TurnCredentials,
        allocation_transport: TransportType,
    ) -> TurnClient {
        TurnClientOpensslTls::allocate(
            transport,
            local_addr,
            remote_addr,
            credentials,
            allocation_transport,
            &[AddressFamily::IPV4],
            test_ssl_context(transport),
        )
        .into()
    }

    fn turn_tcp_openssl_new(
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        credentials: TurnCredentials,
        allocation_transport: TransportType,
    ) -> TurnClient {
        turn_openssl_new(
            TransportType::Tcp,
            local_addr,
            remote_addr,
            credentials,
            allocation_transport,
        )
    }

    fn turn_udp_openssl_new(
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        credentials: TurnCredentials,
        allocation_transport: TransportType,
    ) -> TurnClient {
        turn_openssl_new(
            TransportType::Udp,
            local_addr,
            remote_addr,
            credentials,
            allocation_transport,
        )
    }

    fn turn_server_openssl_new(
        transport: TransportType,
        listen_address: SocketAddr,
        realm: String,
    ) -> OpensslTurnServer {
        OpensslTurnServer::new(
            transport,
            listen_address,
            realm,
            test_openssl_server_config(transport),
        )
    }

    fn turn_udp_server_openssl_new(listen_address: SocketAddr, realm: String) -> OpensslTurnServer {
        turn_server_openssl_new(TransportType::Udp, listen_address, realm)
    }

    fn turn_tcp_server_openssl_new(listen_address: SocketAddr, realm: String) -> OpensslTurnServer {
        turn_server_openssl_new(TransportType::Tcp, listen_address, realm)
    }

    fn create_test(transport: TransportType) -> TurnTest<TurnClient, OpensslTurnServer> {
        match transport {
            TransportType::Udp => TurnTest::<TurnClient, OpensslTurnServer>::builder()
                .build(turn_udp_openssl_new, turn_udp_server_openssl_new),
            TransportType::Tcp => TurnTest::<TurnClient, OpensslTurnServer>::builder()
                .build(turn_tcp_openssl_new, turn_tcp_server_openssl_new),
        }
    }

    fn complete_io<A: TurnClientApi, S: TurnServerApi>(test: &mut TurnTest<A, S>, now: Instant) {
        loop {
            let mut handled = false;
            test.client.poll(now);
            test.server.poll(now);
            if let Some(transmit) = test.client.poll_transmit(now) {
                handled = true;
                trace!("have transmit: {transmit:?}");
                if let Some(transmit) = test.server.recv(transmit, now) {
                    trace!("have transmit: {transmit:?}");
                    test.client.recv(transmit.build(), now);
                }
            }
            if let Some(transmit) = test.server.poll_transmit(now) {
                handled = true;
                trace!("have transmit: {transmit:?}");
                test.client_recv(transmit, now);
            }
            if !handled {
                break;
            }
        }
    }

    fn allocate<A: TurnClientApi, S: TurnServerApi>(test: &mut TurnTest<A, S>, now: Instant) {
        complete_io(test, now);
        test.server.allocated_socket(
            test.client.transport(),
            test.client.remote_addr(),
            test.client.local_addr(),
            test.allocation_transport,
            AddressFamily::IPV4,
            Ok(test.turn_alloc_addr),
            now,
        );
        complete_io(test, now);
        let event = test.client.poll_event().unwrap();
        assert!(matches!(event, TurnEvent::AllocationCreated(_, _)));
        assert_eq!(
            test.client.relayed_addresses().next(),
            Some((test.allocation_transport, test.turn_alloc_addr))
        );
    }

    fn create_permission<A: TurnClientApi, S: TurnServerApi>(
        test: &mut TurnTest<A, S>,
        now: Instant,
    ) {
        test.client
            .create_permission(test.allocation_transport, test.peer_addr.ip(), now)
            .unwrap();
        complete_io(test, now);

        let event = test.client.poll_event().unwrap();
        assert!(matches!(event, TurnEvent::PermissionCreated(_, _)));
        let (transport, relayed) = test.client.relayed_addresses().next().unwrap();
        assert!(test
            .client
            .permissions(transport, relayed)
            .any(|perm_ip| perm_ip == test.peer_addr.ip()));
        assert!(test.client.have_permission(transport, test.peer_addr.ip()));
    }

    fn delete<A: TurnClientApi, S: TurnServerApi>(test: &mut TurnTest<A, S>, now: Instant) {
        test.client.delete(now).unwrap();
        complete_io(test, now);
        assert_eq!(test.client.relayed_addresses().count(), 0);
    }

    fn channel_bind<A: TurnClientApi, S: TurnServerApi>(test: &mut TurnTest<A, S>, now: Instant) {
        test.client
            .bind_channel(test.allocation_transport, test.peer_addr, now)
            .unwrap();
        complete_io(test, now);

        if let Some(event) = test.client.poll_event() {
            assert!(matches!(event, TurnEvent::PermissionCreated(_, _)));
        }
        let (transport, relayed) = test.client.relayed_addresses().next().unwrap();
        assert!(test
            .client
            .permissions(transport, relayed)
            .any(|perm_ip| perm_ip == test.peer_addr.ip()));
        assert!(test.client.have_permission(transport, test.peer_addr.ip()));
    }

    fn sendrecv_data<A: TurnClientApi, S: TurnServerApi>(test: &mut TurnTest<A, S>, now: Instant) {
        // client to peer
        let data = [4; 8];
        let transmit = test
            .client
            .send_to(TransportType::Udp, test.peer_addr, data, now)
            .unwrap()
            .unwrap();
        assert!(matches!(
            transmit.data,
            DelayedMessageOrChannelSend::OwnedData(_)
        ));
        let transmit = transmit_send_build(transmit);
        assert_eq!(transmit.transport, test.client.transport());
        assert_eq!(transmit.from, test.client.local_addr());
        assert_eq!(transmit.to, test.server.listen_address());
        let transmit = test.server.recv(transmit, now).unwrap();
        assert_eq!(transmit.transport, TransportType::Udp);
        assert_eq!(transmit.from, test.turn_alloc_addr);
        assert_eq!(transmit.to, test.peer_addr);

        // peer to client
        let sent_data = [5; 12];
        let transmit = test
            .server
            .recv(
                Transmit::new(
                    sent_data,
                    TransportType::Udp,
                    test.peer_addr,
                    test.turn_alloc_addr,
                ),
                now,
            )
            .unwrap();
        assert_eq!(transmit.transport, test.client.transport());
        assert_eq!(transmit.from, test.server.listen_address());
        assert_eq!(transmit.to, test.client.local_addr());
        let TurnRecvRet::PeerData(peer_data) = test.client.recv(transmit.build(), now) else {
            unreachable!();
        };
        assert_eq!(peer_data.peer, test.peer_addr);
        assert_eq!(peer_data.data(), sent_data);
    }

    #[test]
    fn test_turn_openssl_allocate_udp_permission() {
        let _log = crate::tests::test_init_log();
        for transport in [TransportType::Udp, TransportType::Tcp] {
            let now = Instant::ZERO;
            let mut test = create_test(transport);
            allocate(&mut test, now);
            create_permission(&mut test, now);
            sendrecv_data(&mut test, now);
        }
    }

    #[test]
    fn test_turn_openssl_allocate_refresh() {
        let _log = crate::tests::test_init_log();
        for transport in [TransportType::Udp, TransportType::Tcp] {
            let now = Instant::ZERO;
            let mut test = create_test(transport);
            allocate(&mut test, now);
            let TurnPollRet::WaitUntil(expiry) = test.client.poll(now) else {
                unreachable!();
            };
            assert!(now + Duration::from_secs(1000) < expiry);
            // TODO: removing this (REFRESH handling) produces multiple messages in a single TCP
            // transmit which the server currently does not like.
            complete_io(&mut test, expiry);
            create_permission(&mut test, expiry);
            sendrecv_data(&mut test, expiry);
        }
    }

    #[test]
    fn test_turn_openssl_allocate_delete() {
        let _log = crate::tests::test_init_log();
        for transport in [TransportType::Udp, TransportType::Tcp] {
            let now = Instant::ZERO;
            let mut test = create_test(transport);
            allocate(&mut test, now);
            delete(&mut test, now);
        }
    }

    #[test]
    fn test_turn_openssl_allocate_bind_channel() {
        let _log = crate::tests::test_init_log();
        for transport in [TransportType::Udp, TransportType::Tcp] {
            let now = Instant::ZERO;
            let mut test = create_test(transport);
            allocate(&mut test, now);
            channel_bind(&mut test, now);
            sendrecv_data(&mut test, now);
        }
    }

    #[test]
    fn test_turn_openssl_offpath_data() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        for transport in [TransportType::Udp, TransportType::Tcp] {
            let mut test = create_test(transport);
            allocate(&mut test, now);
            create_permission(&mut test, now);
            let data = Message::builder(
                MessageType::from_class_method(
                    turn_types::stun::message::MessageClass::Error,
                    CREATE_PERMISSION,
                ),
                TransactionId::generate(),
                MessageWriteVec::new(),
            )
            .finish();
            let transmit = Transmit::new(
                data,
                test.client.transport(),
                test.turn_alloc_addr,
                test.client.local_addr(),
            );
            assert!(matches!(
                test.client.recv(transmit, now),
                TurnRecvRet::Ignored(_)
            ));
        }
    }

    fn create_test_tcp_allocation() -> TurnTest<TurnClient, OpensslTurnServer> {
        TurnTest::<TurnClient, OpensslTurnServer>::builder()
            .allocation_transport(TransportType::Tcp)
            .build(turn_tcp_openssl_new, turn_tcp_server_openssl_new)
    }

    fn tcp_connect<A: TurnClientApi, S: TurnServerApi>(test: &mut TurnTest<A, S>, now: Instant) {
        test.client.tcp_connect(test.peer_addr, now).unwrap();
        let transmit = test.client.poll_transmit(now).unwrap();
        assert_eq!(transmit.transport, test.client.transport());
        assert_eq!(transmit.from, test.client.local_addr());
        assert_eq!(transmit.to, test.server.listen_address());
        assert!(test.server.recv(transmit, now).is_none());
        let TurnServerPollRet::TcpConnect {
            relayed_addr,
            peer_addr,
            listen_addr,
            client_addr,
        } = test.server.poll(now)
        else {
            unreachable!();
        };
        assert_eq!(peer_addr, test.peer_addr);
        assert_eq!(listen_addr, test.server.listen_address());
        assert_eq!(client_addr, test.client.local_addr());
        test.server.tcp_connected(
            relayed_addr,
            peer_addr,
            listen_addr,
            client_addr,
            Ok(relayed_addr),
            now,
        );
        let transmit = test.server.poll_transmit(now).unwrap();
        assert_eq!(transmit.from, test.server.listen_address());
        assert_eq!(transmit.to, test.client.local_addr());
        assert_eq!(transmit.transport, test.client.transport());
        assert!(matches!(
            test.client.recv(transmit, now),
            TurnRecvRet::Handled
        ));
        let TurnPollRet::AllocateTcpSocket {
            id,
            socket,
            peer_addr,
        } = test.client.poll(now)
        else {
            unreachable!();
        };
        assert_eq!(socket.transport, TransportType::Tcp);
        assert_eq!(socket.from, test.client.local_addr());
        assert_eq!(socket.to, test.server.listen_address());
        assert_eq!(peer_addr, test.peer_addr);
        test.client
            .allocated_tcp_socket(id, socket, peer_addr, Some(test.local_tcp_socket), now)
            .unwrap();
        complete_io(test, now);

        assert!(matches!(
            test.client.poll_event().unwrap(),
            TurnEvent::TcpConnected(_peer_addr)
        ));
    }

    fn tcp_sendrecv_data<A: TurnClientApi, S: TurnServerApi>(
        test: &mut TurnTest<A, S>,
        now: Instant,
    ) {
        // client to peer
        let data = [4; 8];
        let transmit = test
            .client
            .send_to(TransportType::Tcp, test.peer_addr, data, now)
            .unwrap()
            .unwrap();
        assert!(matches!(
            transmit.data,
            DelayedMessageOrChannelSend::OwnedData(_)
        ));
        let transmit = transmit_send_build(transmit);
        assert_eq!(transmit.transport, test.client.transport());
        assert_eq!(transmit.from, test.local_tcp_socket);
        assert_eq!(transmit.to, test.server.listen_address());
        let transmit = test.server.recv(transmit, now).unwrap();
        let transmit = transmit_send_build(transmit);
        assert_eq!(transmit.transport, TransportType::Tcp);
        assert_eq!(transmit.from, test.turn_alloc_addr);
        assert_eq!(transmit.to, test.peer_addr);
        assert_eq!(transmit.data.as_ref(), data.as_slice());

        // peer to client
        let sent_data = [5; 12];
        let transmit = test
            .server
            .recv(
                Transmit::new(
                    sent_data,
                    TransportType::Tcp,
                    test.peer_addr,
                    test.turn_alloc_addr,
                ),
                now,
            )
            .unwrap();
        assert_eq!(transmit.transport, test.client.transport());
        assert_eq!(transmit.from, test.server.listen_address());
        assert_eq!(transmit.to, test.local_tcp_socket);
        let TurnRecvRet::PeerData(peer_data) = test.client.recv(transmit.build(), now) else {
            unreachable!();
        };
        assert_eq!(peer_data.peer, test.peer_addr);
        assert_eq!(peer_data.data(), sent_data);
    }

    #[test]
    fn test_turn_openssl_tcp_allocation_send_recv_client_close() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut test = create_test_tcp_allocation();
        allocate(&mut test, now);
        create_permission(&mut test, now);
        tcp_connect(&mut test, now);
        tcp_sendrecv_data(&mut test, now);
        assert!(test.client.poll_transmit(now).is_none());
        assert!(test.client.poll_event().is_none());
        test.client
            .tcp_closed(test.local_tcp_socket, test.client.remote_addr(), now);
        let transmit = test.client.poll_transmit(now).unwrap();
        debug!("client transmit {transmit:x?}");
        let transmit = test.server.recv(transmit, now).unwrap().build();
        debug!("server transmit {transmit:x?}");
        assert!(matches!(
            test.client.recv(transmit, now),
            TurnRecvRet::Handled
        ));
        let TurnServerPollRet::TcpClose {
            local_addr,
            remote_addr,
        } = test.server.poll(now)
        else {
            unreachable!();
        };
        assert!(test
            .server
            .recv(
                Transmit::new(
                    [],
                    TransportType::Tcp,
                    test.local_tcp_socket,
                    test.server.listen_address()
                ),
                now
            )
            .is_none());
        assert_eq!(local_addr, test.server.listen_address());
        assert_eq!(remote_addr, test.local_tcp_socket);
        test.client.poll(now);
        assert!(matches!(
            test.client
                .send_to(TransportType::Tcp, test.peer_addr, [0, 1, 2], now),
            Err(SendError::NoTcpSocket)
        ));
    }

    #[test]
    fn test_turn_openssl_tcp_allocation_send_recv_peer_close() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut test = create_test_tcp_allocation();
        allocate(&mut test, now);
        create_permission(&mut test, now);
        tcp_connect(&mut test, now);
        tcp_sendrecv_data(&mut test, now);
        assert!(test.client.poll_transmit(now).is_none());
        assert!(test.client.poll_event().is_none());
        assert!(test
            .server
            .recv(
                Transmit::new(
                    vec![],
                    TransportType::Tcp,
                    test.peer_addr,
                    test.turn_alloc_addr,
                ),
                now,
            )
            .is_none());
        let TurnServerPollRet::WaitUntil(_) = test.server.poll(now) else {
            unreachable!();
        };
        let transmit = test.server.poll_transmit(now).unwrap();
        assert!(matches!(
            test.client.recv(transmit, now),
            TurnRecvRet::Handled
        ));
        test.client.poll(now);
        let transmit = test.client.poll_transmit(now).unwrap();
        debug!("client transmit {transmit:x?}");
        test.client.poll(now);
        assert!(test.server.recv(transmit, now).is_none());
        let TurnServerPollRet::TcpClose {
            local_addr,
            remote_addr,
        } = test.server.poll(now)
        else {
            unreachable!();
        };
        assert_eq!(local_addr, test.server.listen_address());
        assert_eq!(remote_addr, test.local_tcp_socket);
        assert!(matches!(
            test.client
                .send_to(TransportType::Tcp, test.peer_addr, [0, 1, 2], now),
            Err(SendError::NoTcpSocket)
        ));
    }
}
