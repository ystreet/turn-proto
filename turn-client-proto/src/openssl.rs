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
use openssl::ssl::{HandshakeError, MidHandshakeSslStream, Ssl, SslContext, SslStream};
use std::io::{Read, Write};
use turn_types::stun::message::Message;

use stun_proto::agent::{StunAgent, Transmit};
use stun_proto::types::data::Data;
use stun_proto::Instant;

use stun_proto::types::TransportType;

use turn_types::channel::ChannelData;
use turn_types::AddressFamily;
use turn_types::TurnCredentials;

use tracing::{info, trace, warn};

use crate::api::{
    DataRangeOrOwned, DelayedMessageOrChannelSend, TransmitBuild, TurnClientApi, TurnPeerData,
};
use crate::protocol::{TurnClientProtocol, TurnProtocolChannelRecv, TurnProtocolRecv};

pub use crate::api::{
    BindChannelError, CreatePermissionError, DeleteError, SendError, TurnEvent, TurnPollRet,
    TurnRecvRet,
};
use crate::tcp::ensure_data_owned;
use turn_types::tcp::{IncomingTcp, StoredTcp, TurnTcpBuffer};

/// A TURN client that communicates over TLS.
#[derive(Debug)]
pub struct TurnClientOpensslTls {
    protocol: TurnClientProtocol,
    incoming_tcp_buffer: TurnTcpBuffer,
    handshake: HandshakeState,
    closing: bool,
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

impl TurnClientOpensslTls {
    /// Allocate an address on a TURN server to relay data to and from peers.
    pub fn allocate(
        transport: TransportType,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        credentials: TurnCredentials,
        allocation_families: &[AddressFamily],
        ssl_context: SslContext,
    ) -> Self {
        let ssl = Ssl::new(&ssl_context).expect("Cannot create ssl structure");

        let stun_agent = StunAgent::builder(transport, local_addr)
            .remote_addr(remote_addr)
            .build();
        Self {
            protocol: TurnClientProtocol::new(stun_agent, credentials, allocation_families),
            incoming_tcp_buffer: TurnTcpBuffer::new(),
            handshake: HandshakeState::Init(ssl, OsslBio::default()),
            closing: false,
        }
    }

    fn handle_incoming_plaintext<T: AsRef<[u8]> + core::fmt::Debug>(
        &mut self,
        transmit: Transmit<Vec<u8>>,
        now: Instant,
    ) -> TurnRecvRet<T> {
        match self.incoming_tcp_buffer.incoming_tcp(transmit) {
            None => TurnRecvRet::Handled,
            Some(IncomingTcp::CompleteMessage(transmit, msg_range)) => {
                let Ok(msg) =
                    Message::from_bytes(&transmit.data.as_slice()[msg_range.start..msg_range.end])
                else {
                    return TurnRecvRet::Handled;
                };
                TurnRecvRet::from_protocol_recv_stored_ignored(
                    self.protocol.handle_message(msg, now),
                    transmit.data,
                )
            }
            Some(IncomingTcp::CompleteChannel(transmit, msg_range)) => {
                let channel =
                    ChannelData::parse(&transmit.data.as_slice()[msg_range.start..msg_range.end])
                        .unwrap();
                match self.protocol.handle_channel(channel, now) {
                    TurnProtocolChannelRecv::Ignored => TurnRecvRet::Handled,
                    TurnProtocolChannelRecv::PeerData {
                        range,
                        transport,
                        peer,
                    } => TurnRecvRet::PeerData(TurnPeerData {
                        data: DataRangeOrOwned::Owned(ensure_data_owned(transmit.data, range)),
                        transport,
                        peer,
                    }),
                }
            }
            Some(IncomingTcp::StoredMessage(data, transmit)) => {
                let Ok(msg) = Message::from_bytes(&data) else {
                    return TurnRecvRet::Handled;
                };
                TurnRecvRet::from_protocol_recv_stored_ignored(
                    self.protocol.handle_message(msg, now),
                    transmit.data,
                )
            }
            Some(IncomingTcp::StoredChannel(data, transmit)) => {
                let channel = ChannelData::parse(&data).unwrap();
                match self.protocol.handle_channel(channel, now) {
                    TurnProtocolChannelRecv::Ignored => TurnRecvRet::Handled,
                    TurnProtocolChannelRecv::PeerData {
                        range,
                        transport,
                        peer,
                    } => TurnRecvRet::PeerData(TurnPeerData {
                        data: DataRangeOrOwned::Owned(
                            transmit.data[range.start..range.end].to_vec(),
                        ),
                        transport,
                        peer,
                    }),
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
        let protocol_ret = self.protocol.poll(now);
        if !self.handshake.inner_mut().outgoing.is_empty() {
            return TurnPollRet::WaitUntil(now);
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
        if let Some(outgoing) = self.handshake.inner_mut().pop_outgoing() {
            return Some(Transmit::new(
                outgoing.into_boxed_slice().into(),
                self.transport(),
                self.local_addr(),
                self.remote_addr(),
            ));
        }

        let stream = match self.handshake.complete() {
            Ok(stream) => stream,
            Err(_) => {
                if let Some(outgoing) = self.handshake.inner_mut().pop_outgoing() {
                    return Some(Transmit::new(
                        outgoing.into_boxed_slice().into(),
                        self.transport(),
                        self.local_addr(),
                        self.remote_addr(),
                    ));
                } else {
                    return None;
                }
            }
        };

        while let Some(transmit) = self.protocol.poll_transmit(now) {
            stream.write_all(&transmit.data).unwrap();
        }

        self.handshake.inner_mut().pop_outgoing().map(|outgoing| {
            Transmit::new(
                outgoing.into_boxed_slice().into(),
                self.transport(),
                self.local_addr(),
                self.remote_addr(),
            )
        })
    }

    fn poll_event(&mut self) -> Option<TurnEvent> {
        self.protocol.poll_event()
    }

    fn delete(&mut self, now: Instant) -> Result<(), DeleteError> {
        self.protocol.delete(now)?;
        self.closing = true;
        let stream = self.handshake.complete().expect("handshake not completed");

        while let Some(transmit) = self.protocol.poll_transmit(now) {
            stream.write_all(&transmit.data).unwrap();
        }
        stream.shutdown().unwrap();
        Ok(())
    }

    fn create_permission(
        &mut self,
        transport: TransportType,
        peer_addr: IpAddr,
        now: Instant,
    ) -> Result<(), CreatePermissionError> {
        self.protocol.create_permission(transport, peer_addr, now)?;
        let stream = self.handshake.complete().expect("handshake not completed");

        while let Some(transmit) = self.protocol.poll_transmit(now) {
            stream.write_all(&transmit.data).unwrap();
        }

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
        let stream = self.handshake.complete().expect("handshake not completed");

        while let Some(transmit) = self.protocol.poll_transmit(now) {
            stream.write_all(&transmit.data).unwrap();
        }

        Ok(())
    }

    fn send_to<T: AsRef<[u8]> + core::fmt::Debug>(
        &mut self,
        transport: TransportType,
        to: SocketAddr,
        data: T,
        now: Instant,
    ) -> Result<Option<TransmitBuild<DelayedMessageOrChannelSend<T>>>, SendError> {
        let stream = match self.handshake.complete() {
            Ok(stream) => stream,
            Err(_) => return Err(SendError::NoAllocation),
        };
        let transmit = self.protocol.send_to(transport, to, data, now)?;
        let transmit = transmit.build();
        if let Err(e) = stream.write_all(&transmit.data) {
            self.protocol.error();
            warn!("Error when writing plaintext: {e:?}");
            return Err(SendError::NoAllocation);
        }

        if let Some(outgoing) = stream.get_mut().pop_outgoing() {
            return Ok(Some(TransmitBuild::new(
                DelayedMessageOrChannelSend::Data(outgoing),
                self.transport(),
                self.local_addr(),
                self.remote_addr(),
            )));
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
        if transmit.to != self.local_addr()
            || self.transport() != transmit.transport
            || transmit.from != self.remote_addr()
        {
            trace!(
                "received data not directed at us ({:?}) but for {:?}!",
                self.local_addr(),
                transmit.to
            );
            return TurnRecvRet::Ignored(transmit);
        }

        self.handshake
            .inner_mut()
            .push_incoming(transmit.data.as_ref());

        let stream = match self.handshake.complete() {
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
                    self.protocol.error();
                    tracing::warn!("Error: {e}");
                }
                return TurnRecvRet::Ignored(transmit);
            }
        };
        out.resize(len, 0);

        let transmit = Transmit::new(out, transmit.transport, transmit.from, transmit.to);

        self.handle_incoming_plaintext(transmit, now)
    }

    fn poll_recv(&mut self, now: Instant) -> Option<TurnPeerData<Vec<u8>>> {
        while let Some(recv) = self.incoming_tcp_buffer.poll_recv() {
            match recv {
                StoredTcp::Message(msg_data) => {
                    let Ok(msg) = Message::from_bytes(&msg_data) else {
                        continue;
                    };
                    if let TurnProtocolRecv::PeerData {
                        range,
                        transport,
                        peer,
                    } = self.protocol.handle_message(msg, now)
                    {
                        return Some(TurnPeerData {
                            data: DataRangeOrOwned::Range {
                                data: msg_data,
                                range,
                            },
                            transport,
                            peer,
                        });
                    }
                }
                StoredTcp::Channel(data) => {
                    let Ok(channel) = ChannelData::parse(&data) else {
                        continue;
                    };
                    if let TurnProtocolChannelRecv::PeerData {
                        range,
                        transport,
                        peer,
                    } = self.protocol.handle_channel(channel, now)
                    {
                        return Some(TurnPeerData {
                            data: DataRangeOrOwned::Range { data, range },
                            transport,
                            peer,
                        });
                    }
                }
            }
        }
        None
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
    use turn_server_proto::api::TurnServerApi;

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
    ) -> TurnClient {
        TurnClientOpensslTls::allocate(
            transport,
            local_addr,
            remote_addr,
            credentials,
            &[AddressFamily::IPV4],
            test_ssl_context(transport),
        )
        .into()
    }

    fn turn_tcp_openssl_new(
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        credentials: TurnCredentials,
    ) -> TurnClient {
        turn_openssl_new(TransportType::Tcp, local_addr, remote_addr, credentials)
    }

    fn turn_udp_openssl_new(
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        credentials: TurnCredentials,
    ) -> TurnClient {
        turn_openssl_new(TransportType::Udp, local_addr, remote_addr, credentials)
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

    fn allocate_udp<A: TurnClientApi, S: TurnServerApi>(test: &mut TurnTest<A, S>, now: Instant) {
        complete_io(test, now);
        test.server.allocated_udp_socket(
            TransportType::Tcp,
            test.client.remote_addr(),
            test.client.local_addr(),
            AddressFamily::IPV4,
            Ok(test.turn_alloc_addr),
            now,
        );
        complete_io(test, now);
        let event = test.client.poll_event().unwrap();
        assert!(matches!(event, TurnEvent::AllocationCreated(_, _)));
        assert_eq!(
            test.client.relayed_addresses().next(),
            Some((TransportType::Udp, test.turn_alloc_addr))
        );
    }

    fn udp_permission<A: TurnClientApi, S: TurnServerApi>(test: &mut TurnTest<A, S>, now: Instant) {
        test.client
            .create_permission(TransportType::Udp, test.peer_addr.ip(), now)
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

    fn delete_udp<A: TurnClientApi, S: TurnServerApi>(test: &mut TurnTest<A, S>, now: Instant) {
        test.client.delete(now).unwrap();
        complete_io(test, now);
        assert_eq!(test.client.relayed_addresses().count(), 0);
    }

    fn channel_bind<A: TurnClientApi, S: TurnServerApi>(test: &mut TurnTest<A, S>, now: Instant) {
        test.client
            .bind_channel(TransportType::Udp, test.peer_addr, now)
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
            DelayedMessageOrChannelSend::Data(_)
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
        for transport in [TransportType::Tcp, TransportType::Tcp] {
            let now = Instant::ZERO;
            let mut test = create_test(transport);
            allocate_udp(&mut test, now);
            udp_permission(&mut test, now);
            sendrecv_data(&mut test, now);
        }
    }

    #[test]
    fn test_turn_openssl_allocate_refresh() {
        let _log = crate::tests::test_init_log();
        for transport in [TransportType::Tcp, TransportType::Tcp] {
            let now = Instant::ZERO;
            let mut test = create_test(transport);
            allocate_udp(&mut test, now);
            let TurnPollRet::WaitUntil(expiry) = test.client.poll(now) else {
                unreachable!();
            };
            assert!(now + Duration::from_secs(1000) < expiry);
            // TODO: removing this (REFRESH handling) produces multiple messages in a single TCP
            // transmit which the server currently does not like.
            complete_io(&mut test, expiry);
            udp_permission(&mut test, expiry);
            sendrecv_data(&mut test, expiry);
        }
    }

    #[test]
    fn test_turn_openssl_allocate_delete() {
        let _log = crate::tests::test_init_log();
        for transport in [TransportType::Tcp, TransportType::Tcp] {
            let now = Instant::ZERO;
            let mut test = create_test(transport);
            allocate_udp(&mut test, now);
            delete_udp(&mut test, now);
        }
    }

    #[test]
    fn test_turn_openssl_allocate_bind_channel() {
        let _log = crate::tests::test_init_log();
        for transport in [TransportType::Tcp, TransportType::Tcp] {
            let now = Instant::ZERO;
            let mut test = create_test(transport);
            allocate_udp(&mut test, now);
            channel_bind(&mut test, now);
            sendrecv_data(&mut test, now);
        }
    }

    #[test]
    fn test_turn_openssl_offpath_data() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        for transport in [TransportType::Tcp, TransportType::Tcp] {
            let mut test = create_test(transport);
            allocate_udp(&mut test, now);
            udp_permission(&mut test, now);
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
}
