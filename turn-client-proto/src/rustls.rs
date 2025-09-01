// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! TLS TURN client using Rustls.
//!
//! An implementation of a TURN client suitable for TLS over TCP connections.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::net::{IpAddr, SocketAddr};
use std::io::{Read, Write};

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection};

use stun_proto::agent::{StunAgent, Transmit};
use stun_proto::types::data::Data;
use stun_proto::Instant;

use stun_proto::types::TransportType;

use turn_types::channel::ChannelData;
use turn_types::AddressFamily;
use turn_types::TurnCredentials;

use tracing::{trace, warn};

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
pub struct TurnClientTls {
    protocol: TurnClientProtocol,
    conn: Box<ClientConnection>,
    incoming_tcp_buffer: TurnTcpBuffer,
    closing: bool,
}

impl TurnClientTls {
    /// Allocate an address on a TURN server to relay data to and from peers.
    pub fn allocate(
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        credentials: TurnCredentials,
        allocation_families: &[AddressFamily],
        server_name: ServerName<'static>,
        config: Arc<ClientConfig>,
    ) -> Self {
        let stun_agent = StunAgent::builder(TransportType::Tcp, local_addr)
            .remote_addr(remote_addr)
            .build();
        Self {
            protocol: TurnClientProtocol::new(stun_agent, credentials, allocation_families),
            conn: Box::new(ClientConnection::new(config, server_name).unwrap()),
            incoming_tcp_buffer: TurnTcpBuffer::new(),
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
                match self.protocol.handle_message(
                    &transmit.data.as_slice()[msg_range.start..msg_range.end],
                    now,
                ) {
                    TurnProtocolRecv::Handled => TurnRecvRet::Handled,
                    // XXX: this might be grounds for connection termination.
                    TurnProtocolRecv::Ignored(_) => TurnRecvRet::Handled,
                    TurnProtocolRecv::PeerData {
                        data: _,
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
                match self.protocol.handle_message(data, now) {
                    TurnProtocolRecv::Handled => TurnRecvRet::Handled,
                    TurnProtocolRecv::Ignored(_) => TurnRecvRet::Handled,
                    TurnProtocolRecv::PeerData {
                        data: _,
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

impl TurnClientApi for TurnClientTls {
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
        let io_state = match self.conn.process_new_packets() {
            Ok(io_state) => io_state,
            Err(e) => {
                self.protocol.error();
                warn!("Error processing TLS: {e:?}");
                return TurnPollRet::Closed;
            }
        };
        let protocol_ret = self.protocol.poll(now);
        if io_state.tls_bytes_to_write() > 0 {
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
        if self.conn.is_handshaking() && self.conn.wants_write() {
            // TODO: avoid this allocation
            let mut out = vec![];
            match self.conn.write_tls(&mut out) {
                Ok(_written) => {
                    return Some(Transmit::new(
                        Data::from(out.into_boxed_slice()),
                        self.transport(),
                        self.local_addr(),
                        self.remote_addr(),
                    ))
                }
                Err(e) => {
                    warn!("error during handshake: {e:?}");
                    self.protocol.error();
                    return None;
                }
            }
        }

        if !self.conn.wants_write() {
            if let Some(transmit) = self.protocol.poll_transmit(now) {
                self.conn.writer().write_all(&transmit.data).unwrap();
            }
        }

        if self.conn.wants_write() {
            // TODO: avoid this allocation
            let mut out = vec![];
            match self.conn.write_tls(&mut out) {
                Ok(_written) => {
                    return Some(Transmit::new(
                        Data::from(out.into_boxed_slice()),
                        self.transport(),
                        self.local_addr(),
                        self.remote_addr(),
                    ))
                }
                Err(e) => {
                    warn!("error writing TLS: {e:?}");
                    self.protocol.error();
                }
            }
        }
        None
    }

    fn poll_event(&mut self) -> Option<TurnEvent> {
        self.protocol.poll_event()
    }

    fn delete(&mut self, now: Instant) -> Result<(), DeleteError> {
        self.protocol.delete(now)?;
        self.closing = true;

        while let Some(transmit) = self.protocol.poll_transmit(now) {
            self.conn.writer().write_all(&transmit.data).unwrap();
        }
        Ok(())
    }

    fn create_permission(
        &mut self,
        transport: TransportType,
        peer_addr: IpAddr,
        now: Instant,
    ) -> Result<(), CreatePermissionError> {
        self.protocol.create_permission(transport, peer_addr, now)?;

        while let Some(transmit) = self.protocol.poll_transmit(now) {
            self.conn.writer().write_all(&transmit.data).unwrap();
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

        while let Some(transmit) = self.protocol.poll_transmit(now) {
            self.conn.writer().write_all(&transmit.data).unwrap();
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
        let transmit = self.protocol.send_to(transport, to, data, now)?;
        let transmit = transmit.build();
        if let Err(e) = self.conn.writer().write_all(&transmit.data) {
            self.protocol.error();
            warn!("Error when writing plaintext: {e:?}");
            return Err(SendError::NoAllocation);
        }

        if self.conn.wants_write() {
            let mut out = vec![];
            match self.conn.write_tls(&mut out) {
                Ok(_n) => {
                    return Ok(Some(TransmitBuild::new(
                        DelayedMessageOrChannelSend::Data(out),
                        self.transport(),
                        self.local_addr(),
                        self.remote_addr(),
                    )))
                }
                Err(e) => {
                    self.protocol.error();
                    warn!("Error when writing TLS records: {e:?}");
                    return Err(SendError::NoAllocation);
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
        let mut data = std::io::Cursor::new(transmit.data.as_ref());

        let io_state = match self.conn.read_tls(&mut data) {
            Ok(_written) => match self.conn.process_new_packets() {
                Ok(io_state) => io_state,
                Err(e) => {
                    self.protocol.error();
                    warn!("Error processing TLS: {e:?}");
                    return TurnRecvRet::Ignored(transmit);
                }
            },
            Err(e) => {
                warn!("Error receiving data: {e:?}");
                self.protocol.error();
                return TurnRecvRet::Ignored(transmit);
            }
        };
        if io_state.plaintext_bytes_to_read() > 0 {
            let mut out = vec![0; 2048];
            let n = match self.conn.reader().read(&mut out) {
                Ok(n) => n,
                Err(e) => {
                    warn!("Error receiving data: {e:?}");
                    self.protocol.error();
                    return TurnRecvRet::Ignored(transmit);
                }
            };
            out.resize(n, 0);
            let transmit = Transmit::new(out, transmit.transport, transmit.from, transmit.to);

            return self.handle_incoming_plaintext(transmit, now);
        }

        TurnRecvRet::Handled
    }

    fn poll_recv(&mut self, now: Instant) -> Option<TurnPeerData<Vec<u8>>> {
        while let Some(recv) = self.incoming_tcp_buffer.poll_recv() {
            match recv {
                StoredTcp::Message(msg) => {
                    if let TurnProtocolRecv::PeerData {
                        data,
                        range,
                        transport,
                        peer,
                    } = self.protocol.handle_message(msg, now)
                    {
                        return Some(TurnPeerData {
                            data: DataRangeOrOwned::Range { data, range },
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
    use alloc::borrow::ToOwned;
    use alloc::string::{String, ToString};
    use core::time::Duration;

    use crate::api::tests::{transmit_send_build, TurnTest};
    use crate::client::TurnClient;
    use turn_types::message::CREATE_PERMISSION;
    use turn_types::stun::message::{Message, MessageType, MessageWriteVec, TransactionId};
    use turn_types::stun::prelude::MessageWrite;

    use super::*;

    use rcgen::CertifiedKey;
    use rustls::crypto::aws_lc_rs as crypto_provider;
    use rustls::pki_types::PrivateKeyDer;
    use rustls::ServerConfig;
    use turn_server_proto::api::TurnServerApi;
    use turn_server_proto::rustls::RustlsTurnServer;
    mod danger {
        use rustls::client::danger::HandshakeSignatureValid;
        use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
        use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
        use rustls::DigitallySignedStruct;

        use alloc::vec::Vec;

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

    fn client_config() -> Arc<ClientConfig> {
        Arc::new(
            ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(danger::NoCertificateVerification::new(
                    crypto_provider::default_provider(),
                )))
                .with_no_client_auth(),
        )
    }

    fn server_config() -> Arc<ServerConfig> {
        let CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(
                    vec![cert.der().to_owned()],
                    PrivateKeyDer::try_from(signing_key.serialize_der())
                        .unwrap()
                        .clone_key(),
                )
                .unwrap(),
        )
    }

    fn turn_rustls_new(
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        credentials: TurnCredentials,
    ) -> TurnClient {
        TurnClientTls::allocate(
            local_addr,
            remote_addr,
            credentials,
            &[AddressFamily::IPV4],
            remote_addr.ip().into(),
            client_config(),
        )
        .into()
    }

    fn turn_server_rustls_new(listen_address: SocketAddr, realm: String) -> RustlsTurnServer {
        RustlsTurnServer::new(listen_address, realm, server_config())
    }

    fn create_test() -> TurnTest<TurnClient, RustlsTurnServer> {
        TurnTest::<TurnClient, RustlsTurnServer>::builder()
            .build(turn_rustls_new, turn_server_rustls_new)
    }

    fn complete_io<A: TurnClientApi, S: TurnServerApi>(test: &mut TurnTest<A, S>, now: Instant) {
        let mut handled = false;
        loop {
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
            handled = false;
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
    fn test_turn_rustls_allocate_udp_permission() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut test = create_test();
        allocate_udp(&mut test, now);
        udp_permission(&mut test, now);
        sendrecv_data(&mut test, now);
    }

    #[test]
    fn test_turn_rustls_allocate_refresh() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut test = create_test();
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

    #[test]
    fn test_turn_rustls_allocate_delete() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut test = create_test();
        allocate_udp(&mut test, now);
        delete_udp(&mut test, now);
    }

    #[test]
    fn test_turn_rustls_allocate_bind_channel() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut test = create_test();
        allocate_udp(&mut test, now);
        channel_bind(&mut test, now);
        sendrecv_data(&mut test, now);
    }

    #[test]
    fn test_turn_rustls_offpath_data() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut test = create_test();
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
