// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! TLS TURN client using Rustls.
//!
//! An implementation of a TURN client suitable for TLS over TCP connections.

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::net::{IpAddr, SocketAddr};
use core::time::Duration;
use std::io::{Read, Write};

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection};

use stun_proto::agent::Transmit;
use stun_proto::types::data::Data;
use stun_proto::Instant;

use stun_proto::types::TransportType;

use turn_types::AddressFamily;
use turn_types::TurnCredentials;

use tracing::{debug, trace, warn};

use crate::api::{
    DelayedMessageOrChannelSend, Socket5Tuple, TcpAllocateError, TcpConnectError, TransmitBuild,
    TurnClientApi, TurnPeerData,
};

pub use crate::api::{
    BindChannelError, CreatePermissionError, DeleteError, SendError, TurnEvent, TurnPollRet,
    TurnRecvRet,
};
use crate::tcp::TurnClientTcp;

/// A TURN client that communicates over TLS.
#[derive(Debug)]
pub struct TurnClientRustls {
    protocol: TurnClientTcp,
    config: Arc<ClientConfig>,
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
    pub fn allocate(
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        credentials: TurnCredentials,
        allocation_transport: TransportType,
        allocation_families: &[AddressFamily],
        server_name: ServerName<'static>,
        config: Arc<ClientConfig>,
    ) -> Self {
        Self {
            protocol: TurnClientTcp::allocate(
                local_addr,
                remote_addr,
                credentials,
                allocation_transport,
                allocation_families,
            ),
            sockets: vec![Socket {
                local_addr,
                remote_addr,
                tls: ClientConnection::new(config.clone(), server_name.clone()).unwrap(),
                local_closed: false,
                peer_closed: false,
            }],
            config,
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
                    tls: ClientConnection::new(self.config.clone(), self.server_name.clone())
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
    use turn_server_proto::api::{TurnServerApi, TurnServerPollRet};
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
        allocation_transport: TransportType,
    ) -> TurnClient {
        TurnClientRustls::allocate(
            local_addr,
            remote_addr,
            credentials,
            allocation_transport,
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

    fn allocate<A: TurnClientApi, S: TurnServerApi>(test: &mut TurnTest<A, S>, now: Instant) {
        complete_io(test, now);
        test.server.allocated_socket(
            TransportType::Tcp,
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

    fn channel_bind<A: TurnClientApi, S: TurnServerApi>(
        test: &mut TurnTest<A, S>,
        allocation_transport: TransportType,
        now: Instant,
    ) {
        test.client
            .bind_channel(allocation_transport, test.peer_addr, now)
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

    fn udp_sendrecv_data<A: TurnClientApi, S: TurnServerApi>(
        test: &mut TurnTest<A, S>,
        now: Instant,
    ) {
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
    fn test_turn_rustls_allocate_udp_permission() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut test = create_test();
        allocate(&mut test, now);
        create_permission(&mut test, now);
        udp_sendrecv_data(&mut test, now);
    }

    #[test]
    fn test_turn_rustls_allocate_refresh() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut test = create_test();
        allocate(&mut test, now);
        let TurnPollRet::WaitUntil(expiry) = test.client.poll(now) else {
            unreachable!();
        };
        assert!(now + Duration::from_secs(1000) < expiry);
        // TODO: removing this (REFRESH handling) produces multiple messages in a single TCP
        // transmit which the server currently does not like.
        complete_io(&mut test, expiry);
        create_permission(&mut test, expiry);
        udp_sendrecv_data(&mut test, expiry);
    }

    #[test]
    fn test_turn_rustls_allocate_delete() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut test = create_test();
        allocate(&mut test, now);
        delete(&mut test, now);
    }

    #[test]
    fn test_turn_rustls_allocate_bind_channel() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut test = create_test();
        allocate(&mut test, now);
        channel_bind(&mut test, TransportType::Udp, now);
        udp_sendrecv_data(&mut test, now);
    }

    #[test]
    fn test_turn_rustls_offpath_data() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut test = create_test();
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

    fn create_test_tcp_allocation() -> TurnTest<TurnClient, RustlsTurnServer> {
        TurnTest::<TurnClient, RustlsTurnServer>::builder()
            .allocation_transport(TransportType::Tcp)
            .build(turn_rustls_new, turn_server_rustls_new)
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
    fn test_turn_rustls_tcp_allocation_send_recv_client_close() {
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
    fn test_turn_rustls_tcp_allocation_send_recv_peer_close() {
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
