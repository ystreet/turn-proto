// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.
//
// SPDX-License-Identifier: MIT OR Apache-2.0

extern crate alloc;

use alloc::borrow::ToOwned;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use core::time::Duration;
use std::net::SocketAddr;
use stun_proto::agent::Transmit;
use stun_proto::Instant;
use tracing::{debug, trace};
use turn_client_proto::rustls::TurnClientRustls;

use turn_types::message::CREATE_PERMISSION;
use turn_types::stun::message::{Message, MessageType, MessageWriteVec, TransactionId};
use turn_types::stun::prelude::MessageWrite;
use turn_types::{AddressFamily, TransportType, TurnCredentials};

use turn_client_proto::api::*;
use turn_server_proto::api::{TurnServerApi, TurnServerPollRet};
use turn_server_proto::rustls::RustlsTurnServer;

use api_tests::*;

use rcgen::CertifiedKey;
use rustls::crypto::ring as crypto_provider;
use rustls::pki_types::PrivateKeyDer;
use rustls::{ClientConfig, ServerConfig};

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
) -> TurnClientRustls {
    let mut config = TurnConfig::new(credentials);
    config.set_allocation_transport(allocation_transport);
    TurnClientRustls::allocate(
        local_addr,
        remote_addr,
        config,
        remote_addr.ip().into(),
        client_config(),
    )
}

fn turn_server_rustls_new(listen_address: SocketAddr, realm: String) -> RustlsTurnServer {
    RustlsTurnServer::new(listen_address, realm, server_config())
}

fn create_test() -> TurnTest<TurnClientRustls, RustlsTurnServer> {
    TurnTest::<TurnClientRustls, RustlsTurnServer>::builder()
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
    let now = test.client_advance(now);
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
) -> Instant {
    test.client
        .create_permission(test.allocation_transport, test.peer_addr.ip(), now)
        .unwrap();
    let now = test.client_advance(now);
    complete_io(test, now);

    let event = test.client.poll_event().unwrap();
    assert!(matches!(event, TurnEvent::PermissionCreated(_, _)));
    let (transport, relayed) = test.client.relayed_addresses().next().unwrap();
    assert!(test
        .client
        .permissions(transport, relayed)
        .any(|perm_ip| perm_ip == test.peer_addr.ip()));
    assert!(test.client.have_permission(transport, test.peer_addr.ip()));
    now
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
) -> Instant {
    test.client
        .bind_channel(allocation_transport, test.peer_addr, now)
        .unwrap();
    let now = test.client_advance(now);
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
    now
}

fn udp_sendrecv_data<A: TurnClientApi, S: TurnServerApi>(test: &mut TurnTest<A, S>, now: Instant) {
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
    let _log = test_init_log();
    let now = Instant::ZERO;
    let mut test = create_test();
    allocate(&mut test, now);
    let now = create_permission(&mut test, now);
    udp_sendrecv_data(&mut test, now);
}

#[test]
fn test_turn_rustls_allocate_refresh() {
    let _log = test_init_log();
    let now = Instant::ZERO;
    let mut test = create_test();
    allocate(&mut test, now);
    let TurnPollRet::WaitUntil(expiry) = test.client.poll(now) else {
        unreachable!();
    };
    assert!(now + Duration::from_secs(1000) < expiry);
    // stale nonce for REFRESH
    complete_io(&mut test, expiry);
    let expiry = test.client_advance(expiry);
    // REFRESH with corrected nonce.
    complete_io(&mut test, expiry);
    let expiry = create_permission(&mut test, expiry);
    udp_sendrecv_data(&mut test, expiry);
}

#[test]
fn test_turn_rustls_allocate_delete() {
    let _log = test_init_log();
    let now = Instant::ZERO;
    let mut test = create_test();
    allocate(&mut test, now);
    delete(&mut test, now);
}

#[test]
fn test_turn_rustls_allocate_bind_channel() {
    let _log = test_init_log();
    let now = Instant::ZERO;
    let mut test = create_test();
    allocate(&mut test, now);
    let now = channel_bind(&mut test, TransportType::Udp, now);
    udp_sendrecv_data(&mut test, now);
}

#[test]
fn test_turn_rustls_offpath_data() {
    let _log = test_init_log();
    let now = Instant::ZERO;
    let mut test = create_test();
    allocate(&mut test, now);
    let now = create_permission(&mut test, now);
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

fn create_test_tcp_allocation() -> TurnTest<TurnClientRustls, RustlsTurnServer> {
    TurnTest::<TurnClientRustls, RustlsTurnServer>::builder()
        .allocation_transport(TransportType::Tcp)
        .build(turn_rustls_new, turn_server_rustls_new)
}

fn tcp_connect<A: TurnClientApi, S: TurnServerApi>(
    test: &mut TurnTest<A, S>,
    now: Instant,
) -> Instant {
    test.client.tcp_connect(test.peer_addr, now).unwrap();
    let now = test.client_advance(now);
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
    let now = test.client_advance(now);
    complete_io(test, now);

    assert!(matches!(
        test.client.poll_event().unwrap(),
        TurnEvent::TcpConnected(_peer_addr)
    ));
    now
}

fn tcp_sendrecv_data<A: TurnClientApi, S: TurnServerApi>(test: &mut TurnTest<A, S>, now: Instant) {
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
    let _log = test_init_log();
    let now = Instant::ZERO;
    let mut test = create_test_tcp_allocation();
    allocate(&mut test, now);
    let now = create_permission(&mut test, now);
    let now = tcp_connect(&mut test, now);
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
    let _log = test_init_log();
    let now = Instant::ZERO;
    let mut test = create_test_tcp_allocation();
    allocate(&mut test, now);
    let now = create_permission(&mut test, now);
    let now = tcp_connect(&mut test, now);
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
