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

use alloc::string::String;
use core::time::Duration;
use std::net::SocketAddr;
use stun_proto::agent::Transmit;
use stun_proto::Instant;

use openssl::asn1::{Asn1Integer, Asn1Time, Asn1Type};
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::ssl::{SslContext, SslMethod};
use openssl::x509::{X509Name, X509};
use tracing::{debug, trace};

use turn_client_proto::types::message::CREATE_PERMISSION;
use turn_client_proto::types::stun::message::{
    Message, MessageType, MessageWriteVec, TransactionId,
};
use turn_client_proto::types::stun::prelude::MessageWrite;
use turn_client_proto::types::{AddressFamily, TransportType, TurnCredentials};

use turn_client_proto::api::*;

use turn_client_openssl::TurnClientOpensslTls;

use turn_server_openssl::api::{TurnServerApi, TurnServerPollRet};
use turn_server_openssl::OpensslTurnServer;

use api_tests::*;

fn generate_cert() -> (PKey<Private>, X509) {
    let pkey = PKey::ec_gen("prime256v1").unwrap();

    let mut x509 = X509::builder().unwrap();
    x509.set_version(2).unwrap(); // V3 (0-indexed)

    // random 64 bits as serial
    let mut serial = [0_u8; 8];
    openssl::rand::rand_bytes(&mut serial).unwrap();
    let serial = BigNum::from_slice(&serial).unwrap();
    let asn_serial = Asn1Integer::from_bn(&serial).unwrap();
    x509.set_serial_number(&asn_serial).unwrap();

    let common = "localhost";
    let mut cn = X509Name::builder().unwrap();
    cn.append_entry_by_nid_with_type(Nid::COMMONNAME, common, Asn1Type::UTF8STRING)
        .unwrap();
    let cn = cn.build();
    x509.set_issuer_name(&cn).unwrap();
    x509.set_subject_name(&cn).unwrap();

    x509.set_not_before(
        &Asn1Time::from_unix(
            (std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .unwrap()
                - core::time::Duration::from_secs(600))
            .as_secs() as i64,
        )
        .unwrap(),
    )
    .unwrap();

    x509.set_not_after(&Asn1Time::days_from_now(365).unwrap())
        .unwrap();
    x509.set_pubkey(&pkey).unwrap();

    x509.sign(&pkey, MessageDigest::sha256()).unwrap();
    let x509 = x509.build();

    (pkey, x509)
}

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
    let (pkey, cert) = generate_cert();
    let method = match transport {
        TransportType::Udp => SslMethod::dtls_server(),
        TransportType::Tcp => SslMethod::tls_server(),
    };
    let mut builder = SslContext::builder(method).unwrap();
    builder.set_certificate(&cert).unwrap();
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
    config: TurnConfig,
) -> TurnClientOpensslTls {
    TurnClientOpensslTls::allocate(
        transport,
        local_addr,
        remote_addr,
        config,
        test_ssl_context(transport),
    )
}

fn turn_tcp_openssl_new(
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    credentials: TurnCredentials,
    allocation_transport: TransportType,
) -> TurnClientOpensslTls {
    let mut config = TurnConfig::new(credentials);
    config.set_allocation_transport(allocation_transport);
    turn_openssl_new(TransportType::Tcp, local_addr, remote_addr, config)
}

fn turn_udp_openssl_new(
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    credentials: TurnCredentials,
    allocation_transport: TransportType,
) -> TurnClientOpensslTls {
    let mut config = TurnConfig::new(credentials);
    config.set_allocation_transport(allocation_transport);
    turn_openssl_new(TransportType::Udp, local_addr, remote_addr, config)
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

fn create_test(transport: TransportType) -> TurnTest<TurnClientOpensslTls, OpensslTurnServer> {
    match transport {
        TransportType::Udp => TurnTest::<TurnClientOpensslTls, OpensslTurnServer>::builder()
            .build(turn_udp_openssl_new, turn_udp_server_openssl_new),
        TransportType::Tcp => TurnTest::<TurnClientOpensslTls, OpensslTurnServer>::builder()
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
    let now = test.client_advance(now);
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
    now: Instant,
) -> Instant {
    test.client
        .bind_channel(test.allocation_transport, test.peer_addr, now)
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
    let _log = test_init_log();
    for transport in [TransportType::Udp, TransportType::Tcp] {
        let now = Instant::ZERO;
        let mut test = create_test(transport);
        allocate(&mut test, now);
        let now = create_permission(&mut test, now);
        sendrecv_data(&mut test, now);
    }
}

#[test]
fn test_turn_openssl_allocate_refresh() {
    let _log = test_init_log();
    for transport in [TransportType::Udp, TransportType::Tcp] {
        let now = Instant::ZERO;
        let mut test = create_test(transport);
        allocate(&mut test, now);
        let expiry = test.client_advance(now);
        assert!(now + Duration::from_secs(1000) < expiry);
        // stale nonce for REFRESH.
        complete_io(&mut test, expiry);
        let expiry = test.client_advance(expiry);
        // REFRESH with corrected nonce.
        complete_io(&mut test, expiry);
        let expiry = create_permission(&mut test, expiry);
        sendrecv_data(&mut test, expiry);
    }
}

#[test]
fn test_turn_openssl_allocate_delete() {
    let _log = test_init_log();
    for transport in [TransportType::Udp, TransportType::Tcp] {
        let now = Instant::ZERO;
        let mut test = create_test(transport);
        allocate(&mut test, now);
        delete(&mut test, now);
    }
}

#[test]
fn test_turn_openssl_allocate_bind_channel() {
    let _log = test_init_log();
    for transport in [TransportType::Udp, TransportType::Tcp] {
        let now = Instant::ZERO;
        let mut test = create_test(transport);
        allocate(&mut test, now);
        let now = channel_bind(&mut test, now);
        sendrecv_data(&mut test, now);
    }
}

#[test]
fn test_turn_openssl_offpath_data() {
    let _log = test_init_log();
    let now = Instant::ZERO;
    for transport in [TransportType::Udp, TransportType::Tcp] {
        let mut test = create_test(transport);
        allocate(&mut test, now);
        let now = create_permission(&mut test, now);
        let data = Message::builder(
            MessageType::from_class_method(
                turn_client_proto::types::stun::message::MessageClass::Error,
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

fn create_test_tcp_allocation() -> TurnTest<TurnClientOpensslTls, OpensslTurnServer> {
    TurnTest::<TurnClientOpensslTls, OpensslTurnServer>::builder()
        .allocation_transport(TransportType::Tcp)
        .build(turn_tcp_openssl_new, turn_tcp_server_openssl_new)
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
fn test_turn_openssl_tcp_allocation_send_recv_client_close() {
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
fn test_turn_openssl_tcp_allocation_send_recv_peer_close() {
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
