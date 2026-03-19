// Copyright (C) 2026 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.
//
// SPDX-License-Identifier: MIT OR Apache-2.0

extern crate alloc;

use core::time::Duration;
use core::net::SocketAddr;

use alloc::string::String;
use alloc::sync::Arc;

use turn_server_dimpl::api::TurnServerApi;
use turn_server_dimpl::DimplTurnServer;

use turn_client_proto::types::message::CREATE_PERMISSION;
use turn_client_proto::types::stun::message::{
    Message, MessageType, MessageWriteVec, TransactionId,
};
use turn_client_proto::types::stun::prelude::MessageWrite;
use turn_client_proto::types::{AddressFamily, TurnCredentials};
use turn_client_proto::types::{Instant, TransportType};

use turn_client_proto::api::*;

use turn_client_dimpl::TurnClientDimpl;

use api_tests::*;

use tracing::trace;

fn generate_cert() -> dimpl::DtlsCertificate {
    dimpl::certificate::generate_self_signed_certificate().unwrap()
}

fn test_dimpl_config() -> Arc<dimpl::Config> {
    Arc::new(dimpl::Config::builder().build().unwrap())
}

fn test_dimpl_server_config() -> Arc<dimpl::Config> {
    Arc::new(dimpl::Config::builder().build().unwrap())
}

fn turn_dimpl_new(
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    config: TurnConfig,
) -> TurnClientDimpl {
    TurnClientDimpl::allocate(local_addr, remote_addr, config, test_dimpl_config())
}

fn turn_udp_dimpl_new(
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    credentials: TurnCredentials,
    allocation_transport: TransportType,
) -> TurnClientDimpl {
    let mut config = TurnConfig::new(credentials);
    config.set_allocation_transport(allocation_transport);
    turn_dimpl_new(local_addr, remote_addr, config)
}

fn turn_server_dimpl_new(listen_address: SocketAddr, realm: String) -> DimplTurnServer {
    DimplTurnServer::new(
        TransportType::Udp,
        listen_address,
        realm,
        test_dimpl_server_config(),
        generate_cert(),
    )
}

fn create_test() -> TurnTest<TurnClientDimpl, DimplTurnServer> {
    TurnTest::<TurnClientDimpl, DimplTurnServer>::builder()
        .build(turn_udp_dimpl_new, turn_server_dimpl_new)
}

fn complete_io<A: TurnClientApi, S: TurnServerApi>(test: &mut TurnTest<A, S>, now: Instant) {
    loop {
        let mut handled = false;
        trace!("client poll: {:?}", test.client.poll(now));
        trace!("server poll: {:?}", test.server.poll(now));
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
    tracing::error!("{test:?}");
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
fn test_turn_dimpl_allocate_udp_permission() {
    let _log = test_init_log();
    let now = Instant::ZERO;
    let mut test = create_test();
    allocate(&mut test, now);
    let now = create_permission(&mut test, now);
    sendrecv_data(&mut test, now);
}

#[test]
fn test_turn_dimpl_allocate_refresh() {
    let _log = test_init_log();
    let now = Instant::ZERO;
    let mut test = create_test();
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

#[test]
fn test_turn_dimpl_allocate_delete() {
    let _log = test_init_log();
    let now = Instant::ZERO;
    let mut test = create_test();
    allocate(&mut test, now);
    delete(&mut test, now);
}

#[test]
fn test_turn_dimpl_allocate_bind_channel() {
    let _log = test_init_log();
    let now = Instant::ZERO;
    let mut test = create_test();
    allocate(&mut test, now);
    let now = channel_bind(&mut test, now);
    sendrecv_data(&mut test, now);
}

#[test]
fn test_turn_dimpl_offpath_data() {
    let _log = test_init_log();
    let now = Instant::ZERO;
    let mut test = create_test();
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
