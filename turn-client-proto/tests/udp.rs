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

use std::net::SocketAddr;

use alloc::string::String;
use stun_proto::agent::Transmit;
use stun_proto::Instant;
use turn_server_proto::api::TurnServerApi;
use turn_server_proto::server::TurnServer;
use turn_types::{TransportType, TurnCredentials};

use turn_client_proto::api::*;
use turn_client_proto::udp::TurnClientUdp;

use api_tests::*;

pub(crate) fn turn_udp_new(
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    credentials: TurnCredentials,
    allocation_transport: TransportType,
) -> TurnClientUdp {
    assert_eq!(allocation_transport, TransportType::Udp);
    let mut config = TurnConfig::new(credentials);
    config.set_allocation_transport(allocation_transport);
    TurnClientUdp::allocate(local_addr, remote_addr, config)
}

fn turn_server_udp_new(listen_address: SocketAddr, realm: String) -> TurnServer {
    TurnServer::new(TransportType::Udp, listen_address, realm)
}

pub(crate) fn create_test() -> TurnTest<TurnClientUdp, TurnServer> {
    TurnTest::<TurnClientUdp, TurnServer>::builder().build(turn_udp_new, turn_server_udp_new)
}

#[test]
fn test_turn_udp_allocate_udp_permission() {
    let _log = test_init_log();
    let now = Instant::ZERO;
    let mut test = create_test();
    turn_allocate_permission(&mut test, now);
}

#[test]
fn test_udp_turn_allocate_expire_server() {
    let _log = test_init_log();
    let now = Instant::ZERO;
    let mut test = create_test();
    turn_allocate_expire_server(&mut test, now);
}

#[test]
fn test_udp_turn_allocate_expire_client() {
    let _log = test_init_log();
    let now = Instant::ZERO;
    let mut test = create_test();
    turn_allocate_expire_client(&mut test, now);
}

#[test]
fn test_udp_turn_allocate_refresh() {
    let _log = test_init_log();
    let now = Instant::ZERO;
    let mut test = create_test();
    turn_allocate_refresh(&mut test, now);
}

#[test]
fn test_udp_turn_allocate_delete() {
    let _log = test_init_log();
    let now = Instant::ZERO;
    let mut test = create_test();
    turn_allocate_delete(&mut test, now);
}

#[test]
fn test_udp_turn_channel_bind() {
    let _log = test_init_log();
    let now = Instant::ZERO;
    let mut test = create_test();
    turn_channel_bind(&mut test, now);
}

#[test]
fn test_udp_turn_peer_incoming_stun() {
    let _log = test_init_log();
    let now = Instant::ZERO;
    let mut test = create_test();
    turn_peer_incoming_stun(&mut test, now);
}

#[test]
fn test_udp_turn_create_permission_refresh() {
    let _log = test_init_log();
    let now = Instant::ZERO;
    let mut test = create_test();
    turn_create_permission_refresh(&mut test, now);
}

#[test]
fn test_udp_turn_create_permission_timeout() {
    let _log = test_init_log();
    let now = Instant::ZERO;
    let mut test = create_test();
    turn_create_permission_timeout(&mut test, now);
}

#[test]
fn test_udp_turn_channel_bind_refresh() {
    let _log = test_init_log();
    let now = Instant::ZERO;
    let mut test = create_test();
    turn_channel_bind_refresh(&mut test, now);
}

#[test]
fn test_udp_offpath_data() {
    let _log = test_init_log();
    let now = Instant::ZERO;
    let mut test = create_test();
    turn_offpath_data(&mut test, now);
}

#[test]
fn test_udp_unparseable_data() {
    let _log = test_init_log();
    let now = Instant::ZERO;
    let mut test = create_test();
    turn_unparseable_data(&mut test, now);
}

#[test]
fn test_client_receive_offpath_data() {
    let _log = test_init_log();

    let now = Instant::ZERO;

    let mut test = create_test();
    let data = [0x40, 0, 0, 14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let TurnRecvRet::Ignored(ignored) = test.client.recv(
        Transmit::new(
            &data,
            test.client.transport(),
            test.client.remote_addr(),
            test.client.local_addr(),
        ),
        now,
    ) else {
        unreachable!();
    };
    assert_eq!(ignored.data, &data);
}

#[test]
fn test_server_receive_offpath_data() {
    let _log = test_init_log();

    let now = Instant::ZERO;
    let mut test = create_test();

    let data = [3; 9];
    assert!(test
        .server
        .recv(
            Transmit::new(
                &data,
                TransportType::Udp,
                test.peer_addr,
                test.client.local_addr(),
            ),
            now,
        )
        .is_none());
}
