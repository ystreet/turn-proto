// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::time::Duration;
use std::net::SocketAddr;

use stun_proto::{agent::Transmit, Instant};
use turn_client_proto::api::*;
use turn_client_proto::tcp::TurnClientTcp;
use turn_server_proto::api::*;
use turn_server_proto::server::TurnServer;

use turn_types::{TransportType, TurnCredentials};

use api_tests::*;

fn turn_tcp_new(
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    credentials: TurnCredentials,
    allocation_transport: TransportType,
) -> TurnClientTcp {
    let mut config = TurnConfig::new(credentials);
    config.set_allocation_transport(allocation_transport);
    TurnClientTcp::allocate(local_addr, remote_addr, config)
}

fn turn_server_tcp_new(listen_addr: SocketAddr, realm: String) -> TurnServer {
    TurnServer::new(TransportType::Tcp, listen_addr, realm)
}

fn create_test(split_transmit_bytes: usize) -> TurnTest<TurnClientTcp, TurnServer> {
    TurnTest::<TurnClientTcp, TurnServer>::builder()
        .split_transmit_bytes(split_transmit_bytes)
        .build(turn_tcp_new, turn_server_tcp_new)
}

static TRANSMIT_SPLITS: [usize; 3] = [0, 3, 6];

#[test]
fn test_turn_tcp_allocate_udp_permission() {
    let _log = test_init_log();
    let now = Instant::ZERO;
    for split in TRANSMIT_SPLITS {
        let mut test = create_test(split);
        turn_allocate_permission(&mut test, now);
    }
}

#[test]
fn test_tcp_turn_allocate_expire_server() {
    let _log = test_init_log();
    let now = Instant::ZERO;
    for split in TRANSMIT_SPLITS {
        let mut test = create_test(split);
        turn_allocate_expire_server(&mut test, now);
    }
}

#[test]
fn test_tcp_turn_allocate_expire_client() {
    let _log = test_init_log();
    let now = Instant::ZERO;
    for split in TRANSMIT_SPLITS {
        let mut test = create_test(split);
        turn_allocate_expire_client(&mut test, now);
    }
}

#[test]
fn test_tcp_turn_allocate_refresh() {
    let _log = test_init_log();
    let now = Instant::ZERO;
    for split in TRANSMIT_SPLITS {
        let mut test = create_test(split);
        turn_allocate_refresh(&mut test, now);
    }
}

#[test]
fn test_tcp_turn_allocate_delete() {
    let _log = test_init_log();
    let now = Instant::ZERO;
    for split in TRANSMIT_SPLITS {
        let mut test = create_test(split);
        turn_allocate_delete(&mut test, now);
    }
}

#[test]
fn test_tcp_turn_channel_bind() {
    let _log = test_init_log();
    let now = Instant::ZERO;
    for split in TRANSMIT_SPLITS {
        let mut test = create_test(split);
        turn_channel_bind(&mut test, now);
    }
}

#[test]
fn test_tcp_turn_peer_incoming_stun() {
    let _log = test_init_log();
    let now = Instant::ZERO;
    for split in TRANSMIT_SPLITS {
        let mut test = create_test(split);
        turn_peer_incoming_stun(&mut test, now);
    }
}

#[test]
fn test_tcp_turn_create_permission_refresh() {
    let _log = test_init_log();
    let now = Instant::ZERO;
    for split in TRANSMIT_SPLITS {
        let mut test = create_test(split);
        turn_create_permission_refresh(&mut test, now);
    }
}

#[test]
fn test_tcp_turn_create_permission_timeout() {
    let _log = test_init_log();
    let now = Instant::ZERO;
    for split in TRANSMIT_SPLITS {
        let mut test = create_test(split);
        turn_create_permission_timeout(&mut test, now);
    }
}

#[test]
fn test_tcp_turn_channel_bind_refresh() {
    let _log = test_init_log();
    let now = Instant::ZERO;
    for split in TRANSMIT_SPLITS {
        let mut test = create_test(split);
        turn_channel_bind_refresh(&mut test, now);
    }
}

#[test]
fn test_turn_tcp_allocate_udp_send_recv() {
    let _log = test_init_log();
    let now = Instant::ZERO;
    let mut test = create_test(0);
    test.allocate(now);
    let Some(TurnEvent::AllocationCreated(transport, relayed_address)) = test.client.poll_event()
    else {
        unreachable!();
    };
    assert_eq!(transport, test.allocation_transport);
    assert_eq!(relayed_address, test.turn_alloc_addr);
    test.create_permission(now);
    let Some(TurnEvent::PermissionCreated(transport, permission_ip)) = test.client.poll_event()
    else {
        unreachable!();
    };
    assert_eq!(transport, test.allocation_transport);
    assert_eq!(permission_ip, test.peer_addr.ip());
    let sent_data = [7; 9];
    let transmit = test
        .client
        .send_to(TransportType::Udp, test.peer_addr, sent_data, now)
        .unwrap()
        .unwrap()
        .build();
    assert_eq!(transmit.transport, TransportType::Tcp);
    assert_eq!(transmit.from, test.client.local_addr());
    assert_eq!(transmit.to, test.server.listen_address());
    let forward = test.server.recv(transmit, now).unwrap().build();
    assert_eq!(forward.transport, TransportType::Udp);
    assert_eq!(forward.from, test.turn_alloc_addr);
    assert_eq!(forward.to, test.peer_addr);
    assert_eq!(&forward.data, sent_data.as_slice());

    let sent_data = [9; 8];
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
        .unwrap()
        .build();
    assert_eq!(transmit.transport, TransportType::Tcp);
    assert_eq!(transmit.from, test.server.listen_address());
    assert_eq!(transmit.to, test.client.local_addr());
    let TurnRecvRet::PeerData(peer_data) = test.client.recv(transmit, now) else {
        unreachable!();
    };
    assert_eq!(peer_data.transport, TransportType::Udp);
    assert_eq!(peer_data.peer, test.peer_addr);
    assert_eq!(peer_data.data(), sent_data);
}

#[test]
fn test_tcp_offpath_data() {
    let _log = test_init_log();
    let now = Instant::ZERO;
    let mut test = create_test(0);
    turn_offpath_data(&mut test, now);
}

fn peer_transmit<A: TurnClientApi, S: TurnServerApi>(
    test: &TurnTest<A, S>,
    data: &[u8],
) -> Transmit<Vec<u8>> {
    Transmit::new(
        data.to_vec(),
        TransportType::Udp,
        test.peer_addr,
        test.turn_alloc_addr,
    )
}

fn combine_transmit<T: AsRef<[u8]> + core::fmt::Debug, R: AsRef<[u8]> + core::fmt::Debug>(
    a: &Transmit<T>,
    b: &Transmit<R>,
) -> Transmit<Vec<u8>> {
    assert_eq!(a.transport, b.transport);
    assert_eq!(a.from, b.from);
    assert_eq!(a.to, b.to);
    let mut data = a.data.as_ref().to_vec();
    data.extend_from_slice(b.data.as_ref());
    Transmit::new(data, a.transport, a.from, a.to)
}

#[test]
fn test_tcp_combined_message_channel() {
    let _log = test_init_log();
    let now = Instant::ZERO;
    let mut test = create_test(0);
    turn_allocate_permission(&mut test, now);
    let TurnPollRet::WaitUntil(now) = test.client.poll(now) else {
        unreachable!();
    };
    let transmit = test.client.poll_transmit(now).unwrap();
    let msg_reply = test.server.recv(transmit, now).unwrap();
    let peer_data = [8; 9];
    let peer_transmit = test
        .server
        .recv(peer_transmit(&test, peer_data.as_slice()), now)
        .unwrap();
    let TurnRecvRet::PeerData(peer) = test.client.recv(
        combine_transmit(&msg_reply.build(), &peer_transmit.build()),
        now,
    ) else {
        unreachable!();
    };
    assert_eq!(peer.data(), peer_data.as_slice());
}

#[test]
fn test_tcp_combined_channel_message() {
    let _log = test_init_log();
    let now = Instant::ZERO;
    let mut test = create_test(0);
    turn_allocate_permission(&mut test, now);
    tracing::error!("{:?}", test.client);
    let TurnPollRet::WaitUntil(now) = test.client.poll(now) else {
        unreachable!();
    };
    let transmit = test.client.poll_transmit(now).unwrap();
    let msg_reply = test.server.recv(transmit, now).unwrap();
    let peer_data = [8; 9];
    let peer_transmit = test
        .server
        .recv(peer_transmit(&test, peer_data.as_slice()), now)
        .unwrap();
    let TurnRecvRet::PeerData(peer) = test.client.recv(
        combine_transmit(&peer_transmit.build(), &msg_reply.build()),
        now,
    ) else {
        unreachable!();
    };
    assert_eq!(peer.data(), peer_data.as_slice());
}

fn create_test_tcp_allocation(split_transmit_bytes: usize) -> TurnTest<TurnClientTcp, TurnServer> {
    TurnTest::<TurnClientTcp, TurnServer>::builder()
        .split_transmit_bytes(split_transmit_bytes)
        .allocation_transport(TransportType::Tcp)
        .build(turn_tcp_new, turn_server_tcp_new)
}

#[test]
fn test_turn_tcp_data_peer_close() {
    let _log = test_init_log();
    let now = Instant::ZERO;
    for split in TRANSMIT_SPLITS {
        let mut test = create_test_tcp_allocation(split);
        turn_allocate_permission(&mut test, now);
        test.client
            .tcp_closed(test.local_tcp_socket, test.server.listen_address(), now);
        assert!(matches!(
            test.client
                .send_to(test.allocation_transport, test.peer_addr, [0, 3, 2], now),
            Err(SendError::NoTcpSocket)
        ));
    }
}

#[test]
fn test_turn_tcp_allocate_tcp_expire_server() {
    let _log = test_init_log();
    let now = Instant::ZERO;
    for split in TRANSMIT_SPLITS {
        let mut test = create_test_tcp_allocation(split);
        turn_allocate_expire_server(&mut test, now);
    }
}

#[test]
fn test_turn_tcp_permission_expire() {
    let _log = test_init_log();
    let now = Instant::ZERO;
    for split in TRANSMIT_SPLITS {
        let mut test = create_test_tcp_allocation(split);
        turn_allocate_permission(&mut test, now);
        let now = now + Duration::from_secs(3000);
        assert!(
            matches!(test.server.poll(now), TurnServerPollRet::TcpClose { local_addr, remote_addr } if local_addr == test.turn_alloc_addr && remote_addr == test.peer_addr)
        );
        assert!(
            matches!(test.server.poll(now), TurnServerPollRet::TcpClose { local_addr, remote_addr } if local_addr == test.server.listen_address() && remote_addr == test.local_tcp_socket)
        );
        assert!(matches!(
            test.client.recv(
                Transmit::new(
                    [],
                    TransportType::Tcp,
                    test.server.listen_address(),
                    test.local_tcp_socket
                ),
                now
            ),
            TurnRecvRet::Handled
        ));
        assert!(
            matches!(test.server.poll(now), TurnServerPollRet::SocketClose { transport, listen_addr } if transport == test.allocation_transport && listen_addr == test.turn_alloc_addr)
        );

        assert!(matches!(
            test.client
                .send_to(test.allocation_transport, test.peer_addr, [0, 3, 2], now),
            Err(SendError::NoTcpSocket)
        ));
    }
}

#[test]
fn test_turn_tcp_connection_bind_success_with_data_poll_recv() {
    let _log = test_init_log();
    let now = Instant::ZERO;
    for split in TRANSMIT_SPLITS {
        let mut test = create_test_tcp_allocation(split);
        test.allocate(now);
        let Some(TurnEvent::AllocationCreated(transport, relayed_address)) =
            test.client.poll_event()
        else {
            unreachable!();
        };
        assert_eq!(transport, test.allocation_transport);
        assert_eq!(relayed_address, test.turn_alloc_addr);
        test.create_permission(now);
        let Some(TurnEvent::PermissionCreated(_transport, _permission_ip)) =
            test.client.poll_event()
        else {
            unreachable!();
        };
        let (now, connection_id) = test.tcp_connect(now);
        let TurnPollRet::AllocateTcpSocket {
            id,
            socket,
            peer_addr,
        } = test.client.poll(now)
        else {
            unreachable!();
        };
        assert_eq!(connection_id, id);
        test.client
            .allocated_tcp_socket(id, socket, peer_addr, Some(test.local_tcp_socket), now)
            .unwrap();

        let data = [8; 7];
        // some peer sent data before ConnectionBind has completed
        assert!(test
            .server
            .recv(
                Transmit::new(
                    data,
                    test.allocation_transport,
                    test.peer_addr,
                    relayed_address
                ),
                now
            )
            .is_none());

        let now = test.client_advance(now);
        let transmit = test.client.poll_transmit(now).unwrap();
        let reply = test.server.recv(transmit, now).unwrap().build();
        let reply2 = test.server.poll_transmit(now).unwrap();
        assert!(matches!(
            test.client_recv(combine_transmit(&reply, &reply2), now),
            TurnRecvRet::Handled
        ));

        assert!(matches!(
            test.client.poll_event().unwrap(),
            TurnEvent::TcpConnected(_peer_addr)
        ));

        let recved = test.client.poll_recv(now).unwrap();
        assert_eq!(recved.transport, test.allocation_transport);
        assert_eq!(recved.peer, test.peer_addr);
        assert_eq!(recved.data(), data.as_slice());
    }
}

#[test]
fn test_turn_tcp_connection_bind_success_with_data_recv() {
    let _log = test_init_log();
    let now = Instant::ZERO;
    for split in TRANSMIT_SPLITS {
        let mut test = create_test_tcp_allocation(split);
        test.allocate(now);
        let Some(TurnEvent::AllocationCreated(transport, relayed_address)) =
            test.client.poll_event()
        else {
            unreachable!();
        };
        assert_eq!(transport, test.allocation_transport);
        assert_eq!(relayed_address, test.turn_alloc_addr);
        test.create_permission(now);
        let Some(TurnEvent::PermissionCreated(_transport, _permission_ip)) =
            test.client.poll_event()
        else {
            unreachable!();
        };
        let (now, connection_id) = test.tcp_connect(now);
        let TurnPollRet::AllocateTcpSocket {
            id,
            socket,
            peer_addr,
        } = test.client.poll(now)
        else {
            unreachable!();
        };
        assert_eq!(connection_id, id);
        test.client
            .allocated_tcp_socket(id, socket, peer_addr, Some(test.local_tcp_socket), now)
            .unwrap();

        let data = [8; 7];
        // some peer sent data before ConnectionBind has completed
        assert!(test
            .server
            .recv(
                Transmit::new(
                    data,
                    test.allocation_transport,
                    test.peer_addr,
                    relayed_address
                ),
                now
            )
            .is_none());

        let now = test.client_advance(now);
        let transmit = test.client.poll_transmit(now).unwrap();
        let reply = test.server.recv(transmit, now).unwrap().build();
        let reply2 = test.server.poll_transmit(now).unwrap();
        assert!(matches!(
            test.client_recv(combine_transmit(&reply, &reply2), now),
            TurnRecvRet::Handled
        ));

        assert!(matches!(
            test.client.poll_event().unwrap(),
            TurnEvent::TcpConnected(_peer_addr)
        ));

        let data2 = [42; 19];
        let transmit = test
            .server
            .recv(
                Transmit::new(
                    data2,
                    test.allocation_transport,
                    test.peer_addr,
                    relayed_address,
                ),
                now,
            )
            .unwrap()
            .build();

        let TurnRecvRet::PeerData(recved) = test.client.recv(transmit, now) else {
            unreachable!();
        };
        assert_eq!(recved.transport, test.allocation_transport);
        assert_eq!(recved.peer, test.peer_addr);
        assert_eq!(&recved.data()[..data.len()], data.as_slice());
        assert_eq!(&recved.data()[data.len()..], data2.as_slice());
    }
}
