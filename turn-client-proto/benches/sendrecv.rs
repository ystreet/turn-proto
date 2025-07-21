// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![cfg(not(tarpaulin))]

use std::net::SocketAddr;
use std::time::Instant;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use stun_proto::agent::Transmit;
use turn_client_proto::common::{
    DelayedMessageOrChannelSend, DelayedTransmitBuild, TurnEvent, TurnRecvRet,
};
use turn_client_proto::prelude::*;
use turn_client_proto::udp::TurnClientUdp;
use turn_server_proto::{TurnServer, TurnServerPollRet};
use turn_types::{stun::TransportType, TurnCredentials};

struct TurnTest<T: TurnClientApi> {
    client: T,
    server: TurnServer,
    relayed_addr: SocketAddr,
    peer_addr: SocketAddr,
}

impl<T: TurnClientApi> TurnTest<T> {
    fn new<F: FnOnce(SocketAddr, SocketAddr, TurnCredentials) -> T>(init: F) -> Self {
        let local_addr = "192.168.0.2:2000".parse().unwrap();
        let turn_addr = "192.168.0.10:3478".parse().unwrap();
        let relayed_addr = "10.0.0.2:9000".parse().unwrap();
        let peer_addr: SocketAddr = "10.0.3.2:9999".parse().unwrap();
        let credentials = TurnCredentials::new("tuser", "tpass");
        let mut server = TurnServer::new(
            turn_types::stun::TransportType::Udp,
            turn_addr,
            String::from("realm"),
        );
        server.add_user(
            credentials.username().to_string(),
            credentials.password().to_string(),
        );
        let client = init(local_addr, turn_addr, credentials);

        Self {
            client,
            server,
            peer_addr,
            relayed_addr,
        }
    }

    fn allocate(&mut self, now: Instant) {
        let transmit = self.client.poll_transmit(now).unwrap();
        let transmit = self.server.recv(transmit, now).unwrap().unwrap();
        assert!(matches!(
            self.client.recv(transmit, now),
            TurnRecvRet::Handled
        ));
        let transmit = self.client.poll_transmit(now).unwrap();
        self.server.recv(transmit, now).unwrap();
        let TurnServerPollRet::AllocateSocketUdp {
            transport: _,
            local_addr,
            remote_addr,
        } = self.server.poll(now)
        else {
            unreachable!();
        };
        self.server.allocated_udp_socket(
            TransportType::Udp,
            local_addr,
            remote_addr,
            Ok(self.relayed_addr),
            now,
        );
        let transmit = self.server.poll_transmit(now).unwrap();
        assert!(matches!(
            self.client.recv(transmit, now),
            TurnRecvRet::Handled
        ));
        assert!(self
            .client
            .relayed_addresses()
            .any(|(transport, relayed)| transport == TransportType::Udp
                && relayed == self.relayed_addr));
        assert!(matches!(
            self.client.poll_event(),
            Some(TurnEvent::AllocationCreated(TransportType::Udp, _))
        ));

        self.client
            .create_permission(TransportType::Udp, self.peer_addr.ip(), now)
            .unwrap();
        let transmit = self.client.poll_transmit(now).unwrap();
        let transmit = self.server.recv(transmit, now).unwrap().unwrap();
        assert!(matches!(
            self.client.recv(transmit, now),
            TurnRecvRet::Handled
        ));
        assert!(matches!(
            self.client.poll_event(),
            Some(TurnEvent::PermissionCreated(TransportType::Udp, _))
        ));
    }

    fn channel_bind(&mut self, now: Instant) {
        self.client
            .bind_channel(TransportType::Udp, self.peer_addr, now)
            .unwrap();
        let transmit = self.client.poll_transmit(now).unwrap();
        let transmit = self.server.recv(transmit, now).unwrap().unwrap();
        assert!(matches!(
            self.client.recv(transmit, now),
            TurnRecvRet::Handled
        ));
    }
}

static SIZES: [usize; 3] = [32, 1024, 16000];

fn bench_turn_client_sendrecv(c: &mut Criterion) {
    let mut test = TurnTest::new(
        |local_addr: SocketAddr, remote_addr: SocketAddr, credentials: TurnCredentials| {
            TurnClientUdp::allocate(local_addr, remote_addr, credentials)
        },
    );

    let now = Instant::now();
    test.allocate(now);

    let mut group = c.benchmark_group("Turn/Send");

    for size in SIZES.iter() {
        group.throughput(criterion::Throughput::Bytes(*size as u64));
        let data = vec![7; *size];
        let transmit = test
            .client
            .send_to(TransportType::Udp, test.peer_addr, &data, now)
            .unwrap()
            .unwrap();
        assert!(matches!(
            transmit.data,
            DelayedMessageOrChannelSend::Message(_)
        ));
        group.bench_with_input(BenchmarkId::new("Indication", size), &data, |b, data| {
            b.iter(|| {
                test.client
                    .send_to(TransportType::Udp, test.peer_addr, data, now)
            })
        });
        group.bench_with_input(
            BenchmarkId::new("Indication/Build", size),
            &data,
            |b, data| {
                b.iter(|| {
                    let transmit = test
                        .client
                        .send_to(TransportType::Udp, test.peer_addr, data, now)
                        .unwrap()
                        .unwrap();
                    transmit.data.build()
                })
            },
        );
        let mut output = vec![0; *size + 36];
        group.bench_with_input(
            BenchmarkId::new("Indication/WriteInto", size),
            &data,
            |b, data| {
                b.iter(|| {
                    let transmit = test
                        .client
                        .send_to(TransportType::Udp, test.peer_addr, data, now)
                        .unwrap()
                        .unwrap();
                    transmit.data.write_into(&mut output);
                })
            },
        );
    }

    test.channel_bind(now);

    for size in SIZES.iter() {
        group.throughput(criterion::Throughput::Bytes(*size as u64));
        let data = vec![7; *size];
        let transmit = test
            .client
            .send_to(TransportType::Udp, test.peer_addr, &data, now)
            .unwrap()
            .unwrap();
        assert!(matches!(
            transmit.data,
            DelayedMessageOrChannelSend::Channel(_)
        ));
        group.bench_with_input(BenchmarkId::new("Channel", size), &data, |b, data| {
            b.iter(|| {
                test.client
                    .send_to(TransportType::Udp, test.peer_addr, data, now)
            })
        });
        group.bench_with_input(BenchmarkId::new("Channel/Build", size), &data, |b, data| {
            b.iter(|| {
                let transmit = test
                    .client
                    .send_to(TransportType::Udp, test.peer_addr, data, now)
                    .unwrap()
                    .unwrap();
                transmit.data.build()
            })
        });
        let mut output = vec![0; *size + 4];
        group.bench_with_input(
            BenchmarkId::new("Channel/WriteInto", size),
            &data,
            |b, data| {
                b.iter(|| {
                    let transmit = test
                        .client
                        .send_to(TransportType::Udp, test.peer_addr, data, now)
                        .unwrap()
                        .unwrap();
                    transmit.data.write_into(&mut output);
                })
            },
        );
    }
    drop(group);

    let mut group = c.benchmark_group("Turn/Recv");
    let mut test = TurnTest::new(
        |local_addr: SocketAddr, remote_addr: SocketAddr, credentials: TurnCredentials| {
            TurnClientUdp::allocate(local_addr, remote_addr, credentials)
        },
    );
    let now = Instant::now();
    test.allocate(now);

    for size in SIZES.iter() {
        group.throughput(criterion::Throughput::Bytes(*size as u64));
        let data = vec![9; *size];
        let transmit = Transmit::new(data, TransportType::Udp, test.peer_addr, test.relayed_addr);
        let transmit = test.server.recv(transmit, now).unwrap().unwrap();
        assert!(matches!(
            test.client.recv(
                Transmit::new(
                    transmit.data.clone(),
                    transmit.transport,
                    transmit.from,
                    transmit.to
                ),
                now
            ),
            TurnRecvRet::PeerData(peer) if peer.transport == TransportType::Udp && peer.peer == test.peer_addr
        ));
        group.bench_with_input(
            BenchmarkId::new("Indication", size),
            &transmit,
            |b, transmit| {
                b.iter_batched(
                    || {
                        Transmit::new(
                            transmit.data.clone(),
                            transmit.transport,
                            transmit.from,
                            transmit.to,
                        )
                    },
                    |transmit| test.client.recv(transmit, now),
                    criterion::BatchSize::SmallInput,
                )
            },
        );
    }

    test.channel_bind(now);

    for size in SIZES.iter() {
        group.throughput(criterion::Throughput::Bytes(*size as u64));
        let data = vec![9; *size];
        let transmit = Transmit::new(data, TransportType::Udp, test.peer_addr, test.relayed_addr);
        let transmit = test.server.recv(transmit, now).unwrap().unwrap();
        assert!(matches!(
            test.client.recv(
                Transmit::new(
                    transmit.data.clone(),
                    transmit.transport,
                    transmit.from,
                    transmit.to
                ),
                now
            ),
            TurnRecvRet::PeerData(peer) if peer.transport == TransportType::Udp && peer.peer == test.peer_addr
        ));
        group.bench_with_input(
            BenchmarkId::new("Channel", size),
            &transmit,
            |b, transmit| {
                b.iter_batched(
                    || {
                        Transmit::new(
                            transmit.data.clone(),
                            transmit.transport,
                            transmit.from,
                            transmit.to,
                        )
                    },
                    |transmit| test.client.recv(transmit, now),
                    criterion::BatchSize::SmallInput,
                )
            },
        );
    }
}

criterion_group!(turn_client_sendrecv, bench_turn_client_sendrecv);
criterion_main!(turn_client_sendrecv);
