// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![cfg(not(tarpaulin))]

use std::net::SocketAddr;
use turn_types::message::ALLOCATE;
use turn_types::stun::message::Message;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use stun_proto::agent::Transmit;
use stun_proto::Instant;
use turn_client_proto::api::{TurnEvent, TurnRecvRet};
use turn_client_proto::prelude::*;
use turn_client_proto::udp::TurnClientUdp;
use turn_server_proto::api::{TurnServerApi, TurnServerPollRet};
use turn_server_proto::server::TurnServer;
use turn_types::AddressFamily;
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
        let transmit = self.server.recv(transmit, now).unwrap();
        assert!(matches!(
            self.client.recv(transmit.build(), now),
            TurnRecvRet::Handled
        ));
        let transmit = self.client.poll_transmit(now).unwrap();
        assert!(self.server.recv(transmit, now).is_none());
        let TurnServerPollRet::AllocateSocketUdp {
            transport: _,
            local_addr,
            remote_addr,
            family,
        } = self.server.poll(now)
        else {
            unreachable!();
        };
        self.server.allocated_udp_socket(
            TransportType::Udp,
            local_addr,
            remote_addr,
            family,
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
    }

    fn create_permission(&mut self, now: Instant) {
        self.client
            .create_permission(TransportType::Udp, self.peer_addr.ip(), now)
            .unwrap();
        let transmit = self.client.poll_transmit(now).unwrap();
        let transmit = self.server.recv(transmit, now).unwrap();
        assert!(matches!(
            self.client.recv(transmit.build(), now),
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
        let transmit = self.server.recv(transmit, now).unwrap();
        assert!(matches!(
            self.client.recv(transmit.build(), now),
            TurnRecvRet::Handled
        ));
    }
}

static SIZES: [usize; 3] = [32, 1024, 16000];

fn bench_turn_server_sendrecv(c: &mut Criterion) {
    let mut test = TurnTest::new(
        |local_addr: SocketAddr, remote_addr: SocketAddr, credentials: TurnCredentials| {
            TurnClientUdp::allocate(local_addr, remote_addr, credentials, &[AddressFamily::IPV4])
        },
    );
    let now = Instant::ZERO;
    let transmit = test.client.poll_transmit(now).unwrap();
    let msg = Message::from_bytes(&transmit.data).unwrap();
    assert_eq!(msg.method(), ALLOCATE);

    c.bench_function("Allocate/Unauthenticated", |b| {
        b.iter_batched(
            || {
                Transmit::new(
                    transmit.data.clone(),
                    transmit.transport,
                    transmit.from,
                    transmit.to,
                )
            },
            |transmit| {
                test.server.recv(transmit, now).unwrap();
            },
            criterion::BatchSize::SmallInput,
        )
    });

    c.bench_function("Allocate/Authenticated", |b| {
        b.iter_batched(
            || {
                let mut test = TurnTest::new(
                    |local_addr: SocketAddr,
                     remote_addr: SocketAddr,
                     credentials: TurnCredentials| {
                        TurnClientUdp::allocate(
                            local_addr,
                            remote_addr,
                            credentials,
                            &[AddressFamily::IPV4],
                        )
                    },
                );
                let transmit = test.client.poll_transmit(now).unwrap();
                let transmit = test.server.recv(transmit, now).unwrap();
                test.client.recv(transmit.build(), now);
                let transmit = test.client.poll_transmit(now).unwrap();
                (test, transmit)
            },
            |(mut test, transmit)| {
                assert!(test.server.recv(transmit, now).is_none());
                let TurnServerPollRet::AllocateSocketUdp {
                    transport: _,
                    local_addr,
                    remote_addr,
                    family,
                } = test.server.poll(now)
                else {
                    unreachable!();
                };
                test.server.allocated_udp_socket(
                    TransportType::Udp,
                    local_addr,
                    remote_addr,
                    family,
                    Ok(test.relayed_addr),
                    now,
                );
                let _transmit = test.server.poll_transmit(now).unwrap();
            },
            criterion::BatchSize::SmallInput,
        )
    });

    c.bench_function("CreatePermission", |b| {
        b.iter_batched(
            || {
                let mut test = TurnTest::new(
                    |local_addr: SocketAddr,
                     remote_addr: SocketAddr,
                     credentials: TurnCredentials| {
                        TurnClientUdp::allocate(
                            local_addr,
                            remote_addr,
                            credentials,
                            &[AddressFamily::IPV4],
                        )
                    },
                );
                test.allocate(now);
                test.client
                    .create_permission(TransportType::Udp, test.peer_addr.ip(), now)
                    .unwrap();
                let transmit = test.client.poll_transmit(now).unwrap();

                (test, transmit)
            },
            |(mut test, transmit)| {
                let _transmit = test.server.recv(transmit, now).unwrap();
            },
            criterion::BatchSize::SmallInput,
        )
    });

    c.bench_function("ChannelBind", |b| {
        b.iter_batched(
            || {
                let mut test = TurnTest::new(
                    |local_addr: SocketAddr,
                     remote_addr: SocketAddr,
                     credentials: TurnCredentials| {
                        TurnClientUdp::allocate(
                            local_addr,
                            remote_addr,
                            credentials,
                            &[AddressFamily::IPV4],
                        )
                    },
                );
                test.allocate(now);
                test.create_permission(now);
                test.client
                    .bind_channel(TransportType::Udp, test.peer_addr, now)
                    .unwrap();
                let transmit = test.client.poll_transmit(now).unwrap();

                (test, transmit)
            },
            |(mut test, transmit)| {
                let _transmit = test.server.recv(transmit, now).unwrap();
            },
            criterion::BatchSize::SmallInput,
        )
    });

    let mut group = c.benchmark_group("Send");
    let mut test = TurnTest::new(
        |local_addr: SocketAddr, remote_addr: SocketAddr, credentials: TurnCredentials| {
            TurnClientUdp::allocate(local_addr, remote_addr, credentials, &[AddressFamily::IPV4])
        },
    );
    let now = Instant::ZERO;
    test.allocate(now);
    test.create_permission(now);
    for size in SIZES.iter() {
        let data = vec![8; *size];
        let transmit = test
            .client
            .send_to(TransportType::Udp, test.peer_addr, data, now)
            .unwrap()
            .unwrap()
            .build();
        let peer_transmit = test
            .server
            .recv(
                Transmit::new(
                    transmit.data.clone(),
                    transmit.transport,
                    transmit.from,
                    transmit.to,
                ),
                now,
            )
            .unwrap();
        assert_eq!(peer_transmit.transport, TransportType::Udp);
        assert_eq!(peer_transmit.from, test.relayed_addr);
        assert_eq!(peer_transmit.to, test.peer_addr);
        group.throughput(criterion::Throughput::Bytes(*size as u64));
        group.bench_function(BenchmarkId::new("Indication", *size), |b| {
            b.iter_batched(
                || {
                    Transmit::new(
                        transmit.data.clone(),
                        transmit.transport,
                        transmit.from,
                        transmit.to,
                    )
                },
                |transmit| {
                    let _transmit = test.server.recv(transmit, now).unwrap();
                },
                criterion::BatchSize::SmallInput,
            )
        });
    }
    test.channel_bind(now);
    for size in SIZES.iter() {
        let data = vec![8; *size];
        let transmit = test
            .client
            .send_to(TransportType::Udp, test.peer_addr, data, now)
            .unwrap()
            .unwrap()
            .build();
        let peer_transmit = test
            .server
            .recv(
                Transmit::new(
                    transmit.data.clone(),
                    transmit.transport,
                    transmit.from,
                    transmit.to,
                ),
                now,
            )
            .unwrap();
        assert_eq!(peer_transmit.transport, TransportType::Udp);
        assert_eq!(peer_transmit.from, test.relayed_addr);
        assert_eq!(peer_transmit.to, test.peer_addr);
        group.throughput(criterion::Throughput::Bytes(*size as u64));
        group.bench_function(BenchmarkId::new("Channel", *size), |b| {
            b.iter_batched(
                || {
                    Transmit::new(
                        transmit.data.clone(),
                        transmit.transport,
                        transmit.from,
                        transmit.to,
                    )
                },
                |transmit| {
                    let _transmit = test.server.recv(transmit, now).unwrap();
                },
                criterion::BatchSize::SmallInput,
            )
        });
    }
    group.finish();

    let mut group = c.benchmark_group("Recv");
    let mut test = TurnTest::new(
        |local_addr: SocketAddr, remote_addr: SocketAddr, credentials: TurnCredentials| {
            TurnClientUdp::allocate(local_addr, remote_addr, credentials, &[AddressFamily::IPV4])
        },
    );
    let now = Instant::ZERO;
    test.allocate(now);
    test.create_permission(now);
    for size in SIZES.iter() {
        let data = vec![8; *size];
        let transmit = Transmit::new(data, TransportType::Udp, test.peer_addr, test.relayed_addr);
        let peer_transmit = test
            .server
            .recv(
                Transmit::new(
                    transmit.data.clone(),
                    transmit.transport,
                    transmit.from,
                    transmit.to,
                ),
                now,
            )
            .unwrap();
        assert_eq!(peer_transmit.transport, TransportType::Udp);
        assert_eq!(peer_transmit.from, test.client.remote_addr());
        assert_eq!(peer_transmit.to, test.client.local_addr());
        group.throughput(criterion::Throughput::Bytes(*size as u64));
        group.bench_function(BenchmarkId::new("Indication", *size), |b| {
            b.iter_batched(
                || {
                    Transmit::new(
                        transmit.data.clone(),
                        transmit.transport,
                        transmit.from,
                        transmit.to,
                    )
                },
                |transmit| {
                    let _transmit = test.server.recv(transmit, now).unwrap();
                },
                criterion::BatchSize::SmallInput,
            )
        });
    }
    test.channel_bind(now);
    for size in SIZES.iter() {
        let data = vec![8; *size];
        let transmit = Transmit::new(data, TransportType::Udp, test.peer_addr, test.relayed_addr);
        let peer_transmit = test
            .server
            .recv(
                Transmit::new(
                    transmit.data.clone(),
                    transmit.transport,
                    transmit.from,
                    transmit.to,
                ),
                now,
            )
            .unwrap();
        assert_eq!(peer_transmit.transport, TransportType::Udp);
        assert_eq!(peer_transmit.from, test.client.remote_addr());
        assert_eq!(peer_transmit.to, test.client.local_addr());
        group.throughput(criterion::Throughput::Bytes(*size as u64));
        group.bench_function(BenchmarkId::new("Channel", *size), |b| {
            b.iter_batched(
                || {
                    Transmit::new(
                        transmit.data.clone(),
                        transmit.transport,
                        transmit.from,
                        transmit.to,
                    )
                },
                |transmit| {
                    let _transmit = test.server.recv(transmit, now).unwrap();
                },
                criterion::BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

criterion_group!(turn_client_sendrecv, bench_turn_server_sendrecv);
criterion_main!(turn_client_sendrecv);
