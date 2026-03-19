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

use alloc::borrow::ToOwned;
use alloc::string::String;
use core::time::Duration;
use std::println;

use tracing::trace;

use turn_client_proto::api::*;
use turn_server_proto::api::{TurnServerApi, TurnServerPollRet};
use turn_types::{
    attribute::{
        ConnectionId, Data as AData, Lifetime, RequestedTransport, XorPeerAddress,
        XorRelayedAddress,
    },
    channel::ChannelData,
    message::{ALLOCATE, CHANNEL_BIND, CONNECT, CONNECTION_BIND, CREATE_PERMISSION, DATA, REFRESH},
    stun::{
        attribute::{
            AttributeStaticType, ErrorCode, MessageIntegrity, MessageIntegritySha256, Nonce, Realm,
            Userhash, Username, XorMappedAddress,
        },
        message::{Message, MessageClass, MessageType, MessageWriteVec, Method, TransactionId},
        prelude::{MessageWrite, MessageWriteExt},
    },
    TurnCredentials,
};

use tracing::subscriber::DefaultGuard;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::Layer;

use alloc::vec::Vec;
use core::net::SocketAddr;
use turn_types::prelude::DelayedTransmitBuild;
use turn_types::transmit::TransmitBuild;

use stun_proto::agent::Transmit;
use stun_proto::types::data::Data;
use stun_proto::types::TransportType;
use stun_proto::Instant;

static EXPIRY_BUFFER: Duration = Duration::from_secs(60);
static PERMISSION_DURATION: Duration = Duration::from_secs(300);
static MIN_STUN_REQUEST_CADENCE: Duration = Duration::from_millis(50);

pub fn test_init_log() -> DefaultGuard {
    turn_types::debug_init();
    let level_filter = std::env::var("TURN_LOG")
        .or(std::env::var("RUST_LOG"))
        .ok()
        .and_then(|var| var.parse::<tracing_subscriber::filter::Targets>().ok())
        .unwrap_or(tracing_subscriber::filter::Targets::new().with_default(tracing::Level::TRACE));
    let registry = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_file(true)
            .with_line_number(true)
            .with_level(true)
            .with_target(false)
            .with_test_writer()
            .with_filter(level_filter),
    );
    tracing::subscriber::set_default(registry)
}

pub fn transmit_send_build<T: DelayedTransmitBuild + core::fmt::Debug>(
    transmit: TransmitBuild<T>,
) -> Transmit<Data<'static>> {
    transmit
        .build()
        .reinterpret_data(|data| Data::from(data.into_boxed_slice()))
}
#[derive(Debug)]
pub struct TurnTestBuilder {
    turn_listen_addr: SocketAddr,
    credentials: TurnCredentials,
    realm: String,
    client_addr: SocketAddr,
    turn_alloc_addr: SocketAddr,
    peer_addr: SocketAddr,
    split_transmit_bytes: usize,
    allocation_transport: TransportType,
}
impl TurnTestBuilder {
    pub fn build<
        A: TurnClientApi,
        S: TurnServerApi,
        FClient: FnOnce(SocketAddr, SocketAddr, TurnCredentials, TransportType) -> A,
        FServer: FnOnce(SocketAddr, String) -> S,
    >(
        self,
        client: FClient,
        server: FServer,
    ) -> TurnTest<A, S> {
        let client = client(
            self.client_addr,
            self.turn_listen_addr,
            self.credentials.clone(),
            self.allocation_transport,
        );
        let mut server = server(self.turn_listen_addr, self.realm);
        server.add_user(
            self.credentials.username().to_owned(),
            self.credentials.password().to_owned(),
        );
        server.set_nonce_expiry_duration(Duration::from_secs(30));
        TurnTest {
            client,
            server,
            turn_alloc_addr: self.turn_alloc_addr,
            peer_addr: self.peer_addr,
            split_transmit_bytes: self.split_transmit_bytes,
            allocation_transport: self.allocation_transport,
            local_tcp_socket: "127.0.0.1:9999".parse().unwrap(),
        }
    }

    pub fn split_transmit_bytes(mut self, bytes: usize) -> Self {
        self.split_transmit_bytes = bytes;
        self
    }

    pub fn allocation_transport(mut self, allocation_transport: TransportType) -> Self {
        self.allocation_transport = allocation_transport;
        self
    }
}

#[derive(Debug)]
pub struct TurnTest<A: TurnClientApi, S: TurnServerApi> {
    pub client: A,
    pub server: S,
    pub turn_alloc_addr: SocketAddr,
    pub peer_addr: SocketAddr,
    pub split_transmit_bytes: usize,
    pub allocation_transport: TransportType,
    pub local_tcp_socket: SocketAddr,
}

impl<A: TurnClientApi, S: TurnServerApi> TurnTest<A, S> {
    pub fn builder() -> TurnTestBuilder {
        let credentials = TurnCredentials::new("turnuser", "turnpass");
        TurnTestBuilder {
            turn_listen_addr: "127.0.0.1:3478".parse().unwrap(),
            credentials,
            realm: String::from("realm"),
            client_addr: "127.0.0.1:2000".parse().unwrap(),
            turn_alloc_addr: "10.0.0.20:2000".parse().unwrap(),
            peer_addr: "10.0.0.3:3000".parse().unwrap(),
            split_transmit_bytes: 0,
            allocation_transport: TransportType::Udp,
        }
    }

    pub fn client_recv<T: AsRef<[u8]> + core::fmt::Debug>(
        &mut self,
        transmit: Transmit<T>,
        now: Instant,
    ) -> TurnRecvRet<Vec<u8>> {
        if self.split_transmit_bytes > 0 {
            assert!(matches!(
                self.client.recv(
                    Transmit::new(
                        &transmit.data.as_ref()[..self.split_transmit_bytes],
                        transmit.transport,
                        transmit.from,
                        transmit.to
                    ),
                    now
                ),
                TurnRecvRet::Handled
            ));
            self.client.recv(
                Transmit::new(
                    transmit.data.as_ref()[self.split_transmit_bytes..].to_vec(),
                    transmit.transport,
                    transmit.from,
                    transmit.to,
                ),
                now,
            )
        } else {
            self.client.recv(
                transmit.reinterpret_data(|data| data.as_ref().to_vec()),
                now,
            )
        }
    }

    pub fn client_advance(&mut self, now: Instant) -> Instant {
        let TurnPollRet::WaitUntil(expiry) = self.client.poll(now) else {
            unreachable!();
        };
        assert!(expiry > now);
        trace!("advancing time to {expiry}");
        expiry
    }

    pub fn allocate(&mut self, now: Instant) -> Instant {
        // initial allocate
        let transmit = self.client.poll_transmit(now).unwrap();
        let msg = Message::from_bytes(&transmit.data).unwrap();
        assert!(msg.has_method(ALLOCATE));
        assert!(msg.has_class(stun_proto::types::message::MessageClass::Request));
        assert!(msg.has_attribute(RequestedTransport::TYPE));
        assert!(!msg.has_attribute(Realm::TYPE));
        assert!(!msg.has_attribute(Nonce::TYPE));
        assert!(!msg.has_attribute(Username::TYPE));
        assert!(!msg.has_attribute(Userhash::TYPE));
        assert!(!msg.has_attribute(MessageIntegrity::TYPE));
        assert!(!msg.has_attribute(MessageIntegritySha256::TYPE));
        // error reply
        let transmit = self.server.recv(transmit, now).unwrap().build();
        let msg = Message::from_bytes(&transmit.data).unwrap();
        assert!(msg.has_method(ALLOCATE));
        assert!(msg.has_class(stun_proto::types::message::MessageClass::Error));
        assert!(msg.has_attribute(Realm::TYPE));
        let err = msg.attribute::<ErrorCode>().unwrap();
        assert_eq!(err.code(), ErrorCode::UNAUTHORIZED);
        assert!(msg.has_attribute(Nonce::TYPE));
        assert!(matches!(
            self.client_recv(transmit, now),
            TurnRecvRet::Handled
        ));

        // authenticated allocate
        let now = self.client_advance(now);
        let transmit = self.client.poll_transmit(now).unwrap();
        let msg = Message::from_bytes(&transmit.data).unwrap();
        assert!(msg.has_method(ALLOCATE));
        assert!(msg.has_class(stun_proto::types::message::MessageClass::Request));
        assert!(msg.has_attribute(RequestedTransport::TYPE));
        assert!(msg.has_attribute(Realm::TYPE));
        assert!(msg.has_attribute(Nonce::TYPE));
        assert!(msg.has_attribute(Username::TYPE) || msg.has_attribute(Userhash::TYPE));
        assert!(msg.has_attribute(MessageIntegrity::TYPE));
        assert!(self.server.recv(transmit, now).is_none());
        let TurnServerPollRet::AllocateSocket {
            transport,
            listen_addr: alloc_local_addr,
            client_addr: alloc_remote_addr,
            allocation_transport,
            family,
        } = self.server.poll(now)
        else {
            unreachable!();
        };
        assert_eq!(transport, self.client.transport());
        assert_eq!(alloc_local_addr, self.server.listen_address());
        assert_eq!(alloc_remote_addr, self.client.local_addr());
        assert_eq!(allocation_transport, self.allocation_transport);
        self.server.allocated_socket(
            transport,
            alloc_local_addr,
            alloc_remote_addr,
            allocation_transport,
            family,
            Ok(self.turn_alloc_addr),
            now,
        );
        // ok reply
        let Some(transmit) = self.server.poll_transmit(now) else {
            unreachable!();
        };
        trace!("server: {:?}", self.server);
        let msg = Message::from_bytes(&transmit.data).unwrap();
        assert!(msg.has_method(ALLOCATE));
        assert!(msg.has_class(stun_proto::types::message::MessageClass::Success));
        assert!(msg.has_attribute(XorRelayedAddress::TYPE));
        assert!(msg.has_attribute(Lifetime::TYPE));
        assert!(msg.has_attribute(XorMappedAddress::TYPE));
        assert!(msg.has_attribute(MessageIntegrity::TYPE));
        assert!(matches!(
            self.client_recv(transmit, now),
            TurnRecvRet::Handled
        ));
        assert!(self
            .client
            .relayed_addresses()
            .any(
                |(transport, relayed)| transport == self.allocation_transport
                    && relayed == self.turn_alloc_addr
            ));
        now
    }

    fn refresh(&mut self, now: Instant) -> Instant {
        let TurnPollRet::WaitUntil(expiry) = self.client.poll(now) else {
            unreachable!()
        };
        assert_eq!(now, expiry);
        let transmit = self.client.poll_transmit(now).unwrap();
        trace!("transmit {:?}", transmit.data);
        let msg = Message::from_bytes(&transmit.data).unwrap();
        assert!(msg.has_method(REFRESH));
        assert!(msg.has_class(stun_proto::types::message::MessageClass::Request));
        assert!(msg.has_attribute(Realm::TYPE));
        assert!(msg.has_attribute(Nonce::TYPE));
        assert!(msg.has_attribute(Username::TYPE) || msg.has_attribute(Userhash::TYPE));
        assert!(msg.has_attribute(MessageIntegrity::TYPE));
        // ok reply
        let transmit = self.server.recv(transmit, now).unwrap().build();
        let Some(transmit) = self.maybe_handles_stale_nonce(transmit, now) else {
            return self.refresh(now + MIN_STUN_REQUEST_CADENCE);
        };
        let msg = Message::from_bytes(&transmit.data).unwrap();
        assert!(msg.has_method(REFRESH));
        assert!(msg.has_class(stun_proto::types::message::MessageClass::Success));
        assert!(msg.has_attribute(Lifetime::TYPE));
        assert!(msg.has_attribute(MessageIntegrity::TYPE));
        assert!(matches!(
            self.client_recv(transmit, now),
            TurnRecvRet::Handled
        ));
        assert!(self
            .client
            .relayed_addresses()
            .any(
                |(transport, relayed)| transport == self.allocation_transport
                    && relayed == self.turn_alloc_addr
            ));
        now
    }

    fn delete_allocation(&mut self, now: Instant) -> Instant {
        self.client.delete(now).unwrap();
        let now = self.client_advance(now);
        let transmit = self.client.poll_transmit(now).unwrap();
        self.handle_delete_allocation(transmit, now)
    }

    fn handle_delete_allocation<T: AsRef<[u8]> + core::fmt::Debug>(
        &mut self,
        transmit: Transmit<T>,
        now: Instant,
    ) -> Instant {
        let msg = Message::from_bytes(transmit.data.as_ref()).unwrap();
        assert!(msg.has_method(REFRESH));
        assert!(msg.has_class(stun_proto::types::message::MessageClass::Request));
        assert!(msg.has_attribute(Lifetime::TYPE));
        assert!(msg.has_attribute(Realm::TYPE));
        assert!(msg.has_attribute(Nonce::TYPE));
        assert!(msg.has_attribute(Username::TYPE) || msg.has_attribute(Userhash::TYPE));
        assert!(msg.has_attribute(MessageIntegrity::TYPE));
        // ok reply
        let transmit = self.server.recv(transmit, now).unwrap().build();
        let Some(transmit) = self.maybe_handles_stale_nonce(transmit, now) else {
            let now = self.client_advance(now);
            let transmit = self.client.poll_transmit(now).unwrap();
            self.handle_delete_allocation(transmit, now);
            return now;
        };
        let msg = Message::from_bytes(&transmit.data).unwrap();
        assert!(msg.has_method(REFRESH));
        assert!(msg.has_class(stun_proto::types::message::MessageClass::Success));
        assert!(msg.has_attribute(Lifetime::TYPE));
        assert!(msg.has_attribute(MessageIntegrity::TYPE));
        assert!(matches!(
            self.client_recv(transmit, now),
            TurnRecvRet::Handled
        ));
        assert!(!self
            .client
            .relayed_addresses()
            .any(
                |(transport, relayed)| transport == self.allocation_transport
                    && relayed == self.turn_alloc_addr
            ));
        now
    }

    pub fn create_permission(&mut self, now: Instant) -> Instant {
        self.client
            .create_permission(self.allocation_transport, self.peer_addr.ip(), now)
            .unwrap();
        let now = self.client_advance(now);
        let transmit = self.client.poll_transmit(now).unwrap();
        self.handle_create_permission(transmit, now)
    }

    fn handle_create_permission<T: AsRef<[u8]> + core::fmt::Debug>(
        &mut self,
        transmit: Transmit<T>,
        now: Instant,
    ) -> Instant {
        let msg = Message::from_bytes(transmit.data.as_ref()).unwrap();
        assert!(msg.has_method(CREATE_PERMISSION));
        assert!(msg.has_class(stun_proto::types::message::MessageClass::Request));
        assert!(msg.has_attribute(XorPeerAddress::TYPE));
        assert!(msg.has_attribute(MessageIntegrity::TYPE));
        let transmit = self.server.recv(transmit, now).unwrap().build();
        let Some(transmit) = self.maybe_handles_stale_nonce(transmit, now) else {
            let now = self.client_advance(now);
            let transmit = self.client.poll_transmit(now).unwrap();
            self.handle_create_permission(transmit, now);
            return now;
        };
        assert!(matches!(
            self.client_recv(transmit, now),
            TurnRecvRet::Handled
        ));
        self.validate_client_permission_state();
        now
    }

    fn maybe_handles_stale_nonce<T: AsRef<[u8]> + core::fmt::Debug>(
        &mut self,
        transmit: Transmit<T>,
        now: Instant,
    ) -> Option<Transmit<T>> {
        let msg = Message::from_bytes(transmit.data.as_ref()).unwrap();
        if msg.has_class(stun_proto::types::message::MessageClass::Error) {
            let error = msg.attribute::<ErrorCode>().unwrap();
            assert_eq!(error.code(), ErrorCode::STALE_NONCE);
            assert!(matches!(
                self.client_recv(transmit, now),
                TurnRecvRet::Handled
            ));
            None
        } else {
            Some(transmit)
        }
    }

    fn validate_client_permission_state(&self) {
        assert!(self
            .client
            .permissions(self.allocation_transport, self.turn_alloc_addr)
            .any(|perm_addr| perm_addr == self.peer_addr.ip()));
    }

    fn bind_channel(&mut self, now: Instant) -> Instant {
        self.client
            .bind_channel(self.allocation_transport, self.peer_addr, now)
            .unwrap();
        let now = self.client_advance(now);
        let transmit = self.client.poll_transmit(now).unwrap();
        self.handle_bind_channel(transmit, now)
    }

    fn handle_bind_channel<T: AsRef<[u8]> + core::fmt::Debug>(
        &mut self,
        transmit: Transmit<T>,
        now: Instant,
    ) -> Instant {
        let msg = Message::from_bytes(transmit.data.as_ref()).unwrap();
        assert!(msg.has_method(CHANNEL_BIND));
        assert!(msg.has_class(stun_proto::types::message::MessageClass::Request));
        assert!(msg.has_attribute(XorPeerAddress::TYPE));
        assert!(msg.has_attribute(MessageIntegrity::TYPE));
        let transmit = self.server.recv(transmit, now).unwrap().build();
        let Some(transmit) = self.maybe_handles_stale_nonce(transmit, now) else {
            let now = self.client_advance(now);
            let transmit = self.client.poll_transmit(now).unwrap();
            self.handle_create_permission(transmit, now);
            return now;
        };
        assert!(matches!(
            self.client_recv(transmit, now),
            TurnRecvRet::Handled
        ));
        assert!(self
            .client
            .have_permission(self.allocation_transport, self.peer_addr.ip()));
        now
    }

    fn sendrecv_data(&mut self, now: Instant) {
        // client to peer
        let data = [4; 8];
        let transmit = self
            .client
            .send_to(self.allocation_transport, self.peer_addr, data, now)
            .unwrap()
            .unwrap();
        assert!(matches!(
            transmit.data,
            DelayedMessageOrChannelSend::Message(_)
        ));
        let transmit = transmit_send_build(transmit);
        assert_eq!(transmit.transport, self.client.transport());
        assert_eq!(transmit.from, self.client.local_addr());
        assert_eq!(transmit.to, self.server.listen_address());
        let transmit = self.server.recv(transmit, now).unwrap();
        assert_eq!(transmit.transport, self.allocation_transport);
        assert_eq!(transmit.from, self.turn_alloc_addr);
        assert_eq!(transmit.to, self.peer_addr);
        assert_eq!(transmit.build().data, data);

        // peer to client
        let sent_data = [5; 12];
        let transmit = self
            .server
            .recv(
                Transmit::new(
                    sent_data,
                    self.allocation_transport,
                    self.peer_addr,
                    self.turn_alloc_addr,
                ),
                now,
            )
            .unwrap()
            .build();
        assert_eq!(transmit.transport, self.client.transport());
        assert_eq!(transmit.from, self.server.listen_address());
        assert_eq!(transmit.to, self.client.local_addr());
        let msg = Message::from_bytes(&transmit.data).unwrap();
        assert!(msg.has_class(stun_proto::types::message::MessageClass::Indication));
        assert!(msg.has_method(DATA));
        let data = msg.attribute::<AData>().unwrap();
        assert_eq!(data.data(), sent_data);
        let TurnRecvRet::PeerData(peer_data) = self.client_recv(transmit, now) else {
            unreachable!();
        };
        assert_eq!(peer_data.peer, self.peer_addr);
        assert_eq!(peer_data.as_ref(), sent_data);
        assert!(self.client.poll_recv(now).is_none());
    }

    fn sendrecv_data_channel(&mut self, now: Instant) {
        let to_peer = [4; 8];
        let from_peer = [5; 12];
        self.sendrecv_data_channel_with_data(&to_peer, &from_peer, now);
    }

    fn sendrecv_data_channel_with_data(&mut self, to_peer: &[u8], from_peer: &[u8], now: Instant) {
        let transmit = self
            .client
            .send_to(self.allocation_transport, self.peer_addr, to_peer, now)
            .unwrap()
            .unwrap();
        assert!(matches!(
            transmit.data,
            DelayedMessageOrChannelSend::Channel(_)
        ));
        assert_eq!(transmit.transport, self.client.transport());
        assert_eq!(transmit.from, self.client.local_addr());
        assert_eq!(transmit.to, self.server.listen_address());
        let transmit = transmit_send_build(transmit);
        let transmit = self
            .server
            .recv(transmit, now)
            .map(|transmit| transmit.build())
            .or_else(|| self.server.poll_transmit(now))
            .unwrap();
        assert_eq!(transmit.transport, self.allocation_transport);
        assert_eq!(transmit.from, self.turn_alloc_addr);
        assert_eq!(transmit.to, self.peer_addr);
        assert_eq!(transmit.data, to_peer);

        // peer to client
        let transmit = self
            .server
            .recv(
                Transmit::new(
                    from_peer,
                    self.allocation_transport,
                    self.peer_addr,
                    self.turn_alloc_addr,
                ),
                now,
            )
            .unwrap()
            .build();
        assert_eq!(transmit.transport, self.client.transport());
        assert_eq!(transmit.from, self.server.listen_address());
        assert_eq!(transmit.to, self.client.local_addr());
        let cd = ChannelData::parse(&transmit.data).unwrap();
        assert_eq!(cd.data(), from_peer);
        let TurnRecvRet::PeerData(peer_data) = self.client_recv(transmit, now) else {
            unreachable!();
        };
        assert_eq!(peer_data.peer, self.peer_addr);
        assert_eq!(peer_data.data(), from_peer);
        assert!(self.client.poll_recv(now).is_none());
    }

    pub fn tcp_connect(&mut self, now: Instant) -> (Instant, u32) {
        self.client.tcp_connect(self.peer_addr, now).unwrap();
        let now = self.client_advance(now);
        let transmit = self.client.poll_transmit(now).unwrap();
        assert_eq!(transmit.transport, self.client.transport());
        assert_eq!(transmit.from, self.client.local_addr());
        assert_eq!(transmit.to, self.server.listen_address());
        let msg = Message::from_bytes(&transmit.data).unwrap();
        assert!(msg.has_method(CONNECT));
        assert!(self.server.recv(transmit, now).is_none());
        let TurnServerPollRet::TcpConnect {
            relayed_addr,
            peer_addr,
            listen_addr,
            client_addr,
        } = self.server.poll(now)
        else {
            unreachable!();
        };
        assert_eq!(peer_addr, self.peer_addr);
        assert_eq!(listen_addr, self.server.listen_address());
        assert_eq!(client_addr, self.client.local_addr());
        self.server.tcp_connected(
            relayed_addr,
            peer_addr,
            listen_addr,
            client_addr,
            Ok(relayed_addr),
            now,
        );
        let transmit = self.server.poll_transmit(now).unwrap();
        assert_eq!(transmit.from, self.server.listen_address());
        assert_eq!(transmit.to, self.client.local_addr());
        assert_eq!(transmit.transport, self.client.transport());
        let msg = Message::from_bytes(&transmit.data).unwrap();
        assert!(msg.has_method(CONNECT));
        assert!(msg.has_class(MessageClass::Success));
        let connection_id = msg.attribute::<ConnectionId>().unwrap().id();
        assert!(matches!(
            self.client_recv(transmit, now),
            TurnRecvRet::Handled
        ));
        (now, connection_id)
    }

    pub fn tcp_connection_bind(&mut self, connection_id: u32, now: Instant) -> Instant {
        let TurnPollRet::AllocateTcpSocket {
            id,
            socket,
            peer_addr,
        } = self.client.poll(now)
        else {
            unreachable!();
        };
        assert_eq!(connection_id, id);
        assert_eq!(socket.transport, TransportType::Tcp);
        assert_eq!(socket.from, self.client.local_addr());
        assert_eq!(socket.to, self.server.listen_address());
        assert_eq!(peer_addr, self.peer_addr);
        self.client
            .allocated_tcp_socket(id, socket, peer_addr, Some(self.local_tcp_socket), now)
            .unwrap();
        let now = self.client_advance(now);
        let transmit = self.client.poll_transmit(now).unwrap();
        assert_eq!(transmit.transport, TransportType::Tcp);
        assert_eq!(transmit.from, self.local_tcp_socket);
        assert_eq!(transmit.to, self.server.listen_address());
        let msg = Message::from_bytes(&transmit.data).unwrap();
        assert!(msg.has_method(CONNECTION_BIND));
        assert_eq!(msg.attribute::<ConnectionId>().unwrap().id(), id);
        let reply = self.server.recv(transmit, now).unwrap().build();
        assert_eq!(reply.transport, TransportType::Tcp);
        assert_eq!(reply.from, self.server.listen_address());
        assert_eq!(reply.to, self.local_tcp_socket);
        let msg = Message::from_bytes(&reply.data).unwrap();
        assert!(msg.has_method(CONNECTION_BIND));
        assert!(msg.has_class(MessageClass::Success));
        assert!(matches!(self.client_recv(reply, now), TurnRecvRet::Handled));

        assert!(matches!(
            self.client.poll_event().unwrap(),
            TurnEvent::TcpConnected(_peer_addr)
        ));
        now
    }

    fn tcp_alloc_sendrecv_data(&mut self, now: Instant) {
        // client to peer
        let data = [4; 8];
        let transmit = self
            .client
            .send_to(self.allocation_transport, self.peer_addr, data, now)
            .unwrap()
            .unwrap();
        assert!(matches!(
            transmit.data,
            DelayedMessageOrChannelSend::Data(_)
        ));
        let transmit = transmit_send_build(transmit);
        assert_eq!(transmit.transport, self.client.transport());
        assert_eq!(transmit.from, self.local_tcp_socket);
        assert_eq!(transmit.to, self.server.listen_address());
        let transmit = self.server.recv(transmit, now).unwrap();
        assert_eq!(transmit.transport, self.allocation_transport);
        assert_eq!(transmit.from, self.turn_alloc_addr);
        assert_eq!(transmit.to, self.peer_addr);
        assert_eq!(transmit.build().data, data);

        // peer to client
        let sent_data = [5; 12];
        let transmit = self
            .server
            .recv(
                Transmit::new(
                    sent_data,
                    self.allocation_transport,
                    self.peer_addr,
                    self.turn_alloc_addr,
                ),
                now,
            )
            .unwrap()
            .build();
        assert_eq!(transmit.transport, self.client.transport());
        assert_eq!(transmit.from, self.server.listen_address());
        assert_eq!(transmit.to, self.local_tcp_socket);
        assert_eq!(&transmit.data, sent_data.as_slice());
        let TurnRecvRet::PeerData(peer_data) = self.client.recv(transmit, now) else {
            unreachable!();
        };
        assert_eq!(peer_data.peer, self.peer_addr);
        assert_eq!(peer_data.as_ref(), sent_data);
        assert!(self.client.poll_recv(now).is_none());
    }
}

pub fn turn_allocate_permission<A: TurnClientApi, S: TurnServerApi>(
    test: &mut TurnTest<A, S>,
    now: Instant,
) -> Instant {
    let now = test.allocate(now);
    let Some(TurnEvent::AllocationCreated(transport, relayed_address)) = test.client.poll_event()
    else {
        unreachable!();
    };
    assert_eq!(transport, test.allocation_transport);
    assert_eq!(relayed_address, test.turn_alloc_addr);
    let now = test.create_permission(now);
    let Some(TurnEvent::PermissionCreated(transport, permission_ip)) = test.client.poll_event()
    else {
        unreachable!();
    };
    assert_eq!(transport, test.allocation_transport);
    assert_eq!(permission_ip, test.peer_addr.ip());

    if test.allocation_transport == TransportType::Tcp {
        let (now, connection_id) = test.tcp_connect(now);
        let now = test.tcp_connection_bind(connection_id, now);
        test.tcp_alloc_sendrecv_data(now);
        now
    } else {
        test.sendrecv_data(now);
        let now = test.bind_channel(now);
        let Some(TurnEvent::ChannelCreated(transport, channel_addr)) = test.client.poll_event()
        else {
            unreachable!();
        };
        assert_eq!(transport, test.allocation_transport);
        assert_eq!(channel_addr, test.peer_addr);
        test.sendrecv_data_channel(now);
        now
    }
}

pub fn turn_allocate_expire_server<A: TurnClientApi, S: TurnServerApi>(
    test: &mut TurnTest<A, S>,
    now: Instant,
) {
    test.server
        .set_nonce_expiry_duration(Duration::from_secs(9000));

    test.allocate(now);
    let Some(TurnEvent::AllocationCreated(transport, relayed_address)) = test.client.poll_event()
    else {
        unreachable!();
    };
    assert_eq!(transport, test.allocation_transport);
    assert_eq!(relayed_address, test.turn_alloc_addr);
    test.client
        .create_permission(test.allocation_transport, test.peer_addr.ip(), now)
        .unwrap();
    let now = test.client_advance(now);
    let transmit = test.client.poll_transmit(now).unwrap();
    let now = now + Duration::from_secs(3000);
    let transmit = test.server.recv(transmit, now).unwrap().build();
    let msg = Message::from_bytes(&transmit.data).unwrap();
    assert!(msg.has_method(CREATE_PERMISSION));
    assert!(msg.has_class(stun_proto::types::message::MessageClass::Error));
    let err = msg.attribute::<ErrorCode>().unwrap();
    assert_eq!(err.code(), ErrorCode::ALLOCATION_MISMATCH);
    let ret = test.client.recv(transmit, now);
    assert!(matches!(ret, TurnRecvRet::Handled));
    assert!(
        matches!(test.server.poll(now), TurnServerPollRet::SocketClose { transport, listen_addr } if transport == test.allocation_transport && listen_addr == test.turn_alloc_addr)
    );
}

pub fn turn_allocate_expire_client<A: TurnClientApi, S: TurnServerApi>(
    test: &mut TurnTest<A, S>,
    now: Instant,
) {
    let now = test.allocate(now);
    let Some(TurnEvent::AllocationCreated(transport, relayed_address)) = test.client.poll_event()
    else {
        unreachable!();
    };
    assert_eq!(transport, test.allocation_transport);
    assert_eq!(relayed_address, test.turn_alloc_addr);
    let now = now + Duration::from_secs(3000);
    let Err(CreatePermissionError::NoAllocation) =
        test.client
            .create_permission(test.allocation_transport, test.peer_addr.ip(), now)
    else {
        unreachable!();
    };
    assert!(
        matches!(test.server.poll(now), TurnServerPollRet::SocketClose { transport, listen_addr } if transport == test.allocation_transport && listen_addr == test.turn_alloc_addr)
    );
}

pub fn turn_allocate_refresh<A: TurnClientApi, S: TurnServerApi>(
    test: &mut TurnTest<A, S>,
    now: Instant,
) {
    let now = test.allocate(now);
    let Some(TurnEvent::AllocationCreated(transport, relayed_address)) = test.client.poll_event()
    else {
        unreachable!();
    };
    assert_eq!(transport, test.allocation_transport);
    assert_eq!(relayed_address, test.turn_alloc_addr);

    let TurnPollRet::WaitUntil(expiry) = test.client.poll(now) else {
        unreachable!()
    };
    trace!("expiry: {expiry:?}");
    assert!(expiry > now + Duration::from_secs(1000));

    let expiry = test.refresh(expiry);
    test.create_permission(expiry);
    let Some(TurnEvent::PermissionCreated(transport, permission_ip)) = test.client.poll_event()
    else {
        unreachable!();
    };
    assert_eq!(transport, test.allocation_transport);
    assert_eq!(permission_ip, test.peer_addr.ip());
    test.sendrecv_data(expiry);
}

pub fn turn_allocate_delete<A: TurnClientApi, S: TurnServerApi>(
    test: &mut TurnTest<A, S>,
    now: Instant,
) {
    let now = test.allocate(now);
    let Some(TurnEvent::AllocationCreated(_transport, _relayed_address)) = test.client.poll_event()
    else {
        unreachable!();
    };
    test.delete_allocation(now);
    assert!(
        matches!(test.server.poll(now), TurnServerPollRet::SocketClose { transport, listen_addr } if transport == test.allocation_transport && listen_addr == test.turn_alloc_addr)
    );

    let Err(CreatePermissionError::NoAllocation) =
        test.client
            .create_permission(test.allocation_transport, test.peer_addr.ip(), now)
    else {
        unreachable!();
    };
}

pub fn turn_channel_bind<A: TurnClientApi, S: TurnServerApi>(
    test: &mut TurnTest<A, S>,
    now: Instant,
) {
    let now = test.allocate(now);
    let Some(TurnEvent::AllocationCreated(transport, relayed_address)) = test.client.poll_event()
    else {
        unreachable!();
    };
    assert_eq!(transport, test.allocation_transport);
    assert_eq!(relayed_address, test.turn_alloc_addr);
    let now = test.bind_channel(now);
    let Some(TurnEvent::PermissionCreated(transport, permission_ip)) = test.client.poll_event()
    else {
        unreachable!();
    };
    assert_eq!(transport, test.allocation_transport);
    assert_eq!(permission_ip, test.peer_addr.ip());
    test.sendrecv_data_channel(now);
}

pub fn turn_peer_incoming_stun<A: TurnClientApi, S: TurnServerApi>(
    test: &mut TurnTest<A, S>,
    now: Instant,
) {
    // tests that sending stun messages can be passed through the turn server
    let now = test.allocate(now);
    let Some(TurnEvent::AllocationCreated(transport, relayed_address)) = test.client.poll_event()
    else {
        unreachable!();
    };
    assert_eq!(transport, test.allocation_transport);
    assert_eq!(relayed_address, test.turn_alloc_addr);
    let now = test.bind_channel(now);
    let Some(TurnEvent::PermissionCreated(transport, permission_ip)) = test.client.poll_event()
    else {
        unreachable!();
    };
    assert_eq!(transport, test.allocation_transport);
    assert_eq!(permission_ip, test.peer_addr.ip());

    let mut msg = Message::builder(
        MessageType::from_class_method(
            turn_types::stun::message::MessageClass::Indication,
            Method::new(0x1432),
        ),
        TransactionId::generate(),
        MessageWriteVec::new(),
    );
    let realm = Realm::new("realm").unwrap();
    msg.add_attribute(&realm).unwrap();
    let data = msg.finish();
    test.sendrecv_data_channel_with_data(&data, &data, now);
}

pub fn turn_create_permission_refresh<A: TurnClientApi, S: TurnServerApi>(
    test: &mut TurnTest<A, S>,
    now: Instant,
) {
    let now = test.allocate(now);
    let Some(TurnEvent::AllocationCreated(transport, relayed_address)) = test.client.poll_event()
    else {
        unreachable!();
    };
    assert_eq!(transport, test.allocation_transport);
    assert_eq!(relayed_address, test.turn_alloc_addr);

    let now = test.create_permission(now);
    let Some(TurnEvent::PermissionCreated(transport, permission_ip)) = test.client.poll_event()
    else {
        unreachable!();
    };
    assert_eq!(transport, test.allocation_transport);
    assert_eq!(permission_ip, test.peer_addr.ip());

    let TurnPollRet::WaitUntil(expiry) = test.client.poll(now) else {
        unreachable!()
    };
    assert_eq!(expiry, now + PERMISSION_DURATION - EXPIRY_BUFFER);
    let TurnPollRet::WaitUntil(mut now) = test.client.poll(expiry) else {
        unreachable!()
    };
    assert_eq!(now, expiry);

    let create_permission = |test: &mut TurnTest<A, S>, now: Instant| -> Transmit<Vec<u8>> {
        let transmit = test.client.poll_transmit(now).unwrap();
        let msg = Message::from_bytes(&transmit.data).unwrap();
        assert_eq!(msg.method(), CREATE_PERMISSION);
        test.server.recv(transmit, now).unwrap().build()
    };

    let transmit = create_permission(test, now);
    let transmit = if let Some(transmit) = test.maybe_handles_stale_nonce(transmit, now) {
        transmit
    } else {
        now = test.client_advance(now);
        create_permission(test, now)
    };
    assert!(matches!(
        test.client.recv(transmit, expiry),
        TurnRecvRet::Handled
    ));
    test.validate_client_permission_state();

    test.sendrecv_data(expiry);
}

pub fn turn_create_permission_timeout<A: TurnClientApi, S: TurnServerApi>(
    test: &mut TurnTest<A, S>,
    now: Instant,
) {
    let now = test.allocate(now);
    let Some(TurnEvent::AllocationCreated(transport, relayed_address)) = test.client.poll_event()
    else {
        unreachable!();
    };
    assert_eq!(transport, test.allocation_transport);
    assert_eq!(relayed_address, test.turn_alloc_addr);

    let now = test.create_permission(now);
    let Some(TurnEvent::PermissionCreated(transport, permission_ip)) = test.client.poll_event()
    else {
        unreachable!();
    };
    assert_eq!(transport, test.allocation_transport);
    assert_eq!(permission_ip, test.peer_addr.ip());

    let TurnPollRet::WaitUntil(expiry) = test.client.poll(now) else {
        unreachable!()
    };
    assert_eq!(expiry, now + PERMISSION_DURATION - EXPIRY_BUFFER);
    let TurnPollRet::WaitUntil(now) = test.client.poll(expiry) else {
        unreachable!()
    };
    assert_eq!(now, expiry);

    let transmit = test.client.poll_transmit(expiry).unwrap();
    let msg = Message::from_bytes(&transmit.data).unwrap();
    assert_eq!(msg.method(), CREATE_PERMISSION);
    // drop the create permission refresh (and retransmits)
    let mut expiry = now;
    let n_transmits = if test.client.transport() == TransportType::Udp {
        8
    } else {
        2
    };
    for _i in 0..n_transmits {
        let TurnPollRet::WaitUntil(new_now) = test.client.poll(expiry) else {
            unreachable!()
        };
        let _ = test.client.poll_transmit(new_now);
        expiry = new_now;
    }
    assert_eq!(expiry, now + EXPIRY_BUFFER);
    let TurnPollRet::WaitUntil(_now) = test.client.poll(expiry) else {
        unreachable!()
    };

    assert!(!test
        .client
        .have_permission(test.allocation_transport, test.peer_addr.ip()));
    let Some(TurnEvent::PermissionCreateFailed(_transport, ip)) = test.client.poll_event() else {
        unreachable!();
    };
    assert_eq!(ip, test.peer_addr.ip());
}

pub fn turn_channel_bind_refresh<A: TurnClientApi, S: TurnServerApi>(
    test: &mut TurnTest<A, S>,
    now: Instant,
) {
    let now = test.allocate(now);
    let Some(TurnEvent::AllocationCreated(transport, relayed_address)) = test.client.poll_event()
    else {
        unreachable!();
    };
    assert_eq!(transport, test.allocation_transport);
    assert_eq!(relayed_address, test.turn_alloc_addr);

    let now = test.bind_channel(now);
    let Some(TurnEvent::PermissionCreated(transport, permission_ip)) = test.client.poll_event()
    else {
        unreachable!();
    };
    assert_eq!(transport, test.allocation_transport);
    assert_eq!(permission_ip, test.peer_addr.ip());
    let Some(TurnEvent::ChannelCreated(transport, channel_addr)) = test.client.poll_event() else {
        unreachable!();
    };
    assert_eq!(transport, test.allocation_transport);
    assert_eq!(channel_addr, test.peer_addr);

    // two permission refreshes
    let mut permissions_done = now;
    for _i in 0..2 {
        let now = permissions_done;
        let expiry = test.client_advance(now);
        assert_eq!(expiry, now + PERMISSION_DURATION - EXPIRY_BUFFER);
        let TurnPollRet::WaitUntil(mut now) = test.client.poll(expiry) else {
            unreachable!()
        };
        assert_eq!(now, expiry);

        let create_permission =
            move |test: &mut TurnTest<A, S>, now: Instant| -> Transmit<Vec<u8>> {
                let transmit = test.client.poll_transmit(now).unwrap();
                let msg = Message::from_bytes(&transmit.data).unwrap();
                assert_eq!(msg.method(), CREATE_PERMISSION);
                test.server.recv(transmit, now).unwrap().build()
            };

        let transmit = create_permission(test, now);
        let transmit = if let Some(transmit) = test.maybe_handles_stale_nonce(transmit, now) {
            transmit
        } else {
            now = test.client_advance(now);
            create_permission(test, now)
        };
        assert!(matches!(
            test.client.recv(transmit, now),
            TurnRecvRet::Handled
        ));
        test.validate_client_permission_state();
        permissions_done = now;
    }
    let now = permissions_done;

    let TurnPollRet::WaitUntil(expiry) = test.client.poll(now) else {
        unreachable!()
    };
    assert_eq!(
        expiry,
        now + Duration::from_secs(60) - 2 * MIN_STUN_REQUEST_CADENCE
    );
    let TurnPollRet::WaitUntil(now) = test.client.poll(expiry) else {
        unreachable!()
    };
    assert_eq!(now, expiry);
    let transmit = test.client.poll_transmit(expiry).unwrap();
    let msg = Message::from_bytes(&transmit.data).unwrap();
    println!("message {msg}");
    assert_eq!(msg.method(), CHANNEL_BIND);
    let transmit = test.server.recv(transmit, now).unwrap();
    assert!(matches!(
        test.client.recv(transmit.build(), expiry),
        TurnRecvRet::Handled
    ));

    test.sendrecv_data_channel(expiry);
}

pub fn turn_offpath_data<A: TurnClientApi, S: TurnServerApi>(
    test: &mut TurnTest<A, S>,
    now: Instant,
) {
    let now = turn_allocate_permission(test, now);
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

pub fn turn_unparseable_data<A: TurnClientApi, S: TurnServerApi>(
    test: &mut TurnTest<A, S>,
    now: Instant,
) {
    let now = turn_allocate_permission(test, now);
    let data = [1; 4];
    let transmit = Transmit::new(
        data,
        test.client.transport(),
        test.client.remote_addr(),
        test.client.local_addr(),
    );
    assert!(matches!(
        test.client.recv(transmit, now),
        TurnRecvRet::Ignored(_)
    ));
}
