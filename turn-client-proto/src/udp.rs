// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! UDP TURN client.
//!
//! An implementation of a TURN client suitable for UDP connections.

use sans_io_time::Instant;
use std::net::{IpAddr, SocketAddr};

use stun_proto::agent::{StunAgent, Transmit};
use stun_proto::types::data::Data;

use stun_proto::types::TransportType;

use turn_types::channel::ChannelData;
use turn_types::stun::message::MessageHeader;
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

/// A TURN client.
#[derive(Debug)]
pub struct TurnClientUdp {
    protocol: TurnClientProtocol,
}

impl TurnClientUdp {
    /// Allocate an address on a TURN server to relay data to and from peers.
    ///
    /// # Examples
    /// ```
    /// # use turn_types::TurnCredentials;
    /// # use turn_client_proto::prelude::*;
    /// # use turn_client_proto::udp::TurnClientUdp;
    /// # use stun_proto::types::TransportType;
    /// let credentials = TurnCredentials::new("tuser", "tpass");
    /// let transport = TransportType::Udp;
    /// let local_addr = "192.168.0.1:4000".parse().unwrap();
    /// let remote_addr = "10.0.0.1:3478".parse().unwrap();
    /// let client = TurnClientUdp::allocate(local_addr, remote_addr, credentials);
    /// assert_eq!(client.transport(), TransportType::Udp);
    /// assert_eq!(client.local_addr(), local_addr);
    /// assert_eq!(client.remote_addr(), remote_addr);
    /// ```
    #[tracing::instrument(
        name = "turn_client_allocate"
        skip(credentials)
    )]
    pub fn allocate(
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        credentials: TurnCredentials,
    ) -> Self {
        let stun_agent = StunAgent::builder(TransportType::Udp, local_addr)
            .remote_addr(remote_addr)
            .build();

        Self {
            protocol: TurnClientProtocol::new(stun_agent, credentials),
        }
    }
}

impl TurnClientApi for TurnClientUdp {
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
        self.protocol.poll(now)
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
        self.protocol.poll_transmit(now)
    }

    fn poll_event(&mut self) -> Option<TurnEvent> {
        self.protocol.poll_event()
    }

    fn delete(&mut self, now: Instant) -> Result<(), DeleteError> {
        self.protocol.delete(now)
    }

    fn create_permission(
        &mut self,
        transport: TransportType,
        peer_addr: IpAddr,
        now: Instant,
    ) -> Result<(), CreatePermissionError> {
        self.protocol.create_permission(transport, peer_addr, now)
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
        self.protocol.bind_channel(transport, peer_addr, now)
    }

    fn send_to<T: AsRef<[u8]> + std::fmt::Debug>(
        &mut self,
        transport: TransportType,
        to: SocketAddr,
        data: T,
        now: Instant,
    ) -> Result<Option<TransmitBuild<DelayedMessageOrChannelSend<T>>>, SendError> {
        self.protocol.send_to(transport, to, data, now).map(Some)
    }

    fn recv<T: AsRef<[u8]> + std::fmt::Debug>(
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

        let data = transmit.data.as_ref();
        let Ok(_hdr) = MessageHeader::from_bytes(data) else {
            let Ok(channel) = ChannelData::parse(data) else {
                return TurnRecvRet::Ignored(transmit);
            };
            let ret = self.protocol.handle_channel(channel, now);
            match ret {
                TurnProtocolChannelRecv::Ignored => return TurnRecvRet::Ignored(transmit),
                TurnProtocolChannelRecv::PeerData {
                    range,
                    transport,
                    peer,
                } => {
                    return TurnRecvRet::PeerData(TurnPeerData {
                        data: DataRangeOrOwned::Range {
                            data: transmit.data,
                            range,
                        },
                        transport,
                        peer,
                    })
                }
            }
        };
        match self.protocol.handle_message(transmit.data, now) {
            TurnProtocolRecv::Handled => TurnRecvRet::Handled,
            TurnProtocolRecv::Ignored(data) => TurnRecvRet::Ignored(Transmit::new(
                data,
                transmit.transport,
                transmit.from,
                transmit.to,
            )),
            TurnProtocolRecv::PeerData {
                data,
                range,
                transport,
                peer,
            } => TurnRecvRet::PeerData(TurnPeerData {
                data: DataRangeOrOwned::Range { data, range },
                transport,
                peer,
            }),
        }
    }

    fn poll_recv(&mut self, _now: Instant) -> Option<TurnPeerData<Vec<u8>>> {
        None
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use turn_server_proto::server::TurnServer;

    use super::*;

    use crate::{
        api::tests::{
            turn_allocate_delete, turn_allocate_expire_client, turn_allocate_expire_server,
            turn_allocate_permission, turn_allocate_refresh, turn_channel_bind,
            turn_channel_bind_refresh, turn_create_permission_refresh,
            turn_create_permission_timeout, turn_offpath_data, turn_peer_incoming_stun,
            turn_unparseable_data, TurnTest,
        },
        client::TurnClient,
    };

    pub(crate) fn turn_udp_new(
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        credentials: TurnCredentials,
    ) -> TurnClient {
        TurnClientUdp::allocate(local_addr, remote_addr, credentials).into()
    }

    fn turn_server_udp_new(listen_address: SocketAddr, realm: String) -> TurnServer {
        TurnServer::new(TransportType::Udp, listen_address, realm)
    }

    pub(crate) fn create_test() -> TurnTest<TurnClient, TurnServer> {
        TurnTest::<TurnClient, TurnServer>::builder().build(turn_udp_new, turn_server_udp_new)
    }

    #[test]
    fn test_turn_udp_allocate_udp_permission() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut test = create_test();
        turn_allocate_permission(&mut test, now);
    }

    #[test]
    fn test_udp_turn_allocate_expire_server() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut test = create_test();
        turn_allocate_expire_server(&mut test, now);
    }

    #[test]
    fn test_udp_turn_allocate_expire_client() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut test = create_test();
        turn_allocate_expire_client(&mut test, now);
    }

    #[test]
    fn test_udp_turn_allocate_refresh() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut test = create_test();
        turn_allocate_refresh(&mut test, now);
    }

    #[test]
    fn test_udp_turn_allocate_delete() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut test = create_test();
        turn_allocate_delete(&mut test, now);
    }

    #[test]
    fn test_udp_turn_channel_bind() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut test = create_test();
        turn_channel_bind(&mut test, now);
    }

    #[test]
    fn test_udp_turn_peer_incoming_stun() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut test = create_test();
        turn_peer_incoming_stun(&mut test, now);
    }

    #[test]
    fn test_udp_turn_create_permission_refresh() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut test = create_test();
        turn_create_permission_refresh(&mut test, now);
    }

    #[test]
    fn test_udp_turn_create_permission_timeout() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut test = create_test();
        turn_create_permission_timeout(&mut test, now);
    }

    #[test]
    fn test_udp_turn_channel_bind_refresh() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut test = create_test();
        turn_channel_bind_refresh(&mut test, now);
    }

    #[test]
    fn test_udp_offpath_data() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut test = create_test();
        turn_offpath_data(&mut test, now);
    }

    #[test]
    fn test_udp_unparseable_data() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut test = create_test();
        turn_unparseable_data(&mut test, now);
    }
}
