// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! # TURN client
//!
//! An implementation of a TURN client suitable for UDP connections.

use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

use stun_proto::agent::{StunAgent, Transmit};
use stun_proto::types::data::Data;

use stun_proto::types::TransportType;

use turn_types::channel::ChannelData;
use turn_types::stun::message::MessageHeader;
use turn_types::TurnCredentials;

use tracing::{trace, warn};

use crate::common::{
    DataRangeOrOwned, DelayedMessageOrChannelSend, TransmitBuild, TurnClientApi, TurnPeerData,
};
use crate::protocol::{TurnClientProtocol, TurnProtocolChannelRecv, TurnProtocolRecv};

pub use crate::common::{
    BindChannelError, CreatePermissionError, DeleteError, TurnEvent, TurnPollRet, TurnRecvRet,
};
pub use crate::protocol::SendError;

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
    type SendError = SendError;

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
    ) -> Result<Option<TransmitBuild<DelayedMessageOrChannelSend<T>>>, Self::SendError> {
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
            let ret = self.protocol.handle_channel(
                Transmit::new(channel, transmit.transport, transmit.from, transmit.to),
                now,
            );
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
