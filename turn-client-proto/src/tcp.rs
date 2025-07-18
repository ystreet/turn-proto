// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! # TCP TURN client
//!
//! An implementation of a TURN client suitable for TCP connections.

use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

use stun_proto::agent::{StunAgent, Transmit};
use stun_proto::types::data::Data;

use stun_proto::types::TransportType;

use turn_types::channel::ChannelData;
use turn_types::stun::message::{Message, MessageHeader};
use turn_types::TurnCredentials;

use tracing::{debug, trace, warn};

use crate::common::{
    DataRangeOrOwned, DelayedMessageOrChannelSend, TransmitBuild, TurnClientApi, TurnPeerData,
};
use crate::protocol::{SendError, TurnClientProtocol, TurnProtocolChannelRecv, TurnProtocolRecv};

pub use crate::common::{
    BindChannelError, CreatePermissionError, DeleteError, TurnEvent, TurnPollRet, TurnRecvRet,
};

/// A TURN client.
#[derive(Debug)]
pub struct TurnClientTcp {
    protocol: TurnClientProtocol,
    incoming_tcp_buffer: TurnTcpBuffer,
}

impl TurnClientTcp {
    /// Allocate an address on a TURN server to relay data to and from peers.
    ///
    /// # Examples
    /// ```
    /// # use turn_types::TurnCredentials;
    /// # use turn_client_proto::prelude::*;
    /// # use turn_client_proto::tcp::TurnClientTcp;
    /// # use stun_proto::types::TransportType;
    /// let credentials = TurnCredentials::new("tuser", "tpass");
    /// let local_addr = "192.168.0.1:4000".parse().unwrap();
    /// let remote_addr = "10.0.0.1:3478".parse().unwrap();
    /// let client = TurnClientTcp::allocate(local_addr, remote_addr, credentials);
    /// assert_eq!(client.transport(), TransportType::Tcp);
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
        let stun_agent = StunAgent::builder(TransportType::Tcp, local_addr)
            .remote_addr(remote_addr)
            .build();

        Self {
            protocol: TurnClientProtocol::new(stun_agent, credentials),
            incoming_tcp_buffer: TurnTcpBuffer::new(),
        }
    }
}

#[derive(Debug)]
pub(crate) enum IncomingTcp<T: AsRef<[u8]> + std::fmt::Debug> {
    /// Not enough data for processing to complete.
    NeedMoreData,
    /// Input data contains a complete STUN Message.
    CompleteMessage(Transmit<T>),
    /// Input data contains a complete Channel data message.
    CompleteChannel(Transmit<T>),
    /// A STUN message has been produced from the buffered data.
    StoredMessage(Vec<u8>, Transmit<T>),
    /// A Channel data message has been produced from the buffered data.
    StoredChannel(Vec<u8>, Transmit<T>),
}

impl TurnClientApi for TurnClientTcp {
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

        match self.incoming_tcp_buffer.incoming_tcp(transmit) {
            IncomingTcp::NeedMoreData => TurnRecvRet::Handled,
            IncomingTcp::CompleteMessage(transmit) => {
                self.protocol.handle_message(transmit, now).into()
            }
            IncomingTcp::CompleteChannel(transmit) => {
                let channel = ChannelData::parse(transmit.data.as_ref()).unwrap();
                let ret = self.protocol.handle_channel(
                    Transmit::new(channel, transmit.transport, transmit.from, transmit.to),
                    now,
                );
                match ret {
                    TurnProtocolChannelRecv::Ignored => TurnRecvRet::Ignored(transmit),
                    TurnProtocolChannelRecv::PeerData {
                        range,
                        transport,
                        peer,
                    } => TurnRecvRet::PeerData(TurnPeerData {
                        data: DataRangeOrOwned::Range {
                            data: transmit.data,
                            range,
                        },
                        transport,
                        peer,
                    }),
                }
            }
            IncomingTcp::StoredMessage(data, transmit) => protocol_recv_to_api(
                self.protocol.handle_message(
                    Transmit::new(data, transmit.transport, transmit.from, transmit.to),
                    now,
                ),
                transmit,
            ),
            IncomingTcp::StoredChannel(data, transmit) => {
                let channel = ChannelData::parse(&data).unwrap();
                let ret = self.protocol.handle_channel(
                    Transmit::new(channel, transmit.transport, transmit.from, transmit.to),
                    now,
                );
                match ret {
                    TurnProtocolChannelRecv::Ignored => TurnRecvRet::Ignored(transmit),
                    TurnProtocolChannelRecv::PeerData {
                        range,
                        transport,
                        peer,
                    } => TurnRecvRet::PeerData(TurnPeerData {
                        data: DataRangeOrOwned::Range {
                            data: transmit.data,
                            range,
                        },
                        transport,
                        peer,
                    }),
                }
            }
        }
    }
}

#[derive(Debug)]
pub(crate) struct TurnTcpBuffer {
    tcp_buffer: Vec<u8>,
}

impl TurnTcpBuffer {
    pub(crate) fn new() -> Self {
        Self { tcp_buffer: vec![] }
    }

    #[tracing::instrument(ret,
        skip(self, transmit),
        fields(
            transmit.data_len = transmit.data.as_ref().len(),
            from = ?transmit.from
        )
    )]
    pub(crate) fn incoming_tcp<T: AsRef<[u8]> + std::fmt::Debug>(
        &mut self,
        transmit: Transmit<T>,
    ) -> IncomingTcp<T> {
        if self.tcp_buffer.is_empty() {
            let data = transmit.data.as_ref();
            trace!("Trying to parse incoming data as a complete message/channel");
            let Ok(hdr) = MessageHeader::from_bytes(data) else {
                let Ok(channel) = ChannelData::parse(data) else {
                    self.tcp_buffer.extend_from_slice(data);
                    return IncomingTcp::NeedMoreData;
                };
                let channel_len = 4 + channel.data().len();
                debug!(
                    "Incoming data contains a channel with id {} and len {}",
                    channel.id(),
                    channel_len - 4
                );
                if channel_len > data.len() {
                    self.tcp_buffer.extend_from_slice(&data[channel_len..]);
                }
                return IncomingTcp::CompleteChannel(transmit);
            };
            let msg_len = MessageHeader::LENGTH + hdr.data_length() as usize;
            if data.len() < msg_len {
                self.tcp_buffer.extend_from_slice(data);
                return IncomingTcp::NeedMoreData;
            }
            let Ok(_msg) = Message::from_bytes(data) else {
                // XXX: this might need some other return value for a more serious error.
                self.tcp_buffer.extend_from_slice(data);
                return IncomingTcp::NeedMoreData;
            };
            if msg_len > data.len() {
                self.tcp_buffer.extend_from_slice(&data[msg_len..]);
            }
            return IncomingTcp::CompleteMessage(transmit);
        }

        self.tcp_buffer.extend_from_slice(transmit.data.as_ref());
        let Ok(hdr) = MessageHeader::from_bytes(&self.tcp_buffer) else {
            let Ok(channel) = ChannelData::parse(&self.tcp_buffer) else {
                return IncomingTcp::NeedMoreData;
            };
            let channel_len = 4 + channel.data().len();
            let (data, remaining) = self.tcp_buffer.split_at(channel_len);
            let data_binding = data.to_vec();
            self.tcp_buffer = remaining.to_vec();
            return IncomingTcp::StoredChannel(data_binding, transmit);
        };
        let msg_len = MessageHeader::LENGTH + hdr.data_length() as usize;
        if self.tcp_buffer.len() < msg_len {
            return IncomingTcp::NeedMoreData;
        }
        let (data, remaining) = self.tcp_buffer.split_at(msg_len);
        let data_binding = data.to_vec();
        self.tcp_buffer = remaining.to_vec();
        let Ok(_msg) = Message::from_bytes(&data_binding) else {
            // XXX: this might need some other return value for a more serious error.
            return IncomingTcp::NeedMoreData;
        };
        IncomingTcp::StoredMessage(data_binding, transmit)
    }
}

fn protocol_recv_to_api<T: AsRef<[u8]> + std::fmt::Debug>(
    recv: TurnProtocolRecv<Vec<u8>>,
    original: Transmit<T>,
) -> TurnRecvRet<T> {
    match recv {
        TurnProtocolRecv::Handled => TurnRecvRet::Handled,
        TurnProtocolRecv::Ignored(_) => TurnRecvRet::Ignored(original),
        TurnProtocolRecv::PeerData {
            transmit,
            range,
            transport,
            peer,
        } => {
            if range.start == 0 && range.end == transmit.data.len() {
                TurnRecvRet::PeerData(TurnPeerData {
                    data: DataRangeOrOwned::Owned(transmit.data),
                    transport,
                    peer,
                })
            } else {
                // FIXME: try to avoid this copy
                TurnRecvRet::PeerData(TurnPeerData {
                    data: DataRangeOrOwned::Owned(transmit.data[range.start..range.end].to_vec()),
                    transport,
                    peer,
                })
            }
        }
    }
}
