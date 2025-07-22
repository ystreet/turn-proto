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
use std::ops::Range;
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
    CompleteMessage(Transmit<T>, Range<usize>),
    /// Input data contains a complete Channel data message.
    CompleteChannel(Transmit<T>, Range<usize>),
    /// A STUN message has been produced from the buffered data.
    StoredMessage(Vec<u8>, Transmit<T>),
    /// A Channel data message has been produced from the buffered data.
    StoredChannel(Vec<u8>, Transmit<T>),
}

pub(crate) enum StoredTcp {
    Message(Vec<u8>),
    Channel(Vec<u8>),
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
            IncomingTcp::CompleteMessage(transmit, msg_range) => {
                match self.protocol.handle_message(transmit.data, now) {
                    TurnProtocolRecv::Handled => TurnRecvRet::Handled,
                    // XXX: Ignored should probably produce an error for TCP
                    TurnProtocolRecv::Ignored(_data) => TurnRecvRet::Handled,
                    TurnProtocolRecv::PeerData {
                        data,
                        range,
                        transport,
                        peer,
                    } => TurnRecvRet::PeerData(TurnPeerData {
                        data: DataRangeOrOwned::Range {
                            data,
                            range: msg_range.start + range.start..msg_range.start + range.end,
                        },
                        transport,
                        peer,
                    }),
                }
            }
            IncomingTcp::CompleteChannel(transmit, range) => {
                let channel =
                    ChannelData::parse(&transmit.data.as_ref()[range.start..range.end]).unwrap();
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
            IncomingTcp::StoredMessage(msg, transmit) => {
                protocol_recv_to_api(self.protocol.handle_message(msg, now), transmit)
            }
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
                        data: DataRangeOrOwned::Owned(ensure_data_owned(data, range)),
                        transport,
                        peer,
                    }),
                }
            }
        }
    }

    fn poll_recv(&mut self, now: Instant) -> Option<TurnPeerData<Vec<u8>>> {
        while let Some(recv) = self.incoming_tcp_buffer.poll_recv() {
            match recv {
                StoredTcp::Message(msg) => {
                    if let TurnProtocolRecv::PeerData {
                        data,
                        range,
                        transport,
                        peer,
                    } = self.protocol.handle_message(msg, now)
                    {
                        return Some(TurnPeerData {
                            data: DataRangeOrOwned::Range { data, range },
                            transport,
                            peer,
                        });
                    }
                }
                StoredTcp::Channel(data) => {
                    let Ok(channel) = ChannelData::parse(&data) else {
                        continue;
                    };
                    if let TurnProtocolChannelRecv::PeerData {
                        range,
                        transport,
                        peer,
                    } = self.protocol.handle_channel(
                        Transmit::new(
                            channel,
                            TransportType::Tcp,
                            self.remote_addr(),
                            self.local_addr(),
                        ),
                        now,
                    ) {
                        return Some(TurnPeerData {
                            data: DataRangeOrOwned::Range { data, range },
                            transport,
                            peer,
                        });
                    }
                }
            }
        }
        None
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
        level = "trace",
        ret,
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
                return IncomingTcp::CompleteChannel(transmit, 0..channel_len);
            };
            let msg_len = MessageHeader::LENGTH + hdr.data_length() as usize;
            if data.len() < msg_len {
                self.tcp_buffer.extend_from_slice(data);
                return IncomingTcp::NeedMoreData;
            }
            let Ok(_msg) = Message::from_bytes(&data[..msg_len]) else {
                // XXX: this might need some other return value for a more serious error.
                self.tcp_buffer.extend_from_slice(data);
                return IncomingTcp::NeedMoreData;
            };
            if msg_len < data.len() {
                self.tcp_buffer.extend_from_slice(&data[msg_len..]);
            }
            return IncomingTcp::CompleteMessage(transmit, 0..msg_len);
        }

        self.tcp_buffer.extend_from_slice(transmit.data.as_ref());
        match self.poll_recv() {
            None => IncomingTcp::NeedMoreData,
            Some(StoredTcp::Message(msg)) => IncomingTcp::StoredMessage(msg, transmit),
            Some(StoredTcp::Channel(channel)) => IncomingTcp::StoredChannel(channel, transmit),
        }
    }

    pub(crate) fn poll_recv(&mut self) -> Option<StoredTcp> {
        trace!("poll_recv: tcp buffer: {:x?}", self.tcp_buffer);
        let Ok(hdr) = MessageHeader::from_bytes(&self.tcp_buffer) else {
            trace!("poll_recv: failed message parse");
            let Ok(channel) = ChannelData::parse(&self.tcp_buffer) else {
                trace!("poll_recv: failed channel parse");
                return None;
            };
            let channel_len = 4 + channel.data().len();
            let (data, remaining) = self.tcp_buffer.split_at(channel_len);
            let data_binding = data.to_vec();
            self.tcp_buffer = remaining.to_vec();
            return Some(StoredTcp::Channel(data_binding));
        };
        let msg_len = MessageHeader::LENGTH + hdr.data_length() as usize;
        if self.tcp_buffer.len() < msg_len {
            return None;
        }
        let (data, remaining) = self.tcp_buffer.split_at(msg_len);
        let data_binding = data.to_vec();
        self.tcp_buffer = remaining.to_vec();
        let Ok(_msg) = Message::from_bytes(&data_binding) else {
            // XXX: this might need some other return value for a more serious error.
            return None;
        };
        Some(StoredTcp::Message(data_binding))
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
            data,
            range,
            transport,
            peer,
        } => TurnRecvRet::PeerData(TurnPeerData {
            data: DataRangeOrOwned::Owned(ensure_data_owned(data, range)),
            transport,
            peer,
        }),
    }
}

pub(crate) fn ensure_data_owned(data: Vec<u8>, range: Range<usize>) -> Vec<u8> {
    if range.start == 0 && range.end == data.len() {
        data
    } else {
        data[range.start..range.end].to_vec()
    }
}

#[cfg(test)]
mod tests {
    use tracing::info;
    use turn_server_proto::server::TurnServer;
    use turn_types::{
        message::ALLOCATE,
        stun::{
            attribute::Software,
            message::MessageWriteVec,
            prelude::{MessageWrite, MessageWriteExt},
        },
    };

    use crate::common::tests::turn_allocate_permission;
    use crate::common::tests::{
        turn_allocate_delete, turn_allocate_expire_client, turn_allocate_expire_server,
        turn_allocate_refresh, turn_channel_bind, turn_channel_bind_refresh,
        turn_create_permission_refresh, turn_create_permission_timeout, turn_peer_incoming_stun,
    };
    use crate::{
        common::tests::{turn_offpath_data, TurnTest},
        tests::test_init_log,
    };

    use super::*;

    fn generate_message() -> Vec<u8> {
        let mut msg = Message::builder_request(ALLOCATE, MessageWriteVec::new());
        msg.add_attribute(&Software::new("turn-client-proto").unwrap())
            .unwrap();
        msg.add_fingerprint().unwrap();
        msg.finish()
    }

    fn generate_message_in_channel() -> Vec<u8> {
        let msg = generate_message();
        let channel = ChannelData::new(0x4000, &msg);
        let mut out = vec![0; msg.len() + 4];
        channel.write_into_unchecked(&mut out);
        out
    }

    fn generate_addresses() -> (SocketAddr, SocketAddr) {
        (
            "192.168.0.1:1000".parse().unwrap(),
            "10.0.0.2:2000".parse().unwrap(),
        )
    }

    #[test]
    fn test_incoming_tcp_complete_message() {
        let _init = test_init_log();
        let (local_addr, remote_addr) = generate_addresses();
        let mut tcp = TurnTcpBuffer::new();
        let msg = generate_message();
        let ret = tcp.incoming_tcp(Transmit::new(
            msg,
            TransportType::Tcp,
            remote_addr,
            local_addr,
        ));
        assert!(matches!(ret, IncomingTcp::CompleteMessage(_, _)));
    }

    #[test]
    fn test_incoming_tcp_complete_message_in_channel() {
        let _init = test_init_log();
        let (local_addr, remote_addr) = generate_addresses();
        let mut tcp = TurnTcpBuffer::new();
        let msg = generate_message_in_channel();
        let ret = tcp.incoming_tcp(Transmit::new(
            msg,
            TransportType::Tcp,
            remote_addr,
            local_addr,
        ));
        assert!(matches!(ret, IncomingTcp::CompleteChannel(_, _)));
    }

    #[test]
    fn test_incoming_tcp_partial_message() {
        let _init = test_init_log();
        let (local_addr, remote_addr) = generate_addresses();
        let mut tcp = TurnTcpBuffer::new();
        let msg = generate_message();
        info!("message: {msg:x?}");
        for i in 1..msg.len() {
            let ret = tcp.incoming_tcp(Transmit::new(
                &msg[i - 1..i],
                TransportType::Tcp,
                remote_addr,
                local_addr,
            ));
            assert!(matches!(ret, IncomingTcp::NeedMoreData));
        }
        let IncomingTcp::StoredMessage(produced, _) = tcp.incoming_tcp(Transmit::new(
            &msg[msg.len() - 1..],
            TransportType::Tcp,
            remote_addr,
            local_addr,
        )) else {
            unreachable!()
        };
        assert_eq!(produced, msg);
    }

    #[test]
    fn test_incoming_tcp_partial_channel() {
        let _init = test_init_log();
        let (local_addr, remote_addr) = generate_addresses();
        let mut tcp = TurnTcpBuffer::new();
        let channel = generate_message_in_channel();
        info!("message: {channel:x?}");
        for i in 1..channel.len() {
            let ret = tcp.incoming_tcp(Transmit::new(
                &channel[i - 1..i],
                TransportType::Tcp,
                remote_addr,
                local_addr,
            ));
            assert!(matches!(ret, IncomingTcp::NeedMoreData));
        }
        let IncomingTcp::StoredChannel(produced, _) = tcp.incoming_tcp(Transmit::new(
            &channel[channel.len() - 1..],
            TransportType::Tcp,
            remote_addr,
            local_addr,
        )) else {
            unreachable!()
        };
        assert_eq!(produced, channel);
    }

    #[test]
    fn test_incoming_tcp_message_and_channel() {
        let _init = test_init_log();
        let (local_addr, remote_addr) = generate_addresses();
        let mut tcp = TurnTcpBuffer::new();
        let msg = generate_message();
        let channel = generate_message_in_channel();
        let mut input = msg.clone();
        input.extend_from_slice(&channel);
        info!("input: {input:x?}");
        let IncomingTcp::CompleteMessage(transmit, msg_range) = tcp.incoming_tcp(Transmit::new(
            input.clone(),
            TransportType::Tcp,
            remote_addr,
            local_addr,
        )) else {
            unreachable!()
        };
        assert_eq!(msg_range, 0..msg.len());
        assert_eq!(transmit.data, input);
        let Some(StoredTcp::Channel(produced)) = tcp.poll_recv() else {
            unreachable!()
        };
        assert_eq!(produced, channel);
    }

    fn turn_tcp_new(
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        credentials: TurnCredentials,
    ) -> TurnClientTcp {
        TurnClientTcp::allocate(local_addr, remote_addr, credentials)
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
        let _log = crate::tests::test_init_log();
        let now = Instant::now();
        for split in TRANSMIT_SPLITS {
            let mut test = create_test(split);
            turn_allocate_permission(&mut test, now);
        }
    }

    #[test]
    fn test_tcp_turn_allocate_expire_server() {
        let _log = crate::tests::test_init_log();
        let now = Instant::now();
        for split in TRANSMIT_SPLITS {
            let mut test = create_test(split);
            turn_allocate_expire_server(&mut test, now);
        }
    }

    #[test]
    fn test_tcp_turn_allocate_expire_client() {
        let _log = crate::tests::test_init_log();
        let now = Instant::now();
        for split in TRANSMIT_SPLITS {
            let mut test = create_test(split);
            turn_allocate_expire_client(&mut test, now);
        }
    }

    #[test]
    fn test_tcp_turn_allocate_refresh() {
        let _log = crate::tests::test_init_log();
        let now = Instant::now();
        for split in TRANSMIT_SPLITS {
            let mut test = create_test(split);
            turn_allocate_refresh(&mut test, now);
        }
    }

    #[test]
    fn test_tcp_turn_allocate_delete() {
        let _log = crate::tests::test_init_log();
        let now = Instant::now();
        for split in TRANSMIT_SPLITS {
            let mut test = create_test(split);
            turn_allocate_delete(&mut test, now);
        }
    }

    #[test]
    fn test_tcp_turn_channel_bind() {
        let _log = crate::tests::test_init_log();
        let now = Instant::now();
        for split in TRANSMIT_SPLITS {
            let mut test = create_test(split);
            turn_channel_bind(&mut test, now);
        }
    }

    #[test]
    fn test_tcp_turn_peer_incoming_stun() {
        let _log = crate::tests::test_init_log();
        let now = Instant::now();
        for split in TRANSMIT_SPLITS {
            let mut test = create_test(split);
            turn_peer_incoming_stun(&mut test, now);
        }
    }

    #[test]
    fn test_tcp_turn_create_permission_refresh() {
        let _log = crate::tests::test_init_log();
        let now = Instant::now();
        for split in TRANSMIT_SPLITS {
            let mut test = create_test(split);
            turn_create_permission_refresh(&mut test, now);
        }
    }

    #[test]
    fn test_tcp_turn_create_permission_timeout() {
        let _log = crate::tests::test_init_log();
        let now = Instant::now();
        for split in TRANSMIT_SPLITS {
            let mut test = create_test(split);
            turn_create_permission_timeout(&mut test, now);
        }
    }

    #[test]
    fn test_tcp_turn_channel_bind_refresh() {
        let _log = crate::tests::test_init_log();
        let now = Instant::now();
        for split in TRANSMIT_SPLITS {
            let mut test = create_test(split);
            turn_channel_bind_refresh(&mut test, now);
        }
    }

    #[test]
    fn test_tcp_offpath_data() {
        let _log = crate::tests::test_init_log();
        let now = Instant::now();
        let mut test = create_test(0);
        turn_offpath_data(&mut test, now);
    }
}
