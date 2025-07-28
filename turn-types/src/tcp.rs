// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Handle TURN over TCP.
//!
//! A TURN connection between a client and a server can have two types of data:
//! - STUN [`Message`]s, and
//! - [`ChannelData`]s
//!
//! Unlike a UDP connection which inherently contains a size for every message, TCP is a
//! stream-based protocol and the size of a message must be infered from the contained data. This
//! module performs the relevant buffering of incoming data over a TCP connection and produces
//! [`Message`]s or [`ChannelData`] as they are completely received.

use std::ops::Range;

use stun_proto::agent::Transmit;
use stun_types::message::{Message, MessageHeader};
use tracing::{debug, trace};

use crate::channel::ChannelData;

/// Reply to [`TurnTcpBuffer::incoming_tcp()`]
#[derive(Debug)]
pub enum IncomingTcp<T: AsRef<[u8]> + std::fmt::Debug> {
    /// Input data (with the provided range) contains a complete STUN Message.
    ///
    /// Any extra data after the range is stored for later processing.
    CompleteMessage(Transmit<T>, Range<usize>),
    /// Input data (with the provided range) contains a complete Channel data message.
    ///
    /// Any extra data after the range is stored for later processing.
    CompleteChannel(Transmit<T>, Range<usize>),
    /// A STUN message has been produced from the buffered data.
    StoredMessage(Vec<u8>, Transmit<T>),
    /// A Channel data message has been produced from the buffered data.
    StoredChannel(Vec<u8>, Transmit<T>),
}

impl<T: AsRef<[u8]> + std::fmt::Debug> IncomingTcp<T> {
    /// The byte slice for this incoming or stored data.
    pub fn data(&self) -> &[u8] {
        match self {
            Self::CompleteMessage(transmit, range) => {
                &transmit.data.as_ref()[range.start..range.end]
            }
            Self::CompleteChannel(transmit, range) => {
                &transmit.data.as_ref()[range.start..range.end]
            }
            Self::StoredMessage(data, _transmit) => data,
            Self::StoredChannel(data, _transmit) => data,
        }
    }

    /// The [`Message`] contained in this incoming or stored data.
    pub fn message(&self) -> Option<Message<'_>> {
        if !matches!(
            self,
            Self::CompleteMessage(_, _) | Self::StoredMessage(_, _)
        ) {
            return None;
        }
        Message::from_bytes(self.data()).ok()
    }

    /// The [`ChannelData`] contained in this incoming or stored data.
    pub fn channel(&self) -> Option<ChannelData<'_>> {
        if !matches!(
            self,
            Self::CompleteChannel(_, _) | Self::StoredChannel(_, _)
        ) {
            return None;
        }
        ChannelData::parse(self.data()).ok()
    }
}

impl<T: AsRef<[u8]> + std::fmt::Debug> AsRef<[u8]> for IncomingTcp<T> {
    fn as_ref(&self) -> &[u8] {
        self.data()
    }
}

/// A stored [`Message`] or [`ChannelData`]
#[derive(Debug)]
pub enum StoredTcp {
    /// A STUN [`Message`] has been received.
    Message(Vec<u8>),
    /// A [`ChannelData`] has been received.
    Channel(Vec<u8>),
}

impl StoredTcp {
    /// The byte slice for this stored data.
    pub fn data(&self) -> &[u8] {
        match self {
            Self::Message(data) => data,
            Self::Channel(data) => data,
        }
    }

    fn into_incoming<T: AsRef<[u8]> + std::fmt::Debug>(
        self,
        transmit: Transmit<T>,
    ) -> IncomingTcp<T> {
        match self {
            Self::Message(msg) => IncomingTcp::StoredMessage(msg, transmit),
            Self::Channel(channel) => IncomingTcp::StoredChannel(channel, transmit),
        }
    }
}

impl AsRef<[u8]> for StoredTcp {
    fn as_ref(&self) -> &[u8] {
        self.data()
    }
}

/// A TCP buffer for TURN messages.
#[derive(Debug, Default)]
pub struct TurnTcpBuffer {
    tcp_buffer: Vec<u8>,
}

impl TurnTcpBuffer {
    /// Construct a new [`TurnTcpBuffer`].
    pub fn new() -> Self {
        Self { tcp_buffer: vec![] }
    }

    /// Provide incoming TCP data to parse.
    ///
    /// A return value of `None` indicates that the more data is required to provide a complete
    /// STUN [`Message`] or a [`ChannelData`].
    #[tracing::instrument(
        level = "trace",
        skip(self, transmit),
        fields(
            transmit.data_len = transmit.data.as_ref().len(),
            from = ?transmit.from
        )
    )]
    pub fn incoming_tcp<T: AsRef<[u8]> + std::fmt::Debug>(
        &mut self,
        transmit: Transmit<T>,
    ) -> Option<IncomingTcp<T>> {
        if self.tcp_buffer.is_empty() {
            let data = transmit.data.as_ref();
            trace!("Trying to parse incoming data as a complete message/channel");
            let Ok(hdr) = MessageHeader::from_bytes(data) else {
                let Ok(channel) = ChannelData::parse(data) else {
                    self.tcp_buffer.extend_from_slice(data);
                    return None;
                };
                let channel_len = 4 + channel.data().len();
                debug!(
                    channel.id = channel.id(),
                    channel.len = channel_len - 4,
                    "Incoming data contains a channel",
                );
                if channel_len < data.len() {
                    self.tcp_buffer.extend_from_slice(&data[channel_len..]);
                }
                return Some(IncomingTcp::CompleteChannel(transmit, 0..channel_len));
            };
            let msg_len = MessageHeader::LENGTH + hdr.data_length() as usize;
            debug!(
                msg.transaction = %hdr.transaction_id(),
                msg.len = msg_len,
                "Incoming data contains a message",
            );
            if data.len() < msg_len {
                self.tcp_buffer.extend_from_slice(data);
                return None;
            }
            if msg_len < data.len() {
                self.tcp_buffer.extend_from_slice(&data[msg_len..]);
            }
            return Some(IncomingTcp::CompleteMessage(transmit, 0..msg_len));
        }

        self.tcp_buffer.extend_from_slice(transmit.data.as_ref());
        self.poll_recv().map(|recv| recv.into_incoming(transmit))
    }

    /// Return the next complete message (if any).
    #[tracing::instrument(
        level = "trace",
        skip(self),
        fields(
            buffered_len = self.tcp_buffer.len(),
        )
    )]
    pub fn poll_recv(&mut self) -> Option<StoredTcp> {
        let Ok(hdr) = MessageHeader::from_bytes(&self.tcp_buffer) else {
            let Ok((id, channel_data_len)) = ChannelData::parse_header(&self.tcp_buffer) else {
                trace!(
                    buffered.len = self.tcp_buffer.len(),
                    "cannot parse stored data"
                );
                return None;
            };
            let channel_len = 4 + channel_data_len;
            if self.tcp_buffer.len() < channel_len {
                trace!(
                    buffered.len = self.tcp_buffer.len(),
                    required = channel_len,
                    "need more bytes to complete channel data"
                );
                return None;
            }
            let (data, remaining) = self.tcp_buffer.split_at(channel_len);
            let data_binding = data.to_vec();
            debug!(
                channel.id = id,
                channel.len = channel_data_len,
                remaining = remaining.len(),
                "buffered data contains a channel",
            );
            self.tcp_buffer = remaining.to_vec();
            return Some(StoredTcp::Channel(data_binding));
        };
        let msg_len = MessageHeader::LENGTH + hdr.data_length() as usize;
        if self.tcp_buffer.len() < msg_len {
            trace!(
                buffered.len = self.tcp_buffer.len(),
                required = msg_len,
                "need more bytes to complete STUN message"
            );
            return None;
        }
        let (data, remaining) = self.tcp_buffer.split_at(msg_len);
        let data_binding = data.to_vec();
        debug!(
            msg.transaction = %hdr.transaction_id(),
            msg.len = msg_len,
            remaining = remaining.len(),
            "stored data contains a message",
        );
        self.tcp_buffer = remaining.to_vec();
        Some(StoredTcp::Message(data_binding))
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use stun_types::{
        attribute::Software,
        message::{Message, MessageWriteVec},
        prelude::{MessageWrite, MessageWriteExt},
        TransportType,
    };
    use tracing::info;

    use crate::message::ALLOCATE;

    use super::*;

    fn generate_addresses() -> (SocketAddr, SocketAddr) {
        (
            "192.168.0.1:1000".parse().unwrap(),
            "10.0.0.2:2000".parse().unwrap(),
        )
    }

    fn generate_message() -> Vec<u8> {
        let mut msg = Message::builder_request(ALLOCATE, MessageWriteVec::new());
        msg.add_attribute(&Software::new("turn-types").unwrap())
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

    #[test]
    fn test_incoming_tcp_complete_message() {
        let _init = crate::tests::test_init_log();
        let (local_addr, remote_addr) = generate_addresses();
        let mut tcp = TurnTcpBuffer::new();
        let msg = generate_message();
        let ret = tcp
            .incoming_tcp(Transmit::new(
                msg.clone(),
                TransportType::Tcp,
                remote_addr,
                local_addr,
            ))
            .unwrap();
        assert!(matches!(ret, IncomingTcp::CompleteMessage(_, _)));
        assert_eq!(ret.data(), &msg);
        assert!(ret.message().is_some());
    }

    #[test]
    fn test_incoming_tcp_complete_message_in_channel() {
        let _init = crate::tests::test_init_log();
        let (local_addr, remote_addr) = generate_addresses();
        let mut tcp = TurnTcpBuffer::new();
        let msg = generate_message_in_channel();
        let ret = tcp
            .incoming_tcp(Transmit::new(
                msg.clone(),
                TransportType::Tcp,
                remote_addr,
                local_addr,
            ))
            .unwrap();
        assert!(matches!(ret, IncomingTcp::CompleteChannel(_, _)));
        assert_eq!(ret.data(), &msg);
        assert!(ret.channel().is_some());
    }

    #[test]
    fn test_incoming_tcp_partial_message() {
        let _init = crate::tests::test_init_log();
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
            assert!(ret.is_none());
        }
        let ret = tcp
            .incoming_tcp(Transmit::new(
                &msg[msg.len() - 1..],
                TransportType::Tcp,
                remote_addr,
                local_addr,
            ))
            .unwrap();
        assert_eq!(ret.data(), &msg);
        assert!(ret.message().is_some());
        let IncomingTcp::StoredMessage(produced, _) = ret else {
            unreachable!();
        };
        assert_eq!(produced, msg);
    }

    #[test]
    fn test_incoming_tcp_partial_channel() {
        let _init = crate::tests::test_init_log();
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
            assert!(ret.is_none());
        }
        let ret = tcp
            .incoming_tcp(Transmit::new(
                &channel[channel.len() - 1..],
                TransportType::Tcp,
                remote_addr,
                local_addr,
            ))
            .unwrap();
        assert_eq!(ret.data(), &channel);
        assert!(ret.channel().is_some());
        let IncomingTcp::StoredChannel(produced, _) = ret else {
            unreachable!()
        };
        assert_eq!(produced, channel);
    }

    #[test]
    fn test_incoming_tcp_message_and_channel() {
        let _init = crate::tests::test_init_log();
        let (local_addr, remote_addr) = generate_addresses();
        let mut tcp = TurnTcpBuffer::new();
        let msg = generate_message();
        let channel = generate_message_in_channel();
        let mut input = msg.clone();
        input.extend_from_slice(&channel);
        let ret = tcp
            .incoming_tcp(Transmit::new(
                input.clone(),
                TransportType::Tcp,
                remote_addr,
                local_addr,
            ))
            .unwrap();
        assert_eq!(ret.data(), &msg);
        assert!(ret.message().is_some());
        let IncomingTcp::CompleteMessage(transmit, msg_range) = ret else {
            unreachable!();
        };
        assert_eq!(msg_range, 0..msg.len());
        assert_eq!(transmit.data, input);
        let ret = tcp.poll_recv().unwrap();
        assert_eq!(ret.data(), &channel);
        let StoredTcp::Channel(produced) = ret else {
            unreachable!()
        };
        assert_eq!(produced, channel);
    }

    #[test]
    fn test_incoming_tcp_channel_and_message() {
        let _init = crate::tests::test_init_log();
        let (local_addr, remote_addr) = generate_addresses();
        let mut tcp = TurnTcpBuffer::new();
        let msg = generate_message();
        let channel = generate_message_in_channel();
        let mut input = channel.clone();
        input.extend_from_slice(&msg);
        let ret = tcp
            .incoming_tcp(Transmit::new(
                input.clone(),
                TransportType::Tcp,
                remote_addr,
                local_addr,
            ))
            .unwrap();
        assert_eq!(ret.data(), &channel);
        assert!(ret.channel().is_some());
        let IncomingTcp::CompleteChannel(transmit, channel_range) = ret else {
            unreachable!()
        };
        assert_eq!(channel_range, 0..channel.len());
        assert_eq!(transmit.data, input);
        let ret = tcp.poll_recv().unwrap();
        assert_eq!(ret.data(), &msg);
        let StoredTcp::Message(produced) = ret else {
            unreachable!()
        };
        assert_eq!(produced, msg);
    }
}
