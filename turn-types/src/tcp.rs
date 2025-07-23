// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Handle TURN over TCP.

use std::ops::Range;

use stun_proto::agent::Transmit;
use stun_types::message::{Message, MessageHeader};
use tracing::{debug, trace};

use crate::channel::ChannelData;

/// Reply to [`TurnTcpBuffer::incoming_tcp()`]
#[derive(Debug)]
pub enum IncomingTcp<T: AsRef<[u8]> + std::fmt::Debug> {
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

/// A Stored TCP Message or Channel
#[derive(Debug)]
pub enum StoredTcp {
    /// Message
    Message(Vec<u8>),
    /// Channel
    Channel(Vec<u8>),
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
    #[tracing::instrument(ret,
        level = "trace",
        ret,
        skip(self, transmit),
        fields(
            transmit.data_len = transmit.data.as_ref().len(),
            from = ?transmit.from
        )
    )]
    pub fn incoming_tcp<T: AsRef<[u8]> + std::fmt::Debug>(
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

    /// Return the next complete message (if any).
    pub fn poll_recv(&mut self) -> Option<StoredTcp> {
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

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use stun_types::{
        attribute::Software,
        message::MessageWriteVec,
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
        let _init = crate::tests::test_init_log();
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
        let _init = crate::tests::test_init_log();
        let (local_addr, remote_addr) = generate_addresses();
        let mut tcp = TurnTcpBuffer::new();
        let msg = generate_message();
        let channel = generate_message_in_channel();
        let mut input = msg.clone();
        input.extend_from_slice(&channel);
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
}
