// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Transmit structures and helpers.

use alloc::vec::Vec;
use byteorder::{BigEndian, ByteOrder};
use core::net::SocketAddr;
use stun_types::message::Message;
use stun_types::message::MessageHeader;
use stun_types::message::MessageType;
use stun_types::message::MessageWriteMutSlice;
use stun_types::message::MessageWriteVec;
use stun_types::message::TransactionId;
use stun_types::prelude::AttributeExt;
use stun_types::prelude::MessageWrite;
use stun_types::prelude::MessageWriteExt;

use stun_proto::agent::Transmit;
use stun_types::TransportType;

use crate::attribute::Data as AData;
use crate::attribute::XorPeerAddress;
use crate::message::{DATA, SEND};

/// A piece of data that needs to be built before it can be transmitted.
#[derive(Debug)]
pub struct TransmitBuild<T: DelayedTransmitBuild + core::fmt::Debug> {
    /// The data blob
    pub data: T,
    /// The transport for the transmission
    pub transport: TransportType,
    /// The source address of the transmission
    pub from: SocketAddr,
    /// The destination address of the transmission
    pub to: SocketAddr,
}

impl<T: DelayedTransmitBuild + core::fmt::Debug> TransmitBuild<T> {
    /// Construct a new [`Transmit`] with the specifid data and 5-tuple.
    pub fn new(data: T, transport: TransportType, from: SocketAddr, to: SocketAddr) -> Self {
        Self {
            data,
            transport,
            from,
            to,
        }
    }

    /// Write the [`TransmitBuild`] to a new `Vec<u8>`.
    pub fn build(self) -> Transmit<Vec<u8>> {
        Transmit {
            data: self.data.build(),
            transport: self.transport,
            from: self.from,
            to: self.to,
        }
    }

    /// Write the [`TransmitBuild`] into the provided destination buffer.
    pub fn write_into(self, dest: &mut [u8]) -> Transmit<&mut [u8]> {
        let len = self.data.write_into(dest);
        Transmit {
            data: &mut dest[..len],
            transport: self.transport,
            from: self.from,
            to: self.to,
        }
    }
}

/// A trait for delaying building a byte sequence for transmission
pub trait DelayedTransmitBuild {
    /// Write the packet in to a new Vec.
    fn build(self) -> Vec<u8>;
    /// The length (in bytes) of the produced data.
    fn len(&self) -> usize;
    /// Whether the resulting data would be empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Write the data into a provided output buffer.
    ///
    /// Returns the number of bytes written.
    fn write_into(self, data: &mut [u8]) -> usize;
}

impl DelayedTransmitBuild for Vec<u8> {
    fn len(&self) -> usize {
        self.len()
    }
    fn build(self) -> Vec<u8> {
        self
    }
    fn is_empty(&self) -> bool {
        self.is_empty()
    }
    fn write_into(self, data: &mut [u8]) -> usize {
        data[..self.len()].copy_from_slice(&self);
        self.len()
    }
}

impl DelayedTransmitBuild for &[u8] {
    fn len(&self) -> usize {
        (**self).len()
    }
    fn build(self) -> Vec<u8> {
        self.to_vec()
    }
    fn is_empty(&self) -> bool {
        (**self).is_empty()
    }
    fn write_into(self, data: &mut [u8]) -> usize {
        data[..self.len()].copy_from_slice(self);
        self.len()
    }
}

/// A `Transmit` that will construct a channel message towards a TURN client or server.
#[derive(Debug)]
pub struct DelayedChannel<T: AsRef<[u8]> + core::fmt::Debug> {
    data: T,
    channel_id: u16,
}

impl<T: AsRef<[u8]> + core::fmt::Debug> DelayedChannel<T> {
    /// Construct a new [`DelayedChannel`] with the specified channel ID and data.
    pub fn new(channel_id: u16, data: T) -> Self {
        Self { channel_id, data }
    }
}

impl<T: AsRef<[u8]> + core::fmt::Debug> DelayedChannel<T> {
    fn write_header_into(&self, len: u16, dest: &mut [u8]) {
        BigEndian::write_u16(&mut dest[..2], self.channel_id);
        BigEndian::write_u16(&mut dest[2..4], len);
    }
}

impl<T: AsRef<[u8]> + core::fmt::Debug> DelayedTransmitBuild for DelayedChannel<T> {
    fn len(&self) -> usize {
        self.data.as_ref().len() + 4
    }

    fn build(self) -> Vec<u8> {
        let data = self.data.as_ref();
        let data_len = data.len();
        let mut header = [0; 4];
        self.write_header_into(data_len as u16, &mut header);
        let mut out = Vec::with_capacity(4 + data_len);
        out.extend(header.as_slice());
        out.extend_from_slice(data);
        out
    }

    fn write_into(self, dest: &mut [u8]) -> usize {
        let data = self.data.as_ref();
        let data_len = data.len();
        self.write_header_into(data_len as u16, dest);
        dest[4..4 + data_len].copy_from_slice(data);
        data_len + 4
    }
}

/// A `Transmit` that will construct a STUN message towards a client with the relevant data.
#[derive(Debug)]
pub struct DelayedMessage<T: AsRef<[u8]> + core::fmt::Debug> {
    data: T,
    peer_addr: SocketAddr,
    for_client: bool,
}

impl<T: AsRef<[u8]> + core::fmt::Debug> DelayedMessage<T> {
    /// Construct a [`Message`] aimed at being delievered to a TURN client.
    pub fn for_client(peer_addr: SocketAddr, data: T) -> Self {
        Self {
            peer_addr,
            data,
            for_client: true,
        }
    }
    /// Construct a [`Message`] aimed at being delievered to a TURN server.
    pub fn for_server(peer_addr: SocketAddr, data: T) -> Self {
        Self {
            peer_addr,
            data,
            for_client: false,
        }
    }
}

impl<T: AsRef<[u8]> + core::fmt::Debug> DelayedTransmitBuild for DelayedMessage<T> {
    fn len(&self) -> usize {
        let xor_peer_addr = XorPeerAddress::new(self.peer_addr, 0.into());
        let data = AData::new(self.data.as_ref());
        MessageHeader::LENGTH + xor_peer_addr.padded_len() + data.padded_len()
    }

    fn build(self) -> Vec<u8> {
        let transaction_id = TransactionId::generate();
        let method = if self.for_client { DATA } else { SEND };
        let mut msg = Message::builder(
            MessageType::from_class_method(
                stun_proto::types::message::MessageClass::Indication,
                method,
            ),
            transaction_id,
            MessageWriteVec::with_capacity(self.len()),
        );
        let xor_peer_address = XorPeerAddress::new(self.peer_addr, transaction_id);
        msg.add_attribute(&xor_peer_address).unwrap();
        let data = AData::new(self.data.as_ref());
        msg.add_attribute(&data).unwrap();
        msg.finish()
    }

    fn write_into(self, dest: &mut [u8]) -> usize {
        let transaction_id = TransactionId::generate();
        let mut msg = Message::builder(
            MessageType::from_class_method(
                stun_proto::types::message::MessageClass::Indication,
                SEND,
            ),
            transaction_id,
            MessageWriteMutSlice::new(dest),
        );
        let xor_peer_address = XorPeerAddress::new(self.peer_addr, transaction_id);
        msg.add_attribute(&xor_peer_address).unwrap();
        let data = AData::new(self.data.as_ref());
        msg.add_attribute(&data).unwrap();
        msg.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use alloc::vec;

    #[test]
    fn test_delayed_vecu8() {
        let data = vec![7; 7];
        assert_eq!(DelayedTransmitBuild::len(&data), data.len());
        assert_eq!(DelayedTransmitBuild::build(data.clone()), data);
        assert!(!DelayedTransmitBuild::is_empty(&data));
        assert!(DelayedTransmitBuild::is_empty(&Vec::new()));
        let mut out = vec![0; 8];
        assert_eq!(DelayedTransmitBuild::write_into(data.clone(), &mut out), 7);
    }

    #[test]
    fn test_delayed_u8slice() {
        let data = [7; 7];
        assert_eq!(DelayedTransmitBuild::len(&data.as_slice()), data.len());
        assert_eq!(DelayedTransmitBuild::build(data.as_slice()), data);
        assert!(!DelayedTransmitBuild::is_empty(&data.as_slice()));
        assert!(DelayedTransmitBuild::is_empty(&[].as_slice()));
        let mut out = [0; 8];
        assert_eq!(
            DelayedTransmitBuild::write_into(data.as_slice(), &mut out),
            7
        );
    }
}
