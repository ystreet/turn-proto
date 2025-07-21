// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! # Common module

use std::net::{IpAddr, SocketAddr};
use std::ops::Range;
use std::time::Instant;

use byteorder::{BigEndian, ByteOrder};
use stun_proto::agent::Transmit;
use stun_proto::types::data::Data;
use stun_proto::types::message::{
    Message, MessageHeader, MessageType, MessageWriteMutSlice, MessageWriteVec, TransactionId,
};
use stun_proto::types::prelude::*;
use stun_proto::types::TransportType;
use turn_types::attribute::Data as AData;
use turn_types::attribute::XorPeerAddress;
use turn_types::message::SEND;

/// The public API of a TURN client.
pub trait TurnClientApi {
    /// The error produced when attemptingo to send to a peer.
    type SendError: std::error::Error;

    /// The transport of the connection to the TURN server.
    fn transport(&self) -> TransportType;

    /// The local address of this TURN client.
    fn local_addr(&self) -> SocketAddr;

    /// The remote TURN server's address.
    fn remote_addr(&self) -> SocketAddr;

    /// The list of allocated relayed addresses on the TURN server.
    fn relayed_addresses(&self) -> impl Iterator<Item = (TransportType, SocketAddr)> + '_;

    /// The list of permissions available for the provided relayed address.
    fn permissions(
        &self,
        transport: TransportType,
        relayed: SocketAddr,
    ) -> impl Iterator<Item = IpAddr> + '_;

    /// Remove the allocation/s on the server.
    fn delete(&mut self, now: Instant) -> Result<(), DeleteError>;

    /// Create a permission address to allow sending/receiving data to/from.
    fn create_permission(
        &mut self,
        transport: TransportType,
        peer_addr: IpAddr,
        now: Instant,
    ) -> Result<(), CreatePermissionError>;

    /// Bind a channel for sending/receiving data to/from a particular peer.
    fn bind_channel(
        &mut self,
        transport: TransportType,
        peer_addr: SocketAddr,
        now: Instant,
    ) -> Result<(), BindChannelError>;

    /// Send data to a peer through the TURN server.
    ///
    /// The provided transport, address and data are the data to send to the peer.
    ///
    /// The returned value will instruct the caller to send a message to the turn server.
    fn send_to<T: AsRef<[u8]> + std::fmt::Debug>(
        &mut self,
        transport: TransportType,
        to: SocketAddr,
        data: T,
        now: Instant,
    ) -> Result<Option<TransmitBuild<DelayedMessageOrChannelSend<T>>>, Self::SendError>;

    /// Provide received data to the TURN client for handling.
    ///
    /// The returned data outlines what to do with this data.
    fn recv<T: AsRef<[u8]> + std::fmt::Debug>(
        &mut self,
        transmit: Transmit<T>,
        now: Instant,
    ) -> TurnRecvRet<T>;

    /// Poll the client for any further recevied data.
    fn poll_recv(&mut self, now: Instant) -> Option<TurnPeerData<Vec<u8>>>;

    /// Poll the client for further progress.
    fn poll(&mut self, now: Instant) -> TurnPollRet;

    /// Poll for a packet to send.
    fn poll_transmit(&mut self, now: Instant) -> Option<Transmit<Data<'static>>>;

    /// Poll for an event that has occurred.
    fn poll_event(&mut self) -> Option<TurnEvent>;
}

/// Return value from calling [poll](TurnClientApi::poll)().
#[derive(Debug)]
pub enum TurnPollRet {
    /// The caller should wait until the provided time. Other events may cause this value to
    /// modified and poll() should be rechecked.
    WaitUntil(Instant),
    /// The connection is closed and no further progress will be made.
    Closed,
}

/// Return value from call [recv](TurnClientApi::recv).
#[derive(Debug)]
pub enum TurnRecvRet<T: AsRef<[u8]> + std::fmt::Debug> {
    /// The data has been handled internally and should not be forwarded any further.
    Handled,
    /// The data is not directed at this [`TurnClientApi`].
    Ignored(Transmit<T>),
    /// Data has been received from a peer of the TURN server.
    PeerData(TurnPeerData<T>),
}

/// Data that has been received from the TURN server.
#[derive(Debug)]
pub struct TurnPeerData<T: AsRef<[u8]> + std::fmt::Debug> {
    /// The data received.
    pub(crate) data: DataRangeOrOwned<T>,
    /// The transport the data was received over.
    pub transport: TransportType,
    /// The address of the peer that sent the data.
    pub peer: SocketAddr,
}

impl<T: AsRef<[u8]> + std::fmt::Debug> TurnPeerData<T> {
    /// The data slice of this [`TurnPeerData`]
    pub fn data(&self) -> &[u8] {
        self.data.as_ref()
    }
}

impl<T: AsRef<[u8]> + std::fmt::Debug> AsRef<[u8]> for TurnPeerData<T> {
    fn as_ref(&self) -> &[u8] {
        self.data.as_ref()
    }
}

/// A set of events that can occur within a TURN client's connection to a TURN server.
#[derive(Debug)]
pub enum TurnEvent {
    /// An allocation was created on the server for the client.  The allocation as the associated
    /// transport and address.
    AllocationCreated(TransportType, SocketAddr),
    /// Allocation failed to be created.
    AllocationCreateFailed,
    /// A permission was created for the provided transport and IP address.
    PermissionCreated(TransportType, IpAddr),
    /// A permission could not be installed for the provided transport and IP address.
    PermissionCreateFailed(TransportType, IpAddr),
}

/// Errors produced when attempting to bind a channel.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BindChannelError {
    /// The channel identifier already exists and cannot be recreated.
    #[error("The channel identifier already exists and cannot be recreated.")]
    AlreadyExists,
    /// There is no connection to the TURN server that can handle this channel.
    #[error("There is no connection to the TURN server that can handle this channel.")]
    NoAllocation,
}

/// Errors produced when attempting to create a permission for a peer address.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CreatePermissionError {
    /// The permission already exists and cannot be recreated.
    #[error("The permission already exists and cannot be recreated.")]
    AlreadyExists,
    /// There is no connection to the TURN server that can handle this permission.
    #[error("There is no connection to the TURN server that can handle this permission")]
    NoAllocation,
}

/// Errors produced when attempting to delete an allocation.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DeleteError {
    /// There is no connection to the TURN server.
    #[error("There is no connection to the TURN server")]
    NoAllocation,
}

/// A slice range or an owned piece of data.
#[derive(Debug)]
pub enum DataRangeOrOwned<T: AsRef<[u8]> + std::fmt::Debug> {
    /// A range of a provided data slice.
    Range {
        /// The data received.
        data: T,
        /// The range of data to access.
        range: Range<usize>,
    },
    /// An owned piece of data.
    Owned(Vec<u8>),
}

impl<T: AsRef<[u8]> + std::fmt::Debug> AsRef<[u8]> for DataRangeOrOwned<T> {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Range { data, range } => &data.as_ref()[range.start..range.end],
            Self::Owned(owned) => owned,
        }
    }
}

/// A piece of data that needs to be built before it can be transmitted.
#[derive(Debug)]
pub struct TransmitBuild<T: DelayedTransmitBuild + std::fmt::Debug> {
    /// The data blob
    pub data: T,
    /// The transport for the transmission
    pub transport: TransportType,
    /// The source address of the transmission
    pub from: SocketAddr,
    /// The destination address of the transmission
    pub to: SocketAddr,
}

impl<T: DelayedTransmitBuild + std::fmt::Debug> TransmitBuild<T> {
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
    /// The length of any generated data
    fn len(&self) -> usize;
    /// Whether the resulting data would be empty
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Write the data into a provided output buffer. Returns the number of bytes written.
    fn write_into(self, data: &mut [u8]) -> usize;
}

/// A `Transmit` where the data is some subset of the provided region.
#[derive(Debug)]
pub struct DelayedTransmit<T: AsRef<[u8]> + std::fmt::Debug> {
    data: T,
    range: Range<usize>,
}

impl<T: AsRef<[u8]> + std::fmt::Debug> DelayedTransmit<T> {
    fn data(&self) -> &[u8] {
        &self.data.as_ref()[self.range.clone()]
    }
}

impl<T: AsRef<[u8]> + std::fmt::Debug> DelayedTransmitBuild for DelayedTransmit<T> {
    fn len(&self) -> usize {
        self.range.len()
    }

    fn build(self) -> Vec<u8> {
        self.data().to_vec()
    }

    fn write_into(self, data: &mut [u8]) -> usize {
        data.copy_from_slice(self.data());
        self.len()
    }
}

/// A `Transmit` that will construct a STUN message towards a client with the relevant data.
#[derive(Debug)]
pub struct DelayedMessageSend<T: AsRef<[u8]> + std::fmt::Debug> {
    data: T,
    peer_addr: SocketAddr,
}

impl<T: AsRef<[u8]> + std::fmt::Debug> DelayedTransmitBuild for DelayedMessageSend<T> {
    fn len(&self) -> usize {
        let xor_peer_addr = XorPeerAddress::new(self.peer_addr, 0.into());
        let data = AData::new(self.data.as_ref());
        MessageHeader::LENGTH + xor_peer_addr.padded_len() + data.padded_len()
    }

    fn build(self) -> Vec<u8> {
        let transaction_id = TransactionId::generate();
        let mut msg = Message::builder(
            MessageType::from_class_method(
                stun_proto::types::message::MessageClass::Indication,
                SEND,
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

/// A `Transmit` that will construct a channel message towards a TURN client.
#[derive(Debug)]
pub struct DelayedChannelSend<T: AsRef<[u8]> + std::fmt::Debug> {
    data: T,
    channel_id: u16,
}

impl<T: AsRef<[u8]> + std::fmt::Debug> DelayedChannelSend<T> {
    fn write_header_into(&self, len: u16, dest: &mut [u8]) {
        BigEndian::write_u16(&mut dest[..2], self.channel_id);
        BigEndian::write_u16(&mut dest[2..4], len);
    }
}

impl<T: AsRef<[u8]> + std::fmt::Debug> DelayedTransmitBuild for DelayedChannelSend<T> {
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

/// A delayed `Transmit` that will produce data for a TURN client.
#[derive(Debug)]
pub enum DelayedMessageOrChannelSend<T: AsRef<[u8]> + std::fmt::Debug> {
    /// A [`DelayedChannelSend`].
    Channel(DelayedChannelSend<T>),
    /// A [`DelayedMessageSend`].
    Message(DelayedMessageSend<T>),
    /// An already constructed piece of data.
    Data(Vec<u8>),
}

impl<T: AsRef<[u8]> + std::fmt::Debug> DelayedMessageOrChannelSend<T> {
    pub(crate) fn new_channel(data: T, channel_id: u16) -> Self {
        Self::Channel(DelayedChannelSend { data, channel_id })
    }

    pub(crate) fn new_message(data: T, peer_addr: SocketAddr) -> Self {
        Self::Message(DelayedMessageSend { data, peer_addr })
    }
}

impl<T: AsRef<[u8]> + std::fmt::Debug> DelayedTransmitBuild for DelayedMessageOrChannelSend<T> {
    fn len(&self) -> usize {
        match self {
            Self::Channel(channel) => channel.len(),
            Self::Message(msg) => msg.len(),
            Self::Data(owned) => owned.len(),
        }
    }

    fn build(self) -> Vec<u8> {
        match self {
            Self::Channel(channel) => channel.build(),
            Self::Message(msg) => msg.build(),
            Self::Data(owned) => owned,
        }
    }

    fn write_into(self, data: &mut [u8]) -> usize {
        match self {
            Self::Channel(channel) => channel.write_into(data),
            Self::Message(msg) => msg.write_into(data),
            Self::Data(owned) => {
                data.copy_from_slice(&owned);
                owned.len()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use turn_types::channel::ChannelData;

    #[test]
    fn test_delayed_message() {
        let data = [5; 5];
        let peer_addr = "127.0.0.1:1".parse().unwrap();
        let transmit = DelayedMessageOrChannelSend::Message(DelayedMessageSend { data, peer_addr });
        let len = transmit.len();
        let out = transmit.build();
        assert_eq!(len, out.len());
        let msg = Message::from_bytes(&out).unwrap();
        let addr = msg.attribute::<XorPeerAddress>().unwrap();
        assert_eq!(addr.addr(msg.transaction_id()), peer_addr);
        let out_data = msg.attribute::<AData>().unwrap();
        assert_eq!(out_data.data(), data.as_ref());
        let transmit = DelayedMessageOrChannelSend::Message(DelayedMessageSend { data, peer_addr });
        let mut out2 = vec![0; len];
        transmit.write_into(&mut out2);
        let msg = Message::from_bytes(&out2).unwrap();
        let addr = msg.attribute::<XorPeerAddress>().unwrap();
        assert_eq!(addr.addr(msg.transaction_id()), peer_addr);
        let out_data = msg.attribute::<AData>().unwrap();
        assert_eq!(out_data.data(), data.as_ref());
    }

    #[test]
    fn test_delayed_channel() {
        let data = [5; 5];
        let channel_id = 0x4567;
        let transmit =
            DelayedMessageOrChannelSend::Channel(DelayedChannelSend { data, channel_id });
        let len = transmit.len();
        let out = transmit.build();
        assert_eq!(len, out.len());
        let channel = ChannelData::parse(&out).unwrap();
        assert_eq!(channel.id(), channel_id);
        assert_eq!(channel.data(), data.as_ref());
        let transmit =
            DelayedMessageOrChannelSend::Channel(DelayedChannelSend { data, channel_id });
        let mut out2 = vec![0; len];
        transmit.write_into(&mut out2);
        assert_eq!(len, out.len());
        let channel = ChannelData::parse(&out).unwrap();
        assert_eq!(channel.id(), channel_id);
        assert_eq!(channel.data(), data.as_ref());
    }
}
