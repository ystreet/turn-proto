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
pub trait TurnClientApi: std::fmt::Debug + Send {
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

    /// Whether the client currently has a permission installed for the provided transport and
    /// address.
    fn have_permission(&self, transport: TransportType, to: IpAddr) -> bool;

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
pub(crate) mod tests {
    use std::time::Duration;

    use crate::protocol::{EXPIRY_BUFFER, PERMISSION_DURATION};

    use super::*;
    use tracing::trace;
    use turn_server_proto::api::{TurnServerApi, TurnServerPollRet};
    use turn_types::{
        attribute::{Lifetime, RequestedTransport, XorRelayedAddress},
        channel::ChannelData,
        message::{ALLOCATE, CHANNEL_BIND, CREATE_PERMISSION, DATA, REFRESH},
        stun::{
            attribute::{
                ErrorCode, MessageIntegrity, MessageIntegritySha256, Nonce, Realm, Username,
                XorMappedAddress,
            },
            message::Method,
        },
        TurnCredentials,
    };

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

    pub(crate) fn transmit_send_build<T: DelayedTransmitBuild + std::fmt::Debug>(
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
    }
    impl TurnTestBuilder {
        pub(crate) fn build<
            A: TurnClientApi,
            S: TurnServerApi,
            FClient: FnOnce(SocketAddr, SocketAddr, TurnCredentials) -> A,
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
            }
        }

        pub(crate) fn split_transmit_bytes(mut self, bytes: usize) -> Self {
            self.split_transmit_bytes = bytes;
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
    }

    impl<A: TurnClientApi, S: TurnServerApi> TurnTest<A, S> {
        pub(crate) fn builder() -> TurnTestBuilder {
            let credentials = TurnCredentials::new("turnuser", "turnpass");
            TurnTestBuilder {
                turn_listen_addr: "127.0.0.1:3478".parse().unwrap(),
                credentials,
                realm: String::from("realm"),
                client_addr: "127.0.0.1:2000".parse().unwrap(),
                turn_alloc_addr: "10.0.0.20:2000".parse().unwrap(),
                peer_addr: "10.0.0.3:3000".parse().unwrap(),
                split_transmit_bytes: 0,
            }
        }

        pub(crate) fn client_recv<T: AsRef<[u8]> + std::fmt::Debug>(
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

        fn allocate(&mut self, now: Instant) {
            // initial allocate
            let transmit = self.client.poll_transmit(now).unwrap();
            let msg = Message::from_bytes(&transmit.data).unwrap();
            assert!(msg.has_method(ALLOCATE));
            assert!(msg.has_class(stun_proto::types::message::MessageClass::Request));
            assert!(msg.has_attribute(RequestedTransport::TYPE));
            assert!(!msg.has_attribute(Realm::TYPE));
            assert!(!msg.has_attribute(Nonce::TYPE));
            assert!(!msg.has_attribute(Username::TYPE));
            assert!(!msg.has_attribute(MessageIntegrity::TYPE));
            assert!(!msg.has_attribute(MessageIntegritySha256::TYPE));
            // error reply
            let transmit = self.server.recv(transmit, now).unwrap().unwrap();
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
            let transmit = self.client.poll_transmit(now).unwrap();
            let msg = Message::from_bytes(&transmit.data).unwrap();
            assert!(msg.has_method(ALLOCATE));
            assert!(msg.has_class(stun_proto::types::message::MessageClass::Request));
            assert!(msg.has_attribute(RequestedTransport::TYPE));
            assert!(msg.has_attribute(Realm::TYPE));
            assert!(msg.has_attribute(Nonce::TYPE));
            assert!(msg.has_attribute(Username::TYPE));
            assert!(msg.has_attribute(MessageIntegrity::TYPE));
            let Ok(None) = self.server.recv(transmit, now) else {
                unreachable!();
            };
            let TurnServerPollRet::AllocateSocketUdp {
                transport,
                local_addr: alloc_local_addr,
                remote_addr: alloc_remote_addr,
            } = self.server.poll(now)
            else {
                unreachable!();
            };
            assert_eq!(transport, self.client.transport());
            assert_eq!(alloc_local_addr, self.server.listen_address());
            assert_eq!(alloc_remote_addr, self.client.local_addr());
            self.server.allocated_udp_socket(
                transport,
                alloc_local_addr,
                alloc_remote_addr,
                Ok(self.turn_alloc_addr),
                now,
            );
            // ok reply
            let Some(transmit) = self.server.poll_transmit(now) else {
                unreachable!();
            };
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
                .any(|(transport, relayed)| transport == TransportType::Udp
                    && relayed == self.turn_alloc_addr))
        }

        fn refresh(&mut self, now: Instant) {
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
            assert!(msg.has_attribute(Username::TYPE));
            assert!(msg.has_attribute(MessageIntegrity::TYPE));
            // ok reply
            let Ok(Some(transmit)) = self.server.recv(transmit, now) else {
                unreachable!();
            };
            let Some(transmit) = self.maybe_handles_stale_nonce(transmit, now) else {
                self.refresh(now);
                return;
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
                .any(|(transport, relayed)| transport == TransportType::Udp
                    && relayed == self.turn_alloc_addr))
        }

        fn delete_allocation(&mut self, now: Instant) {
            self.client.delete(now).unwrap();
            let transmit = self.client.poll_transmit(now).unwrap();
            self.handle_delete_allocation(transmit, now);
        }

        fn handle_delete_allocation<T: AsRef<[u8]> + std::fmt::Debug>(
            &mut self,
            transmit: Transmit<T>,
            now: Instant,
        ) {
            let msg = Message::from_bytes(transmit.data.as_ref()).unwrap();
            assert!(msg.has_method(REFRESH));
            assert!(msg.has_class(stun_proto::types::message::MessageClass::Request));
            assert!(msg.has_attribute(Lifetime::TYPE));
            assert!(msg.has_attribute(Realm::TYPE));
            assert!(msg.has_attribute(Nonce::TYPE));
            assert!(msg.has_attribute(Username::TYPE));
            assert!(msg.has_attribute(MessageIntegrity::TYPE));
            // ok reply
            let Ok(Some(transmit)) = self.server.recv(transmit, now) else {
                unreachable!();
            };
            let Some(transmit) = self.maybe_handles_stale_nonce(transmit, now) else {
                let transmit = self.client.poll_transmit(now).unwrap();
                self.handle_delete_allocation(transmit, now);
                return;
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
                .any(|(transport, relayed)| transport == TransportType::Udp
                    && relayed == self.turn_alloc_addr))
        }

        fn create_permission(&mut self, now: Instant) {
            self.client
                .create_permission(TransportType::Udp, self.peer_addr.ip(), now)
                .unwrap();
            let transmit = self.client.poll_transmit(now).unwrap();
            self.handle_create_permission(transmit, now);
        }

        fn handle_create_permission<T: AsRef<[u8]> + std::fmt::Debug>(
            &mut self,
            transmit: Transmit<T>,
            now: Instant,
        ) {
            let msg = Message::from_bytes(transmit.data.as_ref()).unwrap();
            assert!(msg.has_method(CREATE_PERMISSION));
            assert!(msg.has_class(stun_proto::types::message::MessageClass::Request));
            assert!(msg.has_attribute(XorPeerAddress::TYPE));
            assert!(msg.has_attribute(MessageIntegrity::TYPE));
            let Ok(Some(transmit)) = self.server.recv(transmit, now) else {
                unreachable!();
            };
            let Some(transmit) = self.maybe_handles_stale_nonce(transmit, now) else {
                let transmit = self.client.poll_transmit(now).unwrap();
                self.handle_create_permission(transmit, now);
                return;
            };
            assert!(matches!(
                self.client_recv(transmit, now),
                TurnRecvRet::Handled
            ));
            self.validate_client_permission_state();
        }

        fn maybe_handles_stale_nonce<T: AsRef<[u8]> + std::fmt::Debug>(
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
                .permissions(TransportType::Udp, self.turn_alloc_addr)
                .any(|perm_addr| perm_addr == self.peer_addr.ip()));
        }

        fn bind_channel(&mut self, now: Instant) {
            self.client
                .bind_channel(TransportType::Udp, self.peer_addr, now)
                .unwrap();
            let transmit = self.client.poll_transmit(now).unwrap();
            self.handle_bind_channel(transmit, now);
        }

        fn handle_bind_channel<T: AsRef<[u8]> + std::fmt::Debug>(
            &mut self,
            transmit: Transmit<T>,
            now: Instant,
        ) {
            let msg = Message::from_bytes(transmit.data.as_ref()).unwrap();
            assert!(msg.has_method(CHANNEL_BIND));
            assert!(msg.has_class(stun_proto::types::message::MessageClass::Request));
            assert!(msg.has_attribute(XorPeerAddress::TYPE));
            assert!(msg.has_attribute(MessageIntegrity::TYPE));
            let Ok(Some(transmit)) = self.server.recv(transmit, now) else {
                unreachable!();
            };
            let Some(transmit) = self.maybe_handles_stale_nonce(transmit, now) else {
                let transmit = self.client.poll_transmit(now).unwrap();
                self.handle_create_permission(transmit, now);
                return;
            };
            assert!(matches!(
                self.client_recv(transmit, now),
                TurnRecvRet::Handled
            ));
            assert!(self
                .client
                .have_permission(TransportType::Udp, self.peer_addr.ip()))
        }

        fn sendrecv_data(&mut self, now: Instant) {
            // client to peer
            let data = [4; 8];
            let transmit = self
                .client
                .send_to(TransportType::Udp, self.peer_addr, data, now)
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
            let Ok(Some(transmit)) = self.server.recv(transmit, now) else {
                unreachable!();
            };
            assert_eq!(transmit.transport, TransportType::Udp);
            assert_eq!(transmit.from, self.turn_alloc_addr);
            assert_eq!(transmit.to, self.peer_addr);

            // peer to client
            let sent_data = [5; 12];
            let Some(transmit) = self
                .server
                .recv(
                    Transmit::new(
                        sent_data,
                        TransportType::Udp,
                        self.peer_addr,
                        self.turn_alloc_addr,
                    ),
                    now,
                )
                .unwrap()
            else {
                unreachable!();
            };
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
            assert_eq!(peer_data.data(), sent_data);
        }

        fn sendrecv_data_channel(&mut self, now: Instant) {
            let to_peer = [4; 8];
            let from_peer = [5; 12];
            self.sendrecv_data_channel_with_data(&to_peer, &from_peer, now);
        }

        fn sendrecv_data_channel_with_data(
            &mut self,
            to_peer: &[u8],
            from_peer: &[u8],
            now: Instant,
        ) {
            let transmit = self
                .client
                .send_to(TransportType::Udp, self.peer_addr, to_peer, now)
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
            let Some(transmit) = self
                .server
                .recv(transmit, now)
                .ok()
                .flatten()
                .or_else(|| self.server.poll_transmit(now))
            else {
                unreachable!();
            };
            assert_eq!(transmit.transport, TransportType::Udp);
            assert_eq!(transmit.from, self.turn_alloc_addr);
            assert_eq!(transmit.to, self.peer_addr);

            // peer to client
            let Some(transmit) = self
                .server
                .recv(
                    Transmit::new(
                        from_peer,
                        TransportType::Udp,
                        self.peer_addr,
                        self.turn_alloc_addr,
                    ),
                    now,
                )
                .unwrap()
            else {
                unreachable!();
            };
            assert_eq!(transmit.transport, self.client.transport());
            assert_eq!(transmit.from, self.server.listen_address());
            assert_eq!(transmit.to, self.client.local_addr());
            let cd = ChannelData::parse(&transmit.data).unwrap();
            assert_eq!(cd.data(), from_peer);
            let TurnRecvRet::PeerData(peer_data) = self.client_recv(transmit, now) else {
                unreachable!();
            };
            println!("{peer_data:?}");
            assert_eq!(peer_data.peer, self.peer_addr);
            assert_eq!(peer_data.data(), from_peer);
        }
    }

    pub(crate) fn turn_allocate_permission<A: TurnClientApi, S: TurnServerApi>(
        test: &mut TurnTest<A, S>,
        now: Instant,
    ) {
        test.allocate(now);
        let Some(TurnEvent::AllocationCreated(TransportType::Udp, relayed_address)) =
            test.client.poll_event()
        else {
            unreachable!();
        };
        assert_eq!(relayed_address, test.turn_alloc_addr);
        test.create_permission(now);
        let Some(TurnEvent::PermissionCreated(TransportType::Udp, permission_ip)) =
            test.client.poll_event()
        else {
            unreachable!();
        };
        assert_eq!(permission_ip, test.peer_addr.ip());

        test.sendrecv_data(now);
        test.bind_channel(now);
        test.sendrecv_data_channel(now);
    }

    pub(crate) fn turn_allocate_expire_server<A: TurnClientApi, S: TurnServerApi>(
        test: &mut TurnTest<A, S>,
        now: Instant,
    ) {
        test.server
            .set_nonce_expiry_duration(Duration::from_secs(9000));

        test.allocate(now);
        let Some(TurnEvent::AllocationCreated(TransportType::Udp, relayed_address)) =
            test.client.poll_event()
        else {
            unreachable!();
        };
        assert_eq!(relayed_address, test.turn_alloc_addr);
        test.client
            .create_permission(TransportType::Udp, test.peer_addr.ip(), now)
            .unwrap();
        let transmit = test.client.poll_transmit(now).unwrap();
        let now = now + Duration::from_secs(3000);
        let Ok(Some(transmit)) = test.server.recv(transmit, now) else {
            unreachable!();
        };
        let msg = Message::from_bytes(&transmit.data).unwrap();
        assert!(msg.has_method(CREATE_PERMISSION));
        assert!(msg.has_class(stun_proto::types::message::MessageClass::Error));
        let err = msg.attribute::<ErrorCode>().unwrap();
        assert_eq!(err.code(), ErrorCode::ALLOCATION_MISMATCH);
        let ret = test.client.recv(transmit, now);
        assert!(matches!(ret, TurnRecvRet::Handled));
    }

    pub(crate) fn turn_allocate_expire_client<A: TurnClientApi, S: TurnServerApi>(
        test: &mut TurnTest<A, S>,
        now: Instant,
    ) {
        test.allocate(now);
        let Some(TurnEvent::AllocationCreated(TransportType::Udp, relayed_address)) =
            test.client.poll_event()
        else {
            unreachable!();
        };
        assert_eq!(relayed_address, test.turn_alloc_addr);
        let now = now + Duration::from_secs(3000);
        let Err(CreatePermissionError::NoAllocation) =
            test.client
                .create_permission(TransportType::Udp, test.peer_addr.ip(), now)
        else {
            unreachable!();
        };
    }

    pub(crate) fn turn_allocate_refresh<A: TurnClientApi, S: TurnServerApi>(
        test: &mut TurnTest<A, S>,
        now: Instant,
    ) {
        test.allocate(now);
        let Some(TurnEvent::AllocationCreated(TransportType::Udp, relayed_address)) =
            test.client.poll_event()
        else {
            unreachable!();
        };
        assert_eq!(relayed_address, test.turn_alloc_addr);

        let TurnPollRet::WaitUntil(expiry) = test.client.poll(now) else {
            unreachable!()
        };
        trace!("expiry: {expiry:?}");
        assert!(expiry > now + Duration::from_secs(1000));

        test.refresh(expiry);
        test.create_permission(expiry);
        let Some(TurnEvent::PermissionCreated(TransportType::Udp, permission_ip)) =
            test.client.poll_event()
        else {
            unreachable!();
        };
        assert_eq!(permission_ip, test.peer_addr.ip());
        test.sendrecv_data(expiry);
    }

    pub(crate) fn turn_allocate_delete<A: TurnClientApi, S: TurnServerApi>(
        test: &mut TurnTest<A, S>,
        now: Instant,
    ) {
        test.allocate(now);
        test.delete_allocation(now);

        let Err(CreatePermissionError::NoAllocation) =
            test.client
                .create_permission(TransportType::Udp, test.peer_addr.ip(), now)
        else {
            unreachable!();
        };
    }

    pub(crate) fn turn_channel_bind<A: TurnClientApi, S: TurnServerApi>(
        test: &mut TurnTest<A, S>,
        now: Instant,
    ) {
        test.allocate(now);
        let Some(TurnEvent::AllocationCreated(TransportType::Udp, relayed_address)) =
            test.client.poll_event()
        else {
            unreachable!();
        };
        assert_eq!(relayed_address, test.turn_alloc_addr);
        test.bind_channel(now);
        let Some(TurnEvent::PermissionCreated(TransportType::Udp, permission_ip)) =
            test.client.poll_event()
        else {
            unreachable!();
        };
        assert_eq!(permission_ip, test.peer_addr.ip());
        test.sendrecv_data_channel(now);
    }

    pub(crate) fn turn_peer_incoming_stun<A: TurnClientApi, S: TurnServerApi>(
        test: &mut TurnTest<A, S>,
        now: Instant,
    ) {
        // tests that sending stun messages can be passed through the turn server
        test.allocate(now);
        let Some(TurnEvent::AllocationCreated(TransportType::Udp, relayed_address)) =
            test.client.poll_event()
        else {
            unreachable!();
        };
        assert_eq!(relayed_address, test.turn_alloc_addr);
        test.bind_channel(now);
        let Some(TurnEvent::PermissionCreated(TransportType::Udp, permission_ip)) =
            test.client.poll_event()
        else {
            unreachable!();
        };
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

    pub(crate) fn turn_create_permission_refresh<A: TurnClientApi, S: TurnServerApi>(
        test: &mut TurnTest<A, S>,
        now: Instant,
    ) {
        test.allocate(now);
        let Some(TurnEvent::AllocationCreated(TransportType::Udp, relayed_address)) =
            test.client.poll_event()
        else {
            unreachable!();
        };
        assert_eq!(relayed_address, test.turn_alloc_addr);

        test.create_permission(now);
        let Some(TurnEvent::PermissionCreated(TransportType::Udp, permission_ip)) =
            test.client.poll_event()
        else {
            unreachable!();
        };
        assert_eq!(permission_ip, test.peer_addr.ip());

        let TurnPollRet::WaitUntil(expiry) = test.client.poll(now) else {
            unreachable!()
        };
        assert_eq!(expiry, now + PERMISSION_DURATION - EXPIRY_BUFFER);
        let TurnPollRet::WaitUntil(now) = test.client.poll(expiry) else {
            unreachable!()
        };
        assert_eq!(now, expiry);

        let create_permission = |test: &mut TurnTest<A, S>, now: Instant| -> Transmit<Vec<u8>> {
            let transmit = test.client.poll_transmit(now).unwrap();
            let msg = Message::from_bytes(&transmit.data).unwrap();
            assert_eq!(msg.method(), CREATE_PERMISSION);
            let Ok(Some(transmit)) = test.server.recv(transmit, now) else {
                unreachable!();
            };
            transmit
        };

        let transmit = create_permission(test, now);
        let transmit = if let Some(transmit) = test.maybe_handles_stale_nonce(transmit, now) {
            transmit
        } else {
            create_permission(test, now)
        };
        assert!(matches!(
            test.client.recv(transmit, expiry),
            TurnRecvRet::Handled
        ));
        test.validate_client_permission_state();

        test.sendrecv_data(expiry);
    }

    pub(crate) fn turn_create_permission_timeout<A: TurnClientApi, S: TurnServerApi>(
        test: &mut TurnTest<A, S>,
        now: Instant,
    ) {
        test.allocate(now);
        let Some(TurnEvent::AllocationCreated(TransportType::Udp, relayed_address)) =
            test.client.poll_event()
        else {
            unreachable!();
        };
        assert_eq!(relayed_address, test.turn_alloc_addr);

        test.create_permission(now);
        let Some(TurnEvent::PermissionCreated(TransportType::Udp, permission_ip)) =
            test.client.poll_event()
        else {
            unreachable!();
        };
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
            .have_permission(TransportType::Udp, test.peer_addr.ip()));
        let Some(TurnEvent::PermissionCreateFailed(_transport, ip)) = test.client.poll_event()
        else {
            unreachable!();
        };
        assert_eq!(ip, test.peer_addr.ip());
    }

    pub(crate) fn turn_channel_bind_refresh<A: TurnClientApi, S: TurnServerApi>(
        test: &mut TurnTest<A, S>,
        now: Instant,
    ) {
        test.allocate(now);
        let Some(TurnEvent::AllocationCreated(TransportType::Udp, relayed_address)) =
            test.client.poll_event()
        else {
            unreachable!();
        };
        assert_eq!(relayed_address, test.turn_alloc_addr);

        test.bind_channel(now);
        let Some(TurnEvent::PermissionCreated(TransportType::Udp, permission_ip)) =
            test.client.poll_event()
        else {
            unreachable!();
        };
        assert_eq!(permission_ip, test.peer_addr.ip());

        // two permission refreshes
        let mut permissions_done = now;
        for _i in 0..2 {
            let now = permissions_done;
            let TurnPollRet::WaitUntil(expiry) = test.client.poll(now) else {
                unreachable!()
            };
            assert_eq!(expiry, now + PERMISSION_DURATION - EXPIRY_BUFFER);
            let TurnPollRet::WaitUntil(now) = test.client.poll(expiry) else {
                unreachable!()
            };
            assert_eq!(now, expiry);

            let create_permission =
                move |test: &mut TurnTest<A, S>, now: Instant| -> Transmit<Vec<u8>> {
                    let transmit = test.client.poll_transmit(now).unwrap();
                    let msg = Message::from_bytes(&transmit.data).unwrap();
                    assert_eq!(msg.method(), CREATE_PERMISSION);
                    let Ok(Some(transmit)) = test.server.recv(transmit, now) else {
                        unreachable!();
                    };
                    transmit
                };

            let transmit = create_permission(test, now);
            let transmit = if let Some(transmit) = test.maybe_handles_stale_nonce(transmit, now) {
                transmit
            } else {
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
        assert_eq!(expiry, now + Duration::from_secs(60));
        let TurnPollRet::WaitUntil(now) = test.client.poll(expiry) else {
            unreachable!()
        };
        assert_eq!(now, expiry);
        let transmit = test.client.poll_transmit(expiry).unwrap();
        let msg = Message::from_bytes(&transmit.data).unwrap();
        println!("message {msg}");
        assert_eq!(msg.method(), CHANNEL_BIND);
        let Ok(Some(transmit)) = test.server.recv(transmit, now) else {
            unreachable!();
        };
        assert!(matches!(
            test.client.recv(transmit, expiry),
            TurnRecvRet::Handled
        ));

        test.sendrecv_data_channel(expiry);
    }

    pub(crate) fn turn_offpath_data<A: TurnClientApi, S: TurnServerApi>(
        test: &mut TurnTest<A, S>,
        now: Instant,
    ) {
        turn_allocate_permission(test, now);
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

    pub(crate) fn turn_unparseable_data<A: TurnClientApi, S: TurnServerApi>(
        test: &mut TurnTest<A, S>,
        now: Instant,
    ) {
        turn_allocate_permission(test, now);
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
}
