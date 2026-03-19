// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! TURN client API.
//!
//! Provides a consistent interface between multiple implementations of TURN clients for different
//! transports (TCP, and UDP) and wrappers (TLS).

use alloc::vec::Vec;
use core::net::{IpAddr, SocketAddr};
use core::ops::Range;
use stun_proto::auth::Feature;
use turn_types::prelude::DelayedTransmitBuild;
use turn_types::stun::message::IntegrityAlgorithm;
pub use turn_types::transmit::TransmitBuild;
use turn_types::transmit::{DelayedChannel, DelayedMessage};

pub use stun_proto::agent::Transmit;
pub use stun_proto::types::data::Data;
use stun_proto::types::TransportType;
use stun_proto::Instant;
use turn_types::{AddressFamily, TurnCredentials};

/// The public API of a TURN client.
pub trait TurnClientApi: core::fmt::Debug + Send {
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

    /// Attempt to connect to a peer from the TURN server using TCP.
    ///
    /// Requires that a TCP allocation has been allocated on the TURN server.
    fn tcp_connect(&mut self, peer_addr: SocketAddr, now: Instant) -> Result<(), TcpConnectError>;

    /// Indicate success (or failure) to create a socket for the specified server and peer address.
    ///
    /// The values @id, @five_tuple, and @peer_addr must match the values provided in matching the
    /// [`TurnPollRet::AllocateTcpSocket`].
    fn allocated_tcp_socket(
        &mut self,
        id: u32,
        five_tuple: Socket5Tuple,
        peer_addr: SocketAddr,
        local_addr: Option<SocketAddr>,
        now: Instant,
    ) -> Result<(), TcpAllocateError>;

    /// Indicate that the TCP connection has been closed.
    fn tcp_closed(&mut self, local_addr: SocketAddr, remote_addr: SocketAddr, now: Instant);

    /// Send data to a peer through the TURN server.
    ///
    /// The provided transport, address and data are the data to send to the peer.
    ///
    /// The returned value may instruct the caller to send a message to the turn server.
    fn send_to<T: AsRef<[u8]> + core::fmt::Debug>(
        &mut self,
        transport: TransportType,
        to: SocketAddr,
        data: T,
        now: Instant,
    ) -> Result<Option<TransmitBuild<DelayedMessageOrChannelSend<T>>>, SendError>;

    /// Provide received data to the TURN client for handling.
    ///
    /// The return value outlines what to do with this data.
    fn recv<T: AsRef<[u8]> + core::fmt::Debug>(
        &mut self,
        transmit: Transmit<T>,
        now: Instant,
    ) -> TurnRecvRet<T>;

    /// Poll the client for any further received data.
    fn poll_recv(&mut self, now: Instant) -> Option<TurnPeerData<Vec<u8>>>;

    /// Poll the client for further progress.
    fn poll(&mut self, now: Instant) -> TurnPollRet;

    /// Poll for a packet to send.
    fn poll_transmit(&mut self, now: Instant) -> Option<Transmit<Data<'static>>>;

    /// Poll for an event that has occurred.
    fn poll_event(&mut self) -> Option<TurnEvent>;

    /// A higher layer has encountered an error and this client is no longer usable.
    fn protocol_error(&mut self);
}

/// Configuration structure for handling TURN client configuration.
///
/// Holds the following information:
///   - Long term credentials for connecting to a TURN server.
///   - The [`TransportType`] of the requested allocation.
///   - A list of [`AddressFamily`]s the allocation should be attempted to be created with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TurnConfig {
    allocation_transport: TransportType,
    address_families: smallvec::SmallVec<[AddressFamily; 2]>,
    credentials: TurnCredentials,
    supported_integrity: smallvec::SmallVec<[IntegrityAlgorithm; 2]>,
    anonymous_username: Feature,
}

impl TurnConfig {
    /// Construct a new [`TurnConfig`] with the provided credentials.
    ///
    /// By default a IPV4/UDP allocation is requested.
    ///
    /// # Examples
    ///
    /// ```
    /// # use turn_client_proto::api::TurnConfig;
    /// # use turn_types::{AddressFamily, TransportType, TurnCredentials};
    /// let credentials = TurnCredentials::new("user", "pass");
    /// let config = TurnConfig::new(credentials.clone());
    /// assert_eq!(config.credentials(), &credentials);
    /// assert_eq!(config.allocation_transport(), TransportType::Udp);
    /// assert_eq!(config.address_families(), &[AddressFamily::IPV4]);
    /// ```
    pub fn new(credentials: TurnCredentials) -> Self {
        Self {
            allocation_transport: TransportType::Udp,
            address_families: smallvec::smallvec![AddressFamily::IPV4],
            credentials,
            supported_integrity: smallvec::smallvec![IntegrityAlgorithm::Sha1],
            anonymous_username: Feature::Auto,
        }
    }

    /// Set the allocation transport requested.
    ///
    /// # Examples
    ///
    /// ```
    /// # use turn_client_proto::api::TurnConfig;
    /// # use turn_types::{TransportType, TurnCredentials};
    /// let credentials = TurnCredentials::new("user", "pass");
    /// let mut config = TurnConfig::new(credentials.clone());
    /// config.set_allocation_transport(TransportType::Tcp);
    /// assert_eq!(config.allocation_transport(), TransportType::Tcp);
    /// ```
    pub fn set_allocation_transport(&mut self, allocation_transport: TransportType) {
        self.allocation_transport = allocation_transport;
    }

    /// Retrieve the allocation transport requested.
    pub fn allocation_transport(&self) -> TransportType {
        self.allocation_transport
    }

    /// Add an [`AddressFamily`] that will be requested.
    ///
    /// Duplicate [`AddressFamily`]s are ignored.
    ///
    /// # Examples
    ///
    /// ```
    /// # use turn_client_proto::api::TurnConfig;
    /// # use turn_types::{AddressFamily, TurnCredentials};
    /// let credentials = TurnCredentials::new("user", "pass");
    /// let mut config = TurnConfig::new(credentials.clone());
    /// assert_eq!(config.address_families(), &[AddressFamily::IPV4]);
    /// // Duplicate AddressFamily is ignored.
    /// config.add_address_family(AddressFamily::IPV4);
    /// assert_eq!(config.address_families(), &[AddressFamily::IPV4]);
    /// config.add_address_family(AddressFamily::IPV6);
    /// assert_eq!(config.address_families(), &[AddressFamily::IPV4, AddressFamily::IPV6]);
    /// ```
    pub fn add_address_family(&mut self, family: AddressFamily) {
        if !self.address_families.contains(&family) {
            self.address_families.push(family);
        }
    }

    /// Set the [`AddressFamily`] that will be requested.
    ///
    /// # Examples
    ///
    /// ```
    /// # use turn_client_proto::api::TurnConfig;
    /// # use turn_types::{AddressFamily, TurnCredentials};
    /// let credentials = TurnCredentials::new("user", "pass");
    /// let mut config = TurnConfig::new(credentials.clone());
    /// assert_eq!(config.address_families(), &[AddressFamily::IPV4]);
    /// config.set_address_family(AddressFamily::IPV4);
    /// assert_eq!(config.address_families(), &[AddressFamily::IPV4]);
    /// config.set_address_family(AddressFamily::IPV6);
    /// assert_eq!(config.address_families(), &[AddressFamily::IPV6]);
    /// ```
    pub fn set_address_family(&mut self, family: AddressFamily) {
        self.address_families = smallvec::smallvec![family];
    }

    /// Retrieve the [`AddressFamily`]s that are requested.
    pub fn address_families(&self) -> &[AddressFamily] {
        &self.address_families
    }

    /// Retrieve the [`TurnCredentials`] used for authenticating with the TURN server.
    pub fn credentials(&self) -> &TurnCredentials {
        &self.credentials
    }

    /// Add a supported integrity algorithm that could be used.
    pub fn add_supported_integrity(&mut self, integrity: IntegrityAlgorithm) {
        if !self.supported_integrity.contains(&integrity) {
            self.supported_integrity.push(integrity);
        }
    }

    /// Set the supported integrity algorithm used.
    pub fn set_supported_integrity(&mut self, integrity: IntegrityAlgorithm) {
        self.supported_integrity = smallvec::smallvec![integrity];
    }

    /// The supported integrity algorithms used.
    pub fn supported_integrity(&self) -> &[IntegrityAlgorithm] {
        &self.supported_integrity
    }

    /// Set whether anonymous username usage is required.
    ///
    /// A value of `Required` requires the server to support RFC 8489 and the
    /// [`Userhash`](stun_proto::types::attribute::Userhash) attribute.
    pub fn set_anonymous_username(&mut self, anon: Feature) {
        self.anonymous_username = anon;
    }

    /// Whether anonymous username usage is required.
    ///
    /// A value of `Required` requires the server to support RFC 8489 and the
    /// [`Userhash`](stun_proto::types::attribute::Userhash) attribute.
    pub fn anonymous_username(&self) -> Feature {
        self.anonymous_username
    }
}

/// Return value from calling [poll](TurnClientApi::poll)().
#[derive(Debug)]
pub enum TurnPollRet {
    /// The caller should wait until the provided time. Other events may cause this value to
    /// modified and poll() should be rechecked.
    WaitUntil(Instant),
    /// The caller should initiate a connection using the provided remote address based on the
    /// provided local address.
    AllocateTcpSocket {
        /// The server-unique identifier for this connection.
        id: u32,
        /// The client-server network 5-tuple.
        socket: Socket5Tuple,
        /// The address of the peer to connect to.
        peer_addr: SocketAddr,
    },
    /// The client has completed closing a TCP connection between the TURN client and a peer.
    ///
    /// The connection can be in progress of being setup.
    TcpClose {
        /// The socket address local to the TURN client.
        local_addr: SocketAddr,
        /// The address of the remote peer.
        remote_addr: SocketAddr,
    },
    /// The connection is closed and no further progress will be made.
    Closed,
}

/// A socket with the specified network 5-tuple.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Socket5Tuple {
    /// The transport for the socket.
    pub transport: TransportType,
    /// The local address for the socket.
    pub from: SocketAddr,
    /// The remote address for the socket.
    pub to: SocketAddr,
}

/// Return value from call [recv](TurnClientApi::recv).
#[derive(Debug)]
pub enum TurnRecvRet<T: AsRef<[u8]> + core::fmt::Debug> {
    /// The data has been handled internally and should not be forwarded any further.
    Handled,
    /// The data is not directed at this [`TurnClientApi`].
    Ignored(Transmit<T>),
    /// Data has been received from a peer of the TURN server.
    PeerData(TurnPeerData<T>),
    /// An ICMP packet has been received from a peer of the TURN server.
    PeerIcmp {
        /// The [`TransportType`] of the peer address.
        transport: TransportType,
        /// The network address of the peer that produced the ICMP data.
        peer: SocketAddr,
        /// The type of ICMP data.
        icmp_type: u8,
        /// The ICMP code.
        icmp_code: u8,
        /// The ICMP data.
        icmp_data: u32,
    },
}

/// Data that has been received from the TURN server.
#[derive(Debug)]
pub struct TurnPeerData<T: AsRef<[u8]> + core::fmt::Debug> {
    /// The data received.
    pub(crate) data: DataRangeOrOwned<T>,
    /// The transport the data was received over.
    pub transport: TransportType,
    /// The address of the peer that sent the data.
    pub peer: SocketAddr,
}

impl<T: AsRef<[u8]> + core::fmt::Debug> TurnPeerData<T> {
    /// Produce an owned variant of [`TurnPeerData`], copying only if necessary.
    pub fn into_owned<R: AsRef<[u8]> + core::fmt::Debug>(self) -> TurnPeerData<R> {
        TurnPeerData {
            data: self.data.into_owned(),
            transport: self.transport,
            peer: self.peer,
        }
    }
}

impl<T: AsRef<[u8]> + core::fmt::Debug> TurnPeerData<T> {
    /// The data slice of this [`TurnPeerData`]
    pub fn data(&self) -> &[u8] {
        self.data.as_ref()
    }
}

impl<T: AsRef<[u8]> + core::fmt::Debug> AsRef<[u8]> for TurnPeerData<T> {
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
    /// Allocation failed to be created for the specified address family.
    AllocationCreateFailed(AddressFamily),
    /// A permission was created for the provided transport and IP address.
    PermissionCreated(TransportType, IpAddr),
    /// A permission could not be installed for the provided transport and IP address.
    PermissionCreateFailed(TransportType, IpAddr),
    /// A channel was created for the provided transport and IP address.
    ChannelCreated(TransportType, SocketAddr),
    /// A channel could not be installed for the provided transport and IP address.
    ChannelCreateFailed(TransportType, SocketAddr),
    /// A TCP connection was created for the provided peer IP address.
    TcpConnected(SocketAddr),
    /// A TCP connection could not be installed for the provided peer IP address.
    TcpConnectFailed(SocketAddr),
}

/// Errors produced when attempting to bind a channel.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BindChannelError {
    /// The channel identifier already exists and cannot be recreated.
    #[error("The channel identifier already exists and cannot be recreated.")]
    AlreadyExists,
    /// The channel for requested peer address has expired and cannot be recreated yet.
    #[error("The channel for requested peer address has expired and cannot be recreated until {}.", .0)]
    ExpiredChannelExists(Instant),
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

/// Errors produced when attempting to send data to a peer.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SendError {
    /// There is no connection to the TURN server.
    #[error("There is no connection to the TURN server")]
    NoAllocation,
    /// There is no permission installed for the requested peer.
    #[error("There is no permission installed for the requested peer")]
    NoPermission,
    /// There is no local TCP socket for the requested peer.
    #[error("There is no local TCP socket for the requested peer")]
    NoTcpSocket,
}

/// Errors produced when attempting to connect to a peer over TCP.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TcpConnectError {
    /// The TCP connection already exists and cannot be recreated.
    #[error("The TCP connection already exists and cannot be recreated.")]
    AlreadyExists,
    /// There is no connection to the TURN server that can handle this TCP socket.
    #[error("There is no connection to the TURN server that can handle this TCP socket.")]
    NoAllocation,
    /// There is no permission installed for the requested peer.
    #[error("There is no permission installed for the requested peer")]
    NoPermission,
}

/// Errors produced when attempting to connect to a peer over TCP.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TcpAllocateError {
    /// The TCP connection already exists and cannot be recreated.
    #[error("The TCP connection already exists and cannot be recreated.")]
    AlreadyExists,
    /// There is no connection to the TURN server that can handle this TCP socket.
    #[error("There is no connection to the TURN server that can handle this TCP socket.")]
    NoAllocation,
}

/// A slice range or an owned piece of data.
#[derive(Debug)]
pub enum DataRangeOrOwned<T: AsRef<[u8]> + core::fmt::Debug> {
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

impl<T: AsRef<[u8]> + core::fmt::Debug> AsRef<[u8]> for DataRangeOrOwned<T> {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Range { data, range } => &data.as_ref()[range.start..range.end],
            Self::Owned(owned) => owned,
        }
    }
}

impl<T: AsRef<[u8]> + core::fmt::Debug> DataRangeOrOwned<T> {
    pub(crate) fn into_owned<R: AsRef<[u8]> + core::fmt::Debug>(self) -> DataRangeOrOwned<R> {
        DataRangeOrOwned::Owned(match self {
            Self::Range { data: _, range: _ } => self.as_ref().to_vec(),
            Self::Owned(owned) => owned,
        })
    }
}

/// A `Transmit` where the data is some subset of the provided data.
#[derive(Debug)]
pub struct DelayedTransmit<T: AsRef<[u8]> + core::fmt::Debug> {
    data: T,
    range: Range<usize>,
}

impl<T: AsRef<[u8]> + core::fmt::Debug> DelayedTransmit<T> {
    fn data(&self) -> &[u8] {
        &self.data.as_ref()[self.range.clone()]
    }
}

impl<T: AsRef<[u8]> + core::fmt::Debug> DelayedTransmitBuild for DelayedTransmit<T> {
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

/// A delayed `Transmit` that will produce data for a TURN server.
#[derive(Debug)]
pub enum DelayedMessageOrChannelSend<T: AsRef<[u8]> + core::fmt::Debug> {
    /// A [`DelayedChannel`].
    Channel(DelayedChannel<T>),
    /// A [`DelayedMessage`].
    Message(DelayedMessage<T>),
    /// Passthrough of a piece of data.
    Data(T),
    /// An already constructed piece of data.
    OwnedData(Vec<u8>),
}

impl<T: AsRef<[u8]> + core::fmt::Debug> DelayedMessageOrChannelSend<T> {
    pub(crate) fn new_channel(data: T, channel_id: u16) -> Self {
        Self::Channel(DelayedChannel::new(channel_id, data))
    }

    pub(crate) fn new_message(data: T, peer_addr: SocketAddr) -> Self {
        Self::Message(DelayedMessage::for_server(peer_addr, data))
    }
}

impl<T: AsRef<[u8]> + core::fmt::Debug> DelayedTransmitBuild for DelayedMessageOrChannelSend<T> {
    fn len(&self) -> usize {
        match self {
            Self::Channel(channel) => channel.len(),
            Self::Message(msg) => msg.len(),
            Self::Data(data) => data.as_ref().len(),
            Self::OwnedData(owned) => owned.len(),
        }
    }

    fn build(self) -> Vec<u8> {
        match self {
            Self::Channel(channel) => channel.build(),
            Self::Message(msg) => msg.build(),
            Self::Data(data) => data.as_ref().to_vec(),
            Self::OwnedData(owned) => owned,
        }
    }

    fn write_into(self, data: &mut [u8]) -> usize {
        match self {
            Self::Channel(channel) => channel.write_into(data),
            Self::Message(msg) => msg.write_into(data),
            Self::Data(slice) => {
                data.copy_from_slice(slice.as_ref());
                slice.as_ref().len()
            }
            Self::OwnedData(owned) => {
                data.copy_from_slice(&owned);
                owned.len()
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use alloc::vec;

    use super::*;
    use turn_types::stun::message::Message;
    use turn_types::{
        attribute::{Data as AData, XorPeerAddress},
        channel::ChannelData,
    };

    pub(crate) fn generate_addresses() -> (SocketAddr, SocketAddr) {
        (
            "192.168.0.1:1000".parse().unwrap(),
            "10.0.0.2:2000".parse().unwrap(),
        )
    }

    #[test]
    fn test_delayed_message() {
        let (local_addr, remote_addr) = generate_addresses();
        let data = [5; 5];
        let peer_addr = "127.0.0.1:1".parse().unwrap();
        let transmit = TransmitBuild::new(
            DelayedMessageOrChannelSend::Message(DelayedMessage::for_server(peer_addr, data)),
            TransportType::Udp,
            local_addr,
            remote_addr,
        );
        assert!(!transmit.data.is_empty());
        let len = transmit.data.len();
        let out = transmit.build();
        assert_eq!(len, out.data.len());
        let msg = Message::from_bytes(&out.data).unwrap();
        let addr = msg.attribute::<XorPeerAddress>().unwrap();
        assert_eq!(addr.addr(msg.transaction_id()), peer_addr);
        let out_data = msg.attribute::<AData>().unwrap();
        assert_eq!(out_data.data(), data.as_ref());
        let transmit = TransmitBuild::new(
            DelayedMessageOrChannelSend::Message(DelayedMessage::for_server(peer_addr, data)),
            TransportType::Udp,
            local_addr,
            remote_addr,
        );
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
        let (local_addr, remote_addr) = generate_addresses();
        let data = [5; 5];
        let channel_id = 0x4567;
        let transmit = TransmitBuild::new(
            DelayedMessageOrChannelSend::Channel(DelayedChannel::new(channel_id, data)),
            TransportType::Udp,
            local_addr,
            remote_addr,
        );
        assert!(!transmit.data.is_empty());
        let len = transmit.data.len();
        let out = transmit.build();
        assert_eq!(len, out.data.len());
        let channel = ChannelData::parse(&out.data).unwrap();
        assert_eq!(channel.id(), channel_id);
        assert_eq!(channel.data(), data.as_ref());
        let transmit = TransmitBuild::new(
            DelayedMessageOrChannelSend::Channel(DelayedChannel::new(channel_id, data)),
            TransportType::Udp,
            local_addr,
            remote_addr,
        );
        let mut out2 = vec![0; len];
        transmit.write_into(&mut out2);
        assert_eq!(len, out2.len());
        let channel = ChannelData::parse(&out2).unwrap();
        assert_eq!(channel.id(), channel_id);
        assert_eq!(channel.data(), data.as_ref());
    }

    #[test]
    fn test_delayed_owned() {
        let (local_addr, remote_addr) = generate_addresses();
        let data = vec![7; 7];
        let transmit = TransmitBuild::new(
            DelayedMessageOrChannelSend::<Vec<u8>>::Data(data.clone()),
            TransportType::Udp,
            local_addr,
            remote_addr,
        );
        assert!(!transmit.data.is_empty());
        let len = transmit.data.len();
        let out = transmit.build();
        assert_eq!(len, out.data.len());
        assert_eq!(data, out.data);
        let transmit = TransmitBuild::new(
            DelayedMessageOrChannelSend::<Vec<u8>>::Data(data.clone()),
            TransportType::Udp,
            local_addr,
            remote_addr,
        );
        let mut out2 = vec![0; len];
        transmit.write_into(&mut out2);
        assert_eq!(len, out2.len());
        assert_eq!(data, out2);
    }
}
