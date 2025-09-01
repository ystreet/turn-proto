// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! TURN Client.
//!
//! A cohesive TURN client that can be one of the transport specific (UDP, TCP, TLS) implementations.

use alloc::vec::Vec;
use core::net::{IpAddr, SocketAddr};

use stun_proto::agent::Transmit;
use stun_proto::Instant;
use turn_types::stun::{data::Data, TransportType};

pub use crate::api::{
    BindChannelError, CreatePermissionError, DeleteError, SendError, TurnEvent, TurnPollRet,
    TurnRecvRet,
};
use crate::api::{DelayedMessageOrChannelSend, TransmitBuild, TurnClientApi, TurnPeerData};
#[cfg(feature = "rustls")]
use crate::rustls::TurnClientTls;
use crate::tcp::TurnClientTcp;
use crate::udp::TurnClientUdp;

/// A TURN client.
#[derive(Debug)]
pub enum TurnClient {
    /// A UDP TURN client.
    Udp(TurnClientUdp),
    /// A TCP TURN client.
    Tcp(TurnClientTcp),
    #[cfg(feature = "rustls")]
    /// A TLS TURN client.
    Tls(TurnClientTls),
}

impl TurnClientApi for TurnClient {
    /// The transport of the connection to the TURN server.
    fn transport(&self) -> TransportType {
        match self {
            Self::Udp(udp) => udp.transport(),
            Self::Tcp(tcp) => tcp.transport(),
            #[cfg(feature = "rustls")]
            Self::Tls(tcp) => tcp.transport(),
        }
    }

    /// The local address of this TURN client.
    fn local_addr(&self) -> SocketAddr {
        match self {
            Self::Udp(udp) => udp.local_addr(),
            Self::Tcp(tcp) => tcp.local_addr(),
            #[cfg(feature = "rustls")]
            Self::Tls(tcp) => tcp.local_addr(),
        }
    }

    /// The remote TURN server's address.
    fn remote_addr(&self) -> SocketAddr {
        match self {
            Self::Udp(udp) => udp.remote_addr(),
            Self::Tcp(tcp) => tcp.remote_addr(),
            #[cfg(feature = "rustls")]
            Self::Tls(tcp) => tcp.remote_addr(),
        }
    }

    /// The list of allocated relayed addresses on the TURN server.
    fn relayed_addresses(&self) -> impl Iterator<Item = (TransportType, SocketAddr)> + '_ {
        match self {
            Self::Udp(udp) => RelayedAddressesIter::Udp(udp.relayed_addresses()),
            Self::Tcp(tcp) => RelayedAddressesIter::Tcp(tcp.relayed_addresses()),
            #[cfg(feature = "rustls")]
            Self::Tls(tcp) => RelayedAddressesIter::Tls(tcp.relayed_addresses()),
        }
    }

    /// The list of permissions available for the provided relayed address.
    fn permissions(
        &self,
        transport: TransportType,
        relayed: SocketAddr,
    ) -> impl Iterator<Item = IpAddr> + '_ {
        match self {
            Self::Udp(udp) => PermissionAddressesIter::Udp(udp.permissions(transport, relayed)),
            Self::Tcp(tcp) => PermissionAddressesIter::Tcp(tcp.permissions(transport, relayed)),
            #[cfg(feature = "rustls")]
            Self::Tls(tcp) => PermissionAddressesIter::Tls(tcp.permissions(transport, relayed)),
        }
    }

    /// Remove the allocation/s on the server.
    fn delete(&mut self, now: Instant) -> Result<(), DeleteError> {
        match self {
            Self::Udp(udp) => udp.delete(now),
            Self::Tcp(tcp) => tcp.delete(now),
            #[cfg(feature = "rustls")]
            Self::Tls(tcp) => tcp.delete(now),
        }
    }

    /// Create a permission address to allow sending/receiving data to/from.
    fn create_permission(
        &mut self,
        transport: TransportType,
        peer_addr: IpAddr,
        now: Instant,
    ) -> Result<(), CreatePermissionError> {
        match self {
            Self::Udp(udp) => udp.create_permission(transport, peer_addr, now),
            Self::Tcp(tcp) => tcp.create_permission(transport, peer_addr, now),
            #[cfg(feature = "rustls")]
            Self::Tls(tcp) => tcp.create_permission(transport, peer_addr, now),
        }
    }

    /// Whether the client currently has a permission installed for the provided transport and
    /// address.
    fn have_permission(&self, transport: TransportType, to: IpAddr) -> bool {
        match self {
            Self::Udp(udp) => udp.have_permission(transport, to),
            Self::Tcp(tcp) => tcp.have_permission(transport, to),
            #[cfg(feature = "rustls")]
            Self::Tls(tcp) => tcp.have_permission(transport, to),
        }
    }

    /// Bind a channel for sending/receiving data to/from a particular peer.
    fn bind_channel(
        &mut self,
        transport: TransportType,
        peer_addr: SocketAddr,
        now: Instant,
    ) -> Result<(), BindChannelError> {
        match self {
            Self::Udp(udp) => udp.bind_channel(transport, peer_addr, now),
            Self::Tcp(tcp) => tcp.bind_channel(transport, peer_addr, now),
            #[cfg(feature = "rustls")]
            Self::Tls(tcp) => tcp.bind_channel(transport, peer_addr, now),
        }
    }

    /// Send data to a peer through the TURN server.
    ///
    /// The provided transport, address and data are the data to send to the peer.
    ///
    /// The returned value will instruct the caller to send a message to the turn server.
    fn send_to<T: AsRef<[u8]> + core::fmt::Debug>(
        &mut self,
        transport: TransportType,
        to: SocketAddr,
        data: T,
        now: Instant,
    ) -> Result<Option<TransmitBuild<DelayedMessageOrChannelSend<T>>>, SendError> {
        match self {
            Self::Udp(udp) => udp.send_to(transport, to, data, now),
            Self::Tcp(tcp) => tcp.send_to(transport, to, data, now),
            #[cfg(feature = "rustls")]
            Self::Tls(tcp) => tcp.send_to(transport, to, data, now),
        }
    }

    /// Provide received data to the TURN client for handling.
    ///
    /// The returned data outlines what to do with this data.
    fn recv<T: AsRef<[u8]> + core::fmt::Debug>(
        &mut self,
        transmit: Transmit<T>,
        now: Instant,
    ) -> TurnRecvRet<T> {
        match self {
            Self::Udp(udp) => udp.recv(transmit, now),
            Self::Tcp(tcp) => tcp.recv(transmit, now),
            #[cfg(feature = "rustls")]
            Self::Tls(tcp) => tcp.recv(transmit, now),
        }
    }

    /// Poll the client for any further recevied data.
    fn poll_recv(&mut self, now: Instant) -> Option<TurnPeerData<Vec<u8>>> {
        match self {
            Self::Udp(udp) => udp.poll_recv(now),
            Self::Tcp(tcp) => tcp.poll_recv(now),
            #[cfg(feature = "rustls")]
            Self::Tls(tcp) => tcp.poll_recv(now),
        }
    }

    /// Poll the client for further progress.
    fn poll(&mut self, now: Instant) -> TurnPollRet {
        match self {
            Self::Udp(udp) => udp.poll(now),
            Self::Tcp(tcp) => tcp.poll(now),
            #[cfg(feature = "rustls")]
            Self::Tls(tcp) => tcp.poll(now),
        }
    }

    /// Poll for a packet to send.
    fn poll_transmit(&mut self, now: Instant) -> Option<Transmit<Data<'static>>> {
        match self {
            Self::Udp(udp) => udp.poll_transmit(now),
            Self::Tcp(tcp) => tcp.poll_transmit(now),
            #[cfg(feature = "rustls")]
            Self::Tls(tcp) => tcp.poll_transmit(now),
        }
    }

    /// Poll for an event that has occurred.
    fn poll_event(&mut self) -> Option<TurnEvent> {
        match self {
            Self::Udp(udp) => udp.poll_event(),
            Self::Tcp(tcp) => tcp.poll_event(),
            #[cfg(feature = "rustls")]
            Self::Tls(tcp) => tcp.poll_event(),
        }
    }
}

macro_rules! impl_iterator {
    ($name:ident, $ret:ty, $($option:ident),+) => {
        enum $name<$($option: Iterator<Item = $ret>, )+> {
            $($option($option),)+
        }
        impl<$($option: Iterator<Item = $ret>,)+> Iterator for $name<$($option,)+>
        {
            type Item = $ret;

            fn next(&mut self) -> Option<Self::Item> {
                match self {
                    $(Self::$option(ref mut val) => val.next(),)+
                }
            }
        }
    }
}

#[cfg(feature = "rustls")]
impl_iterator!(
    RelayedAddressesIter,
    (TransportType, SocketAddr),
    Udp,
    Tcp,
    Tls
);
#[cfg(not(feature = "rustls"))]
impl_iterator!(RelayedAddressesIter, (TransportType, SocketAddr), Udp, Tcp);

#[cfg(feature = "rustls")]
impl_iterator!(PermissionAddressesIter, IpAddr, Udp, Tcp, Tls);
#[cfg(not(feature = "rustls"))]
impl_iterator!(PermissionAddressesIter, IpAddr, Udp, Tcp);

impl From<TurnClientUdp> for TurnClient {
    fn from(value: TurnClientUdp) -> Self {
        Self::Udp(value)
    }
}

impl From<TurnClientTcp> for TurnClient {
    fn from(value: TurnClientTcp) -> Self {
        Self::Tcp(value)
    }
}

#[cfg(feature = "rustls")]
impl From<TurnClientTls> for TurnClient {
    fn from(value: TurnClientTls) -> Self {
        Self::Tls(value)
    }
}
