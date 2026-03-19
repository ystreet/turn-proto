// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! TURN Client.
//!
//! A cohesive TURN client that can be one of the transport specific (UDP, TCP, TLS) implementations.

use alloc::vec::Vec;

pub use crate::api::{
    BindChannelError, CreatePermissionError, DeleteError, SendError, TcpAllocateError, TurnEvent,
    TurnPollRet, TurnRecvRet,
};
use crate::tcp::TurnClientTcp;
use crate::udp::TurnClientUdp;

/// Implement an enum over a list of TURN client implementations.
///
/// All discriminants must implement `TurnClientApi`.
///
/// # Example
///
/// ```
/// # use turn_client_proto::udp::TurnClientUdp;
/// # use turn_client_proto::tcp::TurnClientTcp;
/// turn_client_proto::impl_client!(pub TurnClient, (Udp, TurnClientUdp), (Tcp, TurnClientTcp));
/// ```
///
/// Roughly translates to:
///
/// ```
/// # use turn_client_proto::udp::TurnClientUdp;
/// # use turn_client_proto::tcp::TurnClientTcp;
/// pub enum TurnClient {
///    Udp(TurnClientUdp),
///    Tcp(TurnClientTcp),
/// }
///
/// // impl TurnClientApi for TurnClient {
/// //    ...
/// // }
/// ```
#[macro_export]
macro_rules! impl_client {
    ($vis:vis $name:ident, $(($variant:ident, $ty:ty)),+) => {
        /// A TURN client.
        #[derive(Debug)]
        $vis enum $name {
            $(
                #[doc = "A "]
                #[doc = stringify!($ty)]
                #[doc = " TURN client."]
                $variant($ty),)+
        }
        impl $crate::api::TurnClientApi for $name
        {
            fn transport(&self) -> $crate::types::TransportType {
                match self {
                    $(Self::$variant(val) => val.transport(),)+
                }
            }
            fn local_addr(&self) -> core::net::SocketAddr {
                match self {
                    $(Self::$variant(val) => val.local_addr(),)+
                }
            }
            fn remote_addr(&self) -> core::net::SocketAddr {
                match self {
                    $(Self::$variant(val) => val.remote_addr(),)+
                }
            }
            fn relayed_addresses(&self) -> impl Iterator<Item = ($crate::types::TransportType, core::net::SocketAddr)> + '_ {
                match self {
                    $(Self::$variant(val) => RelayedAddressesIter::$variant(val.relayed_addresses()),)+
                }
            }
            fn permissions(
                &self,
                transport: $crate::types::TransportType,
                relayed: core::net::SocketAddr,
            ) -> impl Iterator<Item = core::net::IpAddr> + '_ {
                match self {
                    $(Self::$variant(val) => PermissionAddressesIter::$variant(val.permissions(transport, relayed)),)+
                }
            }
            fn delete(&mut self, now: $crate::types::Instant) -> Result<(), $crate::api::DeleteError> {
                match self {
                    $(Self::$variant(val) => val.delete(now),)+
                }
            }
            fn create_permission(
                &mut self,
                transport: $crate::types::TransportType,
                peer_addr: core::net::IpAddr,
                now: $crate::types::Instant,
            ) -> Result<(), $crate::api::CreatePermissionError> {
                match self {
                    $(Self::$variant(val) => val.create_permission(transport, peer_addr, now),)+
                }
            }
            fn have_permission(&self, transport: $crate::types::TransportType, to: core::net::IpAddr) -> bool {
                match self {
                    $(Self::$variant(val) => val.have_permission(transport, to),)+
                }
            }
            fn bind_channel(
                &mut self,
                transport: $crate::types::TransportType,
                peer_addr: core::net::SocketAddr,
                now: $crate::types::Instant,
            ) -> Result<(), $crate::api::BindChannelError> {
                match self {
                    $(Self::$variant(val) => val.bind_channel(transport, peer_addr, now),)+
                }
            }
            fn tcp_connect(&mut self, peer_addr: core::net::SocketAddr, now: $crate::types::Instant) -> Result<(), $crate::api::TcpConnectError> {
                match self {
                    $(Self::$variant(val) => val.tcp_connect(peer_addr, now),)+
                }
            }
            fn allocated_tcp_socket(
                &mut self,
                id: u32,
                five_tuple: $crate::api::Socket5Tuple,
                peer_addr: core::net::SocketAddr,
                local_addr: Option<core::net::SocketAddr>,
                now: $crate::types::Instant,
            ) -> Result<(), $crate::api::TcpAllocateError> {
                match self {
                    $(Self::$variant(val) => val.allocated_tcp_socket(id, five_tuple, peer_addr, local_addr, now),)+
                }
            }
            fn tcp_closed(
                &mut self,
                local_addr: core::net::SocketAddr,
                remote_addr: core::net::SocketAddr,
                now: $crate::types::Instant,
            ) {
                match self {
                    $(Self::$variant(val) => val.tcp_closed(local_addr, remote_addr, now),)+
                }
            }
            fn send_to<T: AsRef<[u8]> + core::fmt::Debug>(
                &mut self,
                transport: $crate::types::TransportType,
                to: core::net::SocketAddr,
                data: T,
                now: $crate::types::Instant,
            ) -> Result<Option<$crate::api::TransmitBuild<$crate::api::DelayedMessageOrChannelSend<T>>>, $crate::api::SendError> {
                match self {
                    $(Self::$variant(val) => val.send_to(transport, to, data, now),)+
                }
            }
            fn recv<T: AsRef<[u8]> + core::fmt::Debug>(
                &mut self,
                transmit: $crate::api::Transmit<T>,
                now: $crate::types::Instant,
            ) -> $crate::api::TurnRecvRet<T> {
                match self {
                    $(Self::$variant(val) => val.recv(transmit, now),)+
                }
            }
            fn poll_recv(&mut self, now: $crate::types::Instant) -> Option<$crate::api::TurnPeerData<Vec<u8>>> {
                match self {
                    $(Self::$variant(val) => val.poll_recv(now),)+
                }
            }
            fn poll(&mut self, now: $crate::types::Instant) -> $crate::api::TurnPollRet {
                match self {
                    $(Self::$variant(val) => val.poll(now),)+
                }
            }
            fn poll_transmit(&mut self, now: $crate::types::Instant) -> Option<$crate::api::Transmit<$crate::types::stun::data::Data<'static>>> {
                match self {
                    $(Self::$variant(val) => val.poll_transmit(now),)+
                }
            }
            fn poll_event(&mut self) -> Option<$crate::api::TurnEvent> {
                match self {
                    $(Self::$variant(val) => val.poll_event(),)+
                }
            }
            fn protocol_error(&mut self) {
                match self {
                    $(Self::$variant(val) => val.protocol_error(),)+
                }
            }
        }
        enum RelayedAddressesIter<$($variant: Iterator<Item = ($crate::types::TransportType, core::net::SocketAddr)>, )+> {
            $($variant($variant),)+
        }
        impl<$($variant: Iterator<Item = ($crate::types::TransportType, core::net::SocketAddr)>,)+> Iterator for RelayedAddressesIter<$($variant,)+> {
            type Item = ($crate::types::TransportType, core::net::SocketAddr);
            fn next(&mut self) -> Option<Self::Item> {
                match self {
                    $(Self::$variant(ref mut val) => val.next(),)+
                }
            }
        }
        enum PermissionAddressesIter<$($variant: Iterator<Item = core::net::IpAddr>, )+> {
            $($variant($variant),)+
        }
        impl<$($variant: Iterator<Item = core::net::IpAddr>,)+> Iterator for PermissionAddressesIter<$($variant,)+> {
            type Item = core::net::IpAddr;
            fn next(&mut self) -> Option<Self::Item> {
                match self {
                    $(Self::$variant(ref mut val) => val.next(),)+
                }
            }
        }
        $(impl From<$ty> for $name {
            fn from(value: $ty) -> Self {
                Self::$variant(value)
            }
        })+
    }
}

impl_client!(pub TurnClient, (Udp, TurnClientUdp), (Tcp, TurnClientTcp));
