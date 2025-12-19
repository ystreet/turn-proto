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
    BindChannelError, CreatePermissionError, DeleteError, SendError, TcpAllocateError, TurnEvent,
    TurnPollRet, TurnRecvRet,
};
use crate::api::{
    DelayedMessageOrChannelSend, Socket5Tuple, TcpConnectError, TransmitBuild, TurnClientApi,
    TurnPeerData,
};
#[cfg(feature = "openssl")]
use crate::openssl::TurnClientOpensslTls;
#[cfg(feature = "rustls")]
use crate::rustls::TurnClientRustls;
use crate::tcp::TurnClientTcp;
use crate::udp::TurnClientUdp;

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
        impl TurnClientApi for $name
        {
            fn transport(&self) -> TransportType {
                match self {
                    $(Self::$variant(val) => val.transport(),)+
                }
            }
            fn local_addr(&self) -> SocketAddr {
                match self {
                    $(Self::$variant(val) => val.local_addr(),)+
                }
            }
            fn remote_addr(&self) -> SocketAddr {
                match self {
                    $(Self::$variant(val) => val.remote_addr(),)+
                }
            }
            fn relayed_addresses(&self) -> impl Iterator<Item = (TransportType, SocketAddr)> + '_ {
                match self {
                    $(Self::$variant(val) => RelayedAddressesIter::$variant(val.relayed_addresses()),)+
                }
            }
            fn permissions(
                &self,
                transport: TransportType,
                relayed: SocketAddr,
            ) -> impl Iterator<Item = IpAddr> + '_ {
                match self {
                    $(Self::$variant(val) => PermissionAddressesIter::$variant(val.permissions(transport, relayed)),)+
                }
            }
            fn delete(&mut self, now: Instant) -> Result<(), DeleteError> {
                match self {
                    $(Self::$variant(val) => val.delete(now),)+
                }
            }
            fn create_permission(
                &mut self,
                transport: TransportType,
                peer_addr: IpAddr,
                now: Instant,
            ) -> Result<(), CreatePermissionError> {
                match self {
                    $(Self::$variant(val) => val.create_permission(transport, peer_addr, now),)+
                }
            }
            fn have_permission(&self, transport: TransportType, to: IpAddr) -> bool {
                match self {
                    $(Self::$variant(val) => val.have_permission(transport, to),)+
                }
            }
            fn bind_channel(
                &mut self,
                transport: TransportType,
                peer_addr: SocketAddr,
                now: Instant,
            ) -> Result<(), BindChannelError> {
                match self {
                    $(Self::$variant(val) => val.bind_channel(transport, peer_addr, now),)+
                }
            }
            fn tcp_connect(&mut self, peer_addr: SocketAddr, now: Instant) -> Result<(), TcpConnectError> {
                match self {
                    $(Self::$variant(val) => val.tcp_connect(peer_addr, now),)+
                }
            }
            fn allocated_tcp_socket(
                &mut self,
                id: u32,
                five_tuple: Socket5Tuple,
                peer_addr: SocketAddr,
                local_addr: Option<SocketAddr>,
                now: Instant,
            ) -> Result<(), TcpAllocateError> {
                match self {
                    $(Self::$variant(val) => val.allocated_tcp_socket(id, five_tuple, peer_addr, local_addr, now),)+
                }
            }
            fn tcp_closed(
                &mut self,
                local_addr: SocketAddr,
                remote_addr: SocketAddr,
                now: Instant,
            ) {
                match self {
                    $(Self::$variant(val) => val.tcp_closed(local_addr, remote_addr, now),)+
                }
            }
            fn send_to<T: AsRef<[u8]> + core::fmt::Debug>(
                &mut self,
                transport: TransportType,
                to: SocketAddr,
                data: T,
                now: Instant,
            ) -> Result<Option<TransmitBuild<DelayedMessageOrChannelSend<T>>>, SendError> {
                match self {
                    $(Self::$variant(val) => val.send_to(transport, to, data, now),)+
                }
            }
            fn recv<T: AsRef<[u8]> + core::fmt::Debug>(
                &mut self,
                transmit: Transmit<T>,
                now: Instant,
            ) -> TurnRecvRet<T> {
                match self {
                    $(Self::$variant(val) => val.recv(transmit, now),)+
                }
            }
            fn poll_recv(&mut self, now: Instant) -> Option<TurnPeerData<Vec<u8>>> {
                match self {
                    $(Self::$variant(val) => val.poll_recv(now),)+
                }
            }
            fn poll(&mut self, now: Instant) -> TurnPollRet {
                match self {
                    $(Self::$variant(val) => val.poll(now),)+
                }
            }
            fn poll_transmit(&mut self, now: Instant) -> Option<Transmit<Data<'static>>> {
                match self {
                    $(Self::$variant(val) => val.poll_transmit(now),)+
                }
            }
            fn poll_event(&mut self) -> Option<TurnEvent> {
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
        enum RelayedAddressesIter<$($variant: Iterator<Item = (TransportType, SocketAddr)>, )+> {
            $($variant($variant),)+
        }
        impl<$($variant: Iterator<Item = (TransportType, SocketAddr)>,)+> Iterator for RelayedAddressesIter<$($variant,)+> {
            type Item = (TransportType, SocketAddr);
            fn next(&mut self) -> Option<Self::Item> {
                match self {
                    $(Self::$variant(ref mut val) => val.next(),)+
                }
            }
        }
        enum PermissionAddressesIter<$($variant: Iterator<Item = IpAddr>, )+> {
            $($variant($variant),)+
        }
        impl<$($variant: Iterator<Item = IpAddr>,)+> Iterator for PermissionAddressesIter<$($variant,)+> {
            type Item = IpAddr;
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
pub(crate) use impl_client;

#[cfg(all(feature = "rustls", feature = "openssl"))]
impl_client!(pub TurnClient, (Udp, TurnClientUdp), (Tcp, TurnClientTcp), (Rustls, TurnClientRustls), (Openssl, TurnClientOpensslTls));
#[cfg(all(feature = "rustls", not(feature = "openssl")))]
impl_client!(pub TurnClient, (Udp, TurnClientUdp), (Tcp, TurnClientTcp), (Rustls, TurnClientRustls));
#[cfg(all(not(feature = "rustls"), feature = "openssl"))]
impl_client!(pub TurnClient, (Udp, TurnClientUdp), (Tcp, TurnClientTcp), (Openssl, TurnClientOpensslTls));
#[cfg(all(not(feature = "rustls"), not(feature = "openssl")))]
impl_client!(pub TurnClient, (Udp, TurnClientUdp), (Tcp, TurnClientTcp));
