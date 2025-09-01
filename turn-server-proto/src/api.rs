// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! API for TURN servers.

use alloc::string::String;
use alloc::vec::Vec;
use core::{net::SocketAddr, time::Duration};

use stun_proto::agent::Transmit;
use stun_proto::Instant;
use turn_types::prelude::DelayedTransmitBuild;
use turn_types::stun::{attribute::ErrorCode, TransportType};
use turn_types::transmit::{DelayedChannel, DelayedMessage, TransmitBuild};
use turn_types::AddressFamily;

/// API for TURN servers.
pub trait TurnServerApi: Send + core::fmt::Debug {
    /// Add a user credentials that would be accepted by this [`TurnServerApi`].
    fn add_user(&mut self, username: String, password: String);
    /// The address that the [`TurnServerApi`] is listening on for incoming client connections.
    fn listen_address(&self) -> SocketAddr;
    /// Set the amount of time that a Nonce (used for authentication) will expire and a new Nonce
    /// will need to be acquired by a client.
    fn set_nonce_expiry_duration(&mut self, expiry_duration: Duration);
    /// Provide received data to the [`TurnServerApi`].
    ///
    /// Any returned Transmit should be forwarded to the appropriate socket.
    fn recv<T: AsRef<[u8]> + core::fmt::Debug>(
        &mut self,
        transmit: Transmit<T>,
        now: Instant,
    ) -> Option<TransmitBuild<DelayedMessageOrChannelSend<T>>>;
    /// Provide a received ICMP packet to the [`TurnServerApi`].
    ///
    /// Any returned Transmit should be forwarded to the appropriate socket.
    fn recv_icmp<T: AsRef<[u8]>>(
        &mut self,
        family: AddressFamily,
        bytes: T,
        now: Instant,
    ) -> Option<Transmit<Vec<u8>>>;
    /// Poll the [`TurnServerApi`] in order to make further progress.
    ///
    /// The returned value indicates what the caller should do.
    fn poll(&mut self, now: Instant) -> TurnServerPollRet;
    /// Poll for a new Transmit to send over a socket.
    fn poll_transmit(&mut self, now: Instant) -> Option<Transmit<Vec<u8>>>;
    /// Notify the [`TurnServerApi`] that a UDP socket has been allocated (or an error) in response to
    /// [TurnServerPollRet::AllocateSocketUdp].
    fn allocated_udp_socket(
        &mut self,
        transport: TransportType,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        family: AddressFamily,
        socket_addr: Result<SocketAddr, SocketAllocateError>,
        now: Instant,
    );
}

/// Return value for [poll](TurnServerApi::poll).
#[derive(Debug)]
pub enum TurnServerPollRet {
    /// Wait until the specified time before calling poll() again.
    WaitUntil(Instant),
    /// Allocate a UDP socket for a client specified by the client's network 5-tuple.
    AllocateSocketUdp {
        /// The transport of the client asking for an allocation.
        transport: TransportType,
        /// The TURN server address of the client asking for an allocation.
        local_addr: SocketAddr,
        /// The client local address of the client asking for an allocation.
        remote_addr: SocketAddr,
        /// The address family of the request for an allocation.
        family: AddressFamily,
    },
}

/// Errors that can be conveyed when allocating a socket for a client.
#[derive(Debug, Clone, Copy, thiserror::Error, PartialEq, Eq)]
pub enum SocketAllocateError {
    /// The requested Address family is not supported.
    #[error("The address family is not supported.")]
    AddressFamilyNotSupported,
    /// The server does not have the capacity to handle this request.
    #[error("The server does not have the capacity to handle this request.")]
    InsufficientCapacity,
}

impl SocketAllocateError {
    /// Convert this error into an error code for the `ErrorCode` or `AddressErrorCode` attributes.
    pub fn into_error_code(self) -> u16 {
        match self {
            Self::AddressFamilyNotSupported => ErrorCode::ADDRESS_FAMILY_NOT_SUPPORTED,
            Self::InsufficientCapacity => ErrorCode::INSUFFICIENT_CAPACITY,
        }
    }
}

/// Transmission data that needs to be constructed before transmit.
#[derive(Debug)]
pub enum DelayedMessageOrChannelSend<T: AsRef<[u8]> + core::fmt::Debug> {
    /// A STUN Message.
    Message(DelayedMessage<T>),
    /// A Turn Channel Data.
    Channel(DelayedChannel<T>),
    /// An already constructed piece of data.
    Owned(Vec<u8>),
    /// A subset of the incoming data.
    Range(T, core::ops::Range<usize>),
}

impl<T: AsRef<[u8]> + core::fmt::Debug> DelayedTransmitBuild for DelayedMessageOrChannelSend<T> {
    fn len(&self) -> usize {
        match self {
            Self::Message(msg) => msg.len(),
            Self::Channel(channel) => channel.len(),
            Self::Owned(v) => v.len(),
            Self::Range(_data, range) => range.end - range.start,
        }
    }

    fn build(self) -> Vec<u8> {
        match self {
            Self::Message(msg) => msg.build(),
            Self::Channel(channel) => channel.build(),
            Self::Owned(v) => v,
            Self::Range(data, range) => data.as_ref()[range.start..range.end].to_vec(),
        }
    }
    fn is_empty(&self) -> bool {
        match self {
            Self::Message(msg) => msg.is_empty(),
            Self::Channel(channel) => channel.is_empty(),
            Self::Owned(v) => v.is_empty(),
            Self::Range(_data, range) => range.end == range.start,
        }
    }
    fn write_into(self, data: &mut [u8]) -> usize {
        match self {
            Self::Message(msg) => msg.write_into(data),
            Self::Channel(channel) => channel.write_into(data),
            Self::Owned(v) => v.write_into(data),
            Self::Range(src, range) => {
                data.copy_from_slice(&src.as_ref()[range.start..range.end]);
                range.end - range.start
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use turn_types::attribute::Data as AData;
    use turn_types::attribute::XorPeerAddress;
    use turn_types::channel::ChannelData;
    use turn_types::stun::message::Message;

    use super::*;

    fn generate_addresses() -> (SocketAddr, SocketAddr) {
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
            DelayedMessageOrChannelSend::<Vec<u8>>::Owned(data.clone()),
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
            DelayedMessageOrChannelSend::<Vec<u8>>::Owned(data.clone()),
            TransportType::Udp,
            local_addr,
            remote_addr,
        );
        let mut out2 = vec![0; len];
        transmit.write_into(&mut out2);
        assert_eq!(len, out2.len());
        assert_eq!(data, out2);
    }

    #[test]
    fn test_delayed_range() {
        let (local_addr, remote_addr) = generate_addresses();
        let data = vec![7; 7];
        let range = 2..6;
        const LEN: usize = 4;
        let transmit = TransmitBuild::new(
            DelayedMessageOrChannelSend::Range(data.clone(), range.clone()),
            TransportType::Udp,
            local_addr,
            remote_addr,
        );
        let len = transmit.data.len();
        assert_eq!(len, LEN);
        let out = transmit.build();
        assert_eq!(len, out.data.len());
        assert_eq!(data[range.start..range.end], out.data);
        let transmit = TransmitBuild::new(
            DelayedMessageOrChannelSend::Range(data.clone(), range.clone()),
            TransportType::Udp,
            local_addr,
            remote_addr,
        );
        let mut out2 = vec![0; len];
        transmit.write_into(&mut out2);
        assert_eq!(len, out2.len());
        assert_eq!(data[range.start..range.end], out2);
    }
}
