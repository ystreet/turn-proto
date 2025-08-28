// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! API for TURN servers.

use sans_io_time::Instant;
use std::{net::SocketAddr, time::Duration};

use stun_proto::agent::Transmit;
use turn_types::{
    stun::{attribute::ErrorCode, TransportType},
    AddressFamily,
};

/// API for TURN servers.
pub trait TurnServerApi: Send + std::fmt::Debug {
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
    fn recv<T: AsRef<[u8]>>(
        &mut self,
        transmit: Transmit<T>,
        now: Instant,
    ) -> Option<Transmit<Vec<u8>>>;
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
