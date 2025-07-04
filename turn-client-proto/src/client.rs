// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};
use std::ops::Range;
use std::time::{Duration, Instant};

use byteorder::{BigEndian, ByteOrder};
use stun_proto::agent::{
    DelayedTransmitBuild, HandleStunReply, StunAgent, StunAgentPollRet, StunError, Transmit,
    TransmitBuild,
};
use stun_proto::types::attribute::{ErrorCode, Nonce, Realm, Username};
use stun_proto::types::data::Data;
use stun_proto::types::message::{
    LongTermCredentials, Message, MessageClass, MessageHeader, MessageIntegrityCredentials,
    MessageType, TransactionId,
};
use stun_proto::types::prelude::AttributeExt;
use turn_types::channel::ChannelData;

use stun_proto::types::TransportType;

use turn_types::attribute::Data as AData;
use turn_types::attribute::{
    ChannelNumber, DontFragment, Lifetime, RequestedTransport, XorPeerAddress, XorRelayedAddress,
};
use turn_types::message::*;
use turn_types::TurnCredentials;

use tracing::{error, info, trace, warn};

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

#[derive(Debug)]
struct Channel {
    id: u16,
    peer_addr: SocketAddr,
    expires_at: Instant,
    pending_refresh: Option<TransactionId>,
}

#[derive(Debug)]
struct Permission {
    expired: bool,
    expires_at: Instant,
    ip: IpAddr,
    pending_refresh: Option<TransactionId>,
}

#[derive(Debug)]
struct Allocation {
    relayed_address: SocketAddr,
    transport: TransportType,
    expired: bool,
    lifetime: Duration,
    expires_at: Instant,
    permissions: Vec<Permission>,
    channels: Vec<Channel>,

    pending_permissions: VecDeque<(Permission, TransactionId)>,
    pending_channels: VecDeque<(Channel, TransactionId)>,
    pending_refresh: Option<(TransactionId, u32)>,

    expired_channels: Vec<Channel>,
}

/// A TURN client.
#[derive(Debug)]
pub struct TurnClient {
    stun_agent: StunAgent,
    credentials: TurnCredentials,
    state: AuthState,
    allocations: Vec<Allocation>,

    tcp_buffer: Vec<u8>,
    pending_transmits: VecDeque<Transmit<Data<'static>>>,

    pending_events: VecDeque<TurnEvent>,
}

#[derive(Debug)]
enum AuthState {
    Initial,
    InitialSent(TransactionId),
    Authenticating {
        credentials: LongTermCredentials,
        nonce: String,
        transaction_id: TransactionId,
    },
    Authenticated {
        credentials: LongTermCredentials,
        nonce: String,
    },
    Error,
}

/// Return value from calling [poll](TurnClient::poll)().
#[derive(Debug)]
pub enum TurnPollRet {
    /// The caller should wait until the provided time. Other events may cause this value to
    /// modified and poll() should be rechecked.
    WaitUntil(Instant),
    /// The connection is closed and no further progress will be made.
    Closed,
}

/// Return value from call [recv](TurnClient::recv).
#[derive(Debug)]
pub enum TurnRecvRet<T: AsRef<[u8]> + std::fmt::Debug> {
    /// The data has been handled internally and should not be forwarded any further.
    Handled,
    /// The data is not directed at this [TurnClient].
    Ignored(Transmit<T>),
    /// Data has been received from a peer of the TURN server.
    // TODO: try to return existing data without a copy
    PeerData {
        /// The data received.
        data: Vec<u8>,
        /// The transport the data was received over.
        transport: TransportType,
        /// The address of the peer that sent the data.
        peer: SocketAddr,
    },
}

#[derive(Debug)]
enum InternalHandleStunReply {
    Handled,
    Ignored,
    PeerData {
        data: Vec<u8>,
        transport: TransportType,
        peer: SocketAddr,
    },
}

/// Errors produced when attempting to create a permission for a peer address.
#[derive(Debug, thiserror::Error)]
pub enum CreatePermissionError {
    /// The permission already exists and cannot be recreated.
    #[error("The permission already exists and cannot be recreated.")]
    AlreadyExists,
    /// There is no connection to the TURN server that can handle this permission.
    #[error("There is no connection to the TURN server that can handle this permission")]
    NoAllocation,
}

/// Errors produced when attempting to bind a channel.
#[derive(Debug, thiserror::Error)]
pub enum BindChannelError {
    /// The channel identifier already exists and cannot be recreated.
    #[error("The channel identifier already exists and cannot be recreated.")]
    AlreadyExists,
    /// There is no connection to the TURN server that can handle this channel.
    #[error("There is no connection to the TURN server that can handle this channel.")]
    NoAllocation,
}

impl TurnClient {
    /// Allocate an address on a TURN server to relay data to and from peers.
    ///
    /// # Examples
    /// ```
    /// # use turn_types::TurnCredentials;
    /// # use turn_client_proto::TurnClient;
    /// # use stun_proto::types::TransportType;
    /// let credentials = TurnCredentials::new("tuser", "tpass");
    /// let transport = TransportType::Udp;
    /// let local_addr = "192.168.0.1:4000".parse().unwrap();
    /// let remote_addr = "10.0.0.1:3478".parse().unwrap();
    /// let client = TurnClient::allocate(transport, local_addr, remote_addr, credentials);
    /// assert_eq!(client.transport(), transport);
    /// assert_eq!(client.local_addr(), local_addr);
    /// assert_eq!(client.remote_addr(), remote_addr);
    /// ```
    #[tracing::instrument(
        name = "turn_client_allocate"
        skip(credentials)
    )]
    pub fn allocate(
        ttype: TransportType,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        credentials: TurnCredentials,
    ) -> Self {
        turn_types::debug_init();
        let stun_agent = StunAgent::builder(ttype, local_addr)
            .remote_addr(remote_addr)
            .build();

        Self {
            stun_agent,
            credentials,
            state: AuthState::Initial,
            allocations: vec![],
            pending_transmits: VecDeque::default(),
            tcp_buffer: vec![],
            pending_events: VecDeque::default(),
        }
    }

    /// The transport of the connection to the TURN server.
    pub fn transport(&self) -> TransportType {
        self.stun_agent.transport()
    }

    /// The local address of this TURN client.
    pub fn local_addr(&self) -> SocketAddr {
        self.stun_agent.local_addr()
    }

    /// The remote TURN server's address.
    pub fn remote_addr(&self) -> SocketAddr {
        self.stun_agent.remote_addr().unwrap()
    }

    /// Poll the client for further progress.
    #[tracing::instrument(name = "turn_client_poll", ret, skip(self))]
    pub fn poll(&mut self, now: Instant) -> TurnPollRet {
        trace!("polling at {now:?}");
        if !self.pending_events.is_empty() || !self.pending_transmits.is_empty() {
            return TurnPollRet::WaitUntil(now);
        }
        let mut earliest_wait = now + Duration::from_secs(9999);
        let cancelled_transaction = match self.stun_agent.poll(now) {
            StunAgentPollRet::WaitUntil(wait) => {
                earliest_wait = earliest_wait.min(wait);
                None
            }
            StunAgentPollRet::TransactionTimedOut(transaction)
            | StunAgentPollRet::TransactionCancelled(transaction) => Some(transaction),
        };
        if let Some(transaction) = cancelled_transaction {
            trace!("STUN transaction {transaction} was cancelled/timed out");
        }
        match &mut self.state {
            AuthState::Error => return TurnPollRet::Closed,
            AuthState::Initial => {
                return TurnPollRet::WaitUntil(now);
            }
            AuthState::InitialSent(transaction_id) => {
                if cancelled_transaction.is_some_and(|cancelled| &cancelled == transaction_id) {
                    self.state = AuthState::Error;
                }
                return TurnPollRet::WaitUntil(earliest_wait);
            }
            AuthState::Authenticating {
                credentials: _,
                nonce: _,
                transaction_id,
            } => {
                if cancelled_transaction.is_some_and(|cancelled| &cancelled == transaction_id) {
                    self.state = AuthState::Error;
                }
                return TurnPollRet::WaitUntil(earliest_wait);
            }
            AuthState::Authenticated { credentials, nonce } => {
                for alloc in self.allocations.iter_mut() {
                    let mut expires_at = alloc.expires_at
                        - if alloc.pending_refresh.is_none() {
                            if alloc.lifetime > Duration::from_secs(120) {
                                Duration::from_secs(60)
                            } else {
                                alloc.lifetime / 2
                            }
                        } else {
                            Duration::ZERO
                        };
                    if alloc.pending_refresh.is_none() && expires_at <= now {
                        let mut refresh = Message::builder_request(REFRESH);
                        let transaction_id = refresh.transaction_id();
                        let lifetime = Lifetime::new(1800);
                        refresh.add_attribute(&lifetime).unwrap();
                        let username = Username::new(credentials.username()).unwrap();
                        refresh.add_attribute(&username).unwrap();
                        let realm = Realm::new(credentials.realm()).unwrap();
                        refresh.add_attribute(&realm).unwrap();
                        let nonce = Nonce::new(nonce).unwrap();
                        refresh.add_attribute(&nonce).unwrap();
                        refresh
                            .add_message_integrity(
                                &MessageIntegrityCredentials::LongTerm(credentials.clone()),
                                stun_proto::types::message::IntegrityAlgorithm::Sha1,
                            )
                            .unwrap();
                        let remote_addr = self.stun_agent.remote_addr().unwrap();
                        let transmit = self
                            .stun_agent
                            .send_request(refresh, remote_addr, now)
                            .unwrap();
                        alloc.pending_refresh = Some((transaction_id, 1800));
                        self.pending_transmits.push_back(transmit.into_owned());
                        earliest_wait = now.min(earliest_wait);
                    }
                    if let Some((pending, _lifetime)) = alloc.pending_refresh {
                        if cancelled_transaction.is_some_and(|cancelled| cancelled == pending) {
                            // TODO: need to eventually fail when the allocation times out.
                            warn!("Refresh timed out or was cancelled");
                            expires_at = alloc.expires_at;
                        } else {
                            expires_at = earliest_wait;
                        }
                    }
                    for channel in alloc.channels.iter_mut() {
                        let refresh_time = channel.expires_at - Duration::from_secs(60);
                        if let Some(pending) = channel.pending_refresh {
                            if cancelled_transaction.is_some_and(|cancelled| cancelled == pending) {
                                // TODO: need to eventually fail when the permission times out.
                                warn!("{} channel {} from {} to {} refresh timed out or was cancelled", alloc.transport, channel.id, alloc.relayed_address, channel.peer_addr);
                                expires_at = channel.expires_at;
                            } else if channel.expires_at <= now {
                                info!(
                                    "{} channel {} from {} to {} has expired",
                                    alloc.transport,
                                    channel.id,
                                    alloc.relayed_address,
                                    channel.peer_addr
                                );
                            } else {
                                expires_at = expires_at.min(channel.expires_at);
                            }
                        } else if refresh_time <= now {
                            info!(
                                "refreshing {} channel {} from {} to {}",
                                alloc.transport,
                                channel.id,
                                alloc.relayed_address,
                                channel.peer_addr
                            );
                            let (transmit, transaction_id) = Self::send_channel_bind_request(
                                &mut self.stun_agent,
                                credentials.clone(),
                                nonce,
                                channel.id,
                                channel.peer_addr,
                                now,
                            );
                            channel.pending_refresh = Some(transaction_id);
                            self.pending_transmits.push_back(transmit);
                            expires_at = expires_at.min(refresh_time);
                        } else {
                            expires_at = expires_at.min(refresh_time);
                        }
                    }

                    // refresh permission if necessary
                    for permission in alloc.permissions.iter_mut() {
                        let refresh_time = permission.expires_at - Duration::from_secs(60);
                        if let Some(pending) = permission.pending_refresh {
                            if cancelled_transaction.is_some_and(|cancelled| cancelled == pending) {
                                warn!(
                                    "permission {} from {} to {} refresh timed out or was cancelled",
                                    alloc.transport, alloc.relayed_address, permission.ip
                                );
                                expires_at = permission.expires_at;
                            } else if permission.expires_at <= now {
                                info!(
                                    "permission {} from {} to {} has expired",
                                    alloc.transport, alloc.relayed_address, permission.ip
                                );
                                permission.expired = true;
                                self.pending_events
                                    .push_back(TurnEvent::PermissionCreateFailed(
                                        alloc.transport,
                                        permission.ip,
                                    ));
                            } else {
                                expires_at = expires_at.min(permission.expires_at);
                            }
                        } else if refresh_time <= now {
                            info!(
                                "refreshing {} permission from {} to {}",
                                alloc.transport, alloc.relayed_address, permission.ip
                            );
                            let (transmit, transaction_id) = Self::send_create_permission_request(
                                &mut self.stun_agent,
                                credentials.clone(),
                                nonce,
                                permission.ip,
                                now,
                            );
                            permission.pending_refresh = Some(transaction_id);
                            self.pending_transmits.push_back(transmit);
                            expires_at = expires_at.min(refresh_time);
                        } else {
                            expires_at = expires_at.min(refresh_time);
                        }
                    }
                    earliest_wait = expires_at.min(earliest_wait)
                }
                return TurnPollRet::WaitUntil(earliest_wait.max(now));
            }
        }
    }

    /// The list of allocated relayed addresses on the TURN server.
    pub fn relayed_addresses(&self) -> impl Iterator<Item = (TransportType, SocketAddr)> + '_ {
        self.allocations
            .iter()
            .filter(|allocation| !allocation.expired)
            .map(|allocation| (allocation.transport, allocation.relayed_address))
    }

    /// The list of permissions available for the provided relayed address.
    pub fn permissions(
        &self,
        transport: TransportType,
        relayed: SocketAddr,
    ) -> impl Iterator<Item = IpAddr> + '_ {
        self.allocations
            .iter()
            .filter(move |allocation| {
                !allocation.expired
                    && allocation.transport == transport
                    && allocation.relayed_address == relayed
            })
            .flat_map(|allocation| {
                allocation
                    .permissions
                    .iter()
                    .filter(|permission| !permission.expired)
                    .map(|permission| permission.ip)
            })
    }

    /// Poll for a packet to send.
    #[tracing::instrument(
        name = "turn_client_poll_transmit"
        skip(self)
    )]
    pub fn poll_transmit(&mut self, now: Instant) -> Option<Transmit<Data<'static>>> {
        if let Some(transmit) = self.pending_transmits.pop_front() {
            return Some(transmit);
        }
        if let Some(transmit) = self
            .stun_agent
            .poll_transmit(now)
            .map(|transmit| transmit_send(&transmit))
        {
            return Some(transmit);
        }
        match &mut self.state {
            AuthState::Error => None,
            AuthState::Initial => {
                let (transmit, transaction_id) = self.send_initial_request(now);
                self.state = AuthState::InitialSent(transaction_id);
                Some(transmit)
            }
            AuthState::InitialSent(_transaction_id) => None,
            AuthState::Authenticating {
                credentials: _,
                nonce: _,
                transaction_id: _,
            } => None,
            AuthState::Authenticated {
                credentials: _,
                nonce: _,
            } => None,
        }
    }

    /// Poll for an event that has occurred.
    #[tracing::instrument(name = "turn_client_poll_event", ret, skip(self))]
    pub fn poll_event(&mut self) -> Option<TurnEvent> {
        self.pending_events.pop_back()
    }

    fn send_initial_request(&mut self, now: Instant) -> (Transmit<Data<'static>>, TransactionId) {
        let mut msg = Message::builder_request(ALLOCATE);
        let lifetime = Lifetime::new(3600);
        msg.add_attribute(&lifetime).unwrap();
        let requested = RequestedTransport::new(RequestedTransport::UDP);
        msg.add_attribute(&requested).unwrap();
        let dont_fragment = DontFragment::new();
        msg.add_attribute(&dont_fragment).unwrap();
        let transaction_id = msg.transaction_id();

        let remote_addr = self.stun_agent.remote_addr().unwrap();
        let transmit = self.stun_agent.send_request(msg, remote_addr, now).unwrap();
        (transmit.into_owned(), transaction_id)
    }

    fn send_authenticating_request(
        &mut self,
        credentials: LongTermCredentials,
        nonce: &str,
        now: Instant,
    ) -> (Transmit<Data<'static>>, TransactionId) {
        let mut builder = Message::builder_request(ALLOCATE);
        let requested_transport = RequestedTransport::new(RequestedTransport::UDP);
        builder.add_attribute(&requested_transport).unwrap();
        let username = Username::new(credentials.username()).unwrap();
        builder.add_attribute(&username).unwrap();
        let realm = Realm::new(credentials.realm()).unwrap();
        builder.add_attribute(&realm).unwrap();
        let nonce = Nonce::new(nonce).unwrap();
        builder.add_attribute(&nonce).unwrap();
        builder
            .add_message_integrity(
                &stun_proto::types::message::MessageIntegrityCredentials::LongTerm(credentials),
                stun_proto::types::message::IntegrityAlgorithm::Sha1,
            )
            .unwrap();
        let transaction_id = builder.transaction_id();
        let transmit = self
            .stun_agent
            .send_request(builder, self.stun_agent.remote_addr().unwrap(), now)
            .unwrap();
        (transmit.into_owned(), transaction_id)
    }

    fn update_permission_state(&mut self, msg: Message<'_>, now: Instant) -> bool {
        if let Some((alloc_idx, pending_idx)) =
            self.allocations
                .iter()
                .enumerate()
                .find_map(|(idx, allocation)| {
                    allocation
                        .pending_permissions
                        .iter()
                        .position(|(_permission, transaction_id)| {
                            transaction_id == &msg.transaction_id()
                        })
                        .map(|pending_idx| (idx, pending_idx))
                })
        {
            let (mut permission, _transaction_id) = self.allocations[alloc_idx]
                .pending_permissions
                .swap_remove_back(pending_idx)
                .unwrap();
            info!("Succesfully created {permission:?}");
            if msg.has_class(stun_proto::types::message::MessageClass::Error) {
                warn!(
                    "Received error response to create permission request for {}",
                    permission.ip
                );
                permission.expired = true;
                permission.expires_at = now;
                permission.pending_refresh = None;
                self.pending_events
                    .push_back(TurnEvent::PermissionCreateFailed(
                        self.allocations[alloc_idx].transport,
                        permission.ip,
                    ));
            } else {
                self.pending_events.push_front(TurnEvent::PermissionCreated(
                    self.allocations[alloc_idx].transport,
                    permission.ip,
                ));
                permission.expires_at = now + Duration::from_secs(300);
                permission.expired = false;
                self.allocations[alloc_idx].permissions.push(permission);
            }
            true
        } else if let Some((alloc_idx, existing_idx)) =
            self.allocations
                .iter()
                .enumerate()
                .find_map(|(idx, allocation)| {
                    allocation
                        .permissions
                        .iter()
                        .enumerate()
                        .find_map(|(idx, existing_permission)| {
                            if existing_permission.pending_refresh.is_some_and(
                                |refresh_transaction| refresh_transaction == msg.transaction_id(),
                            ) {
                                Some(idx)
                            } else {
                                None
                            }
                        })
                        .map(|pending_idx| (idx, pending_idx))
                })
        {
            let transport = self.allocations[alloc_idx].transport;
            let permission = &mut self.allocations[alloc_idx].permissions[existing_idx];
            permission.pending_refresh = None;
            if msg.has_class(stun_proto::types::message::MessageClass::Error) {
                warn!(
                    "Received error response to create permission request for {}",
                    permission.ip
                );
                permission.expired = true;
                permission.expires_at = now;
                self.pending_events
                    .push_back(TurnEvent::PermissionCreateFailed(transport, permission.ip));
            } else {
                permission.expires_at = now + Duration::from_secs(300);
            }
            true
        } else {
            false
        }
    }

    /// Provide received data to the TURN client for handling.
    ///
    /// The returned data outlines what to do with this data.
    #[tracing::instrument(
        name = "turn_client_recv",
        skip(self, transmit),
        fields(
            transport = ?transmit.transport,
            from = ?transmit.from,
            to = ?transmit.to,
            data_len = transmit.data.as_ref().len(),
        )
    )]
    pub fn recv<T: AsRef<[u8]> + std::fmt::Debug>(
        &mut self,
        transmit: Transmit<T>,
        now: Instant,
    ) -> TurnRecvRet<T> {
        /* is this data for our client? */
        if transmit.to != self.stun_agent.local_addr()
            || self.stun_agent.transport() != transmit.transport
            || transmit.from != self.stun_agent.remote_addr().unwrap()
        {
            trace!(
                "received data not directed at us ({:?}) but for {:?}!",
                self.stun_agent.local_addr(),
                transmit.to
            );
            return TurnRecvRet::Ignored(transmit);
        }
        let (credentials, _nonce) = match &mut self.state {
            AuthState::Error | AuthState::Initial => return TurnRecvRet::Ignored(transmit),
            AuthState::InitialSent(transaction_id) => {
                let msg = if self.stun_agent.transport() == TransportType::Tcp {
                    self.tcp_buffer.extend_from_slice(transmit.data.as_ref());
                    let Ok(hdr) = MessageHeader::from_bytes(&self.tcp_buffer) else {
                        return TurnRecvRet::Handled;
                    };
                    if self.tcp_buffer.len() < MessageHeader::LENGTH + hdr.data_length() as usize {
                        return TurnRecvRet::Handled;
                    }
                    let Ok(ret) = Message::from_bytes(transmit.data.as_ref()) else {
                        return TurnRecvRet::Ignored(transmit);
                    };
                    ret
                } else {
                    let Ok(ret) = Message::from_bytes(transmit.data.as_ref()) else {
                        return TurnRecvRet::Ignored(transmit);
                    };
                    ret
                };
                trace!("received STUN message {msg}");
                let msg = match self.stun_agent.handle_stun(msg, transmit.from) {
                    HandleStunReply::Drop => return TurnRecvRet::Handled,
                    HandleStunReply::IncomingStun(_) => return TurnRecvRet::Ignored(transmit),
                    HandleStunReply::StunResponse(msg) => msg,
                };
                if !msg.is_response() || &msg.transaction_id() != transaction_id {
                    return TurnRecvRet::Ignored(transmit);
                }
                /* The Initial stun request should result in an unauthorized error as there were
                 * no credentials in the initial request */
                if !msg.has_class(stun_proto::types::message::MessageClass::Error) {
                    self.state = AuthState::Error;
                    self.pending_events
                        .push_front(TurnEvent::AllocationCreateFailed);
                    return TurnRecvRet::Ignored(transmit);
                }
                let Ok(error_code) = msg.attribute::<ErrorCode>() else {
                    self.state = AuthState::Error;
                    self.pending_events
                        .push_front(TurnEvent::AllocationCreateFailed);
                    return TurnRecvRet::Ignored(transmit);
                };
                let Ok(realm) = msg.attribute::<Realm>() else {
                    self.state = AuthState::Error;
                    self.pending_events
                        .push_front(TurnEvent::AllocationCreateFailed);
                    return TurnRecvRet::Ignored(transmit);
                };
                let Ok(nonce) = msg.attribute::<Nonce>() else {
                    self.state = AuthState::Error;
                    self.pending_events
                        .push_front(TurnEvent::AllocationCreateFailed);
                    return TurnRecvRet::Ignored(transmit);
                };
                match error_code.code() {
                    ErrorCode::UNAUTHORIZED => {
                        /* retry the request with the correct credentials */
                        let credentials = self
                            .credentials
                            .clone()
                            .into_long_term_credentials(realm.realm());
                        let (transmit, transaction_id) = self.send_authenticating_request(
                            credentials.clone(),
                            nonce.nonce(),
                            now,
                        );
                        self.stun_agent.set_remote_credentials(
                            MessageIntegrityCredentials::LongTerm(credentials.clone()),
                        );
                        self.pending_transmits.push_back(transmit.into_owned());
                        self.state = AuthState::Authenticating {
                            credentials,
                            nonce: nonce.nonce().to_string(),
                            transaction_id,
                        };
                        return TurnRecvRet::Handled;
                    }
                    ErrorCode::TRY_ALTERNATE => (), // FIXME: implement
                    code => {
                        trace!("Unknown error code returned {code:?}");
                        self.state = AuthState::Error;
                        self.pending_events
                            .push_front(TurnEvent::AllocationCreateFailed);
                    }
                }
                return TurnRecvRet::Ignored(transmit);
            }
            AuthState::Authenticating {
                credentials,
                nonce,
                transaction_id,
            } => {
                let msg = if self.stun_agent.transport() == TransportType::Tcp {
                    self.tcp_buffer.extend_from_slice(transmit.data.as_ref());
                    let Ok(hdr) = MessageHeader::from_bytes(&self.tcp_buffer) else {
                        return TurnRecvRet::Handled;
                    };
                    if self.tcp_buffer.len() < MessageHeader::LENGTH + hdr.data_length() as usize {
                        return TurnRecvRet::Handled;
                    }
                    let Ok(ret) = Message::from_bytes(transmit.data.as_ref()) else {
                        return TurnRecvRet::Ignored(transmit);
                    };
                    ret
                } else {
                    let Ok(ret) = Message::from_bytes(transmit.data.as_ref()) else {
                        return TurnRecvRet::Ignored(transmit);
                    };
                    ret
                };
                trace!("received STUN message {msg}");
                let msg = match self.stun_agent.handle_stun(msg, transmit.from) {
                    HandleStunReply::Drop => return TurnRecvRet::Handled,
                    HandleStunReply::IncomingStun(_) => return TurnRecvRet::Ignored(transmit),
                    HandleStunReply::StunResponse(msg) => msg,
                };
                if !msg.is_response() || &msg.transaction_id() != transaction_id {
                    return TurnRecvRet::Ignored(transmit);
                }
                match msg.class() {
                    stun_proto::types::message::MessageClass::Error => {
                        let Ok(error_code) = msg.attribute::<ErrorCode>() else {
                            self.state = AuthState::Error;
                            return TurnRecvRet::Ignored(transmit);
                        };
                        match error_code.code() {
                            ErrorCode::STALE_NONCE => {
                                let Ok(realm) = msg.attribute::<Realm>() else {
                                    self.state = AuthState::Error;
                                    return TurnRecvRet::Ignored(transmit);
                                };
                                let Ok(nonce) = msg.attribute::<Nonce>() else {
                                    self.state = AuthState::Error;
                                    return TurnRecvRet::Ignored(transmit);
                                };
                                let credentials = self
                                    .credentials
                                    .clone()
                                    .into_long_term_credentials(realm.realm());
                                let (transmit, transaction_id) = self.send_authenticating_request(
                                    credentials.clone(),
                                    nonce.nonce(),
                                    now,
                                );
                                self.pending_transmits.push_back(transmit.into_owned());
                                self.state = AuthState::Authenticating {
                                    credentials,
                                    nonce: nonce.nonce().to_string(),
                                    transaction_id,
                                };
                                return TurnRecvRet::Handled;
                            }
                            code => {
                                warn!("Unknown error code returned while authenticating: {code:?}");
                                self.state = AuthState::Error;
                            }
                        }
                    }
                    stun_proto::types::message::MessageClass::Success => {
                        let Ok(_) = msg.validate_integrity(&MessageIntegrityCredentials::LongTerm(
                            credentials.clone(),
                        )) else {
                            return TurnRecvRet::Ignored(transmit);
                        };
                        let xor_relayed_address = msg.attribute::<XorRelayedAddress>();
                        let lifetime = msg.attribute::<Lifetime>();
                        let (Ok(xor_relayed_address), Ok(lifetime)) =
                            (xor_relayed_address, lifetime)
                        else {
                            self.state = AuthState::Error;
                            return TurnRecvRet::Ignored(transmit);
                        };
                        let relayed_address = xor_relayed_address.addr(msg.transaction_id());
                        let lifetime = Duration::from_secs(lifetime.seconds() as u64);
                        let expires_at = now + lifetime;
                        self.state = AuthState::Authenticated {
                            credentials: credentials.clone(),
                            nonce: nonce.clone(),
                        };
                        info!(relayed = ?relayed_address, transport = ?TransportType::Udp, "New allocation expiring in {}s", lifetime.as_secs());
                        self.allocations.push(Allocation {
                            relayed_address,
                            // TODO support TCP
                            transport: TransportType::Udp,
                            expired: false,
                            lifetime,
                            expires_at,
                            permissions: vec![],
                            channels: vec![],
                            pending_permissions: VecDeque::default(),
                            pending_channels: VecDeque::default(),
                            pending_refresh: None,
                            expired_channels: vec![],
                        });
                        self.pending_events.push_front(TurnEvent::AllocationCreated(
                            TransportType::Udp,
                            relayed_address,
                        ));
                        return TurnRecvRet::Handled;
                    }
                    _ => (),
                }
                return TurnRecvRet::Ignored(transmit);
            }
            AuthState::Authenticated { credentials, nonce } => (credentials.clone(), nonce),
        };

        if self.stun_agent.transport() == TransportType::Tcp {
            // TODO: handle multiple messages/channeldata in a single transmit
            self.tcp_buffer.extend_from_slice(transmit.data.as_ref());
            let Ok(hdr) = MessageHeader::from_bytes(&self.tcp_buffer) else {
                let Ok(channel) = ChannelData::parse(&self.tcp_buffer) else {
                    return TurnRecvRet::Ignored(transmit);
                };
                let data = channel.data();
                for alloc in self.allocations.iter_mut() {
                    if let Some(chan) = alloc
                        .channels
                        .iter_mut()
                        .find(|chan| chan.id == channel.id())
                    {
                        let data = data.to_vec();
                        self.tcp_buffer = self.tcp_buffer.split_at(data.len() + 2).1.to_vec();
                        return TurnRecvRet::PeerData {
                            data,
                            transport: alloc.transport,
                            peer: chan.peer_addr,
                        };
                    }
                }
                self.tcp_buffer = self.tcp_buffer.split_at(data.len() + 2).1.to_vec();
                return TurnRecvRet::Handled;
            };
            if self.tcp_buffer.len() < MessageHeader::LENGTH + hdr.data_length() as usize {
                return TurnRecvRet::Handled;
            }
            let Ok(msg) = Message::from_bytes(transmit.data.as_ref()) else {
                return TurnRecvRet::Ignored(transmit);
            };

            // FIXME: dual allocations
            let transport = self
                .allocations
                .iter()
                .map(|allocation| allocation.transport)
                .next()
                .unwrap();

            match self.handle_stun(msg, transport, transmit.from, credentials, now) {
                InternalHandleStunReply::Handled => TurnRecvRet::Handled,
                InternalHandleStunReply::Ignored => TurnRecvRet::Ignored(transmit),
                InternalHandleStunReply::PeerData {
                    data,
                    transport,
                    peer,
                } => TurnRecvRet::PeerData {
                    data,
                    transport,
                    peer,
                },
            }
        } else {
            let Ok(msg) = Message::from_bytes(transmit.data.as_ref()) else {
                let Ok(channel) = ChannelData::parse(transmit.data.as_ref()) else {
                    return TurnRecvRet::Ignored(transmit);
                };
                for alloc in self.allocations.iter_mut() {
                    if let Some(chan) = alloc
                        .channels
                        .iter_mut()
                        .find(|chan| chan.id == channel.id())
                    {
                        return TurnRecvRet::PeerData {
                            data: channel.data().to_vec(),
                            transport: alloc.transport,
                            peer: chan.peer_addr,
                        };
                    }
                }
                return TurnRecvRet::Ignored(transmit);
            };

            // FIXME: TCP allocations
            let transport = self
                .allocations
                .iter()
                .map(|allocation| allocation.transport)
                .next()
                .unwrap();

            match self.handle_stun(msg, transport, transmit.from, credentials, now) {
                InternalHandleStunReply::Handled => TurnRecvRet::Handled,
                InternalHandleStunReply::Ignored => TurnRecvRet::Ignored(transmit),
                InternalHandleStunReply::PeerData {
                    data,
                    transport,
                    peer,
                } => TurnRecvRet::PeerData {
                    data,
                    transport,
                    peer,
                },
            }
        }
    }

    fn handle_stun(
        &mut self,
        msg: Message<'_>,
        transport: TransportType,
        from: SocketAddr,
        credentials: LongTermCredentials,
        now: Instant,
    ) -> InternalHandleStunReply {
        trace!("received STUN message {msg}");
        let msg = match self.stun_agent.handle_stun(msg, from) {
            HandleStunReply::Drop => return InternalHandleStunReply::Ignored,
            HandleStunReply::IncomingStun(msg) => msg,
            HandleStunReply::StunResponse(msg) => msg,
        };
        if msg.is_response() {
            let Ok(_) = msg.validate_integrity(&MessageIntegrityCredentials::LongTerm(credentials))
            else {
                trace!("incoming message failed integrity check");
                return InternalHandleStunReply::Ignored;
            };

            match msg.method() {
                REFRESH => {
                    let is_success = if msg.has_class(MessageClass::Error) {
                        msg.attribute::<ErrorCode>()
                            .is_ok_and(|err| err.code() == ErrorCode::ALLOCATION_MISMATCH)
                    } else {
                        msg.has_class(MessageClass::Success)
                    };
                    let mut remove_allocations = false;
                    let mut handled = false;
                    if is_success {
                        for alloc in self.allocations.iter_mut() {
                            let Ok(lifetime) = msg.attribute::<Lifetime>() else {
                                continue;
                            };
                            let (_transaction_id, requested_lifetime) = if alloc
                                .pending_refresh
                                .is_some_and(|(transaction_id, _requested_lifetime)| {
                                    transaction_id == msg.transaction_id() && is_success
                                }) {
                                alloc.pending_refresh.take().unwrap()
                            } else {
                                continue;
                            };
                            if requested_lifetime == 0 {
                                remove_allocations = true;
                            } else {
                                alloc.expires_at =
                                    now + Duration::from_secs(lifetime.seconds() as u64);
                            }
                            handled = true;
                        }
                    }

                    if remove_allocations {
                        self.allocations.clear();
                        self.state = AuthState::Error;
                    }
                    if handled {
                        if remove_allocations {
                            info!("Successfully deleted allocation");
                        } else {
                            info!("Successfully refreshed allocation");
                        }
                        InternalHandleStunReply::Handled
                    } else {
                        InternalHandleStunReply::Ignored
                    }
                }
                CREATE_PERMISSION => {
                    if self.update_permission_state(msg, now) {
                        InternalHandleStunReply::Handled
                    } else {
                        InternalHandleStunReply::Ignored
                    }
                }
                CHANNEL_BIND => {
                    if let Some((alloc_idx, channel_idx)) = self
                        .allocations
                        .iter()
                        .enumerate()
                        .find_map(|(idx, allocation)| {
                            allocation
                                .pending_channels
                                .iter()
                                .position(|(_channel, transaction_id)| {
                                    transaction_id == &msg.transaction_id()
                                })
                                .map(|perm_idx| (idx, perm_idx))
                        })
                    {
                        let (mut channel, _transaction_id) = self.allocations[alloc_idx]
                            .pending_channels
                            .swap_remove_back(channel_idx)
                            .unwrap();
                        if msg.has_class(stun_proto::types::message::MessageClass::Error) {
                            error!("Received error response to channel bind request");
                            // TODO: handle
                            return InternalHandleStunReply::Handled;
                        }
                        info!("Succesfully created/refreshed {channel:?}");
                        self.update_permission_state(msg, now);
                        if let Some(existing_idx) = self.allocations[alloc_idx]
                            .channels
                            .iter()
                            .enumerate()
                            .find_map(|(idx, existing_channel)| {
                                if channel.peer_addr == existing_channel.peer_addr {
                                    Some(idx)
                                } else {
                                    None
                                }
                            })
                        {
                            self.allocations[alloc_idx].channels[existing_idx].expires_at =
                                now + Duration::from_secs(600);
                        } else {
                            channel.expires_at = now + Duration::from_secs(600);
                            self.allocations[alloc_idx].channels.push(channel);
                        }
                        return InternalHandleStunReply::Handled;
                    }
                    InternalHandleStunReply::Ignored
                }
                _ => InternalHandleStunReply::Ignored, // Other responses are not expected
            }
        } else if msg.has_class(stun_proto::types::message::MessageClass::Request) {
            let Ok(_) = msg.validate_integrity(&MessageIntegrityCredentials::LongTerm(credentials))
            else {
                trace!("incoming message failed integrity check");
                return InternalHandleStunReply::Ignored;
            };

            // TODO: reply with an error?
            InternalHandleStunReply::Ignored
        } else {
            /* The message is an indication */
            match msg.method() {
                DATA => {
                    let Ok(peer_addr) = msg.attribute::<XorPeerAddress>() else {
                        return InternalHandleStunReply::Ignored;
                    };
                    let Ok(data) = msg.attribute::<AData>() else {
                        return InternalHandleStunReply::Ignored;
                    };
                    InternalHandleStunReply::PeerData {
                        data: data.data().to_vec(),
                        transport,
                        peer: peer_addr.addr(msg.transaction_id()),
                    }
                }
                _ => InternalHandleStunReply::Ignored, // All other indications should be ignored
            }
        }
    }

    /// Remove the allocation/s on the server.
    pub fn delete(&mut self, now: Instant) -> Option<Transmit<Data<'static>>> {
        let mut builder = Message::builder_request(REFRESH);
        let transaction_id = builder.transaction_id();

        let AuthState::Authenticated { credentials, nonce } = &self.state else {
            return None;
        };

        let lifetime = Lifetime::new(0);
        builder.add_attribute(&lifetime).unwrap();
        let username = Username::new(credentials.username()).unwrap();
        builder.add_attribute(&username).unwrap();
        let realm = Realm::new(credentials.realm()).unwrap();
        builder.add_attribute(&realm).unwrap();
        let nonce = Nonce::new(nonce).unwrap();
        builder.add_attribute(&nonce).unwrap();
        builder
            .add_message_integrity(
                &stun_proto::types::message::MessageIntegrityCredentials::LongTerm(
                    credentials.clone(),
                ),
                stun_proto::types::message::IntegrityAlgorithm::Sha1,
            )
            .unwrap();

        let transmit = self
            .stun_agent
            .send_request(builder, self.stun_agent.remote_addr().unwrap(), now)
            .unwrap();
        info!("Deleting allocations");
        for alloc in self.allocations.iter_mut() {
            alloc.permissions.clear();
            alloc.channels.clear();
            alloc.expires_at = now;
            alloc.expired = true;
            alloc.pending_refresh = Some((transaction_id, 0));
        }
        Some(transmit.into_owned())
    }

    fn send_create_permission_request(
        stun_agent: &mut StunAgent,
        credentials: LongTermCredentials,
        nonce: &str,
        peer_addr: IpAddr,
        now: Instant,
    ) -> (Transmit<Data<'static>>, TransactionId) {
        let mut builder = Message::builder_request(CREATE_PERMISSION);
        let transaction_id = builder.transaction_id();

        let xor_peer_address = XorPeerAddress::new(SocketAddr::new(peer_addr, 0), transaction_id);
        builder.add_attribute(&xor_peer_address).unwrap();
        let username = Username::new(credentials.username()).unwrap();
        builder.add_attribute(&username).unwrap();
        let realm = Realm::new(credentials.realm()).unwrap();
        builder.add_attribute(&realm).unwrap();
        let nonce = Nonce::new(nonce).unwrap();
        builder.add_attribute(&nonce).unwrap();
        builder
            .add_message_integrity(
                &stun_proto::types::message::MessageIntegrityCredentials::LongTerm(
                    credentials.clone(),
                ),
                stun_proto::types::message::IntegrityAlgorithm::Sha1,
            )
            .unwrap();
        let transmit = stun_agent
            .send_request(builder, stun_agent.remote_addr().unwrap(), now)
            .unwrap();
        (transmit.into_owned(), transaction_id)
    }

    /// Create a permission address to allow sending/receiving data to/from.
    #[tracing::instrument(name = "turn_client_create_permission", skip(self, now), err)]
    pub fn create_permission(
        &mut self,
        transport: TransportType,
        peer_addr: IpAddr,
        now: Instant,
    ) -> Result<Transmit<Data<'static>>, CreatePermissionError> {
        let Some(allocation) = self.allocations.iter_mut().find(|allocation| {
            allocation.transport == transport
                && allocation.relayed_address.is_ipv4() == peer_addr.is_ipv4()
        }) else {
            warn!("No allocation available to create this permission");
            return Err(CreatePermissionError::NoAllocation);
        };

        if now >= allocation.expires_at {
            allocation.expired = true;
            warn!("Allocation has expired");
            return Err(CreatePermissionError::NoAllocation);
        }

        if allocation
            .permissions
            .iter()
            .any(|permission| permission.ip == peer_addr)
        {
            return Err(CreatePermissionError::AlreadyExists);
        }
        if allocation
            .pending_permissions
            .iter()
            .any(|(permission, _transaction_id)| permission.ip == peer_addr)
        {
            return Err(CreatePermissionError::AlreadyExists);
        }
        let AuthState::Authenticated { credentials, nonce } = &self.state else {
            warn!("Not authenticated yet: {:?}", self.state);
            return Err(CreatePermissionError::NoAllocation);
        };
        let permission = Permission {
            expired: false,
            expires_at: now,
            ip: peer_addr,
            pending_refresh: None,
        };

        let (transmit, transaction_id) = Self::send_create_permission_request(
            &mut self.stun_agent,
            credentials.clone(),
            nonce,
            peer_addr,
            now,
        );
        info!("Creating {permission:?}");
        allocation
            .pending_permissions
            .push_back((permission, transaction_id));
        Ok(transmit)
    }

    fn send_channel_bind_request(
        stun_agent: &mut StunAgent,
        credentials: LongTermCredentials,
        nonce: &str,
        id: u16,
        peer_addr: SocketAddr,
        now: Instant,
    ) -> (Transmit<Data<'static>>, TransactionId) {
        let mut builder = Message::builder_request(CHANNEL_BIND);
        let transaction_id = builder.transaction_id();
        let channel_no = ChannelNumber::new(id);
        builder.add_attribute(&channel_no).unwrap();
        let xor_peer_address = XorPeerAddress::new(peer_addr, transaction_id);
        builder.add_attribute(&xor_peer_address).unwrap();
        let username = Username::new(credentials.username()).unwrap();
        builder.add_attribute(&username).unwrap();
        let realm = Realm::new(credentials.realm()).unwrap();
        builder.add_attribute(&realm).unwrap();
        let nonce = Nonce::new(nonce).unwrap();
        builder.add_attribute(&nonce).unwrap();
        builder
            .add_message_integrity(
                &stun_proto::types::message::MessageIntegrityCredentials::LongTerm(
                    credentials.clone(),
                ),
                stun_proto::types::message::IntegrityAlgorithm::Sha1,
            )
            .unwrap();

        let transmit = stun_agent
            .send_request(builder, stun_agent.remote_addr().unwrap(), now)
            .unwrap();
        (transmit.into_owned(), transaction_id)
    }

    /// Bind a channel for sending/receiving data to/from a particular peer.
    pub fn bind_channel(
        &mut self,
        transport: TransportType,
        peer_addr: SocketAddr,
        now: Instant,
    ) -> Result<Transmit<Data<'static>>, BindChannelError> {
        let Some(allocation) = self.allocations.iter_mut().find(|allocation| {
            allocation.transport == transport
                && allocation.relayed_address.is_ipv4() == peer_addr.is_ipv4()
        }) else {
            warn!("No allocation available to create this permission");
            return Err(BindChannelError::NoAllocation);
        };

        if now >= allocation.expires_at {
            allocation.expired = true;
            return Err(BindChannelError::NoAllocation);
        }

        if allocation
            .channels
            .iter()
            .any(|channel| channel.peer_addr == peer_addr)
        {
            return Err(BindChannelError::AlreadyExists);
        }

        let AuthState::Authenticated { credentials, nonce } = &self.state else {
            return Err(BindChannelError::NoAllocation);
        };

        let mut channel_id = 0x4000;
        for channel in 0x4000..=0x7FFF {
            channel_id = channel;
            if allocation
                .channels
                .iter()
                .chain(
                    allocation
                        .pending_channels
                        .iter()
                        .map(|(channel, _transaction_id)| channel),
                )
                .chain(allocation.expired_channels.iter())
                .any(|channel| {
                    channel.expires_at + Duration::from_secs(300) <= now && channel.id == channel_id
                })
            {
                continue;
            }
            break;
        }

        let (transmit, transaction_id) = Self::send_channel_bind_request(
            &mut self.stun_agent,
            credentials.clone(),
            nonce,
            channel_id,
            peer_addr,
            now,
        );

        // FIXME: update any existing permission
        let permission = Permission {
            expired: false,
            expires_at: now,
            ip: peer_addr.ip(),
            pending_refresh: None,
        };
        allocation
            .pending_permissions
            .push_back((permission, transaction_id));
        let channel = Channel {
            id: channel_id,
            expires_at: now,
            peer_addr,
            pending_refresh: None,
        };
        info!("Creating channel {channel:?}");
        allocation
            .pending_channels
            .push_back((channel, transaction_id));
        Ok(transmit.into_owned())
    }

    fn have_permission(&self, transport: TransportType, to: SocketAddr, now: Instant) -> bool {
        self.allocations.iter().any(|allocation| {
            allocation.transport == transport
                && allocation.expires_at >= now
                && allocation
                    .permissions
                    .iter()
                    .any(|permission| permission.expires_at >= now && permission.ip == to.ip())
        })
    }

    /// Send data to a peer through the TURN server.
    ///
    /// The provided transport, address and data are the data to send to the peer.
    ///
    /// The returned value will instruct the caller to send a message to the turn server.
    pub fn send_to<T: AsRef<[u8]> + std::fmt::Debug>(
        &mut self,
        transport: TransportType,
        to: SocketAddr,
        data: T,
        now: Instant,
    ) -> Result<TransmitBuild<DelayedMessageOrChannelSend<T>>, StunError> {
        if !self.have_permission(transport, to, now) {
            return Err(StunError::ResourceNotFound);
        }

        if let Some(channel) = self.channel(transport, to) {
            if channel.expires_at >= now {
                return Ok(TransmitBuild::new(
                    DelayedMessageOrChannelSend::Channel(DelayedChannelSend {
                        data,
                        channel_id: channel.id,
                    }),
                    self.stun_agent.transport(),
                    self.stun_agent.local_addr(),
                    self.stun_agent.remote_addr().unwrap(),
                ));
            }
        }
        Ok(TransmitBuild::new(
            DelayedMessageOrChannelSend::Message(DelayedMessageSend {
                data,
                peer_addr: to,
            }),
            self.stun_agent.transport(),
            self.stun_agent.local_addr(),
            self.stun_agent.remote_addr().unwrap(),
        ))
    }

    #[cfg(test)]
    fn permission(&self, transport: TransportType, ip: IpAddr) -> Option<&Permission> {
        self.allocations
            .iter()
            .filter(|allocation| allocation.transport == transport)
            .find_map(|allocation| {
                allocation
                    .permissions
                    .iter()
                    .find(|permission| permission.ip == ip)
            })
    }

    fn channel(&self, transport: TransportType, addr: SocketAddr) -> Option<&Channel> {
        self.allocations
            .iter()
            .filter(|allocation| allocation.transport == transport)
            .find_map(|allocation| {
                allocation
                    .channels
                    .iter()
                    .find(|channel| channel.peer_addr == addr)
            })
    }
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
        );
        let xor_peer_address = XorPeerAddress::new(self.peer_addr, transaction_id);
        msg.add_attribute(&xor_peer_address).unwrap();
        let data = AData::new(self.data.as_ref());
        msg.add_attribute(&data).unwrap();
        msg.build()
    }

    fn write_into(self, dest: &mut [u8]) -> usize {
        let transaction_id = TransactionId::generate();
        let mut msg = Message::builder(
            MessageType::from_class_method(
                stun_proto::types::message::MessageClass::Indication,
                SEND,
            ),
            transaction_id,
        );
        let xor_peer_address = XorPeerAddress::new(self.peer_addr, transaction_id);
        msg.add_attribute(&xor_peer_address).unwrap();
        let data = AData::new(self.data.as_ref());
        msg.add_attribute(&data).unwrap();
        msg.write_into(dest)
    }
}

/// A `Transmit` that will construct a channel message towards a TURN client.
#[derive(Debug)]
pub struct DelayedChannelSend<T: AsRef<[u8]> + std::fmt::Debug> {
    data: T,
    channel_id: u16,
}

impl<T: AsRef<[u8]> + std::fmt::Debug> DelayedTransmitBuild for DelayedChannelSend<T> {
    fn len(&self) -> usize {
        self.data.as_ref().len() + 4
    }

    fn build(self) -> Vec<u8> {
        let mut data = vec![0; self.data.as_ref().len() + 4];
        self.write_into(&mut data);
        data
    }

    fn write_into(self, dest: &mut [u8]) -> usize {
        let data_len = self.data.as_ref().len();
        BigEndian::write_u16(&mut dest[..2], self.channel_id);
        BigEndian::write_u16(&mut dest[2..4], data_len as u16);
        dest[4..].copy_from_slice(self.data.as_ref());
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
}

impl<T: AsRef<[u8]> + std::fmt::Debug> DelayedTransmitBuild for DelayedMessageOrChannelSend<T> {
    fn len(&self) -> usize {
        match self {
            Self::Channel(channel) => channel.len(),
            Self::Message(msg) => msg.len(),
        }
    }

    fn build(self) -> Vec<u8> {
        match self {
            Self::Channel(channel) => channel.build(),
            Self::Message(msg) => msg.build(),
        }
    }

    fn write_into(self, data: &mut [u8]) -> usize {
        match self {
            Self::Channel(channel) => channel.write_into(data),
            Self::Message(msg) => msg.write_into(data),
        }
    }
}

fn transmit_send<T: AsRef<[u8]> + std::fmt::Debug>(
    transmit: &Transmit<T>,
) -> Transmit<Data<'static>> {
    Transmit::new(
        Data::from(transmit.data.as_ref()),
        transmit.transport,
        transmit.from,
        transmit.to,
    )
    .into_owned()
}

#[cfg(test)]
mod tests {
    use stun_proto::types::{
        attribute::{MessageIntegrity, MessageIntegritySha256, XorMappedAddress},
        prelude::AttributeStaticType,
    };

    use super::*;
    use turn_server_proto::{TurnServer, TurnServerPollRet};

    #[test]
    fn test_turn_client_new_properties() {
        let _log = crate::tests::test_init_log();

        let local_addr = "192.168.0.1:31234".parse().unwrap();
        let remote_addr = "10.0.0.1:3478".parse().unwrap();
        let credentials = TurnCredentials::new("tuser", "tpass");

        let mut client =
            TurnClient::allocate(TransportType::Udp, local_addr, remote_addr, credentials);
        assert_eq!(client.transport(), TransportType::Udp);
        assert_eq!(client.local_addr(), local_addr);
        assert_eq!(client.remote_addr(), remote_addr);

        let now = Instant::now();
        let TurnPollRet::WaitUntil(new_now) = client.poll(now) else {
            unreachable!();
        };
        assert_eq!(now, new_now);
        assert!(client.poll_event().is_none());

        assert_eq!(client.relayed_addresses().count(), 0);
    }

    fn transmit_send_build<T: DelayedTransmitBuild>(
        transmit: TransmitBuild<T>,
    ) -> Transmit<Data<'static>> {
        let data = transmit.data.build().into_boxed_slice();
        Transmit::new(
            Data::from(data),
            transmit.transport,
            transmit.from,
            transmit.to,
        )
        .into_owned()
    }

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

    #[derive(Debug)]
    struct TurnTestBuilder {
        turn_listen_addr: SocketAddr,
        credentials: TurnCredentials,
        realm: String,
        client_addr: SocketAddr,
        client_transport: TransportType,
        turn_alloc_addr: SocketAddr,
        peer_addr: SocketAddr,
    }
    impl TurnTestBuilder {
        fn build(self) -> TurnTest {
            let mut server =
                TurnServer::new(self.client_transport, self.turn_listen_addr, self.realm);
            server.add_user(
                self.credentials.username().to_owned(),
                self.credentials.password().to_owned(),
            );
            let client = TurnClient::allocate(
                self.client_transport,
                self.client_addr,
                self.turn_listen_addr,
                self.credentials,
            );
            TurnTest {
                client,
                server,
                turn_alloc_addr: self.turn_alloc_addr,
                peer_addr: self.peer_addr,
            }
        }

        fn client_transport(mut self, transport: TransportType) -> Self {
            self.client_transport = transport;
            self
        }
    }

    #[derive(Debug)]
    struct TurnTest {
        client: TurnClient,
        server: TurnServer,
        turn_alloc_addr: SocketAddr,
        peer_addr: SocketAddr,
    }

    impl TurnTest {
        fn builder() -> TurnTestBuilder {
            let credentials = TurnCredentials::new("turnuser", "turnpass");
            TurnTestBuilder {
                turn_listen_addr: "127.0.0.1:3478".parse().unwrap(),
                credentials,
                realm: String::from("realm"),
                client_addr: "127.0.0.1:2000".parse().unwrap(),
                client_transport: TransportType::Udp,
                turn_alloc_addr: "10.0.0.20:2000".parse().unwrap(),
                peer_addr: "10.0.0.3:3000".parse().unwrap(),
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
            let Ok(Some(transmit)) = self.server.recv(transmit, now) else {
                unreachable!();
            };
            let msg = Message::from_bytes(&transmit.data).unwrap();
            assert!(msg.has_method(ALLOCATE));
            assert!(msg.has_class(stun_proto::types::message::MessageClass::Error));
            assert!(msg.has_attribute(Realm::TYPE));
            let err = msg.attribute::<ErrorCode>().unwrap();
            assert_eq!(err.code(), ErrorCode::UNAUTHORIZED);
            assert!(msg.has_attribute(Nonce::TYPE));
            self.client.recv(transmit, now);

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
            self.client.recv(transmit, now);
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
            let msg = Message::from_bytes(&transmit.data).unwrap();
            assert!(msg.has_method(REFRESH));
            assert!(msg.has_class(stun_proto::types::message::MessageClass::Success));
            assert!(msg.has_attribute(Lifetime::TYPE));
            assert!(msg.has_attribute(MessageIntegrity::TYPE));
            self.client.recv(transmit, now);
            assert!(self
                .client
                .relayed_addresses()
                .any(|(transport, relayed)| transport == TransportType::Udp
                    && relayed == self.turn_alloc_addr))
        }

        fn delete_allocation(&mut self, now: Instant) {
            let transmit = self.client.delete(now).unwrap();
            let msg = Message::from_bytes(&transmit.data).unwrap();
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
            let msg = Message::from_bytes(&transmit.data).unwrap();
            assert!(msg.has_method(REFRESH));
            assert!(msg.has_class(stun_proto::types::message::MessageClass::Success));
            assert!(msg.has_attribute(Lifetime::TYPE));
            assert!(msg.has_attribute(MessageIntegrity::TYPE));
            self.client.recv(transmit, now);
            assert!(!self
                .client
                .relayed_addresses()
                .any(|(transport, relayed)| transport == TransportType::Udp
                    && relayed == self.turn_alloc_addr))
        }

        fn create_permission(&mut self, now: Instant) {
            let transmit = self
                .client
                .create_permission(TransportType::Udp, self.peer_addr.ip(), now)
                .unwrap();
            let msg = Message::from_bytes(&transmit.data).unwrap();
            assert!(msg.has_method(CREATE_PERMISSION));
            assert!(msg.has_class(stun_proto::types::message::MessageClass::Request));
            assert!(msg.has_attribute(XorPeerAddress::TYPE));
            assert!(msg.has_attribute(MessageIntegrity::TYPE));
            let Ok(Some(transmit)) = self.server.recv(transmit, now) else {
                unreachable!();
            };
            self.client.recv(transmit, now);
            self.validate_client_permission_state(now);
        }

        fn validate_client_permission_state(&self, now: Instant) {
            let Some(permision) = self
                .client
                .permission(TransportType::Udp, self.peer_addr.ip())
            else {
                unreachable!();
            };
            assert_eq!(permision.expires_at, now + Duration::from_secs(300));
            assert!(self
                .client
                .permissions(TransportType::Udp, self.turn_alloc_addr)
                .any(|perm_addr| perm_addr == self.peer_addr.ip()));
        }

        fn bind_channel(&mut self, now: Instant) {
            let transmit = self
                .client
                .bind_channel(TransportType::Udp, self.peer_addr, now)
                .unwrap();
            let msg = Message::from_bytes(&transmit.data).unwrap();
            assert!(msg.has_method(CHANNEL_BIND));
            assert!(msg.has_class(stun_proto::types::message::MessageClass::Request));
            assert!(msg.has_attribute(XorPeerAddress::TYPE));
            assert!(msg.has_attribute(MessageIntegrity::TYPE));
            let Ok(Some(transmit)) = self.server.recv(transmit, now) else {
                unreachable!();
            };
            self.client.recv(transmit, now);
            let Some(permision) = self
                .client
                .permission(TransportType::Udp, self.peer_addr.ip())
            else {
                unreachable!();
            };
            assert_eq!(permision.expires_at, now + Duration::from_secs(300));
            let Some(channel) = self.client.channel(TransportType::Udp, self.peer_addr) else {
                unreachable!();
            };
            assert_eq!(channel.expires_at, now + Duration::from_secs(600));
        }

        fn sendrecv_data(&mut self, now: Instant) {
            // client to peer
            let data = [4; 8];
            let transmit = self
                .client
                .send_to(TransportType::Udp, self.peer_addr, data, now)
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
            let TurnRecvRet::PeerData {
                data: recv_data,
                transport,
                peer,
            } = self.client.recv(transmit, now)
            else {
                unreachable!();
            };
            assert_eq!(transport, TransportType::Udp);
            assert_eq!(peer, self.peer_addr);
            assert_eq!(recv_data, sent_data);
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
        }
    }

    fn turn_allocate_permission(client_transport: TransportType, now: Instant) -> TurnTest {
        let mut test = TurnTest::builder()
            .client_transport(client_transport)
            .build();

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
        test
    }

    #[test]
    fn test_turn_udp_allocate_udp_permission() {
        let _log = crate::tests::test_init_log();

        let now = Instant::now();
        turn_allocate_permission(TransportType::Udp, now);
    }

    #[test]
    fn test_turn_tcp_allocate_udp_permission() {
        let _log = crate::tests::test_init_log();

        let now = Instant::now();
        turn_allocate_permission(TransportType::Tcp, now);
    }

    #[test]
    fn test_turn_allocate_expire_server() {
        let _log = crate::tests::test_init_log();

        let mut test = TurnTest::builder().build();
        let now = Instant::now();

        test.allocate(now);
        let Some(TurnEvent::AllocationCreated(TransportType::Udp, relayed_address)) =
            test.client.poll_event()
        else {
            unreachable!();
        };
        assert_eq!(relayed_address, test.turn_alloc_addr);
        let transmit = test
            .client
            .create_permission(TransportType::Udp, test.peer_addr.ip(), now)
            .unwrap();
        let now = now + Duration::from_secs(3000);
        let Ok(Some(transmit)) = test.server.recv(transmit, now) else {
            unreachable!();
        };
        let msg = Message::from_bytes(&transmit.data).unwrap();
        assert!(msg.has_method(CREATE_PERMISSION));
        assert!(msg.has_class(stun_proto::types::message::MessageClass::Error));
        let err = msg.attribute::<ErrorCode>().unwrap();
        assert_eq!(err.code(), ErrorCode::ALLOCATION_MISMATCH);
        test.client.recv(transmit, now);
    }

    #[test]
    fn test_turn_allocate_expire_client() {
        let _log = crate::tests::test_init_log();

        let mut test = TurnTest::builder().build();
        let now = Instant::now();

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

    #[test]
    fn test_turn_allocate_refresh() {
        let _log = crate::tests::test_init_log();

        let mut test = TurnTest::builder().build();
        let now = Instant::now();

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

    #[test]
    fn test_turn_allocate_delete() {
        let _log = crate::tests::test_init_log();

        let mut test = TurnTest::builder().build();
        let now = Instant::now();

        test.allocate(now);
        test.delete_allocation(now);

        let Err(CreatePermissionError::NoAllocation) =
            test.client
                .create_permission(TransportType::Udp, test.peer_addr.ip(), now)
        else {
            unreachable!();
        };
    }

    #[test]
    fn test_turn_channel_bind() {
        let _log = crate::tests::test_init_log();

        let mut test = TurnTest::builder().build();
        let now = Instant::now();

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

    #[test]
    fn test_turn_peer_incoming_stun() {
        // tests that sending stun messages can be passed through the turn server
        let _log = crate::tests::test_init_log();

        let mut test = TurnTest::builder().build();
        let now = Instant::now();

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
            MessageType::from_class_method(MessageClass::Indication, 0x1432),
            TransactionId::generate(),
        );
        let realm = Realm::new("realm").unwrap();
        msg.add_attribute(&realm).unwrap();
        let data = msg.build();
        test.sendrecv_data_channel_with_data(&data, &data, now);
    }

    #[test]
    fn test_turn_create_permission_refresh() {
        let _log = crate::tests::test_init_log();

        let mut test = TurnTest::builder().build();
        let now = Instant::now();

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
        assert_eq!(expiry, now + Duration::from_secs(240));
        let TurnPollRet::WaitUntil(now) = test.client.poll(expiry) else {
            unreachable!()
        };
        assert_eq!(now, expiry);

        let transmit = test.client.poll_transmit(expiry).unwrap();
        let msg = Message::from_bytes(&transmit.data).unwrap();
        assert_eq!(msg.method(), CREATE_PERMISSION);
        let Ok(Some(transmit)) = test.server.recv(transmit, now) else {
            unreachable!();
        };
        test.client.recv(transmit, expiry);
        test.validate_client_permission_state(expiry);

        test.sendrecv_data(expiry);
    }

    #[test]
    fn test_turn_create_permission_timeout() {
        let _log = crate::tests::test_init_log();

        let mut test = TurnTest::builder().build();
        let now = Instant::now();

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
        assert_eq!(expiry, now + Duration::from_secs(240));
        let TurnPollRet::WaitUntil(now) = test.client.poll(expiry) else {
            unreachable!()
        };
        assert_eq!(now, expiry);

        let transmit = test.client.poll_transmit(expiry).unwrap();
        let msg = Message::from_bytes(&transmit.data).unwrap();
        assert_eq!(msg.method(), CREATE_PERMISSION);
        // drop the create permission refresh (and retransmits)
        let mut expiry = now;
        for _i in 0..8 {
            let TurnPollRet::WaitUntil(new_now) = test.client.poll(expiry) else {
                unreachable!()
            };
            let _ = test.client.poll_transmit(new_now);
            expiry = new_now;
        }
        assert_eq!(expiry, now + Duration::from_secs(60));
        let TurnPollRet::WaitUntil(now) = test.client.poll(expiry) else {
            unreachable!()
        };

        assert!(!test
            .client
            .have_permission(TransportType::Udp, test.peer_addr, now));
        let Some(TurnEvent::PermissionCreateFailed(_transport, ip)) = test.client.poll_event()
        else {
            unreachable!();
        };
        assert_eq!(ip, test.peer_addr.ip());
    }

    #[test]
    fn test_turn_channel_bind_refresh() {
        let _log = crate::tests::test_init_log();

        let mut test = TurnTest::builder().build();
        let now = Instant::now();

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
            assert_eq!(expiry, now + Duration::from_secs(240));
            let TurnPollRet::WaitUntil(now) = test.client.poll(expiry) else {
                unreachable!()
            };
            assert_eq!(now, expiry);

            let transmit = test.client.poll_transmit(now).unwrap();
            let msg = Message::from_bytes(&transmit.data).unwrap();
            assert_eq!(msg.method(), CREATE_PERMISSION);
            let Ok(Some(transmit)) = test.server.recv(transmit, now) else {
                unreachable!();
            };
            test.client.recv(transmit, now);
            test.validate_client_permission_state(now);
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
        test.client.recv(transmit, expiry);

        test.sendrecv_data_channel(expiry);
    }

    #[test]
    fn test_client_receive_offpath_data() {
        let _log = crate::tests::test_init_log();

        let now = Instant::now();

        let mut test = turn_allocate_permission(TransportType::Udp, now);
        let data = [3; 9];
        let TurnRecvRet::Ignored(transmit) = test.client.recv(
            Transmit::new(
                &data,
                TransportType::Udp,
                test.peer_addr,
                test.client.local_addr(),
            ),
            now,
        ) else {
            unreachable!();
        };
        assert_eq!(transmit.data, &data);
        assert_eq!(transmit.transport, TransportType::Udp);
        assert_eq!(transmit.from, test.peer_addr);
        assert_eq!(transmit.to, test.client.local_addr());
    }

    #[test]
    fn test_server_receive_offpath_data() {
        let _log = crate::tests::test_init_log();

        let now = Instant::now();

        let mut test = turn_allocate_permission(TransportType::Udp, now);
        let data = [3; 9];
        assert!(test
            .server
            .recv(
                Transmit::new(
                    &data,
                    TransportType::Udp,
                    test.peer_addr,
                    test.client.local_addr(),
                ),
                now,
            )
            .unwrap()
            .is_none());
    }
}
