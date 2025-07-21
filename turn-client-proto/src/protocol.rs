// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! # Protocl module
//!
//! Contains the protocol state machine for a TURN client.

use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};
use std::ops::Range;
use std::time::{Duration, Instant};
use stun_proto::agent::{HandleStunReply, StunAgent, StunAgentPollRet, Transmit};
use stun_proto::types::attribute::{ErrorCode, Nonce, Realm, Username};
use stun_proto::types::data::Data;
use stun_proto::types::message::{
    LongTermCredentials, Message, MessageClass, MessageIntegrityCredentials, TransactionId,
};
use stun_proto::types::TransportType;
use tracing::{error, info, trace, warn};
use turn_types::attribute::{ChannelNumber, Lifetime, XorPeerAddress};
use turn_types::attribute::{Data as AData, DontFragment, RequestedTransport, XorRelayedAddress};
use turn_types::channel::ChannelData;
use turn_types::message::*;
use turn_types::stun::message::MessageWriteVec;
use turn_types::stun::prelude::{MessageWrite, MessageWriteExt};
use turn_types::TurnCredentials;

use crate::common::{
    BindChannelError, CreatePermissionError, DelayedMessageOrChannelSend, DeleteError,
    TransmitBuild, TurnEvent, TurnPollRet,
};

/// Buffer before an expiration time before sending a refresh packet.
static EXPIRY_BUFFER: Duration = Duration::from_secs(60);
/// Lifetime of a permission.
static PERMISSION_DURATION: Duration = Duration::from_secs(300);
/// Lifetime of a channel
static CHANNEL_DURATION: Duration = Duration::from_secs(600);
/// Lifetime of a removed channel before the channel can be reused
static CHANNEL_REMOVE_DURATION: Duration = Duration::from_secs(300);

#[derive(Debug)]
pub(crate) struct TurnClientProtocol {
    stun_agent: StunAgent,
    credentials: TurnCredentials,
    state: AuthState,
    allocations: Vec<Allocation>,

    pending_transmits: VecDeque<Transmit<Data<'static>>>,

    pending_events: VecDeque<TurnEvent>,
}

impl TurnClientProtocol {
    pub(crate) fn new(stun_agent: StunAgent, credentials: TurnCredentials) -> Self {
        turn_types::debug_init();
        Self {
            stun_agent,
            credentials,
            state: AuthState::Initial,
            allocations: vec![],
            pending_transmits: VecDeque::default(),
            pending_events: VecDeque::default(),
        }
    }

    fn send_initial_request(&mut self, now: Instant) -> (Transmit<Data<'static>>, TransactionId) {
        let mut msg = Message::builder_request(ALLOCATE, MessageWriteVec::new());
        let lifetime = Lifetime::new(3600);
        msg.add_attribute(&lifetime).unwrap();
        let requested = RequestedTransport::new(RequestedTransport::UDP);
        msg.add_attribute(&requested).unwrap();
        let dont_fragment = DontFragment::new();
        msg.add_attribute(&dont_fragment).unwrap();
        let transaction_id = msg.transaction_id();
        let msg = msg.finish();

        let remote_addr = self.stun_agent.remote_addr().unwrap();
        let transmit = self
            .stun_agent
            .send_request(&msg, remote_addr, now)
            .unwrap();
        (transmit.into_owned(), transaction_id)
    }

    fn send_authenticating_request(
        &mut self,
        credentials: LongTermCredentials,
        nonce: &str,
        now: Instant,
    ) -> (Transmit<Data<'static>>, TransactionId) {
        let mut builder = Message::builder_request(ALLOCATE, MessageWriteVec::new());
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
        let msg = builder.finish();
        let transmit = self
            .stun_agent
            .send_request(&msg, self.stun_agent.remote_addr().unwrap(), now)
            .unwrap();
        (transmit.into_owned(), transaction_id)
    }

    fn update_permission_state(
        allocations: &mut [Allocation],
        pending_events: &mut VecDeque<TurnEvent>,
        msg: Message<'_>,
        now: Instant,
    ) -> bool {
        if let Some((alloc_idx, pending_idx)) =
            allocations
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
            let (mut permission, _transaction_id) = allocations[alloc_idx]
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
                pending_events.push_back(TurnEvent::PermissionCreateFailed(
                    allocations[alloc_idx].transport,
                    permission.ip,
                ));
            } else {
                pending_events.push_front(TurnEvent::PermissionCreated(
                    allocations[alloc_idx].transport,
                    permission.ip,
                ));
                permission.expires_at = now + PERMISSION_DURATION;
                permission.expired = false;
                allocations[alloc_idx].permissions.push(permission);
            }
            true
        } else if let Some((alloc_idx, existing_idx)) =
            allocations
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
            let transport = allocations[alloc_idx].transport;
            let permission = &mut allocations[alloc_idx].permissions[existing_idx];
            permission.pending_refresh = None;
            if msg.has_class(stun_proto::types::message::MessageClass::Error) {
                warn!(
                    "Received error response to create permission request for {}",
                    permission.ip
                );
                permission.expired = true;
                permission.expires_at = now;
                pending_events
                    .push_back(TurnEvent::PermissionCreateFailed(transport, permission.ip));
            } else {
                permission.expires_at = now + PERMISSION_DURATION;
            }
            true
        } else {
            false
        }
    }

    fn handle_unvalidated_stun(
        stun_agent: &mut StunAgent,
        state: &mut AuthState,
        allocations: &mut [Allocation],
        pending_transmits: &mut VecDeque<Transmit<Data<'static>>>,
        msg: Message<'_>,
        credentials: LongTermCredentials,
        now: Instant,
    ) -> InternalHandleStunReply {
        // only handle STALE_NONCE errors here as that is the only unvalidated case that we have.
        if !msg.has_class(MessageClass::Error) {
            return InternalHandleStunReply::Ignored;
        }
        let Ok(error) = msg.attribute::<ErrorCode>() else {
            return InternalHandleStunReply::Ignored;
        };
        if error.code() != ErrorCode::STALE_NONCE {
            return InternalHandleStunReply::Ignored;
        }
        let Ok(nonce) = msg
            .attribute::<Nonce>()
            .map(|nonce| nonce.nonce().to_string())
        else {
            return InternalHandleStunReply::Ignored;
        };
        let Ok(realm) = msg
            .attribute::<Realm>()
            .map(|realm| realm.realm().to_string())
        else {
            return InternalHandleStunReply::Ignored;
        };

        let mut new_credentials = None;

        'outer: for alloc in allocations.iter_mut() {
            if let Some((pending, _lifetime)) = alloc.pending_refresh {
                if pending == msg.transaction_id() {
                    let credentials = LongTermCredentials::new(
                        credentials.username().to_string(),
                        credentials.password().to_string(),
                        realm,
                    );
                    info!("Received STALE_NONCE in response to REFRESH for transaction {pending}, resending");
                    let (transmit, transaction_id, lifetime) =
                        Self::send_refresh(stun_agent, credentials.clone(), &nonce, 1800, now);
                    pending_transmits.push_back(transmit);
                    new_credentials = Some(credentials);
                    alloc.pending_refresh = Some((transaction_id, lifetime));
                    stun_agent.remove_outstanding_request(msg.transaction_id());
                    break 'outer;
                }
            }
            for permission in alloc.permissions.iter_mut() {
                if permission
                    .pending_refresh
                    .is_some_and(|pending| pending == msg.transaction_id())
                {
                    info!("Received STALE_NONCE in response to CREATE_PERMISSION {} for transaction {}, resending", permission.ip, msg.transaction_id());
                    let credentials = LongTermCredentials::new(
                        credentials.username().to_string(),
                        credentials.password().to_string(),
                        realm,
                    );
                    let peer_addr = permission.ip;
                    let (transmit, transaction_id) = Self::send_create_permission_request(
                        stun_agent,
                        credentials.clone(),
                        &nonce,
                        peer_addr,
                        now,
                    );
                    permission.pending_refresh = Some(transaction_id);
                    pending_transmits.push_back(transmit);
                    new_credentials = Some(credentials);
                    stun_agent.remove_outstanding_request(msg.transaction_id());
                    break 'outer;
                }
            }
            for channel in alloc.channels.iter_mut() {
                if channel
                    .pending_refresh
                    .is_some_and(|pending| pending == msg.transaction_id())
                {
                    info!("Received STALE_NONCE in response to BIND_CHANNEL {} for transaction {}, resending", channel.peer_addr, msg.transaction_id());
                    let credentials = LongTermCredentials::new(
                        credentials.username().to_string(),
                        credentials.password().to_string(),
                        realm,
                    );
                    let (transmit, transaction_id) = Self::send_channel_bind_request(
                        stun_agent,
                        credentials.clone(),
                        &nonce,
                        channel.id,
                        channel.peer_addr,
                        now,
                    );
                    channel.pending_refresh = Some(transaction_id);
                    pending_transmits.push_back(transmit);
                    new_credentials = Some(credentials);
                    stun_agent.remove_outstanding_request(msg.transaction_id());
                    break 'outer;
                }
            }
        }

        if let Some(credentials) = new_credentials {
            match state {
                AuthState::Error | AuthState::Initial | AuthState::InitialSent(_) => unreachable!(),
                AuthState::Authenticating {
                    credentials: _,
                    nonce: _,
                    transaction_id: _,
                } => unreachable!(),
                AuthState::Authenticated {
                    credentials: _,
                    nonce: _,
                } => *state = AuthState::Authenticated { credentials, nonce },
            }
            InternalHandleStunReply::Handled
        } else {
            InternalHandleStunReply::Ignored
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn handle_stun(
        stun_agent: &mut StunAgent,
        state: &mut AuthState,
        allocations: &mut Vec<Allocation>,
        pending_transmits: &mut VecDeque<Transmit<Data<'static>>>,
        pending_events: &mut VecDeque<TurnEvent>,
        msg: Message<'_>,
        transport: TransportType,
        from: SocketAddr,
        credentials: LongTermCredentials,
        now: Instant,
    ) -> InternalHandleStunReply {
        trace!("received STUN message {msg}");
        let msg = match stun_agent.handle_stun(msg, from) {
            HandleStunReply::Drop => return InternalHandleStunReply::Ignored,
            HandleStunReply::IncomingStun(msg) => msg,
            HandleStunReply::ValidatedStunResponse(msg) => msg,
            HandleStunReply::UnvalidatedStunResponse(msg) => {
                return Self::handle_unvalidated_stun(
                    stun_agent,
                    state,
                    allocations,
                    pending_transmits,
                    msg,
                    credentials,
                    now,
                )
            }
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
                        for alloc in allocations.iter_mut() {
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
                        allocations.clear();
                        *state = AuthState::Error;
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
                    if Self::update_permission_state(allocations, pending_events, msg, now) {
                        InternalHandleStunReply::Handled
                    } else {
                        InternalHandleStunReply::Ignored
                    }
                }
                CHANNEL_BIND => {
                    if let Some((alloc_idx, channel_idx)) =
                        allocations
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
                        let (mut channel, _transaction_id) = allocations[alloc_idx]
                            .pending_channels
                            .swap_remove_back(channel_idx)
                            .unwrap();
                        if msg.has_class(stun_proto::types::message::MessageClass::Error) {
                            error!("Received error response to channel bind request");
                            // TODO: handle
                            return InternalHandleStunReply::Handled;
                        }
                        info!("Succesfully created/refreshed {channel:?}");
                        Self::update_permission_state(allocations, pending_events, msg, now);
                        if let Some(existing_idx) =
                            allocations[alloc_idx].channels.iter().enumerate().find_map(
                                |(idx, existing_channel)| {
                                    if channel.peer_addr == existing_channel.peer_addr {
                                        Some(idx)
                                    } else {
                                        None
                                    }
                                },
                            )
                        {
                            allocations[alloc_idx].channels[existing_idx].expires_at =
                                now + CHANNEL_DURATION;
                        } else {
                            channel.expires_at = now + CHANNEL_DURATION;
                            allocations[alloc_idx].channels.push(channel);
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
                    let Ok((offset, data)) = msg.attribute_and_offset::<AData>() else {
                        return InternalHandleStunReply::Ignored;
                    };
                    InternalHandleStunReply::PeerData {
                        range: offset + 4..offset + 4 + data.data().len(),
                        transport,
                        peer: peer_addr.addr(msg.transaction_id()),
                    }
                }
                _ => InternalHandleStunReply::Ignored, // All other indications should be ignored
            }
        }
    }

    fn send_refresh(
        stun_agent: &mut StunAgent,
        credentials: LongTermCredentials,
        nonce: &str,
        lifetime: u32,
        now: Instant,
    ) -> (Transmit<Data<'static>>, TransactionId, u32) {
        let mut refresh = Message::builder_request(REFRESH, MessageWriteVec::new());
        let transaction_id = refresh.transaction_id();
        let lt = Lifetime::new(lifetime);
        refresh.add_attribute(&lt).unwrap();
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
        let remote_addr = stun_agent.remote_addr().unwrap();
        let refresh = refresh.finish();
        let transmit = stun_agent.send_request(&refresh, remote_addr, now).unwrap();
        (transmit.into_owned(), transaction_id, lifetime)
    }

    fn send_create_permission_request(
        stun_agent: &mut StunAgent,
        credentials: LongTermCredentials,
        nonce: &str,
        peer_addr: IpAddr,
        now: Instant,
    ) -> (Transmit<Data<'static>>, TransactionId) {
        let mut builder = Message::builder_request(CREATE_PERMISSION, MessageWriteVec::new());
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
        let msg = builder.finish();
        let transmit = stun_agent
            .send_request(&msg, stun_agent.remote_addr().unwrap(), now)
            .unwrap();
        (transmit.into_owned(), transaction_id)
    }

    fn send_channel_bind_request(
        stun_agent: &mut StunAgent,
        credentials: LongTermCredentials,
        nonce: &str,
        id: u16,
        peer_addr: SocketAddr,
        now: Instant,
    ) -> (Transmit<Data<'static>>, TransactionId) {
        let mut builder = Message::builder_request(CHANNEL_BIND, MessageWriteVec::new());
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
        let msg = builder.finish();

        let transmit = stun_agent
            .send_request(&msg, stun_agent.remote_addr().unwrap(), now)
            .unwrap();
        (transmit.into_owned(), transaction_id)
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

    #[tracing::instrument(
        name = "turn_handle_channel",
        skip(self, transmit),
        fields(
            transport = ?transmit.transport,
            from = ?transmit.from,
            to = ?transmit.to,
            data_len = transmit.data.as_ref().len(),
        )
    )]
    pub(crate) fn handle_channel<'a>(
        &mut self,
        transmit: Transmit<ChannelData<'a>>,
        now: Instant,
    ) -> TurnProtocolChannelRecv {
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
            return TurnProtocolChannelRecv::Ignored;
        }

        for alloc in self.allocations.iter_mut() {
            if let Some(chan) = alloc
                .channels
                .iter_mut()
                .find(|chan| chan.id == transmit.data.id())
            {
                return TurnProtocolChannelRecv::PeerData {
                    range: 4..4 + transmit.data.data().len(),
                    transport: alloc.transport,
                    peer: chan.peer_addr,
                };
            }
        }
        TurnProtocolChannelRecv::Ignored
    }

    #[tracing::instrument(
        name = "turn_handle_message",
        skip(self, data),
        fields(
            data_len = data.as_ref().len(),
        )
    )]
    pub(crate) fn handle_message<T: AsRef<[u8]> + std::fmt::Debug>(
        &mut self,
        data: T,
        now: Instant,
    ) -> TurnProtocolRecv<T> {
        let Ok(msg) = Message::from_bytes(data.as_ref()) else {
            return TurnProtocolRecv::Ignored(data);
        };
        let remote_addr = self.remote_addr();
        let (credentials, _nonce) = match &mut self.state {
            AuthState::Error | AuthState::Initial => return TurnProtocolRecv::Ignored(data),
            AuthState::InitialSent(transaction_id) => {
                trace!("received STUN message {msg}");
                let msg = match self.stun_agent.handle_stun(msg, remote_addr) {
                    HandleStunReply::Drop => return TurnProtocolRecv::Handled,
                    HandleStunReply::IncomingStun(_) => return TurnProtocolRecv::Ignored(data),
                    HandleStunReply::ValidatedStunResponse(msg) => msg,
                    HandleStunReply::UnvalidatedStunResponse(_msg) => {
                        return TurnProtocolRecv::Ignored(data)
                    }
                };
                if !msg.is_response() || &msg.transaction_id() != transaction_id {
                    return TurnProtocolRecv::Ignored(data);
                }
                /* The Initial stun request should result in an unauthorized error as there were
                 * no credentials in the initial request */
                if !msg.has_class(stun_proto::types::message::MessageClass::Error) {
                    self.state = AuthState::Error;
                    self.pending_events
                        .push_front(TurnEvent::AllocationCreateFailed);
                    return TurnProtocolRecv::Ignored(data);
                }
                let Ok(error_code) = msg.attribute::<ErrorCode>() else {
                    self.state = AuthState::Error;
                    self.pending_events
                        .push_front(TurnEvent::AllocationCreateFailed);
                    return TurnProtocolRecv::Ignored(data);
                };
                let Ok(realm) = msg.attribute::<Realm>() else {
                    self.state = AuthState::Error;
                    self.pending_events
                        .push_front(TurnEvent::AllocationCreateFailed);
                    return TurnProtocolRecv::Ignored(data);
                };
                let Ok(nonce) = msg.attribute::<Nonce>() else {
                    self.state = AuthState::Error;
                    self.pending_events
                        .push_front(TurnEvent::AllocationCreateFailed);
                    return TurnProtocolRecv::Ignored(data);
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
                        return TurnProtocolRecv::Handled;
                    }
                    ErrorCode::TRY_ALTERNATE => (), // FIXME: implement
                    code => {
                        trace!("Unknown error code returned {code:?}");
                        self.state = AuthState::Error;
                        self.pending_events
                            .push_front(TurnEvent::AllocationCreateFailed);
                    }
                }
                return TurnProtocolRecv::Ignored(data);
            }
            AuthState::Authenticating {
                credentials,
                nonce,
                transaction_id,
            } => {
                trace!("received STUN message {msg}");
                let msg = match self.stun_agent.handle_stun(msg, remote_addr) {
                    HandleStunReply::Drop => return TurnProtocolRecv::Handled,
                    HandleStunReply::IncomingStun(_) => return TurnProtocolRecv::Ignored(data),
                    HandleStunReply::ValidatedStunResponse(msg) => msg,
                    HandleStunReply::UnvalidatedStunResponse(_msg) => {
                        return TurnProtocolRecv::Ignored(data)
                    }
                };
                if !msg.is_response() || &msg.transaction_id() != transaction_id {
                    return TurnProtocolRecv::Ignored(data);
                }
                match msg.class() {
                    stun_proto::types::message::MessageClass::Error => {
                        let Ok(error_code) = msg.attribute::<ErrorCode>() else {
                            self.state = AuthState::Error;
                            return TurnProtocolRecv::Ignored(data);
                        };
                        match error_code.code() {
                            ErrorCode::STALE_NONCE => {
                                let Ok(realm) = msg.attribute::<Realm>() else {
                                    self.state = AuthState::Error;
                                    return TurnProtocolRecv::Ignored(data);
                                };
                                let Ok(nonce) = msg.attribute::<Nonce>() else {
                                    self.state = AuthState::Error;
                                    return TurnProtocolRecv::Ignored(data);
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
                                return TurnProtocolRecv::Handled;
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
                            return TurnProtocolRecv::Ignored(data);
                        };
                        let xor_relayed_address = msg.attribute::<XorRelayedAddress>();
                        let lifetime = msg.attribute::<Lifetime>();
                        let (Ok(xor_relayed_address), Ok(lifetime)) =
                            (xor_relayed_address, lifetime)
                        else {
                            self.state = AuthState::Error;
                            return TurnProtocolRecv::Ignored(data);
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
                        return TurnProtocolRecv::Handled;
                    }
                    _ => (),
                }
                return TurnProtocolRecv::Ignored(data);
            }
            AuthState::Authenticated { credentials, nonce } => (credentials.clone(), nonce),
        };

        // FIXME: TCP allocations
        let transport = self
            .allocations
            .iter()
            .map(|allocation| allocation.transport)
            .next()
            .unwrap();

        match Self::handle_stun(
            &mut self.stun_agent,
            &mut self.state,
            &mut self.allocations,
            &mut self.pending_transmits,
            &mut self.pending_events,
            msg,
            transport,
            remote_addr,
            credentials,
            now,
        ) {
            InternalHandleStunReply::Handled => TurnProtocolRecv::Handled,
            InternalHandleStunReply::Ignored => TurnProtocolRecv::Ignored(data),
            InternalHandleStunReply::PeerData {
                range,
                transport,
                peer,
            } => TurnProtocolRecv::PeerData {
                data,
                range,
                transport,
                peer,
            },
        }
    }

    pub(crate) fn send_to<T: AsRef<[u8]> + std::fmt::Debug>(
        &mut self,
        transport: TransportType,
        to: SocketAddr,
        data: T,
        now: Instant,
    ) -> Result<TransmitBuild<DelayedMessageOrChannelSend<T>>, SendError> {
        if !self.have_permission(transport, to, now) {
            return Err(SendError::NoPermission);
        }

        if let Some(channel) = self.channel(transport, to) {
            if channel.expires_at >= now {
                return Ok(TransmitBuild::new(
                    DelayedMessageOrChannelSend::new_channel(data, channel.id),
                    self.stun_agent.transport(),
                    self.stun_agent.local_addr(),
                    self.stun_agent.remote_addr().unwrap(),
                ));
            }
        }
        Ok(TransmitBuild::new(
            DelayedMessageOrChannelSend::new_message(data, to),
            self.stun_agent.transport(),
            self.stun_agent.local_addr(),
            self.stun_agent.remote_addr().unwrap(),
        ))
    }

    pub(crate) fn transport(&self) -> TransportType {
        self.stun_agent.transport()
    }

    pub(crate) fn local_addr(&self) -> SocketAddr {
        self.stun_agent.local_addr()
    }

    pub(crate) fn remote_addr(&self) -> SocketAddr {
        self.stun_agent.remote_addr().unwrap()
    }

    pub(crate) fn relayed_addresses(
        &self,
    ) -> impl Iterator<Item = (TransportType, SocketAddr)> + '_ {
        self.allocations
            .iter()
            .filter(|allocation| !allocation.expired)
            .map(|allocation| (allocation.transport, allocation.relayed_address))
    }

    pub(crate) fn permissions(
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

    #[tracing::instrument(name = "turn_client_poll", ret, skip(self))]
    pub(crate) fn poll(&mut self, now: Instant) -> TurnPollRet {
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
                            if alloc.lifetime > EXPIRY_BUFFER * 2 {
                                EXPIRY_BUFFER
                            } else {
                                alloc.lifetime / 2
                            }
                        } else {
                            Duration::ZERO
                        };
                    if alloc.pending_refresh.is_none() && expires_at <= now {
                        let (transmit, transaction_id, lifetime) = Self::send_refresh(
                            &mut self.stun_agent,
                            credentials.clone(),
                            nonce,
                            1800,
                            now,
                        );
                        alloc.pending_refresh = Some((transaction_id, lifetime));
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
                        let refresh_time = channel.expires_at - EXPIRY_BUFFER;
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
                        let refresh_time = permission.expires_at - EXPIRY_BUFFER;
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

    #[tracing::instrument(
        name = "turn_client_poll_transmit"
        skip(self)
    )]
    pub(crate) fn poll_transmit(&mut self, now: Instant) -> Option<Transmit<Data<'static>>> {
        if let Some(transmit) = self.pending_transmits.pop_front() {
            return Some(transmit);
        }
        if let Some(transmit) = self
            .stun_agent
            .poll_transmit(now)
            .map(|transmit| transmit.reinterpret_data(|data| Data::from(data).into_owned()))
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
    pub(crate) fn poll_event(&mut self) -> Option<TurnEvent> {
        self.pending_events.pop_back()
    }

    /// Remove the allocation/s on the server.
    pub(crate) fn delete(&mut self, now: Instant) -> Result<(), DeleteError> {
        let mut builder = Message::builder_request(REFRESH, MessageWriteVec::new());
        let transaction_id = builder.transaction_id();

        let AuthState::Authenticated { credentials, nonce } = &self.state else {
            return Err(DeleteError::NoAllocation);
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
        let msg = builder.finish();

        let transmit = self
            .stun_agent
            .send_request(&msg, self.stun_agent.remote_addr().unwrap(), now)
            .unwrap();
        info!("Deleting allocations");
        for alloc in self.allocations.iter_mut() {
            alloc.permissions.clear();
            alloc.channels.clear();
            alloc.expires_at = now;
            alloc.expired = true;
            alloc.pending_refresh = Some((transaction_id, 0));
        }
        self.pending_transmits.push_back(transmit.into_owned());
        Ok(())
    }

    #[tracing::instrument(name = "turn_client_create_permission", skip(self, now), err)]
    pub(crate) fn create_permission(
        &mut self,
        transport: TransportType,
        peer_addr: IpAddr,
        now: Instant,
    ) -> Result<(), CreatePermissionError> {
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
        self.pending_transmits.push_back(transmit);
        Ok(())
    }

    pub(crate) fn bind_channel(
        &mut self,
        transport: TransportType,
        peer_addr: SocketAddr,
        now: Instant,
    ) -> Result<(), BindChannelError> {
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
                    channel.expires_at + CHANNEL_REMOVE_DURATION <= now && channel.id == channel_id
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
        self.pending_transmits.push_back(transmit.into_owned());
        Ok(())
    }

    pub(crate) fn error(&mut self) {
        self.state = AuthState::Error;
    }
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
enum InternalHandleStunReply {
    Handled,
    Ignored,
    PeerData {
        range: Range<usize>,
        transport: TransportType,
        peer: SocketAddr,
    },
}

#[derive(Debug)]
pub(crate) enum TurnProtocolRecv<T: AsRef<[u8]> + std::fmt::Debug> {
    Handled,
    Ignored(T),
    PeerData {
        data: T,
        range: Range<usize>,
        transport: TransportType,
        peer: SocketAddr,
    },
}

#[derive(Debug)]
pub(crate) enum TurnProtocolChannelRecv {
    Ignored,
    PeerData {
        range: Range<usize>,
        transport: TransportType,
        peer: SocketAddr,
    },
}

#[cfg(test)]
mod tests {
    use stun_proto::types::{
        attribute::{MessageIntegrity, MessageIntegritySha256, XorMappedAddress},
        message::Method,
        prelude::AttributeStaticType,
    };
    use turn_types::{
        attribute::XorRelayedAddress, channel::ChannelData, stun::message::MessageType,
    };

    use crate::common::{DelayedMessageOrChannelSend, DelayedTransmitBuild, TransmitBuild};

    use super::*;
    use turn_server_proto::{TurnServer, TurnServerPollRet};

    #[test]
    fn test_turn_client_protocol_new_properties() {
        let _log = crate::tests::test_init_log();

        let local_addr = "192.168.0.1:31234".parse().unwrap();
        let remote_addr = "10.0.0.1:3478".parse().unwrap();
        let credentials = TurnCredentials::new("tuser", "tpass");

        let stun_agent = StunAgent::builder(TransportType::Udp, local_addr)
            .remote_addr(remote_addr)
            .build();
        let mut client = TurnClientProtocol::new(stun_agent, credentials);
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

    fn transmit_send_build<T: DelayedTransmitBuild + std::fmt::Debug>(
        transmit: TransmitBuild<T>,
    ) -> Transmit<Data<'static>> {
        transmit
            .build()
            .reinterpret_data(|data| Data::from(data.into_boxed_slice()))
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
            server.set_nonce_expiry_duration(Duration::from_secs(30));
            let stun_agent = StunAgent::builder(self.client_transport, self.client_addr)
                .remote_addr(self.turn_listen_addr)
                .build();
            let client = TurnClientProtocol::new(stun_agent, self.credentials);
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
        client: TurnClientProtocol,
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
            self.client.handle_message(transmit.data, now);

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
                self.client.handle_message(transmit.data, now),
                TurnProtocolRecv::Handled
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
                self.client.handle_message(transmit.data, now),
                TurnProtocolRecv::Handled
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
            self.client.handle_message(transmit.data, now);
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
                self.client.handle_message(transmit.data, now),
                TurnProtocolRecv::Handled
            ));
            self.validate_client_permission_state(now);
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
                    self.client.handle_message(transmit.data, now),
                    TurnProtocolRecv::Handled
                ));
                None
            } else {
                Some(transmit)
            }
        }

        fn validate_client_permission_state(&self, now: Instant) {
            let Some(permision) = self
                .client
                .permission(TransportType::Udp, self.peer_addr.ip())
            else {
                unreachable!();
            };
            assert_eq!(permision.expires_at, now + PERMISSION_DURATION);
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
            self.client.handle_message(transmit.data, now);
            let permision = self
                .client
                .permission(TransportType::Udp, self.peer_addr.ip())
                .unwrap();
            assert_eq!(permision.expires_at, now + PERMISSION_DURATION);
            let channel = self
                .client
                .channel(TransportType::Udp, self.peer_addr)
                .unwrap();
            assert_eq!(channel.expires_at, now + CHANNEL_DURATION);
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
            let TurnProtocolRecv::PeerData {
                data,
                range,
                transport: TransportType::Udp,
                peer,
            } = self.client.handle_message(transmit.data, now)
            else {
                unreachable!();
            };
            assert_eq!(peer, self.peer_addr);
            assert_eq!(&data[range.start..range.end], sent_data);
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
        test.server
            .set_nonce_expiry_duration(Duration::from_secs(9000));
        let now = Instant::now();

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
        test.client.handle_message(transmit.data, now);
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
            MessageType::from_class_method(MessageClass::Indication, Method::new(0x1432)),
            TransactionId::generate(),
            MessageWriteVec::new(),
        );
        let realm = Realm::new("realm").unwrap();
        msg.add_attribute(&realm).unwrap();
        let data = msg.finish();
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
        assert_eq!(expiry, now + PERMISSION_DURATION - EXPIRY_BUFFER);
        let TurnPollRet::WaitUntil(now) = test.client.poll(expiry) else {
            unreachable!()
        };
        assert_eq!(now, expiry);

        let create_permission = |test: &mut TurnTest, now: Instant| -> Transmit<Vec<u8>> {
            let transmit = test.client.poll_transmit(now).unwrap();
            let msg = Message::from_bytes(&transmit.data).unwrap();
            assert_eq!(msg.method(), CREATE_PERMISSION);
            let Ok(Some(transmit)) = test.server.recv(transmit, now) else {
                unreachable!();
            };
            transmit
        };

        let transmit = create_permission(&mut test, now);
        let transmit = if let Some(transmit) = test.maybe_handles_stale_nonce(transmit, now) {
            transmit
        } else {
            create_permission(&mut test, now)
        };
        test.client.handle_message(transmit.data, expiry);
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
        for _i in 0..8 {
            let TurnPollRet::WaitUntil(new_now) = test.client.poll(expiry) else {
                unreachable!()
            };
            let _ = test.client.poll_transmit(new_now);
            expiry = new_now;
        }
        assert_eq!(expiry, now + EXPIRY_BUFFER);
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
            assert_eq!(expiry, now + PERMISSION_DURATION - EXPIRY_BUFFER);
            let TurnPollRet::WaitUntil(now) = test.client.poll(expiry) else {
                unreachable!()
            };
            assert_eq!(now, expiry);

            let create_permission = move |test: &mut TurnTest, now: Instant| -> Transmit<Vec<u8>> {
                let transmit = test.client.poll_transmit(now).unwrap();
                let msg = Message::from_bytes(&transmit.data).unwrap();
                assert_eq!(msg.method(), CREATE_PERMISSION);
                let Ok(Some(transmit)) = test.server.recv(transmit, now) else {
                    unreachable!();
                };
                transmit
            };

            let transmit = create_permission(&mut test, now);
            let transmit = if let Some(transmit) = test.maybe_handles_stale_nonce(transmit, now) {
                transmit
            } else {
                create_permission(&mut test, now)
            };
            test.client.handle_message(transmit.data, now);
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
        test.client.handle_message(transmit.data, expiry);

        test.sendrecv_data_channel(expiry);
    }

    #[test]
    fn test_client_receive_offpath_data() {
        let _log = crate::tests::test_init_log();

        let now = Instant::now();

        let mut test = turn_allocate_permission(TransportType::Udp, now);
        let data = [0x40, 0, 0, 14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let TurnProtocolRecv::Ignored(ignored) = test.client.handle_message(&data, now) else {
            unreachable!();
        };
        assert_eq!(ignored, &data);
        let channel = ChannelData::parse(ignored).unwrap();
        let TurnProtocolChannelRecv::Ignored = test.client.handle_channel(
            Transmit::new(
                channel,
                TransportType::Udp,
                test.peer_addr,
                test.client.local_addr(),
            ),
            now,
        ) else {
            unreachable!();
        };
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
