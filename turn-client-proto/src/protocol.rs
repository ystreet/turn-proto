// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! TURN protocol state machine.
//!
//! Contains the protocol state machine for a TURN client.

use alloc::collections::VecDeque;
use alloc::vec;
use alloc::vec::Vec;
use core::net::{IpAddr, SocketAddr};
use core::ops::Range;
use core::time::Duration;
use stun_proto::agent::{StunAgent, StunAgentPollRet, Transmit};
use stun_proto::auth::{AuthErrorReason, LongTermClientAuth, LongTermValidation};
use stun_proto::types::attribute::ErrorCode;
use stun_proto::types::data::Data;
use stun_proto::types::message::{Message, MessageClass, TransactionId};
use stun_proto::types::TransportType;
use stun_proto::Instant;
use tracing::{debug, info, trace, warn};
use turn_types::attribute::{
    AdditionalAddressFamily, ChannelNumber, ConnectionId, Icmp, Lifetime, RequestedAddressFamily,
    XorPeerAddress, XorRelayedAddress,
};
use turn_types::attribute::{Data as AData, DontFragment, RequestedTransport};
use turn_types::channel::ChannelData;
use turn_types::message::*;
use turn_types::stun::message::{MessageHeader, MessageType, MessageWriteVec};
use turn_types::stun::prelude::{
    Attribute, AttributeExt, AttributeFromRaw, AttributeStaticType, MessageWrite, MessageWriteExt,
};
use turn_types::AddressFamily;

use crate::api::{
    BindChannelError, CreatePermissionError, DataRangeOrOwned, DelayedMessageOrChannelSend,
    DeleteError, SendError, Socket5Tuple, TcpAllocateError, TcpConnectError, TransmitBuild,
    TurnEvent, TurnPeerData, TurnPollRet, TurnRecvRet,
};
use crate::tcp::ensure_data_owned;

/// Buffer before an expiration time before sending a refresh packet.
pub(crate) static EXPIRY_BUFFER: Duration = Duration::from_secs(60);
/// Lifetime of a permission.
pub(crate) static PERMISSION_DURATION: Duration = Duration::from_secs(300);
/// Lifetime of a channel
pub(crate) static CHANNEL_DURATION: Duration = Duration::from_secs(600);
/// Lifetime of a removed channel before the channel can be reused
pub(crate) static CHANNEL_REMOVE_DURATION: Duration = Duration::from_secs(300);
/// Timeout for a TCP STUN request to expire.
pub(crate) static TCP_STUN_REQUEST_TIMEOUT: Duration = Duration::from_millis(39500);

#[derive(Debug)]
pub(crate) struct TurnClientProtocol {
    allocation_transport: TransportType,
    families: smallvec::SmallVec<[AddressFamily; 2]>,
    stun_agent: StunAgent,
    stun_auth: LongTermClientAuth,
    state: AuthState,
    allocations: Vec<Allocation>,

    pending_transmits: VecDeque<Transmit<Data<'static>>>,

    pending_events: VecDeque<TurnEvent>,
    pending_socket_removal: VecDeque<Socket5Tuple>,
}

impl TurnClientProtocol {
    pub(crate) fn new(
        stun_agent: StunAgent,
        stun_auth: LongTermClientAuth,
        allocation_transport: TransportType,
        address_families: &[AddressFamily],
    ) -> Self {
        turn_types::debug_init();
        let families = address_families.iter().cloned().fold(
            smallvec::SmallVec::with_capacity(address_families.len()),
            |mut ret, fam| {
                if !ret.contains(&fam) {
                    ret.push(fam);
                }
                ret
            },
        );
        if families.is_empty() {
            panic!("Incorrect number of address families");
        }
        if allocation_transport == TransportType::Tcp
            && stun_agent.transport() != TransportType::Tcp
        {
            panic!("Cannot create TCP allocation without a TCP client connection");
        }
        Self {
            allocation_transport,
            families,
            stun_agent,
            stun_auth,
            state: AuthState::Initial,
            allocations: vec![],
            pending_transmits: VecDeque::default(),
            pending_events: VecDeque::default(),
            pending_socket_removal: VecDeque::default(),
        }
    }

    fn send_initial_request(&mut self, now: Instant) -> (Transmit<Data<'static>>, TransactionId) {
        info!("sending initial ALLOCATE");
        let lifetime = Lifetime::new(1800);
        let requested = match self.allocation_transport {
            TransportType::Udp => RequestedTransport::new(RequestedTransport::UDP),
            TransportType::Tcp => RequestedTransport::new(RequestedTransport::TCP),
        };
        let dont_fragment = DontFragment::new();
        let mut msg = Message::builder_request(
            ALLOCATE,
            MessageWriteVec::with_capacity(
                MessageHeader::LENGTH
                    + lifetime.padded_len()
                    + requested.padded_len()
                    + dont_fragment.padded_len()
                    + 8 * self.families.len(),
            ),
        );
        msg.add_attribute(&lifetime).unwrap();
        msg.add_attribute(&requested).unwrap();
        msg.add_attribute(&dont_fragment).unwrap();
        if self.families.len() > 1 {
            // This is the RFC 8656 path where a single client transport produces multiple
            // allocations on the server
            for fam in self.families.iter().cloned() {
                if fam != AddressFamily::IPV4 {
                    msg.add_attribute(&AdditionalAddressFamily::new(fam))
                        .unwrap();
                }
            }
        } else if self.families.is_empty() {
            // Checked in new()
            unreachable!();
        } else if self.families[0] == AddressFamily::IPV6 {
            // This is the RFC 6156 path (or RFC 8656 if only a single IPV6 allocation is required)
            msg.add_attribute(&RequestedAddressFamily::new(AddressFamily::IPV6))
                .unwrap();
        }
        let transaction_id = msg.transaction_id();
        let msg = msg.finish();

        let remote_addr = self.stun_agent.remote_addr().unwrap();
        let transmit = self
            .stun_agent
            .send_request(&msg, remote_addr, now)
            .unwrap();
        (transmit.into_owned(), transaction_id)
    }

    #[allow(clippy::too_many_arguments)]
    fn send_authenticating_request(
        stun_agent: &mut StunAgent,
        stun_auth: &mut LongTermClientAuth,
        allocation_transport: TransportType,
        address_families: &[AddressFamily],
        now: Instant,
    ) -> (Transmit<Data<'static>>, TransactionId) {
        info!("sending authenticated ALLOCATE");
        let requested_transport = match allocation_transport {
            TransportType::Udp => RequestedTransport::new(RequestedTransport::UDP),
            TransportType::Tcp => RequestedTransport::new(RequestedTransport::TCP),
        };
        let lifetime = Lifetime::new(1800);
        let mut builder = Message::builder_request(
            ALLOCATE,
            MessageWriteVec::with_capacity(
                MessageHeader::LENGTH
                    + lifetime.padded_len()
                    + requested_transport.padded_len()
                    + 8 * address_families.len()
                    + stun_auth.message_signature_bytes(),
            ),
        );
        builder.add_attribute(&requested_transport).unwrap();
        builder.add_attribute(&lifetime).unwrap();
        if address_families.len() > 1 {
            // This is the RFC 8656 path where a single client transport produces multiple
            // allocations on the server
            for fam in address_families.iter().cloned() {
                if fam != AddressFamily::IPV4 {
                    builder
                        .add_attribute(&AdditionalAddressFamily::new(fam))
                        .unwrap();
                }
            }
        } else if address_families.is_empty() {
            // Checked in new()
            unreachable!();
        } else if address_families[0] == AddressFamily::IPV6 {
            // This is the RFC 6156 path (or RFC 8656 if only a single IPV6 allocation is required)
            builder
                .add_attribute(&RequestedAddressFamily::new(AddressFamily::IPV6))
                .unwrap();
        }
        let transaction_id = builder.transaction_id();
        let remote_addr = stun_agent.remote_addr().unwrap();
        let builder = stun_auth.sign_outgoing_message(builder).unwrap();
        let msg = builder.finish();
        let transmit = stun_agent.send_request(&msg, remote_addr, now).unwrap();
        (transmit.into_owned(), transaction_id)
    }

    /// Update permission state on a success response for anything the resets the permission expiry
    /// time (CREATE_PERMISSION, CHANNEL_BIND, etc).
    fn update_permission_state(
        allocations: &mut [Allocation],
        pending_events: &mut VecDeque<TurnEvent>,
        msg: &Message<'_>,
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
            if msg.has_class(stun_proto::types::message::MessageClass::Error) {
                warn!(
                    "Received error response to create permission request for {}",
                    permission.ip
                );
                permission.expired = true;
                permission.expires_at = now;
                permission.pending_refresh = None;
                pending_events.push_front(TurnEvent::PermissionCreateFailed(
                    allocations[alloc_idx].transport,
                    permission.ip,
                ));
            } else {
                info!("Succesfully created {permission:?}");
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

    #[allow(clippy::too_many_arguments)]
    fn handle_resend_request(
        stun_agent: &mut StunAgent,
        stun_auth: &mut LongTermClientAuth,
        state: &mut AuthState,
        allocations: &mut [Allocation],
        allocation_transport: TransportType,
        address_families: &[AddressFamily],
        pending_transmits: &mut VecDeque<Transmit<Data<'static>>>,
        msg: &Message<'_>,
        now: Instant,
    ) -> TurnProtocolRecv {
        // only handle STALE_NONCE errors here as that is the only unvalidated case that we have.
        let mut resent = false;
        debug!("state: {:?}", state);
        if let AuthState::Authenticating(transaction_id) | AuthState::InitialSent(transaction_id) =
            state
        {
            if msg.transaction_id() == *transaction_id {
                let (transmit, new_transaction_id) = Self::send_authenticating_request(
                    stun_agent,
                    stun_auth,
                    allocation_transport,
                    address_families,
                    now,
                );
                pending_transmits.push_back(transmit);
                *state = AuthState::Authenticating(new_transaction_id);
                stun_agent.handle_stun_message(msg, stun_agent.remote_addr().unwrap());
                resent = true;
            }
        }
        'outer: for alloc in allocations.iter_mut() {
            if let Some((pending, _lifetime)) = alloc.pending_refresh {
                if pending == msg.transaction_id() {
                    info!("Received STALE_NONCE in response to REFRESH for transaction {pending}, resending");
                    let (transmit, transaction_id, lifetime) =
                        Self::send_refresh(stun_agent, stun_auth, 1800, now);
                    pending_transmits.push_back(transmit);
                    alloc.pending_refresh = Some((transaction_id, lifetime));
                    stun_agent.handle_stun_message(msg, stun_agent.remote_addr().unwrap());
                    resent = true;
                    break 'outer;
                }
            }

            let mut channel_resent = None;
            for (channel, transaction_id) in alloc.pending_channels.iter_mut() {
                if *transaction_id != msg.transaction_id() {
                    continue;
                }
                info!("Received STALE_NONCE in response to BIND_CHANNEL {} for transaction {}, resending", channel.peer_addr, msg.transaction_id());
                let (transmit, new_transaction_id) = Self::send_channel_bind_request(
                    stun_agent,
                    stun_auth,
                    channel.id,
                    channel.peer_addr,
                    now,
                );
                *transaction_id = new_transaction_id;
                pending_transmits.push_back(transmit);
                stun_agent.handle_stun_message(msg, stun_agent.remote_addr().unwrap());
                channel_resent = Some(new_transaction_id);
                resent = true;
                break;
            }
            for channel in alloc.channels.iter_mut() {
                if channel
                    .pending_refresh
                    .is_some_and(|pending| pending == msg.transaction_id())
                {
                    info!("Received STALE_NONCE in response to BIND_CHANNEL {} for transaction {}, resending", channel.peer_addr, msg.transaction_id());
                    let (transmit, transaction_id) = Self::send_channel_bind_request(
                        stun_agent,
                        stun_auth,
                        channel.id,
                        channel.peer_addr,
                        now,
                    );
                    channel.pending_refresh = Some(transaction_id);
                    pending_transmits.push_back(transmit);
                    stun_agent.handle_stun_message(msg, stun_agent.remote_addr().unwrap());
                    channel_resent = Some(transaction_id);
                    resent = true;
                    break;
                }
            }
            for (permission, transaction_id) in alloc.pending_permissions.iter_mut() {
                if *transaction_id != msg.transaction_id() {
                    continue;
                }
                if let Some(new_transaction_id) = channel_resent {
                    *transaction_id = new_transaction_id;
                    break 'outer;
                }
                info!("Received STALE_NONCE in response to CREATE_PERMISSION {} for transaction {}, resending", permission.ip, msg.transaction_id());
                let peer_addr = permission.ip;
                let (transmit, new_transaction_id) =
                    Self::send_create_permission_request(stun_agent, stun_auth, peer_addr, now);
                *transaction_id = new_transaction_id;
                pending_transmits.push_back(transmit);
                stun_agent.handle_stun_message(msg, stun_agent.remote_addr().unwrap());
                resent = true;
                break 'outer;
            }
            for permission in alloc.permissions.iter_mut() {
                if permission
                    .pending_refresh
                    .is_some_and(|pending| pending == msg.transaction_id())
                {
                    if let Some(new_transaction_id) = channel_resent {
                        permission.pending_refresh = Some(new_transaction_id);
                        break 'outer;
                    }
                    info!("Received STALE_NONCE in response to CREATE_PERMISSION {} for transaction {}, resending", permission.ip, msg.transaction_id());
                    let peer_addr = permission.ip;
                    let (transmit, transaction_id) =
                        Self::send_create_permission_request(stun_agent, stun_auth, peer_addr, now);
                    permission.pending_refresh = Some(transaction_id);
                    pending_transmits.push_back(transmit);
                    stun_agent.handle_stun_message(msg, stun_agent.remote_addr().unwrap());
                    resent = true;
                    break 'outer;
                }
            }
        }

        if resent {
            trace!(
                "resending request {} as a new transaction",
                msg.transaction_id()
            );
            TurnProtocolRecv::Handled
        } else {
            TurnProtocolRecv::Ignored
        }
    }

    #[tracing::instrument(
        level = "trace",
        ret,
        skip(
            stun_agent,
            stun_auth,
            state,
            allocations,
            pending_transmits,
            pending_events,
            msg,
            now
        )
    )]
    #[allow(clippy::too_many_arguments)]
    fn handle_authenticated_stun(
        stun_agent: &mut StunAgent,
        stun_auth: &mut LongTermClientAuth,
        state: &mut AuthState,
        allocations: &mut Vec<Allocation>,
        allocation_transport: TransportType,
        address_families: &[AddressFamily],
        pending_transmits: &mut VecDeque<Transmit<Data<'static>>>,
        pending_events: &mut VecDeque<TurnEvent>,
        msg: Message<'_>,
        transport: TransportType,
        from: SocketAddr,
        now: Instant,
    ) -> TurnProtocolRecv {
        trace!("received STUN message {msg}");
        if msg.has_class(MessageClass::Indication) {
            /* The message is an indication */
            return match msg.method() {
                DATA => {
                    let mut peer_addr = None;
                    let mut data = None;
                    let mut icmp = None;

                    for (offset, attr) in msg.iter_attributes() {
                        match attr.get_type() {
                            XorPeerAddress::TYPE => peer_addr = XorPeerAddress::from_raw(attr).ok(),
                            AData::TYPE => {
                                data = AData::from_raw(attr).ok().map(|data| (offset, data))
                            }
                            Icmp::TYPE => icmp = Icmp::from_raw(attr).ok(),
                            _atype => return TurnProtocolRecv::Ignored,
                        }
                    }
                    let Some(peer_addr) = peer_addr else {
                        return TurnProtocolRecv::Ignored;
                    };
                    let peer_addr = peer_addr.addr(msg.transaction_id());
                    if let Some((offset, data)) = data {
                        let Some(allocation_transport) = allocations.iter().find_map(|alloc| {
                            if alloc.have_permission(peer_addr.ip()) {
                                Some(alloc.transport)
                            } else {
                                None
                            }
                        }) else {
                            return TurnProtocolRecv::Ignored;
                        };
                        return TurnProtocolRecv::PeerData {
                            range: offset + 4..offset + 4 + data.data().len(),
                            transport: allocation_transport,
                            peer: peer_addr,
                        };
                    } else if let Some(icmp) = icmp {
                        if allocations
                            .iter()
                            .all(|alloc| !alloc.have_permission(peer_addr.ip()))
                        {
                            return TurnProtocolRecv::Ignored;
                        }
                        TurnProtocolRecv::PeerIcmp {
                            transport,
                            peer: peer_addr,
                            icmp_type: icmp.icmp_type(),
                            icmp_code: icmp.code(),
                            icmp_data: icmp.data(),
                        }
                    } else {
                        TurnProtocolRecv::Ignored
                    }
                }
                _ => TurnProtocolRecv::Ignored, // All other indications should be ignored
            };
        }
        match stun_auth.validate_incoming_message(&msg) {
            Ok(LongTermValidation::Validated(_algo)) => (),
            Ok(LongTermValidation::ResendRequest(_algo)) => {
                return Self::handle_resend_request(
                    stun_agent,
                    stun_auth,
                    state,
                    allocations,
                    allocation_transport,
                    address_families,
                    pending_transmits,
                    &msg,
                    now,
                );
            }
            Err(_e) => return TurnProtocolRecv::Ignored,
        }
        if !stun_agent.handle_stun_message(&msg, from) {
            return TurnProtocolRecv::Ignored;
        }
        if msg.has_class(stun_proto::types::message::MessageClass::Request) {
            if msg.has_method(CONNECTION_ATTEMPT) {
                let Ok(connection_id) = msg.attribute::<ConnectionId>() else {
                    let msg = Self::bad_request_signed(&msg, stun_auth).finish();
                    let transmit = stun_agent
                        .send(Data::from(msg.into_boxed_slice()), from, now)
                        .unwrap();
                    pending_transmits.push_back(transmit);
                    return TurnProtocolRecv::Handled;
                };
                let connection_id = connection_id.id();

                let Ok(xor_peer_addr) = msg.attribute::<XorPeerAddress>() else {
                    let msg = Self::bad_request_signed(&msg, stun_auth).finish();
                    let transmit = stun_agent
                        .send(Data::from(msg.into_boxed_slice()), from, now)
                        .unwrap();
                    pending_transmits.push_back(transmit);
                    return TurnProtocolRecv::Handled;
                };
                let peer_addr = xor_peer_addr.addr(msg.transaction_id());
                let Some(allocation) = allocations.iter_mut().find(|alloc| {
                    alloc.transport == transport
                        && alloc.relayed_address.is_ipv4() == peer_addr.is_ipv4()
                }) else {
                    let msg = Self::bad_request_signed(&msg, stun_auth).finish();
                    let transmit = stun_agent
                        .send(Data::from(msg.into_boxed_slice()), from, now)
                        .unwrap();
                    pending_transmits.push_back(transmit);
                    return TurnProtocolRecv::Handled;
                };
                if allocation
                    .tcp_data
                    .iter()
                    .any(|tcp| tcp.peer_addr == peer_addr)
                    || allocation
                        .pending_tcp_allocate
                        .iter()
                        .any(|tcp| tcp.peer_addr == peer_addr)
                {
                    warn!("TURN-TCP connection already configured (or pending) for {peer_addr}");
                    let mut msg = Message::builder_error(&msg, MessageWriteVec::new());
                    msg.add_attribute(
                        &ErrorCode::builder(ErrorCode::CONNECTION_ALREADY_EXISTS)
                            .build()
                            .unwrap(),
                    )
                    .unwrap();
                    let msg = stun_auth.sign_outgoing_message(msg).unwrap();
                    let transmit = stun_agent
                        .send(Data::from(msg.finish().into_boxed_slice()), from, now)
                        .unwrap();
                    pending_transmits.push_back(transmit);
                    return TurnProtocolRecv::Handled;
                }

                allocation.pending_tcp_allocate.push(PendingTcpAllocate {
                    connection_id,
                    peer_addr,
                    initiation_time: None,
                    request_transaction_id: Some(msg.transaction_id()),
                });

                return TurnProtocolRecv::Handled;
            }

            // TODO: reply with an error?
            TurnProtocolRecv::Ignored
        } else if msg.is_response() {
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
                    for alloc in allocations.iter_mut() {
                        let (transaction_id, requested_lifetime) = if alloc
                            .pending_refresh
                            .is_some_and(|(transaction_id, _requested_lifetime)| {
                                transaction_id == msg.transaction_id()
                            }) {
                            alloc.pending_refresh.take().unwrap()
                        } else {
                            continue;
                        };
                        debug!("removed pending REFRESH transaction {transaction_id}");
                        if is_success {
                            if requested_lifetime == 0 {
                                remove_allocations = true;
                            } else {
                                let Ok(lifetime) = msg.attribute::<Lifetime>() else {
                                    continue;
                                };
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
                    }
                    TurnProtocolRecv::Handled
                }
                CREATE_PERMISSION => {
                    if Self::update_permission_state(allocations, pending_events, &msg, now) {
                        TurnProtocolRecv::Handled
                    } else {
                        TurnProtocolRecv::Ignored
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
                                    .map(|channel_idx| (idx, channel_idx))
                            })
                    {
                        let (mut channel, _transaction_id) = allocations[alloc_idx]
                            .pending_channels
                            .swap_remove_back(channel_idx)
                            .unwrap();
                        if msg.has_class(stun_proto::types::message::MessageClass::Error) {
                            warn!("Received error response to channel bind request");
                            pending_events.push_front(TurnEvent::ChannelCreateFailed(
                                allocations[alloc_idx].transport,
                                channel.peer_addr,
                            ));
                            return TurnProtocolRecv::Handled;
                        }
                        info!("Succesfully created/refreshed {channel:?}");
                        Self::update_permission_state(allocations, pending_events, &msg, now);
                        channel.expires_at = now + CHANNEL_DURATION;
                        pending_events.push_front(TurnEvent::ChannelCreated(
                            allocations[alloc_idx].transport,
                            channel.peer_addr,
                        ));
                        allocations[alloc_idx].channels.push(channel);
                        return TurnProtocolRecv::Handled;
                    } else if let Some((alloc_idx, existing_idx)) = allocations
                        .iter()
                        .enumerate()
                        .find_map(|(idx, allocation)| {
                            allocation
                                .channels
                                .iter()
                                .enumerate()
                                .find_map(|(idx, existing_channel)| {
                                    if existing_channel.pending_refresh.is_some_and(
                                        |refresh_transaction| {
                                            refresh_transaction == msg.transaction_id()
                                        },
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
                        let channel = &mut allocations[alloc_idx].channels[existing_idx];
                        channel.pending_refresh = None;
                        if msg.has_class(stun_proto::types::message::MessageClass::Error) {
                            warn!("Received error response to channel bind request");
                            pending_events.push_front(TurnEvent::ChannelCreateFailed(
                                transport,
                                channel.peer_addr,
                            ));
                            channel.expires_at = now;
                            return TurnProtocolRecv::Handled;
                        }
                        info!("Succesfully created/refreshed {channel:?}");
                        Self::update_permission_state(allocations, pending_events, &msg, now);
                        allocations[alloc_idx].channels[existing_idx].expires_at =
                            now + CHANNEL_DURATION;
                        return TurnProtocolRecv::Handled;
                    }
                    TurnProtocolRecv::Ignored
                }
                CONNECT => {
                    if let Some((allocation, existing_idx)) =
                        allocations.iter_mut().find_map(|allocation| {
                            allocation
                                .pending_tcp_turn
                                .iter()
                                .position(|pending| pending.transaction_id == msg.transaction_id())
                                .map(|channel_idx| (allocation, channel_idx))
                        })
                    {
                        let pending = allocation.pending_tcp_turn.swap_remove(existing_idx);
                        let Ok(connection_id) = msg.attribute::<ConnectionId>() else {
                            pending_events
                                .push_front(TurnEvent::TcpConnectFailed(pending.peer_addr));
                            return TurnProtocolRecv::Handled;
                        };
                        let connection_id = connection_id.id();
                        allocation.pending_tcp_allocate.push(PendingTcpAllocate {
                            connection_id,
                            peer_addr: pending.peer_addr,
                            initiation_time: None,
                            request_transaction_id: None,
                        });
                        return TurnProtocolRecv::Handled;
                    }
                    TurnProtocolRecv::Ignored
                }
                _ => TurnProtocolRecv::Ignored, // Other responses are not expected
            }
        } else {
            TurnProtocolRecv::Ignored
        }
    }

    fn bad_request(msg: &Message<'_>, additional_bytes: usize) -> MessageWriteVec {
        let error = ErrorCode::builder(ErrorCode::BAD_REQUEST).build().unwrap();
        let mut builder = Message::builder_error(
            msg,
            MessageWriteVec::with_capacity(
                MessageHeader::LENGTH + error.padded_len() + additional_bytes,
            ),
        );
        builder.add_attribute(&error).unwrap();
        builder
    }

    fn bad_request_signed(
        msg: &Message<'_>,
        stun_auth: &mut LongTermClientAuth,
    ) -> MessageWriteVec {
        let builder = Self::bad_request(msg, stun_auth.message_signature_bytes());
        stun_auth.sign_outgoing_message(builder).unwrap()
    }

    fn send_refresh(
        stun_agent: &mut StunAgent,
        stun_auth: &mut LongTermClientAuth,
        lifetime: u32,
        now: Instant,
    ) -> (Transmit<Data<'static>>, TransactionId, u32) {
        info!(lifetime, "sending REFRESH");
        let lt = Lifetime::new(lifetime);
        let mut refresh = Message::builder_request(
            REFRESH,
            MessageWriteVec::with_capacity(
                MessageHeader::LENGTH + lt.padded_len() + stun_auth.message_signature_bytes(),
            ),
        );
        let transaction_id = refresh.transaction_id();
        refresh.add_attribute(&lt).unwrap();
        let remote_addr = stun_agent.remote_addr().unwrap();
        let refresh = stun_auth.sign_outgoing_message(refresh).unwrap();
        let refresh = refresh.finish();
        let transmit = stun_agent.send_request(&refresh, remote_addr, now).unwrap();
        (transmit.into_owned(), transaction_id, lifetime)
    }

    fn send_create_permission_request(
        stun_agent: &mut StunAgent,
        stun_auth: &mut LongTermClientAuth,
        peer_addr: IpAddr,
        now: Instant,
    ) -> (Transmit<Data<'static>>, TransactionId) {
        info!(peer_addr = ?peer_addr, "sending CREATE_PERMISSION");
        let transaction_id = TransactionId::generate();
        let xor_peer_address = XorPeerAddress::new(SocketAddr::new(peer_addr, 0), transaction_id);
        let mut builder = Message::builder(
            MessageType::from_class_method(MessageClass::Request, CREATE_PERMISSION),
            transaction_id,
            MessageWriteVec::with_capacity(
                MessageHeader::LENGTH
                    + xor_peer_address.padded_len()
                    + stun_auth.message_signature_bytes(),
            ),
        );

        builder.add_attribute(&xor_peer_address).unwrap();
        let remote_addr = stun_agent.remote_addr().unwrap();
        let builder = stun_auth.sign_outgoing_message(builder).unwrap();
        let msg = builder.finish();
        let transmit = stun_agent.send_request(&msg, remote_addr, now).unwrap();
        (transmit.into_owned(), transaction_id)
    }

    #[allow(clippy::too_many_arguments)]
    fn send_channel_bind_request(
        stun_agent: &mut StunAgent,
        stun_auth: &mut LongTermClientAuth,
        id: u16,
        peer_addr: SocketAddr,
        now: Instant,
    ) -> (Transmit<Data<'static>>, TransactionId) {
        info!(peer_addr = ?peer_addr, id, "sending CHANNEL_BIND");
        let transaction_id = TransactionId::generate();
        let channel_no = ChannelNumber::new(id);
        let xor_peer_address = XorPeerAddress::new(peer_addr, transaction_id);

        let mut builder = Message::builder(
            MessageType::from_class_method(MessageClass::Request, CHANNEL_BIND),
            transaction_id,
            MessageWriteVec::with_capacity(
                MessageHeader::LENGTH
                    + channel_no.padded_len()
                    + xor_peer_address.padded_len()
                    + stun_auth.message_signature_bytes(),
            ),
        );
        builder.add_attribute(&channel_no).unwrap();
        builder.add_attribute(&xor_peer_address).unwrap();
        let remote_addr = stun_agent.remote_addr().unwrap();
        let builder = stun_auth.sign_outgoing_message(builder).unwrap();
        let msg = builder.finish();

        let transmit = stun_agent.send_request(&msg, remote_addr, now).unwrap();
        (transmit.into_owned(), transaction_id)
    }

    #[allow(clippy::too_many_arguments)]
    fn send_connection_bind_request(
        stun_agent: &mut StunAgent,
        stun_auth: &mut LongTermClientAuth,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        connection_id: u32,
        now: Instant,
    ) -> (Transmit<Data<'static>>, TransactionId) {
        info!(?local_addr, ?remote_addr, "sending CONNECTION BIND");
        let transaction_id = TransactionId::generate();
        let connection_id = ConnectionId::new(connection_id);

        let mut builder = Message::builder(
            MessageType::from_class_method(MessageClass::Request, CONNECTION_BIND),
            transaction_id,
            MessageWriteVec::with_capacity(
                MessageHeader::LENGTH
                    + connection_id.padded_len()
                    + stun_auth.message_signature_bytes(),
            ),
        );
        builder.add_attribute(&connection_id).unwrap();
        let builder = stun_auth.sign_outgoing_message(builder).unwrap();
        let msg = builder.finish();

        let mut transmit = stun_agent.send_request(msg, remote_addr, now).unwrap();
        transmit.from = local_addr;
        let transmit = transmit.reinterpret_data(|data| data.into_owned());

        (transmit, transaction_id)
    }

    #[allow(clippy::too_many_arguments)]
    fn send_connect_request(
        stun_agent: &mut StunAgent,
        stun_auth: &mut LongTermClientAuth,
        peer_addr: SocketAddr,
        now: Instant,
    ) -> (Transmit<Data<'static>>, TransactionId) {
        info!(peer_addr = ?peer_addr, "sending CONNECTION BIND");
        let transaction_id = TransactionId::generate();
        let xor_peer_address = XorPeerAddress::new(peer_addr, transaction_id);

        let mut builder = Message::builder(
            MessageType::from_class_method(MessageClass::Request, CONNECT),
            transaction_id,
            MessageWriteVec::with_capacity(
                MessageHeader::LENGTH
                    + xor_peer_address.padded_len()
                    + stun_auth.message_signature_bytes(),
            ),
        );
        builder.add_attribute(&xor_peer_address).unwrap();
        let remote_addr = stun_agent.remote_addr().unwrap();
        let builder = stun_auth.sign_outgoing_message(builder).unwrap();
        let msg = builder.finish();

        let transmit = stun_agent.send_request(&msg, remote_addr, now).unwrap();
        (transmit.into_owned(), transaction_id)
    }

    #[allow(clippy::too_many_arguments)]
    fn send_connection_attempt_response(
        stun_auth: &mut LongTermClientAuth,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        transaction_id: TransactionId,
        peer_addr: SocketAddr,
        error_code: Option<u16>,
    ) -> Transmit<Data<'static>> {
        info!(peer_addr = ?peer_addr, "sending CONNECTION ATTEMPT response");
        let error_code = error_code.map(|code| ErrorCode::builder(code).build().unwrap());
        let mut additional_bytes = stun_auth.message_signature_bytes();

        let cls = if let Some(code) = error_code.as_ref() {
            additional_bytes += code.padded_len();
            MessageClass::Error
        } else {
            MessageClass::Success
        };
        let mut builder = Message::builder(
            MessageType::from_class_method(cls, CONNECTION_ATTEMPT),
            transaction_id,
            MessageWriteVec::with_capacity(MessageHeader::LENGTH + additional_bytes),
        );
        if let Some(code) = error_code {
            builder.add_attribute(&code).unwrap();
        }
        let builder = stun_auth.sign_outgoing_message(builder).unwrap();
        let msg = builder.finish();

        Transmit::new(
            Data::from(msg.into_boxed_slice()),
            TransportType::Tcp,
            local_addr,
            remote_addr,
        )
    }

    pub(crate) fn have_permission(&self, transport: TransportType, to: IpAddr) -> bool {
        self.allocations.iter().any(|allocation| {
            allocation.transport == transport
                && !allocation.expired
                && allocation
                    .permissions
                    .iter()
                    .any(|permission| !permission.expired && permission.ip == to)
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
        skip(self, channel),
        fields(
            channel.id = channel.id(),
            channel.data.len = channel.data().len(),
        )
    )]
    pub(crate) fn handle_channel<'a>(
        &mut self,
        channel: ChannelData<'a>,
        now: Instant,
    ) -> TurnProtocolChannelRecv {
        for alloc in self.allocations.iter_mut() {
            if let Some(chan) = alloc
                .channels
                .iter_mut()
                .find(|chan| chan.id == channel.id())
            {
                return TurnProtocolChannelRecv::PeerData {
                    range: 4..4 + channel.data().len(),
                    transport: alloc.transport,
                    peer: chan.peer_addr,
                };
            }
        }
        TurnProtocolChannelRecv::Ignored
    }

    #[tracing::instrument(name = "turn_client_handle_message", skip(self, transmit))]
    pub(crate) fn handle_message(
        &mut self,
        transmit: Transmit<Message<'_>>,
        now: Instant,
    ) -> TurnProtocolRecv {
        match &mut self.state {
            AuthState::Error | AuthState::Initial => return TurnProtocolRecv::Ignored,
            AuthState::InitialSent(_transaction_id) => {
                trace!("received STUN message {}", transmit.data);
                if !transmit.data.is_response() {
                    return TurnProtocolRecv::Ignored;
                };
                let resend = match self.stun_auth.validate_incoming_message(&transmit.data) {
                    Ok(LongTermValidation::ResendRequest(_algo)) => true,
                    Err(e) => matches!(e.reason(), AuthErrorReason::StaleNonce),
                    Ok(LongTermValidation::Validated(_algo)) => {
                        self.state = AuthState::Error;
                        for fam in self.families.iter().cloned() {
                            self.pending_events
                                .push_front(TurnEvent::AllocationCreateFailed(fam));
                        }
                        return TurnProtocolRecv::Ignored;
                    }
                };
                if !self
                    .stun_agent
                    .handle_stun_message(&transmit.data, transmit.from)
                {
                    return TurnProtocolRecv::Ignored;
                }
                if !resend {
                    self.state = AuthState::Error;
                    for fam in self.families.iter().cloned() {
                        self.pending_events
                            .push_front(TurnEvent::AllocationCreateFailed(fam));
                    }
                    return TurnProtocolRecv::Handled;
                }
                return Self::handle_resend_request(
                    &mut self.stun_agent,
                    &mut self.stun_auth,
                    &mut self.state,
                    &mut self.allocations,
                    self.allocation_transport,
                    &self.families,
                    &mut self.pending_transmits,
                    &transmit.data,
                    now,
                );
            }
            AuthState::Authenticating(transaction_id) => {
                trace!("received STUN message {}", transmit.data);
                let msg = transmit.data;
                if !msg.is_response() || &msg.transaction_id() != transaction_id {
                    return TurnProtocolRecv::Ignored;
                }
                match self.stun_auth.validate_incoming_message(&transmit.data) {
                    Ok(LongTermValidation::ResendRequest(_algo)) => {
                        return Self::handle_resend_request(
                            &mut self.stun_agent,
                            &mut self.stun_auth,
                            &mut self.state,
                            &mut self.allocations,
                            self.allocation_transport,
                            &self.families,
                            &mut self.pending_transmits,
                            &msg,
                            now,
                        );
                    }
                    Ok(LongTermValidation::Validated(_algo)) => (),
                    Err(e) => {
                        if e.integrity().is_some() {
                            self.state = AuthState::Error;
                            for fam in self.families.iter().cloned() {
                                self.pending_events
                                    .push_front(TurnEvent::AllocationCreateFailed(fam));
                            }
                            return TurnProtocolRecv::Handled;
                        } else {
                            return TurnProtocolRecv::Ignored;
                        }
                    }
                }
                if !self.stun_agent.handle_stun_message(&msg, transmit.from) {
                    return TurnProtocolRecv::Handled;
                }
                if !msg.is_response() || &msg.transaction_id() != transaction_id {
                    return TurnProtocolRecv::Ignored;
                }
                match msg.class() {
                    stun_proto::types::message::MessageClass::Error => {
                        let Ok(error_code) = msg.attribute::<ErrorCode>() else {
                            info!("Authenticating ALLOCATE error response missing ErrorCode attribute");
                            self.state = AuthState::Error;
                            for fam in self.families.iter().cloned() {
                                self.pending_events
                                    .push_front(TurnEvent::AllocationCreateFailed(fam));
                            }
                            return TurnProtocolRecv::Handled;
                        };
                        if error_code.code() == ErrorCode::ADDRESS_FAMILY_NOT_SUPPORTED
                            && self.families.len() > 1
                        {
                            let mut removed_ipv4_family = false;
                            self.families.retain(|fam| {
                                if *fam != AddressFamily::IPV4 {
                                    true
                                } else {
                                    removed_ipv4_family = true;
                                    false
                                }
                            });
                            if removed_ipv4_family {
                                info!("Attempt to create dual IPv4/6 allocation failed with IPv4 failure. Attempting to create IPv6-only allocation");
                                self.pending_events
                                    .push_front(TurnEvent::AllocationCreateFailed(
                                        AddressFamily::IPV4,
                                    ));
                                /* retry the request with a slightly different construction */
                                let (transmit, transaction_id) = Self::send_authenticating_request(
                                    &mut self.stun_agent,
                                    &mut self.stun_auth,
                                    self.allocation_transport,
                                    &self.families,
                                    now,
                                );
                                self.pending_transmits.push_back(transmit.into_owned());
                                self.state = AuthState::Authenticating(transaction_id);
                                return TurnProtocolRecv::Handled;
                            }
                        }
                        warn!(
                            "Unknown error code {} returned while authenticating: {}",
                            error_code.code(),
                            error_code.reason()
                        );
                        self.state = AuthState::Error;
                        for fam in self.families.iter().cloned() {
                            self.pending_events
                                .push_front(TurnEvent::AllocationCreateFailed(fam));
                        }
                        return TurnProtocolRecv::Handled;
                    }
                    stun_proto::types::message::MessageClass::Success => {
                        let lifetime = msg.attribute::<Lifetime>();
                        let Ok(lifetime) = lifetime else {
                            info!("Authenticating ALLOCATE response missing Lifetime attributes");
                            self.state = AuthState::Error;
                            for fam in self.families.iter().cloned() {
                                self.pending_events
                                    .push_front(TurnEvent::AllocationCreateFailed(fam));
                            }
                            return TurnProtocolRecv::Handled;
                        };
                        let lifetime = Duration::from_secs(lifetime.seconds() as u64);
                        let expires_at = now + lifetime;

                        let mut any_relayed = false;
                        let mut relayed_i = 0;
                        let mut unseen_families = self.families.clone();
                        while let Ok(xor_relayed_address) =
                            msg.nth_attribute::<XorRelayedAddress>(relayed_i)
                        {
                            let relayed_address = xor_relayed_address.addr(msg.transaction_id());
                            let relayed_family = if relayed_address.is_ipv4() {
                                AddressFamily::IPV4
                            } else if relayed_address.is_ipv6() {
                                AddressFamily::IPV6
                            } else {
                                // only IPv4/6 supported so far
                                unreachable!();
                            };

                            if unseen_families.contains(&relayed_family) {
                                info!(relayed = ?relayed_address, transport = ?self.allocation_transport, "New allocation expiring in {}s at {expires_at}", lifetime.as_secs());
                                self.allocations.push(Allocation {
                                    relayed_address,
                                    transport: self.allocation_transport,
                                    expired: false,
                                    lifetime,
                                    expires_at,
                                    permissions: vec![],
                                    channels: vec![],
                                    pending_tcp_turn: Vec::default(),
                                    tcp_data: Vec::default(),
                                    pending_permissions: VecDeque::default(),
                                    pending_channels: VecDeque::default(),
                                    pending_refresh: None,
                                    expired_channels: vec![],
                                    pending_tcp_allocate: vec![],
                                });
                                self.pending_events.push_front(TurnEvent::AllocationCreated(
                                    self.allocation_transport,
                                    relayed_address,
                                ));
                                any_relayed = true;
                                unseen_families.retain(|family| relayed_family != *family);
                            }
                            relayed_i += 1;
                        }
                        for fam in unseen_families {
                            self.pending_events
                                .push_front(TurnEvent::AllocationCreateFailed(fam));
                        }
                        if !any_relayed {
                            warn!("Authenticated ALLOCATE response missing XorRelayedAddress attributes");
                            self.state = AuthState::Error;
                            return TurnProtocolRecv::Handled;
                        };
                        self.state = AuthState::Authenticated;
                        return TurnProtocolRecv::Handled;
                    }
                    _ => (),
                }
                return TurnProtocolRecv::Ignored;
            }
            AuthState::Authenticated => (),
        };

        if self.local_addr() == transmit.to {
            Self::handle_authenticated_stun(
                &mut self.stun_agent,
                &mut self.stun_auth,
                &mut self.state,
                &mut self.allocations,
                self.allocation_transport,
                &self.families,
                &mut self.pending_transmits,
                &mut self.pending_events,
                transmit.data,
                transmit.transport,
                transmit.from,
                now,
            )
        } else if self.allocation_transport == TransportType::Tcp {
            if transmit.data.method() != CONNECTION_BIND {
                return TurnProtocolRecv::Ignored;
            }

            for alloc in self.allocations.iter_mut() {
                let Some((tcp_idx, tcp)) = alloc
                    .tcp_data
                    .iter_mut()
                    .enumerate()
                    .find(|(_idx, tcp)| tcp.local_addr == transmit.to)
                else {
                    continue;
                };
                let mut failure = false;
                let Some((_transaction, _expiry, connection_id)) = tcp
                    .pending_transaction_id
                    .take_if(|(id, _, _)| id == &transmit.data.transaction_id())
                else {
                    self.pending_events
                        .push_front(TurnEvent::TcpConnectFailed(tcp.peer_addr));
                    let tcp_data = alloc.tcp_data.swap_remove(tcp_idx);
                    self.pending_socket_removal.push_back(Socket5Tuple {
                        transport: TransportType::Tcp,
                        from: tcp_data.local_addr,
                        to: self.remote_addr(),
                    });
                    return TurnProtocolRecv::Handled;
                };
                if !transmit.data.is_response() {
                    self.pending_events
                        .push_front(TurnEvent::TcpConnectFailed(tcp.peer_addr));
                    let tcp_data = alloc.tcp_data.swap_remove(tcp_idx);
                    self.pending_socket_removal.push_back(Socket5Tuple {
                        transport: TransportType::Tcp,
                        from: tcp_data.local_addr,
                        to: self.remote_addr(),
                    });
                    return TurnProtocolRecv::Handled;
                }
                match self.stun_auth.validate_incoming_message(&transmit.data) {
                    Ok(LongTermValidation::Validated(_algo)) => (),
                    Ok(LongTermValidation::ResendRequest(_algo)) => {
                        let (transmit, transaction_id) = Self::send_connection_bind_request(
                            &mut self.stun_agent,
                            &mut self.stun_auth,
                            transmit.to,
                            transmit.from,
                            connection_id,
                            now,
                        );
                        tcp.pending_transaction_id = Some((transaction_id, now, connection_id));
                        self.pending_transmits.push_back(transmit);
                        return TurnProtocolRecv::Handled;
                    }
                    Err(_e) => failure = true,
                };
                if !self
                    .stun_agent
                    .handle_stun_message(&transmit.data, transmit.from)
                {
                    failure = true;
                }
                if !transmit.data.has_class(MessageClass::Success) {
                    failure = true;
                }
                if failure {
                    self.pending_events
                        .push_front(TurnEvent::TcpConnectFailed(tcp.peer_addr));
                    let tcp_data = alloc.tcp_data.swap_remove(tcp_idx);
                    self.pending_socket_removal.push_back(Socket5Tuple {
                        transport: TransportType::Tcp,
                        from: tcp_data.local_addr,
                        to: self.remote_addr(),
                    });
                    return TurnProtocolRecv::Handled;
                }
                self.pending_events
                    .push_front(TurnEvent::TcpConnected(tcp.peer_addr));
                return TurnProtocolRecv::TcpConnectionBound {
                    peer_addr: tcp.peer_addr,
                };
            }
            TurnProtocolRecv::Ignored
        } else {
            TurnProtocolRecv::Ignored
        }
    }

    pub(crate) fn send_to<T: AsRef<[u8]> + core::fmt::Debug>(
        &mut self,
        transport: TransportType,
        to: SocketAddr,
        data: T,
        now: Instant,
    ) -> Result<TransmitBuild<DelayedMessageOrChannelSend<T>>, SendError> {
        if !self.have_permission(transport, to.ip()) {
            return Err(SendError::NoPermission);
        }

        if self.allocation_transport == TransportType::Tcp {
            // find any allocated TCP connection for this peer
            for alloc in self.allocations.iter() {
                if alloc.transport != transport {
                    continue;
                }
                let Some(local_addr) = alloc.tcp_data.iter().find_map(|tcp| {
                    if tcp.pending_transaction_id.is_none() && tcp.peer_addr == to {
                        Some(tcp.local_addr)
                    } else {
                        None
                    }
                }) else {
                    continue;
                };
                trace!(
                    "sending {} bytes from {local_addr} to {} over TCP for TCP peer",
                    data.as_ref().len(),
                    self.remote_addr()
                );
                return Ok(TransmitBuild::new(
                    DelayedMessageOrChannelSend::Data(data),
                    self.allocation_transport,
                    local_addr,
                    self.remote_addr(),
                ));
            }
            return Err(SendError::NoTcpSocket);
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

    #[tracing::instrument(name = "turn_client_poll", level = "trace", ret, skip(self))]
    pub(crate) fn poll(&mut self, now: Instant) -> TurnPollRet {
        if !self.pending_events.is_empty() || !self.pending_transmits.is_empty() {
            return TurnPollRet::WaitUntil(now);
        }
        let remote_addr = self.remote_addr();
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
        let ret = match &mut self.state {
            AuthState::Error => return TurnPollRet::Closed,
            AuthState::Initial => TurnPollRet::WaitUntil(now),
            AuthState::InitialSent(transaction_id) => {
                if cancelled_transaction.is_some_and(|cancelled| &cancelled == transaction_id) {
                    info!("Initial transaction timed out or was cancelled");
                    for fam in self.families.iter().cloned() {
                        self.pending_events
                            .push_back(TurnEvent::AllocationCreateFailed(fam));
                    }
                    self.state = AuthState::Error;
                    return TurnPollRet::Closed;
                }
                TurnPollRet::WaitUntil(earliest_wait)
            }
            AuthState::Authenticating(transaction_id) => {
                if cancelled_transaction.is_some_and(|cancelled| &cancelled == transaction_id) {
                    info!("Authenticating transaction timed out or was cancelled");
                    self.state = AuthState::Error;
                }
                TurnPollRet::WaitUntil(earliest_wait)
            }
            AuthState::Authenticated => {
                let mut remove_allocation_indices = vec![];
                for (idx, alloc) in self.allocations.iter_mut().enumerate() {
                    // TCP socket creation from the user.
                    for pending in alloc.pending_tcp_allocate.iter_mut() {
                        if pending.initiation_time.is_none() {
                            pending.initiation_time = Some(now);
                            let connection_id = pending.connection_id;
                            let peer_addr = pending.peer_addr;
                            return TurnPollRet::AllocateTcpSocket {
                                id: connection_id,
                                socket: Socket5Tuple {
                                    transport: self.transport(),
                                    from: self.local_addr(),
                                    to: self.remote_addr(),
                                },
                                peer_addr,
                            };
                        }
                    }
                    let mut expires_at;

                    trace!(
                        "alloc {} {} refresh time in {:?}",
                        alloc.transport,
                        alloc.relayed_address,
                        alloc.refresh_time() - now
                    );
                    // Refresh the allocation if necessary.
                    if let Some((pending, _lifetime)) = alloc.pending_refresh {
                        if cancelled_transaction.is_some_and(|cancelled| cancelled == pending) {
                            warn!("Refresh timed out or was cancelled");
                            if alloc.expires_at > now {
                                expires_at = alloc.expires_at;
                            } else {
                                remove_allocation_indices.push(idx);
                                continue;
                            }
                        } else if alloc.expires_at > now {
                            expires_at = alloc.expires_at;
                        } else if !alloc.expired {
                            warn!(
                                "Allocation {} {} timed out",
                                alloc.transport, alloc.relayed_address
                            );
                            remove_allocation_indices.push(idx);
                            continue;
                        } else {
                            expires_at = now;
                        }
                    } else if alloc.expires_at > now {
                        expires_at = alloc.refresh_time().max(now);
                    } else {
                        warn!(
                            "Allocation {} {} timed out",
                            alloc.transport, alloc.relayed_address
                        );
                        remove_allocation_indices.push(idx);
                        continue;
                    }

                    if let Some(t) = cancelled_transaction {
                        let mut channel_idx = None;
                        for (idx, (channel, pending_transaction)) in
                            alloc.pending_channels.iter_mut().enumerate()
                        {
                            if t == *pending_transaction {
                                channel_idx = Some(idx);
                                self.pending_events
                                    .push_back(TurnEvent::ChannelCreateFailed(
                                        alloc.transport,
                                        channel.peer_addr,
                                    ));
                                break;
                            }
                        }
                        if let Some(idx) = channel_idx {
                            alloc.pending_channels.remove(idx);
                        }
                        let mut permission_idx = None;
                        for (idx, (permission, pending_transaction)) in
                            alloc.pending_permissions.iter_mut().enumerate()
                        {
                            if t == *pending_transaction {
                                permission_idx = Some(idx);
                                self.pending_events
                                    .push_back(TurnEvent::PermissionCreateFailed(
                                        alloc.transport,
                                        permission.ip,
                                    ));
                                break;
                            }
                        }
                        if let Some(idx) = permission_idx {
                            alloc.pending_permissions.remove(idx);
                        }
                    }

                    // refresh TURN channel allocation
                    for channel in alloc.channels.iter_mut() {
                        trace!(
                            "channel {} {} {} refresh time in {:?}",
                            channel.id,
                            alloc.transport,
                            channel.peer_addr,
                            channel.refresh_time() - now
                        );
                        if let Some(pending) = channel.pending_refresh {
                            if cancelled_transaction.is_some_and(|cancelled| cancelled == pending) {
                                // TODO: need to eventually fail when the permission times out.
                                warn!("{} channel {} from {} to {} refresh timed out or was cancelled", alloc.transport, channel.id, alloc.relayed_address, channel.peer_addr);
                                expires_at = channel.expires_at;
                                self.pending_events
                                    .push_back(TurnEvent::ChannelCreateFailed(
                                        alloc.transport,
                                        channel.peer_addr,
                                    ));
                            } else if channel.expires_at <= now {
                                info!(
                                    "{} channel {} from {} to {} has expired",
                                    alloc.transport,
                                    channel.id,
                                    alloc.relayed_address,
                                    channel.peer_addr
                                );
                                self.pending_events
                                    .push_back(TurnEvent::ChannelCreateFailed(
                                        alloc.transport,
                                        channel.peer_addr,
                                    ));
                            } else {
                                expires_at = expires_at.min(channel.expires_at);
                            }
                        } else {
                            expires_at = expires_at.min(channel.refresh_time().max(now));
                        }
                    }

                    // refresh TURN permission if necessary
                    for permission in alloc.permissions.iter_mut() {
                        trace!(
                            "permission {} {} refresh time in {:?}",
                            alloc.transport,
                            permission.ip,
                            permission.refresh_time() - now
                        );
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
                        } else {
                            expires_at = expires_at.min(permission.refresh_time().max(now));
                        }
                    }

                    // check for any cancelled tcp CONNECT
                    for (idx, tcp) in alloc.pending_tcp_turn.iter_mut().enumerate() {
                        if cancelled_transaction
                            .is_some_and(|cancelled| cancelled == tcp.transaction_id)
                        {
                            warn!(
                                "TCP CONNECT from relayed {} to peer {} timed out or was cancelled",
                                alloc.relayed_address, tcp.peer_addr,
                            );
                            self.pending_events
                                .push_back(TurnEvent::TcpConnectFailed(tcp.peer_addr));
                            alloc.pending_tcp_turn.swap_remove(idx);
                            expires_at = now;
                            break;
                        }
                    }

                    // check for any cancelled tcp CONNECTION_BIND
                    let mut remove_tcp_data_indices = vec![];
                    for (idx, tcp) in alloc.tcp_data.iter_mut().enumerate() {
                        if let Some((transaction_id, expiry, _connection_id)) =
                            tcp.pending_transaction_id
                        {
                            if cancelled_transaction
                                .is_some_and(|cancelled| cancelled == transaction_id)
                                || expiry < now
                            {
                                warn!(
                                    "TCP CONNECTION_BIND from local {} relayed {} to peer {} timed out or was cancelled",
                                    tcp.local_addr, alloc.relayed_address, tcp.peer_addr,
                                );
                                self.pending_events
                                    .push_back(TurnEvent::TcpConnectFailed(tcp.peer_addr));
                                remove_tcp_data_indices.push(idx);
                                expires_at = now;
                            } else {
                                expires_at = expires_at.min(expiry);
                            }
                        }
                    }
                    for (i, idx) in remove_tcp_data_indices.into_iter().enumerate() {
                        let tcp_data = alloc.tcp_data.remove(idx - i);
                        self.pending_socket_removal.push_back(Socket5Tuple {
                            transport: TransportType::Tcp,
                            from: tcp_data.local_addr,
                            to: remote_addr,
                        });
                    }

                    // check for any cancelled tcp CONNECTION_BIND
                    for (idx, tcp) in alloc.pending_tcp_allocate.iter_mut().enumerate() {
                        if cancelled_transaction == tcp.request_transaction_id {
                            self.pending_events
                                .push_back(TurnEvent::TcpConnectFailed(tcp.peer_addr));
                            alloc.pending_tcp_allocate.swap_remove(idx);
                            expires_at = now;
                            break;
                        }
                    }

                    earliest_wait = expires_at.min(earliest_wait)
                }
                for (i, idx) in remove_allocation_indices.into_iter().enumerate() {
                    self.allocations.remove(idx - i);
                }
                if self.allocations.is_empty() {
                    TurnPollRet::Closed
                } else {
                    TurnPollRet::WaitUntil(earliest_wait.max(now))
                }
            }
        };
        if let Some(socket) = self.pending_socket_removal.pop_front() {
            match socket.transport {
                TransportType::Tcp => {
                    return TurnPollRet::TcpClose {
                        local_addr: socket.from,
                        remote_addr: socket.to,
                    };
                }
                TransportType::Udp => unreachable!(),
            }
        }
        ret
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
            AuthState::Authenticating(_transaction_id) => None,
            AuthState::Authenticated => {
                for alloc in self.allocations.iter_mut() {
                    if alloc.expired || alloc.expires_at < now {
                        continue;
                    }
                    if alloc.pending_refresh.is_none() && alloc.refresh_time() <= now {
                        let (transmit, transaction_id, lifetime) = Self::send_refresh(
                            &mut self.stun_agent,
                            &mut self.stun_auth,
                            1800,
                            now,
                        );
                        alloc.pending_refresh = Some((transaction_id, lifetime));
                        return Some(transmit);
                    }

                    for channel in alloc.channels.iter_mut() {
                        if channel.expires_at < now {
                            continue;
                        }
                        if channel.pending_refresh.is_none() && channel.refresh_time() <= now {
                            info!(
                                "refreshing {} channel {} from {} to {}",
                                alloc.transport,
                                channel.id,
                                alloc.relayed_address,
                                channel.peer_addr
                            );
                            let (transmit, transaction_id) = Self::send_channel_bind_request(
                                &mut self.stun_agent,
                                &mut self.stun_auth,
                                channel.id,
                                channel.peer_addr,
                                now,
                            );
                            channel.pending_refresh = Some(transaction_id);
                            return Some(transmit);
                        }
                    }

                    for permission in alloc.permissions.iter_mut() {
                        if permission.expires_at < now {
                            continue;
                        }
                        if permission.pending_refresh.is_none() && permission.refresh_time() <= now
                        {
                            info!(
                                "refreshing {} permission from {} to {}",
                                alloc.transport, alloc.relayed_address, permission.ip
                            );
                            let (transmit, transaction_id) = Self::send_create_permission_request(
                                &mut self.stun_agent,
                                &mut self.stun_auth,
                                permission.ip,
                                now,
                            );
                            permission.pending_refresh = Some(transaction_id);
                            return Some(transmit);
                        }
                    }
                }
                None
            }
        }
    }

    /// Poll for an event that has occurred.
    #[tracing::instrument(name = "turn_client_poll_event", ret, skip(self))]
    pub(crate) fn poll_event(&mut self) -> Option<TurnEvent> {
        self.pending_events.pop_back()
    }

    /// Remove the allocation/s on the server.
    #[tracing::instrument(name = "turn_client_delete", ret, skip(self))]
    pub(crate) fn delete(&mut self, now: Instant) -> Result<(), DeleteError> {
        if !matches!(self.state, AuthState::Authenticated) {
            return Err(DeleteError::NoAllocation);
        };

        let (transmit, transaction_id, lifetime) =
            Self::send_refresh(&mut self.stun_agent, &mut self.stun_auth, 0, now);

        info!("Deleting allocations");
        for alloc in self.allocations.iter_mut() {
            alloc.permissions.clear();
            alloc.channels.clear();
            alloc.expires_at = now;
            alloc.expired = true;
            alloc.pending_refresh = Some((transaction_id, lifetime));
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
        if !matches!(self.state, AuthState::Authenticated) {
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
            &mut self.stun_auth,
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

    #[tracing::instrument(name = "turn_client_tcp_connect", skip(self, now), err)]
    pub(crate) fn tcp_connect(
        &mut self,
        peer_addr: SocketAddr,
        now: Instant,
    ) -> Result<(), TcpConnectError> {
        let Some(allocation) = self.allocations.iter_mut().find(|allocation| {
            allocation.transport == TransportType::Tcp
                && allocation.relayed_address.is_ipv4() == peer_addr.is_ipv4()
        }) else {
            warn!("No allocation available to connect to this peer");
            return Err(TcpConnectError::NoAllocation);
        };

        if now >= allocation.expires_at {
            allocation.expired = true;
            return Err(TcpConnectError::NoAllocation);
        }

        if !matches!(self.state, AuthState::Authenticated) {
            return Err(TcpConnectError::NoAllocation);
        };

        if !allocation.have_permission(peer_addr.ip()) {
            return Err(TcpConnectError::NoPermission);
        }

        if allocation
            .tcp_data
            .iter()
            .map(|tcp| tcp.peer_addr)
            .chain(allocation.pending_tcp_turn.iter().map(|tcp| tcp.peer_addr))
            .chain(
                allocation
                    .pending_tcp_allocate
                    .iter()
                    .map(|tcp| tcp.peer_addr),
            )
            .any(|addr| addr == peer_addr)
        {
            return Err(TcpConnectError::AlreadyExists);
        }

        let (transmit, transaction_id) =
            Self::send_connect_request(&mut self.stun_agent, &mut self.stun_auth, peer_addr, now);
        allocation.pending_tcp_turn.push(PendingTurnTcp {
            transaction_id,
            peer_addr,
        });
        self.pending_transmits.push_back(transmit.into_owned());
        Ok(())
    }

    pub(crate) fn allocated_tcp_socket(
        &mut self,
        id: u32,
        five_tuple: Socket5Tuple,
        peer_addr: SocketAddr,
        tcp_addr: Option<SocketAddr>,
        now: Instant,
    ) -> Result<(), TcpAllocateError> {
        if self.allocation_transport != TransportType::Tcp
            || five_tuple.transport != self.transport()
            || five_tuple.from != self.local_addr()
            || five_tuple.to != self.remote_addr()
        {
            return Err(TcpAllocateError::NoAllocation);
        }
        let Some((alloc_idx, pending_idx)) =
            self.allocations
                .iter()
                .enumerate()
                .find_map(|(idx, alloc)| {
                    alloc
                        .pending_tcp_allocate
                        .iter()
                        .enumerate()
                        .find_map(|(pending_idx, pending)| {
                            if pending.connection_id == id && pending.peer_addr == peer_addr {
                                Some(pending_idx)
                            } else {
                                None
                            }
                        })
                        .map(|pending_idx| (idx, pending_idx))
                })
        else {
            return Err(TcpAllocateError::NoAllocation);
        };

        if !matches!(self.state, AuthState::Authenticated) {
            return Err(TcpAllocateError::NoAllocation);
        };
        let alloc = &mut self.allocations[alloc_idx];
        let pending = alloc.pending_tcp_allocate.swap_remove(pending_idx);
        let local_addr = self.local_addr();
        let remote_addr = self.remote_addr();

        let Some(tcp_addr) = tcp_addr else {
            if let Some(request_id) = pending.request_transaction_id {
                let transmit = Self::send_connection_attempt_response(
                    &mut self.stun_auth,
                    local_addr,
                    remote_addr,
                    request_id,
                    peer_addr,
                    Some(ErrorCode::CONNECTION_TIMEOUT_OR_FAILURE),
                );
                self.pending_transmits.push_back(transmit);
            }
            return Ok(());
        };
        if self
            .allocations
            .iter()
            .any(|alloc| alloc.tcp_data.iter().any(|tcp| tcp.local_addr == tcp_addr))
        {
            return Err(TcpAllocateError::AlreadyExists);
        }

        debug!(
            "TCP socket allocate took {:?} producing tcp address {}",
            pending.initiation_time.map(|s| now - s),
            tcp_addr,
        );

        if let Some(request_id) = pending.request_transaction_id {
            let transmit = Self::send_connection_attempt_response(
                &mut self.stun_auth,
                local_addr,
                remote_addr,
                request_id,
                peer_addr,
                None,
            );
            self.pending_transmits.push_back(transmit);
        }
        let connection_id = pending.connection_id;

        let (transmit, transaction_id) = Self::send_connection_bind_request(
            &mut self.stun_agent,
            &mut self.stun_auth,
            tcp_addr,
            remote_addr,
            connection_id,
            now,
        );

        let alloc = &mut self.allocations[alloc_idx];
        alloc.tcp_data.push(TcpDataChannel {
            pending_transaction_id: Some((
                transaction_id,
                now + TCP_STUN_REQUEST_TIMEOUT,
                connection_id,
            )),
            local_addr: tcp_addr,
            peer_addr,
        });

        self.pending_transmits.push_back(transmit);

        Ok(())
    }

    pub(crate) fn tcp_closed(
        &mut self,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        _now: Instant,
    ) {
        if remote_addr != self.remote_addr() || self.transport() != TransportType::Tcp {
            return;
        }
        if let Some((alloc_idx, tcp_idx)) =
            self.allocations
                .iter()
                .enumerate()
                .find_map(|(idx, alloc)| {
                    alloc
                        .tcp_data
                        .iter()
                        .enumerate()
                        .find_map(|(tcp_idx, tcp)| {
                            if tcp.local_addr == local_addr {
                                Some((idx, tcp_idx))
                            } else {
                                None
                            }
                        })
                })
        {
            let tcp = self.allocations[alloc_idx].tcp_data.swap_remove(tcp_idx);
            info!(
                "Removed tcp socket with local: {}, peer: {}",
                tcp.local_addr, tcp.peer_addr
            );
            self.pending_socket_removal.push_front(Socket5Tuple {
                transport: TransportType::Tcp,
                from: tcp.local_addr,
                to: remote_addr,
            });
        }
    }

    #[tracing::instrument(name = "turn_client_bind_channel", skip(self, now), err)]
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

        if !matches!(self.state, AuthState::Authenticated) {
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
            &mut self.stun_auth,
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
        if !allocation.have_permission(peer_addr.ip())
            && !allocation.have_pending_permission(peer_addr.ip())
        {
            allocation
                .pending_permissions
                .push_back((permission, transaction_id));
        }
        let channel = Channel {
            id: channel_id,
            expires_at: now,
            peer_addr,
            pending_refresh: None,
        };
        allocation
            .pending_channels
            .push_back((channel, transaction_id));
        self.pending_transmits.push_back(transmit.into_owned());
        Ok(())
    }

    pub(crate) fn protocol_error(&mut self) {
        warn!("protocol produced an error");
        self.state = AuthState::Error;
        for &family in self.families.iter() {
            self.pending_events
                .push_front(TurnEvent::AllocationCreateFailed(family));
        }
    }
}

#[derive(Debug)]
enum AuthState {
    Initial,
    InitialSent(TransactionId),
    Authenticating(TransactionId),
    Authenticated,
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

    pending_tcp_turn: Vec<PendingTurnTcp>,
    pending_tcp_allocate: Vec<PendingTcpAllocate>,
    tcp_data: Vec<TcpDataChannel>,

    pending_permissions: VecDeque<(Permission, TransactionId)>,
    pending_channels: VecDeque<(Channel, TransactionId)>,
    pending_refresh: Option<(TransactionId, u32)>,

    expired_channels: Vec<Channel>,
}

impl Allocation {
    fn refresh_time(&self) -> Instant {
        self.expires_at
            - if self.lifetime > EXPIRY_BUFFER * 2 {
                EXPIRY_BUFFER
            } else {
                self.lifetime / 2
            }
    }

    fn have_permission(&self, peer_addr: IpAddr) -> bool {
        self.permissions
            .iter()
            .any(|permission| !permission.expired && permission.ip == peer_addr)
    }

    fn have_pending_permission(&self, peer_addr: IpAddr) -> bool {
        self.pending_permissions
            .iter()
            .any(|(permission, _transaction_id)| !permission.expired && permission.ip == peer_addr)
    }
}

/// Waiting for the TURN server to reply to a TCP CONNECT request.
#[derive(Debug)]
struct PendingTurnTcp {
    transaction_id: TransactionId,
    peer_addr: SocketAddr,
}

/// Waiting for the caller to allocate a TCP socket.
#[derive(Debug)]
struct PendingTcpAllocate {
    connection_id: u32,
    peer_addr: SocketAddr,
    initiation_time: Option<Instant>,
    /// Whether the server initiated the TCP connection and the corresponding STUN transaction ID.
    request_transaction_id: Option<TransactionId>,
}

/// An allocated TCP data connection with the TURN server for a specific peer address.
#[derive(Debug)]
struct TcpDataChannel {
    /// The initial CONNECTION_BIND request. `None` means data can flow.
    pending_transaction_id: Option<(TransactionId, Instant, u32)>,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
}

#[derive(Debug)]
struct Channel {
    id: u16,
    peer_addr: SocketAddr,
    expires_at: Instant,
    pending_refresh: Option<TransactionId>,
}

impl Channel {
    fn refresh_time(&self) -> Instant {
        self.expires_at - EXPIRY_BUFFER
    }
}

#[derive(Debug)]
struct Permission {
    expired: bool,
    expires_at: Instant,
    ip: IpAddr,
    pending_refresh: Option<TransactionId>,
}

impl Permission {
    fn refresh_time(&self) -> Instant {
        self.expires_at - EXPIRY_BUFFER
    }
}

#[derive(Debug)]
pub(crate) enum TurnProtocolRecv {
    Handled,
    Ignored,
    PeerData {
        range: Range<usize>,
        transport: TransportType,
        peer: SocketAddr,
    },
    PeerIcmp {
        transport: TransportType,
        peer: SocketAddr,
        icmp_type: u8,
        icmp_code: u8,
        icmp_data: u32,
    },
    TcpConnectionBound {
        peer_addr: SocketAddr,
    },
}

impl<T: AsRef<[u8]> + core::fmt::Debug> TurnRecvRet<T> {
    pub(crate) fn from_protocol_recv(proto: TurnProtocolRecv, original: Transmit<T>) -> Self {
        match proto {
            TurnProtocolRecv::Handled => TurnRecvRet::Handled,
            TurnProtocolRecv::Ignored => TurnRecvRet::Ignored(original),
            TurnProtocolRecv::PeerData {
                range,
                transport,
                peer,
            } => TurnRecvRet::PeerData(TurnPeerData {
                data: DataRangeOrOwned::Range {
                    data: original.data,
                    range,
                },
                transport,
                peer,
            }),
            TurnProtocolRecv::PeerIcmp {
                transport,
                peer,
                icmp_type,
                icmp_code,
                icmp_data,
            } => TurnRecvRet::PeerIcmp {
                transport,
                peer,
                icmp_type,
                icmp_code,
                icmp_data,
            },
            TurnProtocolRecv::TcpConnectionBound { peer_addr: _ } => TurnRecvRet::Handled,
        }
    }

    pub(crate) fn from_protocol_recv_subrange(
        proto: TurnProtocolRecv,
        original: Transmit<T>,
        offset: usize,
    ) -> Self {
        match proto {
            TurnProtocolRecv::Handled => TurnRecvRet::Handled,
            TurnProtocolRecv::Ignored => TurnRecvRet::Ignored(original),
            TurnProtocolRecv::PeerData {
                range,
                transport,
                peer,
            } => TurnRecvRet::PeerData(TurnPeerData {
                data: DataRangeOrOwned::Range {
                    data: original.data,
                    range: offset + range.start..offset + range.end,
                },
                transport,
                peer,
            }),
            TurnProtocolRecv::PeerIcmp {
                transport,
                peer,
                icmp_type,
                icmp_code,
                icmp_data,
            } => TurnRecvRet::PeerIcmp {
                transport,
                peer,
                icmp_type,
                icmp_code,
                icmp_data,
            },
            TurnProtocolRecv::TcpConnectionBound { peer_addr: _ } => TurnRecvRet::Handled,
        }
    }

    pub(crate) fn from_protocol_recv_stored(
        proto: TurnProtocolRecv,
        original: Transmit<T>,
        msg_data: Vec<u8>,
    ) -> Self {
        match proto {
            TurnProtocolRecv::Handled => TurnRecvRet::Handled,
            TurnProtocolRecv::Ignored => TurnRecvRet::Ignored(original),
            TurnProtocolRecv::PeerData {
                range,
                transport,
                peer,
            } => TurnRecvRet::PeerData(TurnPeerData {
                data: DataRangeOrOwned::Owned(ensure_data_owned(msg_data, range)),
                transport,
                peer,
            }),
            TurnProtocolRecv::PeerIcmp {
                transport,
                peer,
                icmp_type,
                icmp_code,
                icmp_data,
            } => TurnRecvRet::PeerIcmp {
                transport,
                peer,
                icmp_type,
                icmp_code,
                icmp_data,
            },
            TurnProtocolRecv::TcpConnectionBound { peer_addr: _ } => TurnRecvRet::Handled,
        }
    }
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
    use std::string::ToString;

    use turn_server_proto::api::TurnServerApi;
    use turn_types::attribute::ConnectionId;
    use turn_types::prelude::DelayedTransmitBuild;
    use turn_types::stun::attribute::{Nonce, Realm, UnknownAttributes};
    use turn_types::stun::message::{
        IntegrityAlgorithm, LongTermKeyCredentials, MessageHeader, Method,
    };
    use turn_types::stun::prelude::AttributeStaticType;
    use turn_types::TurnCredentials;

    use crate::api::tests::generate_addresses;
    use crate::api::TurnClientApi;
    use crate::tcp::TurnRecvRet;

    use super::*;

    fn new_protocol() -> TurnClientProtocol {
        new_protocol_with_families(
            TransportType::Udp,
            TransportType::Udp,
            &[AddressFamily::IPV4],
        )
    }

    fn new_protocol_with_families(
        client_transport: TransportType,
        allocation_transport: TransportType,
        families: &[AddressFamily],
    ) -> TurnClientProtocol {
        let (local_addr, remote_addr) = generate_addresses();
        let credentials = TurnCredentials::new("tuser", "tpass");

        let stun_agent = StunAgent::builder(client_transport, local_addr)
            .remote_addr(remote_addr)
            .build();
        let mut stun_auth = LongTermClientAuth::new();
        stun_auth.set_credentials(credentials.into());
        let client = TurnClientProtocol::new(stun_agent, stun_auth, allocation_transport, families);
        assert_eq!(client.transport(), client_transport);
        assert_eq!(client.local_addr(), local_addr);
        assert_eq!(client.remote_addr(), remote_addr);

        client
    }

    #[test]
    fn test_turn_client_protocol_new_properties() {
        let _log = crate::tests::test_init_log();
        let mut client = new_protocol();
        let now = Instant::ZERO;

        let TurnPollRet::WaitUntil(new_now) = client.poll(now) else {
            unreachable!();
        };
        assert_eq!(now, new_now);
        assert!(client.poll_event().is_none());

        assert_eq!(client.relayed_addresses().count(), 0);
    }

    fn response<F: FnOnce(Message<'_>) -> Vec<u8>>(
        client: &mut TurnClientProtocol,
        method: Method,
        reply: F,
        now: Instant,
    ) -> TurnProtocolRecv {
        let transmit = client.poll_transmit(now).unwrap();
        let msg = Message::from_bytes(&transmit.data).unwrap();
        trace!(
            "client sending from {} to {} over {} {msg}",
            transmit.from,
            transmit.to,
            transmit.transport
        );
        assert_eq!(msg.method(), method);
        let reply = reply(msg);
        let msg = Message::from_bytes(&reply).unwrap();
        trace!(
            "client receiving from {} to {} over {} {msg}",
            transmit.to,
            transmit.from,
            transmit.transport
        );
        client.handle_message(
            Transmit::new(msg, transmit.transport, transmit.to, transmit.from),
            now,
        )
    }

    fn allocate_response<F: FnOnce(Message<'_>) -> Vec<u8>>(
        client: &mut TurnClientProtocol,
        reply: F,
        now: Instant,
    ) -> TurnProtocolRecv {
        response(client, ALLOCATE, reply, now)
    }

    fn check_allocate_reply_failed(
        client: &mut TurnClientProtocol,
        ret: TurnProtocolRecv,
        now: Instant,
    ) {
        assert!(matches!(ret, TurnProtocolRecv::Handled));
        assert!(matches!(
            client.poll_event(),
            Some(TurnEvent::AllocationCreateFailed(_))
        ));
        assert!(matches!(client.poll(now), TurnPollRet::Closed));
    }

    #[test]
    fn test_turn_client_protocol_initial_allocate_bad_request() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut client = new_protocol();
        let ret = allocate_response(
            &mut client,
            |msg| Message::bad_request(&msg, MessageWriteVec::new()).finish(),
            now,
        );
        check_allocate_reply_failed(&mut client, ret, now);
    }

    #[test]
    fn test_turn_client_protocol_initial_allocate_reply_with_request() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut client = new_protocol();
        let ret = allocate_response(
            &mut client,
            |_msg| Message::builder_request(ALLOCATE, MessageWriteVec::new()).finish(),
            now,
        );
        assert!(matches!(ret, TurnProtocolRecv::Ignored));
    }

    #[test]
    fn test_turn_client_protocol_initial_allocate_reply_missing_attributes() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut client = new_protocol();
        let ret = allocate_response(
            &mut client,
            |msg| {
                let mut reply = Message::builder_error(&msg, MessageWriteVec::new());
                reply.add_attribute(&Nonce::new("nonce").unwrap()).unwrap();
                reply
                    .add_attribute(
                        &ErrorCode::builder(ErrorCode::INSUFFICIENT_CAPACITY)
                            .build()
                            .unwrap(),
                    )
                    .unwrap();
                reply.finish()
            },
            now,
        );
        check_allocate_reply_failed(&mut client, ret, now);

        let mut client = new_protocol();
        let ret = allocate_response(
            &mut client,
            |msg| {
                let mut reply = Message::builder_error(&msg, MessageWriteVec::new());
                reply.add_attribute(&Realm::new("realm").unwrap()).unwrap();
                reply
                    .add_attribute(
                        &ErrorCode::builder(ErrorCode::INSUFFICIENT_CAPACITY)
                            .build()
                            .unwrap(),
                    )
                    .unwrap();
                reply.finish()
            },
            now,
        );
        check_allocate_reply_failed(&mut client, ret, now);

        let mut client = new_protocol();
        let ret = allocate_response(
            &mut client,
            |msg| {
                let mut reply = Message::builder_error(&msg, MessageWriteVec::new());
                reply.add_attribute(&Realm::new("realm").unwrap()).unwrap();
                reply.add_attribute(&Nonce::new("nonce").unwrap()).unwrap();
                reply.finish()
            },
            now,
        );
        check_allocate_reply_failed(&mut client, ret, now);
    }

    #[test]
    fn test_turn_client_protocol_initial_allocate_reply_wrong_errorcode() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut client = new_protocol();
        let ret = allocate_response(
            &mut client,
            |msg| {
                let mut reply = Message::builder_error(&msg, MessageWriteVec::new());
                reply.add_attribute(&Realm::new("realm").unwrap()).unwrap();
                reply.add_attribute(&Nonce::new("nonce").unwrap()).unwrap();
                reply
                    .add_attribute(
                        &ErrorCode::builder(ErrorCode::INSUFFICIENT_CAPACITY)
                            .build()
                            .unwrap(),
                    )
                    .unwrap();
                reply.finish()
            },
            now,
        );
        check_allocate_reply_failed(&mut client, ret, now);
    }

    #[test]
    fn test_turn_client_protocol_initial_allocate_timeout() {
        let _log = crate::tests::test_init_log();
        let mut now = Instant::ZERO;
        let mut client = new_protocol();
        let _transmit = client.poll_transmit(now).unwrap();
        while let TurnPollRet::WaitUntil(new_now) = client.poll(now) {
            now = new_now;
            let _transmit = client.poll_transmit(now);
        }
        check_allocate_reply_failed(&mut client, TurnProtocolRecv::Handled, now + EXPIRY_BUFFER);
    }

    #[test]
    fn test_turn_client_protocol_initial_allocate_unexpected_success() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut client = new_protocol();
        let ret = allocate_response(
            &mut client,
            |msg| {
                let mut reply = Message::builder_success(&msg, MessageWriteVec::new());
                reply.add_attribute(&Realm::new("realm").unwrap()).unwrap();
                reply.add_attribute(&Nonce::new("nonce").unwrap()).unwrap();
                reply.finish()
            },
            now,
        );
        check_allocate_reply_failed(&mut client, ret, now);
    }

    fn initial_allocate(client: &mut TurnClientProtocol, now: Instant) {
        assert!(matches!(
            allocate_response(
                client,
                |msg| {
                    let mut reply = Message::builder_error(&msg, MessageWriteVec::new());
                    reply.add_attribute(&Realm::new("realm").unwrap()).unwrap();
                    reply.add_attribute(&Nonce::new("nonce").unwrap()).unwrap();
                    reply
                        .add_attribute(
                            &ErrorCode::builder(ErrorCode::UNAUTHORIZED).build().unwrap(),
                        )
                        .unwrap();
                    reply.finish()
                },
                now,
            ),
            TurnProtocolRecv::Handled
        ));
    }

    fn client_credentials(client: &TurnClientProtocol) -> LongTermKeyCredentials {
        client
            .stun_auth
            .credentials()
            .unwrap()
            .to_key("realm".to_string())
    }

    #[test]
    fn test_turn_client_protocol_authenticated_allocate_reply_with_request() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut client = new_protocol();
        initial_allocate(&mut client, now);
        let credentials = client_credentials(&client);
        let ret = allocate_response(
            &mut client,
            |_msg| {
                let mut reply = Message::builder_request(ALLOCATE, MessageWriteVec::new());
                reply
                    .add_message_integrity(&credentials.into(), IntegrityAlgorithm::Sha1)
                    .unwrap();
                reply.finish()
            },
            now,
        );
        assert!(matches!(ret, TurnProtocolRecv::Ignored));
    }

    #[test]
    fn test_turn_client_protocol_authenticated_allocate_reply_bad_request() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut client = new_protocol();
        initial_allocate(&mut client, now);
        let credentials = client_credentials(&client);
        let ret = allocate_response(
            &mut client,
            |msg| {
                let mut reply = Message::bad_request(&msg, MessageWriteVec::new());
                reply
                    .add_message_integrity(&credentials.into(), IntegrityAlgorithm::Sha1)
                    .unwrap();
                reply.finish()
            },
            now,
        );
        check_allocate_reply_failed(&mut client, ret, now);
    }

    #[test]
    fn test_turn_client_protocol_authenticated_allocate_reply_error() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut client = new_protocol();
        initial_allocate(&mut client, now);
        let credentials = client_credentials(&client);
        let ret = allocate_response(
            &mut client,
            |msg| {
                let mut reply = Message::builder_error(&msg, MessageWriteVec::new());
                reply
                    .add_message_integrity(&credentials.into(), IntegrityAlgorithm::Sha1)
                    .unwrap();
                reply.finish()
            },
            now,
        );
        check_allocate_reply_failed(&mut client, ret, now);
    }

    fn generate_xor_relayed_address() -> SocketAddr {
        "10.0.0.4:40000".parse().unwrap()
    }

    fn generate_ipv6_xor_relayed_address() -> SocketAddr {
        "[::1]:40000".parse().unwrap()
    }

    fn generate_xor_peer_address() -> SocketAddr {
        "10.0.0.3:9000".parse().unwrap()
    }

    fn generate_ipv6_xor_peer_address() -> SocketAddr {
        "[::1]:9000".parse().unwrap()
    }

    static TEST_ALLOCATION_LIFETIME: u32 = 1000;

    #[test]
    fn test_turn_client_protocol_authenticated_allocate_reply_missing_attribute() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut client = new_protocol();
        initial_allocate(&mut client, now);
        let credentials = client_credentials(&client);
        let ret = allocate_response(
            &mut client,
            |msg| {
                let mut reply = Message::builder_success(&msg, MessageWriteVec::new());
                reply
                    .add_attribute(&Lifetime::new(TEST_ALLOCATION_LIFETIME))
                    .unwrap();
                reply
                    .add_message_integrity(&credentials.into(), IntegrityAlgorithm::Sha1)
                    .unwrap();
                reply.finish()
            },
            now,
        );
        check_allocate_reply_failed(&mut client, ret, now);

        let mut client = new_protocol();
        initial_allocate(&mut client, now);
        let credentials = client_credentials(&client);
        let ret = allocate_response(
            &mut client,
            |msg| {
                let mut reply = Message::builder_success(&msg, MessageWriteVec::new());
                let transaction_id = reply.transaction_id();
                reply
                    .add_attribute(&XorRelayedAddress::new(
                        generate_xor_relayed_address(),
                        transaction_id,
                    ))
                    .unwrap();
                reply
                    .add_message_integrity(&credentials.into(), IntegrityAlgorithm::Sha1)
                    .unwrap();
                reply.finish()
            },
            now,
        );
        check_allocate_reply_failed(&mut client, ret, now);
    }

    fn authenticated_allocate(client: &mut TurnClientProtocol, now: Instant) {
        authenticated_allocate_with_address(client, &[generate_xor_relayed_address()], now);
    }

    fn authenticated_allocate_with_address(
        client: &mut TurnClientProtocol,
        relayed: &[SocketAddr],
        now: Instant,
    ) {
        let credentials = client_credentials(client);
        let ret = allocate_response(
            client,
            |msg| {
                let mut reply = Message::builder_success(&msg, MessageWriteVec::new());
                let transaction_id = reply.transaction_id();
                for addr in relayed {
                    reply
                        .add_attribute(&XorRelayedAddress::new(*addr, transaction_id))
                        .unwrap();
                }
                reply
                    .add_attribute(&Lifetime::new(TEST_ALLOCATION_LIFETIME))
                    .unwrap();
                reply
                    .add_message_integrity(&credentials.into(), IntegrityAlgorithm::Sha1)
                    .unwrap();
                reply.finish()
            },
            now,
        );
        assert!(matches!(ret, TurnProtocolRecv::Handled));
        for _addr in relayed {
            let Some(TurnEvent::AllocationCreated(transport, allocation)) = client.poll_event()
            else {
                unreachable!();
            };
            assert_eq!(transport, client.allocation_transport);
            assert!(relayed.contains(&allocation));
        }
        assert_eq!(client.relayed_addresses().count(), relayed.len());
    }

    fn wait_advance(client: &mut TurnClientProtocol, now: Instant) -> Instant {
        let TurnPollRet::WaitUntil(expiry) = client.poll(now) else {
            unreachable!();
        };
        assert!(expiry > now);
        expiry
    }

    fn check_closed(client: &mut TurnClientProtocol, now: Instant) {
        assert!(matches!(client.poll(now), TurnPollRet::Closed));
        assert_eq!(client.relayed_addresses().count(), 0);
    }

    #[test]
    fn test_turn_client_protocol_authenticated_allocate_expire() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut client = new_protocol();
        initial_allocate(&mut client, now);
        authenticated_allocate(&mut client, now);
        let now = wait_advance(&mut client, now);
        check_closed(&mut client, now + EXPIRY_BUFFER + Duration::from_secs(1));
    }

    fn generate_stale_nonce(msg: &Message<'_>) -> Vec<u8> {
        let mut reply = Message::builder_error(msg, MessageWriteVec::new());
        reply
            .add_attribute(&ErrorCode::builder(ErrorCode::STALE_NONCE).build().unwrap())
            .unwrap();
        reply.add_attribute(&Realm::new("realm").unwrap()).unwrap();
        reply.add_attribute(&Nonce::new("nonce").unwrap()).unwrap();
        reply.finish()
    }

    #[test]
    fn test_turn_client_protocol_authenticated_allocate_reply_stale_nonce() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut client = new_protocol();
        initial_allocate(&mut client, now);
        let ret = allocate_response(&mut client, |msg| generate_stale_nonce(&msg), now);
        assert!(matches!(ret, TurnProtocolRecv::Handled));
        authenticated_allocate(&mut client, now);
    }

    #[test]
    fn test_turn_client_protocol_authenticated_allocate_reply_stale_nonce_missing_attributes() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut client = new_protocol();
        initial_allocate(&mut client, now);
        let ret = allocate_response(
            &mut client,
            |msg| {
                let mut reply = Message::builder_error(&msg, MessageWriteVec::new());
                reply
                    .add_attribute(&ErrorCode::builder(ErrorCode::STALE_NONCE).build().unwrap())
                    .unwrap();
                reply.add_attribute(&Nonce::new("nonce").unwrap()).unwrap();
                reply.finish()
            },
            now,
        );
        assert!(matches!(ret, TurnProtocolRecv::Ignored));

        let mut client = new_protocol();
        initial_allocate(&mut client, now);
        let ret = allocate_response(
            &mut client,
            |msg| {
                let mut reply = Message::builder_error(&msg, MessageWriteVec::new());
                reply.add_attribute(&Realm::new("realm").unwrap()).unwrap();
                reply.add_attribute(&Nonce::new("nonce").unwrap()).unwrap();
                reply.finish()
            },
            now,
        );
        assert!(matches!(ret, TurnProtocolRecv::Ignored));

        let mut client = new_protocol();
        initial_allocate(&mut client, now);
        let ret = allocate_response(
            &mut client,
            |msg| {
                let mut reply = Message::builder_error(&msg, MessageWriteVec::new());
                reply
                    .add_attribute(&ErrorCode::builder(ErrorCode::STALE_NONCE).build().unwrap())
                    .unwrap();
                reply.add_attribute(&Nonce::new("nonce").unwrap()).unwrap();
                reply.finish()
            },
            now,
        );
        assert!(matches!(ret, TurnProtocolRecv::Ignored));
    }

    #[test]
    fn test_turn_client_protocol_ipv6_allocation_unknown_requested_address_family() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut client = new_protocol_with_families(
            TransportType::Udp,
            TransportType::Udp,
            &[AddressFamily::IPV6],
        );
        initial_allocate(&mut client, now);
        let credentials = client_credentials(&client);
        let ret = allocate_response(
            &mut client,
            |msg| {
                assert!(msg.has_attribute(RequestedAddressFamily::TYPE));
                let mut reply = Message::builder_error(&msg, MessageWriteVec::new());
                reply
                    .add_attribute(
                        &ErrorCode::builder(ErrorCode::UNKNOWN_ATTRIBUTE)
                            .build()
                            .unwrap(),
                    )
                    .unwrap();
                reply
                    .add_attribute(&UnknownAttributes::new(&[RequestedAddressFamily::TYPE]))
                    .unwrap();
                reply
                    .add_message_integrity(&credentials.into(), IntegrityAlgorithm::Sha1)
                    .unwrap();
                reply.finish()
            },
            now,
        );
        assert!(matches!(ret, TurnProtocolRecv::Handled));
        let Some(TurnEvent::AllocationCreateFailed(AddressFamily::IPV6)) = client.poll_event()
        else {
            unreachable!();
        };
        assert_eq!(client.relayed_addresses().count(), 0);
    }

    // this is the auth flow for a server that does not support RFC8656 and only supports IPv6
    // allocations.
    #[test]
    fn test_turn_client_protocol_unsupported_address_family() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut client = new_protocol_with_families(
            TransportType::Udp,
            TransportType::Udp,
            &[AddressFamily::IPV4, AddressFamily::IPV6],
        );
        initial_allocate(&mut client, now);
        let credentials = client_credentials(&client);
        let ret = allocate_response(
            &mut client,
            |msg| {
                let mut reply = Message::builder_error(&msg, MessageWriteVec::new());
                reply
                    .add_attribute(
                        &ErrorCode::builder(ErrorCode::ADDRESS_FAMILY_NOT_SUPPORTED)
                            .build()
                            .unwrap(),
                    )
                    .unwrap();
                reply
                    .add_message_integrity(&credentials.into(), IntegrityAlgorithm::Sha1)
                    .unwrap();
                reply.finish()
            },
            now,
        );
        assert!(matches!(ret, TurnProtocolRecv::Handled));
        let Some(TurnEvent::AllocationCreateFailed(AddressFamily::IPV4)) = client.poll_event()
        else {
            unreachable!();
        };
        assert_eq!(client.relayed_addresses().count(), 0);
        authenticated_allocate_with_address(
            &mut client,
            &[generate_ipv6_xor_relayed_address()],
            now,
        );
    }

    #[test]
    fn test_turn_client_protocol_dual_allocation() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut client = new_protocol_with_families(
            TransportType::Udp,
            TransportType::Udp,
            &[AddressFamily::IPV4, AddressFamily::IPV6],
        );
        initial_allocate(&mut client, now);
        authenticated_allocate_with_address(
            &mut client,
            &[
                generate_ipv6_xor_relayed_address(),
                generate_xor_relayed_address(),
            ],
            now,
        );
    }

    #[test]
    fn test_turn_client_protocol_refresh_timeout() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut client = new_protocol();
        initial_allocate(&mut client, now);
        authenticated_allocate(&mut client, now);
        let mut now = wait_advance(&mut client, now);
        let _transmit = client.poll_transmit(now).unwrap();
        while let TurnPollRet::WaitUntil(new_now) = client.poll(now) {
            now = new_now;
            let _transmit = client.poll_transmit(now);
        }
        check_closed(&mut client, now + EXPIRY_BUFFER);
    }

    #[test]
    fn test_turn_client_protocol_refresh_reply_missing_attributes() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut client = new_protocol();
        initial_allocate(&mut client, now);
        authenticated_allocate(&mut client, now);
        let now = wait_advance(&mut client, now);
        let credentials = client_credentials(&client);
        let ret = refresh_response(
            &mut client,
            |msg| {
                let mut reply = Message::builder_success(&msg, MessageWriteVec::new());
                reply
                    .add_message_integrity(&credentials.into(), IntegrityAlgorithm::Sha1)
                    .unwrap();
                reply.finish()
            },
            now,
        );
        assert!(matches!(ret, TurnProtocolRecv::Handled));
    }

    fn refresh_response<F: FnOnce(Message<'_>) -> Vec<u8>>(
        client: &mut TurnClientProtocol,
        reply: F,
        now: Instant,
    ) -> TurnProtocolRecv {
        response(client, REFRESH, reply, now)
    }

    #[test]
    fn test_turn_client_protocol_refresh_error() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut client = new_protocol();
        initial_allocate(&mut client, now);
        authenticated_allocate(&mut client, now);
        let now = wait_advance(&mut client, now);
        let credentials = client_credentials(&client);
        let ret = refresh_response(
            &mut client,
            |msg| {
                let mut reply = Message::builder_error(&msg, MessageWriteVec::new());
                reply
                    .add_message_integrity(&credentials.into(), IntegrityAlgorithm::Sha1)
                    .unwrap();
                reply.finish()
            },
            now,
        );
        assert!(matches!(ret, TurnProtocolRecv::Handled));
        check_closed(&mut client, now + EXPIRY_BUFFER + Duration::from_secs(1));
    }

    fn generate_refresh_response(
        msg: &Message<'_>,
        credentials: LongTermKeyCredentials,
    ) -> Vec<u8> {
        let mut reply = Message::builder_success(msg, MessageWriteVec::new());
        reply
            .add_attribute(&Lifetime::new(TEST_ALLOCATION_LIFETIME))
            .unwrap();
        reply
            .add_message_integrity(&credentials.into(), IntegrityAlgorithm::Sha1)
            .unwrap();
        reply.finish()
    }

    fn generate_delete_response(msg: &Message<'_>, credentials: LongTermKeyCredentials) -> Vec<u8> {
        let mut reply = Message::builder_success(msg, MessageWriteVec::new());
        reply.add_attribute(&Lifetime::new(0)).unwrap();
        reply
            .add_message_integrity(&credentials.into(), IntegrityAlgorithm::Sha1)
            .unwrap();
        reply.finish()
    }

    fn refresh(client: &mut TurnClientProtocol, now: Instant) {
        let credentials = client_credentials(client);
        let ret = refresh_response(
            client,
            |msg| generate_refresh_response(&msg, credentials),
            now,
        );
        assert!(matches!(ret, TurnProtocolRecv::Handled));
    }

    #[test]
    fn test_turn_client_protocol_refresh_stale_nonce() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut client = new_protocol();
        initial_allocate(&mut client, now);
        authenticated_allocate(&mut client, now);
        let now = wait_advance(&mut client, now);
        let ret = refresh_response(&mut client, |msg| generate_stale_nonce(&msg), now);
        assert!(matches!(ret, TurnProtocolRecv::Handled));
        refresh(&mut client, now);
        let TurnPollRet::WaitUntil(_now) =
            client.poll(now + EXPIRY_BUFFER + Duration::from_secs(1))
        else {
            unreachable!();
        };
        assert_eq!(client.relayed_addresses().count(), 1);
    }

    #[test]
    fn test_turn_client_protocol_refresh_stale_nonce_unanswered_refresh() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut client = new_protocol();
        initial_allocate(&mut client, now);
        authenticated_allocate(&mut client, now);
        let now = wait_advance(&mut client, now);
        let ret = refresh_response(&mut client, |msg| generate_stale_nonce(&msg), now);
        assert!(matches!(ret, TurnProtocolRecv::Handled));
        // drop the re-REFRESH
        let _transmit = client.poll_transmit(now).unwrap();
        check_closed(&mut client, now + EXPIRY_BUFFER + Duration::from_secs(1));
    }

    #[test]
    fn test_turn_client_protocol_delete_stale_nonce() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut client = new_protocol();
        initial_allocate(&mut client, now);
        authenticated_allocate(&mut client, now);
        let now = wait_advance(&mut client, now);
        client.delete(now).unwrap();
        let ret = refresh_response(&mut client, |msg| generate_stale_nonce(&msg), now);
        assert!(matches!(ret, TurnProtocolRecv::Handled));
        let credentials = client_credentials(&client);
        let ret = refresh_response(
            &mut client,
            |msg| generate_delete_response(&msg, credentials),
            now,
        );
        assert!(matches!(ret, TurnProtocolRecv::Handled));
        check_closed(&mut client, now);
    }

    #[test]
    fn test_turn_client_protocol_delete_allocation_mismatch() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut client = new_protocol();
        initial_allocate(&mut client, now);
        authenticated_allocate(&mut client, now);
        let now = wait_advance(&mut client, now);
        client.delete(now).unwrap();
        let credentials = client_credentials(&client);
        let ret = refresh_response(
            &mut client,
            |msg| {
                let mut reply = Message::builder_error(&msg, MessageWriteVec::new());
                reply
                    .add_attribute(
                        &ErrorCode::builder(ErrorCode::ALLOCATION_MISMATCH)
                            .build()
                            .unwrap(),
                    )
                    .unwrap();
                reply
                    .add_message_integrity(&credentials.into(), IntegrityAlgorithm::Sha1)
                    .unwrap();
                reply.finish()
            },
            now,
        );
        assert!(matches!(ret, TurnProtocolRecv::Handled));
        check_closed(&mut client, now);
    }

    #[test]
    fn test_turn_client_protocol_channel_bind_timeout() {
        let _log = crate::tests::test_init_log();
        let mut now = Instant::ZERO;
        let mut client = new_protocol();
        initial_allocate(&mut client, now);
        authenticated_allocate(&mut client, now);
        client
            .bind_channel(TransportType::Udp, generate_xor_peer_address(), now)
            .unwrap();
        let _transmit = client.poll_transmit(now);
        while let TurnPollRet::WaitUntil(new_now) = client.poll(now) {
            let (transport, relayed) = client.relayed_addresses().next().unwrap();
            assert_eq!(client.permissions(transport, relayed).count(), 0);
            if now == new_now {
                break;
            }
            now = new_now;
            let _transmit = client.poll_transmit(now);
        }
        assert!(matches!(
            client.poll_event(),
            Some(TurnEvent::PermissionCreateFailed(_, _))
        ));
    }

    fn channel_bind_response<F: FnOnce(Message<'_>) -> Vec<u8>>(
        client: &mut TurnClientProtocol,
        reply: F,
        now: Instant,
    ) -> TurnProtocolRecv {
        response(client, CHANNEL_BIND, reply, now)
    }

    fn check_permission_create_failed(client: &mut TurnClientProtocol, ret: TurnProtocolRecv) {
        let (transport, relayed) = client.relayed_addresses().next().unwrap();
        assert_eq!(client.permissions(transport, relayed).count(), 0);
        assert!(matches!(ret, TurnProtocolRecv::Handled));
        assert!(matches!(
            client.poll_event(),
            Some(TurnEvent::PermissionCreateFailed(_, _))
        ));
    }

    fn check_channel_bind_failed(client: &mut TurnClientProtocol, ret: TurnProtocolRecv) {
        let (transport, relayed) = client.relayed_addresses().next().unwrap();
        assert_eq!(client.permissions(transport, relayed).count(), 0);
        assert!(matches!(ret, TurnProtocolRecv::Handled));
        assert!(matches!(
            client.poll_event(),
            Some(TurnEvent::ChannelCreateFailed(_, _))
        ));
    }

    #[test]
    fn test_turn_client_protocol_channel_bind_error() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut client = new_protocol();
        initial_allocate(&mut client, now);
        authenticated_allocate(&mut client, now);
        client
            .bind_channel(TransportType::Udp, generate_xor_peer_address(), now)
            .unwrap();
        let credentials = client_credentials(&client);
        let ret = channel_bind_response(
            &mut client,
            |msg| {
                let mut reply = Message::builder_error(&msg, MessageWriteVec::new());
                reply
                    .add_attribute(&ErrorCode::builder(ErrorCode::FORBIDDEN).build().unwrap())
                    .unwrap();
                reply
                    .add_message_integrity(&credentials.into(), IntegrityAlgorithm::Sha1)
                    .unwrap();
                reply.finish()
            },
            now,
        );
        check_channel_bind_failed(&mut client, ret);
    }

    fn channel_bind_refresh_success_response(client: &mut TurnClientProtocol, now: Instant) {
        let credentials = client_credentials(client);
        assert!(matches!(
            channel_bind_response(
                client,
                |msg| {
                    let mut reply = Message::builder_success(&msg, MessageWriteVec::new());
                    reply
                        .add_message_integrity(&credentials.into(), IntegrityAlgorithm::Sha1)
                        .unwrap();
                    reply.finish()
                },
                now,
            ),
            TurnProtocolRecv::Handled
        ));
        let (transport, _relayed) = client.relayed_addresses().next().unwrap();
        assert!(client.have_permission(transport, generate_xor_peer_address().ip()));
    }

    fn channel_bind_success_response(client: &mut TurnClientProtocol, now: Instant) {
        channel_bind_refresh_success_response(client, now);
        assert!(matches!(
            client.poll_event(),
            Some(TurnEvent::PermissionCreated(_, _))
        ));
        assert!(matches!(
            client.poll_event(),
            Some(TurnEvent::ChannelCreated(_, _))
        ));
    }

    fn channel_bind(client: &mut TurnClientProtocol, now: Instant) {
        channel_bind_with_address(client, generate_xor_peer_address(), now);
    }

    fn channel_bind_with_address(client: &mut TurnClientProtocol, peer: SocketAddr, now: Instant) {
        client.bind_channel(TransportType::Udp, peer, now).unwrap();
        channel_bind_success_response(client, now);
    }

    #[test]
    fn test_turn_client_protocol_channel_bind_refresh_timeout() {
        let _log = crate::tests::test_init_log();
        let mut now = Instant::ZERO;
        let mut client = new_protocol();
        initial_allocate(&mut client, now);
        authenticated_allocate(&mut client, now);
        channel_bind(&mut client, now);
        while let TurnPollRet::WaitUntil(new_now) = client.poll(now) {
            if now == new_now {
                break;
            }
            now = new_now;
            if let Some(transmit) = client.poll_transmit(now) {
                let hdr = MessageHeader::from_bytes(&transmit.data).unwrap();
                match hdr.get_type().method() {
                    CREATE_PERMISSION => {
                        client.pending_transmits.push_front(transmit);
                        create_permission_success_response(&mut client, now);
                    }
                    REFRESH => {
                        client.pending_transmits.push_front(transmit);
                        refresh(&mut client, now);
                    }
                    _ => (),
                }
            }
        }
    }

    #[test]
    fn test_turn_client_protocol_channel_bind_stale_nonce() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut client = new_protocol();
        initial_allocate(&mut client, now);
        authenticated_allocate(&mut client, now);
        client
            .bind_channel(TransportType::Udp, generate_xor_peer_address(), now)
            .unwrap();
        let ret = channel_bind_response(&mut client, |msg| generate_stale_nonce(&msg), now);
        assert!(matches!(ret, TurnProtocolRecv::Handled));
        channel_bind_success_response(&mut client, now);
    }

    #[test]
    fn test_turn_client_protocol_channel_bind_refresh_stale_nonce() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut client = new_protocol();
        initial_allocate(&mut client, now);
        authenticated_allocate(&mut client, now);
        channel_bind(&mut client, now);
        let TurnPollRet::WaitUntil(now) = client.poll(now) else {
            unreachable!();
        };
        create_permission_success_response(&mut client, now);
        let TurnPollRet::WaitUntil(now) = client.poll(now) else {
            unreachable!();
        };
        create_permission_success_response(&mut client, now);
        let TurnPollRet::WaitUntil(now) = client.poll(now) else {
            unreachable!();
        };
        let ret = channel_bind_response(&mut client, |msg| generate_stale_nonce(&msg), now);
        assert!(matches!(ret, TurnProtocolRecv::Handled));
        channel_bind_refresh_success_response(&mut client, now);
    }

    #[test]
    fn test_turn_client_protocol_dual_allocation_channel_bind() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut client = new_protocol_with_families(
            TransportType::Udp,
            TransportType::Udp,
            &[AddressFamily::IPV4, AddressFamily::IPV6],
        );
        initial_allocate(&mut client, now);
        authenticated_allocate_with_address(
            &mut client,
            &[
                generate_ipv6_xor_relayed_address(),
                generate_xor_relayed_address(),
            ],
            now,
        );
        channel_bind_with_address(&mut client, generate_xor_peer_address(), now);
        channel_bind_with_address(&mut client, generate_ipv6_xor_peer_address(), now);
    }

    #[test]
    fn test_turn_client_protocol_channel_bind_wrong_address_family() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut client = new_protocol_with_families(
            TransportType::Udp,
            TransportType::Udp,
            &[AddressFamily::IPV4, AddressFamily::IPV6],
        );
        initial_allocate(&mut client, now);
        authenticated_allocate(&mut client, now);
        assert!(matches!(
            client.bind_channel(TransportType::Udp, generate_ipv6_xor_peer_address(), now),
            Err(BindChannelError::NoAllocation)
        ));
    }

    #[test]
    fn test_turn_client_protocol_create_permission_timeout() {
        let _log = crate::tests::test_init_log();
        let mut now = Instant::ZERO;
        let mut client = new_protocol();
        initial_allocate(&mut client, now);
        authenticated_allocate(&mut client, now);
        client
            .create_permission(TransportType::Udp, generate_xor_peer_address().ip(), now)
            .unwrap();
        let _transmit = client.poll_transmit(now);
        while let TurnPollRet::WaitUntil(new_now) = client.poll(now) {
            let (transport, relayed) = client.relayed_addresses().next().unwrap();
            assert_eq!(client.permissions(transport, relayed).count(), 0);
            if now == new_now {
                break;
            }
            now = new_now;
            let _transmit = client.poll_transmit(now);
        }
        assert!(matches!(
            client.poll_event(),
            Some(TurnEvent::PermissionCreateFailed(_, _))
        ));
    }

    fn create_permission_response<F: FnOnce(Message<'_>) -> Vec<u8>>(
        client: &mut TurnClientProtocol,
        reply: F,
        now: Instant,
    ) -> TurnProtocolRecv {
        response(client, CREATE_PERMISSION, reply, now)
    }

    #[test]
    fn test_turn_client_protocol_create_permission_error() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut client = new_protocol();
        initial_allocate(&mut client, now);
        authenticated_allocate(&mut client, now);
        client
            .create_permission(TransportType::Udp, generate_xor_peer_address().ip(), now)
            .unwrap();
        let credentials = client_credentials(&client);
        let ret = create_permission_response(
            &mut client,
            |msg| {
                let mut reply = Message::builder_error(&msg, MessageWriteVec::new());
                reply
                    .add_attribute(&ErrorCode::builder(ErrorCode::FORBIDDEN).build().unwrap())
                    .unwrap();
                reply
                    .add_message_integrity(&credentials.into(), IntegrityAlgorithm::Sha1)
                    .unwrap();
                reply.finish()
            },
            now,
        );
        check_permission_create_failed(&mut client, ret);
    }

    fn create_permission_success_response(client: &mut TurnClientProtocol, now: Instant) {
        let credentials = client_credentials(client);
        assert!(matches!(
            create_permission_response(
                client,
                |msg| {
                    let mut reply = Message::builder_success(&msg, MessageWriteVec::new());
                    reply
                        .add_message_integrity(&credentials.into(), IntegrityAlgorithm::Sha1)
                        .unwrap();
                    reply.finish()
                },
                now,
            ),
            TurnProtocolRecv::Handled
        ));
    }

    fn create_permission(client: &mut TurnClientProtocol, now: Instant) {
        create_permission_with_address(client, generate_xor_peer_address(), now);
    }

    fn create_permission_with_address(
        client: &mut TurnClientProtocol,
        peer: SocketAddr,
        now: Instant,
    ) {
        client
            .create_permission(client.allocation_transport, peer.ip(), now)
            .unwrap();
        create_permission_success_response(client, now);
        let (transport, _relayed) = client.relayed_addresses().next().unwrap();
        assert!(matches!(
            client.poll_event(),
            Some(TurnEvent::PermissionCreated(_, _))
        ));
        assert!(client.have_permission(transport, peer.ip()));
    }

    #[test]
    fn test_turn_client_protocol_create_permission_refresh_timeout() {
        let _log = crate::tests::test_init_log();
        let mut now = Instant::ZERO;
        let mut client = new_protocol();
        initial_allocate(&mut client, now);
        authenticated_allocate(&mut client, now);
        create_permission(&mut client, now);
        while let TurnPollRet::WaitUntil(new_now) = client.poll(now) {
            if now == new_now {
                break;
            }
            now = new_now;
            let _transmit = client.poll_transmit(now);
        }
        assert!(matches!(
            client.poll_event(),
            Some(TurnEvent::PermissionCreateFailed(_, _))
        ));
    }

    #[test]
    fn test_turn_client_protocol_create_permission_stale_nonce() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut client = new_protocol();
        initial_allocate(&mut client, now);
        authenticated_allocate(&mut client, now);
        client
            .create_permission(TransportType::Udp, generate_xor_peer_address().ip(), now)
            .unwrap();
        let ret = create_permission_response(&mut client, |msg| generate_stale_nonce(&msg), now);
        assert!(matches!(ret, TurnProtocolRecv::Handled));
        create_permission_success_response(&mut client, now);
    }

    #[test]
    fn test_turn_client_protocol_create_permission_refresh_stale_nonce() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut client = new_protocol();
        initial_allocate(&mut client, now);
        authenticated_allocate(&mut client, now);
        create_permission(&mut client, now);
        let TurnPollRet::WaitUntil(now) = client.poll(now) else {
            unreachable!();
        };
        let ret = create_permission_response(&mut client, |msg| generate_stale_nonce(&msg), now);
        assert!(matches!(ret, TurnProtocolRecv::Handled));
        create_permission_success_response(&mut client, now);
    }

    #[test]
    fn test_turn_client_protocol_dual_allocation_create_permission() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut client = new_protocol_with_families(
            TransportType::Udp,
            TransportType::Udp,
            &[AddressFamily::IPV4, AddressFamily::IPV6],
        );
        initial_allocate(&mut client, now);
        authenticated_allocate_with_address(
            &mut client,
            &[
                generate_ipv6_xor_relayed_address(),
                generate_xor_relayed_address(),
            ],
            now,
        );
        create_permission_with_address(&mut client, generate_xor_peer_address(), now);
        create_permission_with_address(&mut client, generate_ipv6_xor_peer_address(), now);
    }

    #[test]
    fn test_turn_client_protocol_create_permission_wrong_address_family() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut client = new_protocol_with_families(
            TransportType::Udp,
            TransportType::Udp,
            &[AddressFamily::IPV4, AddressFamily::IPV6],
        );
        initial_allocate(&mut client, now);
        authenticated_allocate(&mut client, now);
        assert!(matches!(
            client.create_permission(
                TransportType::Udp,
                generate_ipv6_xor_peer_address().ip(),
                now
            ),
            Err(CreatePermissionError::NoAllocation)
        ));
    }

    fn generate_icmp_message(peer: SocketAddr) -> Vec<u8> {
        let mut msg = Message::builder_indication(DATA, MessageWriteVec::new());
        msg.add_attribute(&XorPeerAddress::new(peer, msg.transaction_id()))
            .unwrap();
        msg.add_attribute(&Icmp::new(0x1, 0x2, 0x3)).unwrap();
        msg.finish()
    }

    #[test]
    fn test_turn_client_protocol_icmp_without_permission() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut client = new_protocol_with_families(
            TransportType::Udp,
            TransportType::Udp,
            &[AddressFamily::IPV4],
        );
        initial_allocate(&mut client, now);
        authenticated_allocate(&mut client, now);

        let msg = generate_icmp_message(generate_xor_peer_address());
        let msg = Message::from_bytes(&msg).unwrap();
        assert!(matches!(
            client.handle_message(
                Transmit::new(
                    msg,
                    client.transport(),
                    client.remote_addr(),
                    client.local_addr()
                ),
                now
            ),
            TurnProtocolRecv::Ignored
        ));
    }

    #[test]
    fn test_turn_client_protocol_icmp() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut client = new_protocol_with_families(
            TransportType::Udp,
            TransportType::Udp,
            &[AddressFamily::IPV4],
        );
        initial_allocate(&mut client, now);
        authenticated_allocate(&mut client, now);
        create_permission(&mut client, now);
        let msg = generate_icmp_message(generate_xor_peer_address());
        let msg = Message::from_bytes(&msg).unwrap();
        let TurnProtocolRecv::PeerIcmp {
            transport,
            peer,
            icmp_type,
            icmp_code,
            icmp_data,
        } = client.handle_message(
            Transmit::new(
                msg,
                client.transport(),
                client.remote_addr(),
                client.local_addr(),
            ),
            now,
        )
        else {
            unreachable!();
        };
        assert_eq!(transport, TransportType::Udp);
        assert_eq!(peer, generate_xor_peer_address());
        assert_eq!(icmp_type, 0x1);
        assert_eq!(icmp_code, 0x2);
        assert_eq!(icmp_data, 0x3);
    }

    fn connect_response<F: FnOnce(Message<'_>) -> Vec<u8>>(
        client: &mut TurnClientProtocol,
        reply: F,
        now: Instant,
    ) -> TurnProtocolRecv {
        response(client, CONNECT, reply, now)
    }

    fn connect_success_response(client: &mut TurnClientProtocol, id: u32, now: Instant) {
        let credentials = client_credentials(client);
        assert!(matches!(
            connect_response(
                client,
                |msg| {
                    let mut reply = Message::builder_success(&msg, MessageWriteVec::new());
                    reply.add_attribute(&ConnectionId::new(id)).unwrap();
                    reply
                        .add_message_integrity(&credentials.into(), IntegrityAlgorithm::Sha1)
                        .unwrap();
                    reply.finish()
                },
                now,
            ),
            TurnProtocolRecv::Handled
        ));
        let TurnPollRet::AllocateTcpSocket {
            id: connection_id,
            socket,
            peer_addr,
        } = client.poll(now)
        else {
            unreachable!();
        };
        assert_eq!(id, connection_id);
        assert_eq!(
            socket,
            Socket5Tuple {
                transport: TransportType::Tcp,
                from: client.local_addr(),
                to: client.remote_addr(),
            }
        );
        assert_eq!(peer_addr, generate_xor_peer_address());
    }

    fn connection_bind_response<F: FnOnce(Message<'_>) -> Vec<u8>>(
        client: &mut TurnClientProtocol,
        reply: F,
        now: Instant,
    ) -> TurnProtocolRecv {
        response(client, CONNECTION_BIND, reply, now)
    }

    fn connection_bind_success_response(
        client: &mut TurnClientProtocol,
        peer_addr: SocketAddr,
        now: Instant,
    ) {
        let credentials = client_credentials(client);
        assert!(matches!(
            connection_bind_response(
                client,
                |msg| {
                    let mut reply = Message::builder_success(&msg, MessageWriteVec::new());
                    reply
                        .add_message_integrity(&credentials.into(), IntegrityAlgorithm::Sha1)
                        .unwrap();
                    reply.finish()
                },
                now,
            ),
            TurnProtocolRecv::TcpConnectionBound {
                peer_addr: tcp_peer_addr
            } if tcp_peer_addr == peer_addr
        ));
    }

    fn generate_tcp_local_address() -> SocketAddr {
        "192.168.0.1:4000".parse().unwrap()
    }

    #[test]
    fn test_turn_client_protocol_tcp_connection_bind_without_client_permission() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut client = new_protocol_with_families(
            TransportType::Tcp,
            TransportType::Tcp,
            &[AddressFamily::IPV4],
        );
        initial_allocate(&mut client, now);
        authenticated_allocate(&mut client, now);
        assert!(matches!(
            client.tcp_connect(generate_xor_peer_address(), now),
            Err(TcpConnectError::NoPermission)
        ));
    }

    #[test]
    fn test_turn_client_protocol_tcp_connection_bind_pending_already_exists_on_client() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut client = new_protocol_with_families(
            TransportType::Tcp,
            TransportType::Tcp,
            &[AddressFamily::IPV4],
        );
        initial_allocate(&mut client, now);
        authenticated_allocate(&mut client, now);
        create_permission(&mut client, now);
        client
            .tcp_connect(generate_xor_peer_address(), now)
            .unwrap();
        assert!(matches!(
            client.tcp_connect(generate_xor_peer_address(), now),
            Err(TcpConnectError::AlreadyExists)
        ));
    }

    #[test]
    fn test_turn_client_protocol_tcp_connection_bind_pending_already_exists_on_client_after_connect(
    ) {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut client = new_protocol_with_families(
            TransportType::Tcp,
            TransportType::Tcp,
            &[AddressFamily::IPV4],
        );
        initial_allocate(&mut client, now);
        authenticated_allocate(&mut client, now);
        create_permission(&mut client, now);
        client
            .tcp_connect(generate_xor_peer_address(), now)
            .unwrap();
        connect_success_response(&mut client, 1, now);
        assert!(matches!(
            client.tcp_connect(generate_xor_peer_address(), now),
            Err(TcpConnectError::AlreadyExists)
        ));
    }

    #[test]
    fn test_turn_client_protocol_tcp_connection_bind_already_exists_on_client_after_tcp_allocate() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut client = new_protocol_with_families(
            TransportType::Tcp,
            TransportType::Tcp,
            &[AddressFamily::IPV4],
        );
        initial_allocate(&mut client, now);
        authenticated_allocate(&mut client, now);
        create_permission(&mut client, now);
        client
            .tcp_connect(generate_xor_peer_address(), now)
            .unwrap();
        connect_success_response(&mut client, 1, now);
        client
            .allocated_tcp_socket(
                1,
                Socket5Tuple {
                    transport: TransportType::Tcp,
                    from: client.local_addr(),
                    to: client.remote_addr(),
                },
                generate_xor_peer_address(),
                Some(generate_tcp_local_address()),
                now,
            )
            .unwrap();
        assert!(matches!(
            client.tcp_connect(generate_xor_peer_address(), now),
            Err(TcpConnectError::AlreadyExists)
        ));
    }

    #[test]
    fn test_turn_client_protocol_tcp_connect_timeout() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut client = new_protocol_with_families(
            TransportType::Tcp,
            TransportType::Tcp,
            &[AddressFamily::IPV4],
        );
        initial_allocate(&mut client, now);
        authenticated_allocate(&mut client, now);
        create_permission(&mut client, now);
        client
            .tcp_connect(generate_xor_peer_address(), now)
            .unwrap();

        let transmit = client.poll_transmit(now).unwrap();
        let msg = Message::from_bytes(&transmit.data).unwrap();
        assert!(msg.has_method(CONNECT));
        let now = wait_advance(&mut client, now);
        let TurnPollRet::WaitUntil(new_now) = client.poll(now) else {
            unreachable!();
        };
        assert_eq!(new_now, now);
        assert!(
            matches!(client.poll_event(), Some(TurnEvent::TcpConnectFailed(addr)) if addr == generate_xor_peer_address())
        );
    }

    #[test]
    fn test_turn_client_protocol_tcp_connection_bind_timeout() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut client = new_protocol_with_families(
            TransportType::Tcp,
            TransportType::Tcp,
            &[AddressFamily::IPV4],
        );
        initial_allocate(&mut client, now);
        authenticated_allocate(&mut client, now);
        create_permission(&mut client, now);
        client
            .tcp_connect(generate_xor_peer_address(), now)
            .unwrap();
        connect_success_response(&mut client, 1, now);
        client
            .allocated_tcp_socket(
                1,
                Socket5Tuple {
                    transport: TransportType::Tcp,
                    from: client.local_addr(),
                    to: client.remote_addr(),
                },
                generate_xor_peer_address(),
                Some(generate_tcp_local_address()),
                now,
            )
            .unwrap();

        let transmit = client.poll_transmit(now).unwrap();
        let msg = Message::from_bytes(&transmit.data).unwrap();
        assert!(msg.has_method(CONNECTION_BIND));
        let now = wait_advance(&mut client, now) + Duration::from_nanos(1);
        let TurnPollRet::TcpClose {
            local_addr,
            remote_addr,
        } = client.poll(now)
        else {
            unreachable!();
        };
        assert_eq!(local_addr, generate_tcp_local_address());
        assert_eq!(remote_addr, client.remote_addr());
        let TurnPollRet::WaitUntil(new_now) = client.poll(now) else {
            unreachable!();
        };
        assert_eq!(new_now, now);
        assert!(
            matches!(client.poll_event(), Some(TurnEvent::TcpConnectFailed(addr)) if addr == generate_xor_peer_address())
        );
    }

    #[test]
    fn test_turn_client_protocol_tcp_connection_bind_stale_nonce() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut client = new_protocol_with_families(
            TransportType::Tcp,
            TransportType::Tcp,
            &[AddressFamily::IPV4],
        );
        initial_allocate(&mut client, now);
        authenticated_allocate(&mut client, now);
        create_permission(&mut client, now);
        client
            .tcp_connect(generate_xor_peer_address(), now)
            .unwrap();
        connect_success_response(&mut client, 1, now);
        client
            .allocated_tcp_socket(
                1,
                Socket5Tuple {
                    transport: TransportType::Tcp,
                    from: client.local_addr(),
                    to: client.remote_addr(),
                },
                generate_xor_peer_address(),
                Some(generate_tcp_local_address()),
                now,
            )
            .unwrap();
        assert!(matches!(
            connection_bind_response(&mut client, |msg| generate_stale_nonce(&msg), now,),
            TurnProtocolRecv::Handled
        ));

        connection_bind_success_response(&mut client, generate_xor_peer_address(), now);
        let data = [4; 9];
        let transmit = client
            .send_to(TransportType::Tcp, generate_xor_peer_address(), data, now)
            .unwrap();
        assert_eq!(transmit.transport, TransportType::Tcp);
        assert_eq!(transmit.from, generate_tcp_local_address());
        assert_eq!(transmit.to, client.remote_addr());
        assert_eq!(&transmit.data.build(), data.as_slice());
    }

    #[test]
    fn test_turn_client_protocol_tcp_connection_bind_success() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut client = new_protocol_with_families(
            TransportType::Tcp,
            TransportType::Tcp,
            &[AddressFamily::IPV4],
        );
        initial_allocate(&mut client, now);
        authenticated_allocate(&mut client, now);
        create_permission(&mut client, now);
        client
            .tcp_connect(generate_xor_peer_address(), now)
            .unwrap();
        connect_success_response(&mut client, 1, now);
        client
            .allocated_tcp_socket(
                1,
                Socket5Tuple {
                    transport: TransportType::Tcp,
                    from: client.local_addr(),
                    to: client.remote_addr(),
                },
                generate_xor_peer_address(),
                Some(generate_tcp_local_address()),
                now,
            )
            .unwrap();
        connection_bind_success_response(&mut client, generate_xor_peer_address(), now);
        let data = [4; 9];
        let transmit = client
            .send_to(TransportType::Tcp, generate_xor_peer_address(), data, now)
            .unwrap();
        assert_eq!(transmit.transport, TransportType::Tcp);
        assert_eq!(transmit.from, generate_tcp_local_address());
        assert_eq!(transmit.to, client.remote_addr());
        assert_eq!(&transmit.data.build(), data.as_slice());
    }

    #[test]
    fn test_turn_client_protocol_tcp_connection_bind_already_exists() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut client = new_protocol_with_families(
            TransportType::Tcp,
            TransportType::Tcp,
            &[AddressFamily::IPV4],
        );
        initial_allocate(&mut client, now);
        authenticated_allocate(&mut client, now);
        create_permission(&mut client, now);
        client
            .tcp_connect(generate_xor_peer_address(), now)
            .unwrap();
        connect_success_response(&mut client, 1, now);
        client
            .allocated_tcp_socket(
                1,
                Socket5Tuple {
                    transport: TransportType::Tcp,
                    from: client.local_addr(),
                    to: client.remote_addr(),
                },
                generate_xor_peer_address(),
                Some(generate_tcp_local_address()),
                now,
            )
            .unwrap();
        let credentials = client_credentials(&client);
        assert!(matches!(
            connection_bind_response(
                &mut client,
                |msg| {
                    let mut response = Message::builder_error(&msg, MessageWriteVec::new());
                    response
                        .add_attribute(
                            &ErrorCode::builder(ErrorCode::CONNECTION_ALREADY_EXISTS)
                                .build()
                                .unwrap(),
                        )
                        .unwrap();
                    response
                        .add_message_integrity(
                            &credentials.clone().into(),
                            IntegrityAlgorithm::Sha1,
                        )
                        .unwrap();
                    response.finish()
                },
                now,
            ),
            TurnProtocolRecv::Handled
        ));
        assert!(
            matches!(client.poll_event(), Some(TurnEvent::TcpConnectFailed(peer_addr)) if peer_addr == generate_xor_peer_address())
        );

        let data = [4; 9];
        assert!(matches!(
            client.send_to(TransportType::Tcp, generate_xor_peer_address(), data, now),
            Err(SendError::NoTcpSocket)
        ));
    }

    #[test]
    fn test_turn_client_protocol_tcp_connection_bind_bad_integrity() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut client = new_protocol_with_families(
            TransportType::Tcp,
            TransportType::Tcp,
            &[AddressFamily::IPV4],
        );
        initial_allocate(&mut client, now);
        authenticated_allocate(&mut client, now);
        create_permission(&mut client, now);
        client
            .tcp_connect(generate_xor_peer_address(), now)
            .unwrap();
        connect_success_response(&mut client, 1, now);
        client
            .allocated_tcp_socket(
                1,
                Socket5Tuple {
                    transport: TransportType::Tcp,
                    from: client.local_addr(),
                    to: client.remote_addr(),
                },
                generate_xor_peer_address(),
                Some(generate_tcp_local_address()),
                now,
            )
            .unwrap();
        let wrong_credentials = client
            .stun_auth
            .credentials()
            .unwrap()
            .to_key("wrong-realm".to_string());
        assert!(matches!(
            connection_bind_response(
                &mut client,
                |msg| {
                    let mut response = Message::builder_success(&msg, MessageWriteVec::new());
                    response
                        .add_message_integrity(
                            &wrong_credentials.clone().into(),
                            IntegrityAlgorithm::Sha1,
                        )
                        .unwrap();
                    response.finish()
                },
                now,
            ),
            TurnProtocolRecv::Handled
        ));
        assert!(
            matches!(client.poll_event(), Some(TurnEvent::TcpConnectFailed(peer_addr)) if peer_addr == generate_xor_peer_address())
        );

        let data = [4; 9];
        assert!(matches!(
            client.send_to(TransportType::Tcp, generate_xor_peer_address(), data, now),
            Err(SendError::NoTcpSocket)
        ));
    }

    #[test]
    fn test_turn_client_protocol_tcp_connection_bind_wrong_transaction_id() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut client = new_protocol_with_families(
            TransportType::Tcp,
            TransportType::Tcp,
            &[AddressFamily::IPV4],
        );
        initial_allocate(&mut client, now);
        authenticated_allocate(&mut client, now);
        create_permission(&mut client, now);
        client
            .tcp_connect(generate_xor_peer_address(), now)
            .unwrap();
        connect_success_response(&mut client, 1, now);
        client
            .allocated_tcp_socket(
                1,
                Socket5Tuple {
                    transport: TransportType::Tcp,
                    from: client.local_addr(),
                    to: client.remote_addr(),
                },
                generate_xor_peer_address(),
                Some(generate_tcp_local_address()),
                now,
            )
            .unwrap();
        let credentials = client_credentials(&client);
        assert!(matches!(
            connection_bind_response(
                &mut client,
                |msg| {
                    let mut response = Message::builder(
                        MessageType::from_class_method(MessageClass::Success, msg.method()),
                        TransactionId::generate(),
                        MessageWriteVec::new(),
                    );
                    response
                        .add_message_integrity(
                            &credentials.clone().into(),
                            IntegrityAlgorithm::Sha1,
                        )
                        .unwrap();
                    response.finish()
                },
                now,
            ),
            TurnProtocolRecv::Handled
        ));
        assert!(
            matches!(client.poll_event(), Some(TurnEvent::TcpConnectFailed(peer_addr)) if peer_addr == generate_xor_peer_address())
        );

        let data = [4; 9];
        assert!(matches!(
            client.send_to(TransportType::Tcp, generate_xor_peer_address(), data, now),
            Err(SendError::NoTcpSocket)
        ));
    }

    fn server_connection_attempt_message(
        connection_id: u32,
        credentials: LongTermKeyCredentials,
        peer_addr: SocketAddr,
    ) -> MessageWriteVec {
        let mut request = Message::builder_request(CONNECTION_ATTEMPT, MessageWriteVec::new());
        request
            .add_attribute(&ConnectionId::new(connection_id))
            .unwrap();
        request
            .add_attribute(&XorPeerAddress::new(peer_addr, request.transaction_id()))
            .unwrap();
        request
            .add_message_integrity(&credentials.into(), IntegrityAlgorithm::Sha1)
            .unwrap();
        request
    }

    fn server_connection_attempt_success(
        client: &mut TurnClientProtocol,
        connection_id: u32,
        credentials: LongTermKeyCredentials,
        peer_addr: SocketAddr,
        local_tcp_addr: Option<SocketAddr>,
        now: Instant,
    ) {
        let request =
            server_connection_attempt_message(connection_id, credentials.clone(), peer_addr)
                .finish();
        let msg_transmit = Transmit::new(
            Message::from_bytes(&request).unwrap(),
            client.transport(),
            client.remote_addr(),
            client.local_addr(),
        );
        assert!(matches!(
            client.handle_message(msg_transmit, now),
            TurnProtocolRecv::Handled
        ));
        let TurnPollRet::AllocateTcpSocket {
            id,
            socket,
            peer_addr: allocate_peer_addr,
        } = client.poll(now)
        else {
            unreachable!();
        };
        assert_eq!(id, connection_id);
        assert_eq!(allocate_peer_addr, peer_addr);
        assert_eq!(socket.transport, TransportType::Tcp);
        assert_eq!(socket.from, client.local_addr());
        assert_eq!(socket.to, client.remote_addr());
        client
            .allocated_tcp_socket(id, socket, peer_addr, local_tcp_addr, now)
            .unwrap();

        let transmit = client.poll_transmit(now).unwrap();
        assert_eq!(transmit.transport, TransportType::Tcp);
        assert_eq!(transmit.from, client.local_addr());
        assert_eq!(transmit.to, client.remote_addr());
        let msg = Message::from_bytes(&transmit.data).unwrap();
        if local_tcp_addr.is_some() {
            assert!(msg.has_class(MessageClass::Success));
        } else {
            assert!(msg.has_class(MessageClass::Error));
        }
        assert!(msg.has_method(CONNECTION_ATTEMPT));
    }

    #[test]
    fn test_turn_client_protocol_tcp_connection_attempt() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut client = new_protocol_with_families(
            TransportType::Tcp,
            TransportType::Tcp,
            &[AddressFamily::IPV4],
        );
        initial_allocate(&mut client, now);
        authenticated_allocate(&mut client, now);
        create_permission(&mut client, now);

        let credentials = client_credentials(&client);
        server_connection_attempt_success(
            &mut client,
            1,
            credentials,
            generate_xor_peer_address(),
            Some(generate_tcp_local_address()),
            now,
        );

        let data = [4; 9];
        assert!(matches!(
            client.send_to(TransportType::Tcp, generate_xor_peer_address(), data, now),
            Err(SendError::NoTcpSocket)
        ));
        connection_bind_success_response(&mut client, generate_xor_peer_address(), now);

        let transmit = client
            .send_to(TransportType::Tcp, generate_xor_peer_address(), data, now)
            .unwrap();
        assert_eq!(transmit.transport, TransportType::Tcp);
        assert_eq!(transmit.from, generate_tcp_local_address());
        assert_eq!(transmit.to, client.remote_addr());
        assert_eq!(&transmit.data.build(), data.as_slice());
    }

    #[test]
    fn test_turn_client_protocol_tcp_connection_attempt_socket_allocate_failure() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut client = new_protocol_with_families(
            TransportType::Tcp,
            TransportType::Tcp,
            &[AddressFamily::IPV4],
        );
        initial_allocate(&mut client, now);
        authenticated_allocate(&mut client, now);
        create_permission(&mut client, now);

        let credentials = client_credentials(&client);
        server_connection_attempt_success(
            &mut client,
            1,
            credentials,
            generate_xor_peer_address(),
            None,
            now,
        );

        let data = [4; 9];
        assert!(matches!(
            client.send_to(TransportType::Tcp, generate_xor_peer_address(), data, now),
            Err(SendError::NoTcpSocket)
        ));
    }

    #[test]
    fn test_turn_client_protocol_tcp_connection_attempt_missing_attributes() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        for attr in [ConnectionId::TYPE, XorPeerAddress::TYPE] {
            let mut client = new_protocol_with_families(
                TransportType::Tcp,
                TransportType::Tcp,
                &[AddressFamily::IPV4],
            );
            initial_allocate(&mut client, now);
            authenticated_allocate(&mut client, now);
            create_permission(&mut client, now);

            let credentials = client_credentials(&client);
            let mut request = Message::builder_request(CONNECTION_ATTEMPT, MessageWriteVec::new());
            if attr != ConnectionId::TYPE {
                request.add_attribute(&ConnectionId::new(1)).unwrap();
            }
            if attr != XorPeerAddress::TYPE {
                request
                    .add_attribute(&XorPeerAddress::new(
                        generate_xor_peer_address(),
                        request.transaction_id(),
                    ))
                    .unwrap();
            }
            request
                .add_message_integrity(&credentials.clone().into(), IntegrityAlgorithm::Sha1)
                .unwrap();
            let msg_transmit = Transmit::new(
                Message::from_bytes(&request).unwrap(),
                client.transport(),
                client.remote_addr(),
                client.local_addr(),
            );
            assert!(matches!(
                client.handle_message(msg_transmit, now),
                TurnProtocolRecv::Handled
            ));
            let transmit = client.poll_transmit(now).unwrap();
            assert_eq!(transmit.from, client.local_addr());
            assert_eq!(transmit.to, client.remote_addr());
            let msg = Message::from_bytes(&transmit.data).unwrap();
            msg.validate_integrity(&credentials.into()).unwrap();
            assert!(msg.has_method(CONNECTION_ATTEMPT));
            assert!(msg.has_class(MessageClass::Error));
            let error = msg.attribute::<ErrorCode>().unwrap();
            assert_eq!(error.code(), ErrorCode::BAD_REQUEST);
        }
    }

    #[test]
    fn test_turn_client_protocol_tcp_connection_attempt_wrong_ip_family() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut client = new_protocol_with_families(
            TransportType::Tcp,
            TransportType::Tcp,
            &[AddressFamily::IPV4],
        );
        initial_allocate(&mut client, now);
        authenticated_allocate(&mut client, now);
        create_permission(&mut client, now);

        let credentials = client_credentials(&client);
        let request = server_connection_attempt_message(
            1,
            credentials.clone(),
            generate_ipv6_xor_peer_address(),
        );
        let msg_transmit = Transmit::new(
            Message::from_bytes(&request).unwrap(),
            client.transport(),
            client.remote_addr(),
            client.local_addr(),
        );
        assert!(matches!(
            client.handle_message(msg_transmit, now),
            TurnProtocolRecv::Handled
        ));
        let transmit = client.poll_transmit(now).unwrap();
        assert_eq!(transmit.from, client.local_addr());
        assert_eq!(transmit.to, client.remote_addr());
        let msg = Message::from_bytes(&transmit.data).unwrap();
        msg.validate_integrity(&credentials.into()).unwrap();
        assert!(msg.has_method(CONNECTION_ATTEMPT));
        assert!(msg.has_class(MessageClass::Error));
        let error = msg.attribute::<ErrorCode>().unwrap();
        assert_eq!(error.code(), ErrorCode::BAD_REQUEST);
    }

    #[test]
    fn test_turn_client_protocol_tcp_connection_attempt_already_exists() {
        let _log = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut client = new_protocol_with_families(
            TransportType::Tcp,
            TransportType::Tcp,
            &[AddressFamily::IPV4],
        );
        initial_allocate(&mut client, now);
        authenticated_allocate(&mut client, now);
        create_permission(&mut client, now);

        let credentials = client_credentials(&client);
        server_connection_attempt_success(
            &mut client,
            1,
            credentials.clone(),
            generate_xor_peer_address(),
            Some(generate_tcp_local_address()),
            now,
        );
        connection_bind_success_response(&mut client, generate_xor_peer_address(), now);

        let request =
            server_connection_attempt_message(2, credentials.clone(), generate_xor_peer_address())
                .finish();
        let msg_transmit = Transmit::new(
            Message::from_bytes(&request).unwrap(),
            client.transport(),
            client.remote_addr(),
            client.local_addr(),
        );
        assert!(matches!(
            client.handle_message(msg_transmit, now),
            TurnProtocolRecv::Handled
        ));
        let transmit = client.poll_transmit(now).unwrap();
        assert_eq!(transmit.from, client.local_addr());
        assert_eq!(transmit.to, client.remote_addr());
        let msg = Message::from_bytes(&transmit.data).unwrap();
        msg.validate_integrity(&credentials.into()).unwrap();
        assert!(msg.has_method(CONNECTION_ATTEMPT));
        assert!(msg.has_class(MessageClass::Error));
        let error = msg.attribute::<ErrorCode>().unwrap();
        assert_eq!(error.code(), ErrorCode::CONNECTION_ALREADY_EXISTS);

        let data = [4; 9];
        let transmit = client
            .send_to(TransportType::Tcp, generate_xor_peer_address(), data, now)
            .unwrap();
        assert_eq!(transmit.transport, TransportType::Tcp);
        assert_eq!(transmit.from, generate_tcp_local_address());
        assert_eq!(transmit.to, client.remote_addr());
        assert_eq!(&transmit.data.build(), data.as_slice());
    }

    #[test]
    fn test_client_receive_offpath_data() {
        let _log = crate::tests::test_init_log();

        let now = Instant::ZERO;

        let mut test = crate::udp::tests::create_test();
        let data = [0x40, 0, 0, 14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let TurnRecvRet::Ignored(ignored) = test.client.recv(
            Transmit::new(
                &data,
                test.client.transport(),
                test.client.remote_addr(),
                test.client.local_addr(),
            ),
            now,
        ) else {
            unreachable!();
        };
        assert_eq!(ignored.data, &data);
    }

    #[test]
    fn test_server_receive_offpath_data() {
        let _log = crate::tests::test_init_log();

        let now = Instant::ZERO;
        let mut test = crate::udp::tests::create_test();

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
            .is_none());
    }
}
