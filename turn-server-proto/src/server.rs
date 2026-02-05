// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A TURN server that can handle UDP and TCP connections.

use alloc::borrow::ToOwned;
use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use byteorder::{BigEndian, ByteOrder};
use core::net::{IpAddr, SocketAddr};
use core::time::Duration;
use pnet_packet::Packet;
use turn_types::stun::prelude::AttributeExt;
use turn_types::tcp::{IncomingTcp, StoredTcp, TurnTcpBuffer};
use turn_types::transmit::{DelayedChannel, DelayedMessage, TransmitBuild};

use stun_proto::agent::{StunAgent, Transmit};
use stun_proto::types::attribute::{
    AttributeType, ErrorCode, Fingerprint, MessageIntegrity, Nonce, Realm, Username,
    XorMappedAddress,
};
use stun_proto::types::message::{
    LongTermCredentials, Message, MessageClass, MessageIntegrityCredentials, MessageType,
    MessageWrite, MessageWriteExt, MessageWriteVec, TransactionId, BINDING,
};
use stun_proto::types::prelude::{Attribute, AttributeFromRaw, AttributeStaticType};
use stun_proto::types::TransportType;
use stun_proto::Instant;
use turn_types::channel::ChannelData;

use turn_types::message::{CONNECT, CONNECTION_ATTEMPT, CONNECTION_BIND, CREATE_PERMISSION};

use turn_types::attribute::{
    AdditionalAddressFamily, AddressErrorCode, ConnectionId, Data as AData, DontFragment, EvenPort,
    Icmp, RequestedAddressFamily, ReservationToken,
};
use turn_types::attribute::{
    ChannelNumber, Lifetime, RequestedTransport, XorPeerAddress, XorRelayedAddress,
};
use turn_types::message::{ALLOCATE, CHANNEL_BIND, DATA, REFRESH, SEND};
use turn_types::stun::message::{IntegrityAlgorithm, IntegrityKey, MessageHeader};
use turn_types::AddressFamily;

use tracing::{debug, error, info, trace, warn};

use crate::api::{
    DelayedMessageOrChannelSend, SocketAllocateError, TcpConnectError, TurnServerApi,
    TurnServerPollRet,
};

static MINIMUM_NONCE_EXPIRY_DURATION: Duration = Duration::from_secs(30);
static DEFAULT_NONCE_EXPIRY_DURATION: Duration = Duration::from_secs(3600);
static MAXIMUM_ALLOCATION_DURATION: Duration = Duration::from_secs(3600);
static DEFAULT_ALLOCATION_DURATION: Duration = Duration::from_secs(600);
static PERMISSION_DURATION: Duration = Duration::from_secs(300);
static CHANNEL_DURATION: Duration = Duration::from_secs(600);
static TCP_PEER_CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);

/// A TURN server.
#[derive(Debug)]
pub struct TurnServer {
    protocol: TurnServerProtocol,

    // client_addr, listen_addr
    incoming_tcp_buffers: BTreeMap<(SocketAddr, SocketAddr), TcpBuffer>,
    // allocation_addr, peer_addr, pending
    peer_tcp: BTreeMap<(SocketAddr, SocketAddr), PeerTcp>,
}

#[derive(Debug)]
struct TurnServerProtocol {
    realm: String,
    stun: StunAgent,

    nonces: Vec<NonceData>,
    clients: Vec<Client>,
    earliest_nonce_expiry: Option<Instant>,
    pending_transmits: VecDeque<Transmit<Vec<u8>>>,
    pending_allocates: VecDeque<PendingClient>,
    pending_socket_removals: VecDeque<Socket5Tuple>,
    pending_socket_listen_removals: VecDeque<(TransportType, SocketAddr)>,

    // username -> password mapping.
    users: BTreeMap<String, IntegrityKey>,
    nonce_expiry_duration: Duration,

    tcp_connection_id: u32,
    pending_tcp_connection_binds: Vec<PendingConnectionBind>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
struct Socket5Tuple {
    transport: TransportType,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
}

#[derive(Debug)]
struct PendingClient {
    client: Client,
    allocation_transport: TransportType,
    transaction_id: TransactionId,
    to_ask_families: smallvec::SmallVec<[AddressFamily; 2]>,
    pending_families: smallvec::SmallVec<[AddressFamily; 2]>,
    pending_sockets:
        smallvec::SmallVec<[(AddressFamily, Result<SocketAddr, SocketAllocateError>); 2]>,
    requested_lifetime: Option<u32>,
}

#[derive(Debug)]
struct NonceData {
    nonce: String,
    expires_at: Instant,

    transport: TransportType,
    remote_addr: SocketAddr,
    local_addr: SocketAddr,
}

#[derive(Debug)]
struct ForwardChannelData {
    transport: TransportType,
    from: SocketAddr,
    to: SocketAddr,
}

#[derive(Debug)]
struct PendingConnectionBind {
    connection_id: u32,
    listen_addr: SocketAddr,
    relayed_addr: SocketAddr,
    peer_addr: SocketAddr,
    // the remote address of the client's control connection.
    client_control_addr: SocketAddr,
}

/// TCP buffers on a TURN listening socket
#[derive(Debug)]
enum TcpBuffer {
    // It is unknown what kind of connection this is.
    Unknown(TurnTcpBuffer),
    // The control TURN connection. Always buffered.
    Control(TurnTcpBuffer),
    Passthrough {
        relayed_addr: SocketAddr,
        peer_addr: SocketAddr,
        pending_data: Vec<u8>,
    },
}

/// TCP buffers when sending/receiving between a relayed address and a peer.
#[derive(Debug)]
enum PeerTcp {
    PendingConnectionBind {
        peer_data: Vec<u8>,
        expires_at: Instant,
    },
    Passthrough {
        client_addr: SocketAddr,
        listen_addr: SocketAddr,
        pending_data: Vec<u8>,
    },
}

impl TurnServerProtocol {
    fn generate_nonce() -> String {
        #[cfg(not(feature = "std"))]
        {
            use rand::Rng;
            use rand::TryRngCore;
            let mut rng = rand::rngs::OsRng.unwrap_err();
            String::from_iter((0..16).map(|_| rng.sample(rand::distr::Alphanumeric) as char))
        }
        #[cfg(feature = "std")]
        {
            use rand::Rng;
            let mut rng = rand::rng();
            String::from_iter((0..16).map(|_| rng.sample(rand::distr::Alphanumeric) as char))
        }
    }

    fn recalculate_nonce_expiry(&mut self, now: Instant) {
        self.earliest_nonce_expiry = self
            .nonces
            .iter()
            .try_fold(now + self.nonce_expiry_duration, |ret, val| {
                Some(ret.min(val.expires_at))
            });
    }

    fn validate_nonce(
        &mut self,
        ttype: TransportType,
        from: SocketAddr,
        to: SocketAddr,
        now: Instant,
    ) -> String {
        //   o  If the NONCE is no longer valid, the server MUST generate an error
        //      response with an error code of 438 (Stale Nonce).  This response
        //      MUST include NONCE and REALM attributes and SHOULD NOT include the
        //      USERNAME or MESSAGE-INTEGRITY attribute.  Servers can invalidate
        //      nonces in order to provide additional security.  See Section 4.3
        //      of [RFC2617] for guidelines.
        let nonce_expiry_duration = self.nonce_expiry_duration;
        let nonce_data = self.mut_nonce_from_5tuple(ttype, to, from);
        if let Some(nonce_data) = nonce_data {
            if nonce_data.expires_at < now {
                nonce_data.nonce = Self::generate_nonce();
                nonce_data.expires_at = now + nonce_expiry_duration;
                let ret = nonce_data.nonce.clone();
                if self
                    .earliest_nonce_expiry
                    .map_or(true, |earliest| earliest < now)
                {
                    self.recalculate_nonce_expiry(now);
                }
                ret
            } else {
                nonce_data.nonce.clone()
            }
        } else {
            let nonce_value = Self::generate_nonce();
            self.nonces.push(NonceData {
                transport: ttype,
                remote_addr: from,
                local_addr: to,
                nonce: nonce_value.clone(),
                expires_at: now + self.nonce_expiry_duration,
            });
            self.recalculate_nonce_expiry(now);
            nonce_value
        }
    }

    fn validate_stun(
        &mut self,
        transmit: &Transmit<&Message<'_>>,
        now: Instant,
    ) -> Result<&IntegrityKey, MessageWriteVec> {
        let msg = transmit.data;

        let mut integrity = None;
        let mut username = None;
        let mut realm = None;
        let mut nonce = None;

        for (_offset, attr) in msg.iter_attributes() {
            match attr.get_type() {
                MessageIntegrity::TYPE => integrity = MessageIntegrity::from_raw(attr).ok(),
                Username::TYPE => username = Username::from_raw(attr).ok(),
                Realm::TYPE => realm = Realm::from_raw(attr).ok(),
                Nonce::TYPE => nonce = Nonce::from_raw(attr).ok(),
                _ => (),
            }
        }

        // TODO: check for SHA256 integrity
        if integrity.is_none() {
            //   o  If the message does not contain a MESSAGE-INTEGRITY attribute, the
            //      server MUST generate an error response with an error code of 401
            //      (Unauthorized).  This response MUST include a REALM value.  It is
            //      RECOMMENDED that the REALM value be the domain name of the
            //      provider of the STUN server.  The response MUST include a NONCE,
            //      selected by the server.  The response SHOULD NOT contain a
            //      USERNAME or MESSAGE-INTEGRITY attribute.
            let nonce_value =
                self.validate_nonce(transmit.transport, transmit.from, transmit.to, now);
            trace!("no message-integrity, returning unauthorized with nonce: {nonce_value}",);
            let nonce = Nonce::new(&nonce_value).unwrap();
            let realm = Realm::new(&self.realm).unwrap();
            let error = ErrorCode::builder(ErrorCode::UNAUTHORIZED).build().unwrap();
            let mut builder = Message::builder_error(
                msg,
                MessageWriteVec::with_capacity(
                    MessageHeader::LENGTH
                        + nonce.padded_len()
                        + realm.padded_len()
                        + error.padded_len(),
                ),
            );
            builder.add_attribute(&nonce).unwrap();
            builder.add_attribute(&realm).unwrap();
            builder.add_attribute(&error).unwrap();
            return Err(builder);
        }

        //  o  If the message contains a MESSAGE-INTEGRITY attribute, but is
        //      missing the USERNAME, REALM, or NONCE attribute, the server MUST
        //      generate an error response with an error code of 400 (Bad
        //      Request).  This response SHOULD NOT include a USERNAME, NONCE,
        //      REALM, or MESSAGE-INTEGRITY attribute.
        let Some(((username, _realm), nonce)) = username.zip(realm).zip(nonce) else {
            trace!("bad request due to missing username, realm, nonce");
            return Err(Self::bad_request(msg, 0));
        };

        let nonce_value = self.validate_nonce(transmit.transport, transmit.from, transmit.to, now);
        if nonce_value != nonce.nonce() {
            trace!("stale nonce");
            let error = ErrorCode::builder(ErrorCode::STALE_NONCE).build().unwrap();
            let realm = Realm::new(&self.realm).unwrap();
            let nonce = Nonce::new(&nonce_value).unwrap();
            let mut builder = Message::builder_error(
                msg,
                MessageWriteVec::with_capacity(
                    MessageHeader::LENGTH
                        + nonce.padded_len()
                        + realm.padded_len()
                        + error.padded_len(),
                ),
            );
            builder.add_attribute(&error).unwrap();
            builder.add_attribute(&realm).unwrap();
            builder.add_attribute(&nonce).unwrap();

            return Err(builder);
        }

        //   o  Using the password associated with the username in the USERNAME
        //      attribute, compute the value for the message integrity as
        //      described in Section 15.4.  If the resulting value does not match
        //      the contents of the MESSAGE-INTEGRITY attribute, the server MUST
        //      reject the request with an error response.  This response MUST use
        //      an error code of 401 (Unauthorized).  It MUST include REALM and
        //      NONCE attributes and SHOULD NOT include the USERNAME or MESSAGE-
        //      INTEGRITY attribute.
        let password_key = self.users.get(username.username());
        if password_key.map_or(true, |password_key| {
            msg.validate_integrity_with_key(password_key).is_err()
        }) {
            trace!("integrity failed");
            let error = ErrorCode::builder(ErrorCode::UNAUTHORIZED).build().unwrap();
            let realm = Realm::new(&self.realm).unwrap();
            let nonce = Nonce::new(&nonce_value).unwrap();
            let mut builder = Message::builder_error(
                msg,
                MessageWriteVec::with_capacity(
                    MessageHeader::LENGTH
                        + nonce.padded_len()
                        + realm.padded_len()
                        + error.padded_len(),
                ),
            );
            builder.add_attribute(&error).unwrap();
            builder.add_attribute(&realm).unwrap();
            builder.add_attribute(&nonce).unwrap();
            return Err(builder);
        }
        let password_key = password_key.unwrap();

        // All requests after the initial Allocate must use the same username as
        // that used to create the allocation, to prevent attackers from
        // hijacking the client's allocation.  Specifically, if the server
        // requires the use of the long-term credential mechanism, and if a non-
        // Allocate request passes authentication under this mechanism, and if
        // the 5-tuple identifies an existing allocation, but the request does
        // not use the same username as used to create the allocation, then the
        // request MUST be rejected with a 441 (Wrong Credentials) error.
        if let Some(client) =
            self.client_from_5tuple(transmit.transport, transmit.to, transmit.from)
        {
            if client.username != username.username() {
                trace!("mismatched username");
                let error = ErrorCode::builder(ErrorCode::WRONG_CREDENTIALS)
                    .build()
                    .unwrap();
                let mut builder = Message::builder_error(
                    msg,
                    MessageWriteVec::with_capacity(MessageHeader::LENGTH + error.padded_len() + 24),
                );
                builder.add_attribute(&error).unwrap();
                builder
                    .add_message_integrity_with_key(password_key, IntegrityAlgorithm::Sha1)
                    .unwrap();
                return Err(builder);
            }
        }

        Ok(password_key)
    }

    fn server_error(msg: &Message<'_>) -> MessageWriteVec {
        let error = ErrorCode::builder(ErrorCode::SERVER_ERROR).build().unwrap();
        let mut response = Message::builder_error(
            msg,
            MessageWriteVec::with_capacity(MessageHeader::LENGTH + error.padded_len() + 8),
        );
        response.add_attribute(&error).unwrap();
        response.add_fingerprint().unwrap();
        response
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

    fn bad_request_signed(msg: &Message<'_>, key: &IntegrityKey) -> MessageWriteVec {
        let mut builder = Self::bad_request(msg, 24);
        builder
            .add_message_integrity_with_key(key, IntegrityAlgorithm::Sha1)
            .unwrap();
        builder
    }

    fn allocation_mismatch(msg: &Message<'_>, key: &IntegrityKey) -> MessageWriteVec {
        let error = ErrorCode::builder(ErrorCode::ALLOCATION_MISMATCH)
            .build()
            .unwrap();
        let mut response = Message::builder_error(
            msg,
            MessageWriteVec::with_capacity(MessageHeader::LENGTH + error.padded_len() + 24 + 8),
        );
        response.add_attribute(&error).unwrap();
        response
            .add_message_integrity_with_key(key, IntegrityAlgorithm::Sha1)
            .unwrap();
        response.add_fingerprint().unwrap();
        response
    }

    fn handle_stun_binding(
        &mut self,
        transmit: Transmit<&Message<'_>>,
        now: Instant,
    ) -> Result<Transmit<Vec<u8>>, MessageWriteVec> {
        let msg = transmit.data;
        let response = if let Some(error_msg) = Message::check_attribute_types(
            msg,
            &[Fingerprint::TYPE],
            &[],
            MessageWriteVec::with_capacity(64),
        ) {
            error_msg
        } else {
            let xor_addr = XorMappedAddress::new(transmit.from, msg.transaction_id());
            let mut response = Message::builder_success(
                msg,
                MessageWriteVec::with_capacity(MessageHeader::LENGTH + xor_addr.padded_len() + 8),
            );
            response.add_attribute(&xor_addr).unwrap();
            response.add_fingerprint().unwrap();
            response
        };
        let response = response.finish();

        let Ok(transmit) = self.stun.send(response, transmit.to, now) else {
            error!("Failed to send");
            return Err(Self::server_error(msg));
        };

        Ok(transmit)
    }

    fn handle_stun_allocate(
        &mut self,
        transmit: Transmit<&Message<'_>>,
        tcp_type: TcpStunType,
        now: Instant,
        tcp_stun_change: &mut Option<TcpStunChange>,
    ) -> Result<(), MessageWriteVec> {
        let msg = transmit.data;
        let key = self.validate_stun(&transmit, now)?.clone();
        let mut address_families = smallvec::SmallVec::<[AddressFamily; 2]>::new();

        if let Some(_client) =
            self.mut_client_from_5tuple(transmit.transport, transmit.to, transmit.from)
        {
            trace!("allocation mismatch");
            return Err(Self::allocation_mismatch(msg, &key));
        };

        let mut requested_transport = None;
        let mut lifetime = None;
        let mut reservation_token = None;
        let mut even_port = None;
        let mut requested_address_family = None;
        let mut additional_address_family = None;
        let mut username = None;
        let mut dont_fragment = None;

        let mut unknown_attributes = smallvec::SmallVec::<[AttributeType; 4]>::default();
        for (_offset, attr) in msg.iter_attributes() {
            match attr.get_type() {
                // checked by validate_stun()
                Realm::TYPE | Nonce::TYPE | MessageIntegrity::TYPE => (),
                Username::TYPE => {
                    username = Username::from_raw(attr)
                        .ok()
                        .map(|u| u.username().to_owned())
                }
                RequestedTransport::TYPE => {
                    requested_transport = RequestedTransport::from_raw(attr).ok()
                }
                Lifetime::TYPE => lifetime = Lifetime::from_raw(attr).ok(),
                ReservationToken::TYPE => reservation_token = Some(attr),
                EvenPort::TYPE => even_port = Some(attr),
                RequestedAddressFamily::TYPE => {
                    if additional_address_family.is_some() {
                        return Err(Self::bad_request_signed(msg, &key));
                    } else {
                        requested_address_family = Some(attr)
                    }
                }
                AdditionalAddressFamily::TYPE => {
                    if requested_address_family.is_some() {
                        return Err(Self::bad_request_signed(msg, &key));
                    } else {
                        additional_address_family = Some(attr)
                    }
                }
                DontFragment::TYPE => {
                    dont_fragment = DontFragment::from_raw(attr).ok();
                }
                atype => {
                    if atype.comprehension_required() {
                        unknown_attributes.push(atype);
                    }
                }
            }
        }

        if !unknown_attributes.is_empty() {
            trace!("unknown attributes: {unknown_attributes:?}");
            let mut err = Message::unknown_attributes(
                msg,
                &unknown_attributes,
                MessageWriteVec::with_capacity(64),
            );
            err.add_message_integrity_with_key(&key, IntegrityAlgorithm::Sha1)
                .unwrap();
            return Err(err);
        }

        let Some(requested_transport) = requested_transport else {
            return Err(Self::bad_request_signed(msg, &key));
        };

        let allocation_transport = match requested_transport.protocol() {
            RequestedTransport::UDP => TransportType::Udp,
            RequestedTransport::TCP => {
                // RFC 6062 Section 5.1
                // 2.  If the client connection transport is not TCP or TLS, the server
                //     MUST reject the request with a 400 (Bad Request) error.
                // 3.  If the request contains the DONT-FRAGMENT, EVEN-PORT, or
                //     RESERVATION-TOKEN attribute, the server MUST reject the request
                //     with a 400 (Bad Request) error.
                if self.stun.transport() != TransportType::Tcp
                    || even_port.is_some()
                    || dont_fragment.is_some()
                    || reservation_token.is_some()
                {
                    return Err(Self::bad_request_signed(msg, &key));
                }
                TransportType::Tcp
            }
            protocol => {
                debug!("unsupported RequestedTransport {protocol}",);
                let error = ErrorCode::builder(ErrorCode::UNSUPPORTED_TRANSPORT_PROTOCOL)
                    .build()
                    .unwrap();
                let mut builder = Message::builder_error(
                    msg,
                    MessageWriteVec::with_capacity(MessageHeader::LENGTH + error.padded_len() + 24),
                );
                builder.add_attribute(&error).unwrap();
                builder
                    .add_message_integrity_with_key(&key, IntegrityAlgorithm::Sha1)
                    .unwrap();
                return Err(builder);
            }
        };

        if let Some(additional) = additional_address_family {
            let Ok(additional) = AdditionalAddressFamily::from_raw(additional) else {
                return Err(Self::bad_request_signed(msg, &key));
            };
            /* The server checks if the request contains both
             * REQUESTED-ADDRESS-FAMILY and ADDITIONAL-ADDRESS-FAMILY attributes. If yes,
             * then the server rejects the request with a 400 (Bad Request) error.
             */
            /* The server checks if the request contains an ADDITIONAL-ADDRESS-FAMILY
             * attribute. If yes, and the attribute value is 0x01 (IPv4 address family),
             * then the server rejects the request with a 400 (Bad Request) error.
             */
            if requested_address_family.is_some()
                || additional.family() == AddressFamily::IPV4
                || reservation_token.is_some()
                || even_port.is_some()
            {
                debug!(
                    "AdditionalAddressFamily with either {} == IPV4, ReservationToken {}, RequestedAddressFamily {}, or EvenPort {}. Bad Request",
                    additional.family(),
                    reservation_token.is_some(),
                    requested_address_family.is_some(),
                    even_port.is_some(),
                );
                return Err(Self::bad_request_signed(msg, &key));
            }
            address_families.push(AddressFamily::IPV4);
            address_families.push(additional.family());
        }

        if let Some(requested) = requested_address_family {
            let Ok(requested) = RequestedAddressFamily::from_raw(requested) else {
                return Err(Self::bad_request_signed(msg, &key));
            };
            if reservation_token.is_some() {
                debug!("RequestedAddressFamily with ReservationToken -> Bad Request");
                return Err(Self::bad_request_signed(msg, &key));
            }
            address_families.push(requested.family());
        } else if address_families.is_empty() {
            address_families.push(AddressFamily::IPV4);
        }

        if let Some(_reservation_token) = reservation_token {
            /* The server checks if the request contains a RESERVATION-TOKEN
             * attribute. If yes, and the request also contains an EVEN-PORT or
             * REQUESTED-ADDRESS-FAMILY or ADDITIONAL-ADDRESS-FAMILY attribute,
             * the server rejects the request with a 400 (Bad Request) error.
             * Otherwise, it checks to see if the token is valid (i.e., the
             * token is in range and has not expired, and the corresponding
             * relayed transport address is still available). If the token is
             * not valid for some reason, the server rejects the request with a
             * 508 (Insufficient Capacity) error.
             */
            if even_port.is_some() {
                debug!("ReservationToken with EvenPort -> Bad Request");
                return Err(Self::bad_request_signed(msg, &key));
            }

            // TODO: further RESERVATION-TOKEN handling
        }

        // TODO: DONT-FRAGMENT
        // TODO: EVEN-PORT
        // TODO: allocation quota
        // XXX: TRY-ALTERNATE

        let client = Client {
            transport: transmit.transport,
            remote_addr: transmit.from,
            local_addr: transmit.to,
            allocations: vec![],
            username: username.unwrap(),
            key,
        };
        debug!(
            "have new pending ALLOCATE from client {} from {} to {}",
            transmit.transport, transmit.from, transmit.to
        );

        self.pending_allocates.push_front(PendingClient {
            client,
            allocation_transport,
            transaction_id: msg.transaction_id(),
            to_ask_families: address_families.clone(),
            pending_families: address_families,
            pending_sockets: Default::default(),
            requested_lifetime: lifetime.map(|lt| lt.seconds()),
        });

        if tcp_type == TcpStunType::Unknown {
            *tcp_stun_change = Some(TcpStunChange::Control);
        }

        Ok(())
    }

    fn peer_address_family_mismatch_signed(
        msg: &Message<'_>,
        key: &IntegrityKey,
    ) -> MessageWriteVec {
        let error = ErrorCode::builder(ErrorCode::PEER_ADDRESS_FAMILY_MISMATCH)
            .build()
            .unwrap();
        let mut response = Message::builder_error(
            msg,
            MessageWriteVec::with_capacity(MessageHeader::LENGTH + error.padded_len() + 24 + 8),
        );
        response.add_attribute(&error).unwrap();
        response
            .add_message_integrity_with_key(key, IntegrityAlgorithm::Sha1)
            .unwrap();
        response.add_fingerprint().unwrap();
        response
    }

    fn handle_stun_refresh(
        &mut self,
        transmit: Transmit<&Message<'_>>,
        now: Instant,
        tcp_stun_change: &mut Option<TcpStunChange>,
    ) -> Result<Transmit<Vec<u8>>, MessageWriteVec> {
        let msg = transmit.data;
        let key = self.validate_stun(&transmit, now)?.clone();

        let Some(client) =
            self.mut_client_from_5tuple(transmit.transport, transmit.to, transmit.from)
        else {
            trace!("allocation mismatch");
            return Err(Self::allocation_mismatch(msg, &key));
        };

        let mut request_lifetime = None;
        let mut requested_family = None;

        let mut unknown_attributes = smallvec::SmallVec::<[AttributeType; 4]>::default();
        for (_offset, attr) in msg.iter_attributes() {
            match attr.get_type() {
                // handled by validate_stun
                Username::TYPE | Realm::TYPE | Nonce::TYPE | MessageIntegrity::TYPE => (),
                Lifetime::TYPE => {
                    request_lifetime = Lifetime::from_raw(attr).ok().map(|lt| lt.seconds())
                }
                RequestedAddressFamily::TYPE => {
                    requested_family = RequestedAddressFamily::from_raw(attr)
                        .ok()
                        .map(|r| r.family())
                }
                atype => {
                    if atype.comprehension_required() {
                        unknown_attributes.push(atype);
                    }
                }
            }
        }
        if !unknown_attributes.is_empty() {
            trace!("unknown attributes: {unknown_attributes:?}");
            let mut err = Message::unknown_attributes(
                msg,
                &unknown_attributes,
                MessageWriteVec::with_capacity(64),
            );
            err.add_message_integrity_with_key(&key, IntegrityAlgorithm::Sha1)
                .unwrap();
            return Err(err);
        }

        // TODO: proper lifetime handling
        let mut request_lifetime =
            request_lifetime.unwrap_or(DEFAULT_ALLOCATION_DURATION.as_secs() as u32);
        if request_lifetime > 0 {
            request_lifetime = request_lifetime.clamp(
                DEFAULT_ALLOCATION_DURATION.as_secs() as u32,
                MAXIMUM_ALLOCATION_DURATION.as_secs() as u32,
            );
        }
        let mut modified = false;
        if request_lifetime == 0 {
            error!("deleting allocation");
            if let Some(family) = requested_family {
                if let Some(allocation_idx) = client.allocations.iter().position(|allocation| {
                    (family == AddressFamily::IPV4 && allocation.addr.is_ipv4())
                        || (family == AddressFamily::IPV6 && allocation.addr.is_ipv6())
                }) {
                    modified = true;
                    *tcp_stun_change = Some(TcpStunChange::Delete(vec![client
                        .allocations
                        .swap_remove(allocation_idx)]));
                    if client.allocations.is_empty() {
                        self.remove_client_by_5tuple(
                            transmit.transport,
                            transmit.to,
                            transmit.from,
                        )
                        .unwrap();
                    }
                }
            } else {
                if let Some(client) =
                    self.remove_client_by_5tuple(transmit.transport, transmit.to, transmit.from)
                {
                    *tcp_stun_change = Some(TcpStunChange::Delete(client.allocations));
                } else {
                    unreachable!();
                };
                modified = true;
            }
        } else {
            for allocation in client.allocations.iter_mut() {
                if requested_family.map_or(true, |family| {
                    (family == AddressFamily::IPV4 && allocation.addr.is_ipv4())
                        || (family == AddressFamily::IPV6 && allocation.addr.is_ipv6())
                }) {
                    modified = true;
                    allocation.expires_at = now + Duration::from_secs(request_lifetime as u64)
                }
            }
        }

        let response = if modified {
            let lifetime = Lifetime::new(request_lifetime);
            let mut builder = Message::builder_success(
                msg,
                MessageWriteVec::with_capacity(MessageHeader::LENGTH + lifetime.padded_len() + 24),
            );
            builder.add_attribute(&lifetime).unwrap();
            builder
                .add_message_integrity_with_key(&key, IntegrityAlgorithm::Sha1)
                .unwrap();
            builder.finish()
        } else {
            trace!("peer address family mismatch");
            return Err(Self::peer_address_family_mismatch_signed(msg, &key));
        };

        let Ok(transmit) = self.stun.send(response, transmit.from, now) else {
            error!("Failed to send");
            return Err(Self::server_error(msg));
        };

        if request_lifetime == 0 {
            error!("{:?}", tcp_stun_change);
            info!(
                "Successfully deleted allocation {}, client {} to {}",
                transmit.transport, transmit.from, transmit.to
            );
        } else {
            info!(
                "Successfully refreshed allocation {}, client {} to {}",
                transmit.transport, transmit.from, transmit.to
            );
        }

        Ok(transmit)
    }

    fn handle_stun_create_permission(
        &mut self,
        transmit: Transmit<&Message<'_>>,
        now: Instant,
    ) -> Result<Transmit<Vec<u8>>, MessageWriteVec> {
        let msg = transmit.data;
        let key = self.validate_stun(&transmit, now)?.clone();

        let Some(client) =
            self.mut_client_from_5tuple(transmit.transport, transmit.to, transmit.from)
        else {
            trace!("allocation mismatch");
            return Err(Self::allocation_mismatch(msg, &key));
        };

        let mut peer_addresses = smallvec::SmallVec::<[SocketAddr; 4]>::default();
        let mut unknown_attributes = smallvec::SmallVec::<[AttributeType; 4]>::default();
        for (_offset, attr) in msg.iter_attributes() {
            match attr.get_type() {
                // checked by validate_stun()
                Username::TYPE | Realm::TYPE | Nonce::TYPE | MessageIntegrity::TYPE => (),
                XorPeerAddress::TYPE => {
                    let Ok(xor_peer_addr) = XorPeerAddress::from_raw(attr) else {
                        return Err(Self::bad_request_signed(msg, &key));
                    };
                    peer_addresses.push(xor_peer_addr.addr(msg.transaction_id()));
                }
                atype => {
                    if atype.comprehension_required() {
                        unknown_attributes.push(atype);
                    }
                }
            }
        }
        if !unknown_attributes.is_empty() {
            trace!("unknown attributes: {unknown_attributes:?}");
            let mut err = Message::unknown_attributes(
                msg,
                &unknown_attributes,
                MessageWriteVec::with_capacity(64),
            );
            err.add_message_integrity_with_key(&key, IntegrityAlgorithm::Sha1)
                .unwrap();
            return Err(err);
        }
        if peer_addresses.is_empty() {
            return Err(Self::bad_request_signed(msg, &key));
        }

        for peer_addr in peer_addresses.iter() {
            let Some(alloc) = client
                .allocations
                .iter_mut()
                .find(|a| a.addr.is_ipv4() == peer_addr.is_ipv4())
            else {
                trace!("peer address family mismatch");
                return Err(Self::peer_address_family_mismatch_signed(msg, &key));
            };

            if now > alloc.expires_at {
                trace!("allocation has expired");
                // allocation has expired
                return Err(Self::allocation_mismatch(msg, &key));
            }

            // TODO: support TCP allocations
            if let Some(position) = alloc
                .permissions
                .iter()
                .position(|perm| perm.ttype == TransportType::Udp && perm.addr == peer_addr.ip())
            {
                alloc.permissions[position].expires_at = now + PERMISSION_DURATION;
            } else {
                alloc.permissions.push(Permission {
                    addr: peer_addr.ip(),
                    ttype: TransportType::Udp,
                    expires_at: now + PERMISSION_DURATION,
                });
            }
        }

        let mut builder = Message::builder_success(
            msg,
            MessageWriteVec::with_capacity(MessageHeader::LENGTH + 24),
        );
        builder
            .add_message_integrity_with_key(&key, IntegrityAlgorithm::Sha1)
            .unwrap();
        let response = builder.finish();

        let Ok(transmit) = self.stun.send(response, transmit.from, now) else {
            error!("Failed to send");
            return Err(Self::server_error(msg));
        };
        debug!(
            "allocation {} from {} to {} successfully created permission for {:?}",
            transmit.transport, transmit.from, transmit.to, peer_addresses
        );

        Ok(transmit)
    }

    fn handle_stun_channel_bind(
        &mut self,
        transmit: Transmit<&Message<'_>>,
        now: Instant,
    ) -> Result<Transmit<Vec<u8>>, MessageWriteVec> {
        let msg = transmit.data;
        let key = self.validate_stun(&transmit, now)?.clone();

        let Some(client) =
            self.mut_client_from_5tuple(transmit.transport, transmit.to, transmit.from)
        else {
            trace!("allocation mismatch");
            return Err(Self::allocation_mismatch(msg, &key));
        };

        let mut xor_peer_address = None;
        let mut channel_number = None;

        let mut unknown_attributes = smallvec::SmallVec::<[AttributeType; 4]>::default();
        for (_offset, attr) in msg.iter_attributes() {
            match attr.get_type() {
                // checked by validate_stun()
                Username::TYPE | Realm::TYPE | Nonce::TYPE | MessageIntegrity::TYPE => (),
                XorPeerAddress::TYPE => xor_peer_address = XorPeerAddress::from_raw(attr).ok(),
                ChannelNumber::TYPE => channel_number = ChannelNumber::from_raw(attr).ok(),
                atype => {
                    if atype.comprehension_required() {
                        unknown_attributes.push(atype);
                    }
                }
            }
        }
        if !unknown_attributes.is_empty() {
            trace!("unknown attributes: {unknown_attributes:?}");
            let mut err = Message::unknown_attributes(
                msg,
                &unknown_attributes,
                MessageWriteVec::with_capacity(64),
            );
            err.add_message_integrity_with_key(&key, IntegrityAlgorithm::Sha1)
                .unwrap();
            return Err(err);
        }

        let peer_addr = xor_peer_address.map(|peer_addr| peer_addr.addr(msg.transaction_id()));
        let channel_no = channel_number.map(|channel| channel.channel());

        let Some(peer_addr) = peer_addr else {
            trace!("No peer address");
            return Err(Self::bad_request_signed(msg, &key));
        };

        let Some(alloc) = client
            .allocations
            .iter_mut()
            .find(|allocation| allocation.addr.is_ipv4() == peer_addr.is_ipv4())
        else {
            trace!("peer address family mismatch");
            return Err(Self::peer_address_family_mismatch_signed(msg, &key));
        };

        if now > alloc.expires_at {
            trace!("allocation has expired");
            // allocation has expired
            return Err(Self::allocation_mismatch(msg, &key));
        }

        let mut existing = alloc.channels.iter_mut().find(|channel| {
            channel.peer_addr == peer_addr && channel.peer_transport == TransportType::Udp
        });

        let Some(channel_no) = channel_no else {
            debug!("Bad request: no requested channel id");
            return Err(Self::bad_request_signed(msg, &key));
        };

        // RFC8656 reduces this range to 0x4000..=0x4fff but we keep the RFC5766 range for
        // backwards compatibility
        if !(0x4000..=0x7fff).contains(&channel_no) {
            trace!("Channel id out of range");
            return Err(Self::bad_request_signed(msg, &key));
        }
        if existing
            .as_ref()
            .is_some_and(|existing| existing.id != channel_no)
        {
            trace!("channel peer address does not match channel ID");
            return Err(Self::bad_request_signed(msg, &key));
        }

        if let Some(existing) = existing.as_mut() {
            existing.expires_at = now + CHANNEL_DURATION;
        } else {
            alloc.channels.push(Channel {
                id: channel_no,
                peer_addr,
                peer_transport: TransportType::Udp,
                expires_at: now + CHANNEL_DURATION,
            });
        }

        if let Some(existing) = alloc
            .permissions
            .iter_mut()
            .find(|perm| perm.ttype == TransportType::Udp && perm.addr == peer_addr.ip())
        {
            existing.expires_at = now + PERMISSION_DURATION;
        } else {
            alloc.permissions.push(Permission {
                addr: peer_addr.ip(),
                ttype: TransportType::Udp,
                expires_at: now + PERMISSION_DURATION,
            });
        }

        let mut builder = Message::builder_success(
            msg,
            MessageWriteVec::with_capacity(MessageHeader::LENGTH + 24),
        );
        builder
            .add_message_integrity_with_key(&key, IntegrityAlgorithm::Sha1)
            .unwrap();
        let response = builder.finish();

        let Ok(transmit) = self.stun.send(response, transmit.from, now) else {
            error!("Failed to send");
            return Err(Self::server_error(msg));
        };

        debug!(
            "allocation {} from {} to {} successfully created channel {channel_no} for {:?}",
            transmit.transport,
            transmit.from,
            transmit.to,
            peer_addr.ip()
        );

        Ok(transmit)
    }

    fn connection_already_exists_error_signed(
        msg: &Message<'_>,
        key: &IntegrityKey,
    ) -> MessageWriteVec {
        let error = ErrorCode::builder(ErrorCode::CONNECTION_ALREADY_EXISTS)
            .build()
            .unwrap();
        let mut response = Message::builder_error(
            msg,
            MessageWriteVec::with_capacity(MessageHeader::LENGTH + error.padded_len() + 24 + 8),
        );
        response.add_attribute(&error).unwrap();
        response
            .add_message_integrity_with_key(key, IntegrityAlgorithm::Sha1)
            .unwrap();
        response.add_fingerprint().unwrap();
        response
    }

    fn handle_stun_connect(
        &mut self,
        transmit: Transmit<&Message<'_>>,
        now: Instant,
    ) -> Result<(), MessageWriteVec> {
        let msg = transmit.data;
        let key = self.validate_stun(&transmit, now)?.clone();

        let Some(client) =
            self.mut_client_from_5tuple(transmit.transport, transmit.to, transmit.from)
        else {
            trace!("allocation mismatch");
            return Err(Self::allocation_mismatch(msg, &key));
        };

        let mut peer_addr = None;

        let mut unknown_attributes = smallvec::SmallVec::<[AttributeType; 4]>::default();
        for (_offset, attr) in msg.iter_attributes() {
            match attr.get_type() {
                // handled by validate_stun
                Username::TYPE | Realm::TYPE | Nonce::TYPE | MessageIntegrity::TYPE => (),
                XorPeerAddress::TYPE => {
                    peer_addr = XorPeerAddress::from_raw(attr)
                        .ok()
                        .map(|r| r.addr(msg.transaction_id()))
                }
                atype => {
                    if atype.comprehension_required() {
                        unknown_attributes.push(atype);
                    }
                }
            }
        }
        if !unknown_attributes.is_empty() {
            trace!("unknown attributes: {unknown_attributes:?}");
            let mut err = Message::unknown_attributes(
                msg,
                &unknown_attributes,
                MessageWriteVec::with_capacity(64),
            );
            err.add_message_integrity_with_key(&key, IntegrityAlgorithm::Sha1)
                .unwrap();
            return Err(err);
        }

        let Some(peer_addr) = peer_addr else {
            return Err(Self::bad_request_signed(msg, &key));
        };

        let Some(alloc) = client
            .allocations
            .iter_mut()
            .find(|allocation| allocation.addr.is_ipv4() == peer_addr.is_ipv4())
        else {
            trace!("peer address family mismatch");
            return Err(Self::peer_address_family_mismatch_signed(msg, &key));
        };

        if now > alloc.expires_at {
            trace!("allocation has expired");
            // allocation has expired
            return Err(Self::allocation_mismatch(msg, &key));
        }

        if alloc
            .pending_tcp_connect
            .iter()
            .any(|pending| pending.peer_addr == peer_addr)
        {
            return Err(Self::connection_already_exists_error_signed(msg, &key));
        }

        // TODO: check if a connection bind request is currently in progress.

        alloc.pending_tcp_connect.push(PendingTcpConnect {
            transaction_id: msg.transaction_id(),
            client_control_addr: transmit.from,
            listen_addr: transmit.to,
            relayed_addr: alloc.addr,
            peer_addr,
            expires_at: None,
        });
        Ok(())
    }

    fn handle_stun_connection_bind(
        &mut self,
        transmit: Transmit<&Message<'_>>,
        now: Instant,
        tcp_stun_change: &mut Option<TcpStunChange>,
    ) -> Result<Transmit<Vec<u8>>, MessageWriteVec> {
        let msg = transmit.data;

        if transmit.transport != TransportType::Tcp {
            return Err(Self::bad_request(msg, 0));
        }

        if self
            .client_from_5tuple(transmit.transport, transmit.to, transmit.from)
            .is_some()
        {
            trace!("allocation mismatch");
            let error = ErrorCode::builder(ErrorCode::ALLOCATION_MISMATCH)
                .build()
                .unwrap();
            let mut response = Message::builder_error(
                msg,
                MessageWriteVec::with_capacity(MessageHeader::LENGTH + error.padded_len() + 24 + 8),
            );
            response.add_attribute(&error).unwrap();
            response.add_fingerprint().unwrap();
            return Err(response);
        };

        let mut connection_id = None;

        let mut unknown_attributes = smallvec::SmallVec::<[AttributeType; 4]>::default();
        for (_offset, attr) in msg.iter_attributes() {
            match attr.get_type() {
                // handled by validate_stun
                Username::TYPE | Realm::TYPE | Nonce::TYPE | MessageIntegrity::TYPE => (),
                ConnectionId::TYPE => {
                    connection_id = ConnectionId::from_raw(attr).ok().map(|r| r.id())
                }
                atype => {
                    if atype.comprehension_required() {
                        unknown_attributes.push(atype);
                    }
                }
            }
        }

        // If the request does not contain the CONNECTION-ID attribute, or if
        // this attribute does not refer to an existing pending connection, the
        // server MUST return a 400 (Bad Request) error.
        let Some(connection_id) = connection_id else {
            trace!("missing connection id");
            return Err(Self::bad_request(msg, 0));
        };
        let Some(idx) = self
            .pending_tcp_connection_binds
            .iter()
            .position(|pending| {
                pending.connection_id == connection_id && pending.listen_addr == transmit.to
            })
        else {
            trace!("no pending connection with id {connection_id}");
            return Err(Self::bad_request(msg, 0));
        };

        let pending = &self.pending_tcp_connection_binds[idx];
        // need to validate based on the client control connection.
        let client_transmit = Transmit::new(
            transmit.data,
            TransportType::Tcp,
            pending.client_control_addr,
            pending.listen_addr,
        );
        let key = self.validate_stun(&client_transmit, now)?.clone();

        if !unknown_attributes.is_empty() {
            trace!("unknown attributes: {unknown_attributes:?}");
            let mut err = Message::unknown_attributes(
                msg,
                &unknown_attributes,
                MessageWriteVec::with_capacity(64),
            );
            err.add_message_integrity_with_key(&key, IntegrityAlgorithm::Sha1)
                .unwrap();
            return Err(err);
        }

        // only once the incoming credentials are validated can we remove the pending request.
        let pending = self.pending_tcp_connection_binds.swap_remove(idx);

        *tcp_stun_change = Some(TcpStunChange::Data {
            client_data_addr: transmit.from,
            listen_addr: pending.listen_addr,
            relayed_addr: pending.relayed_addr,
            peer_addr: pending.peer_addr,
        });

        // TODO: state changes required for sending/receiving TCP

        debug!("TCP connection bound for pending {pending:?}");

        let mut msg = Message::builder_success(msg, MessageWriteVec::new());
        msg.add_message_integrity_with_key(&key, IntegrityAlgorithm::Sha1)
            .unwrap();
        Ok(Transmit::new(
            msg.finish(),
            transmit.transport,
            transmit.to,
            transmit.from,
        ))
    }

    fn handle_stun_send_indication(
        &mut self,
        transmit: Transmit<&Message<'_>>,
        now: Instant,
    ) -> Result<
        (
            TransportType,
            SocketAddr,
            SocketAddr,
            core::ops::Range<usize>,
        ),
        (),
    > {
        let msg = transmit.data;
        let mut peer_address = None;
        let mut data = None;

        for (offset, attr) in msg.iter_attributes() {
            match attr.get_type() {
                XorPeerAddress::TYPE => {
                    peer_address = Some(
                        XorPeerAddress::from_raw(attr)
                            .map_err(|_| ())?
                            .addr(msg.transaction_id()),
                    );
                }
                AData::TYPE => data = AData::from_raw(attr).ok().map(|adata| (offset + 4, adata)),
                atype => {
                    if atype.comprehension_required() {
                        return Err(());
                    }
                }
            }
        }
        let Some((peer_address, (offset, data))) = peer_address.zip(data) else {
            return Err(());
        };

        let Some(client) = self.client_from_5tuple(transmit.transport, transmit.to, transmit.from)
        else {
            trace!(
                "no client for transport {} from {}, to {}",
                transmit.transport,
                transmit.from,
                transmit.to
            );
            return Err(());
        };

        let Some(alloc) = client
            .allocations
            .iter()
            .find(|allocation| allocation.addr.ip().is_ipv4() == peer_address.is_ipv4())
        else {
            trace!("no allocation available");
            return Err(());
        };
        if now > alloc.expires_at {
            debug!("{} allocation {} expired", alloc.ttype, alloc.addr);
            return Err(());
        }

        let Some(_permission) = alloc.have_permission(peer_address.ip(), now) else {
            trace!("no permission for {}", peer_address);
            return Err(());
        };

        trace!("have {} to send to {:?}", data.data().len(), peer_address);
        Ok((
            alloc.ttype,
            alloc.addr,
            peer_address,
            offset..offset + data.data().len(),
        ))
    }

    #[tracing::instrument(
        name = "turn_server_handle_stun",
        skip(self, transmit, now, tcp_stun_change),
        fields(
            msg.transaction = %transmit.data.transaction_id(),
            msg.method = %transmit.data.method(),
        )
    )]
    fn handle_stun(
        &mut self,
        transmit: Transmit<&Message<'_>>,
        tcp_type: TcpStunType,
        now: Instant,
        tcp_stun_change: &mut Option<TcpStunChange>,
    ) -> Result<Option<InternalHandleStun>, MessageWriteVec> {
        trace!("received STUN message {}", transmit.data);
        let ret = if transmit
            .data
            .has_class(stun_proto::types::message::MessageClass::Request)
        {
            match transmit.data.method() {
                BINDING if matches!(tcp_type, TcpStunType::Control | TcpStunType::Unknown) => self
                    .handle_stun_binding(transmit, now)
                    .map(|t| Some(InternalHandleStun::Transmit(t))),
                ALLOCATE if matches!(tcp_type, TcpStunType::Unknown | TcpStunType::Control) => self
                    .handle_stun_allocate(transmit, tcp_type, now, tcp_stun_change)
                    .map(|_| None),
                REFRESH if matches!(tcp_type, TcpStunType::Control) => self
                    .handle_stun_refresh(transmit, now, tcp_stun_change)
                    .map(|t| Some(InternalHandleStun::Transmit(t))),
                CREATE_PERMISSION if matches!(tcp_type, TcpStunType::Control) => self
                    .handle_stun_create_permission(transmit, now)
                    .map(|t| Some(InternalHandleStun::Transmit(t))),
                CHANNEL_BIND if matches!(tcp_type, TcpStunType::Control) => self
                    .handle_stun_channel_bind(transmit, now)
                    .map(|t| Some(InternalHandleStun::Transmit(t))),
                CONNECT if matches!(tcp_type, TcpStunType::Control) => {
                    self.handle_stun_connect(transmit, now).map(|_| None)
                }
                CONNECTION_BIND if matches!(tcp_type, TcpStunType::Unknown) => self
                    .handle_stun_connection_bind(transmit, now, tcp_stun_change)
                    .map(|t| Some(InternalHandleStun::Transmit(t))),
                _ => {
                    let key = self.validate_stun(&transmit, now)?.clone();
                    let Some(_client) =
                        self.mut_client_from_5tuple(transmit.transport, transmit.to, transmit.from)
                    else {
                        return Err(Self::allocation_mismatch(transmit.data, &key));
                    };

                    Err(Self::bad_request_signed(transmit.data, &key))
                }
            }
        } else if transmit
            .data
            .has_class(stun_proto::types::message::MessageClass::Indication)
        {
            match transmit.data.method() {
                SEND if tcp_type == TcpStunType::Control => Ok(self
                    .handle_stun_send_indication(transmit, now)
                    .ok()
                    .map(|(transport, from, to, range)| {
                        InternalHandleStun::Data(transport, from, to, range)
                    })),
                _ => Ok(None),
            }
        } else if transmit.data.class().is_response() {
            match transmit.data.method() {
                CONNECTION_ATTEMPT if tcp_type == TcpStunType::Control => {
                    // TODO: handle connection attempt
                    Ok(None)
                }
                _ => Ok(None),
            }
        } else {
            Ok(None)
        };
        ret
    }

    fn mut_nonce_from_5tuple(
        &mut self,
        ttype: TransportType,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) -> Option<&mut NonceData> {
        self.nonces.iter_mut().find(|nonce| {
            nonce.transport == ttype
                && nonce.remote_addr == remote_addr
                && nonce.local_addr == local_addr
        })
    }

    fn client_from_5tuple(
        &self,
        ttype: TransportType,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) -> Option<&Client> {
        self.clients.iter().find(|client| {
            client.transport == ttype
                && client.remote_addr == remote_addr
                && client.local_addr == local_addr
        })
    }

    fn mut_client_from_5tuple(
        &mut self,
        ttype: TransportType,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) -> Option<&mut Client> {
        self.clients.iter_mut().find(|client| {
            client.transport == ttype
                && client.remote_addr == remote_addr
                && client.local_addr == local_addr
        })
    }

    fn remove_client_by_5tuple(
        &mut self,
        ttype: TransportType,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) -> Option<Client> {
        info!("attempting to remove client {ttype}, {remote_addr} -> {local_addr}");
        if let Some(idx) = self.clients.iter().position(|client| {
            client.transport == ttype
                && client.remote_addr == remote_addr
                && client.local_addr == local_addr
        }) {
            Some(self.clients.swap_remove(idx))
        } else {
            None
        }
    }

    fn allocation_from_public_5tuple(
        &self,
        ttype: TransportType,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) -> Option<(&Client, &Allocation, &Permission)> {
        self.clients.iter().find_map(|client| {
            client
                .allocations
                .iter()
                .find_map(|allocation| {
                    if allocation.ttype == ttype && allocation.addr == local_addr {
                        allocation
                            .permissions
                            .iter()
                            .find(|permission| permission.addr == remote_addr.ip())
                            .map(|permission| (allocation, permission))
                    } else {
                        None
                    }
                })
                .map(|(allocation, permission)| (client, allocation, permission))
        })
    }

    fn handle_channel(
        &mut self,
        transport: TransportType,
        from: SocketAddr,
        to: SocketAddr,
        channel: ChannelData<'_>,
        now: Instant,
    ) -> Option<ForwardChannelData> {
        let Some(client) = self.client_from_5tuple(transport, to, from) else {
            trace!(
                "No handler for {} bytes over {:?} from {:?}, to {:?}. Ignoring",
                channel.data().len() + 4,
                transport,
                from,
                to
            );
            return None;
        };
        trace!(
            "received channel {} with {} bytes from {:?}",
            channel.id(),
            channel.data().len(),
            from
        );
        let Some((allocation, existing)) = client.allocations.iter().find_map(|allocation| {
            allocation
                .channel_from_id(channel.id())
                .map(|perm| (allocation, perm))
        }) else {
            warn!(
                "no channel id {} for this client {:?}",
                channel.id(),
                client.remote_addr
            );
            // no channel with that id
            return None;
        };
        if existing.expires_at < now {
            trace!(
                "channel for {from} expired {:?} ago",
                now - existing.expires_at
            );
            return None;
        }

        // A packet from the client needs to be sent to the peer referenced by the
        // configured channel.
        let Some(permission) = allocation.permission_from_5tuple(
            allocation.ttype,
            allocation.addr,
            existing.peer_addr,
        ) else {
            warn!(
                "no permission for {:?} for this allocation {:?}",
                existing.peer_addr, allocation.addr
            );
            return None;
        };
        if permission.expires_at < now {
            trace!(
                "permission for {from} expired {:?} ago",
                now - permission.expires_at
            );
            return None;
        }
        Some(ForwardChannelData {
            transport: allocation.ttype,
            from: allocation.addr,
            to: existing.peer_addr,
        })
    }

    fn handle_listen_tcp_stored_message(
        &mut self,
        remote_addr: SocketAddr,
        data: Vec<u8>,
        tcp_type: TcpStunType,
        now: Instant,
        tcp_stun_change: &mut Option<TcpStunChange>,
    ) -> Option<Transmit<Vec<u8>>> {
        let listen_addr = self.stun.local_addr();
        let Ok(msg) = Message::from_bytes(&data) else {
            return None;
        };
        let msg_transmit = Transmit::new(&msg, TransportType::Tcp, remote_addr, listen_addr);
        match self.handle_stun(msg_transmit, tcp_type, now, tcp_stun_change) {
            Err(builder) => Some(Transmit::new(
                builder.finish(),
                TransportType::Tcp,
                listen_addr,
                remote_addr,
            )),
            Ok(Some(InternalHandleStun::Transmit(transmit))) => Some(transmit),
            Ok(Some(InternalHandleStun::Data(transport, from, to, range))) => Some(Transmit::new(
                data[range.start..range.end].to_vec(),
                transport,
                from,
                to,
            )),
            Ok(None) => None,
        }
    }

    fn connection_attempt(
        connection_id: u32,
        peer_addr: SocketAddr,
        key: &IntegrityKey,
    ) -> MessageWriteVec {
        let transaction_id = TransactionId::generate();
        let connection_id = ConnectionId::new(connection_id);
        let peer_addr = XorPeerAddress::new(peer_addr, transaction_id);
        let mut response = Message::builder(
            MessageType::from_class_method(MessageClass::Request, CONNECTION_ATTEMPT),
            transaction_id,
            MessageWriteVec::with_capacity(
                MessageHeader::LENGTH + connection_id.padded_len() + 24 + 8,
            ),
        );
        response.add_attribute(&connection_id).unwrap();
        response.add_attribute(&peer_addr).unwrap();
        response
            .add_message_integrity_with_key(key, IntegrityAlgorithm::Sha1)
            .unwrap();
        response.add_fingerprint().unwrap();
        response
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum TcpStunType {
    // TCP connection type not determined yet.
    Unknown,
    // Control connection. Always STUN messages.
    Control,
}

#[derive(Debug)]
enum TcpStunChange {
    Control,
    Data {
        client_data_addr: SocketAddr,
        listen_addr: SocketAddr,
        relayed_addr: SocketAddr,
        peer_addr: SocketAddr,
    },
    Delete(Vec<Allocation>),
}

impl TurnServer {
    /// Construct a new [`TurnServer`]
    ///
    /// # Examples
    /// ```
    /// # use turn_server_proto::server::TurnServer;
    /// # use turn_server_proto::api::TurnServerApi;
    /// # use stun_proto::types::TransportType;
    /// let realm = String::from("realm");
    /// let listen_addr = "10.0.0.1:3478".parse().unwrap();
    /// let server = TurnServer::new(TransportType::Udp, listen_addr, realm);
    /// assert_eq!(server.listen_address(), listen_addr);
    /// ```
    pub fn new(ttype: TransportType, listen_addr: SocketAddr, realm: String) -> Self {
        let stun = StunAgent::builder(ttype, listen_addr).build();
        Self {
            protocol: TurnServerProtocol {
                realm,
                stun,
                clients: vec![],
                nonces: vec![],
                earliest_nonce_expiry: None,
                pending_transmits: VecDeque::default(),
                pending_allocates: VecDeque::default(),
                users: BTreeMap::default(),
                nonce_expiry_duration: DEFAULT_NONCE_EXPIRY_DURATION,
                pending_socket_removals: VecDeque::default(),
                pending_socket_listen_removals: VecDeque::default(),
                tcp_connection_id: 0,
                pending_tcp_connection_binds: Default::default(),
            },
            incoming_tcp_buffers: Default::default(),
            peer_tcp: Default::default(),
        }
    }

    /// The [`TransportType`] of this TURN server.
    pub fn transport(&self) -> TransportType {
        self.protocol.stun.transport()
    }

    fn remove_allocation_resources(
        allocation: &mut Allocation,
        peer_tcp: &mut BTreeMap<(SocketAddr, SocketAddr), PeerTcp>,
        incoming_tcp_buffers: &mut BTreeMap<(SocketAddr, SocketAddr), TcpBuffer>,
        pending_socket_removals: &mut VecDeque<Socket5Tuple>,
        pending_socket_listen_removals: &mut VecDeque<(TransportType, SocketAddr)>,
        pending_tcp_connection_binds: &mut Vec<PendingConnectionBind>,
    ) {
        trace!("removing allocation: {allocation:?}");
        let mut remove_peer_connections = vec![];
        let mut remove_client_connections = vec![];
        for pending in allocation.pending_tcp_connect.drain(..) {
            trace!(
                "removing pending tcp connection to peer {} from {}",
                pending.peer_addr,
                pending.relayed_addr
            );
            pending_socket_removals.push_back(Socket5Tuple {
                transport: TransportType::Tcp,
                local_addr: pending.relayed_addr,
                remote_addr: pending.peer_addr,
            });
        }
        peer_tcp.retain(|&(relayed_addr, peer_addr), peer_tcp| {
            if relayed_addr == allocation.addr {
                remove_peer_connections.push((relayed_addr, peer_addr));
                trace!(
                    "removing tcp peer connection from {} to {}",
                    relayed_addr,
                    peer_addr
                );
                pending_socket_removals.push_back(Socket5Tuple {
                    transport: TransportType::Tcp,
                    local_addr: relayed_addr,
                    remote_addr: peer_addr,
                });
                if let PeerTcp::Passthrough {
                    client_addr,
                    listen_addr,
                    pending_data: _,
                } = peer_tcp
                {
                    remove_client_connections.push((*client_addr, *listen_addr));
                }
                false
            } else {
                true
            }
        });
        Self::remove_tcp_resources(
            remove_peer_connections,
            remove_client_connections,
            incoming_tcp_buffers,
            pending_socket_removals,
            pending_tcp_connection_binds,
        );
        pending_socket_listen_removals.push_back((allocation.ttype, allocation.addr));
    }

    fn remove_tcp_resources(
        remove_peer_connections: Vec<(SocketAddr, SocketAddr)>,
        remove_client_connections: Vec<(SocketAddr, SocketAddr)>,
        incoming_tcp_buffers: &mut BTreeMap<(SocketAddr, SocketAddr), TcpBuffer>,
        pending_socket_removals: &mut VecDeque<Socket5Tuple>,
        pending_tcp_connection_binds: &mut Vec<PendingConnectionBind>,
    ) {
        incoming_tcp_buffers.retain(|&(client_addr, listen_addr), _tcp_buffer| {
            if remove_client_connections.contains(&(client_addr, listen_addr)) {
                trace!(
                    "removing tcp connection to client {} from {}",
                    client_addr,
                    listen_addr
                );
                pending_socket_removals.push_back(Socket5Tuple {
                    transport: TransportType::Tcp,
                    local_addr: listen_addr,
                    remote_addr: client_addr,
                });
                false
            } else {
                true
            }
        });
        pending_tcp_connection_binds.retain(|pending| {
            !remove_peer_connections.contains(&(pending.relayed_addr, pending.peer_addr))
        });
    }
}

impl TurnServerApi for TurnServer {
    fn add_user(&mut self, username: String, password: String) {
        let key = MessageIntegrityCredentials::LongTerm(LongTermCredentials::new(
            username.to_owned(),
            password.to_owned(),
            self.protocol.realm.clone(),
        ))
        .make_key();
        self.protocol.users.insert(username, key);
    }

    fn listen_address(&self) -> SocketAddr {
        self.protocol.stun.local_addr()
    }

    fn set_nonce_expiry_duration(&mut self, expiry_duration: Duration) {
        if expiry_duration < MINIMUM_NONCE_EXPIRY_DURATION {
            panic!("Attempted to set a nonce expiry duration ({expiry_duration:?}) of less than the allowed minimum ({MINIMUM_NONCE_EXPIRY_DURATION:?})");
        }
        self.protocol.nonce_expiry_duration = expiry_duration;
    }

    #[tracing::instrument(
        name = "turn_server_recv_icmp",
        skip(self, bytes, now),
        fields(
            data_len = bytes.as_ref().len(),
        )
    )]
    fn recv_icmp<T: AsRef<[u8]>>(
        &mut self,
        family: AddressFamily,
        bytes: T,
        now: Instant,
    ) -> Option<Transmit<Vec<u8>>> {
        use pnet_packet::udp;
        let bytes = bytes.as_ref();
        trace!("have incoming icmp data");
        if bytes.len() < 8 {
            return None;
        }

        let icmpv4;
        let ipv4;
        let icmpv6;
        let ipv6;
        let source;
        let destination;
        let icmp_code;
        let icmp_type;
        let icmp_data;
        let payload = match family {
            AddressFamily::IPV4 => {
                use pnet_packet::{icmp, ipv4};
                icmpv4 = icmp::IcmpPacket::new(bytes)?;
                trace!("parsed icmp: {icmpv4:?}");
                icmp_code = icmpv4.get_icmp_code().0;
                icmp_type = icmpv4.get_icmp_type().0;
                // the server verifies that the type is either 3 or 11 for an ICMPv4
                if ![
                    icmp::IcmpTypes::DestinationUnreachable,
                    icmp::IcmpTypes::TimeExceeded,
                ]
                .contains(&icmpv4.get_icmp_type())
                {
                    debug!("ICMPv4 is not an actionable type");
                    return None;
                }
                if icmpv4.get_icmp_type() == icmp::IcmpTypes::DestinationUnreachable &&
                    icmpv4.get_icmp_code() == icmp::destination_unreachable::IcmpCodes::FragmentationRequiredAndDFFlagSet
                {
                    icmp_data = BigEndian::read_u32(icmpv4.payload());
                } else {
                    icmp_data = 0;
                };
                ipv4 = ipv4::Ipv4Packet::new(&icmpv4.payload()[4..])?;
                trace!("parsed ipv4: {ipv4:?}");
                source = IpAddr::V4(ipv4.get_source().octets().into());
                destination = IpAddr::V4(ipv4.get_destination().octets().into());
                ipv4.payload()
            }
            AddressFamily::IPV6 => {
                use pnet_packet::{icmpv6, ipv6};
                icmpv6 = icmpv6::Icmpv6Packet::new(bytes)?;
                icmp_type = icmpv6.get_icmpv6_type().0;
                icmp_code = icmpv6.get_icmpv6_code().0;
                // the server verifies that the type is either 1, 2, or 3 for an ICMPv6
                if ![
                    icmpv6::Icmpv6Types::DestinationUnreachable,
                    icmpv6::Icmpv6Types::PacketTooBig,
                    icmpv6::Icmpv6Types::TimeExceeded,
                ]
                .contains(&icmpv6.get_icmpv6_type())
                {
                    debug!("ICMPv6 is not an actionable type");
                    return None;
                }
                if icmpv6.get_icmpv6_type() == icmpv6::Icmpv6Types::PacketTooBig {
                    icmp_data = BigEndian::read_u32(icmpv6.payload());
                } else {
                    icmp_data = 0;
                };
                ipv6 = ipv6::Ipv6Packet::new(&icmpv6.payload()[4..])?;
                trace!("parsed ipv6: {ipv6:?}");
                source = IpAddr::V6(ipv6.get_source().segments().into());
                destination = IpAddr::V6(ipv6.get_destination().segments().into());
                ipv6.payload()
            }
        };
        let udp = udp::UdpPacket::new(payload)?;
        let source = SocketAddr::new(source, udp.get_source());
        let destination = SocketAddr::new(destination, udp.get_destination());
        let (client, allocation, permission) =
            self.protocol
                .allocation_from_public_5tuple(TransportType::Udp, source, destination)?;
        if allocation.expires_at < now || permission.expires_at < now {
            return None;
        }

        info!(
            "sending ICMP (type:{icmp_type}, code:{icmp_code}, data{icmp_data}) DATA indication to client {}",
            client.remote_addr
        );
        let transaction_id = TransactionId::generate();
        let xor_addr = XorPeerAddress::new(destination, transaction_id);
        let icmp = Icmp::new(icmp_type, icmp_code, icmp_data);
        let mut msg = Message::builder(
            MessageType::from_class_method(MessageClass::Indication, DATA),
            transaction_id,
            MessageWriteVec::with_capacity(
                MessageHeader::LENGTH + xor_addr.padded_len() + icmp.padded_len(),
            ),
        );
        msg.add_attribute(&xor_addr).unwrap();
        msg.add_attribute(&icmp).unwrap();
        self.protocol
            .stun
            .send(msg.finish(), client.remote_addr, now)
            .ok()
    }

    #[tracing::instrument(
        name = "turn_server_recv",
        skip(self, transmit, now),
        fields(
            transport = %transmit.transport,
            remote_addr = %transmit.from,
            local_addr = %transmit.to,
            data_len = transmit.data.as_ref().len(),
        )
    )]
    fn recv<T: AsRef<[u8]> + core::fmt::Debug>(
        &mut self,
        transmit: Transmit<T>,
        now: Instant,
    ) -> Option<TransmitBuild<DelayedMessageOrChannelSend<T>>> {
        trace!("executing at {now:?}");
        if let Some((client, allocation, permission)) = self.protocol.allocation_from_public_5tuple(
            transmit.transport,
            transmit.to,
            transmit.from,
        ) {
            // A packet from the relayed address needs to be sent to the client that set up
            // the allocation.
            if permission.expires_at < now {
                trace!(
                    "permission for {} expired {:?} ago",
                    permission.addr,
                    now - permission.expires_at
                );
                return None;
            }

            if allocation.ttype == TransportType::Tcp {
                let connection_id = self.protocol.tcp_connection_id;

                if let Some(peer_tcp) = self.peer_tcp.get_mut(&(transmit.to, transmit.from)) {
                    match peer_tcp {
                        PeerTcp::PendingConnectionBind {
                            peer_data,
                            expires_at: _,
                        } => {
                            peer_data.extend_from_slice(transmit.data.as_ref());
                            return None;
                        }
                        PeerTcp::Passthrough {
                            client_addr,
                            listen_addr,
                            pending_data,
                        } => {
                            if pending_data.is_empty() {
                                let len = transmit.data.as_ref().len();
                                if len > 0 {
                                    return Some(TransmitBuild::new(
                                        DelayedMessageOrChannelSend::Range(transmit.data, 0..len),
                                        TransportType::Tcp,
                                        *listen_addr,
                                        *client_addr,
                                    ));
                                } else {
                                    let client_addr = *client_addr;
                                    let listen_addr = *listen_addr;
                                    if self
                                        .incoming_tcp_buffers
                                        .remove(&(client_addr, listen_addr))
                                        .is_some()
                                    {
                                        self.protocol.pending_socket_removals.push_back(
                                            Socket5Tuple {
                                                transport: TransportType::Tcp,
                                                local_addr: listen_addr,
                                                remote_addr: client_addr,
                                            },
                                        );
                                    }
                                    self.peer_tcp.remove(&(transmit.to, transmit.from));
                                    return None;
                                }
                            } else {
                                let mut peer_data = core::mem::take(pending_data);
                                peer_data.extend_from_slice(transmit.data.as_ref());
                                return Some(TransmitBuild::new(
                                    DelayedMessageOrChannelSend::Owned(peer_data),
                                    TransportType::Tcp,
                                    *listen_addr,
                                    *client_addr,
                                ));
                            }
                        }
                    }
                } else {
                    // No TCP connection set up for this peer address. Ask the client if they want
                    // to accept this peer.
                    let Some((allocation, msg, listen_addr, client_addr)) =
                        self.protocol.clients.iter_mut().find_map(|client| {
                            client
                                .allocations
                                .iter_mut()
                                .find(|allocation| {
                                    allocation.ttype == TransportType::Tcp
                                        && allocation.addr == transmit.to
                                        && allocation
                                            .permissions
                                            .iter()
                                            .any(|permission| permission.addr == transmit.from.ip())
                                })
                                .map(|allocation| {
                                    let msg = TurnServerProtocol::connection_attempt(
                                        connection_id,
                                        transmit.from,
                                        &client.key,
                                    );
                                    (allocation, msg, client.local_addr, client.remote_addr)
                                })
                        })
                    else {
                        // unknown relayed address
                        return None;
                    };
                    let relayed_addr = allocation.addr;
                    self.protocol.tcp_connection_id =
                        self.protocol.tcp_connection_id.wrapping_add(1);

                    self.peer_tcp.insert(
                        (transmit.to, transmit.from),
                        PeerTcp::PendingConnectionBind {
                            peer_data: transmit.data.as_ref().to_vec(),
                            expires_at: now + TCP_PEER_CONNECTION_TIMEOUT,
                        },
                    );
                    self.protocol
                        .pending_tcp_connection_binds
                        .push(PendingConnectionBind {
                            connection_id,
                            listen_addr,
                            relayed_addr,
                            peer_addr: transmit.from,
                            client_control_addr: client_addr,
                        });
                    return Some(TransmitBuild::new(
                        DelayedMessageOrChannelSend::Owned(msg.finish()),
                        TransportType::Tcp,
                        listen_addr,
                        client_addr,
                    ));
                }
            }

            if let Some(existing) =
                allocation.channel_from_5tuple(transmit.transport, transmit.to, transmit.from)
            {
                debug!(
                    "found existing channel {} for {:?} for this allocation {:?}",
                    existing.id, transmit.from, allocation.addr
                );
                Some(TransmitBuild::new(
                    DelayedMessageOrChannelSend::Channel(DelayedChannel::new(
                        existing.id,
                        transmit.data,
                    )),
                    client.transport,
                    client.local_addr,
                    client.remote_addr,
                ))
            } else {
                // no channel with that id
                debug!(
                    "no channel for {:?} for this allocation {:?}, using DATA indication",
                    transmit.from, allocation.addr
                );

                Some(TransmitBuild::new(
                    DelayedMessageOrChannelSend::Message(DelayedMessage::for_client(
                        transmit.from,
                        transmit.data,
                    )),
                    client.transport,
                    client.local_addr,
                    client.remote_addr,
                ))
            }
        } else if transmit.transport == self.protocol.stun.transport()
            && transmit.to == self.protocol.stun.local_addr()
        {
            match transmit.transport {
                TransportType::Tcp => {
                    let mut incoming_tcp_hoist;
                    let incoming_tcp = if transmit.data.as_ref().is_empty() {
                        incoming_tcp_hoist = self
                            .incoming_tcp_buffers
                            .remove(&(transmit.from, transmit.to))?;
                        &mut incoming_tcp_hoist
                    } else {
                        self.incoming_tcp_buffers
                            .entry((transmit.from, transmit.to))
                            .or_insert_with(|| TcpBuffer::Unknown(TurnTcpBuffer::new()))
                    };
                    let (tcp_type, tcp_buffer) = match incoming_tcp {
                        TcpBuffer::Unknown(tcp_buffer) => (TcpStunType::Unknown, tcp_buffer),
                        TcpBuffer::Control(tcp_buffer) => (TcpStunType::Control, tcp_buffer),
                        TcpBuffer::Passthrough {
                            relayed_addr,
                            peer_addr,
                            pending_data,
                        } => {
                            if pending_data.is_empty() {
                                let len = transmit.data.as_ref().len();
                                return Some(TransmitBuild::new(
                                    DelayedMessageOrChannelSend::Range(transmit.data, 0..len),
                                    TransportType::Tcp,
                                    *relayed_addr,
                                    *peer_addr,
                                ));
                            } else {
                                let mut peer_data = core::mem::take(pending_data);
                                peer_data.extend_from_slice(transmit.data.as_ref());
                                return Some(TransmitBuild::new(
                                    DelayedMessageOrChannelSend::Owned(peer_data),
                                    TransportType::Tcp,
                                    *relayed_addr,
                                    *peer_addr,
                                ));
                            }
                        }
                    };

                    match tcp_buffer.incoming_tcp(transmit) {
                        None => None,
                        Some(IncomingTcp::CompleteMessage(transmit, range)) => {
                            let Ok(msg) = Message::from_bytes(
                                &transmit.data.as_ref()[range.start..range.end],
                            ) else {
                                return None;
                            };
                            let msg_transmit =
                                Transmit::new(&msg, transmit.transport, transmit.from, transmit.to);
                            let mut tcp_stun_change = None;
                            let ret = self.protocol.handle_stun(
                                msg_transmit,
                                tcp_type,
                                now,
                                &mut tcp_stun_change,
                            );
                            if let Some(tcp_stun_change) = tcp_stun_change {
                                debug!("have tcp connection type change to {tcp_stun_change:?}");
                                match tcp_stun_change {
                                    TcpStunChange::Control => {
                                        *incoming_tcp =
                                            TcpBuffer::Control(core::mem::take(tcp_buffer));
                                    }
                                    TcpStunChange::Data {
                                        client_data_addr,
                                        listen_addr,
                                        relayed_addr,
                                        peer_addr,
                                    } => {
                                        *incoming_tcp = TcpBuffer::Passthrough {
                                            relayed_addr,
                                            peer_addr,
                                            pending_data: core::mem::take(tcp_buffer).into_inner(),
                                        };
                                        self.peer_tcp
                                            .entry((relayed_addr, peer_addr))
                                            .and_modify(|peer_tcp| {
                                                if let PeerTcp::PendingConnectionBind {
                                                    peer_data,
                                                    expires_at: _,
                                                } = peer_tcp
                                                {
                                                    *peer_tcp = PeerTcp::Passthrough {
                                                        client_addr: client_data_addr,
                                                        listen_addr,
                                                        pending_data: core::mem::take(peer_data),
                                                    };
                                                }
                                            })
                                            .or_insert_with(|| PeerTcp::Passthrough {
                                                client_addr: client_data_addr,
                                                listen_addr,
                                                pending_data: Vec::new(),
                                            });
                                    }
                                    TcpStunChange::Delete(allocations) => {
                                        for mut allocation in allocations {
                                            Self::remove_allocation_resources(
                                                &mut allocation,
                                                &mut self.peer_tcp,
                                                &mut self.incoming_tcp_buffers,
                                                &mut self.protocol.pending_socket_removals,
                                                &mut self.protocol.pending_socket_listen_removals,
                                                &mut self.protocol.pending_tcp_connection_binds,
                                            );
                                        }
                                    }
                                }
                            }
                            match ret {
                                Err(builder) => Some(TransmitBuild::new(
                                    DelayedMessageOrChannelSend::Owned(builder.finish()),
                                    transmit.transport,
                                    transmit.to,
                                    transmit.from,
                                )),
                                Ok(Some(InternalHandleStun::Transmit(transmit))) => {
                                    Some(TransmitBuild::new(
                                        DelayedMessageOrChannelSend::Owned(transmit.data),
                                        transmit.transport,
                                        transmit.from,
                                        transmit.to,
                                    ))
                                }
                                Ok(Some(InternalHandleStun::Data(transport, from, to, range))) => {
                                    Some(TransmitBuild::new(
                                        DelayedMessageOrChannelSend::Range(transmit.data, range),
                                        transport,
                                        from,
                                        to,
                                    ))
                                }
                                Ok(None) => None,
                            }
                        }
                        Some(IncomingTcp::CompleteChannel(transmit, range)) => {
                            let Ok(channel) =
                                ChannelData::parse(&transmit.data.as_ref()[range.start..range.end])
                            else {
                                return None;
                            };
                            let ForwardChannelData {
                                transport,
                                from,
                                to,
                            } = self.protocol.handle_channel(
                                transmit.transport,
                                transmit.from,
                                transmit.to,
                                channel,
                                now,
                            )?;
                            Some(TransmitBuild::new(
                                DelayedMessageOrChannelSend::Range(
                                    transmit.data,
                                    4 + range.start..range.end,
                                ),
                                transport,
                                from,
                                to,
                            ))
                        }
                        Some(IncomingTcp::StoredMessage(data, transmit)) => {
                            let mut tcp_stun_change = None;
                            let ret = self
                                .protocol
                                .handle_listen_tcp_stored_message(
                                    transmit.from,
                                    data,
                                    tcp_type,
                                    now,
                                    &mut tcp_stun_change,
                                )
                                .map(|transmit| {
                                    TransmitBuild::new(
                                        DelayedMessageOrChannelSend::Owned(transmit.data),
                                        transmit.transport,
                                        transmit.from,
                                        transmit.to,
                                    )
                                });
                            match tcp_stun_change {
                                Some(TcpStunChange::Control) => {
                                    *incoming_tcp = TcpBuffer::Control(core::mem::take(tcp_buffer));
                                }
                                Some(TcpStunChange::Data {
                                    client_data_addr,
                                    listen_addr,
                                    relayed_addr,
                                    peer_addr,
                                }) => {
                                    *incoming_tcp = TcpBuffer::Passthrough {
                                        relayed_addr,
                                        peer_addr,
                                        pending_data: core::mem::take(tcp_buffer).into_inner(),
                                    };
                                    self.peer_tcp
                                        .entry((relayed_addr, peer_addr))
                                        .and_modify(|peer_tcp| {
                                            if let PeerTcp::PendingConnectionBind {
                                                peer_data,
                                                expires_at: _,
                                            } = peer_tcp
                                            {
                                                *peer_tcp = PeerTcp::Passthrough {
                                                    client_addr: client_data_addr,
                                                    listen_addr,
                                                    pending_data: core::mem::take(peer_data),
                                                };
                                            }
                                        })
                                        .or_insert_with(|| PeerTcp::Passthrough {
                                            client_addr: client_data_addr,
                                            listen_addr,
                                            pending_data: Vec::new(),
                                        });
                                }
                                Some(TcpStunChange::Delete(allocations)) => {
                                    for mut allocation in allocations {
                                        Self::remove_allocation_resources(
                                            &mut allocation,
                                            &mut self.peer_tcp,
                                            &mut self.incoming_tcp_buffers,
                                            &mut self.protocol.pending_socket_removals,
                                            &mut self.protocol.pending_socket_listen_removals,
                                            &mut self.protocol.pending_tcp_connection_binds,
                                        );
                                    }
                                }
                                None => (),
                            }
                            ret
                        }
                        Some(IncomingTcp::StoredChannel(data, transmit)) => {
                            let Ok(channel) = ChannelData::parse(&data) else {
                                return None;
                            };
                            let ForwardChannelData {
                                transport,
                                from,
                                to,
                            } = self.protocol.handle_channel(
                                transmit.transport,
                                transmit.from,
                                transmit.to,
                                channel,
                                now,
                            )?;
                            Some(TransmitBuild::new(
                                DelayedMessageOrChannelSend::Owned(data[4..].to_vec()),
                                transport,
                                from,
                                to,
                            ))
                        }
                    }
                }
                TransportType::Udp => match Message::from_bytes(transmit.data.as_ref()) {
                    Ok(msg) => {
                        let msg_transmit =
                            Transmit::new(&msg, transmit.transport, transmit.from, transmit.to);
                        let mut change = None;
                        let ret = match self.protocol.handle_stun(
                            msg_transmit,
                            TcpStunType::Control,
                            now,
                            &mut change,
                        ) {
                            Err(builder) => Some(TransmitBuild::new(
                                DelayedMessageOrChannelSend::Owned(builder.finish()),
                                transmit.transport,
                                transmit.to,
                                transmit.from,
                            )),
                            Ok(Some(InternalHandleStun::Transmit(transmit))) => {
                                Some(TransmitBuild::new(
                                    DelayedMessageOrChannelSend::Owned(transmit.data),
                                    transmit.transport,
                                    transmit.from,
                                    transmit.to,
                                ))
                            }
                            Ok(Some(InternalHandleStun::Data(transport, from, to, range))) => {
                                Some(TransmitBuild::new(
                                    DelayedMessageOrChannelSend::Range(transmit.data, range),
                                    transport,
                                    from,
                                    to,
                                ))
                            }
                            Ok(None) => None,
                        };
                        if let Some(TcpStunChange::Delete(allocations)) = change {
                            for mut allocation in allocations {
                                Self::remove_allocation_resources(
                                    &mut allocation,
                                    &mut self.peer_tcp,
                                    &mut self.incoming_tcp_buffers,
                                    &mut self.protocol.pending_socket_removals,
                                    &mut self.protocol.pending_socket_listen_removals,
                                    &mut self.protocol.pending_tcp_connection_binds,
                                );
                            }
                        }
                        ret
                    }
                    Err(_) => {
                        let Ok(channel) = ChannelData::parse(transmit.data.as_ref()) else {
                            return None;
                        };
                        let ForwardChannelData {
                            transport,
                            from,
                            to,
                        } = self.protocol.handle_channel(
                            transmit.transport,
                            transmit.from,
                            transmit.to,
                            channel,
                            now,
                        )?;
                        let channel_len = channel.data().len();
                        Some(TransmitBuild::new(
                            DelayedMessageOrChannelSend::Range(transmit.data, 4..4 + channel_len),
                            transport,
                            from,
                            to,
                        ))
                    }
                },
            }
        } else {
            None
        }
    }

    #[tracing::instrument(level = "debug", name = "turn_server_poll", skip(self), ret)]
    fn poll(&mut self, now: Instant) -> TurnServerPollRet {
        let mut lowest_wait = now + Duration::from_secs(3600);
        for pending in self.protocol.pending_allocates.iter_mut() {
            if let Some(family) = pending.to_ask_families.pop() {
                return TurnServerPollRet::AllocateSocket {
                    transport: pending.client.transport,
                    listen_addr: pending.client.local_addr,
                    client_addr: pending.client.remote_addr,
                    allocation_transport: pending.allocation_transport,
                    family,
                };
            }
        }

        let mut remove_peer_connections = vec![];
        let mut remove_client_connections = vec![];
        for client in self.protocol.clients.iter_mut() {
            let mut remove_allocation_indices = vec![];
            for (alloc_idx, allocation) in client.allocations.iter_mut().enumerate() {
                let mut remove_permission = vec![];
                if allocation.expires_at < now {
                    remove_allocation_indices.push(alloc_idx);
                    // removal of allocation resources will be performed after this loop
                    continue;
                } else {
                    allocation
                        .channels
                        .retain(|channel| channel.expires_at >= now);
                    for (permission_idx, permission) in
                        allocation.permissions.iter_mut().enumerate()
                    {
                        if permission.expires_at < now {
                            remove_permission.push(permission_idx);
                        } else {
                            lowest_wait = lowest_wait.min(permission.expires_at);
                        }
                    }
                    lowest_wait = lowest_wait.min(allocation.expires_at);
                }

                let mut remove_pending_tcp = vec![];
                for (pending_idx, pending) in allocation.pending_tcp_connect.iter_mut().enumerate()
                {
                    if let Some(expires_at) = pending.expires_at {
                        if expires_at >= now {
                            remove_pending_tcp.push(pending_idx);
                            let response = pending.as_timeout_or_failure_response(&client.key);
                            self.protocol.pending_transmits.push_back(Transmit::new(
                                response.finish(),
                                TransportType::Tcp,
                                pending.listen_addr,
                                pending.client_control_addr,
                            ));
                            lowest_wait = now;
                        }
                    } else {
                        pending.expires_at = Some(now + TCP_PEER_CONNECTION_TIMEOUT);
                        return TurnServerPollRet::TcpConnect {
                            relayed_addr: allocation.addr,
                            peer_addr: pending.peer_addr,
                            listen_addr: client.local_addr,
                            client_addr: client.remote_addr,
                        };
                    }
                }
                for (idx, permission_idx) in remove_permission.into_iter().enumerate() {
                    let permission = allocation.permissions.remove(permission_idx - idx);
                    self.peer_tcp
                        .retain(|&(relayed_addr, peer_addr), peer_tcp| {
                            if peer_addr.ip() == permission.addr {
                                remove_peer_connections.push((relayed_addr, peer_addr));
                                self.protocol
                                    .pending_socket_removals
                                    .push_back(Socket5Tuple {
                                        transport: TransportType::Tcp,
                                        local_addr: relayed_addr,
                                        remote_addr: peer_addr,
                                    });
                                if let PeerTcp::Passthrough {
                                    client_addr,
                                    listen_addr,
                                    pending_data: _,
                                } = peer_tcp
                                {
                                    remove_client_connections.push((*client_addr, *listen_addr));
                                }
                                false
                            } else {
                                true
                            }
                        });
                }
                for (idx, pending_idx) in remove_pending_tcp.into_iter().enumerate() {
                    let pending = allocation.pending_tcp_connect.remove(pending_idx - idx);
                    self.incoming_tcp_buffers
                        .retain(|&(client_addr, listen_addr), _tcp_buffer| {
                            pending.client_control_addr != client_addr
                                && pending.listen_addr == listen_addr
                        });
                    self.peer_tcp.retain(|&(alloc_addr, peer_addr), _tcp| {
                        pending.relayed_addr != alloc_addr && pending.peer_addr == peer_addr
                    });
                    if pending.expires_at.is_some() {
                        self.protocol
                            .pending_socket_removals
                            .push_back(Socket5Tuple {
                                transport: TransportType::Tcp,
                                local_addr: pending.relayed_addr,
                                remote_addr: pending.peer_addr,
                            });
                    }
                }
            }

            for (idx, allocation_idx) in remove_allocation_indices.into_iter().enumerate() {
                let mut allocation = client.allocations.remove(allocation_idx - idx);
                Self::remove_allocation_resources(
                    &mut allocation,
                    &mut self.peer_tcp,
                    &mut self.incoming_tcp_buffers,
                    &mut self.protocol.pending_socket_removals,
                    &mut self.protocol.pending_socket_listen_removals,
                    &mut self.protocol.pending_tcp_connection_binds,
                )
            }
        }

        for (key, value) in self.peer_tcp.iter_mut() {
            if let PeerTcp::PendingConnectionBind {
                peer_data: _,
                expires_at,
            } = value
            {
                if *expires_at < now {
                    remove_peer_connections.push(*key);
                }
            }
        }
        Self::remove_tcp_resources(
            remove_peer_connections,
            remove_client_connections,
            &mut self.incoming_tcp_buffers,
            &mut self.protocol.pending_socket_removals,
            &mut self.protocol.pending_tcp_connection_binds,
        );

        if let Some(remove) = self.protocol.pending_socket_removals.pop_front() {
            return TurnServerPollRet::TcpClose {
                local_addr: remove.local_addr,
                remote_addr: remove.remote_addr,
            };
        }

        if let Some((transport, listen_addr)) =
            self.protocol.pending_socket_listen_removals.pop_front()
        {
            return TurnServerPollRet::SocketClose {
                transport,
                listen_addr,
            };
        }

        if let Some(earliest) = self.protocol.earliest_nonce_expiry {
            if earliest < now {
                self.protocol.nonces.retain(|nonce| nonce.expires_at >= now);
                self.protocol.recalculate_nonce_expiry(now);
            };
            if let Some(earliest) = self.protocol.earliest_nonce_expiry {
                lowest_wait = lowest_wait.min(earliest);
            }
        }

        TurnServerPollRet::WaitUntil(lowest_wait.max(now))
    }

    #[tracing::instrument(name = "turn_server_poll_transmit", skip(self))]
    fn poll_transmit(&mut self, now: Instant) -> Option<Transmit<Vec<u8>>> {
        if let Some(transmit) = self.protocol.pending_transmits.pop_back() {
            return Some(transmit);
        }
        if self.protocol.stun.transport() != TransportType::Tcp {
            return None;
        }
        let mut removed_allocations = vec![];
        for (&(remote_addr, local_addr), incoming_tcp) in self.incoming_tcp_buffers.iter_mut() {
            let (tcp_type, tcp_buffer) = match incoming_tcp {
                TcpBuffer::Unknown(tcp_buffer) => (TcpStunType::Unknown, tcp_buffer),
                TcpBuffer::Control(tcp_buffer) => (TcpStunType::Control, tcp_buffer),
                TcpBuffer::Passthrough {
                    relayed_addr,
                    peer_addr,
                    pending_data,
                } => {
                    if pending_data.is_empty() {
                        continue;
                    } else {
                        let peer_data = core::mem::take(pending_data);
                        return Some(Transmit::new(
                            peer_data,
                            TransportType::Tcp,
                            *relayed_addr,
                            *peer_addr,
                        ));
                    }
                }
            };

            let ret = match tcp_buffer.poll_recv() {
                Some(StoredTcp::Message(msg)) => {
                    let mut tcp_stun_change = None;
                    let ret = self.protocol.handle_listen_tcp_stored_message(
                        remote_addr,
                        msg,
                        tcp_type,
                        now,
                        &mut tcp_stun_change,
                    );
                    match tcp_stun_change {
                        Some(TcpStunChange::Control) => {
                            *incoming_tcp = TcpBuffer::Control(core::mem::take(tcp_buffer));
                        }
                        Some(TcpStunChange::Data {
                            client_data_addr,
                            listen_addr,
                            relayed_addr,
                            peer_addr,
                        }) => {
                            *incoming_tcp = TcpBuffer::Passthrough {
                                relayed_addr,
                                peer_addr,
                                pending_data: core::mem::take(tcp_buffer).into_inner(),
                            };
                            self.peer_tcp
                                .entry((relayed_addr, peer_addr))
                                .and_modify(|peer_tcp| {
                                    if let PeerTcp::PendingConnectionBind {
                                        peer_data,
                                        expires_at: _,
                                    } = peer_tcp
                                    {
                                        *peer_tcp = PeerTcp::Passthrough {
                                            client_addr: client_data_addr,
                                            listen_addr,
                                            pending_data: core::mem::take(peer_data),
                                        };
                                    }
                                })
                                .or_insert_with(|| PeerTcp::Passthrough {
                                    client_addr: client_data_addr,
                                    listen_addr,
                                    pending_data: Vec::new(),
                                });
                        }
                        Some(TcpStunChange::Delete(allocations)) => {
                            removed_allocations.extend(allocations);
                        }
                        None => (),
                    }
                    ret
                }
                Some(StoredTcp::Channel(channel)) => {
                    let Ok(channel) = ChannelData::parse(&channel) else {
                        continue;
                    };
                    let ForwardChannelData {
                        transport,
                        from,
                        to,
                    } = self.protocol.handle_channel(
                        TransportType::Tcp,
                        remote_addr,
                        local_addr,
                        channel,
                        now,
                    )?;
                    Some(Transmit::new(channel.data().to_vec(), transport, from, to))
                }
                None => continue,
            };
            if ret.is_some() {
                return ret;
            }
        }

        for mut allocation in removed_allocations {
            Self::remove_allocation_resources(
                &mut allocation,
                &mut self.peer_tcp,
                &mut self.incoming_tcp_buffers,
                &mut self.protocol.pending_socket_removals,
                &mut self.protocol.pending_socket_listen_removals,
                &mut self.protocol.pending_tcp_connection_binds,
            );
        }

        for ((_relayed_addr, _peer_addr), peer_tcp) in self.peer_tcp.iter_mut() {
            if let PeerTcp::Passthrough {
                client_addr,
                listen_addr,
                pending_data,
            } = peer_tcp
            {
                if !pending_data.is_empty() {
                    return Some(Transmit::new(
                        core::mem::take(pending_data),
                        TransportType::Tcp,
                        *listen_addr,
                        *client_addr,
                    ));
                }
            }
        }
        None
    }

    #[tracing::instrument(name = "turn_server_allocated_socket", skip(self))]
    fn allocated_socket(
        &mut self,
        transport: TransportType,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        allocation_transport: TransportType,
        family: AddressFamily,
        socket_addr: Result<SocketAddr, SocketAllocateError>,
        now: Instant,
    ) {
        let Some(position) = self.protocol.pending_allocates.iter().position(|pending| {
            pending.client.transport == transport
                && pending.client.local_addr == local_addr
                && pending.client.remote_addr == remote_addr
                && pending.allocation_transport == allocation_transport
                && pending.pending_families.contains(&family)
        }) else {
            warn!("No pending allocation for transport: {transport}, local: {local_addr:?}, remote {remote_addr:?}");
            return;
        };
        info!("pending allocation for transport: {transport}, local: {local_addr:?}, remote {remote_addr:?} family {family} resulted in Udp {socket_addr:?}");
        let pending = &mut self.protocol.pending_allocates[position];
        pending.pending_sockets.push((family, socket_addr));
        pending.pending_families.retain(|fam| *fam != family);
        if !pending.pending_families.is_empty() || !pending.to_ask_families.is_empty() {
            trace!(
                "Still waiting for more allocation results before sending a reply to the client"
            );
            return;
        }

        let mut pending = self.protocol.pending_allocates.remove(position).unwrap();
        let transaction_id = pending.transaction_id;
        let to = pending.client.remote_addr;
        let lifetime_seconds = pending
            .requested_lifetime
            .unwrap_or(DEFAULT_ALLOCATION_DURATION.as_secs() as u32)
            .clamp(
                DEFAULT_ALLOCATION_DURATION.as_secs() as u32,
                MAXIMUM_ALLOCATION_DURATION.as_secs() as u32,
            );

        let is_all_error = pending.pending_sockets.iter().all(|addr| addr.1.is_err());
        let n_pending_sockets = pending.pending_sockets.len();

        let mut builder = Message::builder(
            MessageType::from_class_method(
                if is_all_error {
                    MessageClass::Error
                } else {
                    MessageClass::Success
                },
                ALLOCATE,
            ),
            transaction_id,
            MessageWriteVec::with_capacity(80),
        );

        if is_all_error && pending.pending_sockets.len() > 1 {
            trace!("Returning insufficient capacity");
            // RFC8656 ADDITIONAL-ADDRESS-FAMILY path
            let error = ErrorCode::builder(ErrorCode::INSUFFICIENT_CAPACITY)
                .build()
                .unwrap();
            builder.add_attribute(&error).unwrap();
        } else {
            for (family, socket_addr) in pending.pending_sockets {
                match socket_addr {
                    Ok(addr) => {
                        pending.client.allocations.push(Allocation {
                            addr,
                            ttype: allocation_transport,
                            expires_at: now + Duration::from_secs(lifetime_seconds as u64),
                            permissions: vec![],
                            channels: vec![],
                            pending_tcp_connect: Vec::new(),
                        });
                        let relayed_address = XorRelayedAddress::new(addr, transaction_id);
                        builder.add_attribute(&relayed_address).unwrap();
                        let lifetime = Lifetime::new(lifetime_seconds);
                        builder.add_attribute(&lifetime).unwrap();
                        // TODO RESERVATION-TOKEN
                        let mapped_address =
                            XorMappedAddress::new(pending.client.remote_addr, transaction_id);
                        builder.add_attribute(&mapped_address).unwrap();
                    }
                    Err(e) => {
                        if n_pending_sockets > 1 {
                            // RFC8656 ADDITIONAL-ADDRESS-FAMILY path when at least one socket
                            // allocate succeeds
                            let error = AddressErrorCode::new(
                                family,
                                ErrorCode::builder(e.into_error_code()).build().unwrap(),
                            );
                            builder.add_attribute(&error).unwrap();
                        } else {
                            let error = ErrorCode::builder(e.into_error_code()).build().unwrap();
                            builder.add_attribute(&error).unwrap();
                        }
                    }
                }
            }
        }
        builder
            .add_message_integrity_with_key(&pending.client.key, IntegrityAlgorithm::Sha1)
            .unwrap();
        let msg = builder.finish();

        let Ok(transmit) = self.protocol.stun.send(msg, to, now) else {
            unreachable!();
        };
        if socket_addr.is_ok() {
            self.protocol.clients.push(pending.client);
        }
        self.protocol.pending_transmits.push_back(transmit);
    }

    fn tcp_connected(
        &mut self,
        relayed_addr: SocketAddr,
        peer_addr: SocketAddr,
        listen_addr: SocketAddr,
        client_addr: SocketAddr,
        socket_addr: Result<SocketAddr, TcpConnectError>,
        now: Instant,
    ) {
        let connection_id = self.protocol.tcp_connection_id;
        let Some(client) =
            self.protocol
                .mut_client_from_5tuple(TransportType::Tcp, listen_addr, client_addr)
        else {
            warn!("No client for transport: TCP, local: {listen_addr}, remote {client_addr}. Ignoring TCP connect");
            return;
        };
        let Some(allocation) = client.allocations.iter_mut().find(|allocation| {
            allocation.ttype == TransportType::Tcp
                && allocation.addr == relayed_addr
                && allocation.have_permission(peer_addr.ip(), now).is_some()
        }) else {
            warn!("No TCP allocation for TCP, relayed: {relayed_addr}, peer {peer_addr}");
            return;
        };
        let Some((position, _pending)) = allocation
            .pending_tcp_connect
            .iter_mut()
            .enumerate()
            .find(|(_idx, pending)| {
                pending.client_control_addr == client_addr
                    && pending.listen_addr == listen_addr
                    && pending.relayed_addr == relayed_addr
                    && pending.peer_addr == peer_addr
            })
        else {
            warn!("No outstanding TCP connect for relayed: {relayed_addr}, peer {peer_addr}");
            return;
        };
        let pending = allocation.pending_tcp_connect.swap_remove(position);
        if pending
            .expires_at
            .is_some_and(|expires_at| expires_at < now)
        {
            info!("Pending TCP connect has expired for relayed {relayed_addr}, peer {peer_addr}");
            return;
        }

        let mut response = match socket_addr {
            Ok(socket_addr) => match self.peer_tcp.entry((socket_addr, peer_addr)) {
                alloc::collections::btree_map::Entry::Occupied(_) => {
                    let mut response = Message::builder(
                        MessageType::from_class_method(MessageClass::Error, CONNECT),
                        pending.transaction_id,
                        MessageWriteVec::new(),
                    );
                    response
                        .add_attribute(
                            &ErrorCode::builder(ErrorCode::CONNECTION_ALREADY_EXISTS)
                                .build()
                                .unwrap(),
                        )
                        .unwrap();
                    response
                }
                alloc::collections::btree_map::Entry::Vacant(vacant) => {
                    let mut response = Message::builder(
                        MessageType::from_class_method(MessageClass::Success, CONNECT),
                        pending.transaction_id,
                        MessageWriteVec::new(),
                    );
                    response
                        .add_attribute(&ConnectionId::new(connection_id))
                        .unwrap();
                    vacant.insert(PeerTcp::PendingConnectionBind {
                        peer_data: vec![],
                        expires_at: now + TCP_PEER_CONNECTION_TIMEOUT,
                    });
                    response
                }
            },
            Err(e) => {
                let mut response = Message::builder(
                    MessageType::from_class_method(MessageClass::Error, CONNECT),
                    pending.transaction_id,
                    MessageWriteVec::new(),
                );
                response
                    .add_attribute(&ErrorCode::builder(e.into_error_code()).build().unwrap())
                    .unwrap();
                response
            }
        };
        response
            .add_message_integrity_with_key(&client.key, IntegrityAlgorithm::Sha1)
            .unwrap();
        response.add_fingerprint().unwrap();
        if socket_addr.is_ok() {
            self.protocol.tcp_connection_id += 1;
            self.protocol
                .pending_tcp_connection_binds
                .push(PendingConnectionBind {
                    connection_id,
                    listen_addr,
                    relayed_addr,
                    peer_addr,
                    client_control_addr: pending.client_control_addr,
                });
        }
        self.protocol.pending_transmits.push_front(
            self.protocol
                .stun
                .send(response.finish(), client_addr, now)
                .unwrap(),
        );
    }
}

#[derive(Debug)]
struct Client {
    transport: TransportType,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,

    allocations: Vec<Allocation>,
    username: String,
    key: IntegrityKey,
}

#[derive(Debug)]
struct Allocation {
    // the peer-side address of this allocation
    addr: SocketAddr,
    ttype: TransportType,

    expires_at: Instant,

    permissions: Vec<Permission>,
    channels: Vec<Channel>,

    pending_tcp_connect: Vec<PendingTcpConnect>,
}

/// Connecting to a Peer on behalf of a client and asking the user to perform the actual TCP socket
/// connection.
#[derive(Debug)]
struct PendingTcpConnect {
    /// CONNECT request transaction ID
    transaction_id: TransactionId,
    client_control_addr: SocketAddr,
    listen_addr: SocketAddr,
    relayed_addr: SocketAddr,
    peer_addr: SocketAddr,
    expires_at: Option<Instant>,
}

impl PendingTcpConnect {
    fn as_timeout_or_failure_response(&self, key: &IntegrityKey) -> MessageWriteVec {
        let error = ErrorCode::builder(ErrorCode::CONNECTION_TIMEOUT_OR_FAILURE)
            .build()
            .unwrap();
        let mut response = Message::builder(
            MessageType::from_class_method(MessageClass::Error, CONNECT),
            self.transaction_id,
            MessageWriteVec::with_capacity(MessageHeader::LENGTH + error.padded_len() + 24 + 8),
        );
        response
            .add_message_integrity_with_key(key, IntegrityAlgorithm::Sha1)
            .unwrap();
        response.add_fingerprint().unwrap();
        response
    }
}

impl Allocation {
    fn permission_from_5tuple(
        &self,
        ttype: TransportType,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) -> Option<&Permission> {
        if local_addr != self.addr {
            return None;
        }
        self.permissions
            .iter()
            .find(|permission| permission.ttype == ttype && remote_addr.ip() == permission.addr)
    }

    fn channel_from_id(&self, id: u16) -> Option<&Channel> {
        self.channels.iter().find(|channel| channel.id == id)
    }

    fn channel_from_5tuple(
        &self,
        transport: TransportType,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) -> Option<&Channel> {
        if self.addr != local_addr {
            return None;
        }
        self.channels
            .iter()
            .find(|channel| transport == channel.peer_transport && remote_addr == channel.peer_addr)
    }

    #[tracing::instrument(level = "trace", skip(self, now), fields(ttype = %self.ttype, relayed = %self.addr))]
    fn have_permission(&self, addr: IpAddr, now: Instant) -> Option<&Permission> {
        let Some(permission) = self
            .permissions
            .iter()
            .find(|permission| permission.addr == addr)
        else {
            trace!("no permission available");
            // no permission installed for this peer, ignoring
            return None;
        };
        if now > permission.expires_at {
            trace!("permission has expired");
            return None;
        }
        debug!("have permission");
        Some(permission)
    }
}

#[derive(Debug)]
struct Permission {
    addr: IpAddr,
    ttype: TransportType,

    expires_at: Instant,
}

#[derive(Debug)]
struct Channel {
    id: u16,
    peer_addr: SocketAddr,
    peer_transport: TransportType,

    expires_at: Instant,
}

enum InternalHandleStun {
    Transmit(Transmit<Vec<u8>>),
    Data(
        TransportType,
        SocketAddr,
        SocketAddr,
        core::ops::Range<usize>,
    ),
}

#[cfg(test)]
mod tests {
    use alloc::string::{String, ToString};
    use turn_types::{
        prelude::DelayedTransmitBuild,
        stun::message::{IntegrityAlgorithm, Method},
        TurnCredentials,
    };

    use super::*;

    fn listen_address() -> SocketAddr {
        "127.0.0.1:3478".parse().unwrap()
    }

    fn client_address() -> SocketAddr {
        "127.0.0.1:1000".parse().unwrap()
    }

    fn relayed_address() -> SocketAddr {
        "10.0.0.1:2222".parse().unwrap()
    }

    fn ipv6_relayed_address() -> SocketAddr {
        "[fda9:8765:4321:1::1]:2222".parse().unwrap()
    }

    fn peer_address() -> SocketAddr {
        "10.0.0.2:44444".parse().unwrap()
    }

    fn ipv6_peer_address() -> SocketAddr {
        "[fd12:3456:789a:1::1]:44444".parse().unwrap()
    }

    fn credentials() -> TurnCredentials {
        TurnCredentials::new("tuser", "tpass")
    }

    fn new_server(transport: TransportType) -> TurnServer {
        let mut server = TurnServer::new(transport, listen_address(), "realm".to_string());
        let credentials = credentials();
        server.add_user(
            credentials.username().to_string(),
            credentials.password().to_string(),
        );
        server
    }

    fn client_transmit_from<T: AsRef<[u8]> + core::fmt::Debug>(
        data: T,
        transport: TransportType,
        from: SocketAddr,
    ) -> Transmit<T> {
        Transmit::new(data, transport, from, listen_address())
    }

    fn client_transmit<T: AsRef<[u8]> + core::fmt::Debug>(
        data: T,
        transport: TransportType,
    ) -> Transmit<T> {
        client_transmit_from(data, transport, client_address())
    }

    #[test]
    fn test_server_stun_binding() {
        let _init = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut server = new_server(TransportType::Udp);
        let (_realm, _nonce) = initial_allocate(&mut server, now);
        let reply = server
            .recv(
                client_transmit(
                    {
                        let binding = Message::builder_request(BINDING, MessageWriteVec::new());
                        binding.finish()
                    },
                    server.transport(),
                ),
                now,
            )
            .unwrap();
        let reply = reply.build();
        let msg = Message::from_bytes(&reply.data).unwrap();
        assert!(msg.has_method(BINDING));
        assert!(msg.has_class(MessageClass::Success));
        assert_eq!(
            msg.attribute::<XorMappedAddress>()
                .unwrap()
                .addr(msg.transaction_id()),
            client_address()
        );
    }

    fn initial_allocate_msg() -> Vec<u8> {
        let allocate = Message::builder_request(ALLOCATE, MessageWriteVec::new());
        allocate.finish()
    }

    fn validate_unsigned_error_reply(msg: &[u8], method: Method, code: u16) -> Message<'_> {
        let msg = Message::from_bytes(msg).unwrap();
        assert!(msg.has_method(method));
        assert!(msg.has_class(MessageClass::Error));
        let err = msg.attribute::<ErrorCode>().unwrap();
        assert_eq!(err.code(), code);
        msg
    }

    fn validate_signed_error_reply(
        msg: &[u8],
        method: Method,
        code: u16,
        credentials: LongTermCredentials,
    ) -> Message<'_> {
        let msg = Message::from_bytes(msg).unwrap();
        assert!(msg.has_method(method));
        assert!(msg.has_class(MessageClass::Error));
        let err = msg.attribute::<ErrorCode>().unwrap();
        assert_eq!(err.code(), code);
        msg.validate_integrity(&credentials.into()).unwrap();
        msg
    }

    fn validate_initial_allocate_reply(msg: &[u8]) -> (String, String) {
        let msg = validate_unsigned_error_reply(msg, ALLOCATE, ErrorCode::UNAUTHORIZED);
        let realm = msg.attribute::<Realm>().unwrap();
        let nonce = msg.attribute::<Nonce>().unwrap();
        (realm.realm().to_string(), nonce.nonce().to_string())
    }

    #[test]
    fn test_server_initial_allocate_unauthorized_reply() {
        let _init = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut server = new_server(TransportType::Udp);
        let reply = server
            .recv(
                client_transmit(initial_allocate_msg(), server.transport()),
                now,
            )
            .unwrap();
        validate_initial_allocate_reply(&reply.build().data);
    }

    #[test]
    fn test_server_duplicate_initial_allocate_unauthorized_reply() {
        let _init = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut server = new_server(TransportType::Udp);
        let reply = server
            .recv(
                client_transmit(initial_allocate_msg(), server.transport()),
                now,
            )
            .unwrap();
        let (realm, nonce) = validate_initial_allocate_reply(&reply.build().data);
        let reply = server
            .recv(
                client_transmit(initial_allocate_msg(), server.transport()),
                now,
            )
            .unwrap();
        let (realm2, nonce2) = validate_initial_allocate_reply(&reply.build().data);
        assert_eq!(nonce, nonce2);
        assert_eq!(realm, realm2);
    }

    fn initial_allocate(server: &mut TurnServer, now: Instant) -> (String, String) {
        let reply = server
            .recv(
                client_transmit(initial_allocate_msg(), server.transport()),
                now,
            )
            .unwrap();
        validate_initial_allocate_reply(&reply.build().data)
    }

    #[test]
    fn test_server_authenticated_allocate_missing_attributes() {
        let _init = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let attributes = [
            Nonce::TYPE,
            Realm::TYPE,
            Username::TYPE,
            RequestedTransport::TYPE,
        ];
        for attr in attributes {
            let mut server = new_server(TransportType::Udp);
            let (realm, nonce) = initial_allocate(&mut server, now);
            let creds = credentials().into_long_term_credentials(&realm);
            let mut allocate = Message::builder_request(ALLOCATE, MessageWriteVec::new());
            if attr != Nonce::TYPE {
                allocate
                    .add_attribute(&Nonce::new(&nonce).unwrap())
                    .unwrap();
            }
            if attr != Realm::TYPE {
                allocate
                    .add_attribute(&Realm::new(&realm).unwrap())
                    .unwrap();
            }
            if attr != Username::TYPE {
                allocate
                    .add_attribute(&Username::new(creds.username()).unwrap())
                    .unwrap();
            }
            if attr != RequestedTransport::TYPE {
                allocate
                    .add_attribute(&RequestedTransport::new(RequestedTransport::UDP))
                    .unwrap();
            }
            allocate
                .add_message_integrity(&creds.clone().into(), IntegrityAlgorithm::Sha1)
                .unwrap();
            let reply = server
                .recv(client_transmit(allocate.finish(), server.transport()), now)
                .unwrap();
            if attr != RequestedTransport::TYPE {
                validate_unsigned_error_reply(
                    &reply.build().data,
                    ALLOCATE,
                    ErrorCode::BAD_REQUEST,
                );
            } else {
                validate_signed_error_reply(
                    &reply.build().data,
                    ALLOCATE,
                    ErrorCode::BAD_REQUEST,
                    creds,
                );
            }
        }
    }

    fn add_authenticated_request_required_attributes(
        msg: &mut MessageWriteVec,
        credentials: LongTermCredentials,
        nonce: &str,
    ) {
        msg.add_attribute(&Nonce::new(nonce).unwrap()).unwrap();
        msg.add_attribute(&Realm::new(credentials.realm()).unwrap())
            .unwrap();
        msg.add_attribute(&Username::new(credentials.username()).unwrap())
            .unwrap();
    }

    fn authenticated_allocate_msg(
        credentials: LongTermCredentials,
        nonce: &str,
        transport: u8,
        families: &[(AddressFamily, Result<SocketAddr, SocketAllocateError>)],
    ) -> Vec<u8> {
        let mut allocate = Message::builder_request(ALLOCATE, MessageWriteVec::new());
        add_authenticated_request_required_attributes(&mut allocate, credentials.clone(), nonce);
        allocate
            .add_attribute(&RequestedTransport::new(transport))
            .unwrap();
        if families.len() > 1 {
            for (family, _) in families {
                if *family != AddressFamily::IPV4 {
                    allocate
                        .add_attribute(&AdditionalAddressFamily::new(*family))
                        .unwrap();
                }
            }
        } else if families[0].0 != AddressFamily::IPV4 {
            allocate
                .add_attribute(&RequestedAddressFamily::new(families[0].0))
                .unwrap();
        }
        allocate
            .add_message_integrity(&credentials.into(), IntegrityAlgorithm::Sha1)
            .unwrap();
        allocate.finish()
    }

    fn authenticated_allocate_reply(
        server: &mut TurnServer,
        families: &[(AddressFamily, Result<SocketAddr, SocketAllocateError>)],
        now: Instant,
    ) -> Transmit<Vec<u8>> {
        for _ in 0..families.len() {
            let TurnServerPollRet::AllocateSocket {
                transport,
                listen_addr,
                client_addr,
                allocation_transport,
                family,
            } = server.poll(now)
            else {
                unreachable!();
            };
            let socket_addr = families
                .iter()
                .find_map(|(fam, socket_addr)| {
                    if *fam == family {
                        Some(*socket_addr)
                    } else {
                        None
                    }
                })
                .unwrap();
            server.allocated_socket(
                transport,
                listen_addr,
                client_addr,
                allocation_transport,
                family,
                socket_addr,
                now,
            );
        }
        server.poll_transmit(now).unwrap()
    }

    fn authenticated_allocate_with_credentials_transport_families(
        server: &mut TurnServer,
        credentials: LongTermCredentials,
        nonce: &str,
        from: SocketAddr,
        transport: u8,
        families: &[(AddressFamily, Result<SocketAddr, SocketAllocateError>)],
        now: Instant,
    ) -> Transmit<Vec<u8>> {
        let ret = server.recv(
            client_transmit_from(
                authenticated_allocate_msg(credentials.clone(), nonce, transport, families),
                server.transport(),
                from,
            ),
            now,
        );
        if let Some(transmit) = ret {
            return transmit.build();
        }
        authenticated_allocate_reply(server, families, now)
    }

    fn authenticated_allocate_with_credentials_transport(
        server: &mut TurnServer,
        credentials: LongTermCredentials,
        nonce: &str,
        transport: u8,
        now: Instant,
    ) -> Transmit<Vec<u8>> {
        authenticated_allocate_with_credentials_transport_families(
            server,
            credentials,
            nonce,
            client_address(),
            transport,
            &[(AddressFamily::IPV4, Ok(relayed_address()))],
            now,
        )
    }

    fn authenticated_allocate_with_credentials(
        server: &mut TurnServer,
        transport: TransportType,
        credentials: LongTermCredentials,
        nonce: &str,
        now: Instant,
    ) -> Transmit<Vec<u8>> {
        authenticated_allocate_with_credentials_transport(
            server,
            credentials,
            nonce,
            match transport {
                TransportType::Udp => RequestedTransport::UDP,
                TransportType::Tcp => RequestedTransport::TCP,
            },
            now,
        )
    }

    #[test]
    fn test_server_authenticated_allocate_wrong_credentials() {
        let _init = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut server = new_server(TransportType::Udp);
        let (realm, nonce) = initial_allocate(&mut server, now);
        let creds = credentials();
        let creds = TurnCredentials::new(creds.username(), "another-password")
            .into_long_term_credentials(&realm);
        let reply = authenticated_allocate_with_credentials(
            &mut server,
            TransportType::Udp,
            creds.clone(),
            &nonce,
            now,
        );
        validate_initial_allocate_reply(&reply.data);

        let mut server = new_server(TransportType::Udp);
        let (realm, nonce) = initial_allocate(&mut server, now);
        let creds = credentials();
        let creds = TurnCredentials::new("another-user", creds.password())
            .into_long_term_credentials(&realm);
        let reply = authenticated_allocate_with_credentials(
            &mut server,
            TransportType::Udp,
            creds.clone(),
            &nonce,
            now,
        );
        validate_initial_allocate_reply(&reply.data);

        let mut server = new_server(TransportType::Udp);
        let (_realm, nonce) = initial_allocate(&mut server, now);
        let creds = credentials();
        let creds = TurnCredentials::new(creds.username(), creds.password())
            .into_long_term_credentials("another-realm");
        let reply = authenticated_allocate_with_credentials(
            &mut server,
            TransportType::Udp,
            creds.clone(),
            &nonce,
            now,
        );
        validate_initial_allocate_reply(&reply.data);
    }

    #[test]
    fn test_server_authenticated_allocate_without_initial() {
        let _init = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut server = new_server(TransportType::Udp);
        let nonce = String::from("random");
        let creds = credentials();
        let creds = creds.into_long_term_credentials("realm");
        let reply = authenticated_allocate_with_credentials(
            &mut server,
            TransportType::Udp,
            creds.clone(),
            &nonce,
            now,
        );
        validate_unsigned_error_reply(&reply.data, ALLOCATE, ErrorCode::STALE_NONCE);
    }

    #[test]
    fn test_server_authenticated_allocate_wrong_transport_type() {
        let _init = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut server = new_server(TransportType::Udp);
        let (realm, nonce) = initial_allocate(&mut server, now);
        let creds = credentials().into_long_term_credentials(&realm);
        let reply = authenticated_allocate_with_credentials_transport(
            &mut server,
            creds.clone(),
            &nonce,
            0x0,
            now,
        );
        validate_signed_error_reply(
            &reply.data,
            ALLOCATE,
            ErrorCode::UNSUPPORTED_TRANSPORT_PROTOCOL,
            creds,
        );
    }

    fn validate_signed_success(
        msg: &[u8],
        method: Method,
        credentials: LongTermCredentials,
    ) -> Message<'_> {
        let msg = Message::from_bytes(msg).unwrap();
        assert!(msg.has_method(method));
        assert!(msg.has_class(MessageClass::Success));
        msg.validate_integrity(&credentials.into()).unwrap();
        msg
    }

    fn validate_authenticated_allocate_reply(
        msg: &[u8],
        credentials: LongTermCredentials,
    ) -> (Message<'_>, u32) {
        let msg = validate_signed_success(msg, ALLOCATE, credentials);
        let lifetime = msg.attribute::<Lifetime>().unwrap();
        let _xor_relayed_address = msg.attribute::<XorRelayedAddress>().unwrap();
        let _xor_mapped_address = msg.attribute::<XorMappedAddress>().unwrap();
        (msg, lifetime.seconds())
    }

    #[test]
    fn test_server_authenticated_allocate_ipv6() {
        let _init = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut server = new_server(TransportType::Udp);
        let (realm, nonce) = initial_allocate(&mut server, now);
        let creds = credentials().into_long_term_credentials(&realm);
        let reply = authenticated_allocate_with_credentials_transport_families(
            &mut server,
            creds.clone(),
            &nonce,
            client_address(),
            RequestedTransport::UDP,
            &[(AddressFamily::IPV6, Ok(ipv6_relayed_address()))],
            now,
        );
        validate_authenticated_allocate_reply(&reply.data, creds);
    }

    #[test]
    fn test_server_authenticated_allocate_ipv6_error() {
        let _init = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut server = new_server(TransportType::Udp);
        let (realm, nonce) = initial_allocate(&mut server, now);
        let creds = credentials().into_long_term_credentials(&realm);
        let reply = authenticated_allocate_with_credentials_transport_families(
            &mut server,
            creds.clone(),
            &nonce,
            client_address(),
            RequestedTransport::UDP,
            &[(
                AddressFamily::IPV6,
                Err(SocketAllocateError::AddressFamilyNotSupported),
            )],
            now,
        );
        validate_signed_error_reply(
            &reply.data,
            ALLOCATE,
            ErrorCode::ADDRESS_FAMILY_NOT_SUPPORTED,
            creds,
        );
    }

    #[test]
    fn test_server_authenticated_allocate_dual_ipv6_error() {
        let _init = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut server = new_server(TransportType::Udp);
        let (realm, nonce) = initial_allocate(&mut server, now);
        let creds = credentials().into_long_term_credentials(&realm);
        let reply = authenticated_allocate_with_credentials_transport_families(
            &mut server,
            creds.clone(),
            &nonce,
            client_address(),
            RequestedTransport::UDP,
            &[
                (
                    AddressFamily::IPV6,
                    Err(SocketAllocateError::AddressFamilyNotSupported),
                ),
                (AddressFamily::IPV4, Ok(relayed_address())),
            ],
            now,
        );
        let (msg, _lifetime) = validate_authenticated_allocate_reply(&reply.data, creds);
        let address_error_code = msg.attribute::<AddressErrorCode>().unwrap();
        assert_eq!(address_error_code.family(), AddressFamily::IPV6);
        assert_eq!(
            address_error_code.error().code(),
            ErrorCode::ADDRESS_FAMILY_NOT_SUPPORTED
        );
    }

    #[test]
    fn test_server_authenticated_allocate_dual_ipv4_error() {
        let _init = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut server = new_server(TransportType::Udp);
        let (realm, nonce) = initial_allocate(&mut server, now);
        let creds = credentials().into_long_term_credentials(&realm);
        let reply = authenticated_allocate_with_credentials_transport_families(
            &mut server,
            creds.clone(),
            &nonce,
            client_address(),
            RequestedTransport::UDP,
            &[
                (AddressFamily::IPV6, Ok(ipv6_relayed_address())),
                (
                    AddressFamily::IPV4,
                    Err(SocketAllocateError::AddressFamilyNotSupported),
                ),
            ],
            now,
        );
        let (msg, _lifetime) = validate_authenticated_allocate_reply(&reply.data, creds);
        let address_error_code = msg.attribute::<AddressErrorCode>().unwrap();
        assert_eq!(address_error_code.family(), AddressFamily::IPV4);
        assert_eq!(
            address_error_code.error().code(),
            ErrorCode::ADDRESS_FAMILY_NOT_SUPPORTED
        );
    }

    #[test]
    fn test_server_allocation_expire() {
        let _init = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut server = new_server(TransportType::Udp);
        let (realm, nonce) = initial_allocate(&mut server, now);
        let creds = credentials().into_long_term_credentials(&realm);
        let reply = authenticated_allocate_with_credentials(
            &mut server,
            TransportType::Udp,
            creds.clone(),
            &nonce,
            now,
        );
        let (_msg, lifetime) = validate_authenticated_allocate_reply(&reply.data, creds.clone());
        let TurnServerPollRet::WaitUntil(wait) = server.poll(now) else {
            unreachable!();
        };
        assert_eq!(wait, now + Duration::from_secs(lifetime as u64));
    }

    fn create_permission_request(
        credentials: LongTermCredentials,
        nonce: &str,
        peer: SocketAddr,
    ) -> Vec<u8> {
        let mut request = Message::builder_request(CREATE_PERMISSION, MessageWriteVec::new());
        request
            .add_attribute(&XorPeerAddress::new(peer, request.transaction_id()))
            .unwrap();
        add_authenticated_request_required_attributes(&mut request, credentials.clone(), nonce);
        request
            .add_message_integrity(&credentials.into(), IntegrityAlgorithm::Sha1)
            .unwrap();
        request.finish()
    }

    #[test]
    fn test_server_create_permission_without_allocation() {
        let _init = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut server = new_server(TransportType::Udp);
        let (realm, nonce) = initial_allocate(&mut server, now);
        let creds = credentials().into_long_term_credentials(&realm);
        let reply = server
            .recv(
                client_transmit(
                    create_permission_request(creds.clone(), &nonce, peer_address()),
                    server.transport(),
                ),
                now,
            )
            .unwrap();
        validate_signed_error_reply(
            &reply.build().data,
            CREATE_PERMISSION,
            ErrorCode::ALLOCATION_MISMATCH,
            creds,
        );
    }

    #[test]
    fn test_server_create_permission_without_peer_address() {
        let _init = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut server = new_server(TransportType::Udp);
        let (realm, nonce) = initial_allocate(&mut server, now);
        let creds = credentials().into_long_term_credentials(&realm);
        let reply = authenticated_allocate_with_credentials(
            &mut server,
            TransportType::Udp,
            creds.clone(),
            &nonce,
            now,
        );
        validate_authenticated_allocate_reply(&reply.data, creds.clone());
        let reply = server
            .recv(
                client_transmit(
                    {
                        let mut request =
                            Message::builder_request(CREATE_PERMISSION, MessageWriteVec::new());
                        add_authenticated_request_required_attributes(
                            &mut request,
                            creds.clone(),
                            &nonce,
                        );
                        request
                            .add_message_integrity(&creds.clone().into(), IntegrityAlgorithm::Sha1)
                            .unwrap();
                        request.finish()
                    },
                    server.transport(),
                ),
                now,
            )
            .unwrap();
        validate_signed_error_reply(
            &reply.build().data,
            CREATE_PERMISSION,
            ErrorCode::BAD_REQUEST,
            creds,
        );
    }

    #[test]
    fn test_server_create_permission_wrong_family() {
        let _init = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut server = new_server(TransportType::Udp);
        let (realm, nonce) = initial_allocate(&mut server, now);
        let creds = credentials().into_long_term_credentials(&realm);
        let reply = authenticated_allocate_with_credentials(
            &mut server,
            TransportType::Udp,
            creds.clone(),
            &nonce,
            now,
        );
        validate_authenticated_allocate_reply(&reply.data, creds.clone());
        let reply = server
            .recv(
                client_transmit(
                    create_permission_request(creds.clone(), &nonce, ipv6_peer_address()),
                    server.transport(),
                ),
                now,
            )
            .unwrap();
        validate_signed_error_reply(
            &reply.build().data,
            CREATE_PERMISSION,
            ErrorCode::PEER_ADDRESS_FAMILY_MISMATCH,
            creds,
        );
    }

    #[test]
    fn test_server_create_permission_ipv4_wrong_family() {
        let _init = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut server = new_server(TransportType::Udp);
        let (realm, nonce) = initial_allocate(&mut server, now);
        let creds = credentials().into_long_term_credentials(&realm);
        let reply = authenticated_allocate_with_credentials_transport_families(
            &mut server,
            creds.clone(),
            &nonce,
            client_address(),
            RequestedTransport::UDP,
            &[(AddressFamily::IPV6, Ok(ipv6_relayed_address()))],
            now,
        );
        validate_authenticated_allocate_reply(&reply.data, creds.clone());
        let reply = server
            .recv(
                client_transmit(
                    create_permission_request(creds.clone(), &nonce, peer_address()),
                    server.transport(),
                ),
                now,
            )
            .unwrap();
        validate_signed_error_reply(
            &reply.build().data,
            CREATE_PERMISSION,
            ErrorCode::PEER_ADDRESS_FAMILY_MISMATCH,
            creds,
        );
    }

    #[test]
    fn test_server_create_permission_wrong_username() {
        let _init = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut server = new_server(TransportType::Udp);
        let (realm, nonce) = initial_allocate(&mut server, now);
        let creds = credentials().into_long_term_credentials(&realm);
        server.add_user("another-user".to_string(), creds.password().to_string());
        let reply = authenticated_allocate_with_credentials(
            &mut server,
            TransportType::Udp,
            creds.clone(),
            &nonce,
            now,
        );
        validate_authenticated_allocate_reply(&reply.data, creds.clone());
        let creds = TurnCredentials::new("another-user", creds.password())
            .into_long_term_credentials(&realm);
        let reply = server
            .recv(
                client_transmit(
                    create_permission_request(creds, &nonce, peer_address()),
                    server.transport(),
                ),
                now,
            )
            .unwrap();
        validate_unsigned_error_reply(
            &reply.build().data,
            CREATE_PERMISSION,
            ErrorCode::WRONG_CREDENTIALS,
        );
    }

    #[test]
    fn test_server_create_permission_malformed_peer_address() {
        let _init = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut server = new_server(TransportType::Udp);
        let (realm, nonce) = initial_allocate(&mut server, now);
        let creds = credentials().into_long_term_credentials(&realm);
        let reply = authenticated_allocate_with_credentials(
            &mut server,
            TransportType::Udp,
            creds.clone(),
            &nonce,
            now,
        );
        validate_authenticated_allocate_reply(&reply.data, creds.clone());
        let reply = server
            .recv(
                client_transmit(
                    {
                        let mut request =
                            Message::builder_request(CREATE_PERMISSION, MessageWriteVec::new());
                        request
                            .add_attribute(&XorPeerAddress::new(
                                peer_address(),
                                request.transaction_id(),
                            ))
                            .unwrap();
                        // modify the XorPeerAddress to be invalid
                        request[25] = 0x80;
                        add_authenticated_request_required_attributes(
                            &mut request,
                            creds.clone(),
                            &nonce,
                        );
                        request
                            .add_message_integrity(&creds.clone().into(), IntegrityAlgorithm::Sha1)
                            .unwrap();
                        request.finish()
                    },
                    server.transport(),
                ),
                now,
            )
            .unwrap();
        validate_signed_error_reply(
            &reply.build().data,
            CREATE_PERMISSION,
            ErrorCode::BAD_REQUEST,
            creds,
        );
    }

    fn channel_bind_request(credentials: LongTermCredentials, nonce: &str) -> Vec<u8> {
        let mut request = Message::builder_request(CHANNEL_BIND, MessageWriteVec::new());
        request.add_attribute(&ChannelNumber::new(0x4000)).unwrap();
        request
            .add_attribute(&XorPeerAddress::new(
                peer_address(),
                request.transaction_id(),
            ))
            .unwrap();
        add_authenticated_request_required_attributes(&mut request, credentials.clone(), nonce);
        request
            .add_message_integrity(&credentials.into(), IntegrityAlgorithm::Sha1)
            .unwrap();
        request.finish()
    }

    #[test]
    fn test_server_channel_bind_without_allocation() {
        let _init = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut server = new_server(TransportType::Udp);
        let (realm, nonce) = initial_allocate(&mut server, now);
        let creds = credentials().into_long_term_credentials(&realm);
        let reply = server
            .recv(
                client_transmit(
                    channel_bind_request(creds.clone(), &nonce),
                    server.transport(),
                ),
                now,
            )
            .unwrap();
        validate_signed_error_reply(
            &reply.build().data,
            CHANNEL_BIND,
            ErrorCode::ALLOCATION_MISMATCH,
            creds,
        );
    }

    #[test]
    fn test_server_channel_bind_missing_attributes() {
        let _init = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut server = new_server(TransportType::Udp);
        let (realm, nonce) = initial_allocate(&mut server, now);
        let creds = credentials().into_long_term_credentials(&realm);
        let reply = authenticated_allocate_with_credentials(
            &mut server,
            TransportType::Udp,
            creds.clone(),
            &nonce,
            now,
        );
        validate_authenticated_allocate_reply(&reply.data, creds.clone());
        let reply = server
            .recv(
                client_transmit(
                    {
                        let mut request =
                            Message::builder_request(CHANNEL_BIND, MessageWriteVec::new());
                        request
                            .add_attribute(&XorPeerAddress::new(
                                peer_address(),
                                request.transaction_id(),
                            ))
                            .unwrap();
                        add_authenticated_request_required_attributes(
                            &mut request,
                            creds.clone(),
                            &nonce,
                        );
                        request
                            .add_message_integrity(&creds.clone().into(), IntegrityAlgorithm::Sha1)
                            .unwrap();
                        request.finish()
                    },
                    server.transport(),
                ),
                now,
            )
            .unwrap();
        validate_signed_error_reply(
            &reply.build().data,
            CHANNEL_BIND,
            ErrorCode::BAD_REQUEST,
            creds.clone(),
        );

        let mut server = new_server(TransportType::Udp);
        let (realm, nonce) = initial_allocate(&mut server, now);
        let creds = credentials().into_long_term_credentials(&realm);
        let reply = authenticated_allocate_with_credentials(
            &mut server,
            TransportType::Udp,
            creds.clone(),
            &nonce,
            now,
        );
        validate_authenticated_allocate_reply(&reply.data, creds.clone());
        let reply = server
            .recv(
                client_transmit(
                    {
                        let mut request =
                            Message::builder_request(CHANNEL_BIND, MessageWriteVec::new());
                        request.add_attribute(&ChannelNumber::new(0x4000)).unwrap();
                        add_authenticated_request_required_attributes(
                            &mut request,
                            creds.clone(),
                            &nonce,
                        );
                        request
                            .add_message_integrity(&creds.clone().into(), IntegrityAlgorithm::Sha1)
                            .unwrap();
                        request.finish()
                    },
                    server.transport(),
                ),
                now,
            )
            .unwrap();
        validate_signed_error_reply(
            &reply.build().data,
            CHANNEL_BIND,
            ErrorCode::BAD_REQUEST,
            creds.clone(),
        );
    }

    #[test]
    fn test_server_channel_bind_invalid_id() {
        let _init = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut server = new_server(TransportType::Udp);
        let (realm, nonce) = initial_allocate(&mut server, now);
        let creds = credentials().into_long_term_credentials(&realm);
        let reply = authenticated_allocate_with_credentials(
            &mut server,
            TransportType::Udp,
            creds.clone(),
            &nonce,
            now,
        );
        validate_authenticated_allocate_reply(&reply.data, creds.clone());
        let reply = server
            .recv(
                client_transmit(
                    {
                        let mut request =
                            Message::builder_request(CHANNEL_BIND, MessageWriteVec::new());
                        request.add_attribute(&ChannelNumber::new(0x0)).unwrap();
                        request
                            .add_attribute(&XorPeerAddress::new(
                                peer_address(),
                                request.transaction_id(),
                            ))
                            .unwrap();
                        add_authenticated_request_required_attributes(
                            &mut request,
                            creds.clone(),
                            &nonce,
                        );
                        request
                            .add_message_integrity(&creds.clone().into(), IntegrityAlgorithm::Sha1)
                            .unwrap();
                        request.finish()
                    },
                    server.transport(),
                ),
                now,
            )
            .unwrap();
        validate_signed_error_reply(
            &reply.build().data,
            CHANNEL_BIND,
            ErrorCode::BAD_REQUEST,
            creds.clone(),
        );
    }

    #[test]
    fn test_server_channel_bind_wrong_family() {
        let _init = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut server = new_server(TransportType::Udp);
        let (realm, nonce) = initial_allocate(&mut server, now);
        let creds = credentials().into_long_term_credentials(&realm);
        let reply = authenticated_allocate_with_credentials(
            &mut server,
            TransportType::Udp,
            creds.clone(),
            &nonce,
            now,
        );
        validate_authenticated_allocate_reply(&reply.data, creds.clone());
        let reply = server
            .recv(
                client_transmit(
                    {
                        let mut request =
                            Message::builder_request(CHANNEL_BIND, MessageWriteVec::new());
                        request.add_attribute(&ChannelNumber::new(0x4000)).unwrap();
                        request
                            .add_attribute(&XorPeerAddress::new(
                                ipv6_peer_address(),
                                request.transaction_id(),
                            ))
                            .unwrap();
                        add_authenticated_request_required_attributes(
                            &mut request,
                            creds.clone(),
                            &nonce,
                        );
                        request
                            .add_message_integrity(&creds.clone().into(), IntegrityAlgorithm::Sha1)
                            .unwrap();
                        request.finish()
                    },
                    server.transport(),
                ),
                now,
            )
            .unwrap();
        validate_signed_error_reply(
            &reply.build().data,
            CHANNEL_BIND,
            ErrorCode::PEER_ADDRESS_FAMILY_MISMATCH,
            creds,
        );
    }

    #[test]
    fn test_server_allocation_expire_channel_bind() {
        let _init = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut server = new_server(TransportType::Udp);
        let (realm, nonce) = initial_allocate(&mut server, now);
        let creds = credentials().into_long_term_credentials(&realm);
        let reply = authenticated_allocate_with_credentials(
            &mut server,
            TransportType::Udp,
            creds.clone(),
            &nonce,
            now,
        );
        let (_msg, lifetime) = validate_authenticated_allocate_reply(&reply.data, creds.clone());
        let now = now + Duration::from_secs(lifetime as u64 + 1);
        let reply = server
            .recv(
                client_transmit(
                    channel_bind_request(creds.clone(), &nonce),
                    server.transport(),
                ),
                now,
            )
            .unwrap();
        validate_signed_error_reply(
            &reply.build().data,
            CHANNEL_BIND,
            ErrorCode::ALLOCATION_MISMATCH,
            creds,
        );
    }

    #[test]
    fn test_server_duplicate_channel_bind() {
        let _init = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut server = new_server(TransportType::Udp);
        let (realm, nonce) = initial_allocate(&mut server, now);
        let creds = credentials().into_long_term_credentials(&realm);
        let reply = authenticated_allocate_with_credentials(
            &mut server,
            TransportType::Udp,
            creds.clone(),
            &nonce,
            now,
        );
        validate_authenticated_allocate_reply(&reply.data, creds.clone());
        channel_bind(&mut server, creds.clone(), &nonce, now);
        channel_bind(&mut server, creds.clone(), &nonce, now);
    }

    fn channel_bind(
        server: &mut TurnServer,
        creds: LongTermCredentials,
        nonce: &str,
        now: Instant,
    ) {
        let reply = server
            .recv(
                client_transmit(
                    channel_bind_request(creds.clone(), nonce),
                    server.transport(),
                ),
                now,
            )
            .unwrap();
        validate_signed_success(&reply.build().data, CHANNEL_BIND, creds.clone());
    }

    #[test]
    fn test_server_channel_bind_refresh_wrong_address() {
        let _init = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut server = new_server(TransportType::Udp);
        let (realm, nonce) = initial_allocate(&mut server, now);
        let creds = credentials().into_long_term_credentials(&realm);
        let reply = authenticated_allocate_with_credentials(
            &mut server,
            TransportType::Udp,
            creds.clone(),
            &nonce,
            now,
        );
        validate_authenticated_allocate_reply(&reply.data, creds.clone());
        channel_bind(&mut server, creds.clone(), &nonce, now);
        let reply = server
            .recv(
                client_transmit(
                    {
                        let mut request =
                            Message::builder_request(CHANNEL_BIND, MessageWriteVec::new());
                        request.add_attribute(&ChannelNumber::new(0x4100)).unwrap();
                        request
                            .add_attribute(&XorPeerAddress::new(
                                peer_address(),
                                request.transaction_id(),
                            ))
                            .unwrap();
                        add_authenticated_request_required_attributes(
                            &mut request,
                            creds.clone(),
                            &nonce,
                        );
                        request
                            .add_message_integrity(&creds.clone().into(), IntegrityAlgorithm::Sha1)
                            .unwrap();
                        request.finish()
                    },
                    server.transport(),
                ),
                now,
            )
            .unwrap();
        validate_signed_error_reply(
            &reply.build().data,
            CHANNEL_BIND,
            ErrorCode::BAD_REQUEST,
            creds,
        );
    }

    #[test]
    fn test_server_channel_bind_send_data() {
        let _init = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut server = new_server(TransportType::Udp);
        let (realm, nonce) = initial_allocate(&mut server, now);
        let creds = credentials().into_long_term_credentials(&realm);
        let reply = authenticated_allocate_with_credentials(
            &mut server,
            TransportType::Udp,
            creds.clone(),
            &nonce,
            now,
        );
        validate_authenticated_allocate_reply(&reply.data, creds.clone());
        channel_bind(&mut server, creds.clone(), &nonce, now);
        let data = [8; 9];
        let reply = server
            .recv(
                client_transmit(
                    {
                        let mut out = [0; 13];
                        ChannelData::new(0x4000, data.as_slice()).write_into_unchecked(&mut out);
                        out
                    },
                    server.transport(),
                ),
                now,
            )
            .unwrap();
        assert_eq!(reply.transport, TransportType::Udp);
        assert_eq!(reply.from, relayed_address());
        assert_eq!(reply.to, peer_address());
        assert_eq!(reply.data.build(), data);
    }

    fn refresh_request_with_lifetime(
        credentials: LongTermCredentials,
        nonce: &str,
        lifetime: u32,
        requested_address: Option<AddressFamily>,
    ) -> Vec<u8> {
        let mut request = Message::builder_request(REFRESH, MessageWriteVec::new());
        request.add_attribute(&Lifetime::new(lifetime)).unwrap();
        add_authenticated_request_required_attributes(&mut request, credentials.clone(), nonce);
        if let Some(family) = requested_address {
            request
                .add_attribute(&RequestedAddressFamily::new(family))
                .unwrap();
        }
        request
            .add_message_integrity(&credentials.into(), IntegrityAlgorithm::Sha1)
            .unwrap();
        request.finish()
    }

    fn refresh_request(
        credentials: LongTermCredentials,
        nonce: &str,
        requested_address: Option<AddressFamily>,
    ) -> Vec<u8> {
        refresh_request_with_lifetime(credentials, nonce, 1800, requested_address)
    }

    #[test]
    fn test_server_refresh_without_allocation() {
        let _init = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut server = new_server(TransportType::Udp);
        let (realm, nonce) = initial_allocate(&mut server, now);
        let creds = credentials().into_long_term_credentials(&realm);
        let reply = server
            .recv(
                client_transmit(
                    refresh_request(creds.clone(), &nonce, None),
                    server.transport(),
                ),
                now,
            )
            .unwrap();
        validate_signed_error_reply(
            &reply.build().data,
            REFRESH,
            ErrorCode::ALLOCATION_MISMATCH,
            creds,
        );
    }

    #[test]
    fn test_server_refresh_dual_allocation() {
        let _init = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut server = new_server(TransportType::Udp);
        let (realm, nonce) = initial_allocate(&mut server, now);
        let creds = credentials().into_long_term_credentials(&realm);
        authenticated_allocate_with_credentials_transport_families(
            &mut server,
            creds.clone(),
            &nonce,
            client_address(),
            RequestedTransport::UDP,
            &[
                (AddressFamily::IPV4, Ok(relayed_address())),
                (AddressFamily::IPV6, Ok(ipv6_relayed_address())),
            ],
            now,
        );
        let TurnServerPollRet::WaitUntil(now) = server.poll(now) else {
            unreachable!();
        };
        let reply = server
            .recv(
                client_transmit(
                    refresh_request(creds.clone(), &nonce, None),
                    server.transport(),
                ),
                now,
            )
            .unwrap();
        validate_signed_success(&reply.build().data, REFRESH, creds);
    }

    fn delete_request(
        credentials: LongTermCredentials,
        nonce: &str,
        requested_address: Option<AddressFamily>,
    ) -> Vec<u8> {
        refresh_request_with_lifetime(credentials, nonce, 0, requested_address)
    }

    #[test]
    fn test_server_dual_allocation_delete_single() {
        let _init = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut server = new_server(TransportType::Udp);
        let (realm, nonce) = initial_allocate(&mut server, now);
        let creds = credentials().into_long_term_credentials(&realm);
        authenticated_allocate_with_credentials_transport_families(
            &mut server,
            creds.clone(),
            &nonce,
            client_address(),
            RequestedTransport::UDP,
            &[
                (AddressFamily::IPV4, Ok(relayed_address())),
                (AddressFamily::IPV6, Ok(ipv6_relayed_address())),
            ],
            now,
        );
        let reply = server
            .recv(
                client_transmit(
                    delete_request(creds.clone(), &nonce, Some(AddressFamily::IPV4)),
                    server.transport(),
                ),
                now,
            )
            .unwrap();
        validate_signed_success(&reply.build().data, REFRESH, creds.clone());
        // duplicate delete results in error
        let reply = server
            .recv(
                client_transmit(
                    refresh_request(creds.clone(), &nonce, Some(AddressFamily::IPV4)),
                    server.transport(),
                ),
                now,
            )
            .unwrap();
        validate_signed_error_reply(
            &reply.build().data,
            REFRESH,
            ErrorCode::PEER_ADDRESS_FAMILY_MISMATCH,
            creds.clone(),
        );

        // delete the other relayed address
        let reply = server
            .recv(
                client_transmit(
                    delete_request(creds.clone(), &nonce, Some(AddressFamily::IPV6)),
                    server.transport(),
                ),
                now,
            )
            .unwrap();
        validate_signed_success(&reply.build().data, REFRESH, creds.clone());
        // duplicate delete when there are no allocation results in error
        let reply = server
            .recv(
                client_transmit(
                    refresh_request(creds.clone(), &nonce, Some(AddressFamily::IPV6)),
                    server.transport(),
                ),
                now,
            )
            .unwrap();
        validate_signed_error_reply(
            &reply.build().data,
            REFRESH,
            ErrorCode::ALLOCATION_MISMATCH,
            creds.clone(),
        );
        let reply = server
            .recv(
                client_transmit(
                    refresh_request(creds.clone(), &nonce, None),
                    server.transport(),
                ),
                now,
            )
            .unwrap();
        validate_signed_error_reply(
            &reply.build().data,
            REFRESH,
            ErrorCode::ALLOCATION_MISMATCH,
            creds,
        );
    }

    fn send_indication(peer_addr: SocketAddr, data: &[u8]) -> Vec<u8> {
        let mut msg = Message::builder(
            MessageType::from_class_method(MessageClass::Indication, SEND),
            TransactionId::generate(),
            MessageWriteVec::new(),
        );
        msg.add_attribute(&XorPeerAddress::new(peer_addr, msg.transaction_id()))
            .unwrap();
        msg.add_attribute(&AData::new(data)).unwrap();
        msg.finish()
    }

    #[test]
    fn test_server_send_without_allocation() {
        let _init = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut server = new_server(TransportType::Udp);
        assert!(server
            .recv(
                client_transmit(
                    send_indication(peer_address(), [8; 9].as_slice()),
                    server.transport()
                ),
                now,
            )
            .is_none());
    }

    #[test]
    fn test_server_send_allocation_expired() {
        let _init = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut server = new_server(TransportType::Udp);
        let (realm, nonce) = initial_allocate(&mut server, now);
        let creds = credentials().into_long_term_credentials(&realm);
        let reply = authenticated_allocate_with_credentials(
            &mut server,
            TransportType::Udp,
            creds.clone(),
            &nonce,
            now,
        );
        let (_msg, lifetime) = validate_authenticated_allocate_reply(&reply.data, creds.clone());
        let now = now + Duration::from_secs(lifetime as u64 + 1);
        assert!(server
            .recv(
                client_transmit(
                    send_indication(peer_address(), [8; 9].as_slice()),
                    server.transport()
                ),
                now,
            )
            .is_none());
    }

    #[test]
    fn test_server_send_no_allocation() {
        let _init = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut server = new_server(TransportType::Udp);
        let (realm, nonce) = initial_allocate(&mut server, now);
        let creds = credentials().into_long_term_credentials(&realm);
        let reply = authenticated_allocate_with_credentials(
            &mut server,
            TransportType::Udp,
            creds.clone(),
            &nonce,
            now,
        );
        let (_msg, lifetime) = validate_authenticated_allocate_reply(&reply.data, creds.clone());
        let now = now + Duration::from_secs(lifetime as u64 + 1);
        assert!(server
            .recv(
                client_transmit(
                    send_indication(ipv6_peer_address(), [8; 9].as_slice()),
                    server.transport()
                ),
                now,
            )
            .is_none());
    }

    #[test]
    fn test_server_send_without_permission() {
        let _init = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut server = new_server(TransportType::Udp);
        let (realm, nonce) = initial_allocate(&mut server, now);
        let creds = credentials().into_long_term_credentials(&realm);
        let reply = authenticated_allocate_with_credentials(
            &mut server,
            TransportType::Udp,
            creds.clone(),
            &nonce,
            now,
        );
        validate_authenticated_allocate_reply(&reply.data, creds.clone());
        assert!(server
            .recv(
                client_transmit(
                    send_indication(peer_address(), [8; 9].as_slice()),
                    server.transport()
                ),
                now,
            )
            .is_none());
    }

    fn create_permission_with_address(
        server: &mut TurnServer,
        creds: LongTermCredentials,
        nonce: &str,
        peer_addr: SocketAddr,
        now: Instant,
    ) {
        let reply = server
            .recv(
                client_transmit(
                    create_permission_request(creds.clone(), nonce, peer_addr),
                    server.transport(),
                ),
                now,
            )
            .unwrap();
        validate_signed_success(&reply.build().data, CREATE_PERMISSION, creds);
    }

    fn create_permission(
        server: &mut TurnServer,
        creds: LongTermCredentials,
        nonce: &str,
        now: Instant,
    ) {
        create_permission_with_address(server, creds, nonce, peer_address(), now);
    }

    #[test]
    fn test_server_send_indication_with_permission() {
        let _init = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut server = new_server(TransportType::Udp);
        let (realm, nonce) = initial_allocate(&mut server, now);
        let creds = credentials().into_long_term_credentials(&realm);
        let reply = authenticated_allocate_with_credentials(
            &mut server,
            TransportType::Udp,
            creds.clone(),
            &nonce,
            now,
        );
        validate_authenticated_allocate_reply(&reply.data, creds.clone());
        create_permission(&mut server, creds.clone(), &nonce, now);
        let data = [8; 9];
        let reply = server
            .recv(
                client_transmit(
                    send_indication(peer_address(), data.as_slice()),
                    server.transport(),
                ),
                now,
            )
            .unwrap();
        assert_eq!(reply.transport, TransportType::Udp);
        assert_eq!(reply.from, relayed_address());
        assert_eq!(reply.to, peer_address());
        assert_eq!(reply.data.build(), data);
    }

    #[test]
    fn test_server_unknown_request() {
        let _init = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut server = new_server(TransportType::Udp);
        let (realm, nonce) = initial_allocate(&mut server, now);
        let creds = credentials().into_long_term_credentials(&realm);
        let reply = authenticated_allocate_with_credentials(
            &mut server,
            TransportType::Udp,
            creds.clone(),
            &nonce,
            now,
        );
        validate_authenticated_allocate_reply(&reply.data, creds.clone());
        let reply = server
            .recv(
                client_transmit(
                    {
                        let mut request =
                            Message::builder_request(Method::new(0x123), MessageWriteVec::new());
                        add_authenticated_request_required_attributes(
                            &mut request,
                            creds.clone(),
                            &nonce,
                        );
                        request
                            .add_message_integrity(&creds.clone().into(), IntegrityAlgorithm::Sha1)
                            .unwrap();
                        request.finish()
                    },
                    server.transport(),
                ),
                now,
            )
            .unwrap();
        validate_signed_error_reply(
            &reply.build().data,
            Method::new(0x123),
            ErrorCode::BAD_REQUEST,
            creds,
        );
    }

    #[test]
    fn test_server_unknown_indication() {
        let _init = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut server = new_server(TransportType::Udp);
        let (realm, nonce) = initial_allocate(&mut server, now);
        let creds = credentials().into_long_term_credentials(&realm);
        let reply = authenticated_allocate_with_credentials(
            &mut server,
            TransportType::Udp,
            creds.clone(),
            &nonce,
            now,
        );
        validate_authenticated_allocate_reply(&reply.data, creds.clone());
        assert!(server
            .recv(
                client_transmit(
                    {
                        let request = Message::builder(
                            MessageType::from_class_method(
                                MessageClass::Indication,
                                Method::new(0x123),
                            ),
                            TransactionId::generate(),
                            MessageWriteVec::new(),
                        );
                        request.finish()
                    },
                    server.transport(),
                ),
                now,
            )
            .is_none());
    }

    #[test]
    fn test_server_unknown_source_address() {
        let _init = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut server = new_server(TransportType::Udp);
        assert!(server
            .recv(client_transmit([4; 12], server.transport()), now)
            .is_none());
    }

    #[test]
    fn test_server_invalid_client_data() {
        let _init = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut server = new_server(TransportType::Udp);
        let (realm, nonce) = initial_allocate(&mut server, now);
        let creds = credentials().into_long_term_credentials(&realm);
        let reply = authenticated_allocate_with_credentials(
            &mut server,
            TransportType::Udp,
            creds.clone(),
            &nonce,
            now,
        );
        validate_authenticated_allocate_reply(&reply.data, creds.clone());
        assert!(server
            .recv(client_transmit([4; 12], server.transport()), now)
            .is_none());
    }

    #[test]
    fn test_server_recv_no_channel() {
        let _init = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut server = new_server(TransportType::Udp);
        let (realm, nonce) = initial_allocate(&mut server, now);
        let creds = credentials().into_long_term_credentials(&realm);
        let reply = authenticated_allocate_with_credentials(
            &mut server,
            TransportType::Udp,
            creds.clone(),
            &nonce,
            now,
        );
        validate_authenticated_allocate_reply(&reply.data, creds.clone());
        assert!(server
            .recv(
                client_transmit(
                    {
                        let channel = ChannelData::new(0x4000, [7; 3].as_slice());
                        let mut out = vec![0; 7];
                        channel.write_into_unchecked(&mut out);
                        out
                    },
                    server.transport()
                ),
                now
            )
            .is_none());
    }

    #[test]
    fn test_server_recv_channel_permission_expire() {
        let _init = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut server = new_server(TransportType::Udp);
        let (realm, nonce) = initial_allocate(&mut server, now);
        let creds = credentials().into_long_term_credentials(&realm);
        let reply = authenticated_allocate_with_credentials(
            &mut server,
            TransportType::Udp,
            creds.clone(),
            &nonce,
            now,
        );
        validate_authenticated_allocate_reply(&reply.data, creds.clone());
        channel_bind(&mut server, creds.clone(), &nonce, now);
        let now = now + PERMISSION_DURATION + Duration::from_secs(1);
        assert!(server
            .recv(
                client_transmit(
                    {
                        let channel = ChannelData::new(0x4000, [7; 3].as_slice());
                        let mut out = vec![0; 7];
                        channel.write_into_unchecked(&mut out);
                        out
                    },
                    server.transport()
                ),
                now
            )
            .is_none());
    }

    #[test]
    fn test_server_peer_recv_permission_expire() {
        let _init = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut server = new_server(TransportType::Udp);
        let (realm, nonce) = initial_allocate(&mut server, now);
        let creds = credentials().into_long_term_credentials(&realm);
        let reply = authenticated_allocate_with_credentials(
            &mut server,
            TransportType::Udp,
            creds.clone(),
            &nonce,
            now,
        );
        validate_authenticated_allocate_reply(&reply.data, creds.clone());
        create_permission(&mut server, creds.clone(), &nonce, now);
        let now = now + PERMISSION_DURATION + Duration::from_secs(1);
        assert!(server
            .recv(
                Transmit::new(
                    [6; 7],
                    TransportType::Udp,
                    peer_address(),
                    relayed_address()
                ),
                now
            )
            .is_none());
    }

    fn create_udp(source: SocketAddr, destination: SocketAddr) -> Vec<u8> {
        assert_eq!(source.is_ipv4(), destination.is_ipv4());
        assert_eq!(source.is_ipv6(), destination.is_ipv6());
        let mut udp = [0; pnet_packet::udp::UdpPacket::minimum_packet_size()];
        let mut udp_packet = pnet_packet::udp::MutableUdpPacket::new(&mut udp).unwrap();
        udp_packet.populate(&pnet_packet::udp::Udp {
            source: source.port(),
            destination: destination.port(),
            length: 0x10,
            checksum: 0x0000,
            payload: vec![],
        });
        match (source, destination) {
            (SocketAddr::V4(source), SocketAddr::V4(destination)) => {
                let mut ip = [0; pnet_packet::ipv4::Ipv4Packet::minimum_packet_size()
                    + pnet_packet::udp::UdpPacket::minimum_packet_size()];
                let mut ip_packet = pnet_packet::ipv4::MutableIpv4Packet::new(&mut ip).unwrap();
                ip_packet.set_version(0x4);
                ip_packet.set_header_length(5);
                ip_packet.set_total_length(48);
                ip_packet.set_flags(pnet_packet::ipv4::Ipv4Flags::DontFragment);
                ip_packet.set_ttl(16);
                ip_packet.set_next_level_protocol(pnet_packet::ip::IpNextHeaderProtocols::Udp);
                ip_packet.set_source(source.ip().octets().into());
                ip_packet.set_destination(destination.ip().octets().into());
                ip_packet.set_payload(&udp);
                ip.to_vec()
            }
            (SocketAddr::V6(source), SocketAddr::V6(destination)) => {
                let mut ip = [0; pnet_packet::ipv6::Ipv6Packet::minimum_packet_size()
                    + pnet_packet::udp::UdpPacket::minimum_packet_size()];
                let mut ip_packet = pnet_packet::ipv6::MutableIpv6Packet::new(&mut ip).unwrap();
                ip_packet.set_version(0x6);
                ip_packet.set_payload_length(48);
                ip_packet.set_hop_limit(16);
                ip_packet.set_next_header(pnet_packet::ip::IpNextHeaderProtocols::Udp);
                ip_packet.set_source(source.ip().segments().into());
                ip_packet.set_destination(destination.ip().segments().into());
                ip_packet.set_payload(&udp);
                ip.to_vec()
            }
            _ => unreachable!(),
        }
    }

    fn create_icmpv4<'p, T: AsRef<[u8]>>(
        typ: pnet_packet::icmp::IcmpType,
        code: pnet_packet::icmp::IcmpCode,
        icmp_data: u32,
        other_packet: T,
    ) -> pnet_packet::icmp::IcmpPacket<'p> {
        let data = other_packet.as_ref();
        let ret = vec![0; data.len() + 8];
        let mut icmp = pnet_packet::icmp::MutableIcmpPacket::owned(ret).unwrap();
        icmp.set_icmp_type(typ);
        icmp.set_icmp_code(code);
        let mut payload = vec![0; 4];
        BigEndian::write_u32(&mut payload, icmp_data);
        payload.extend_from_slice(data);
        icmp.set_payload(&payload);
        icmp.consume_to_immutable()
    }

    fn create_icmpv6<'p, T: AsRef<[u8]>>(
        typ: pnet_packet::icmpv6::Icmpv6Type,
        code: pnet_packet::icmpv6::Icmpv6Code,
        icmp_data: u32,
        other_packet: T,
    ) -> pnet_packet::icmpv6::Icmpv6Packet<'p> {
        let data = other_packet.as_ref();
        let ret = vec![0; data.len() + 8];
        let mut icmp = pnet_packet::icmpv6::MutableIcmpv6Packet::owned(ret).unwrap();
        icmp.set_icmpv6_type(typ);
        icmp.set_icmpv6_code(code);
        let mut payload = vec![0; 4];
        BigEndian::write_u32(&mut payload, icmp_data);
        payload.extend_from_slice(data);
        icmp.set_payload(&payload);
        icmp.consume_to_immutable()
    }

    fn validate_icmp(msg: &[u8], peer_addr: SocketAddr, typ: u8, code: u8, data: u32) {
        let msg = Message::from_bytes(msg).unwrap();
        assert!(msg.has_method(DATA));
        let xor_peer_address = msg.attribute::<XorPeerAddress>().unwrap();
        assert_eq!(xor_peer_address.addr(msg.transaction_id()), peer_addr);
        let icmp = msg.attribute::<Icmp>().unwrap();
        assert_eq!(icmp.icmp_type(), typ);
        assert_eq!(icmp.code(), code);
        assert_eq!(icmp.data(), data);
    }

    #[test]
    fn test_server_recv_icmpv4() {
        let _init = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut server = new_server(TransportType::Udp);
        let (realm, nonce) = initial_allocate(&mut server, now);
        let creds = credentials().into_long_term_credentials(&realm);
        let reply = authenticated_allocate_with_credentials(
            &mut server,
            TransportType::Udp,
            creds.clone(),
            &nonce,
            now,
        );
        validate_authenticated_allocate_reply(&reply.data, creds.clone());
        create_permission(&mut server, creds.clone(), &nonce, now);
        // icmpv6 for ipv4 allocation is ignored
        assert!(server
            .recv_icmp(
                AddressFamily::IPV6,
                create_icmpv6(
                    pnet_packet::icmpv6::Icmpv6Types::DestinationUnreachable,
                    pnet_packet::icmpv6::Icmpv6Code::new(0),
                    0,
                    create_udp(ipv6_peer_address(), ipv6_relayed_address())
                )
                .packet(),
                now
            )
            .is_none());
        let icmp_type = pnet_packet::icmp::IcmpTypes::DestinationUnreachable;
        let icmp_code =
            pnet_packet::icmp::destination_unreachable::IcmpCodes::DestinationHostUnreachable;
        let transmit = server
            .recv_icmp(
                AddressFamily::IPV4,
                create_icmpv4(
                    icmp_type,
                    icmp_code,
                    0,
                    create_udp(relayed_address(), peer_address()),
                )
                .packet(),
                now,
            )
            .unwrap();
        assert_eq!(transmit.transport, TransportType::Udp);
        assert_eq!(transmit.from, server.listen_address());
        assert_eq!(transmit.to, client_address());
        validate_icmp(&transmit.data, peer_address(), icmp_type.0, icmp_code.0, 0);
    }

    #[test]
    fn test_server_recv_icmpv6() {
        let _init = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut server = new_server(TransportType::Udp);
        let (realm, nonce) = initial_allocate(&mut server, now);
        let creds = credentials().into_long_term_credentials(&realm);
        let reply = authenticated_allocate_with_credentials_transport_families(
            &mut server,
            creds.clone(),
            &nonce,
            client_address(),
            RequestedTransport::UDP,
            &[(AddressFamily::IPV6, Ok(ipv6_relayed_address()))],
            now,
        );
        validate_authenticated_allocate_reply(&reply.data, creds.clone());
        create_permission_with_address(
            &mut server,
            creds.clone(),
            &nonce,
            ipv6_peer_address(),
            now,
        );
        // icmpv4 for ipv6 allocation is ignored
        assert!(server
            .recv_icmp(
                AddressFamily::IPV4,
                create_icmpv4(
                    pnet_packet::icmp::IcmpTypes::DestinationUnreachable,
                    pnet_packet::icmp::IcmpCode::new(0),
                    0,
                    create_udp(peer_address(), relayed_address())
                )
                .packet(),
                now
            )
            .is_none());
        let icmp_type = pnet_packet::icmpv6::Icmpv6Types::DestinationUnreachable;
        let icmp_code = pnet_packet::icmpv6::Icmpv6Code::new(3);
        let transmit = server
            .recv_icmp(
                AddressFamily::IPV6,
                create_icmpv6(
                    icmp_type,
                    icmp_code,
                    0,
                    create_udp(ipv6_relayed_address(), ipv6_peer_address()),
                )
                .packet(),
                now,
            )
            .unwrap();
        assert_eq!(transmit.transport, TransportType::Udp);
        assert_eq!(transmit.from, server.listen_address());
        assert_eq!(transmit.to, client_address());
        validate_icmp(
            &transmit.data,
            ipv6_peer_address(),
            icmp_type.0,
            icmp_code.0,
            0,
        );
    }

    #[test]
    fn test_tcp_server_split_recv_channel() {
        let _init = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut server = new_server(TransportType::Tcp);
        let (realm, nonce) = initial_allocate(&mut server, now);
        let creds = credentials().into_long_term_credentials(&realm);
        let reply = authenticated_allocate_with_credentials(
            &mut server,
            TransportType::Udp,
            creds.clone(),
            &nonce,
            now,
        );
        validate_authenticated_allocate_reply(&reply.data, creds.clone());
        channel_bind(&mut server, creds.clone(), &nonce, now);
        let data = {
            let channel = ChannelData::new(0x4000, [7; 3].as_slice());
            let mut out = vec![0; 7];
            channel.write_into_unchecked(&mut out);
            out
        };
        for i in 1..data.len() - 1 {
            assert!(server
                .recv(client_transmit(&data[..i], server.transport()), now)
                .is_none());
            let ret = server
                .recv(client_transmit(&data[i..], server.transport()), now)
                .unwrap();
            assert_eq!(ret.transport, TransportType::Udp);
            assert_eq!(ret.from, relayed_address());
            assert_eq!(ret.to, peer_address());
            assert_eq!(&ret.data.build(), &data[4..]);
        }
    }

    #[test]
    fn test_tcp_server_split_recv_indication() {
        let _init = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut server = new_server(TransportType::Tcp);
        let (realm, nonce) = initial_allocate(&mut server, now);
        let creds = credentials().into_long_term_credentials(&realm);
        let reply = authenticated_allocate_with_credentials(
            &mut server,
            TransportType::Udp,
            creds.clone(),
            &nonce,
            now,
        );
        validate_authenticated_allocate_reply(&reply.data, creds.clone());
        create_permission(&mut server, creds.clone(), &nonce, now);
        let mut msg = Message::builder_indication(SEND, MessageWriteVec::new());
        msg.add_attribute(&XorPeerAddress::new(peer_address(), msg.transaction_id()))
            .unwrap();
        let offset = msg.len() + 4;
        msg.add_attribute(&AData::new(&[7; 3])).unwrap();
        let data = msg.clone().build();
        for i in 1..data.len() - 1 {
            assert!(server
                .recv(client_transmit(&data[..i], server.transport()), now)
                .is_none());
            let ret = server
                .recv(client_transmit(&data[i..], server.transport()), now)
                .unwrap();
            assert_eq!(ret.transport, TransportType::Udp);
            assert_eq!(ret.from, relayed_address());
            assert_eq!(ret.to, peer_address());
            assert_eq!(&ret.data.build(), &data[offset..data.len() - 1]);
        }
    }

    #[test]
    fn test_tcp_server_two_interleaved_clients() {
        let _init = crate::tests::test_init_log();
        let now = Instant::ZERO;

        let client_address2 = {
            let mut addr = client_address();
            addr.set_port(1001);
            addr
        };
        let relayed_address2 = {
            let mut addr = relayed_address();
            addr.set_port(2223);
            addr
        };
        let peer_address2 = {
            let mut addr = peer_address();
            addr.set_port(44445);
            addr
        };

        for split in [3, 9] {
            let mut server = new_server(TransportType::Tcp);

            let initial_allocate1 = initial_allocate_msg();
            let initial_allocate2 = initial_allocate_msg();
            assert!(server
                .recv(
                    client_transmit(&initial_allocate1[..split], TransportType::Tcp,),
                    now
                )
                .is_none());

            assert!(server
                .recv(
                    client_transmit_from(
                        &initial_allocate2[..split],
                        TransportType::Tcp,
                        client_address2,
                    ),
                    now
                )
                .is_none());

            let reply = server
                .recv(
                    client_transmit(&initial_allocate1[split..], TransportType::Tcp),
                    now,
                )
                .unwrap();
            let (realm, nonce) = validate_initial_allocate_reply(&reply.build().data);
            let creds = credentials().into_long_term_credentials(&realm);

            let reply = server
                .recv(
                    client_transmit_from(
                        &initial_allocate2[split..],
                        TransportType::Tcp,
                        client_address2,
                    ),
                    now,
                )
                .unwrap();
            let (realm2, nonce2) = validate_initial_allocate_reply(&reply.build().data);
            let creds2 = credentials().into_long_term_credentials(&realm2);

            let families = [(AddressFamily::IPV4, Ok(relayed_address()))];
            let auth_alloc = authenticated_allocate_msg(
                creds.clone(),
                &nonce,
                RequestedTransport::UDP,
                &families,
            );
            let families2 = [(AddressFamily::IPV4, Ok(relayed_address2))];
            let auth_alloc2 = authenticated_allocate_msg(
                creds2.clone(),
                &nonce2,
                RequestedTransport::UDP,
                &families2,
            );

            assert!(server
                .recv(
                    client_transmit(&auth_alloc[..split], TransportType::Tcp,),
                    now
                )
                .is_none());

            assert!(server
                .recv(
                    client_transmit_from(
                        &auth_alloc2[..split],
                        TransportType::Tcp,
                        client_address2,
                    ),
                    now
                )
                .is_none());

            assert!(server
                .recv(
                    client_transmit(&auth_alloc[split..], TransportType::Tcp),
                    now,
                )
                .is_none());
            let reply = authenticated_allocate_reply(&mut server, &families, now);
            validate_authenticated_allocate_reply(&reply.data, creds.clone());

            assert!(server
                .recv(
                    client_transmit_from(
                        &auth_alloc2[split..],
                        TransportType::Tcp,
                        client_address2
                    ),
                    now,
                )
                .is_none());
            let reply = authenticated_allocate_reply(&mut server, &families2, now);
            validate_authenticated_allocate_reply(&reply.data, creds2.clone());

            let perm = create_permission_request(creds.clone(), &nonce, peer_address());
            let perm2 = create_permission_request(creds.clone(), &nonce2, peer_address2);

            assert!(server
                .recv(client_transmit(&perm[..split], TransportType::Tcp,), now)
                .is_none());

            assert!(server
                .recv(
                    client_transmit_from(&perm2[..split], TransportType::Tcp, client_address2,),
                    now
                )
                .is_none());

            let reply = server
                .recv(client_transmit(&perm[split..], TransportType::Tcp), now)
                .unwrap();
            validate_signed_success(&reply.build().data, CREATE_PERMISSION, creds);

            let reply = server
                .recv(
                    client_transmit_from(&perm2[split..], TransportType::Tcp, client_address2),
                    now,
                )
                .unwrap();
            validate_signed_success(&reply.build().data, CREATE_PERMISSION, creds2);
        }
    }

    fn tcp_connect_msg(
        peer_addr: SocketAddr,
        credentials: LongTermCredentials,
        nonce: &str,
    ) -> Vec<u8> {
        let mut connect = Message::builder_request(CONNECT, MessageWriteVec::new());
        connect
            .add_attribute(&XorPeerAddress::new(peer_addr, connect.transaction_id()))
            .unwrap();
        add_authenticated_request_required_attributes(&mut connect, credentials.clone(), nonce);
        connect
            .add_message_integrity(&credentials.into(), IntegrityAlgorithm::Sha1)
            .unwrap();
        connect.add_fingerprint().unwrap();
        connect.finish()
    }

    fn tcp_connection_bind_msg(
        connection_id: u32,
        credentials: LongTermCredentials,
        nonce: &str,
    ) -> Vec<u8> {
        let mut connect = Message::builder_request(CONNECTION_BIND, MessageWriteVec::new());
        connect
            .add_attribute(&ConnectionId::new(connection_id))
            .unwrap();
        add_authenticated_request_required_attributes(&mut connect, credentials.clone(), nonce);
        connect
            .add_message_integrity(&credentials.into(), IntegrityAlgorithm::Sha1)
            .unwrap();
        connect.add_fingerprint().unwrap();
        connect.finish()
    }

    fn tcp_local_address() -> SocketAddr {
        "127.0.0.1:22222".parse().unwrap()
    }

    fn tcp_connect(
        server: &mut TurnServer,
        peer_addr: SocketAddr,
        credentials: LongTermCredentials,
        nonce: &str,
        now: Instant,
    ) -> u32 {
        let msg = tcp_connect_msg(peer_addr, credentials, nonce);
        assert!(server
            .recv(client_transmit(msg, server.transport()), now)
            .is_none());
        let TurnServerPollRet::TcpConnect {
            relayed_addr,
            peer_addr,
            listen_addr,
            client_addr,
        } = server.poll(now)
        else {
            unreachable!();
        };
        assert_eq!(relayed_addr, relayed_address());
        assert_eq!(peer_addr, peer_address());
        assert_eq!(listen_addr, server.listen_address());
        assert_eq!(client_addr, client_address());

        server.tcp_connected(
            relayed_addr,
            peer_addr,
            listen_addr,
            client_addr,
            Ok(relayed_addr),
            now,
        );

        let reply = server.poll_transmit(now).unwrap();
        assert_eq!(reply.transport, server.transport());
        assert_eq!(reply.from, server.listen_address());
        assert_eq!(reply.to, client_address());
        let reply = reply.data.build();
        let reply = Message::from_bytes(&reply).unwrap();
        assert!(reply.has_method(CONNECT));
        assert!(reply.has_class(MessageClass::Success));
        reply.attribute::<ConnectionId>().unwrap().id()
    }

    fn tcp_connection_bind_with_peer_data(
        server: &mut TurnServer,
        connection_id: u32,
        local_addr: SocketAddr,
        creds: LongTermCredentials,
        nonce: &str,
        now: Instant,
        peer_data: &[u8],
    ) {
        let mut msg = tcp_connection_bind_msg(connection_id, creds.clone(), nonce);
        msg.extend_from_slice(peer_data);
        let reply = server
            .recv(
                Transmit::new(msg, server.transport(), local_addr, server.listen_address()),
                now,
            )
            .unwrap();

        assert_eq!(reply.transport, server.transport());
        assert_eq!(reply.from, server.listen_address());
        assert_eq!(reply.to, local_addr);

        let reply = reply.data.build();
        let reply = Message::from_bytes(&reply).unwrap();
        assert!(reply.has_method(CONNECTION_BIND));
        assert!(reply.has_class(MessageClass::Success));
    }

    fn tcp_connection_bind(
        server: &mut TurnServer,
        connection_id: u32,
        local_addr: SocketAddr,
        creds: LongTermCredentials,
        nonce: &str,
        now: Instant,
    ) {
        tcp_connection_bind_with_peer_data(
            server,
            connection_id,
            local_addr,
            creds,
            nonce,
            now,
            &[],
        );
    }

    #[test]
    fn test_server_tcp_allocation_success() {
        let _init = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut server = new_server(TransportType::Tcp);
        let (realm, nonce) = initial_allocate(&mut server, now);
        let creds = credentials().into_long_term_credentials(&realm);
        let reply = authenticated_allocate_with_credentials(
            &mut server,
            TransportType::Tcp,
            creds.clone(),
            &nonce,
            now,
        );
        validate_authenticated_allocate_reply(&reply.data, creds.clone());
        create_permission(&mut server, creds.clone(), &nonce, now);

        let connection_id = tcp_connect(&mut server, peer_address(), creds.clone(), &nonce, now);

        tcp_connection_bind(
            &mut server,
            connection_id,
            tcp_local_address(),
            creds,
            &nonce,
            now,
        );

        let data = [9; 5];
        let forward = server
            .recv(
                Transmit::new(
                    data,
                    server.transport(),
                    tcp_local_address(),
                    server.listen_address(),
                ),
                now,
            )
            .unwrap();
        assert_eq!(forward.transport, TransportType::Tcp);
        assert_eq!(forward.from, relayed_address());
        assert_eq!(forward.to, peer_address());
        assert_eq!(&forward.data.build(), data.as_slice());

        let data = [12; 6];
        let forward = server
            .recv(
                Transmit::new(data, server.transport(), peer_address(), relayed_address()),
                now,
            )
            .unwrap();
        assert_eq!(forward.transport, TransportType::Tcp);
        assert_eq!(forward.from, server.listen_address());
        assert_eq!(forward.to, tcp_local_address());
        assert_eq!(&forward.data.build(), data.as_slice());
    }

    #[test]
    fn test_server_tcp_allocation_early_peer_data() {
        let _init = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut server = new_server(TransportType::Tcp);
        let (realm, nonce) = initial_allocate(&mut server, now);
        let creds = credentials().into_long_term_credentials(&realm);
        let reply = authenticated_allocate_with_credentials(
            &mut server,
            TransportType::Tcp,
            creds.clone(),
            &nonce,
            now,
        );
        validate_authenticated_allocate_reply(&reply.data, creds.clone());
        create_permission(&mut server, creds.clone(), &nonce, now);

        let connection_id = tcp_connect(&mut server, peer_address(), creds.clone(), &nonce, now);

        // early peer data
        let peer_data = [12; 6];
        assert!(server
            .recv(
                Transmit::new(
                    peer_data,
                    server.transport(),
                    peer_address(),
                    relayed_address()
                ),
                now,
            )
            .is_none());

        // client data sent directly after CONNECTION-BIND
        let data = [9; 5];
        tcp_connection_bind_with_peer_data(
            &mut server,
            connection_id,
            tcp_local_address(),
            creds,
            &nonce,
            now,
            &data,
        );

        // order of these transmits is undefined
        let forward = server.poll_transmit(now).unwrap();
        assert_eq!(forward.transport, TransportType::Tcp);
        assert_eq!(forward.from, relayed_address());
        assert_eq!(forward.to, peer_address());
        assert_eq!(&forward.data, data.as_slice());

        let forward = server.poll_transmit(now).unwrap();
        assert_eq!(forward.transport, TransportType::Tcp);
        assert_eq!(forward.from, server.listen_address());
        assert_eq!(forward.to, tcp_local_address());
        assert_eq!(&forward.data.build(), peer_data.as_slice());
    }

    #[test]
    fn test_server_tcp_incoming_peer_data() {
        let _init = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut server = new_server(TransportType::Tcp);
        let (realm, nonce) = initial_allocate(&mut server, now);
        let creds = credentials().into_long_term_credentials(&realm);
        let reply = authenticated_allocate_with_credentials(
            &mut server,
            TransportType::Tcp,
            creds.clone(),
            &nonce,
            now,
        );
        validate_authenticated_allocate_reply(&reply.data, creds.clone());
        create_permission(&mut server, creds.clone(), &nonce, now);

        let peer_data = [12; 6];
        let client_request = server
            .recv(
                Transmit::new(
                    peer_data,
                    server.transport(),
                    peer_address(),
                    relayed_address(),
                ),
                now,
            )
            .unwrap();

        assert_eq!(client_request.transport, TransportType::Tcp);
        assert_eq!(client_request.from, server.listen_address());
        assert_eq!(client_request.to, client_address());
        let data = client_request.data.build();
        let msg = Message::from_bytes(&data).unwrap();
        assert!(msg.has_method(CONNECTION_ATTEMPT));
        assert!(msg.has_class(MessageClass::Request));
        let connection_id = msg.attribute::<ConnectionId>().unwrap().id();
        let peer_addr = msg
            .attribute::<XorPeerAddress>()
            .unwrap()
            .addr(msg.transaction_id());
        assert_eq!(peer_addr, peer_address());

        tcp_connection_bind(
            &mut server,
            connection_id,
            tcp_local_address(),
            creds,
            &nonce,
            now,
        );

        let data = [9; 5];
        let forward = server
            .recv(
                Transmit::new(
                    data,
                    server.transport(),
                    tcp_local_address(),
                    server.listen_address(),
                ),
                now,
            )
            .unwrap();
        assert_eq!(forward.transport, TransportType::Tcp);
        assert_eq!(forward.from, relayed_address());
        assert_eq!(forward.to, peer_address());
        assert_eq!(&forward.data.build(), data.as_slice());

        // the peer data
        let forward = server.poll_transmit(now).unwrap();
        assert_eq!(forward.transport, TransportType::Tcp);
        assert_eq!(forward.from, server.listen_address());
        assert_eq!(forward.to, tcp_local_address());
        assert_eq!(&forward.data.build(), peer_data.as_slice());
    }
}
