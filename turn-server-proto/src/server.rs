// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

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

use turn_types::message::CREATE_PERMISSION;

use turn_types::attribute::{
    AdditionalAddressFamily, AddressErrorCode, Data as AData, EvenPort, Icmp,
    RequestedAddressFamily, ReservationToken,
};
use turn_types::attribute::{
    ChannelNumber, Lifetime, RequestedTransport, XorPeerAddress, XorRelayedAddress,
};
use turn_types::message::{ALLOCATE, CHANNEL_BIND, DATA, REFRESH, SEND};
use turn_types::stun::message::{IntegrityAlgorithm, IntegrityKey};
use turn_types::AddressFamily;

use tracing::{debug, error, info, trace, warn};

use crate::api::{
    DelayedMessageOrChannelSend, SocketAllocateError, TurnServerApi, TurnServerPollRet,
};

static MINIMUM_NONCE_EXPIRY_DURATION: Duration = Duration::from_secs(30);
static DEFAULT_NONCE_EXPIRY_DURATION: Duration = Duration::from_secs(3600);
static MAXIMUM_ALLOCATION_DURATION: Duration = Duration::from_secs(3600);
static DEFAULT_ALLOCATION_DURATION: Duration = Duration::from_secs(600);
static PERMISSION_DURATION: Duration = Duration::from_secs(300);
static CHANNEL_DURATION: Duration = Duration::from_secs(600);

/// A TURN server.
#[derive(Debug)]
pub struct TurnServer {
    realm: String,
    stun: StunAgent,

    clients: Vec<Client>,
    nonces: Vec<NonceData>,
    pending_transmits: VecDeque<Transmit<Vec<u8>>>,
    pending_allocates: VecDeque<PendingClient>,

    // username -> password mapping.
    users: BTreeMap<String, IntegrityKey>,
    nonce_expiry_duration: Duration,
}

#[derive(Debug)]
struct PendingClient {
    client: Client,
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
            realm,
            stun,
            clients: vec![],
            nonces: vec![],
            pending_transmits: VecDeque::default(),
            pending_allocates: VecDeque::default(),
            users: BTreeMap::default(),
            nonce_expiry_duration: DEFAULT_NONCE_EXPIRY_DURATION,
        }
    }

    /// The [`TransportType`] of this TURN server.
    pub fn transport(&self) -> TransportType {
        self.stun.transport()
    }

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
            }
            nonce_data.nonce.clone()
        } else {
            let nonce_value = Self::generate_nonce();
            self.nonces.push(NonceData {
                transport: ttype,
                remote_addr: from,
                local_addr: to,
                nonce: nonce_value.clone(),
                expires_at: now + self.nonce_expiry_duration,
            });
            nonce_value
        }
    }

    fn validate_stun(
        &mut self,
        msg: &Message<'_>,
        ttype: TransportType,
        from: SocketAddr,
        to: SocketAddr,
        now: Instant,
    ) -> Result<&IntegrityKey, MessageWriteVec> {
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
            let nonce_value = self.validate_nonce(ttype, from, to, now);
            trace!("no message-integrity, returning unauthorized with nonce: {nonce_value}",);
            let mut builder = Message::builder_error(msg, MessageWriteVec::new());
            let nonce = Nonce::new(&nonce_value).unwrap();
            builder.add_attribute(&nonce).unwrap();
            let realm = Realm::new(&self.realm).unwrap();
            builder.add_attribute(&realm).unwrap();
            let error = ErrorCode::builder(ErrorCode::UNAUTHORIZED).build().unwrap();
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
            return Err(Self::bad_request(msg));
        };

        let nonce_value = self.validate_nonce(ttype, from, to, now);
        if nonce_value != nonce.nonce() {
            trace!("stale nonce");
            let mut builder = Message::builder_error(msg, MessageWriteVec::new());
            let error = ErrorCode::builder(ErrorCode::STALE_NONCE).build().unwrap();
            builder.add_attribute(&error).unwrap();
            let realm = Realm::new(&self.realm).unwrap();
            builder.add_attribute(&realm).unwrap();
            let nonce = Nonce::new(&nonce_value).unwrap();
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
            let mut builder = Message::builder_error(msg, MessageWriteVec::new());
            let error = ErrorCode::builder(ErrorCode::UNAUTHORIZED).build().unwrap();
            builder.add_attribute(&error).unwrap();
            let realm = Realm::new(&self.realm).unwrap();
            builder.add_attribute(&realm).unwrap();
            let nonce = Nonce::new(&nonce_value).unwrap();
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
        if let Some(client) = self.client_from_5tuple(ttype, to, from) {
            if client.username != username.username() {
                trace!("mismatched username");
                let mut builder = Message::builder_error(msg, MessageWriteVec::new());
                let error = ErrorCode::builder(ErrorCode::WRONG_CREDENTIALS)
                    .build()
                    .unwrap();
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
        let mut response = Message::builder_error(msg, MessageWriteVec::new());
        let error = ErrorCode::builder(ErrorCode::SERVER_ERROR).build().unwrap();
        response.add_attribute(&error).unwrap();
        response.add_fingerprint().unwrap();
        response
    }

    fn bad_request(msg: &Message<'_>) -> MessageWriteVec {
        let mut builder = Message::builder_error(msg, MessageWriteVec::new());
        let error = ErrorCode::builder(ErrorCode::BAD_REQUEST).build().unwrap();
        builder.add_attribute(&error).unwrap();
        builder
    }

    fn bad_request_signed(msg: &Message<'_>, key: &IntegrityKey) -> MessageWriteVec {
        let mut builder = Self::bad_request(msg);
        builder
            .add_message_integrity_with_key(key, IntegrityAlgorithm::Sha1)
            .unwrap();
        builder
    }

    fn allocation_mismatch(msg: &Message<'_>, key: &IntegrityKey) -> MessageWriteVec {
        let mut response = Message::builder_error(msg, MessageWriteVec::new());
        let error = ErrorCode::builder(ErrorCode::ALLOCATION_MISMATCH)
            .build()
            .unwrap();
        response.add_attribute(&error).unwrap();
        response
            .add_message_integrity_with_key(key, IntegrityAlgorithm::Sha1)
            .unwrap();
        response.add_fingerprint().unwrap();
        response
    }

    fn handle_stun_binding(
        &mut self,
        msg: &Message<'_>,
        _ttype: TransportType,
        from: SocketAddr,
        to: SocketAddr,
        now: Instant,
    ) -> Result<Transmit<Vec<u8>>, MessageWriteVec> {
        let response = if let Some(error_msg) =
            Message::check_attribute_types(msg, &[Fingerprint::TYPE], &[], MessageWriteVec::new())
        {
            error_msg
        } else {
            let mut response = Message::builder_success(msg, MessageWriteVec::new());
            let xor_addr = XorMappedAddress::new(from, msg.transaction_id());
            response.add_attribute(&xor_addr).unwrap();
            response.add_fingerprint().unwrap();
            response
        };
        let response = response.finish();

        let Ok(transmit) = self.stun.send(response, to, now) else {
            error!("Failed to send");
            return Err(Self::server_error(msg));
        };

        Ok(transmit)
    }

    fn handle_stun_allocate(
        &mut self,
        msg: &Message<'_>,
        ttype: TransportType,
        from: SocketAddr,
        to: SocketAddr,
        now: Instant,
    ) -> Result<(), MessageWriteVec> {
        let key = self.validate_stun(msg, ttype, from, to, now)?.clone();
        let mut address_families = smallvec::SmallVec::<[AddressFamily; 2]>::new();

        if let Some(_client) = self.mut_client_from_5tuple(ttype, to, from) {
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
                atype => {
                    if atype.comprehension_required() {
                        unknown_attributes.push(atype);
                    }
                }
            }
        }
        if !unknown_attributes.is_empty() {
            trace!("unknown attributes: {unknown_attributes:?}");
            let mut err =
                Message::unknown_attributes(msg, &unknown_attributes, MessageWriteVec::new());
            err.add_message_integrity_with_key(&key, IntegrityAlgorithm::Sha1)
                .unwrap();
            return Err(err);
        }

        let Some(requested_transport) = requested_transport else {
            return Err(Self::bad_request_signed(msg, &key));
        };

        if requested_transport.protocol() != RequestedTransport::UDP {
            debug!(
                "unsupported RequestedTransport {}",
                requested_transport.protocol()
            );
            let mut builder = Message::builder_error(msg, MessageWriteVec::new());
            let error = ErrorCode::builder(ErrorCode::UNSUPPORTED_TRANSPORT_PROTOCOL)
                .build()
                .unwrap();
            builder.add_attribute(&error).unwrap();
            builder
                .add_message_integrity_with_key(&key, IntegrityAlgorithm::Sha1)
                .unwrap();
            return Err(builder);
        }

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
            transport: ttype,
            remote_addr: from,
            local_addr: to,
            allocations: vec![],
            username: username.unwrap(),
            key,
        };
        debug!("have new pending ALLOCATE from client {ttype} from {from} to {to}");

        self.pending_allocates.push_front(PendingClient {
            client,
            transaction_id: msg.transaction_id(),
            to_ask_families: address_families.clone(),
            pending_families: address_families,
            pending_sockets: Default::default(),
            requested_lifetime: lifetime.map(|lt| lt.seconds()),
        });

        Ok(())
    }

    fn handle_stun_refresh(
        &mut self,
        msg: &Message<'_>,
        ttype: TransportType,
        from: SocketAddr,
        to: SocketAddr,
        now: Instant,
    ) -> Result<Transmit<Vec<u8>>, MessageWriteVec> {
        let key = self.validate_stun(msg, ttype, from, to, now)?.clone();

        let Some(client) = self.mut_client_from_5tuple(ttype, to, from) else {
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
            let mut err =
                Message::unknown_attributes(msg, &unknown_attributes, MessageWriteVec::new());
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
            if let Some(family) = requested_family {
                client.allocations.retain(|allocation| {
                    if (family == AddressFamily::IPV4 && allocation.addr.is_ipv4())
                        || (family == AddressFamily::IPV6 && allocation.addr.is_ipv6())
                    {
                        modified = true;
                        false
                    } else {
                        true
                    }
                });
                if client.allocations.is_empty() {
                    self.remove_client_by_5tuple(ttype, to, from);
                }
            } else {
                self.remove_client_by_5tuple(ttype, to, from);
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

        let mut builder = if modified {
            let mut builder = Message::builder_success(msg, MessageWriteVec::new());
            let lifetime = Lifetime::new(request_lifetime);
            builder.add_attribute(&lifetime).unwrap();
            builder
        } else {
            trace!("peer address family mismatch");
            let mut builder = Message::builder_error(msg, MessageWriteVec::new());
            builder
                .add_attribute(
                    &ErrorCode::builder(ErrorCode::PEER_ADDRESS_FAMILY_MISMATCH)
                        .build()
                        .unwrap(),
                )
                .unwrap();
            builder
        };
        builder
            .add_message_integrity_with_key(&key, IntegrityAlgorithm::Sha1)
            .unwrap();
        let response = builder.finish();
        let Ok(transmit) = self.stun.send(response, from, now) else {
            error!("Failed to send");
            return Err(Self::server_error(msg));
        };

        info!("Successfully refreshed allocation {ttype}, from {from} to {to}");

        Ok(transmit)
    }

    fn handle_stun_create_permission(
        &mut self,
        msg: &Message<'_>,
        ttype: TransportType,
        from: SocketAddr,
        to: SocketAddr,
        now: Instant,
    ) -> Result<Transmit<Vec<u8>>, MessageWriteVec> {
        let key = self.validate_stun(msg, ttype, from, to, now)?.clone();

        let Some(client) = self.mut_client_from_5tuple(ttype, to, from) else {
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
            let mut err =
                Message::unknown_attributes(msg, &unknown_attributes, MessageWriteVec::new());
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
                let mut response = Message::builder_error(msg, MessageWriteVec::new());
                response
                    .add_attribute(
                        &ErrorCode::builder(ErrorCode::PEER_ADDRESS_FAMILY_MISMATCH)
                            .build()
                            .unwrap(),
                    )
                    .unwrap();
                response
                    .add_message_integrity_with_key(&key, IntegrityAlgorithm::Sha1)
                    .unwrap();
                response.add_fingerprint().unwrap();
                return Err(response);
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

        let mut builder = Message::builder_success(msg, MessageWriteVec::new());
        builder
            .add_message_integrity_with_key(&key, IntegrityAlgorithm::Sha1)
            .unwrap();
        let response = builder.finish();

        let Ok(transmit) = self.stun.send(response, from, now) else {
            error!("Failed to send");
            return Err(Self::server_error(msg));
        };
        debug!(
            "allocation {ttype} from {from} to {to} successfully created permission for {:?}",
            peer_addresses
        );

        Ok(transmit)
    }

    fn handle_stun_channel_bind(
        &mut self,
        msg: &Message<'_>,
        ttype: TransportType,
        from: SocketAddr,
        to: SocketAddr,
        now: Instant,
    ) -> Result<Transmit<Vec<u8>>, MessageWriteVec> {
        let key = self.validate_stun(msg, ttype, from, to, now)?.clone();

        let Some(client) = self.mut_client_from_5tuple(ttype, to, from) else {
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
            let mut err =
                Message::unknown_attributes(msg, &unknown_attributes, MessageWriteVec::new());
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
            let mut response = Message::builder_error(msg, MessageWriteVec::new());
            response
                .add_attribute(
                    &ErrorCode::builder(ErrorCode::PEER_ADDRESS_FAMILY_MISMATCH)
                        .build()
                        .unwrap(),
                )
                .unwrap();
            response
                .add_message_integrity_with_key(&key, IntegrityAlgorithm::Sha1)
                .unwrap();
            response.add_fingerprint().unwrap();
            return Err(response);
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

        let mut builder = Message::builder_success(msg, MessageWriteVec::new());
        builder
            .add_message_integrity_with_key(&key, IntegrityAlgorithm::Sha1)
            .unwrap();
        let response = builder.finish();

        let Ok(transmit) = self.stun.send(response, from, now) else {
            error!("Failed to send");
            return Err(Self::server_error(msg));
        };

        debug!("allocation {ttype} from {from} to {to} successfully created channel {channel_no} for {:?}", peer_addr.ip());

        Ok(transmit)
    }

    fn handle_stun_send_indication<'a>(
        &mut self,
        msg: &'a Message<'a>,
        ttype: TransportType,
        from: SocketAddr,
        to: SocketAddr,
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

        let Some(client) = self.client_from_5tuple(ttype, to, from) else {
            trace!("no client for transport {ttype:?} from {from:?}, to {to:?}");
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
        skip(self, msg, ttype, from, to, now),
        fields(
            msg.transaction = %msg.transaction_id(),
            msg.method = %msg.method(),
        )
    )]
    fn handle_stun<'a>(
        &mut self,
        msg: &'a Message<'a>,
        ttype: TransportType,
        from: SocketAddr,
        to: SocketAddr,
        now: Instant,
    ) -> Result<Option<InternalHandleStun>, MessageWriteVec> {
        trace!("received STUN message {msg}");
        let ret = if msg.has_class(stun_proto::types::message::MessageClass::Request) {
            match msg.method() {
                BINDING => self
                    .handle_stun_binding(msg, ttype, from, to, now)
                    .map(|t| Some(InternalHandleStun::Transmit(t))),
                ALLOCATE => self
                    .handle_stun_allocate(msg, ttype, from, to, now)
                    .map(|_| None),
                REFRESH => self
                    .handle_stun_refresh(msg, ttype, from, to, now)
                    .map(|t| Some(InternalHandleStun::Transmit(t))),
                CREATE_PERMISSION => self
                    .handle_stun_create_permission(msg, ttype, from, to, now)
                    .map(|t| Some(InternalHandleStun::Transmit(t))),
                CHANNEL_BIND => self
                    .handle_stun_channel_bind(msg, ttype, from, to, now)
                    .map(|t| Some(InternalHandleStun::Transmit(t))),
                _ => {
                    let key = self.validate_stun(msg, ttype, from, to, now)?.clone();
                    let Some(_client) = self.mut_client_from_5tuple(ttype, to, from) else {
                        return Err(Self::allocation_mismatch(msg, &key));
                    };

                    Err(Self::bad_request_signed(msg, &key))
                }
            }
        } else if msg.has_class(stun_proto::types::message::MessageClass::Indication) {
            match msg.method() {
                SEND => Ok(self
                    .handle_stun_send_indication(msg, ttype, from, to, now)
                    .ok()
                    .map(|(transport, from, to, range)| {
                        InternalHandleStun::Data(transport, from, to, range)
                    })),
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
    ) {
        info!("attempting to remove client {ttype}, {remote_addr} -> {local_addr}");
        self.clients.retain(|client| {
            client.transport != ttype
                && client.remote_addr != remote_addr
                && client.local_addr == local_addr
        })
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
}

impl TurnServerApi for TurnServer {
    fn add_user(&mut self, username: String, password: String) {
        let key = MessageIntegrityCredentials::LongTerm(LongTermCredentials::new(
            username.to_owned(),
            password.to_owned(),
            self.realm.clone(),
        ))
        .make_key();
        self.users.insert(username, key);
    }

    fn listen_address(&self) -> SocketAddr {
        self.stun.local_addr()
    }

    fn set_nonce_expiry_duration(&mut self, expiry_duration: Duration) {
        if expiry_duration < MINIMUM_NONCE_EXPIRY_DURATION {
            panic!("Attempted to set a nonce expiry duration ({expiry_duration:?}) of less than the allowed minimum ({MINIMUM_NONCE_EXPIRY_DURATION:?})");
        }
        self.nonce_expiry_duration = expiry_duration;
    }

    #[tracing::instrument(
        name = "turn_server_recv",
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
            self.allocation_from_public_5tuple(TransportType::Udp, source, destination)?;
        if allocation.expires_at < now || permission.expires_at < now {
            return None;
        }

        info!(
            "sending ICMP (type:{icmp_type}, code:{icmp_code}, data{icmp_data}) DATA indication to client {}",
            client.remote_addr
        );
        let mut msg = Message::builder(
            MessageType::from_class_method(MessageClass::Indication, DATA),
            TransactionId::generate(),
            MessageWriteVec::new(),
        );
        msg.add_attribute(&XorPeerAddress::new(destination, msg.transaction_id()))
            .unwrap();
        msg.add_attribute(&Icmp::new(icmp_type, icmp_code, icmp_data))
            .unwrap();
        self.stun.send(msg.finish(), client.remote_addr, now).ok()
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
        if let Some((client, allocation, permission)) =
            self.allocation_from_public_5tuple(transmit.transport, transmit.to, transmit.from)
        {
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
        } else {
            // TODO: TCP buffering requirements
            match Message::from_bytes(transmit.data.as_ref()) {
                Ok(msg) => {
                    match self.handle_stun(
                        &msg,
                        transmit.transport,
                        transmit.from,
                        transmit.to,
                        now,
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
                    }
                }
                Err(_) => {
                    let Some(client) =
                        self.client_from_5tuple(transmit.transport, transmit.to, transmit.from)
                    else {
                        trace!(
                            "No handler for {} bytes over {:?} from {:?}, to {:?}. Ignoring",
                            transmit.data.as_ref().len(),
                            transmit.transport,
                            transmit.from,
                            transmit.to
                        );
                        return None;
                    };
                    trace!(
                        "received {} bytes from {:?}",
                        transmit.data.as_ref().len(),
                        transmit.from
                    );
                    let data = transmit.data.as_ref();
                    let Ok((channel_id, channel_len)) = ChannelData::parse_header(data) else {
                        return None;
                    };
                    if data.len() < 4 + channel_len {
                        // message too short
                        return None;
                    }
                    trace!(
                        "parsed channel data with id {channel_id} and data length {channel_len}",
                    );
                    let Some((allocation, existing)) =
                        client.allocations.iter().find_map(|allocation| {
                            allocation
                                .channel_from_id(channel_id)
                                .map(|perm| (allocation, perm))
                        })
                    else {
                        warn!(
                            "no channel id {channel_id} for this client {:?}",
                            client.remote_addr
                        );
                        // no channel with that id
                        return None;
                    };
                    if existing.expires_at < now {
                        trace!(
                            "channel for {} expired {:?} ago",
                            transmit.from,
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
                            "permission for {} expired {:?} ago",
                            transmit.from,
                            now - permission.expires_at
                        );
                        return None;
                    }
                    Some(TransmitBuild::new(
                        DelayedMessageOrChannelSend::Range(transmit.data, 4..4 + channel_len),
                        allocation.ttype,
                        allocation.addr,
                        existing.peer_addr,
                    ))
                }
            }
        }
    }

    #[tracing::instrument(level = "debug", name = "turn_server_poll", skip(self), ret)]
    fn poll(&mut self, now: Instant) -> TurnServerPollRet {
        for pending in self.pending_allocates.iter_mut() {
            if let Some(family) = pending.to_ask_families.pop() {
                // TODO: TCP
                return TurnServerPollRet::AllocateSocketUdp {
                    transport: pending.client.transport,
                    local_addr: pending.client.local_addr,
                    remote_addr: pending.client.remote_addr,
                    family,
                };
            }
        }

        for client in self.clients.iter_mut() {
            client.allocations.retain_mut(|allocation| {
                if allocation.expires_at >= now {
                    allocation
                        .permissions
                        .retain_mut(|permission| permission.expires_at >= now);
                    allocation
                        .channels
                        .retain_mut(|channel| channel.expires_at >= now);
                    true
                } else {
                    false
                }
            });
        }

        TurnServerPollRet::WaitUntil(now + Duration::from_secs(60))
    }

    #[tracing::instrument(name = "turn_server_poll_transmit", skip(self))]
    fn poll_transmit(&mut self, now: Instant) -> Option<Transmit<Vec<u8>>> {
        if let Some(transmit) = self.pending_transmits.pop_back() {
            return Some(transmit);
        }
        None
    }

    #[tracing::instrument(name = "turn_server_allocated_udp_socket", skip(self))]
    fn allocated_udp_socket(
        &mut self,
        transport: TransportType,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        family: AddressFamily,
        socket_addr: Result<SocketAddr, SocketAllocateError>,
        now: Instant,
    ) {
        let Some(position) = self.pending_allocates.iter().position(|pending| {
            pending.client.transport == transport
                && pending.client.local_addr == local_addr
                && pending.client.remote_addr == remote_addr
                && pending.pending_families.contains(&family)
        }) else {
            warn!("No pending allocation for transport: Udp, local: {local_addr:?}, remote {remote_addr:?}");
            return;
        };
        info!("pending allocation for transport: Udp, local: {local_addr:?}, remote {remote_addr:?} family {family} resulted in {socket_addr:?}");
        let pending = &mut self.pending_allocates[position];
        pending.pending_sockets.push((family, socket_addr));
        pending.pending_families.retain(|fam| *fam != family);
        if !pending.pending_families.is_empty() || !pending.to_ask_families.is_empty() {
            trace!(
                "Still waiting for more allocation results before sending a reply to the client"
            );
            return;
        }

        let mut pending = self.pending_allocates.remove(position).unwrap();
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
            MessageWriteVec::new(),
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
                            ttype: TransportType::Udp,
                            expires_at: now + Duration::from_secs(lifetime_seconds as u64),
                            permissions: vec![],
                            channels: vec![],
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

        let Ok(transmit) = self.stun.send(msg, to, now) else {
            unreachable!();
        };
        if socket_addr.is_ok() {
            self.clients.push(pending.client);
        }
        self.pending_transmits.push_back(transmit);
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

    fn client_transmit<T: AsRef<[u8]> + core::fmt::Debug>(
        data: T,
        transport: TransportType,
    ) -> Transmit<T> {
        Transmit::new(data, transport, client_address(), listen_address())
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

    fn authenticated_allocate_with_credentials_transport_families(
        server: &mut TurnServer,
        credentials: LongTermCredentials,
        nonce: &str,
        transport: u8,
        families: &[(AddressFamily, Result<SocketAddr, SocketAllocateError>)],
        now: Instant,
    ) -> Transmit<Vec<u8>> {
        let ret = server.recv(
            client_transmit(
                {
                    let mut allocate = Message::builder_request(ALLOCATE, MessageWriteVec::new());
                    add_authenticated_request_required_attributes(
                        &mut allocate,
                        credentials.clone(),
                        nonce,
                    );
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
                },
                server.transport(),
            ),
            now,
        );
        if let Some(transmit) = ret {
            return transmit.build();
        }
        for _ in 0..families.len() {
            let TurnServerPollRet::AllocateSocketUdp {
                transport,
                local_addr,
                remote_addr,
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
            server.allocated_udp_socket(
                transport,
                local_addr,
                remote_addr,
                family,
                socket_addr,
                now,
            );
        }
        server.poll_transmit(now).unwrap()
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
            transport,
            &[(AddressFamily::IPV4, Ok(relayed_address()))],
            now,
        )
    }

    fn authenticated_allocate_with_credentials(
        server: &mut TurnServer,
        credentials: LongTermCredentials,
        nonce: &str,
        now: Instant,
    ) -> Transmit<Vec<u8>> {
        authenticated_allocate_with_credentials_transport(
            server,
            credentials,
            nonce,
            RequestedTransport::UDP,
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
        let reply =
            authenticated_allocate_with_credentials(&mut server, creds.clone(), &nonce, now);
        validate_initial_allocate_reply(&reply.data);

        let mut server = new_server(TransportType::Udp);
        let (realm, nonce) = initial_allocate(&mut server, now);
        let creds = credentials();
        let creds = TurnCredentials::new("another-user", creds.password())
            .into_long_term_credentials(&realm);
        let reply =
            authenticated_allocate_with_credentials(&mut server, creds.clone(), &nonce, now);
        validate_initial_allocate_reply(&reply.data);

        let mut server = new_server(TransportType::Udp);
        let (_realm, nonce) = initial_allocate(&mut server, now);
        let creds = credentials();
        let creds = TurnCredentials::new(creds.username(), creds.password())
            .into_long_term_credentials("another-realm");
        let reply =
            authenticated_allocate_with_credentials(&mut server, creds.clone(), &nonce, now);
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
        let reply =
            authenticated_allocate_with_credentials(&mut server, creds.clone(), &nonce, now);
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
        let reply =
            authenticated_allocate_with_credentials(&mut server, creds.clone(), &nonce, now);
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
        let reply =
            authenticated_allocate_with_credentials(&mut server, creds.clone(), &nonce, now);
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
        let reply =
            authenticated_allocate_with_credentials(&mut server, creds.clone(), &nonce, now);
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
        let reply =
            authenticated_allocate_with_credentials(&mut server, creds.clone(), &nonce, now);
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
        let reply =
            authenticated_allocate_with_credentials(&mut server, creds.clone(), &nonce, now);
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
        let reply =
            authenticated_allocate_with_credentials(&mut server, creds.clone(), &nonce, now);
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
        let reply =
            authenticated_allocate_with_credentials(&mut server, creds.clone(), &nonce, now);
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
        let reply =
            authenticated_allocate_with_credentials(&mut server, creds.clone(), &nonce, now);
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
        let reply =
            authenticated_allocate_with_credentials(&mut server, creds.clone(), &nonce, now);
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
        let reply =
            authenticated_allocate_with_credentials(&mut server, creds.clone(), &nonce, now);
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
        let reply =
            authenticated_allocate_with_credentials(&mut server, creds.clone(), &nonce, now);
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
        let reply =
            authenticated_allocate_with_credentials(&mut server, creds.clone(), &nonce, now);
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
        let reply =
            authenticated_allocate_with_credentials(&mut server, creds.clone(), &nonce, now);
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
        let reply =
            authenticated_allocate_with_credentials(&mut server, creds.clone(), &nonce, now);
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
        let reply =
            authenticated_allocate_with_credentials(&mut server, creds.clone(), &nonce, now);
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
        let reply =
            authenticated_allocate_with_credentials(&mut server, creds.clone(), &nonce, now);
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
        let reply =
            authenticated_allocate_with_credentials(&mut server, creds.clone(), &nonce, now);
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
        let reply =
            authenticated_allocate_with_credentials(&mut server, creds.clone(), &nonce, now);
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
        let reply =
            authenticated_allocate_with_credentials(&mut server, creds.clone(), &nonce, now);
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
        let reply =
            authenticated_allocate_with_credentials(&mut server, creds.clone(), &nonce, now);
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
        let reply =
            authenticated_allocate_with_credentials(&mut server, creds.clone(), &nonce, now);
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
        let reply =
            authenticated_allocate_with_credentials(&mut server, creds.clone(), &nonce, now);
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
        let reply =
            authenticated_allocate_with_credentials(&mut server, creds.clone(), &nonce, now);
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
}
