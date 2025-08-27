// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! A TURN server that can handle UDP and TCP connections.

use sans_io_time::Instant;
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use rand::Rng;
use stun_proto::agent::{StunAgent, Transmit};
use stun_proto::types::attribute::{
    ErrorCode, Fingerprint, MessageIntegrity, Nonce, Realm, Username, XorMappedAddress,
};
use stun_proto::types::message::{
    LongTermCredentials, Message, MessageClass, MessageIntegrityCredentials, MessageType,
    MessageWrite, MessageWriteExt, MessageWriteVec, TransactionId, BINDING,
};
use stun_proto::types::prelude::{Attribute, AttributeFromRaw, AttributeStaticType};
use stun_proto::types::TransportType;
use turn_types::channel::ChannelData;

use turn_types::message::CREATE_PERMISSION;

use turn_types::attribute::{
    AdditionalAddressFamily, AddressErrorCode, Data as AData, EvenPort, RequestedAddressFamily,
    ReservationToken,
};
use turn_types::attribute::{
    ChannelNumber, Lifetime, RequestedTransport, XorPeerAddress, XorRelayedAddress,
};
use turn_types::message::{ALLOCATE, CHANNEL_BIND, DATA, REFRESH, SEND};
use turn_types::stun::message::IntegrityAlgorithm;
use turn_types::{AddressFamily, TurnCredentials};

use tracing::{debug, error, info, trace, warn};

use crate::api::{SocketAllocateError, TurnServerApi, TurnServerPollRet};

static MINIMUM_NONCE_EXPIRY_DURATION: Duration = Duration::from_secs(30);
static DEFAULT_NONCE_EXPIRY_DURATION: Duration = Duration::from_secs(3600);
static DEFAULT_ALLOCATION_DURATION: Duration = Duration::from_secs(1800);
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
    users: HashMap<String, String>,
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
            users: HashMap::default(),
            nonce_expiry_duration: DEFAULT_NONCE_EXPIRY_DURATION,
        }
    }

    /// The [`TransportType`] of this TURN server.
    pub fn transport(&self) -> TransportType {
        self.stun.transport()
    }

    fn generate_nonce() -> String {
        let mut rng = rand::rng();
        String::from_iter((0..16).map(|_| rng.sample(rand::distr::Alphanumeric) as char))
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
    ) -> Result<LongTermCredentials, MessageWriteVec> {
        let integrity = msg.attribute::<MessageIntegrity>().ok();
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
        let username = msg.attribute::<Username>().ok();
        let realm = msg.attribute::<Realm>().ok();
        let nonce = msg.attribute::<Nonce>().ok();
        let Some(((username, _realm), nonce)) = username.zip(realm).zip(nonce) else {
            trace!("bad request due to missing username, realm, nonce");
            return Err(Self::bad_request(msg));
        };

        let nonce_value = self.validate_nonce(ttype, from, to, now);
        if nonce_value != nonce.nonce() {
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
        let password = self.users.get(username.username());
        let credentials = TurnCredentials::new(
            username.username(),
            password.map_or("", |pass| pass.as_str()),
        )
        .into_long_term_credentials(&self.realm);
        if password.map_or(true, |_password| {
            msg.validate_integrity(&MessageIntegrityCredentials::LongTerm(credentials.clone()))
                .is_err()
        }) {
            let mut builder = Message::builder_error(msg, MessageWriteVec::new());
            let error = ErrorCode::builder(ErrorCode::UNAUTHORIZED).build().unwrap();
            builder.add_attribute(&error).unwrap();
            let realm = Realm::new(&self.realm).unwrap();
            builder.add_attribute(&realm).unwrap();
            let nonce = Nonce::new(&nonce_value).unwrap();
            builder.add_attribute(&nonce).unwrap();
            return Err(builder);
        }

        // All requests after the initial Allocate must use the same username as
        // that used to create the allocation, to prevent attackers from
        // hijacking the client's allocation.  Specifically, if the server
        // requires the use of the long-term credential mechanism, and if a non-
        // Allocate request passes authentication under this mechanism, and if
        // the 5-tuple identifies an existing allocation, but the request does
        // not use the same username as used to create the allocation, then the
        // request MUST be rejected with a 441 (Wrong Credentials) error.
        if let Some(client) = self.client_from_5tuple(ttype, to, from) {
            if client.credentials.username() != username.username() {
                let mut builder = Message::builder_error(msg, MessageWriteVec::new());
                let error = ErrorCode::builder(ErrorCode::WRONG_CREDENTIALS)
                    .build()
                    .unwrap();
                builder.add_attribute(&error).unwrap();
                builder
                    .add_message_integrity(
                        &MessageIntegrityCredentials::LongTerm(client.credentials.clone()),
                        stun_proto::types::message::IntegrityAlgorithm::Sha1,
                    )
                    .unwrap();
                return Err(builder);
            }
        }

        Ok(credentials)
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

    fn bad_request_signed(msg: &Message<'_>, credentials: LongTermCredentials) -> MessageWriteVec {
        let mut builder = Self::bad_request(msg);
        builder
            .add_message_integrity(&credentials.into(), IntegrityAlgorithm::Sha1)
            .unwrap();
        builder
    }

    fn allocation_mismatch(msg: &Message<'_>, credentials: LongTermCredentials) -> MessageWriteVec {
        let mut response = Message::builder_error(msg, MessageWriteVec::new());
        let error = ErrorCode::builder(ErrorCode::ALLOCATION_MISMATCH)
            .build()
            .unwrap();
        response.add_attribute(&error).unwrap();
        response
            .add_message_integrity(&credentials.into(), IntegrityAlgorithm::Sha1)
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
        let credentials = self.validate_stun(msg, ttype, from, to, now)?;
        let mut address_families = smallvec::SmallVec::<[AddressFamily; 2]>::new();

        if let Some(_client) = self.mut_client_from_5tuple(ttype, to, from) {
            return Err(Self::allocation_mismatch(msg, credentials));
        };

        let Ok(requested_transport) = msg.attribute::<RequestedTransport>() else {
            debug!("no RequestedTransport -> Bad Request");
            return Err(Self::bad_request_signed(msg, credentials));
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
                .add_message_integrity(
                    &MessageIntegrityCredentials::LongTerm(credentials),
                    stun_proto::types::message::IntegrityAlgorithm::Sha1,
                )
                .unwrap();
            return Err(builder);
        }

        let reservation_token = msg.attribute::<ReservationToken>();
        let even_port = msg.attribute::<EvenPort>();
        let requested_address_family = msg.attribute::<RequestedAddressFamily>();
        let additional_address_family = msg.attribute::<AdditionalAddressFamily>();

        if let Ok(additional) = additional_address_family {
            /* The server checks if the request contains both
             * REQUESTED-ADDRESS-FAMILY and ADDITIONAL-ADDRESS-FAMILY attributes. If yes,
             * then the server rejects the request with a 400 (Bad Request) error.
             */
            /* The server checks if the request contains an ADDITIONAL-ADDRESS-FAMILY
             * attribute. If yes, and the attribute value is 0x01 (IPv4 address family),
             * then the server rejects the request with a 400 (Bad Request) error.
             */
            if requested_address_family.is_ok()
                || additional.family() == AddressFamily::IPV4
                || reservation_token.is_ok()
                || even_port.is_ok()
            {
                debug!(
                    "AdditionalAddressFamily with either {} == IPV4, ReservationToken {}, RequestedAddressFamily {}, or EvenPort {}. Bad Request",
                    additional.family(),
                    reservation_token.is_ok(),
                    requested_address_family.is_ok(),
                    even_port.is_ok(),
                );
                return Err(Self::bad_request_signed(msg, credentials));
            }
            address_families.push(AddressFamily::IPV4);
            address_families.push(additional.family());
        }

        if let Ok(requested) = requested_address_family {
            if reservation_token.is_ok() {
                debug!("RequestedAddressFamily with ReservationToken -> Bad Request");
                return Err(Self::bad_request_signed(msg, credentials));
            }
            address_families.push(requested.family());
        } else if address_families.is_empty() {
            address_families.push(AddressFamily::IPV4);
        }

        if let Ok(_reservation_token) = msg.attribute::<ReservationToken>() {
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
            if even_port.is_ok() {
                debug!("ReservationToken with EvenPort -> Bad Request");
                return Err(Self::bad_request_signed(msg, credentials));
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
            credentials,
        };
        debug!("have new pending ALLOCATE from client {ttype} from {from} to {to}");

        self.pending_allocates.push_front(PendingClient {
            client,
            transaction_id: msg.transaction_id(),
            to_ask_families: address_families.clone(),
            pending_families: address_families,
            pending_sockets: Default::default(),
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
        let credentials = self.validate_stun(msg, ttype, from, to, now)?;

        let Some(client) = self.mut_client_from_5tuple(ttype, to, from) else {
            return Err(Self::allocation_mismatch(msg, credentials));
        };

        let requested_family = msg
            .attribute::<RequestedAddressFamily>()
            .ok()
            .map(|requested| requested.family());

        // TODO: proper lifetime handling
        let request_lifetime = msg
            .attribute::<Lifetime>()
            .map(|lt| lt.seconds())
            .unwrap_or(600);
        let mut modified = false;
        let credentials = if request_lifetime == 0 {
            let credentials = client.credentials.clone();
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
            credentials
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
            client.credentials.clone()
        };

        let mut builder = if modified {
            let mut builder = Message::builder_success(msg, MessageWriteVec::new());
            let lifetime = Lifetime::new(request_lifetime);
            builder.add_attribute(&lifetime).unwrap();
            builder
        } else {
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
            .add_message_integrity(
                &MessageIntegrityCredentials::LongTerm(credentials),
                stun_proto::types::message::IntegrityAlgorithm::Sha1,
            )
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
        let credentials = self.validate_stun(msg, ttype, from, to, now)?;

        let Some(client) = self.mut_client_from_5tuple(ttype, to, from) else {
            return Err(Self::allocation_mismatch(msg, credentials));
        };

        let mut peer_addresses = vec![];
        let mut at_least_one_peer_addr = false;
        for (_offset, peer_addr) in msg
            .iter_attributes()
            .filter(|(_offset, a)| a.get_type() == XorPeerAddress::TYPE)
        {
            let Ok(peer_addr) = XorPeerAddress::from_raw(peer_addr) else {
                return Err(Self::bad_request_signed(msg, client.credentials.clone()));
            };
            at_least_one_peer_addr = true;
            let peer_addr = peer_addr.addr(msg.transaction_id());

            let Some(alloc) = client
                .allocations
                .iter_mut()
                .find(|a| a.addr.is_ipv4() == peer_addr.is_ipv4())
            else {
                let mut response = Message::builder_error(msg, MessageWriteVec::new());
                response
                    .add_attribute(
                        &ErrorCode::builder(ErrorCode::PEER_ADDRESS_FAMILY_MISMATCH)
                            .build()
                            .unwrap(),
                    )
                    .unwrap();
                response
                    .add_message_integrity(&credentials.into(), IntegrityAlgorithm::Sha1)
                    .unwrap();
                response.add_fingerprint().unwrap();
                return Err(response);
            };

            if now > alloc.expires_at {
                trace!("allocation has expired");
                // allocation has expired
                return Err(Self::allocation_mismatch(msg, credentials));
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
            peer_addresses.push(peer_addr.ip());
        }

        if !at_least_one_peer_addr {
            return Err(Self::bad_request_signed(msg, client.credentials.clone()));
        }

        let mut builder = Message::builder_success(msg, MessageWriteVec::new());
        builder
            .add_message_integrity(
                &MessageIntegrityCredentials::LongTerm(credentials),
                stun_proto::types::message::IntegrityAlgorithm::Sha1,
            )
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
        let credentials = self.validate_stun(msg, ttype, from, to, now)?;

        let Some(client) = self.mut_client_from_5tuple(ttype, to, from) else {
            return Err(Self::allocation_mismatch(msg, credentials));
        };

        let peer_addr = msg
            .attribute::<XorPeerAddress>()
            .ok()
            .map(|peer_addr| peer_addr.addr(msg.transaction_id()));
        let Some(peer_addr) = peer_addr else {
            trace!("No peer address");
            return Err(Self::bad_request_signed(msg, credentials));
        };

        let Some(alloc) = client
            .allocations
            .iter_mut()
            .find(|allocation| allocation.addr.is_ipv4() == peer_addr.is_ipv4())
        else {
            let mut response = Message::builder_error(msg, MessageWriteVec::new());
            response
                .add_attribute(
                    &ErrorCode::builder(ErrorCode::PEER_ADDRESS_FAMILY_MISMATCH)
                        .build()
                        .unwrap(),
                )
                .unwrap();
            response
                .add_message_integrity(&credentials.into(), IntegrityAlgorithm::Sha1)
                .unwrap();
            response.add_fingerprint().unwrap();
            return Err(response);
        };

        if now > alloc.expires_at {
            trace!("allocation has expired");
            // allocation has expired
            return Err(Self::allocation_mismatch(msg, credentials));
        }

        let mut existing = alloc.channels.iter_mut().find(|channel| {
            channel.peer_addr == peer_addr && channel.peer_transport == TransportType::Udp
        });

        let channel_no = msg
            .attribute::<ChannelNumber>()
            .ok()
            .map(|channel| channel.channel());
        let Some(channel_no) = channel_no else {
            debug!("Bad request: no requested channel id");
            return Err(Self::bad_request_signed(msg, credentials));
        };

        if !(0x4000..=0x7fff).contains(&channel_no) {
            trace!("Channel id out of range");
            return Err(Self::bad_request_signed(msg, credentials));
        }
        if existing
            .as_ref()
            .is_some_and(|existing| existing.id != channel_no)
        {
            trace!("channel peer address does not match channel ID");
            return Err(Self::bad_request_signed(msg, credentials));
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
            .add_message_integrity(
                &MessageIntegrityCredentials::LongTerm(credentials),
                stun_proto::types::message::IntegrityAlgorithm::Sha1,
            )
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
    ) -> Result<Transmit<Vec<u8>>, ()> {
        let peer_address = msg.attribute::<XorPeerAddress>().map_err(|_| ())?;
        let peer_address = peer_address.addr(msg.transaction_id());

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

        let Some(permission) = alloc.have_permission(peer_address.ip(), now) else {
            return Err(());
        };

        let data = msg.attribute::<AData>().map_err(|_| ())?;
        trace!("have {} to send to {:?}", data.data().len(), peer_address);
        Ok(Transmit::new(
            data.data().to_vec(),
            permission.ttype,
            alloc.addr,
            peer_address,
        ))
        // XXX: copies the data.  Try to figure out a way to not do this
        /*
        self.pending_transmits.push_back(Transmit::new_owned(
            data.data(),
            permission.ttype,
            alloc.addr,
            peer_address,
        ));
        Ok(())*/
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
    ) -> Result<Option<Transmit<Vec<u8>>>, MessageWriteVec> {
        trace!("received STUN message {msg}");
        let ret = if msg.has_class(stun_proto::types::message::MessageClass::Request) {
            match msg.method() {
                BINDING => self
                    .handle_stun_binding(msg, ttype, from, to, now)
                    .map(Some),
                ALLOCATE => self
                    .handle_stun_allocate(msg, ttype, from, to, now)
                    .map(|_| None),
                REFRESH => self
                    .handle_stun_refresh(msg, ttype, from, to, now)
                    .map(Some),
                CREATE_PERMISSION => self
                    .handle_stun_create_permission(msg, ttype, from, to, now)
                    .map(Some),
                CHANNEL_BIND => self
                    .handle_stun_channel_bind(msg, ttype, from, to, now)
                    .map(Some),
                _ => {
                    let credentials = self.validate_stun(msg, ttype, from, to, now)?;
                    let Some(_client) = self.mut_client_from_5tuple(ttype, to, from) else {
                        return Err(Self::allocation_mismatch(msg, credentials));
                    };

                    Err(Self::bad_request_signed(msg, credentials))
                }
            }
        } else if msg.has_class(stun_proto::types::message::MessageClass::Indication) {
            match msg.method() {
                SEND => Ok(self
                    .handle_stun_send_indication(msg, ttype, from, to, now)
                    .ok()),
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
    ) -> Option<(&Client, &Allocation)> {
        self.clients.iter().find_map(|client| {
            client
                .allocations
                .iter()
                .find(|allocation| {
                    allocation.ttype == ttype
                        && allocation.addr == local_addr
                        && allocation
                            .permissions
                            .iter()
                            .any(|permission| permission.addr == remote_addr.ip())
                })
                .map(|allocation| (client, allocation))
        })
    }
}

impl TurnServerApi for TurnServer {
    fn add_user(&mut self, username: String, password: String) {
        self.users.insert(username, password);
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
        skip(self, transmit, now),
        fields(
            transport = %transmit.transport,
            remote_addr = %transmit.from,
            local_addr = %transmit.to,
            data_len = transmit.data.as_ref().len(),
        )
    )]
    fn recv<T: AsRef<[u8]>>(
        &mut self,
        transmit: Transmit<T>,
        now: Instant,
    ) -> Option<Transmit<Vec<u8>>> {
        trace!("executing at {now:?}");
        if let Some((client, allocation)) =
            self.allocation_from_public_5tuple(transmit.transport, transmit.to, transmit.from)
        {
            // A packet from the relayed address needs to be sent to the client that set up
            // the allocation.

            // SAFETY: permission existence is checked by `allocation_from_public_5tuple()`
            let permission = allocation
                .permission_from_5tuple(transmit.transport, transmit.to, transmit.from)
                .unwrap();
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
                let mut data = vec![0; 4];
                data[0..2].copy_from_slice(&existing.id.to_be_bytes());
                data[2..4].copy_from_slice(&(transmit.data.as_ref().len() as u16).to_be_bytes());
                // XXX: try to avoid copy?
                data.extend_from_slice(transmit.data.as_ref());
                Some(Transmit::new(
                    data.into_boxed_slice().into(),
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
                let transaction_id = TransactionId::generate();
                let mut builder = Message::builder(
                    MessageType::from_class_method(MessageClass::Indication, DATA),
                    transaction_id,
                    MessageWriteVec::new(),
                );
                let peer_address = XorPeerAddress::new(transmit.from, transaction_id);
                builder.add_attribute(&peer_address).unwrap();
                let data = AData::new(transmit.data.as_ref());
                builder.add_attribute(&data).unwrap();
                // XXX: try to avoid copy?
                let msg_data = builder.finish();

                Some(Transmit::new(
                    msg_data.into_boxed_slice().into(),
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
                        Err(builder) => Some(Transmit::new(
                            builder.finish(),
                            transmit.transport,
                            transmit.to,
                            transmit.from,
                        )),
                        Ok(transmit) => transmit,
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
                    let Ok(channel) = ChannelData::parse(transmit.data.as_ref()) else {
                        return None;
                    };
                    trace!(
                        "parsed channel data with id {} and data length {}",
                        channel.id(),
                        channel.data().len()
                    );
                    let Some((allocation, existing)) =
                        client.allocations.iter().find_map(|allocation| {
                            allocation
                                .channel_from_id(channel.id())
                                .map(|perm| (allocation, perm))
                        })
                    else {
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
                    Some(Transmit::new(
                        channel.data().to_vec(),
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
                            expires_at: now + DEFAULT_ALLOCATION_DURATION,
                            permissions: vec![],
                            channels: vec![],
                        });
                        let relayed_address = XorRelayedAddress::new(addr, transaction_id);
                        builder.add_attribute(&relayed_address).unwrap();
                        let lifetime = Lifetime::new(1800);
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
            .add_message_integrity(
                &MessageIntegrityCredentials::LongTerm(pending.client.credentials.clone()),
                stun_proto::types::message::IntegrityAlgorithm::Sha1,
            )
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
    credentials: LongTermCredentials,
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

#[cfg(test)]
mod tests {
    use turn_types::stun::message::{IntegrityAlgorithm, Method};

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

    fn client_transmit<T: AsRef<[u8]> + std::fmt::Debug>(
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
        validate_initial_allocate_reply(&reply.data);
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
        let (realm, nonce) = validate_initial_allocate_reply(&reply.data);
        let reply = server
            .recv(
                client_transmit(initial_allocate_msg(), server.transport()),
                now,
            )
            .unwrap();
        let (realm2, nonce2) = validate_initial_allocate_reply(&reply.data);
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
        validate_initial_allocate_reply(&reply.data)
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
                validate_unsigned_error_reply(&reply.data, ALLOCATE, ErrorCode::BAD_REQUEST);
            } else {
                validate_signed_error_reply(&reply.data, ALLOCATE, ErrorCode::BAD_REQUEST, creds);
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
            return transmit;
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
            &reply.data,
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
            &reply.data,
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
            &reply.data,
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
            &reply.data,
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
        validate_unsigned_error_reply(&reply.data, CREATE_PERMISSION, ErrorCode::WRONG_CREDENTIALS);
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
            &reply.data,
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
            &reply.data,
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
            &reply.data,
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
            &reply.data,
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
            &reply.data,
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
            &reply.data,
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
            &reply.data,
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
        validate_signed_success(&reply.data, CHANNEL_BIND, creds.clone());
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
        validate_signed_error_reply(&reply.data, CHANNEL_BIND, ErrorCode::BAD_REQUEST, creds);
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
        validate_signed_error_reply(&reply.data, REFRESH, ErrorCode::ALLOCATION_MISMATCH, creds);
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
        validate_signed_success(&reply.data, REFRESH, creds);
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
        validate_signed_success(&reply.data, REFRESH, creds.clone());
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
            &reply.data,
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
        validate_signed_success(&reply.data, REFRESH, creds.clone());
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
            &reply.data,
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
        validate_signed_error_reply(&reply.data, REFRESH, ErrorCode::ALLOCATION_MISMATCH, creds);
    }

    fn send_indication(peer_addr: SocketAddr) -> Vec<u8> {
        let mut msg = Message::builder(
            MessageType::from_class_method(MessageClass::Indication, SEND),
            TransactionId::generate(),
            MessageWriteVec::new(),
        );
        msg.add_attribute(&XorPeerAddress::new(peer_addr, msg.transaction_id()))
            .unwrap();
        msg.add_attribute(&AData::new([8; 9].as_slice())).unwrap();
        msg.finish()
    }

    #[test]
    fn test_server_send_without_allocation() {
        let _init = crate::tests::test_init_log();
        let now = Instant::ZERO;
        let mut server = new_server(TransportType::Udp);
        assert!(server
            .recv(
                client_transmit(send_indication(peer_address()), server.transport()),
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
                client_transmit(send_indication(peer_address()), server.transport()),
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
                client_transmit(send_indication(ipv6_peer_address()), server.transport()),
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
                client_transmit(send_indication(peer_address()), server.transport()),
                now,
            )
            .is_none());
    }

    fn create_permission(
        server: &mut TurnServer,
        creds: LongTermCredentials,
        nonce: &str,
        now: Instant,
    ) {
        let reply = server
            .recv(
                client_transmit(
                    create_permission_request(creds.clone(), nonce, peer_address()),
                    server.transport(),
                ),
                now,
            )
            .unwrap();
        validate_signed_success(&reply.data, CREATE_PERMISSION, creds);
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
        let reply = server
            .recv(
                client_transmit(send_indication(peer_address()), server.transport()),
                now,
            )
            .unwrap();
        assert_eq!(reply.transport, TransportType::Udp);
        assert_eq!(reply.from, relayed_address());
        assert_eq!(reply.to, peer_address());
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
            &reply.data,
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
}
