// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use stun_proto::agent::{StunAgent, StunError, Transmit, TransmitBuild};
use stun_proto::prelude::*;
use stun_proto::types::attribute::{
    ErrorCode, Fingerprint, MessageIntegrity, Nonce, Realm, Username, XorMappedAddress,
};
use stun_proto::types::data::Data;
use stun_proto::types::message::{
    LongTermCredentials, Message, MessageBuilder, MessageClass, MessageIntegrityCredentials,
    MessageType, TransactionId, BINDING,
};
use stun_proto::types::prelude::{Attribute, AttributeFromRaw, AttributeStaticType};
use stun_proto::types::TransportType;
use turn_types::channel::ChannelData;

use turn_types::message::CREATE_PERMISSION;

use turn_types::attribute::Data as AData;
use turn_types::attribute::{
    ChannelNumber, Lifetime, RequestedTransport, XorPeerAddress, XorRelayedAddress,
};
use turn_types::message::{ALLOCATE, CHANNEL_BIND, DATA, REFRESH, SEND};
use turn_types::TurnCredentials;

use tracing::{debug, error, info, trace, warn};

/// A TURN server.
#[derive(Debug)]
pub struct TurnServer {
    realm: String,
    // FIXME: remove
    stun: StunAgent,

    clients: Vec<Client>,
    nonces: Vec<NonceData>,
    pending_transmits: VecDeque<Transmit<Data<'static>>>,
    pending_allocates: VecDeque<PendingClient>,

    // username -> password mapping.
    users: HashMap<String, String>,
}

#[derive(Debug)]
struct PendingClient {
    client: Client,
    asked: bool,
    transaction_id: TransactionId,
}

#[derive(Debug)]
struct NonceData {
    nonce: String,
    expires_at: Instant,

    transport: TransportType,
    remote_addr: SocketAddr,
    local_addr: SocketAddr,
}

/// Return value for [poll](TurnServer::poll).
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
    },
}

impl TurnServer {
    /// Construct a new [`TurnServer`]
    ///
    /// # Examples
    /// ```
    /// # use turn_server_proto::TurnServer;
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
        }
    }

    /// Add a user credentials that would be accepted by this [`TurnServer`].
    pub fn add_user(&mut self, username: String, password: String) {
        self.users.insert(username, password);
    }

    /// The address that the [`TurnServer`] is listening on for incoming client connections.
    pub fn listen_address(&self) -> SocketAddr {
        self.stun.local_addr()
    }

    /// Provide received data to the [`TurnServer`].
    ///
    /// Any returned Transmit should be forwarded to the appropriate socket.
    #[tracing::instrument(
        name = "turn_server_recv",
        skip(self, transmit),
        fields(
            transport = %transmit.transport,
            remote_addr = %transmit.from,
            local_addr = %transmit.to,
            data_len = transmit.data.as_ref().len(),
        )
        err,
        ret,
    )]
    pub fn recv<T: AsRef<[u8]>>(
        &mut self,
        transmit: Transmit<T>,
        now: Instant,
    ) -> Result<Option<Transmit<Data<'static>>>, StunError> {
        if let Some((client, allocation)) =
            self.allocation_from_public_5tuple(transmit.transport, transmit.to, transmit.from)
        {
            // A packet from the relayed address needs to be sent to the client that set up
            // the allocation.
            let Some(_permission) =
                allocation.permissions_from_5tuple(transmit.transport, transmit.to, transmit.from)
            else {
                warn!(
                    "no permission for {:?} for this allocation {:?}",
                    transmit.from, allocation.addr
                );
                return Ok(None);
            };

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
                Ok(Some(Transmit::new(
                    data.into_boxed_slice().into(),
                    client.transport,
                    client.local_addr,
                    client.remote_addr,
                )))
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
                );
                let peer_address = XorPeerAddress::new(transmit.from, transaction_id);
                builder.add_attribute(&peer_address).unwrap();
                let data = AData::new(transmit.data.as_ref());
                builder.add_attribute(&data).unwrap();
                // XXX: try to avoid copy?
                let msg_data = builder.build();

                Ok(Some(Transmit::new(
                    msg_data.into_boxed_slice().into(),
                    client.transport,
                    client.local_addr,
                    client.remote_addr,
                )))
            }
        } else {
            // TODO: TCP buffering requirements
            match Message::from_bytes(transmit.data.as_ref()) {
                Ok(msg) => {
                    trace!("received {} from {:?}", msg, transmit.from);
                    match self.handle_stun(
                        &msg,
                        transmit.transport,
                        transmit.from,
                        transmit.to,
                        now,
                    ) {
                        Err(builder) => {
                            let data = builder.build();
                            return Ok(Some(Transmit::new(
                                data.into_boxed_slice().into(),
                                transmit.transport,
                                transmit.to,
                                transmit.from,
                            )));
                        }
                        Ok(Some(transmit)) => Ok(Some(transmit.into_owned())),
                        Ok(None) => Ok(None),
                    }
                }
                Err(_) => {
                    if let Some(client) =
                        self.client_from_5tuple(transmit.transport, transmit.to, transmit.from)
                    {
                        trace!(
                            "received {} bytes from {:?}",
                            transmit.data.as_ref().len(),
                            transmit.from
                        );
                        let Ok(channel) = ChannelData::parse(transmit.data.as_ref()) else {
                            return Ok(None);
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
                            return Ok(None);
                        };

                        // A packet from the client needs to be sent to the peer referenced by the
                        // configured channel.
                        let Some(_permission) = allocation.permissions_from_5tuple(
                            transmit.transport,
                            allocation.addr,
                            existing.peer_addr,
                        ) else {
                            warn!(
                                "no permission for {:?} for this allocation {:?}",
                                existing.peer_addr, allocation.addr
                            );
                            return Ok(None);
                        };
                        Ok(Some(
                            Transmit::new(
                                Data::from(channel.data()),
                                allocation.ttype,
                                allocation.addr,
                                existing.peer_addr,
                            )
                            .into_owned(),
                        ))
                    } else {
                        trace!(
                            "No handler for {} bytes over {:?} from {:?}, to {:?}. Ignoring",
                            transmit.data.as_ref().len(),
                            transmit.transport,
                            transmit.from,
                            transmit.to
                        );
                        Ok(None)
                    }
                }
            }
        }
    }

    /// Poll the [`TurnServer`] in order to make further progress.
    ///
    /// The returned value indicates what the caller should do.
    #[tracing::instrument(name = "turn_server_poll", skip(self), ret)]
    pub fn poll(&mut self, now: Instant) -> TurnServerPollRet {
        for pending in self.pending_allocates.iter_mut() {
            if pending.asked {
                continue;
            }

            // TODO: TCP
            return TurnServerPollRet::AllocateSocketUdp {
                transport: pending.client.transport,
                local_addr: pending.client.local_addr,
                remote_addr: pending.client.remote_addr,
            };
        }

        for client in self.clients.iter_mut() {
            client.allocations.retain_mut(|allocation| {
                if allocation.expires_at <= now {
                    allocation
                        .permissions
                        .retain_mut(|permission| permission.expires_at <= now);
                    allocation
                        .channels
                        .retain_mut(|channel| channel.expires_at <= now);
                    true
                } else {
                    false
                }
            });
        }

        TurnServerPollRet::WaitUntil(now + Duration::from_secs(60))
    }

    /// Poll for a new Transmit to send over a socket.
    #[tracing::instrument(name = "turn_server_poll_transmit", skip(self))]
    pub fn poll_transmit(&mut self, now: Instant) -> Option<Transmit<Data<'static>>> {
        if let Some(transmit) = self.pending_transmits.pop_back() {
            return Some(transmit);
        }
        None
    }

    /// Notify the [`TurnServer`] that a UDP socket has been allocated (or an error) in response to
    /// [TurnServerPollRet::AllocateSocketUdp].
    #[tracing::instrument(name = "turn_server_allocated_udp_socket", skip(self))]
    pub fn allocated_udp_socket(
        &mut self,
        transport: TransportType,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        socket_addr: Result<SocketAddr, ()>,
        now: Instant,
    ) {
        let Some(position) = self.pending_allocates.iter().position(|pending| {
            pending.client.transport == transport
                && pending.client.local_addr == local_addr
                && pending.client.remote_addr == remote_addr
        }) else {
            warn!("No pending allocation for transport: Udp, local: {local_addr:?}, remote {remote_addr:?}");
            return;
        };
        info!("pending allocation for transport: Udp, local: {local_addr:?}, remote {remote_addr:?} resulted in {socket_addr:?}");
        let mut pending = self.pending_allocates.remove(position).unwrap();
        let transaction_id = pending.transaction_id;
        let to = pending.client.remote_addr;

        let mut builder = if let Ok(socket_addr) = socket_addr {
            pending.client.allocations.push(Allocation {
                addr: socket_addr,
                ttype: TransportType::Udp,
                expires_at: now + Duration::from_secs(1800),
                permissions: vec![],
                channels: vec![],
            });

            let mut builder = Message::builder(
                MessageType::from_class_method(MessageClass::Success, ALLOCATE),
                transaction_id,
            );
            let relayed_address = XorRelayedAddress::new(socket_addr, transaction_id);
            builder.add_attribute(&relayed_address).unwrap();
            let lifetime = Lifetime::new(1800);
            builder.add_attribute(&lifetime).unwrap();
            // TODO RESERVATION-TOKEN
            let mapped_address = XorMappedAddress::new(pending.client.remote_addr, transaction_id);
            builder.add_attribute(&mapped_address).unwrap();

            builder.into_owned()
        } else {
            let mut builder = Message::builder(
                MessageType::from_class_method(MessageClass::Error, ALLOCATE),
                transaction_id,
            );
            let error = ErrorCode::builder(ErrorCode::INSUFFICIENT_CAPACITY)
                .build()
                .unwrap();
            builder.add_attribute(&error).unwrap();
            builder.into_owned()
        };
        builder
            .add_message_integrity(
                &MessageIntegrityCredentials::LongTerm(pending.client.credentials.clone()),
                stun_proto::types::message::IntegrityAlgorithm::Sha1,
            )
            .unwrap();

        let Ok(transmit) = self.stun.send(builder, to, now) else {
            return;
        };
        if socket_addr.is_ok() {
            self.clients.push(pending.client);
        }
        self.pending_transmits
            .push_back(transmit_send_build(transmit));
    }

    fn validate_stun<'a>(
        &mut self,
        msg: &Message<'_>,
        ttype: TransportType,
        from: SocketAddr,
        to: SocketAddr,
        now: Instant,
    ) -> Result<LongTermCredentials, MessageBuilder<'a>> {
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
            let nonce = if let Some(nonce) = self.nonce_from_5tuple(ttype, to, from) {
                nonce
            } else {
                self.nonces.push(NonceData {
                    transport: ttype,
                    remote_addr: from,
                    local_addr: to,
                    // FIXME: use an actual random source.
                    nonce: String::from("random"),
                    expires_at: now + Duration::from_secs(3600),
                });
                self.nonces.last().unwrap()
            };
            trace!(
                "no message-integrity, returning unauthorized with nonce: {}",
                nonce.nonce
            );
            let mut builder = Message::builder_error(msg);
            let nonce = Nonce::new(&nonce.nonce).unwrap();
            builder.add_attribute(&nonce).unwrap();
            let realm = Realm::new(&self.realm).unwrap();
            builder.add_attribute(&realm).unwrap();
            let error = ErrorCode::builder(ErrorCode::UNAUTHORIZED).build().unwrap();
            builder.add_attribute(&error).unwrap();
            return Err(builder.into_owned());
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
            let error = ErrorCode::builder(ErrorCode::BAD_REQUEST).build().unwrap();
            let mut builder = Message::builder_error(msg);
            builder.add_attribute(&error).unwrap();
            return Err(builder.into_owned());
        };

        //   o  If the NONCE is no longer valid, the server MUST generate an error
        //      response with an error code of 438 (Stale Nonce).  This response
        //      MUST include NONCE and REALM attributes and SHOULD NOT include the
        //      USERNAME or MESSAGE-INTEGRITY attribute.  Servers can invalidate
        //      nonces in order to provide additional security.  See Section 4.3
        //      of [RFC2617] for guidelines.
        let nonce_data = self.mut_nonce_from_5tuple(ttype, to, from);
        let mut stale_nonce = false;
        let nonce_value = if let Some(nonce_data) = nonce_data {
            if nonce_data.expires_at < now {
                nonce_data.nonce = String::from("random");
                nonce_data.expires_at = now + Duration::from_secs(3600);
                stale_nonce = true;
            } else if nonce_data.nonce != nonce.nonce() {
                stale_nonce = true;
            }
            nonce_data.nonce.clone()
        } else {
            let nonce_value = String::from("randome");
            self.nonces.push(NonceData {
                transport: ttype,
                remote_addr: from,
                local_addr: to,
                // FIXME: use an actual random source.
                nonce: nonce_value.clone(),
                expires_at: now + Duration::from_secs(3600),
            });
            stale_nonce = true;
            nonce_value
        };

        if stale_nonce {
            let mut builder = Message::builder_error(msg);
            let error = ErrorCode::builder(ErrorCode::STALE_NONCE).build().unwrap();
            builder.add_attribute(&error).unwrap();
            let realm = Realm::new(&self.realm).unwrap();
            builder.add_attribute(&realm).unwrap();
            let nonce = Nonce::new(&nonce_value).unwrap();
            builder.add_attribute(&nonce).unwrap();

            return Err(builder.into_owned());
        };

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
            let mut builder = Message::builder_error(msg);
            let error = ErrorCode::builder(ErrorCode::UNAUTHORIZED).build().unwrap();
            builder.add_attribute(&error).unwrap();
            let realm = Realm::new(&self.realm).unwrap();
            builder.add_attribute(&realm).unwrap();
            let nonce = Nonce::new(&nonce_value).unwrap();
            builder.add_attribute(&nonce).unwrap();
            return Err(builder.into_owned());
        }

        if let Some(client) = self.client_from_5tuple(ttype, to, from) {
            if client.credentials.username() != username.username() {
                let mut builder = Message::builder_error(msg);
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
                return Err(builder.into_owned());
            }
        }

        Ok(credentials)
    }

    fn handle_stun_binding<'a>(
        &mut self,
        msg: &Message<'_>,
        _ttype: TransportType,
        from: SocketAddr,
        to: SocketAddr,
        now: Instant,
    ) -> Result<Transmit<Data<'a>>, MessageBuilder<'a>> {
        let response = if let Some(error_msg) =
            Message::check_attribute_types(msg, &[Fingerprint::TYPE], &[])
        {
            error_msg
        } else {
            let mut response = Message::builder_success(msg);
            let xor_addr = XorMappedAddress::new(from, msg.transaction_id());
            response.add_attribute(&xor_addr).unwrap();
            response.add_fingerprint().unwrap();
            response.into_owned()
        };

        let Ok(transmit) = self.stun.send(response, to, now) else {
            error!("Failed to send");
            let mut response = Message::builder_error(msg);
            let error = ErrorCode::builder(ErrorCode::SERVER_ERROR).build().unwrap();
            response.add_attribute(&error).unwrap();
            response.add_fingerprint().unwrap();
            return Err(response.into_owned());
        };

        Ok(transmit_send_build(transmit))
    }

    fn handle_stun_allocate<'a>(
        &mut self,
        msg: &Message<'_>,
        ttype: TransportType,
        from: SocketAddr,
        to: SocketAddr,
        now: Instant,
    ) -> Result<(), MessageBuilder<'a>> {
        let credentials = self.validate_stun(msg, ttype, from, to, now)?;

        if let Some(_client) = self.mut_client_from_5tuple(ttype, to, from) {
            let mut builder = Message::builder_error(msg);
            let error = ErrorCode::builder(ErrorCode::ALLOCATION_MISMATCH)
                .build()
                .unwrap();
            builder.add_attribute(&error).unwrap();
            return Err(builder.into_owned());
        };

        let Ok(requested_transport) = msg.attribute::<RequestedTransport>() else {
            let mut builder = Message::builder_error(msg);
            let error = ErrorCode::builder(ErrorCode::BAD_REQUEST).build().unwrap();
            builder.add_attribute(&error).unwrap();
            builder
                .add_message_integrity(
                    &MessageIntegrityCredentials::LongTerm(credentials),
                    stun_proto::types::message::IntegrityAlgorithm::Sha1,
                )
                .unwrap();
            return Err(builder.into_owned());
        };

        if requested_transport.protocol() != RequestedTransport::UDP {
            let mut builder = Message::builder_error(msg);
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
            return Err(builder.into_owned());
        }

        // TODO: DONT-FRAGMENT
        // TODO: EVEN-PORT
        // TODO: RESERVATION-TOKEN
        // TODO: allocation quota
        // XXX: TRY-ALTERNATE

        let client = Client {
            transport: ttype,
            remote_addr: from,
            local_addr: to,
            allocations: vec![],
            credentials,
        };

        self.pending_allocates.push_front(PendingClient {
            client,
            asked: false,
            transaction_id: msg.transaction_id(),
        });

        Ok(())
    }

    fn handle_stun_refresh<'a>(
        &mut self,
        msg: &Message<'_>,
        ttype: TransportType,
        from: SocketAddr,
        to: SocketAddr,
        now: Instant,
    ) -> Result<Transmit<Data<'static>>, MessageBuilder<'a>> {
        let _credentials = self.validate_stun(msg, ttype, from, to, now)?;

        let Some(client) = self.mut_client_from_5tuple(ttype, to, from) else {
            let mut builder = Message::builder_error(msg);
            let error = ErrorCode::builder(ErrorCode::ALLOCATION_MISMATCH)
                .build()
                .unwrap();
            builder.add_attribute(&error).unwrap();
            return Err(builder.into_owned());
        };

        // TODO: proper lifetime handling
        let request_lifetime = msg
            .attribute::<Lifetime>()
            .map(|lt| lt.seconds())
            .unwrap_or(600);
        let credentials = if request_lifetime == 0 {
            // TODO: handle dual IPv4/6 allocations.
            let credentials = client.credentials.clone();
            self.remove_client_by_5tuple(ttype, to, from);
            credentials
        } else {
            for allocation in client.allocations.iter_mut() {
                allocation.expires_at = now + Duration::from_secs(request_lifetime as u64)
            }
            client.credentials.clone()
        };

        let mut builder = Message::builder_success(msg);
        let lifetime = Lifetime::new(request_lifetime);
        builder.add_attribute(&lifetime).unwrap();
        builder
            .add_message_integrity(
                &MessageIntegrityCredentials::LongTerm(credentials),
                stun_proto::types::message::IntegrityAlgorithm::Sha1,
            )
            .unwrap();
        let Ok(transmit) = self.stun.send(builder, from, now) else {
            error!("Failed to send");
            let mut response = Message::builder_error(msg);
            let error = ErrorCode::builder(ErrorCode::SERVER_ERROR).build().unwrap();
            response.add_attribute(&error).unwrap();
            response.add_fingerprint().unwrap();
            return Err(response.into_owned());
        };

        Ok(transmit_send_build(transmit))
    }

    fn handle_stun_create_permission<'a>(
        &mut self,
        msg: &Message<'_>,
        ttype: TransportType,
        from: SocketAddr,
        to: SocketAddr,
        now: Instant,
    ) -> Result<Transmit<Data<'static>>, MessageBuilder<'a>> {
        let credentials = self.validate_stun(msg, ttype, from, to, now)?;

        let Some(client) = self.mut_client_from_5tuple(ttype, to, from) else {
            let mut builder = Message::builder_error(msg);
            let error = ErrorCode::builder(ErrorCode::ALLOCATION_MISMATCH)
                .build()
                .unwrap();
            builder.add_attribute(&error).unwrap();
            return Err(builder.into_owned());
        };

        let mut at_least_one_peer_addr = false;
        for peer_addr in msg
            .iter_attributes()
            .filter(|a| a.get_type() == XorPeerAddress::TYPE)
        {
            let Ok(peer_addr) = XorPeerAddress::from_raw(peer_addr) else {
                let mut builder = Message::builder_error(msg);
                let error = ErrorCode::builder(ErrorCode::BAD_REQUEST).build().unwrap();
                builder.add_attribute(&error).unwrap();
                builder
                    .add_message_integrity(
                        &MessageIntegrityCredentials::LongTerm(client.credentials.clone()),
                        stun_proto::types::message::IntegrityAlgorithm::Sha1,
                    )
                    .unwrap();
                return Err(builder.into_owned());
            };
            at_least_one_peer_addr = true;
            let peer_addr = peer_addr.addr(msg.transaction_id());

            let Some(alloc) = client
                .allocations
                .iter_mut()
                .find(|a| a.addr.is_ipv4() == peer_addr.is_ipv4())
            else {
                // XXX: Should always be an allocation available.
                // TODO: support IPv6
                unreachable!();
            };

            if now > alloc.expires_at {
                trace!("allocation has expired");
                // allocation has expired
                let mut builder = Message::builder_error(msg);
                let error = ErrorCode::builder(ErrorCode::ALLOCATION_MISMATCH)
                    .build()
                    .unwrap();
                builder.add_attribute(&error).unwrap();
                builder
                    .add_message_integrity(
                        &MessageIntegrityCredentials::LongTerm(client.credentials.clone()),
                        stun_proto::types::message::IntegrityAlgorithm::Sha1,
                    )
                    .unwrap();
                return Err(builder.into_owned());
            }

            // TODO: support TCP allocations
            if let Some(position) = alloc
                .permissions
                .iter()
                .position(|perm| perm.ttype == TransportType::Udp && perm.addr == peer_addr.ip())
            {
                alloc.permissions[position].expires_at = now + Duration::from_secs(300);
            } else {
                alloc.permissions.push(Permission {
                    addr: peer_addr.ip(),
                    ttype: TransportType::Udp,
                    expires_at: now + Duration::from_secs(300),
                });
            }
        }

        if !at_least_one_peer_addr {
            let mut builder = Message::builder_error(msg);
            let error = ErrorCode::builder(ErrorCode::BAD_REQUEST).build().unwrap();
            builder.add_attribute(&error).unwrap();
            builder
                .add_message_integrity(
                    &MessageIntegrityCredentials::LongTerm(client.credentials.clone()),
                    stun_proto::types::message::IntegrityAlgorithm::Sha1,
                )
                .unwrap();
            return Err(builder.into_owned());
        }

        let mut builder = Message::builder_success(msg);
        builder
            .add_message_integrity(
                &MessageIntegrityCredentials::LongTerm(credentials),
                stun_proto::types::message::IntegrityAlgorithm::Sha1,
            )
            .unwrap();

        let Ok(transmit) = self.stun.send(builder, from, now) else {
            error!("Failed to send");
            let mut response = Message::builder_error(msg);
            let error = ErrorCode::builder(ErrorCode::SERVER_ERROR).build().unwrap();
            response.add_attribute(&error).unwrap();
            response.add_fingerprint().unwrap();
            return Err(response.into_owned());
        };

        Ok(transmit_send_build(transmit))
    }

    fn handle_stun_channel_bind<'a>(
        &mut self,
        msg: &Message<'_>,
        ttype: TransportType,
        from: SocketAddr,
        to: SocketAddr,
        now: Instant,
    ) -> Result<Transmit<Data<'static>>, MessageBuilder<'a>> {
        let credentials = self.validate_stun(msg, ttype, from, to, now)?;

        let Some(client) = self.mut_client_from_5tuple(ttype, to, from) else {
            let mut builder = Message::builder_error(msg);
            let error = ErrorCode::builder(ErrorCode::ALLOCATION_MISMATCH)
                .build()
                .unwrap();
            builder.add_attribute(&error).unwrap();
            return Err(builder.into_owned());
        };

        let bad_request = move |msg: &Message<'_>, credentials: LongTermCredentials| {
            let mut builder = Message::builder_error(msg);
            let error = ErrorCode::builder(ErrorCode::BAD_REQUEST).build().unwrap();
            builder.add_attribute(&error).unwrap();
            builder
                .add_message_integrity(
                    &MessageIntegrityCredentials::LongTerm(credentials),
                    stun_proto::types::message::IntegrityAlgorithm::Sha1,
                )
                .unwrap();
            builder.into_owned()
        };

        let peer_addr = msg
            .attribute::<XorPeerAddress>()
            .ok()
            .map(|peer_addr| peer_addr.addr(msg.transaction_id()));
        let Some(peer_addr) = peer_addr else {
            trace!("No peer address");
            return Err(bad_request(msg, credentials));
        };

        let Some(alloc) = client
            .allocations
            .iter_mut()
            .find(|allocation| allocation.addr.is_ipv4() == peer_addr.is_ipv4())
        else {
            let mut builder = Message::builder_error(msg);
            let error = ErrorCode::builder(ErrorCode::ALLOCATION_MISMATCH)
                .build()
                .unwrap();
            builder.add_attribute(&error).unwrap();
            return Err(builder.into_owned());
        };

        if now > alloc.expires_at {
            trace!("allocation has expired");
            // allocation has expired
            let mut builder = Message::builder_error(msg);
            let error = ErrorCode::builder(ErrorCode::ALLOCATION_MISMATCH)
                .build()
                .unwrap();
            builder.add_attribute(&error).unwrap();
            builder
                .add_message_integrity(
                    &MessageIntegrityCredentials::LongTerm(client.credentials.clone()),
                    stun_proto::types::message::IntegrityAlgorithm::Sha1,
                )
                .unwrap();
            return Err(builder.into_owned());
        }

        let mut existing = alloc.channels.iter_mut().find(|channel| {
            channel.peer_addr == peer_addr && channel.peer_transport == TransportType::Udp
        });

        let channel_no = msg
            .attribute::<ChannelNumber>()
            .ok()
            .map(|channel| channel.channel());
        if let Some(channel_no) = channel_no {
            if !(0x4000..=0x7fff).contains(&channel_no) {
                trace!("Channel id out of range");
                return Err(bad_request(msg, credentials));
            }
            if existing
                .as_ref()
                .is_some_and(|existing| existing.id != channel_no)
            {
                trace!("channel peer address does not match channel ID");
                return Err(bad_request(msg, credentials));
            }
        } else {
            debug!("Bad request: no requested channel id");
            return Err(bad_request(msg, credentials));
        }

        if let Some(existing) = existing.as_mut() {
            existing.expires_at = now + Duration::from_secs(600);
        } else {
            alloc.channels.push(Channel {
                id: channel_no.unwrap(),
                peer_addr,
                peer_transport: TransportType::Udp,
                expires_at: now + Duration::from_secs(600),
            });
        }

        if let Some(existing) = alloc
            .permissions
            .iter_mut()
            .find(|perm| perm.ttype == TransportType::Udp && perm.addr == peer_addr.ip())
        {
            existing.expires_at = now + Duration::from_secs(300);
        } else {
            alloc.permissions.push(Permission {
                addr: peer_addr.ip(),
                ttype: TransportType::Udp,
                expires_at: now + Duration::from_secs(300),
            });
        }

        let mut builder = Message::builder_success(msg);
        builder
            .add_message_integrity(
                &MessageIntegrityCredentials::LongTerm(credentials),
                stun_proto::types::message::IntegrityAlgorithm::Sha1,
            )
            .unwrap();

        let Ok(transmit) = self.stun.send(builder, from, now) else {
            error!("Failed to send");
            let mut response = Message::builder_error(msg);
            let error = ErrorCode::builder(ErrorCode::SERVER_ERROR).build().unwrap();
            response.add_attribute(&error).unwrap();
            response.add_fingerprint().unwrap();
            return Err(response.into_owned());
        };

        Ok(transmit_send_build(transmit))
    }

    fn handle_stun_send_indication<'a>(
        &mut self,
        msg: &'a Message<'a>,
        ttype: TransportType,
        from: SocketAddr,
        to: SocketAddr,
        now: Instant,
    ) -> Result<Transmit<Data<'a>>, ()> {
        let peer_address = msg.attribute::<XorPeerAddress>().map_err(|_| ())?;
        let peer_address = peer_address.addr(msg.transaction_id());

        let Some(client) = self.client_from_5tuple(ttype, to, from) else {
            trace!("no client for transport {ttype:?} from {from:?}, to {to:?}");
            trace!("clients: {:?}", self.clients);
            return Err(());
        };

        let Some(alloc) = client
            .allocations
            .iter()
            .find(|allocation| allocation.addr.ip().is_ipv4() == peer_address.is_ipv4())
        else {
            trace!("no allocation for transport {ttype:?} from {from:?}, to {to:?}");
            trace!("allocations: {:?}", client.allocations);
            return Err(());
        };
        if now > alloc.expires_at {
            trace!("allocation has expired");
            // allocation has expired
            return Err(());
        }

        let Some(permission) = alloc
            .permissions
            .iter()
            .find(|permission| permission.addr == peer_address.ip())
        else {
            trace!("permission not installed");
            // no permission installed for this peer, ignoring
            return Err(());
        };
        if now > permission.expires_at {
            trace!("permission has expired");
            // permission has expired
            return Err(());
        }

        let data = msg.attribute::<AData>().map_err(|_| ())?;
        trace!("have {} to send to {:?}", data.data().len(), peer_address);
        Ok(Transmit::new(
            Data::from(data.data()),
            permission.ttype,
            alloc.addr,
            peer_address,
        )
        .into_owned())
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

    #[tracing::instrument(name = "turn_server_handle_stun", skip(self, msg, from, to, now))]
    fn handle_stun<'a>(
        &mut self,
        msg: &'a Message<'a>,
        ttype: TransportType,
        from: SocketAddr,
        to: SocketAddr,
        now: Instant,
    ) -> Result<Option<Transmit<Data<'a>>>, MessageBuilder<'a>> {
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
                    let mut builder = Message::builder_error(msg);
                    let error = ErrorCode::builder(ErrorCode::BAD_REQUEST).build().unwrap();
                    builder.add_attribute(&error).unwrap();
                    Err(builder.into_owned())
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
        debug!("result: {ret:?}");
        ret
    }

    fn nonce_from_5tuple(
        &self,
        ttype: TransportType,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) -> Option<&NonceData> {
        self.nonces.iter().find(|nonce| {
            nonce.transport == ttype
                && nonce.remote_addr == remote_addr
                && nonce.local_addr == local_addr
        })
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
    fn permissions_from_5tuple(
        &self,
        ttype: TransportType,
        _local_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) -> Option<&Permission> {
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
