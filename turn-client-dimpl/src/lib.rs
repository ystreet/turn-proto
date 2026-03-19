// Copyright (C) 2026 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! #turn-client-dimpl
//!
//! TLS TURN client using Dimpl.
//!
//! An implementation of a TURN client suitable for TLS over TCP connections and DTLS over UDP
//! connections.
//!
//! Note: no certificate validation is currently performed so this is TLS implementation is not
//! currently recommended for use.

#![deny(missing_debug_implementations)]
#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(clippy::std_instead_of_core)]
#![deny(clippy::std_instead_of_alloc)]
#![no_std]

extern crate alloc;

pub use dimpl;

#[cfg(any(feature = "std", test))]
extern crate std;

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::net::{IpAddr, SocketAddr};
use core::time::Duration;

use stun_proto::agent::Transmit;
use stun_proto::types::data::Data;
use stun_proto::Instant;

use stun_proto::types::TransportType;

use tracing::{trace, warn};

use turn_client_proto::api::{
    BindChannelError, CreatePermissionError, DelayedMessageOrChannelSend, DeleteError, SendError,
    Socket5Tuple, TcpAllocateError, TcpConnectError, TransmitBuild, TurnClientApi, TurnConfig,
    TurnEvent, TurnPeerData, TurnPollRet, TurnRecvRet,
};
use turn_client_proto::udp::TurnClientUdp;

/// A TURN client that communicates over TLS.
#[derive(Debug)]
pub struct TurnClientDimpl {
    protocol: TurnClientUdp,
    dtls: Box<dimpl::Dtls>,
    base_instant: std::time::Instant,
    base_now: Option<Instant>,
    connected: bool,
    pending_write: VecDeque<Transmit<Data<'static>>>,
    pending_read: VecDeque<TurnPeerData<Vec<u8>>>,
}

impl TurnClientDimpl {
    /// Allocate an address on a TURN server to relay data to and from peers.
    pub fn allocate(
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        config: TurnConfig,
        tls_config: Arc<dimpl::Config>,
    ) -> Self {
        let cert = dimpl::certificate::generate_self_signed_certificate().unwrap();
        let base_instant = std::time::Instant::now();
        let mut dtls = Box::new(dimpl::Dtls::new_auto(tls_config, cert, base_instant));
        dtls.set_active(true);

        Self {
            protocol: TurnClientUdp::allocate(local_addr, remote_addr, config),
            base_instant,
            base_now: None,
            dtls,
            connected: false,
            pending_read: VecDeque::default(),
            pending_write: VecDeque::default(),
        }
    }

    fn empty_transmit_queue(&mut self, now: Instant) {
        while let Some(transmit) = self.protocol.poll_transmit(now) {
            match self.dtls.send_application_data(&transmit.data) {
                Ok(_) => (),
                Err(e) => {
                    warn!("Failure to send data: {e:?}");
                    continue;
                }
            }
        }
        self.poll(now);
    }
}

impl TurnClientApi for TurnClientDimpl {
    fn transport(&self) -> TransportType {
        self.protocol.transport()
    }

    fn local_addr(&self) -> SocketAddr {
        self.protocol.local_addr()
    }

    fn remote_addr(&self) -> SocketAddr {
        self.protocol.remote_addr()
    }

    fn poll(&mut self, now: Instant) -> TurnPollRet {
        let base_now = *self.base_now.get_or_insert(now);
        let _ = self.dtls.handle_timeout(
            Instant::from_nanos((now - base_now).as_nanos() as i64).to_std(self.base_instant),
        );

        let mut out = [0; 2048];
        let mut earliest_wait = None;
        loop {
            let ret = self.dtls.poll_output(&mut out);
            tracing::error!("dtls poll ret {ret:?}");
            match ret {
                dimpl::Output::Packet(p) => {
                    self.pending_write.push_back(Transmit::new(
                        Data::from(Box::from(p)),
                        TransportType::Udp,
                        self.local_addr(),
                        self.remote_addr(),
                    ));
                    earliest_wait = Some(now);
                }
                dimpl::Output::Timeout(time) => {
                    let wait = Instant::from_nanos((time - self.base_instant).as_nanos() as i64);
                    tracing::error!(
                        "time {time:?} base {:?} wait {wait:?} now {now:?}",
                        self.base_instant
                    );
                    if wait == now {
                        let _ = self.dtls.handle_timeout(time);
                        continue;
                    }
                    if earliest_wait.is_none_or(|earliest| earliest > wait) {
                        earliest_wait = Some(wait);
                    }
                    break;
                }
                dimpl::Output::Connected => self.connected = true,
                // TODO: validate certificate
                dimpl::Output::PeerCert(_peer_cert) => (),
                dimpl::Output::KeyingMaterial(_key, _srtp_profile) => (),
                dimpl::Output::ApplicationData(app_data) => {
                    let transmit = Transmit::new(
                        app_data,
                        TransportType::Udp,
                        self.remote_addr(),
                        self.local_addr(),
                    );
                    match self.protocol.recv(transmit, now) {
                        TurnRecvRet::Handled => (),
                        TurnRecvRet::Ignored(_transmit) => (),
                        TurnRecvRet::PeerData(peer_data) => {
                            self.pending_read.push_back(peer_data.into_owned());
                        }
                        TurnRecvRet::PeerIcmp {
                            transport: _,
                            peer: _,
                            icmp_type: _,
                            icmp_code: _,
                            icmp_data: _,
                        } => (),
                    }
                }
                _ => (),
            }
        }

        if self.connected {
            self.protocol.poll(now)
        } else if let Some(earliest) = earliest_wait {
            TurnPollRet::WaitUntil(earliest)
        } else {
            TurnPollRet::WaitUntil(now + Duration::from_secs(600))
        }
    }

    fn relayed_addresses(&self) -> impl Iterator<Item = (TransportType, SocketAddr)> + '_ {
        self.protocol.relayed_addresses()
    }

    fn permissions(
        &self,
        transport: TransportType,
        relayed: SocketAddr,
    ) -> impl Iterator<Item = IpAddr> + '_ {
        self.protocol.permissions(transport, relayed)
    }

    fn poll_transmit(&mut self, now: Instant) -> Option<Transmit<Data<'static>>> {
        if self.connected {
            self.empty_transmit_queue(now);
        }
        self.pending_write.pop_front()
    }

    fn poll_event(&mut self) -> Option<TurnEvent> {
        self.protocol.poll_event()
    }

    fn delete(&mut self, now: Instant) -> Result<(), DeleteError> {
        self.protocol.delete(now)?;
        self.empty_transmit_queue(now);
        Ok(())
    }

    fn create_permission(
        &mut self,
        transport: TransportType,
        peer_addr: IpAddr,
        now: Instant,
    ) -> Result<(), CreatePermissionError> {
        self.protocol.create_permission(transport, peer_addr, now)?;
        self.empty_transmit_queue(now);
        Ok(())
    }

    fn have_permission(&self, transport: TransportType, to: IpAddr) -> bool {
        self.protocol.have_permission(transport, to)
    }

    fn bind_channel(
        &mut self,
        transport: TransportType,
        peer_addr: SocketAddr,
        now: Instant,
    ) -> Result<(), BindChannelError> {
        self.protocol.bind_channel(transport, peer_addr, now)?;
        self.empty_transmit_queue(now);
        Ok(())
    }

    fn tcp_connect(&mut self, peer_addr: SocketAddr, now: Instant) -> Result<(), TcpConnectError> {
        self.protocol.tcp_connect(peer_addr, now)?;

        self.empty_transmit_queue(now);

        Ok(())
    }

    fn allocated_tcp_socket(
        &mut self,
        _id: u32,
        _five_tuple: Socket5Tuple,
        _peer_addr: SocketAddr,
        _local_addr: Option<SocketAddr>,
        _now: Instant,
    ) -> Result<(), TcpAllocateError> {
        Err(TcpAllocateError::NoAllocation)
    }

    fn tcp_closed(&mut self, local_addr: SocketAddr, remote_addr: SocketAddr, now: Instant) {
        self.protocol.tcp_closed(local_addr, remote_addr, now);
    }

    fn send_to<T: AsRef<[u8]> + core::fmt::Debug>(
        &mut self,
        transport: TransportType,
        to: SocketAddr,
        data: T,
        now: Instant,
    ) -> Result<Option<TransmitBuild<DelayedMessageOrChannelSend<T>>>, SendError> {
        if let Some(transmit) = self.protocol.send_to(transport, to, data, now)? {
            let transmit = transmit.build();
            match self.dtls.send_application_data(&transmit.data) {
                Ok(_) => (),
                Err(e) => {
                    warn!("Error when writing plaintext: {e:?}");
                    return Err(SendError::NoAllocation);
                }
            }
        }
        self.empty_transmit_queue(now);

        Ok(self.poll_transmit(now).map(|transmit| {
            TransmitBuild::new(
                DelayedMessageOrChannelSend::OwnedData(transmit.data.to_vec()),
                transmit.transport,
                transmit.from,
                transmit.to,
            )
        }))
    }

    #[tracing::instrument(
        name = "turn_dimpl_recv",
        skip(self, transmit, now),
        fields(
            transport = %transmit.transport,
            from = ?transmit.from,
            data_len = transmit.data.as_ref().len()
        )
    )]
    fn recv<T: AsRef<[u8]> + core::fmt::Debug>(
        &mut self,
        transmit: Transmit<T>,
        now: Instant,
    ) -> TurnRecvRet<T> {
        /* is this data for our client? */
        if self.transport() != transmit.transport
            || transmit.to != self.local_addr()
            || transmit.from != self.remote_addr()
        {
            trace!(
                "received data not directed at us ({} {:?}) but for {} {:?}!",
                self.transport(),
                self.local_addr(),
                transmit.transport,
                transmit.to,
            );
            return TurnRecvRet::Ignored(transmit);
        };

        match self.dtls.handle_packet(transmit.data.as_ref()) {
            Ok(_) => (),
            Err(e) => {
                warn!("dimpl packet produced error: {e:?}");
                return TurnRecvRet::Ignored(transmit);
            }
        };

        self.poll(now);
        if let Some(recved) = self.poll_recv(now) {
            TurnRecvRet::PeerData(recved.into_owned())
        } else {
            TurnRecvRet::Handled
        }
    }

    fn poll_recv(&mut self, _now: Instant) -> Option<TurnPeerData<Vec<u8>>> {
        self.pending_read.pop_front()
    }

    fn protocol_error(&mut self) {
        self.protocol.protocol_error()
    }
}
