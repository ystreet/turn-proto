// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! # TLS TURN client
//!
//! An implementation of a TURN client suitable for TLS over TCP connections.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::ops::Range;
use std::sync::Arc;
use std::time::Instant;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection};

use stun_proto::agent::{StunAgent, Transmit};
use stun_proto::types::data::Data;

use stun_proto::types::TransportType;

use turn_types::channel::ChannelData;
use turn_types::TurnCredentials;

use tracing::{trace, warn};

use crate::common::{
    DataRangeOrOwned, DelayedMessageOrChannelSend, TransmitBuild, TurnClientApi, TurnPeerData,
};
use crate::protocol::{TurnClientProtocol, TurnProtocolChannelRecv, TurnProtocolRecv};

pub use crate::common::{
    BindChannelError, CreatePermissionError, DeleteError, TurnEvent, TurnPollRet, TurnRecvRet,
};
pub use crate::protocol::SendError;
use crate::tcp::{IncomingTcp, TurnTcpBuffer};

/// A TURN client that communicates over TLS.
#[derive(Debug)]
pub struct TurnClientTls {
    protocol: TurnClientProtocol,
    conn: ClientConnection,
    incoming_tcp_buffer: TurnTcpBuffer,
    closing: bool,
}

impl TurnClientTls {
    /// Allocate an address on a TURN server to relay data to and from peers.
    pub fn allocate(
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        credentials: TurnCredentials,
        server_name: ServerName<'static>,
        config: Arc<ClientConfig>,
    ) -> Self {
        let stun_agent = StunAgent::builder(TransportType::Tcp, local_addr)
            .remote_addr(remote_addr)
            .build();
        Self {
            protocol: TurnClientProtocol::new(stun_agent, credentials),
            conn: ClientConnection::new(config, server_name).unwrap(),
            incoming_tcp_buffer: TurnTcpBuffer::new(),
            closing: false,
        }
    }

    fn ensure_data_owned(data: Vec<u8>, range: Range<usize>) -> Vec<u8> {
        if range.start == 0 && range.end == data.len() {
            data
        } else {
            data[range.start..range.end].to_vec()
        }
    }

    fn handle_incoming_plaintext<T: AsRef<[u8]> + std::fmt::Debug>(
        &mut self,
        transmit: Transmit<Vec<u8>>,
        now: Instant,
    ) -> TurnRecvRet<T> {
        match self.incoming_tcp_buffer.incoming_tcp(transmit) {
            IncomingTcp::NeedMoreData => TurnRecvRet::Handled,
            IncomingTcp::CompleteMessage(transmit) => {
                match self.protocol.handle_message(transmit, now) {
                    TurnProtocolRecv::Handled => TurnRecvRet::Handled,
                    TurnProtocolRecv::Ignored(_) => TurnRecvRet::Handled,
                    TurnProtocolRecv::PeerData {
                        transmit,
                        range,
                        transport,
                        peer,
                    } => TurnRecvRet::PeerData(TurnPeerData {
                        data: DataRangeOrOwned::Owned(Self::ensure_data_owned(
                            transmit.data,
                            range,
                        )),
                        transport,
                        peer,
                    }),
                }
            }
            IncomingTcp::CompleteChannel(transmit) => {
                let channel = ChannelData::parse(transmit.data.as_ref()).unwrap();
                let ret = self.protocol.handle_channel(
                    Transmit::new(channel, transmit.transport, transmit.from, transmit.to),
                    now,
                );
                match ret {
                    TurnProtocolChannelRecv::Ignored => TurnRecvRet::Handled,
                    TurnProtocolChannelRecv::PeerData {
                        range,
                        transport,
                        peer,
                    } => TurnRecvRet::PeerData(TurnPeerData {
                        data: DataRangeOrOwned::Owned(Self::ensure_data_owned(
                            transmit.data,
                            range,
                        )),
                        transport,
                        peer,
                    }),
                }
            }
            IncomingTcp::StoredMessage(data, transmit) => match self.protocol.handle_message(
                Transmit::new(data, transmit.transport, transmit.from, transmit.to),
                now,
            ) {
                TurnProtocolRecv::Handled => TurnRecvRet::Handled,
                TurnProtocolRecv::Ignored(_) => TurnRecvRet::Handled,
                TurnProtocolRecv::PeerData {
                    transmit,
                    range,
                    transport,
                    peer,
                } => TurnRecvRet::PeerData(TurnPeerData {
                    data: DataRangeOrOwned::Owned(Self::ensure_data_owned(transmit.data, range)),
                    transport,
                    peer,
                }),
            },
            IncomingTcp::StoredChannel(data, transmit) => {
                let channel = ChannelData::parse(&data).unwrap();
                let ret = self.protocol.handle_channel(
                    Transmit::new(channel, transmit.transport, transmit.from, transmit.to),
                    now,
                );
                match ret {
                    TurnProtocolChannelRecv::Ignored => TurnRecvRet::Handled,
                    TurnProtocolChannelRecv::PeerData {
                        range,
                        transport,
                        peer,
                    } => TurnRecvRet::PeerData(TurnPeerData {
                        data: DataRangeOrOwned::Owned(
                            transmit.data[range.start..range.end].to_vec(),
                        ),
                        transport,
                        peer,
                    }),
                }
            }
        }
    }
}

impl TurnClientApi for TurnClientTls {
    type SendError = SendError;

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
        let io_state = match self.conn.process_new_packets() {
            Ok(io_state) => io_state,
            Err(e) => {
                self.protocol.error();
                warn!("Error processing TLS: {e:?}");
                return TurnPollRet::Closed;
            }
        };
        let protocol_ret = self.protocol.poll(now);
        if io_state.tls_bytes_to_write() > 0 {
            return TurnPollRet::WaitUntil(now);
        }
        protocol_ret
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
        if self.conn.is_handshaking() && self.conn.wants_write() {
            // TODO: avoid this allocation
            let mut out = vec![];
            match self.conn.write_tls(&mut out) {
                Ok(_written) => {
                    return Some(Transmit::new(
                        Data::from(out.into_boxed_slice()),
                        self.transport(),
                        self.local_addr(),
                        self.remote_addr(),
                    ))
                }
                Err(e) => {
                    warn!("error during handshake: {e:?}");
                    self.protocol.error();
                    return None;
                }
            }
        }

        if !self.conn.wants_write() {
            if let Some(transmit) = self.protocol.poll_transmit(now) {
                self.conn.writer().write_all(&transmit.data).unwrap();
            }
        }

        if self.conn.wants_write() {
            // TODO: avoid this allocation
            let mut out = vec![];
            match self.conn.write_tls(&mut out) {
                Ok(_written) => {
                    return Some(Transmit::new(
                        Data::from(out.into_boxed_slice()),
                        self.transport(),
                        self.local_addr(),
                        self.remote_addr(),
                    ))
                }
                Err(e) => {
                    warn!("error writing TLS: {e:?}");
                    self.protocol.error();
                }
            }
        }
        None
    }

    fn poll_event(&mut self) -> Option<TurnEvent> {
        self.protocol.poll_event()
    }

    fn delete(&mut self, now: Instant) -> Result<(), DeleteError> {
        self.protocol.delete(now)?;
        self.closing = true;

        while let Some(transmit) = self.protocol.poll_transmit(now) {
            self.conn.writer().write_all(&transmit.data).unwrap();
        }
        Ok(())
    }

    fn create_permission(
        &mut self,
        transport: TransportType,
        peer_addr: IpAddr,
        now: Instant,
    ) -> Result<(), CreatePermissionError> {
        self.protocol.create_permission(transport, peer_addr, now)?;

        while let Some(transmit) = self.protocol.poll_transmit(now) {
            self.conn.writer().write_all(&transmit.data).unwrap();
        }

        Ok(())
    }

    fn bind_channel(
        &mut self,
        transport: TransportType,
        peer_addr: SocketAddr,
        now: Instant,
    ) -> Result<(), BindChannelError> {
        self.protocol.bind_channel(transport, peer_addr, now)?;

        while let Some(transmit) = self.protocol.poll_transmit(now) {
            self.conn.writer().write_all(&transmit.data).unwrap();
        }

        Ok(())
    }

    fn send_to<T: AsRef<[u8]> + std::fmt::Debug>(
        &mut self,
        transport: TransportType,
        to: SocketAddr,
        data: T,
        now: Instant,
    ) -> Result<Option<TransmitBuild<DelayedMessageOrChannelSend<T>>>, Self::SendError> {
        let transmit = self.protocol.send_to(transport, to, data, now)?;
        let transmit = transmit.build();
        if let Err(e) = self.conn.writer().write_all(&transmit.data) {
            self.protocol.error();
            warn!("Error when writing plaintext: {e:?}");
            return Err(SendError::NoAllocation);
        }

        if self.conn.wants_write() {
            let mut out = vec![];
            match self.conn.write_tls(&mut out) {
                Ok(_n) => {
                    return Ok(Some(TransmitBuild::new(
                        DelayedMessageOrChannelSend::Data(out),
                        self.transport(),
                        self.local_addr(),
                        self.remote_addr(),
                    )))
                }
                Err(e) => {
                    self.protocol.error();
                    warn!("Error when writing TLS records: {e:?}");
                    return Err(SendError::NoAllocation);
                }
            }
        }

        Ok(None)
    }

    fn recv<T: AsRef<[u8]> + std::fmt::Debug>(
        &mut self,
        transmit: Transmit<T>,
        now: Instant,
    ) -> TurnRecvRet<T> {
        /* is this data for our client? */
        if transmit.to != self.local_addr()
            || self.transport() != transmit.transport
            || transmit.from != self.remote_addr()
        {
            trace!(
                "received data not directed at us ({:?}) but for {:?}!",
                self.local_addr(),
                transmit.to
            );
            return TurnRecvRet::Ignored(transmit);
        }
        let mut data = std::io::Cursor::new(transmit.data.as_ref());

        let io_state = match self.conn.read_tls(&mut data) {
            Ok(_written) => match self.conn.process_new_packets() {
                Ok(io_state) => io_state,
                Err(e) => {
                    self.protocol.error();
                    warn!("Error processing TLS: {e:?}");
                    return TurnRecvRet::Ignored(transmit);
                }
            },
            Err(e) => {
                warn!("Error receiving data: {e:?}");
                self.protocol.error();
                return TurnRecvRet::Ignored(transmit);
            }
        };
        if io_state.plaintext_bytes_to_read() > 0 {
            let mut out = vec![0; 1024];
            let n = match self.conn.reader().read(&mut out) {
                Ok(n) => n,
                Err(e) => {
                    warn!("Error receiving data: {e:?}");
                    self.protocol.error();
                    return TurnRecvRet::Ignored(transmit);
                }
            };
            out.resize(n, 0);
            let transmit = Transmit::new(out, transmit.transport, transmit.from, transmit.to);

            return self.handle_incoming_plaintext(transmit, now);
        }

        TurnRecvRet::Handled
    }
}
