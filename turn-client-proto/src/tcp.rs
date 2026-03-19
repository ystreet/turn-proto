// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! TCP TURN client.
//!
//! An implementation of a TURN client suitable for TCP connections.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::net::{IpAddr, SocketAddr};
use core::ops::Range;
use turn_types::stun::message::Message;

use stun_proto::agent::{StunAgent, Transmit};
use stun_proto::types::data::Data;
use stun_proto::types::TransportType;
use stun_proto::Instant;

use turn_types::channel::ChannelData;
use turn_types::tcp::{IncomingTcp, StoredTcp, TurnTcpBuffer};

use tracing::{trace, warn};

use crate::api::{
    DataRangeOrOwned, DelayedMessageOrChannelSend, Socket5Tuple, TcpAllocateError, TcpConnectError,
    TransmitBuild, TurnClientApi, TurnConfig, TurnPeerData,
};
use crate::protocol::{TurnClientProtocol, TurnProtocolChannelRecv, TurnProtocolRecv};

pub use crate::api::{
    BindChannelError, CreatePermissionError, DeleteError, SendError, TurnEvent, TurnPollRet,
    TurnRecvRet,
};

/// A TURN client.
#[derive(Debug)]
pub struct TurnClientTcp {
    protocol: TurnClientProtocol,
    incoming_tcp_buffers: BTreeMap<(SocketAddr, SocketAddr), TcpBuffer>,
}

#[derive(Debug)]
enum TcpBuffer {
    // The control TURN connection. Always buffered.
    Control(TurnTcpBuffer),
    WaitingForConnectionBindResponse(TurnTcpBuffer),
    // reached if after ConnectionBind there is more data.
    PendingData(Vec<u8>, SocketAddr),
    // peer address
    Passthrough(SocketAddr),
}

impl TurnClientTcp {
    /// Allocate an address on a TURN server to relay data to and from peers.
    ///
    /// # Examples
    /// ```
    /// # use turn_types::TurnCredentials;
    /// # use turn_client_proto::prelude::*;
    /// # use turn_client_proto::tcp::TurnClientTcp;
    /// # use turn_client_proto::api::TurnConfig;
    /// # use stun_proto::types::TransportType;
    /// let credentials = TurnCredentials::new("tuser", "tpass");
    /// let mut config = TurnConfig::new(credentials);
    /// // The transport protocol of the allocation on the TURN server.
    /// config.set_allocation_transport(TransportType::Udp);
    /// let local_addr = "192.168.0.1:4000".parse().unwrap();
    /// let remote_addr = "10.0.0.1:3478".parse().unwrap();
    /// let client = TurnClientTcp::allocate(
    ///     local_addr,
    ///     remote_addr,
    ///     config,
    /// );
    /// assert_eq!(client.transport(), TransportType::Tcp);
    /// assert_eq!(client.local_addr(), local_addr);
    /// assert_eq!(client.remote_addr(), remote_addr);
    /// ```
    #[tracing::instrument(
        name = "turn_client_tcp_allocate"
        skip(config),
        fields(
            allocation_transport = %config.allocation_transport(),
        )
    )]
    pub fn allocate(local_addr: SocketAddr, remote_addr: SocketAddr, config: TurnConfig) -> Self {
        let stun_agent = StunAgent::builder(TransportType::Tcp, local_addr)
            .remote_addr(remote_addr)
            .build();

        Self {
            protocol: TurnClientProtocol::new(stun_agent, config),
            incoming_tcp_buffers: BTreeMap::from([(
                (local_addr, remote_addr),
                TcpBuffer::Control(TurnTcpBuffer::new()),
            )]),
        }
    }
}

impl TurnClientApi for TurnClientTcp {
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
        self.protocol.poll(now)
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
        self.protocol.poll_transmit(now)
    }

    fn poll_event(&mut self) -> Option<TurnEvent> {
        self.protocol.poll_event()
    }

    fn delete(&mut self, now: Instant) -> Result<(), DeleteError> {
        self.protocol.delete(now)
    }

    fn create_permission(
        &mut self,
        transport: TransportType,
        peer_addr: IpAddr,
        now: Instant,
    ) -> Result<(), CreatePermissionError> {
        self.protocol.create_permission(transport, peer_addr, now)
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
        self.protocol.bind_channel(transport, peer_addr, now)
    }

    fn tcp_connect(&mut self, peer_addr: SocketAddr, now: Instant) -> Result<(), TcpConnectError> {
        self.protocol.tcp_connect(peer_addr, now)
    }

    fn allocated_tcp_socket(
        &mut self,
        id: u32,
        five_tuple: Socket5Tuple,
        peer_addr: SocketAddr,
        local_addr: Option<SocketAddr>,
        now: Instant,
    ) -> Result<(), TcpAllocateError> {
        self.protocol
            .allocated_tcp_socket(id, five_tuple, peer_addr, local_addr, now)?;
        if let Some(local_addr) = local_addr {
            self.incoming_tcp_buffers.insert(
                (local_addr, self.remote_addr()),
                TcpBuffer::WaitingForConnectionBindResponse(TurnTcpBuffer::new()),
            );
        }
        Ok(())
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
        self.protocol.send_to(transport, to, data, now).map(Some)
    }

    fn recv<T: AsRef<[u8]> + core::fmt::Debug>(
        &mut self,
        transmit: Transmit<T>,
        now: Instant,
    ) -> TurnRecvRet<T> {
        /* is this data for our client? */
        if self.transport() != transmit.transport || transmit.from != self.remote_addr() {
            trace!(
                "received data not directed at us ({:?}) but for {:?}!",
                self.local_addr(),
                transmit.to
            );
            return TurnRecvRet::Ignored(transmit);
        }

        let Some(tcp_buffer) = self
            .incoming_tcp_buffers
            .get_mut(&(transmit.to, transmit.from))
        else {
            return TurnRecvRet::Ignored(transmit);
        };

        if transmit.data.as_ref().is_empty() {
            self.protocol.tcp_closed(transmit.to, transmit.from, now);
            self.incoming_tcp_buffers
                .remove(&(transmit.to, transmit.from));
            return TurnRecvRet::Handled;
        }

        let tcp_buffer = match tcp_buffer {
            TcpBuffer::WaitingForConnectionBindResponse(buffer) => {
                match buffer.incoming_tcp(transmit) {
                    None => return TurnRecvRet::Handled,
                    // protocol violation
                    Some(
                        IncomingTcp::CompleteChannel(transmit, _)
                        | IncomingTcp::StoredChannel(_, transmit),
                    ) => {
                        return TurnRecvRet::Ignored(transmit);
                    }
                    Some(IncomingTcp::CompleteMessage(transmit, msg_range)) => {
                        let Ok(msg) = Message::from_bytes(
                            &transmit.data.as_ref()[msg_range.start..msg_range.end],
                        ) else {
                            // protocol violation
                            return TurnRecvRet::Handled;
                        };
                        let msg_transmit =
                            Transmit::new(msg, transmit.transport, transmit.from, transmit.to);
                        if let TurnProtocolRecv::TcpConnectionBound { peer_addr } =
                            self.protocol.handle_message(msg_transmit, now)
                        {
                            let data_len = transmit.data.as_ref().len();
                            if msg_range.end < data_len {
                                trace!(
                                    "Have {} bytes after success ConnectionBind from peer",
                                    data_len - msg_range.end
                                );
                                *tcp_buffer = TcpBuffer::PendingData(
                                    transmit.data.as_ref()[msg_range.end..].to_vec(),
                                    peer_addr,
                                );
                            } else {
                                *tcp_buffer = TcpBuffer::Passthrough(peer_addr);
                            }
                            return TurnRecvRet::Handled;
                        } else {
                            // possible protocol violation
                            return TurnRecvRet::Handled;
                        }
                    }
                    Some(IncomingTcp::StoredMessage(msg_data, transmit)) => {
                        let Ok(msg) = Message::from_bytes(&msg_data) else {
                            return TurnRecvRet::Handled;
                        };
                        let msg_transmit =
                            Transmit::new(msg, transmit.transport, transmit.from, transmit.to);
                        if let TurnProtocolRecv::TcpConnectionBound { peer_addr } =
                            self.protocol.handle_message(msg_transmit, now)
                        {
                            if buffer.is_empty() {
                                *tcp_buffer = TcpBuffer::Passthrough(peer_addr);
                            } else {
                                let mut new_buffer = TurnTcpBuffer::new();
                                core::mem::swap(buffer, &mut new_buffer);
                                let data = new_buffer.into_inner();
                                *tcp_buffer = TcpBuffer::PendingData(data, peer_addr);
                            }
                        }
                        return TurnRecvRet::Handled;
                    }
                }
            }
            TcpBuffer::PendingData(data, peer) => {
                let mut replace = Vec::default();
                core::mem::swap(&mut replace, data);
                replace.extend_from_slice(transmit.data.as_ref());
                let ret = TurnRecvRet::PeerData(TurnPeerData {
                    data: DataRangeOrOwned::Owned(replace),
                    transport: transmit.transport,
                    peer: *peer,
                });
                *tcp_buffer = TcpBuffer::Passthrough(*peer);
                return ret;
            }
            TcpBuffer::Passthrough(peer) => {
                return TurnRecvRet::PeerData(TurnPeerData {
                    data: DataRangeOrOwned::Range {
                        range: 0..transmit.data.as_ref().len(),
                        data: transmit.data,
                    },
                    transport: transmit.transport,
                    peer: *peer,
                });
            }
            TcpBuffer::Control(tcp_buffer) => tcp_buffer,
        };

        let ret = match tcp_buffer.incoming_tcp(transmit) {
            None => TurnRecvRet::Handled,
            Some(IncomingTcp::CompleteMessage(transmit, msg_range)) => {
                let Ok(msg) =
                    Message::from_bytes(&transmit.data.as_ref()[msg_range.start..msg_range.end])
                else {
                    return TurnRecvRet::Handled;
                };
                let msg_transmit =
                    Transmit::new(msg, transmit.transport, transmit.from, transmit.to);
                TurnRecvRet::from_protocol_recv_subrange(
                    self.protocol.handle_message(msg_transmit, now),
                    transmit,
                    msg_range.start,
                )
            }
            Some(IncomingTcp::CompleteChannel(transmit, range)) => {
                let channel =
                    ChannelData::parse(&transmit.data.as_ref()[range.start..range.end]).unwrap();
                match self.protocol.handle_channel(channel, now) {
                    // XXX: Ignored should probably produce an error for TCP
                    TurnProtocolChannelRecv::Ignored => TurnRecvRet::Ignored(transmit),
                    TurnProtocolChannelRecv::PeerData {
                        range,
                        transport,
                        peer,
                    } => TurnRecvRet::PeerData(TurnPeerData {
                        data: DataRangeOrOwned::Range {
                            data: transmit.data,
                            range,
                        },
                        transport,
                        peer,
                    }),
                }
            }
            Some(IncomingTcp::StoredMessage(msg_data, transmit)) => {
                let Ok(msg) = Message::from_bytes(&msg_data) else {
                    return TurnRecvRet::Handled;
                };
                let msg_transmit =
                    Transmit::new(msg, transmit.transport, transmit.from, transmit.to);
                TurnRecvRet::from_protocol_recv_stored(
                    self.protocol.handle_message(msg_transmit, now),
                    transmit,
                    msg_data,
                )
            }
            Some(IncomingTcp::StoredChannel(data, transmit)) => {
                let channel = ChannelData::parse(&data).unwrap();
                match self.protocol.handle_channel(channel, now) {
                    // XXX: Ignored should probably produce an error for TCP
                    TurnProtocolChannelRecv::Ignored => TurnRecvRet::Ignored(transmit),
                    TurnProtocolChannelRecv::PeerData {
                        range,
                        transport,
                        peer,
                    } => TurnRecvRet::PeerData(TurnPeerData {
                        data: DataRangeOrOwned::Owned(ensure_data_owned(data, range)),
                        transport,
                        peer,
                    }),
                }
            }
        };

        if matches!(ret, TurnRecvRet::Handled | TurnRecvRet::Ignored(_)) {
            if let Some(TurnPeerData {
                data,
                transport,
                peer,
            }) = self.poll_recv(now)
            {
                return TurnRecvRet::PeerData(TurnPeerData {
                    data: data.into_owned(),
                    transport,
                    peer,
                });
            }
        }
        ret
    }

    fn poll_recv(&mut self, now: Instant) -> Option<TurnPeerData<Vec<u8>>> {
        for ((local_addr, remote_addr), tcp_buffer) in self.incoming_tcp_buffers.iter_mut() {
            match tcp_buffer {
                TcpBuffer::Passthrough(_) => continue,
                TcpBuffer::PendingData(data, peer) => {
                    let mut replace = Vec::default();
                    core::mem::swap(&mut replace, data);
                    let ret = Some(TurnPeerData {
                        data: DataRangeOrOwned::Owned(replace),
                        transport: TransportType::Tcp,
                        peer: *peer,
                    });
                    *tcp_buffer = TcpBuffer::Passthrough(*peer);
                    return ret;
                }
                TcpBuffer::WaitingForConnectionBindResponse(buffer) => {
                    if let Some(recv) = buffer.poll_recv() {
                        match recv {
                            // protocol violation
                            StoredTcp::Channel(_) => continue,
                            StoredTcp::Message(msg_data) => {
                                let Ok(msg) = Message::from_bytes(&msg_data) else {
                                    continue;
                                };
                                if let TurnProtocolRecv::TcpConnectionBound { peer_addr } =
                                    self.protocol.handle_message(
                                        Transmit::new(
                                            msg,
                                            TransportType::Tcp,
                                            *remote_addr,
                                            *local_addr,
                                        ),
                                        now,
                                    )
                                {
                                    if buffer.is_empty() {
                                        *tcp_buffer = TcpBuffer::Passthrough(peer_addr);
                                    } else {
                                        let mut new_buffer = TurnTcpBuffer::new();
                                        core::mem::swap(buffer, &mut new_buffer);
                                        let data = new_buffer.into_inner();
                                        *tcp_buffer = TcpBuffer::PendingData(data, peer_addr);
                                    }
                                }
                            }
                        }
                    }
                }
                TcpBuffer::Control(buffer) => {
                    while let Some(recv) = buffer.poll_recv() {
                        match recv {
                            StoredTcp::Message(msg_data) => {
                                let Ok(msg) = Message::from_bytes(&msg_data) else {
                                    continue;
                                };
                                let msg_transmit = Transmit::new(
                                    msg,
                                    TransportType::Tcp,
                                    *remote_addr,
                                    *local_addr,
                                );
                                if let TurnProtocolRecv::PeerData {
                                    range,
                                    transport,
                                    peer,
                                } = self.protocol.handle_message(msg_transmit, now)
                                {
                                    return Some(TurnPeerData {
                                        data: DataRangeOrOwned::Range {
                                            data: msg_data,
                                            range,
                                        },
                                        transport,
                                        peer,
                                    });
                                }
                            }
                            StoredTcp::Channel(data) => {
                                let Ok(channel) = ChannelData::parse(&data) else {
                                    continue;
                                };
                                if let TurnProtocolChannelRecv::PeerData {
                                    range,
                                    transport,
                                    peer,
                                } = self.protocol.handle_channel(channel, now)
                                {
                                    return Some(TurnPeerData {
                                        data: DataRangeOrOwned::Range { data, range },
                                        transport,
                                        peer,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
        None
    }

    fn protocol_error(&mut self) {
        self.protocol.protocol_error()
    }
}

pub(crate) fn ensure_data_owned(data: Vec<u8>, range: Range<usize>) -> Vec<u8> {
    if range.start == 0 && range.end == data.len() {
        data
    } else {
        data[range.start..range.end].to_vec()
    }
}
