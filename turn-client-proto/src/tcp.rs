// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! # TCP TURN client
//!
//! An implementation of a TURN client suitable for TCP connections.

use std::net::{IpAddr, SocketAddr};
use std::ops::Range;
use std::time::Instant;

use stun_proto::agent::{StunAgent, Transmit};
use stun_proto::types::data::Data;

use stun_proto::types::TransportType;

use turn_types::channel::ChannelData;
pub use turn_types::tcp::{IncomingTcp, StoredTcp, TurnTcpBuffer};
use turn_types::TurnCredentials;

use tracing::{trace, warn};

use crate::api::{
    DataRangeOrOwned, DelayedMessageOrChannelSend, TransmitBuild, TurnClientApi, TurnPeerData,
};
use crate::protocol::{SendError, TurnClientProtocol, TurnProtocolChannelRecv, TurnProtocolRecv};

pub use crate::api::{
    BindChannelError, CreatePermissionError, DeleteError, TurnEvent, TurnPollRet, TurnRecvRet,
};

/// A TURN client.
#[derive(Debug)]
pub struct TurnClientTcp {
    protocol: TurnClientProtocol,
    incoming_tcp_buffer: TurnTcpBuffer,
}

impl TurnClientTcp {
    /// Allocate an address on a TURN server to relay data to and from peers.
    ///
    /// # Examples
    /// ```
    /// # use turn_types::TurnCredentials;
    /// # use turn_client_proto::prelude::*;
    /// # use turn_client_proto::tcp::TurnClientTcp;
    /// # use stun_proto::types::TransportType;
    /// let credentials = TurnCredentials::new("tuser", "tpass");
    /// let local_addr = "192.168.0.1:4000".parse().unwrap();
    /// let remote_addr = "10.0.0.1:3478".parse().unwrap();
    /// let client = TurnClientTcp::allocate(local_addr, remote_addr, credentials);
    /// assert_eq!(client.transport(), TransportType::Tcp);
    /// assert_eq!(client.local_addr(), local_addr);
    /// assert_eq!(client.remote_addr(), remote_addr);
    /// ```
    #[tracing::instrument(
        name = "turn_client_allocate"
        skip(credentials)
    )]
    pub fn allocate(
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        credentials: TurnCredentials,
    ) -> Self {
        let stun_agent = StunAgent::builder(TransportType::Tcp, local_addr)
            .remote_addr(remote_addr)
            .build();

        Self {
            protocol: TurnClientProtocol::new(stun_agent, credentials),
            incoming_tcp_buffer: TurnTcpBuffer::new(),
        }
    }
}

impl TurnClientApi for TurnClientTcp {
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

    fn send_to<T: AsRef<[u8]> + std::fmt::Debug>(
        &mut self,
        transport: TransportType,
        to: SocketAddr,
        data: T,
        now: Instant,
    ) -> Result<Option<TransmitBuild<DelayedMessageOrChannelSend<T>>>, Self::SendError> {
        self.protocol.send_to(transport, to, data, now).map(Some)
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

        let ret = match self.incoming_tcp_buffer.incoming_tcp(transmit) {
            IncomingTcp::NeedMoreData => TurnRecvRet::Handled,
            IncomingTcp::CompleteMessage(transmit, msg_range) => {
                match self.protocol.handle_message(transmit.data, now) {
                    TurnProtocolRecv::Handled => TurnRecvRet::Handled,
                    // XXX: Ignored should probably produce an error for TCP
                    TurnProtocolRecv::Ignored(_data) => TurnRecvRet::Handled,
                    TurnProtocolRecv::PeerData {
                        data,
                        range,
                        transport,
                        peer,
                    } => TurnRecvRet::PeerData(TurnPeerData {
                        data: DataRangeOrOwned::Range {
                            data,
                            range: msg_range.start + range.start..msg_range.start + range.end,
                        },
                        transport,
                        peer,
                    }),
                }
            }
            IncomingTcp::CompleteChannel(transmit, range) => {
                let channel =
                    ChannelData::parse(&transmit.data.as_ref()[range.start..range.end]).unwrap();
                match self.protocol.handle_channel(channel, now) {
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
            IncomingTcp::StoredMessage(msg, transmit) => {
                protocol_recv_to_api(self.protocol.handle_message(msg, now), transmit)
            }
            IncomingTcp::StoredChannel(data, transmit) => {
                let channel = ChannelData::parse(&data).unwrap();
                match self.protocol.handle_channel(channel, now) {
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
        while let Some(recv) = self.incoming_tcp_buffer.poll_recv() {
            match recv {
                StoredTcp::Message(msg) => {
                    if let TurnProtocolRecv::PeerData {
                        data,
                        range,
                        transport,
                        peer,
                    } = self.protocol.handle_message(msg, now)
                    {
                        return Some(TurnPeerData {
                            data: DataRangeOrOwned::Range { data, range },
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
        None
    }
}

fn protocol_recv_to_api<T: AsRef<[u8]> + std::fmt::Debug>(
    recv: TurnProtocolRecv<Vec<u8>>,
    original: Transmit<T>,
) -> TurnRecvRet<T> {
    match recv {
        TurnProtocolRecv::Handled => TurnRecvRet::Handled,
        TurnProtocolRecv::Ignored(_) => TurnRecvRet::Ignored(original),
        TurnProtocolRecv::PeerData {
            data,
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

pub(crate) fn ensure_data_owned(data: Vec<u8>, range: Range<usize>) -> Vec<u8> {
    if range.start == 0 && range.end == data.len() {
        data
    } else {
        data[range.start..range.end].to_vec()
    }
}

#[cfg(test)]
mod tests {
    use turn_server_proto::api::TurnServerApi;
    use turn_server_proto::server::TurnServer;

    use crate::{
        api::tests::{
            turn_allocate_delete, turn_allocate_expire_client, turn_allocate_expire_server,
            turn_allocate_permission, turn_allocate_refresh, turn_channel_bind,
            turn_channel_bind_refresh, turn_create_permission_refresh,
            turn_create_permission_timeout, turn_offpath_data, turn_peer_incoming_stun, TurnTest,
        },
        client::TurnClient,
    };

    use super::*;

    fn turn_tcp_new(
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        credentials: TurnCredentials,
    ) -> TurnClient {
        TurnClientTcp::allocate(local_addr, remote_addr, credentials).into()
    }

    fn turn_server_tcp_new(listen_addr: SocketAddr, realm: String) -> TurnServer {
        TurnServer::new(TransportType::Tcp, listen_addr, realm)
    }

    fn create_test(split_transmit_bytes: usize) -> TurnTest<TurnClient, TurnServer> {
        TurnTest::<TurnClient, TurnServer>::builder()
            .split_transmit_bytes(split_transmit_bytes)
            .build(turn_tcp_new, turn_server_tcp_new)
    }

    static TRANSMIT_SPLITS: [usize; 3] = [0, 3, 6];

    #[test]
    fn test_turn_tcp_allocate_udp_permission() {
        let _log = crate::tests::test_init_log();
        let now = Instant::now();
        for split in TRANSMIT_SPLITS {
            let mut test = create_test(split);
            turn_allocate_permission(&mut test, now);
        }
    }

    #[test]
    fn test_tcp_turn_allocate_expire_server() {
        let _log = crate::tests::test_init_log();
        let now = Instant::now();
        for split in TRANSMIT_SPLITS {
            let mut test = create_test(split);
            turn_allocate_expire_server(&mut test, now);
        }
    }

    #[test]
    fn test_tcp_turn_allocate_expire_client() {
        let _log = crate::tests::test_init_log();
        let now = Instant::now();
        for split in TRANSMIT_SPLITS {
            let mut test = create_test(split);
            turn_allocate_expire_client(&mut test, now);
        }
    }

    #[test]
    fn test_tcp_turn_allocate_refresh() {
        let _log = crate::tests::test_init_log();
        let now = Instant::now();
        for split in TRANSMIT_SPLITS {
            let mut test = create_test(split);
            turn_allocate_refresh(&mut test, now);
        }
    }

    #[test]
    fn test_tcp_turn_allocate_delete() {
        let _log = crate::tests::test_init_log();
        let now = Instant::now();
        for split in TRANSMIT_SPLITS {
            let mut test = create_test(split);
            turn_allocate_delete(&mut test, now);
        }
    }

    #[test]
    fn test_tcp_turn_channel_bind() {
        let _log = crate::tests::test_init_log();
        let now = Instant::now();
        for split in TRANSMIT_SPLITS {
            let mut test = create_test(split);
            turn_channel_bind(&mut test, now);
        }
    }

    #[test]
    fn test_tcp_turn_peer_incoming_stun() {
        let _log = crate::tests::test_init_log();
        let now = Instant::now();
        for split in TRANSMIT_SPLITS {
            let mut test = create_test(split);
            turn_peer_incoming_stun(&mut test, now);
        }
    }

    #[test]
    fn test_tcp_turn_create_permission_refresh() {
        let _log = crate::tests::test_init_log();
        let now = Instant::now();
        for split in TRANSMIT_SPLITS {
            let mut test = create_test(split);
            turn_create_permission_refresh(&mut test, now);
        }
    }

    #[test]
    fn test_tcp_turn_create_permission_timeout() {
        let _log = crate::tests::test_init_log();
        let now = Instant::now();
        for split in TRANSMIT_SPLITS {
            let mut test = create_test(split);
            turn_create_permission_timeout(&mut test, now);
        }
    }

    #[test]
    fn test_tcp_turn_channel_bind_refresh() {
        let _log = crate::tests::test_init_log();
        let now = Instant::now();
        for split in TRANSMIT_SPLITS {
            let mut test = create_test(split);
            turn_channel_bind_refresh(&mut test, now);
        }
    }

    #[test]
    fn test_tcp_offpath_data() {
        let _log = crate::tests::test_init_log();
        let now = Instant::now();
        let mut test = create_test(0);
        turn_offpath_data(&mut test, now);
    }

    fn peer_transmit<A: TurnClientApi, S: TurnServerApi>(
        test: &TurnTest<A, S>,
        data: &[u8],
    ) -> Transmit<Vec<u8>> {
        Transmit::new(
            data.to_vec(),
            TransportType::Udp,
            test.peer_addr,
            test.turn_alloc_addr,
        )
    }

    fn combine_transmit<T: AsRef<[u8]> + std::fmt::Debug, R: AsRef<[u8]> + std::fmt::Debug>(
        a: &Transmit<T>,
        b: &Transmit<R>,
    ) -> Transmit<Vec<u8>> {
        assert_eq!(a.transport, b.transport);
        assert_eq!(a.from, b.from);
        assert_eq!(a.to, b.to);
        let mut data = a.data.as_ref().to_vec();
        data.extend_from_slice(b.data.as_ref());
        Transmit::new(data, a.transport, a.from, a.to)
    }

    #[test]
    fn test_tcp_combined_message_channel() {
        let _log = crate::tests::test_init_log();
        let now = Instant::now();
        let mut test = create_test(0);
        turn_allocate_permission(&mut test, now);
        let TurnPollRet::WaitUntil(now) = test.client.poll(now) else {
            unreachable!();
        };
        let transmit = test.client.poll_transmit(now).unwrap();
        let msg_reply = test.server.recv(transmit, now).unwrap();
        let peer_data = [8; 9];
        let peer_transmit = test
            .server
            .recv(peer_transmit(&test, peer_data.as_slice()), now)
            .unwrap();
        let TurnRecvRet::PeerData(peer) = test
            .client
            .recv(combine_transmit(&msg_reply, &peer_transmit), now)
        else {
            unreachable!();
        };
        assert_eq!(peer.data(), peer_data.as_slice());
    }

    #[test]
    fn test_tcp_combined_channel_message() {
        let _log = crate::tests::test_init_log();
        let now = Instant::now();
        let mut test = create_test(0);
        turn_allocate_permission(&mut test, now);
        tracing::error!("{:?}", test.client);
        let TurnPollRet::WaitUntil(now) = test.client.poll(now) else {
            unreachable!();
        };
        let transmit = test.client.poll_transmit(now).unwrap();
        let msg_reply = test.server.recv(transmit, now).unwrap();
        let peer_data = [8; 9];
        let peer_transmit = test
            .server
            .recv(peer_transmit(&test, peer_data.as_slice()), now)
            .unwrap();
        let TurnRecvRet::PeerData(peer) = test
            .client
            .recv(combine_transmit(&peer_transmit, &msg_reply), now)
        else {
            unreachable!();
        };
        assert_eq!(peer.data(), peer_data.as_slice());
    }
}
