// SPDX-FileCopyrightText: 2025 Matthew Waters <matthew@centricular.com>
//
// SPDX-License-Identifier: MIT OR Apache-2.0
use core::net::SocketAddr;
use stun_types::TransportType;
use turn_client_proto::api::{TurnClientApi, TurnConfig, TurnEvent, TurnPollRet};
use turn_client_proto::client::TurnClient;
use turn_client_proto::stun::Instant;
use turn_client_proto::udp::TurnClientUdp;
use turn_server_proto::api::{TurnServerApi, TurnServerPollRet};
use turn_server_proto::server::TurnServer;
use turn_types::{AddressFamily, TurnCredentials};

struct TestClient {
    client: TurnClient,
    server: TurnServer,
    relayed_ipv4: SocketAddr,
    relayed_ipv6: SocketAddr,
}

impl TestClient {
    fn new() -> Self {
        let client_addr = "127.0.0.1:1".parse().unwrap();
        let server_addr = "127.0.0.1:3478".parse().unwrap();
        let credentials = TurnCredentials::new("tuser", "tpass");
        let mut server = TurnServer::new(
            stun_types::TransportType::Udp,
            server_addr,
            "realm".to_string(),
        );
        server.add_user(
            credentials.username().to_string(),
            credentials.password().to_string(),
        );
        let mut config = TurnConfig::new(credentials.clone());
        config.add_address_family(AddressFamily::IPV6);
        let client = TurnClientUdp::allocate(
            client_addr,
            server_addr,
            config,
        );
        let relayed_ipv4 = "10.0.0.2:2222".parse().unwrap();
        let relayed_ipv6 = "[fe80::1]:2222".parse().unwrap();
        Self {
            client: client.into(),
            server,
            relayed_ipv4,
            relayed_ipv6,
        }
    }

    fn client_advance(&mut self, now: Instant) -> Instant {
        let TurnPollRet::WaitUntil(expiry) = self.client.poll(now) else {
            unreachable!();
        };
        assert!(expiry > now);
        expiry
    }

    fn allocate(&mut self, now: Instant) -> Instant {
        // Initial allocate
        let transmit = self.client.poll_transmit(now).unwrap();
        let transmit = self.server.recv(transmit, now).unwrap().build();
        self.client.recv(transmit, now);
        // authenticated allocate

        let now = self.client_advance(now);
        let transmit = self.client.poll_transmit(now).unwrap();
        self.server.recv(transmit, now);
        for _ in 0..2 {
            let TurnServerPollRet::AllocateSocket {
                transport,
                listen_addr,
                client_addr,
                allocation_transport,
                family,
            } = self.server.poll(now)
            else {
                unreachable!();
            };
            match family {
                AddressFamily::IPV4 => self.server.allocated_socket(
                    transport,
                    listen_addr,
                    client_addr,
                    allocation_transport,
                    family,
                    Ok(self.relayed_ipv4),
                    now,
                ),
                AddressFamily::IPV6 => self.server.allocated_socket(
                    transport,
                    listen_addr,
                    client_addr,
                    allocation_transport,
                    family,
                    Ok(self.relayed_ipv6),
                    now,
                ),
            }
        }
        let transmit = self.server.poll_transmit(now).unwrap();
        self.client.recv(transmit, now);
        let Some(TurnEvent::AllocationCreated(_transport, _relayed_address)) =
            self.client.poll_event()
        else {
            unreachable!();
        };
        let Some(TurnEvent::AllocationCreated(_transport, _relayed_address)) =
            self.client.poll_event()
        else {
            unreachable!();
        };
        now
    }

    fn create_permission(&mut self, addr: SocketAddr, now: Instant) -> Instant {
        self.client
            .create_permission(TransportType::Udp, addr.ip(), now)
            .unwrap();
        let now = self.client_advance(now);
        let transmit = self.client.poll_transmit(now).unwrap();
        let transmit = self.server.recv(transmit, now).unwrap().build();
        self.client.recv(transmit, now);
        let Some(TurnEvent::PermissionCreated(_transport, _permission_ip)) =
            self.client.poll_event()
        else {
            unreachable!();
        };
        now
    }
}
