use core::net::SocketAddr;
use stun_types::TransportType;
use turn_client_proto::stun::Instant;
use turn_client_proto::api::TurnClientApi;
use turn_client_proto::client::TurnClient;
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
        let client = TurnClientUdp::allocate(
            client_addr,
            server_addr,
            credentials.clone(),
            &[AddressFamily::IPV4, AddressFamily::IPV6],
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

    fn allocate(&mut self) {
        let now = Instant::ZERO;
        // Initial allocate
        let transmit = self.client.poll_transmit(now).unwrap();
        let transmit = self.server.recv(transmit, now).unwrap().build();
        self.client.recv(transmit, now);
        // authenticated allocate
        let transmit = self.client.poll_transmit(now).unwrap();
        self.server.recv(transmit, now);
        for _ in 0..2 {
            let TurnServerPollRet::AllocateSocketUdp {
                transport,
                local_addr,
                remote_addr,
                family,
            } = self.server.poll(now) else {
                unreachable!();
            };
            match family {
                AddressFamily::IPV4 => self.server.allocated_udp_socket(
                    transport,
                    local_addr,
                    remote_addr,
                    family,
                    Ok(self.relayed_ipv4),
                    now,
                ),
                AddressFamily::IPV6 => self.server.allocated_udp_socket(
                    transport,
                    local_addr,
                    remote_addr,
                    family,
                    Ok(self.relayed_ipv6),
                    now,
                ),
            }
        }
        let transmit = self.server.poll_transmit(now).unwrap();
        self.client.recv(transmit, now);
    }

    fn create_permission(&mut self, addr: SocketAddr) {
        let now = Instant::ZERO;
        self.client
            .create_permission(TransportType::Udp, addr.ip(), now)
            .unwrap();
        let transmit = self.client.poll_transmit(now).unwrap();
        let transmit = self.server.recv(transmit, now).unwrap().build();
        self.client.recv(transmit, now);
    }
}
