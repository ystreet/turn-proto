#![no_main]
use std::sync::Once;

use libfuzzer_sys::fuzz_target;

use tracing_subscriber::EnvFilter;
use turn_client_proto::stun::agent::Transmit;

include!("helpers/test_client.rs");

pub fn debug_init() {
    static TRACING: Once = Once::new();

    TRACING.call_once(|| {
        turn_client_proto::types::debug_init();
        if let Ok(filter) = EnvFilter::try_from_default_env() {
            tracing_subscriber::fmt().with_env_filter(filter).init();
        }
    });
}

fuzz_target!(|data: &[u8]| {
    let now = Instant::ZERO;
    debug_init();
    let mut test = TestClient::new();
    test.allocate();
    let peer_addr_ipv4 = "10.0.0.4:44444".parse().unwrap();
    test.create_permission(peer_addr_ipv4);
    let peer_addr_ipv6 = "[fe80::1]:44444".parse().unwrap();
    test.create_permission(peer_addr_ipv6);

    if let Some(transmit) = test.server.recv(
        Transmit::new(data, TransportType::Udp, peer_addr_ipv6, test.relayed_ipv6),
        now,
    ) {
        test.client.recv(transmit, now);
    }
    let client_transmit = test
        .server
        .recv(
            Transmit::new(data, TransportType::Udp, peer_addr_ipv4, test.relayed_ipv4),
            now,
        )
        .unwrap();
    test.client.recv(client_transmit, now);
    test.client.recv(
        Transmit::new(
            data,
            TransportType::Udp,
            test.server.listen_address(),
            test.client.local_addr(),
        ),
        now,
    );
});
