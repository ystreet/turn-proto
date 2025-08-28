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
    let peer_addr = "127.0.0.1:1".parse().unwrap();

    test.server.recv(
        Transmit::new(
            data,
            TransportType::Udp,
            peer_addr,
            test.server.listen_address(),
        ),
        now,
    );

    test.server.recv_icmp(AddressFamily::IPV4, data, now);
    test.server.recv_icmp(AddressFamily::IPV6, data, now);
});
