// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! # turn-server-proto
//!
//! `turn-server-proto` provides a sans-IO API for a TURN server communicating with many TURN clients.
//!
//! Relevant standards:
//! - [RFC5766]: Traversal Using Relays around NAT (TURN).
//! - [RFC6062]: Traversal Using Relays around NAT (TURN) Extensions for TCP Allocations
//! - [RFC6156]: Traversal Using Relays around NAT (TURN) Extension for IPv6
//! - [RFC8656]: Traversal Using Relays around NAT (TURN): Relay Extensions to Session
//!   Traversal Utilities for NAT (STUN)
//!
//! [RFC5766]: https://datatracker.ietf.org/doc/html/rfc5766
//! [RFC6062]: https://tools.ietf.org/html/rfc6062
//! [RFC6156]: https://tools.ietf.org/html/rfc6156
//! [RFC8656]: https://tools.ietf.org/html/rfc8656

#![deny(missing_debug_implementations)]
#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![no_std]

extern crate alloc;

#[cfg(any(feature = "std", test))]
extern crate std;

pub mod api;
pub mod server;

#[cfg(feature = "rustls")]
pub mod rustls;

#[cfg(feature = "openssl")]
pub mod openssl;

pub use stun_proto as stun;
pub use turn_types as types;

#[cfg(test)]
mod tests {
    use tracing::subscriber::DefaultGuard;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::Layer;

    pub fn test_init_log() -> DefaultGuard {
        turn_types::debug_init();
        let level_filter = std::env::var("TURN_LOG")
            .or(std::env::var("RUST_LOG"))
            .ok()
            .and_then(|var| var.parse::<tracing_subscriber::filter::Targets>().ok())
            .unwrap_or(
                tracing_subscriber::filter::Targets::new().with_default(tracing::Level::TRACE),
            );
        let registry = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .with_file(true)
                .with_line_number(true)
                .with_level(true)
                .with_target(false)
                .with_test_writer()
                .with_filter(level_filter),
        );
        tracing::subscriber::set_default(registry)
    }
}
