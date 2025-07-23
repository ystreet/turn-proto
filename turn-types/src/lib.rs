// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![deny(missing_debug_implementations)]
#![deny(missing_docs)]

//! # turn-types
//!
//! `turn-types` provides an implementation for two things:
//! 1. TURN specific STUN attributes using the `stun-types` crate.
//! 2. Parsing to and from the actual data sent and received on the wire.
//!
//! This is based on the following standards:
//! - [RFC5766]
//!
//! [RFC5766]: https://tools.ietf.org/html/rfc5766

pub use stun_types as stun;
use stun_types::message::LongTermCredentials;
pub mod attribute;
pub mod channel;
pub mod message;
pub mod tcp;

/// Initialize the library.
pub fn debug_init() {
    attribute::attributes_init();
}

/// Credentials used for a TURN user.
#[derive(Debug, Clone)]
pub struct TurnCredentials {
    username: String,
    password: String,
}

impl TurnCredentials {
    /// Transform these credentials into some `LongTermCredentials` for use in a STUN context.
    pub fn into_long_term_credentials(self, realm: &str) -> LongTermCredentials {
        LongTermCredentials::new(self.username, self.password, realm.to_string())
    }

    /// Construct a new set of [`TurnCredentials`]
    pub fn new(username: &str, password: &str) -> Self {
        Self {
            username: username.to_owned(),
            password: password.to_owned(),
        }
    }

    /// The username of the credentials.
    pub fn username(&self) -> &str {
        &self.username
    }

    /// The password of the credentials.
    pub fn password(&self) -> &str {
        &self.password
    }
}

#[cfg(test)]
mod tests {
    use tracing::subscriber::DefaultGuard;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::Layer;

    pub fn test_init_log() -> DefaultGuard {
        crate::debug_init();
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
