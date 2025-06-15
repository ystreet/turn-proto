// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![deny(missing_debug_implementations)]

pub use stun_proto as stun;
pub use turn_types as types;
mod client;

pub use client::{
    BindChannelError, CreatePermissionError, DelayedChannelSend, DelayedMessageOrChannelSend,
    DelayedMessageSend, TurnClient, TurnEvent, TurnPollRet, TurnRecvRet,
};

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
