// SPDX-FileCopyrightText: 2025 Matthew Waters <matthew@centricular.com>
//
// SPDX-License-Identifier: MIT OR Apache-2.0
#![no_main]
use std::sync::Once;

use libfuzzer_sys::fuzz_target;

#[macro_use]
extern crate tracing;
use tracing_subscriber::EnvFilter;

use turn_types::stun::message::{Message, MessageIntegrityCredentials};

#[derive(arbitrary::Arbitrary, Debug)]
struct DataAndCredentials<'data> {
    data: &'data [u8],
    credentials: MessageIntegrityCredentials,
}

pub fn debug_init() {
    static TRACING: Once = Once::new();

    TRACING.call_once(|| {
        turn_types::debug_init();
        if let Ok(filter) = EnvFilter::try_from_default_env() {
            tracing_subscriber::fmt().with_env_filter(filter).init();
        }
    });
}

fuzz_target!(|data_and_credentials: DataAndCredentials| {
    debug_init();
    let msg = Message::from_bytes(data_and_credentials.data);
    if let Ok(msg) = msg {
        debug!("generated {}", msg);
        let integrity_result = msg.validate_integrity(&data_and_credentials.credentials);
        debug!("integrity result {:?}", integrity_result);
    } else {
        debug!("generated {:?}", msg);
    }
});
