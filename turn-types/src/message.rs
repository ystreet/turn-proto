// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.
//
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Module for TURN message types in addition to those specified by STUN.

use stun_types::message::Method;

/// The value of the Allocate message type.  Can only be used in a request message.
pub const ALLOCATE: Method = Method::new(0x0003);

/// The value of the Refresh message type.  Can only be used in a request message.
pub const REFRESH: Method = Method::new(0x0004);

/// The value of the Send message type.  Can only be used in an indication message.
pub const SEND: Method = Method::new(0x0006);

/// The value of the Data message type.  Can only be used in an indication message.
pub const DATA: Method = Method::new(0x0007);

/// The value of the CreatePermission message type.  Can only be used in request message.
pub const CREATE_PERMISSION: Method = Method::new(0x0008);

/// The value of the ChannelBind message type.  Can only be used in a request message.
pub const CHANNEL_BIND: Method = Method::new(0x0009);

/// The value of the Connect message type.  Can only be used in a request message.
pub const CONNECT: Method = Method::new(0x000a);

/// The value of the ConnectionBind message type.  Can only be used in a request message.
pub const CONNECTION_BIND: Method = Method::new(0x000b);

/// The value of the ConnectionAttempt message type.  Can only be used in a request message.
pub const CONNECTION_ATTEMPT: Method = Method::new(0x000c);

pub(crate) fn debug_init() {
    #[cfg(feature = "std")]
    {
        ALLOCATE.add_name("ALLOCATE");
        REFRESH.add_name("REFRESH");
        SEND.add_name("SEND");
        DATA.add_name("DATA");
        CREATE_PERMISSION.add_name("CREATE_PERMISSION");
        CHANNEL_BIND.add_name("CHANNEL_BIND");
        CONNECT.add_name("CONNECT");
        CONNECTION_BIND.add_name("CONNECTION_BIND");
        CONNECTION_ATTEMPT.add_name("CONNECTION_ATTEMPT");
    }
}
