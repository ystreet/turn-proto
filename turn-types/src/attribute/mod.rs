// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! STUN Attributes for TURN.
//!
//! Provides for generating, parsing and manipulating STUN attributes as specified in TURN
//! [RFC5766].
//!
//! [RFC5766]: https://tools.ietf.org/html/rfc5766

mod address;
pub use address::{AddressFamily, RequestedAddressFamily, XorPeerAddress, XorRelayedAddress};
mod channel;
pub use channel::ChannelNumber;
mod data;
pub use data::Data;
mod even_port;
pub use even_port::EvenPort;
mod fragment;
pub use fragment::DontFragment;
mod lifetime;
pub use lifetime::Lifetime;
mod reservation;
pub use reservation::ReservationToken;
mod transport;
pub use transport::RequestedTransport;

pub(super) fn attributes_init() {
    use stun_types::prelude::*;

    stun_types::attribute_display!(XorPeerAddress);
    XorPeerAddress::TYPE.add_name("XorPeerAddress");
    stun_types::attribute_display!(XorRelayedAddress);
    XorRelayedAddress::TYPE.add_name("XorRelayedAddress");
    stun_types::attribute_display!(ChannelNumber);
    ChannelNumber::TYPE.add_name("ChannelNumber");
    stun_types::attribute_display!(Data);
    Data::TYPE.add_name("Data");
    stun_types::attribute_display!(EvenPort);
    EvenPort::TYPE.add_name("EvenPort");
    stun_types::attribute_display!(DontFragment);
    DontFragment::TYPE.add_name("DontFragment");
    stun_types::attribute_display!(Lifetime);
    Lifetime::TYPE.add_name("Lifetime");
    stun_types::attribute_display!(ReservationToken);
    ReservationToken::TYPE.add_name("ReservationToken");
    stun_types::attribute_display!(RequestedTransport);
    RequestedTransport::TYPE.add_name("RequestedTransport");
    stun_types::attribute_display!(RequestedAddressFamily);
    RequestedAddressFamily::TYPE.add_name("RequestedAddressFamily");
}
