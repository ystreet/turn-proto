// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use byteorder::{BigEndian, ByteOrder};
use stun_types::{attribute::*, message::StunParseError};

/// The [`ConnectionId`] [`Attribute`].
///
/// TCP Connection handling through a TURN server.
///
/// Reference: [RFC6062 Section 6.2.1](https://datatracker.ietf.org/doc/html/rfc6062#section-6.2.1).
#[derive(Debug, Clone)]
pub struct ConnectionId {
    id: u32,
}

impl AttributeStaticType for ConnectionId {
    const TYPE: AttributeType = AttributeType::new(0x002a);
}

impl Attribute for ConnectionId {
    fn get_type(&self) -> AttributeType {
        Self::TYPE
    }

    fn length(&self) -> u16 {
        4
    }
}

impl AttributeWrite for ConnectionId {
    fn to_raw(&self) -> RawAttribute<'_> {
        let mut data = [0; 4];
        BigEndian::write_u32(&mut data, self.id);
        RawAttribute::new(self.get_type(), &data).into_owned()
    }

    fn write_into_unchecked(&self, dest: &mut [u8]) {
        self.write_header_unchecked(dest);
        BigEndian::write_u32(&mut dest[4..8], self.id);
    }
}

impl AttributeFromRaw<'_> for ConnectionId {
    fn from_raw_ref(raw: &RawAttribute) -> Result<Self, StunParseError>
    where
        Self: Sized,
    {
        Self::try_from(raw)
    }
}

impl TryFrom<&RawAttribute<'_>> for ConnectionId {
    type Error = StunParseError;
    fn try_from(raw: &RawAttribute) -> Result<Self, Self::Error> {
        raw.check_type_and_len(Self::TYPE, 4..=4)?;
        Ok(Self {
            id: BigEndian::read_u32(&raw.value[..4]),
        })
    }
}

impl ConnectionId {
    /// Create a new [`ConnectionId`] [`Attribute`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use turn_types::attribute::*;
    /// let conn_id = ConnectionId::new(0x42);
    /// assert_eq!(conn_id.id(), 0x42);
    /// ```
    pub fn new(id: u32) -> Self {
        Self { id }
    }

    /// Retrieve the protocol stored in a [`ConnectionId`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use turn_types::attribute::*;
    /// let conn_id = ConnectionId::new(0x402);
    /// assert_eq!(conn_id.id(), 0x402);
    /// ```
    pub fn id(&self) -> u32 {
        self.id
    }
}

impl core::fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}: {:x?}", self.get_type(), self.id())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use byteorder::{BigEndian, ByteOrder};
    use std::println;

    #[test]
    fn requested_transport() {
        let _log = crate::tests::test_init_log();
        let trans = ConnectionId::new(17);
        assert_eq!(trans.get_type(), ConnectionId::TYPE);
        assert_eq!(trans.id(), 17);
        let raw: RawAttribute = trans.to_raw();
        println!("raw: {raw:?}");
        assert_eq!(raw.get_type(), ConnectionId::TYPE);
        let trans2 = ConnectionId::try_from(&raw).unwrap();
        assert_eq!(trans2.get_type(), ConnectionId::TYPE);
        assert_eq!(trans2.id(), 17);
        // provide incorrectly typed data
        let mut data: Vec<_> = raw.into();
        BigEndian::write_u16(&mut data[0..2], 0);
        assert!(matches!(
            ConnectionId::try_from(&RawAttribute::from_bytes(data.as_ref()).unwrap()),
            Err(StunParseError::WrongAttributeImplementation)
        ));
        let mut data = [0; 8];
        trans.write_into(&mut data).unwrap();
        let raw = RawAttribute::from_bytes(&data).unwrap();
        let trans2 = ConnectionId::from_raw_ref(&raw).unwrap();
        assert_eq!(trans.id(), trans2.id());
    }
}
