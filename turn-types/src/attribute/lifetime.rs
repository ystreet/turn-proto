// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use byteorder::{BigEndian, ByteOrder};

use stun_types::{attribute::*, message::StunParseError};

/// The [`Lifetime`] [`Attribute`].
///
/// The lifetime (in seconds) of a TURN allocation on the server.
///
/// Reference: [RFC5766 Section 14.2](https://datatracker.ietf.org/doc/html/rfc5766#section-14.2).
#[derive(Debug, Clone)]
pub struct Lifetime {
    seconds: u32,
}

impl AttributeStaticType for Lifetime {
    const TYPE: AttributeType = AttributeType::new(0x000D);
}

impl Attribute for Lifetime {
    fn get_type(&self) -> AttributeType {
        Self::TYPE
    }

    fn length(&self) -> u16 {
        4
    }
}

impl AttributeWrite for Lifetime {
    fn to_raw(&self) -> RawAttribute<'_> {
        let mut buf = [0; 4];
        BigEndian::write_u32(&mut buf[..4], self.seconds);
        RawAttribute::new(self.get_type(), &buf).into_owned()
    }

    fn write_into_unchecked(&self, dest: &mut [u8]) {
        self.write_header_unchecked(dest);
        BigEndian::write_u32(&mut dest[4..8], self.seconds);
    }
}

impl AttributeFromRaw<'_> for Lifetime {
    fn from_raw_ref(raw: &RawAttribute) -> Result<Self, StunParseError>
    where
        Self: Sized,
    {
        Self::try_from(raw)
    }
}

impl TryFrom<&RawAttribute<'_>> for Lifetime {
    type Error = StunParseError;
    fn try_from(raw: &RawAttribute) -> Result<Self, Self::Error> {
        raw.check_type_and_len(Self::TYPE, 4..=4)?;
        Ok(Self {
            seconds: BigEndian::read_u32(&raw.value),
        })
    }
}

impl Lifetime {
    /// Create a new [`Lifetime`] [`Attribute`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use turn_types::attribute::*;
    /// let lifetime = Lifetime::new (42);
    /// assert_eq!(lifetime.seconds(), 42);
    /// ```
    pub fn new(seconds: u32) -> Self {
        Self { seconds }
    }

    /// The number of seconds stored in a [`Lifetime`] [`Attribute`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use turn_types::attribute::*;
    /// let lifetime = Lifetime::new (42);
    /// assert_eq!(lifetime.seconds(), 42);
    /// ```
    pub fn seconds(&self) -> u32 {
        self.seconds
    }
}

impl std::fmt::Display for Lifetime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: '{}'", self.get_type(), self.seconds)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use byteorder::{BigEndian, ByteOrder};

    #[test]
    fn lifetime() {
        let _log = crate::tests::test_init_log();
        let lifetime = Lifetime::new(600);
        assert_eq!(lifetime.get_type(), Lifetime::TYPE);
        assert_eq!(lifetime.seconds(), 600);
        let raw: RawAttribute = lifetime.to_raw();
        println!("{}", raw);
        assert_eq!(raw.get_type(), Lifetime::TYPE);
        let lifetime2 = Lifetime::try_from(&raw).unwrap();
        assert_eq!(lifetime2.get_type(), Lifetime::TYPE);
        assert_eq!(lifetime2.seconds(), 600);
        // provide incorrectly typed data
        let mut data: Vec<_> = raw.into();
        BigEndian::write_u16(&mut data[0..2], 0);
        assert!(matches!(
            Lifetime::try_from(&RawAttribute::from_bytes(data.as_ref()).unwrap()),
            Err(StunParseError::WrongAttributeImplementation)
        ));
    }
}
