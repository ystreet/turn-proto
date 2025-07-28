// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use byteorder::{BigEndian, ByteOrder};

use stun_types::{attribute::*, message::StunParseError};

/// The [`ReservationToken`] [`Attribute`].
///
/// Reserves an allocation on the TURN server or acquires an already existing allocation on the
/// TURN server.
///
/// Reference: [RFC5766 Section 14.9](https://datatracker.ietf.org/doc/html/rfc5766#section-14.9).
#[derive(Debug, Clone)]
pub struct ReservationToken {
    token: u64,
}

impl AttributeStaticType for ReservationToken {
    const TYPE: AttributeType = AttributeType::new(0x0022);
}

impl Attribute for ReservationToken {
    fn get_type(&self) -> AttributeType {
        Self::TYPE
    }

    fn length(&self) -> u16 {
        8
    }
}

impl AttributeWrite for ReservationToken {
    fn to_raw(&self) -> RawAttribute<'_> {
        let mut data = vec![0; 8];
        BigEndian::write_u64(&mut data, self.token);
        RawAttribute::new(self.get_type(), &data).into_owned()
    }

    fn write_into_unchecked(&self, dest: &mut [u8]) {
        self.write_header_unchecked(dest);
        BigEndian::write_u64(&mut dest[4..12], self.token);
    }
}

impl AttributeFromRaw<'_> for ReservationToken {
    fn from_raw_ref(raw: &RawAttribute) -> Result<Self, StunParseError>
    where
        Self: Sized,
    {
        Self::try_from(raw)
    }
}

impl TryFrom<&RawAttribute<'_>> for ReservationToken {
    type Error = StunParseError;
    fn try_from(raw: &RawAttribute) -> Result<Self, Self::Error> {
        raw.check_type_and_len(Self::TYPE, 8..=8)?;
        Ok(Self {
            token: BigEndian::read_u64(&raw.value),
        })
    }
}

impl ReservationToken {
    /// Create a new [`ReservationToken`] [`Attribute`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use turn_types::attribute::*;
    /// let token = ReservationToken::new(100);
    /// assert_eq!(token.token(), 100);
    /// ```
    pub fn new(token: u64) -> Self {
        Self { token }
    }

    /// Retrieve the token stored in a [`ReservationToken`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use turn_types::attribute::*;
    /// let token = ReservationToken::new(100);
    /// assert_eq!(token.token(), 100);
    /// ```
    pub fn token(&self) -> u64 {
        self.token
    }
}

impl std::fmt::Display for ReservationToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: 0x{:#x}", self.get_type(), self.token())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use byteorder::{BigEndian, ByteOrder};

    #[test]
    fn reservation_token() {
        let _log = crate::tests::test_init_log();
        let token = ReservationToken::new(200);
        assert_eq!(token.get_type(), ReservationToken::TYPE);
        assert_eq!(token.token(), 200);
        let raw: RawAttribute = token.to_raw();
        println!("{}", raw);
        assert_eq!(raw.get_type(), ReservationToken::TYPE);
        let token2 = ReservationToken::try_from(&raw).unwrap();
        assert_eq!(token2.get_type(), ReservationToken::TYPE);
        assert_eq!(token2.token(), 200);
        // provide incorrectly typed data
        let mut data: Vec<_> = raw.into();
        BigEndian::write_u16(&mut data[0..2], 0);
        assert!(matches!(
            ReservationToken::try_from(&RawAttribute::from_bytes(data.as_ref()).unwrap()),
            Err(StunParseError::WrongAttributeImplementation)
        ));
    }
}
