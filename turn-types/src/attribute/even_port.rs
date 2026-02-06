// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use stun_types::{attribute::*, message::StunParseError};

/// The [`EvenPort`] [`Attribute`].
///
/// Whether an even port is required to be allocated typically for RTP/RTCP purposes.
///
/// Reference: [RFC5766 Section 14.6](https://datatracker.ietf.org/doc/html/rfc5766#section-14.6).
#[derive(Debug, Clone)]
pub struct EvenPort {
    bits: u8,
}
impl AttributeStaticType for EvenPort {
    const TYPE: AttributeType = AttributeType::new(0x0018);
}

impl Attribute for EvenPort {
    fn get_type(&self) -> AttributeType {
        Self::TYPE
    }

    fn length(&self) -> u16 {
        1
    }
}

impl AttributeWrite for EvenPort {
    fn to_raw(&self) -> RawAttribute<'_> {
        RawAttribute::new(self.get_type(), &[self.bits]).into_owned()
    }

    fn write_into_unchecked(&self, dest: &mut [u8]) {
        self.write_header_unchecked(dest);
        dest[4] = self.bits;
        dest[5..self.padded_len()].fill(0)
    }
}

impl AttributeFromRaw<'_> for EvenPort {
    fn from_raw_ref(raw: &RawAttribute) -> Result<Self, StunParseError>
    where
        Self: Sized,
    {
        Self::try_from(raw)
    }
}

impl TryFrom<&RawAttribute<'_>> for EvenPort {
    type Error = StunParseError;
    fn try_from(raw: &RawAttribute) -> Result<Self, Self::Error> {
        raw.check_type_and_len(Self::TYPE, 1..=1)?;
        Ok(Self {
            bits: raw.value[0] & 0x80,
        })
    }
}

impl EvenPort {
    /// Create a new [`EvenPort`] [`Attribute`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use turn_types::attribute::*;
    /// let even_port = EvenPort::new(true);
    /// assert_eq!(even_port.requested(), true);
    /// ```
    pub fn new(request: bool) -> Self {
        let bits = if request { 0x80 } else { 0x00 };
        Self { bits }
    }

    /// Retrieve the address stored in a [`EvenPort`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use turn_types::attribute::*;
    /// let even_port = EvenPort::new(false);
    /// assert_eq!(even_port.requested(), false);
    /// ```
    pub fn requested(&self) -> bool {
        self.bits & 0x80 > 0
    }
}

impl core::fmt::Display for EvenPort {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}: {}", self.get_type(), self.requested())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{vec, vec::Vec};
    use byteorder::{BigEndian, ByteOrder};
    use tracing::trace;

    #[test]
    fn even_port() {
        let _log = crate::tests::test_init_log();
        let even_port = EvenPort::new(true);
        trace!("{even_port}");
        assert_eq!(even_port.get_type(), EvenPort::TYPE);
        assert!(even_port.requested());
    }

    #[test]
    fn even_port_raw() {
        let _log = crate::tests::test_init_log();
        let even_port = EvenPort::new(true);
        let raw = RawAttribute::from(&even_port);
        assert_eq!(raw.get_type(), EvenPort::TYPE);
        let even_port2 = EvenPort::try_from(&raw).unwrap();
        assert_eq!(even_port2.get_type(), EvenPort::TYPE);
        assert!(even_port2.requested());
    }

    #[test]
    fn even_port_raw_wrong_type() {
        let _log = crate::tests::test_init_log();
        let even_port = EvenPort::new(true);
        let raw = RawAttribute::from(&even_port);

        // provide incorrectly typed data
        let mut data: Vec<_> = raw.into();
        BigEndian::write_u16(&mut data[0..2], 0);
        assert!(matches!(
            EvenPort::try_from(&RawAttribute::from_bytes(data.as_ref()).unwrap()),
            Err(StunParseError::WrongAttributeImplementation)
        ));
    }

    #[test]
    fn even_port_write_into() {
        let _log = crate::tests::test_init_log();
        let even_port = EvenPort::new(true);
        let raw = RawAttribute::from(&even_port);

        let mut dest = vec![0; raw.padded_len()];
        even_port.write_into(&mut dest).unwrap();
        let raw = RawAttribute::from_bytes(&dest).unwrap();
        let even_port2 = EvenPort::try_from(&raw).unwrap();
        assert_eq!(even_port2.get_type(), EvenPort::TYPE);
        assert!(even_port2.requested());
    }

    #[test]
    #[should_panic = "out of range"]
    fn even_port_write_into_unchecked() {
        let _log = crate::tests::test_init_log();
        let even_port = EvenPort::new(true);
        let raw = RawAttribute::from(&even_port);

        let mut dest = vec![0; raw.padded_len() - 1];
        even_port.write_into_unchecked(&mut dest);
    }
}
