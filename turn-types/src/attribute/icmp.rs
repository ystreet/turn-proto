// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use byteorder::{BigEndian, ByteOrder};
use stun_types::{attribute::*, message::StunParseError};

/// The [`Icmp`] [`Attribute`].
///
/// Attribute used by TURN to forward ICMP packets towards the client.
///
/// Reference: [RFC8656 Section 18.13](https://datatracker.ietf.org/doc/html/rfc8656#section-18.13).
#[derive(Debug, Clone)]
pub struct Icmp {
    typ: u8,
    code: u8,
    data: u32,
}

impl AttributeStaticType for Icmp {
    const TYPE: AttributeType = AttributeType::new(0x8004);
}

impl Attribute for Icmp {
    fn get_type(&self) -> AttributeType {
        Self::TYPE
    }

    fn length(&self) -> u16 {
        8
    }
}

impl AttributeWrite for Icmp {
    fn to_raw(&self) -> RawAttribute<'_> {
        let mut data = [0; 8];
        data[2] = self.typ;
        data[3] = self.code;
        BigEndian::write_u32(&mut data[4..8], self.data);
        RawAttribute::new(Self::TYPE, &data).into_owned()
    }
    fn write_into_unchecked(&self, dest: &mut [u8]) {
        self.write_header_unchecked(dest);
        dest[6] = self.typ;
        dest[7] = self.code;
        BigEndian::write_u32(&mut dest[8..12], self.data);
    }
}

impl AttributeFromRaw<'_> for Icmp {
    fn from_raw_ref(raw: &RawAttribute) -> Result<Self, StunParseError>
    where
        Self: Sized,
    {
        Self::try_from(raw)
    }
}

impl TryFrom<&RawAttribute<'_>> for Icmp {
    type Error = StunParseError;
    fn try_from(raw: &RawAttribute) -> Result<Self, Self::Error> {
        raw.check_type_and_len(Self::TYPE, 8..=8)?;
        let typ = raw.value[2];
        let code = raw.value[3];
        let data = BigEndian::read_u32(&raw.value[4..8]);
        Ok(Self { typ, code, data })
    }
}

impl Icmp {
    /// Create a new [`Icmp`] [`Attribute`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use turn_types::attribute::*;
    /// let icmp = Icmp::new(1, 2, 3);
    /// assert_eq!(icmp.icmp_type(), 1);
    /// assert_eq!(icmp.code(), 2);
    /// assert_eq!(icmp.data(), 3);
    /// ```
    pub fn new(typ: u8, code: u8, data: u32) -> Self {
        Self { typ, code, data }
    }

    /// Retrieve the type of the ICMP stored in a [`Icmp`].
    pub fn icmp_type(&self) -> u8 {
        self.typ
    }

    /// Retrieve the code of the ICMP stored in a [`Icmp`].
    pub fn code(&self) -> u8 {
        self.code
    }

    /// Retrieve any additional data of the ICMP stored in a [`Icmp`].
    pub fn data(&self) -> u32 {
        self.data
    }
}

impl core::fmt::Display for Icmp {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{}: type:{}, code:{}, data:{}",
            self.get_type(),
            self.typ,
            self.code,
            self.data
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{vec, vec::Vec};
    use tracing::trace;

    #[test]
    fn icmp() {
        let _log = crate::tests::test_init_log();
        let mapped = Icmp::new(2, 4, 8);
        assert_eq!(mapped.get_type(), Icmp::TYPE);
        assert_eq!(mapped.icmp_type(), 2);
        assert_eq!(mapped.code(), 4);
        assert_eq!(mapped.data(), 8);
    }

    #[test]
    fn icmp_raw() {
        let _log = crate::tests::test_init_log();
        let mapped = Icmp::new(2, 4, 8);
        let raw: RawAttribute = mapped.to_raw();
        trace!("{}", raw);
        assert_eq!(raw.get_type(), Icmp::TYPE);
        let mapped2 = Icmp::try_from(&raw).unwrap();
        assert_eq!(mapped2.get_type(), Icmp::TYPE);
        assert_eq!(mapped2.icmp_type(), 2);
        assert_eq!(mapped2.code(), 4);
        assert_eq!(mapped2.data(), 8);
    }

    #[test]
    fn icmp_raw_short() {
        let _log = crate::tests::test_init_log();
        let mapped = Icmp::new(2, 4, 8);
        let raw: RawAttribute = mapped.to_raw();
        assert_eq!(raw.get_type(), Icmp::TYPE);
        // truncate by one byte
        let mut data: Vec<_> = raw.clone().into();
        let len = data.len();
        BigEndian::write_u16(&mut data[2..4], len as u16 - 4 - 1);
        assert!(matches!(
            Icmp::try_from(&RawAttribute::from_bytes(data[..len - 1].as_ref()).unwrap()),
            Err(StunParseError::Truncated {
                expected: _,
                actual: _,
            })
        ));
    }

    #[test]
    fn icmp_raw_wrong_type() {
        let _log = crate::tests::test_init_log();
        let mapped = Icmp::new(2, 4, 8);
        let raw: RawAttribute = mapped.to_raw();
        assert_eq!(raw.get_type(), Icmp::TYPE);
        // provide incorrectly typed data
        let mut data: Vec<_> = raw.clone().into();
        BigEndian::write_u16(&mut data[0..2], 0);
        assert!(matches!(
            Icmp::try_from(&RawAttribute::from_bytes(data.as_ref()).unwrap()),
            Err(StunParseError::WrongAttributeImplementation)
        ));
    }

    #[test]
    fn icmp_write_into() {
        let _log = crate::tests::test_init_log();
        let mapped = Icmp::new(2, 4, 8);
        let raw: RawAttribute = mapped.to_raw();
        let mut dest = vec![0; raw.padded_len()];
        mapped.write_into(&mut dest).unwrap();
        let raw = RawAttribute::from_bytes(&dest).unwrap();
        let mapped2 = Icmp::try_from(&raw).unwrap();
        assert_eq!(mapped2.get_type(), Icmp::TYPE);
        assert_eq!(mapped2.icmp_type(), 2);
        assert_eq!(mapped2.code(), 4);
        assert_eq!(mapped2.data(), 8);
    }

    #[test]
    #[should_panic = "out of range"]
    fn icmp_write_into_unchecked() {
        let _log = crate::tests::test_init_log();
        let mapped = Icmp::new(2, 4, 8);
        let raw: RawAttribute = mapped.to_raw();
        let mut dest = vec![0; raw.padded_len() - 1];
        mapped.write_into_unchecked(&mut dest);
    }
}
