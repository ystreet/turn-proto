// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use stun_types::{attribute::*, message::StunParseError};

/// The Data [`Attribute`]
#[derive(Debug, Clone)]
pub struct Data<'a> {
    data: stun_types::data::Data<'a>,
}

impl AttributeStaticType for Data<'_> {
    const TYPE: AttributeType = AttributeType::new(0x0013);
}

impl Attribute for Data<'_> {
    fn get_type(&self) -> AttributeType {
        Self::TYPE
    }

    fn length(&self) -> u16 {
        self.data.len() as u16
    }
}

impl AttributeWrite for Data<'_> {
    fn to_raw(&self) -> RawAttribute {
        RawAttribute::new(self.get_type(), &self.data)
    }

    fn write_into_unchecked(&self, dest: &mut [u8]) {
        self.write_header_unchecked(dest);
        dest[4..4 + self.data.len()].copy_from_slice(&self.data);
    }
}

impl<'a> AttributeFromRaw<'a> for Data<'a> {
    fn from_raw_ref(raw: &RawAttribute) -> Result<Self, StunParseError>
    where
        Self: Sized,
    {
        raw.check_type_and_len(Self::TYPE, ..)?;
        Ok(Self {
            data: raw.value.clone().into_owned(),
        })
    }

    fn from_raw(raw: RawAttribute<'a>) -> Result<Self, StunParseError>
    where
        Self: Sized,
    {
        Self::try_from(raw)
    }
}

impl<'a> TryFrom<RawAttribute<'a>> for Data<'a> {
    type Error = StunParseError;

    fn try_from(raw: RawAttribute<'a>) -> Result<Self, Self::Error> {
        raw.check_type_and_len(Self::TYPE, ..)?;
        Ok(Self { data: raw.value })
    }
}

impl<'a> Data<'a> {
    /// Create a new Data [`Attribute`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use turn_types::attribute::*;
    /// let bytes = vec![0, 1, 2];
    /// let data = Data::new(&bytes);
    /// assert_eq!(data.data(), &bytes);
    /// ```
    pub fn new(data: &'a [u8]) -> Self {
        if data.len() > u16::MAX as usize {
            panic!(
                "Attempt made to create a Data attribute larger than {}",
                u16::MAX
            );
        }
        Self {
            data: stun_types::data::Data::from(data),
        }
    }

    /// Retrieve the data stored in a [Data]
    ///
    /// # Examples
    ///
    /// ```
    /// # use turn_types::attribute::*;
    /// let bytes = vec![0, 1, 2];
    /// let data = Data::new(&bytes);
    /// assert_eq!(data.data(), &bytes);
    /// ```
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

impl std::fmt::Display for Data<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: len:{}", self.get_type(), self.data.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use byteorder::{BigEndian, ByteOrder};

    #[test]
    fn data() {
        let _log = crate::tests::test_init_log();
        let bytes = vec![0, 1, 2, 3, 4, 5];
        let data = Data::new(&bytes);
        assert_eq!(data.get_type(), Data::TYPE);
        assert_eq!(data.data(), &bytes);
        let raw: RawAttribute = data.to_raw();
        println!("{}", raw);
        assert_eq!(raw.get_type(), Data::TYPE);
        let data2 = Data::try_from(raw.clone()).unwrap();
        assert_eq!(data2.get_type(), Data::TYPE);
        assert_eq!(data2.data(), &bytes);
        // provide incorrectly typed data
        let mut data: Vec<_> = raw.into();
        BigEndian::write_u16(&mut data[0..2], 0);
        assert!(matches!(
            Data::try_from(RawAttribute::from_bytes(data.as_ref()).unwrap()),
            Err(StunParseError::WrongAttributeImplementation)
        ));
    }
}
