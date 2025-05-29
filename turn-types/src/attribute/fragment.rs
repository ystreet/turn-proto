// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use stun_types::{
    attribute::*,
    message::StunParseError,
};

/// The DontFragment [`Attribute`]
#[derive(Default, Debug, Clone)]
pub struct DontFragment {}
impl AttributeStaticType for DontFragment {
    const TYPE: AttributeType = AttributeType::new(0x001A);
}

impl Attribute for DontFragment {
    fn get_type(&self) -> AttributeType {
        Self::TYPE
    }

    fn length(&self) -> u16 {
        0
    }
}

impl AttributeWrite for DontFragment {
    fn to_raw(&self) -> RawAttribute {
        RawAttribute::new(self.get_type(), &[])
    }
    fn write_into_unchecked(&self, dest: &mut [u8]) {
        self.write_header_unchecked(dest);
    }
}

impl AttributeFromRaw<'_> for DontFragment {
    fn from_raw_ref(raw: &RawAttribute) -> Result<Self, StunParseError>
    where
        Self: Sized,
    {
        Self::try_from(raw)
    }
}

impl TryFrom<&RawAttribute<'_>> for DontFragment {
    type Error = StunParseError;
    fn try_from(raw: &RawAttribute) -> Result<Self, Self::Error> {
        raw.check_type_and_len(Self::TYPE, 0..=0)?;
        Ok(Self {})
    }
}

impl DontFragment {
    /// Create a new DontFragment [`Attribute`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use turn_types::attribute::*;
    /// let dont_fragment = DontFragment::new();
    /// ```
    pub fn new() -> Self {
        Self {}
    }
}

impl std::fmt::Display for DontFragment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.get_type())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use byteorder::{BigEndian, ByteOrder};

    #[test]
    fn dont_fragment() {
        let _log = crate::tests::test_init_log();
        let frag = DontFragment::new();
        assert_eq!(frag.get_type(), DontFragment::TYPE);
        let raw: RawAttribute = frag.to_raw();
        println!("{}", raw);
        assert_eq!(raw.get_type(), DontFragment::TYPE);
        let frag2 = DontFragment::try_from(&raw).unwrap();
        assert_eq!(frag2.get_type(), DontFragment::TYPE);
        // provide incorrectly typed data
        let mut data: Vec<_> = raw.into();
        BigEndian::write_u16(&mut data[0..2], 0);
        assert!(matches!(
            DontFragment::try_from(&RawAttribute::from_bytes(data.as_ref()).unwrap()),
            Err(StunParseError::WrongAttributeImplementation)
        ));
    }
}
