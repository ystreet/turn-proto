// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use stun_types::{attribute::*, message::StunParseError};

/// The RequestedTransport [`Attribute`]
#[derive(Debug, Clone)]
pub struct RequestedTransport {
    protocol: u8,
}

impl AttributeStaticType for RequestedTransport {
    const TYPE: AttributeType = AttributeType::new(0x0019);
}

impl Attribute for RequestedTransport {
    fn get_type(&self) -> AttributeType {
        Self::TYPE
    }

    fn length(&self) -> u16 {
        4
    }
}

impl AttributeWrite for RequestedTransport {
    fn to_raw(&self) -> RawAttribute<'_> {
        RawAttribute::new(self.get_type(), &[self.protocol, 0, 0, 0]).into_owned()
    }

    fn write_into_unchecked(&self, dest: &mut [u8]) {
        self.write_header_unchecked(dest);
        dest[4] = self.protocol;
        dest[5] = 0x0;
        dest[6] = 0x0;
        dest[7] = 0x0;
    }
}

impl AttributeFromRaw<'_> for RequestedTransport {
    fn from_raw_ref(raw: &RawAttribute) -> Result<Self, StunParseError>
    where
        Self: Sized,
    {
        Self::try_from(raw)
    }
}

impl TryFrom<&RawAttribute<'_>> for RequestedTransport {
    type Error = StunParseError;
    fn try_from(raw: &RawAttribute) -> Result<Self, Self::Error> {
        raw.check_type_and_len(Self::TYPE, 4..=4)?;
        Ok(Self {
            protocol: raw.value[0],
        })
    }
}

impl RequestedTransport {
    /// The UDP transport type.
    pub const UDP: u8 = 17;

    /// Create a new RequestedTransport [`Attribute`]
    ///
    /// # Examples
    ///
    /// ```
    /// # use turn_types::attribute::*;
    /// let requested_transport = RequestedTransport::new(RequestedTransport::UDP);
    /// assert_eq!(requested_transport.protocol(), RequestedTransport::UDP);
    /// ```
    pub fn new(protocol: u8) -> Self {
        Self { protocol }
    }

    /// Retrieve the protocol stored in a RequestedTransport
    ///
    /// # Examples
    ///
    /// ```
    /// # use turn_types::attribute::*;
    /// let requested_transport = RequestedTransport::new(RequestedTransport::UDP);
    /// assert_eq!(requested_transport.protocol(), RequestedTransport::UDP);
    /// ```
    pub fn protocol(&self) -> u8 {
        self.protocol
    }
}

impl std::fmt::Display for RequestedTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.get_type(), self.protocol())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use byteorder::{BigEndian, ByteOrder};

    #[test]
    fn requested_transport() {
        let _log = crate::tests::test_init_log();
        let trans = RequestedTransport::new(17);
        assert_eq!(trans.get_type(), RequestedTransport::TYPE);
        assert_eq!(trans.protocol(), 17);
        let raw: RawAttribute = trans.to_raw();
        println!("raw: {raw:?}");
        assert_eq!(raw.get_type(), RequestedTransport::TYPE);
        let trans2 = RequestedTransport::try_from(&raw).unwrap();
        assert_eq!(trans2.get_type(), RequestedTransport::TYPE);
        assert_eq!(trans2.protocol(), 17);
        // provide incorrectly typed data
        let mut data: Vec<_> = raw.into();
        BigEndian::write_u16(&mut data[0..2], 0);
        assert!(matches!(
            RequestedTransport::try_from(&RawAttribute::from_bytes(data.as_ref()).unwrap()),
            Err(StunParseError::WrongAttributeImplementation)
        ));
        let mut data = [0; 8];
        trans.write_into(&mut data).unwrap();
        let raw = RawAttribute::from_bytes(&data).unwrap();
        let trans2 = RequestedTransport::from_raw_ref(&raw).unwrap();
        assert_eq!(trans.protocol(), trans2.protocol());
    }
}
