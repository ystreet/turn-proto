// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use byteorder::{BigEndian, ByteOrder};

use stun_types::{attribute::*, message::StunParseError};

/// The [`ChannelNumber`] [`Attribute`].
///
/// Typically used when setting a TURN channel using the
/// [`CHANNEL_BIND`](crate::message::CHANNEL_BIND) method.
///
/// Reference: [RFC5766 section 14.1](https://datatracker.ietf.org/doc/html/rfc5766#section-14.1).
#[derive(Debug, Clone)]
pub struct ChannelNumber {
    channel: u16,
}

impl AttributeStaticType for ChannelNumber {
    const TYPE: AttributeType = AttributeType::new(0x000C);
}

impl Attribute for ChannelNumber {
    fn get_type(&self) -> AttributeType {
        Self::TYPE
    }

    fn length(&self) -> u16 {
        4
    }
}

impl AttributeWrite for ChannelNumber {
    fn to_raw(&self) -> RawAttribute<'_> {
        let mut buf = [0; 4];
        BigEndian::write_u16(&mut buf[..2], self.channel);
        RawAttribute::new(self.get_type(), &buf).into_owned()
    }
    fn write_into_unchecked(&self, dest: &mut [u8]) {
        self.write_header_unchecked(dest);
        BigEndian::write_u16(&mut dest[4..6], self.channel);
    }
}

impl AttributeFromRaw<'_> for ChannelNumber {
    fn from_raw_ref(raw: &RawAttribute) -> Result<Self, StunParseError>
    where
        Self: Sized,
    {
        Self::try_from(raw)
    }
}

impl TryFrom<&RawAttribute<'_>> for ChannelNumber {
    type Error = StunParseError;
    fn try_from(raw: &RawAttribute) -> Result<Self, Self::Error> {
        raw.check_type_and_len(Self::TYPE, 4..=4)?;
        Ok(Self {
            channel: BigEndian::read_u16(&raw.value),
        })
    }
}

impl ChannelNumber {
    /// Create a new [`ChannelNumber`] [`Attribute`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use turn_types::attribute::*;
    /// let channel = ChannelNumber::new (42);
    /// assert_eq!(channel.channel(), 42);
    /// ```
    pub fn new(channel: u16) -> Self {
        Self { channel }
    }

    /// The channel number stored in a [`ChannelNumber`] [`Attribute`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use turn_types::attribute::*;
    /// let channel = ChannelNumber::new (42);
    /// assert_eq!(channel.channel(), 42);
    /// ```
    pub fn channel(&self) -> u16 {
        self.channel
    }
}

impl std::fmt::Display for ChannelNumber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: '{}'", self.get_type(), self.channel)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use byteorder::{BigEndian, ByteOrder};

    #[test]
    fn channel_number() {
        let _log = crate::tests::test_init_log();
        let c = ChannelNumber::new(6);
        assert_eq!(c.get_type(), ChannelNumber::TYPE);
        assert_eq!(c.channel(), 6);
        let raw: RawAttribute = c.to_raw();
        println!("{}", raw);
        assert_eq!(raw.get_type(), ChannelNumber::TYPE);
        let c2 = ChannelNumber::try_from(&raw).unwrap();
        assert_eq!(c2.get_type(), ChannelNumber::TYPE);
        assert_eq!(c2.channel(), 6);
        // provide incorrectly typed data
        let mut data: Vec<_> = raw.into();
        BigEndian::write_u16(&mut data[0..2], 0);
        assert!(matches!(
            ChannelNumber::try_from(&RawAttribute::from_bytes(data.as_ref()).unwrap()),
            Err(StunParseError::WrongAttributeImplementation)
        ));
    }
}
