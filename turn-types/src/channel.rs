// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! TURN [`ChannelData`] messages.
//!
//! Used as an optional more efficient data transfer mechanism between a TURN server and a TURN
//! client.

use stun_types::message::StunParseError;

/// A [`ChannelData`] message.
#[derive(Debug, Copy, Clone)]
pub struct ChannelData<'a> {
    id: u16,
    data: &'a [u8],
}

impl<'a> ChannelData<'a> {
    /// Construct a new [`ChannelData`] with the provided identifer and byte sequence.
    pub fn new(id: u16, data: &'a [u8]) -> Self {
        Self { id, data }
    }

    /// The channel identifier stored in this piece of data.
    pub fn id(&self) -> u16 {
        self.id
    }

    /// The sequence of bytes in this message.
    pub fn data(&self) -> &[u8] {
        self.data
    }

    /// Parse a sequence of bytes into a [`ChannelData`].  Returns appropriate errors on failure.
    ///
    /// # Examples
    /// ```
    /// # use turn_types::channel::*;
    /// let data = [4; 3];
    /// let channel = ChannelData::new(0x4000, &data);
    /// let mut output = [0; 7];
    /// assert_eq!(7, channel.write_into_unchecked(&mut output));
    /// let parsed = ChannelData::parse(&output).unwrap();
    /// assert_eq!(parsed.id(), channel.id());
    /// assert_eq!(parsed.data(), channel.data());
    /// ```
    pub fn parse(data: &'a [u8]) -> Result<Self, StunParseError> {
        if data.len() < 4 {
            return Err(stun_types::message::StunParseError::Truncated {
                expected: 4,
                actual: data.len(),
            });
        }
        let id = u16::from_be_bytes([data[0], data[1]]);
        let len = u16::from_be_bytes([data[2], data[3]]) as usize;
        if len + 4 > data.len() {
            return Err(stun_types::message::StunParseError::Truncated {
                expected: 4 + len,
                actual: data.len(),
            });
        }

        if !(0x4000..=0xFFFE).contains(&id) {
            return Err(stun_types::message::StunParseError::InvalidAttributeData);
        }

        Ok(ChannelData {
            id,
            data: &data[4..4 + len],
        })
    }

    /// Write this [`ChannelData`] into the provided destination slice.
    ///
    /// The destination slice must have size `ChannelData::data().len() + 4`.
    pub fn write_into_unchecked(self, dest: &mut [u8]) -> usize {
        dest[..2].copy_from_slice(self.id.to_be_bytes().as_ref());
        dest[2..4].copy_from_slice((self.data.len() as u16).to_be_bytes().as_ref());
        dest[4..].copy_from_slice(self.data);
        self.data.len() + 4
    }
}

impl std::fmt::Display for ChannelData<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ChannelData(id: {}, data of {} bytes)",
            self.id,
            self.data.len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_data_parse_invalid_id() {
        let data = [0x00, 0x00, 0x00, 0x00];
        assert!(matches!(
            ChannelData::parse(&data),
            Err(StunParseError::InvalidAttributeData)
        ));
    }

    #[test]
    fn channel_data_parse_empty() {
        let data = [0x40, 0x00, 0x00, 0x00];
        let channel = ChannelData::parse(&data).unwrap();
        assert_eq!(channel.data(), &[]);
    }

    #[test]
    fn channel_data_parse_truncated_data() {
        let data = [0x40, 0x00, 0x00, 0x01];
        let Err(StunParseError::Truncated { expected, actual }) = ChannelData::parse(&data) else {
            unreachable!();
        };
        assert_eq!(expected, 5);
        assert_eq!(actual, 4);
    }

    #[test]
    fn channel_data_parse_truncated_header() {
        let data = [0x40, 0x00, 0x00];
        let Err(StunParseError::Truncated { expected, actual }) = ChannelData::parse(&data) else {
            unreachable!();
        };
        assert_eq!(expected, 4);
        assert_eq!(actual, 3);
    }
}
