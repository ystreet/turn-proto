// Copyright (C) 2025 Matthew Waters <matthew@centricular.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::net::SocketAddr;

use stun_types::{
    attribute::*,
    message::{StunParseError, TransactionId},
};

pub use stun_types::attribute::AddressFamily;

/// The [`XorPeerAddress`] [`Attribute`].
///
/// Typically used for signalling the address of the peer that a TURN server should send data
/// towards, or has received data from.
///
/// Reference: [RFC5766 Section 14.3](https://datatracker.ietf.org/doc/html/rfc5766#section-14.3).
#[derive(Debug, Clone)]
pub struct XorPeerAddress {
    // stored XOR-ed as we need the transaction id to get the original value
    addr: XorSocketAddr,
}

impl AttributeStaticType for XorPeerAddress {
    const TYPE: AttributeType = AttributeType::new(0x0012);
}

impl Attribute for XorPeerAddress {
    fn get_type(&self) -> AttributeType {
        Self::TYPE
    }

    fn length(&self) -> u16 {
        self.addr.length()
    }
}

impl AttributeWrite for XorPeerAddress {
    fn to_raw(&self) -> RawAttribute<'_> {
        self.addr.to_raw(self.get_type())
    }
    fn write_into_unchecked(&self, dest: &mut [u8]) {
        self.write_header_unchecked(dest);
        self.addr.write_into_unchecked(&mut dest[4..]);
    }
}

impl AttributeFromRaw<'_> for XorPeerAddress {
    fn from_raw_ref(raw: &RawAttribute) -> Result<Self, StunParseError>
    where
        Self: Sized,
    {
        Self::try_from(raw)
    }
}

impl TryFrom<&RawAttribute<'_>> for XorPeerAddress {
    type Error = StunParseError;
    fn try_from(raw: &RawAttribute) -> Result<Self, Self::Error> {
        raw.check_type_and_len(Self::TYPE, 4..=20)?;
        Ok(Self {
            addr: XorSocketAddr::from_raw(raw)?,
        })
    }
}

impl XorPeerAddress {
    /// Create a new [`XorPeerAddress`] [`Attribute`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use turn_types::attribute::*;
    /// # use std::net::SocketAddr;
    /// let addr = "127.0.0.1:1234".parse().unwrap();
    /// let mapped_addr = XorPeerAddress::new(addr, 0x5678.into());
    /// assert_eq!(mapped_addr.addr(0x5678.into()), addr);
    /// ```
    pub fn new(addr: SocketAddr, transaction: TransactionId) -> Self {
        Self {
            addr: XorSocketAddr::new(addr, transaction),
        }
    }

    /// Retrieve the address stored in a [`XorPeerAddress`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use turn_types::attribute::*;
    /// # use std::net::SocketAddr;
    /// let addr = "[::1]:1234".parse().unwrap();
    /// let mapped_addr = XorPeerAddress::new(addr, 0x5678.into());
    /// assert_eq!(mapped_addr.addr(0x5678.into()), addr);
    /// ```
    pub fn addr(&self, transaction: TransactionId) -> SocketAddr {
        self.addr.addr(transaction)
    }
}

impl std::fmt::Display for XorPeerAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.get_type(), self.addr)
    }
}

/// The [`XorRelayedAddress`] [`Attribute`].
///
/// Used to reference the address allocated on the TURN server on behalf of the client.
///
/// Reference: [RFC5766 Section 14.5](https://datatracker.ietf.org/doc/html/rfc5766#section-14.5).
#[derive(Debug, Clone)]
pub struct XorRelayedAddress {
    addr: XorSocketAddr,
}

impl AttributeStaticType for XorRelayedAddress {
    const TYPE: AttributeType = AttributeType::new(0x0016);
}

impl Attribute for XorRelayedAddress {
    fn get_type(&self) -> AttributeType {
        Self::TYPE
    }

    fn length(&self) -> u16 {
        self.addr.length()
    }
}

impl AttributeWrite for XorRelayedAddress {
    fn to_raw(&self) -> RawAttribute<'_> {
        self.addr.to_raw(self.get_type())
    }
    fn write_into_unchecked(&self, dest: &mut [u8]) {
        self.write_header_unchecked(dest);
        self.addr.write_into_unchecked(&mut dest[4..]);
    }
}

impl AttributeFromRaw<'_> for XorRelayedAddress {
    fn from_raw_ref(raw: &RawAttribute) -> Result<Self, StunParseError>
    where
        Self: Sized,
    {
        Self::try_from(raw)
    }
}

impl TryFrom<&RawAttribute<'_>> for XorRelayedAddress {
    type Error = StunParseError;
    fn try_from(raw: &RawAttribute) -> Result<Self, Self::Error> {
        if raw.get_type() != Self::TYPE {
            return Err(StunParseError::WrongAttributeImplementation);
        }
        Ok(Self {
            addr: XorSocketAddr::from_raw(raw)?,
        })
    }
}

impl XorRelayedAddress {
    /// Create a new [`XorRelayedAddress`] [`Attribute`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use turn_types::attribute::*;
    /// # use std::net::SocketAddr;
    /// let addr = "127.0.0.1:1234".parse().unwrap();
    /// let mapped_addr = XorRelayedAddress::new(addr, 0x5678.into());
    /// assert_eq!(mapped_addr.addr(0x5678.into()), addr);
    /// ```
    pub fn new(addr: SocketAddr, transaction: TransactionId) -> Self {
        Self {
            addr: XorSocketAddr::new(addr, transaction),
        }
    }

    /// Retrieve the address stored in a [`XorRelayedAddress`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use turn_types::attribute::*;
    /// # use std::net::SocketAddr;
    /// let addr = "[::1]:1234".parse().unwrap();
    /// let mapped_addr = XorRelayedAddress::new(addr, 0x5678.into());
    /// assert_eq!(mapped_addr.addr(0x5678.into()), addr);
    /// ```
    pub fn addr(&self, transaction: TransactionId) -> SocketAddr {
        self.addr.addr(transaction)
    }
}

impl std::fmt::Display for XorRelayedAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.get_type(), self.addr)
    }
}

/// The [`RequestedAddressFamily`] [`Attribute`].
///
/// Used to request an allocation with a specific address family.
///
/// Reference: [RFC6156 Section 4.1.1](https://datatracker.ietf.org/doc/html/rfc6156#section-4.1.1).
#[derive(Debug, Clone)]
pub struct RequestedAddressFamily {
    family: AddressFamily,
}

impl AttributeStaticType for RequestedAddressFamily {
    const TYPE: AttributeType = AttributeType::new(0x0017);
}

impl Attribute for RequestedAddressFamily {
    fn get_type(&self) -> AttributeType {
        Self::TYPE
    }

    fn length(&self) -> u16 {
        4
    }
}

impl AttributeWrite for RequestedAddressFamily {
    fn to_raw(&self) -> RawAttribute<'_> {
        let mut data = [0; 4];
        data[0] = match self.family {
            AddressFamily::IPV4 => 1,
            AddressFamily::IPV6 => 2,
        };
        RawAttribute::new(self.get_type(), &data).into_owned()
    }
    fn write_into_unchecked(&self, dest: &mut [u8]) {
        self.write_header_unchecked(dest);
        dest[4] = match self.family {
            AddressFamily::IPV4 => 1,
            AddressFamily::IPV6 => 2,
        };
        dest[5] = 0;
        dest[6] = 0;
        dest[7] = 0;
    }
}

impl AttributeFromRaw<'_> for RequestedAddressFamily {
    fn from_raw_ref(raw: &RawAttribute) -> Result<Self, StunParseError>
    where
        Self: Sized,
    {
        Self::try_from(raw)
    }
}

impl TryFrom<&RawAttribute<'_>> for RequestedAddressFamily {
    type Error = StunParseError;
    fn try_from(raw: &RawAttribute) -> Result<Self, Self::Error> {
        if raw.get_type() != Self::TYPE {
            return Err(StunParseError::WrongAttributeImplementation);
        }
        raw.check_type_and_len(Self::TYPE, 4..=4)?;
        let family = match raw.value[0] {
            1 => AddressFamily::IPV4,
            2 => AddressFamily::IPV6,
            _ => return Err(StunParseError::InvalidAttributeData),
        };
        Ok(Self { family })
    }
}

impl RequestedAddressFamily {
    /// Create a new [`RequestedAddressFamily`] [`Attribute`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use turn_types::attribute::*;
    /// let requested = RequestedAddressFamily::new(AddressFamily::IPV4);
    /// assert_eq!(requested.family(), AddressFamily::IPV4);
    /// ```
    pub fn new(family: AddressFamily) -> Self {
        Self { family }
    }

    /// Retrieve the requested address family stored in a [`RequestedAddressFamily`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use turn_types::attribute::*;
    /// let requested = RequestedAddressFamily::new(AddressFamily::IPV6);
    /// assert_eq!(requested.family(), AddressFamily::IPV6);
    /// ```
    pub fn family(&self) -> AddressFamily {
        self.family
    }
}

impl std::fmt::Display for RequestedAddressFamily {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.get_type(), self.family)
    }
}

#[cfg(test)]
mod tests {
    use crate::attribute::RequestedTransport;

    use super::*;
    use byteorder::{BigEndian, ByteOrder};

    #[test]
    fn xor_peer_address() {
        let _log = crate::tests::test_init_log();
        let transaction_id = 0x9876_5432_1098_7654_3210_9876.into();
        let addrs = &[
            "192.168.0.1:40000".parse().unwrap(),
            "[fd12:3456:789a:1::1]:41000".parse().unwrap(),
        ];
        for addr in addrs {
            let mapped = XorPeerAddress::new(*addr, transaction_id);
            assert_eq!(mapped.get_type(), XorPeerAddress::TYPE);
            assert_eq!(mapped.addr(transaction_id), *addr);
            let raw: RawAttribute = mapped.to_raw();
            println!("{}", raw);
            assert_eq!(raw.get_type(), XorPeerAddress::TYPE);
            let mapped2 = XorPeerAddress::try_from(&raw).unwrap();
            assert_eq!(mapped2.get_type(), XorPeerAddress::TYPE);
            assert_eq!(mapped2.addr(transaction_id), *addr);
            // truncate by one byte
            let mut data: Vec<_> = raw.clone().into();
            let len = data.len();
            BigEndian::write_u16(&mut data[2..4], len as u16 - 4 - 1);
            assert!(matches!(
                XorPeerAddress::try_from(
                    &RawAttribute::from_bytes(data[..len - 1].as_ref()).unwrap()
                ),
                Err(StunParseError::Truncated {
                    expected: _,
                    actual: _,
                })
            ));
            // provide incorrectly typed data
            let mut data: Vec<_> = raw.into();
            BigEndian::write_u16(&mut data[0..2], 0);
            assert!(matches!(
                XorPeerAddress::try_from(&RawAttribute::from_bytes(data.as_ref()).unwrap()),
                Err(StunParseError::WrongAttributeImplementation)
            ));
        }
    }

    #[test]
    fn xor_relayed_address() {
        let _log = crate::tests::test_init_log();
        let transaction_id = 0x9876_5432_1098_7654_3210_9876.into();
        let addrs = &[
            "192.168.0.1:40000".parse().unwrap(),
            "[fd12:3456:789a:1::1]:41000".parse().unwrap(),
        ];
        for addr in addrs {
            let mapped = XorRelayedAddress::new(*addr, transaction_id);
            assert_eq!(mapped.get_type(), XorRelayedAddress::TYPE);
            assert_eq!(mapped.addr(transaction_id), *addr);
            let raw: RawAttribute = mapped.to_raw();
            println!("{}", raw);
            assert_eq!(raw.get_type(), XorRelayedAddress::TYPE);
            let mapped2 = XorRelayedAddress::try_from(&raw).unwrap();
            assert_eq!(mapped2.get_type(), XorRelayedAddress::TYPE);
            assert_eq!(mapped2.addr(transaction_id), *addr);
            // truncate by one byte
            let mut data: Vec<_> = raw.clone().into();
            let len = data.len();
            BigEndian::write_u16(&mut data[2..4], len as u16 - 4 - 1);
            assert!(matches!(
                XorRelayedAddress::try_from(
                    &RawAttribute::from_bytes(data[..len - 1].as_ref()).unwrap()
                ),
                Err(StunParseError::Truncated {
                    expected: _,
                    actual: _,
                })
            ));
            // provide incorrectly typed data
            let mut data: Vec<_> = raw.into();
            BigEndian::write_u16(&mut data[0..2], 0);
            assert!(matches!(
                XorRelayedAddress::try_from(&RawAttribute::from_bytes(data.as_ref()).unwrap()),
                Err(StunParseError::WrongAttributeImplementation)
            ));
        }
    }

    #[test]
    fn requested_address_family() {
        let _log = crate::tests::test_init_log();
        for family in [AddressFamily::IPV4, AddressFamily::IPV6] {
            let mapped = RequestedAddressFamily::new(family);
            assert_eq!(mapped.get_type(), RequestedAddressFamily::TYPE);
            assert_eq!(mapped.family(), family);
            let raw: RawAttribute = mapped.to_raw();
            println!("{}", raw);
            assert_eq!(raw.get_type(), RequestedAddressFamily::TYPE);
            let mapped2 = RequestedAddressFamily::try_from(&raw).unwrap();
            assert_eq!(mapped2.get_type(), RequestedAddressFamily::TYPE);
            assert_eq!(mapped2.family(), family);
        }
        let mapped = RequestedAddressFamily::new(AddressFamily::IPV4);
        let raw: RawAttribute = mapped.to_raw();
        // truncate by one byte
        let mut data: Vec<_> = raw.clone().into();
        let len = data.len();
        BigEndian::write_u16(&mut data[2..4], len as u16 - 4 - 1);
        assert!(matches!(
            RequestedAddressFamily::try_from(
                &RawAttribute::from_bytes(data[..len - 1].as_ref()).unwrap()
            ),
            Err(StunParseError::Truncated {
                expected: _,
                actual: _,
            })
        ));
        // provide incorrectly typed data
        let mut data: Vec<_> = raw.clone().into();
        BigEndian::write_u16(&mut data[0..2], 0);
        assert!(matches!(
            RequestedTransport::try_from(&RawAttribute::from_bytes(data.as_ref()).unwrap()),
            Err(StunParseError::WrongAttributeImplementation)
        ));
        // provide invalid address family
        let mut data: Vec<_> = raw.clone().into();
        data[4] = 3;
        assert!(matches!(
            RequestedAddressFamily::try_from(&RawAttribute::from_bytes(data.as_ref()).unwrap()),
            Err(StunParseError::InvalidAttributeData)
        ));
    }
}
