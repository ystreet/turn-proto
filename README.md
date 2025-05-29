[![Build status](https://github.com/ystreet/turn-proto/actions/workflows/rust.yml/badge.svg?branch=main)](https://github.com/ystreet/turn-proto/actions)
[![codecov](https://codecov.io/gh/ystreet/turn-proto/branch/main/graph/badge.svg)](https://codecov.io/gh/ystreet/turn-proto)
[![Dependencies](https://deps.rs/repo/github/ystreet/turn-proto/status.svg)](https://deps.rs/repo/github/ystreet/turn-proto)
[![crates.io](https://img.shields.io/crates/v/turn-proto.svg)](https://crates.io/crates/turn-proto)
[![docs.rs](https://docs.rs/turn-proto/badge.svg)](https://docs.rs/turn-proto)

# turn-proto

Repository containing a sans-IO implementation of the STUN (RFC5389/RFC8489) protocol
and STUN parsing and writing in the [Rust programming language](https://www.rust-lang.org/).

## Why sans-io?

A couple of reasons: reusability, and testability.

Without being bogged down in the details of how IO happens, the same sans-IO
implementation can be used without prescribing the IO pattern that an application
must follow. Instead, the application (or parent library) has much more freedom
in how bytes are transferred between peers. It's also possible to us a sans-IO
library in either a synchronous or within an asynchronous runtime.

sans-IO also allows easy testing of any specific state the sans-IO
implementation might find itself in. Combined with a comprehensive test-suite,
this provides assurance that the implementation behaves as expected under all
circumstances.

For other examples of sans-IO implementations, take a look at:
- [librice](https://github.com/ystreet/librice)
- [stun-proto](https://github.com/ystreet/stun-proto)
- [Quinn](https://github.com/quinn-rs/quinn/)
- https://sans-io.readthedocs.io/

## Relevant standards

 - [RFC5766](https://tools.ietf.org/html/rfc5766):
   Traversal Using Relays around NAT (TURN): Relay Extensions to Session
   Traversal Utilities for NAT (STUN)
 - [RFC6156](https://tools.ietf.org/html/rfc6156):
   Traversal Using Relays around NAT (TURN) Extension for IPv6
 - [RFC8656](https://tools.ietf.org/html/rfc8656):
   Traversal Using Relays around NAT (TURN): Relay Extensions to Session
   Traversal Utilities for NAT (STUN)

## Structure

### [turn-types](https://github.com/ystreet/turn-proto/tree/main/turn-types)

Contains parsers and writing implementations for STUN messages and attributes.
Message parsing is zero-copy by default and easily supports externally defined
custom attributes.

### [turn-client-proto](https://github.com/ystreet/turn-proto/tree/main/turn-client-proto)

`turn-proto` builds on top of `turn-types` and implements some of the
TURN protocol requirements when communicating with a peer. It does this using a
sans-IO API and thus does no networking calls of its own.
