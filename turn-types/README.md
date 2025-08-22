[![Build status](https://github.com/ystreet/turn-proto/actions/workflows/rust.yml/badge.svg?branch=main)](https://github.com/ystreet/turn-proto/actions)
[![codecov](https://codecov.io/gh/ystreet/turn-proto/branch/main/graph/badge.svg)](https://codecov.io/gh/ystreet/turn-proto)
[![Dependencies](https://deps.rs/repo/github/ystreet/turn-proto/status.svg)](https://deps.rs/repo/github/ystreet/turn-proto)
[![crates.io](https://img.shields.io/crates/v/turn-types.svg)](https://crates.io/crates/turn-types)
[![docs.rs](https://docs.rs/turn-types/badge.svg)](https://docs.rs/turn-types)

# turn-types

Repository containing an implementation of TURN (RFC5766) protocol writing in
the [Rust programming language](https://www.rust-lang.org/). `turn-types` builds
on top of [stun-types](https://docs.rs/sunt-proto/latest/stun_proto) to provide
the relevant attributes and methods for TURN applications.

## Relevant standards

 - [x] [RFC5766](https://tools.ietf.org/html/rfc5766):
   Traversal Using Relays around NAT (TURN): Relay Extensions to Session
   Traversal Utilities for NAT (STUN)
 - [x] [RFC6062](https://tools.ietf.org/html/rfc6062):
   Traversal Using Relays around NAT (TURN) Extensions for TCP Allocations
 - [x] [RFC6156](https://tools.ietf.org/html/rfc6156):
   Traversal Using Relays around NAT (TURN) Extension for IPv6
 - [x] [RFC8656](https://tools.ietf.org/html/rfc8656):
   Traversal Using Relays around NAT (TURN): Relay Extensions to Session
   Traversal Utilities for NAT (STUN)
