// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The ALPN names of cbb's TLS connections, in one place for every part of
//! the core (format section 9). A device offers every name it speaks, the
//! highest first, and the server takes the first of its own list the client
//! offers: the highest common one. Names a peer offers that this version
//! does not know are ignored. No common name ends the handshake with
//! `no_application_protocol`, which the apps show as another version of cbb
//! ([`OTHER_VERSION`]).
//!
//! A new name comes with a new key container or a change of what the
//! handshake's bytes mean; a new message inside the protocol is not a new
//! name. 0.5's names are never offered: 0.6 groups are made anew.

use alloc::vec::Vec;

/// The member protocol of 0.6.
pub const MEMBER: &[u8] = b"cbb/4";
/// The pairing protocol of 0.6.
pub const PAIR: &[u8] = b"cbb-pair/3";

/// The member protocols this version speaks, the highest first.
pub const MEMBERS: &[&[u8]] = &[MEMBER];
/// The pairing protocols this version speaks, the highest first.
pub const PAIRS: &[&[u8]] = &[PAIR];

/// What a connection without a common name tells the person.
pub const OTHER_VERSION: &str =
    "the other device runs another version of cbb that this one cannot talk to: update the older one";

/// The names to offer, as a TLS configuration takes them.
pub fn offer(names: &[&[u8]]) -> Vec<Vec<u8>> {
    names.iter().map(|n| n.to_vec()).collect()
}

/// Whether a connection's negotiated name is one of the member protocols.
pub fn is_member(negotiated: Option<&[u8]>) -> bool {
    negotiated.is_some_and(|n| MEMBERS.contains(&n))
}

/// Whether a connection's negotiated name is one of the pairing protocols.
pub fn is_pair(negotiated: Option<&[u8]>) -> bool {
    negotiated.is_some_and(|n| PAIRS.contains(&n))
}
