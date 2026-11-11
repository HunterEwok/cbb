// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Where a peer's key stands in the records (0.6, design-no-certificates
//! section 3): the one check TLS, the intro and every other way in ask, now
//! that the key is the device's identity.

use crate::format::{Alg, DeviceId, Key, KeyHash};
use crate::records::State;

/// Where a peer's key stands in the records.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Standing {
    /// A device of the group that may talk.
    Member(DeviceId),
    /// A key the records do not name yet: the peer must send its intro
    /// (format 11.3) as its first message, or the connection closes.
    Unknown,
    /// A key that may not talk, and why.
    Refused(&'static str),
}

/// Where the peer with key `peer` stands in the records `state`, for the
/// device whose own key hash is `own`: removed keys, frozen devices, an ID
/// that two keys claim or a removed device's ID, and the device itself are
/// refused; a key no record names is unknown.
pub fn standing(state: &State, own: &KeyHash, peer: &[u8; 65]) -> Standing {
    let key = Key::new(Alg::Es256, peer);
    let h = key.hash();
    if &h == own {
        return Standing::Refused("connected to itself");
    }
    let rh = crate::records::KeyHash(h.0);
    if state.revoked.contains(&rh) {
        return Standing::Refused("removed from the group");
    }
    if let Some(d) = state.device_by_key(&rh) {
        if d.frozen {
            return Standing::Refused("frozen");
        }
        return Standing::Member(DeviceId(d.id.0));
    }
    if state.id_taken(&crate::records::DeviceId(key.device_id().0)) {
        return Standing::Refused("its device ID is not its own in the records");
    }
    Standing::Unknown
}
