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
    /// The group is halted here (`State::halted`): nobody is a member. The
    /// peer may connect only to give and take the recovery key's records,
    /// the fork's proof: no copies, no other records.
    Halted,
    /// The current root has two histories, and a held record of that root
    /// admits this key on one of its lines (`State::proof_to`): it is no
    /// device and is listed nowhere. The connection gives it the proof
    /// (`State::root_pair`) and takes from it only what makes or completes
    /// a pair of the current root (`RecordSet::insert_proof`), then ends.
    ForkProof,
}

/// Where the peer with key `peer` stands in the records `state`, for the
/// device whose own key hash is `own`: removed keys, frozen devices, an ID
/// that two keys claim or a removed device's ID, and the device itself are
/// refused; a key no record names is unknown. While the group is halted
/// every other key is `Halted`, whatever the records say of it. Two
/// histories of the current root stop the group (`State::stopped`) but not
/// sync: the members go on giving each other the pair and their records.
pub fn standing(state: &State, own: &KeyHash, peer: &[u8; 65]) -> Standing {
    let key = Key::new(Alg::Es256, peer);
    let h = key.hash();
    if &h == own {
        return Standing::Refused("connected to itself");
    }
    if state.halted() {
        return Standing::Halted;
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
    if state.proof_to.binary_search(&rh).is_ok() {
        return Standing::ForkProof;
    }
    if state.id_taken(&crate::records::DeviceId(key.device_id().0)) {
        return Standing::Refused("its device ID is not its own in the records");
    }
    Standing::Unknown
}
