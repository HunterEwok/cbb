// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Joining a group in 0.6, without certificates (design-no-certificates
//! section 4, format section 11): the joiner's Info, the admitter's
//! decision and the joiner's record, the Welcome and the joiner's checks of
//! it, the intro a member sends a peer that does not know its key yet, and
//! the invitation (one for home and away).
//!
//! The order stays: a code or an invitation, CPace, the channel binding.
//! What changes is what is bound and sent: CPace binds the key hashes of
//! both TLS keys (each side's key container), and the Welcome carries the
//! group's first root key and records, no certificate. The joiner's device
//! ID is its key's hash, so nobody can join as a device ID it does not hold
//! the key of, and a removed device's ID is never given again.

pub mod decide;
pub mod info;
pub mod intro;
pub mod invitation;
pub mod waiting;
pub mod welcome;

#[cfg(test)]
mod tests;

use alloc::vec::Vec;

use crate::format::{KeyHash, Rule};
use crate::identity::ExternalKey;
use crate::records::Key;

/// The ALPN protocol of pairing in 0.6.
pub const PAIR_PROTOCOL: &[u8] = b"cbb-pair/3";

/// The pairing messages (format 11.1).
pub const T_START: u64 = 64;
pub const T_REPLY: u64 = 65;
pub const T_CONFIRM: u64 = 66;
pub const T_WELCOME: u64 = 67;
pub const T_DONE: u64 = 68;
pub const T_ERROR: u64 = 69;
/// The intro of a peer whose key the other side does not know (format 11.3).
pub const T_INTRO: u64 = 8;

/// Reads one frame of pairing. Before the code is confirmed every message
/// takes the pairing limit (1 MiB); after it, the Welcome (message 67) may
/// take the member limit (7 MiB) and every other message still the pairing
/// limit. A Welcome before the confirm is refused whatever its size.
///
/// What is read of message 67 before its tag (`welcome::open`) is checked:
/// this walk of the frame's CBOR, at most one member frame (7 MiB), into
/// values whose arrays and maps are sized by the bytes left, never by the
/// counts their heads announce, so the memory is linear in the frame's
/// bytes. Nothing of field 3 is interpreted before the tag holds. The fuzz
/// target `welcome_message` feeds it any bytes.
pub fn read_pairing(frame: &[u8], confirmed: bool) -> Result<crate::format::frame::Message<'_>, Rule> {
    use crate::format::frame::{self, LIMIT_MEMBER, LIMIT_PAIRING};
    let m = frame::read(frame, if confirmed { LIMIT_MEMBER } else { LIMIT_PAIRING })?;
    if m.t == T_WELCOME && !confirmed {
        return Err(RULE_EARLY_WELCOME);
    }
    if m.t != T_WELCOME && frame.len().saturating_sub(4) > LIMIT_PAIRING {
        return Err(Rule::FRAME_GRID);
    }
    Ok(m)
}

/// The length a pairing frame's header announces, checked against the
/// widest the next message may be: the member limit after the confirm
/// (only a Welcome reaches it, which [`read_pairing`] checks once read),
/// the pairing limit before.
pub fn pairing_length(header: [u8; 4], confirmed: bool) -> Result<usize, Rule> {
    use crate::format::frame::{self, LIMIT_MEMBER, LIMIT_PAIRING};
    frame::length(header, if confirmed { LIMIT_MEMBER } else { LIMIT_PAIRING })
}

/// A Welcome before the code is confirmed.
pub const RULE_EARLY_WELCOME: Rule = Rule::field("pair/early-welcome");

/// The label of the admin key's proof at pairing.
pub const LABEL_ADMIN_POP: &str = "cbb admin pop v1";

/// The prefix of CPace's channel identifier in 0.6.
const CHANNEL_PREFIX: &[u8] = b"cbb pair channel v3\0";

/// Why a pairing ends, as message 69 carries it (format 11.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PairError {
    WrongCode = 1,
    Closed = 2,
    Busy = 3,
    Expired = 4,
    TooMany = 5,
    Refused = 6,
    Declined = 7,
    /// The joiner's device ID is taken: a device of the group, or one that
    /// was removed, holds it. A removed device comes back only with a new
    /// key, as a new device.
    Taken = 8,
}

impl PairError {
    /// The code's number.
    pub fn code(self) -> u64 {
        self as u64
    }

    /// The error of a number; None for one this version does not know.
    pub fn of(code: u64) -> Option<PairError> {
        Some(match code {
            1 => PairError::WrongCode,
            2 => PairError::Closed,
            3 => PairError::Busy,
            4 => PairError::Expired,
            5 => PairError::TooMany,
            6 => PairError::Refused,
            7 => PairError::Declined,
            8 => PairError::Taken,
            _ => return None,
        })
    }
}

/// The invitation ID of a pairing at home without an invitation: 16 zero
/// bytes, which no invitation has (`invite/shape`).
pub const NO_INVITATION: [u8; 16] = [0; 16];

/// CPace's channel identifier: the prefix, the key hashes of the member's
/// TLS key and the joiner's, the member's first, and the ID of the
/// invitation each side believes it is using ([`NO_INVITATION`] at home
/// without one). The keys come from the key containers the TLS handshake
/// saw, so a party in the middle with its own keys gets another
/// identifier and the exchange fails; two ends in the flows of two
/// invitations get two identifiers too.
pub fn channel_id(member: &KeyHash, joiner: &KeyHash, invitation: &[u8; 16]) -> Vec<u8> {
    let mut ci = CHANNEL_PREFIX.to_vec();
    ci.extend_from_slice(&member.0);
    ci.extend_from_slice(&joiner.0);
    ci.extend_from_slice(invitation);
    ci
}

/// The admin key's proof of possession: its signature over the pairing
/// session's TLS exporter, under [`LABEL_ADMIN_POP`]. A joiner that offers
/// an admin key without it is admitted without one.
pub fn sign_admin_pop(admin: &dyn ExternalKey, exporter: &[u8]) -> crate::error::Result<[u8; 64]> {
    crate::records::key::sign_es256(admin, LABEL_ADMIN_POP, exporter)
}

/// Checks an admin key's proof over this session's exporter.
pub fn verify_admin_pop(admin: &Key, exporter: &[u8], pop: &[u8]) -> bool {
    crate::records::key::verify_es256(admin, LABEL_ADMIN_POP, exporter, pop).is_ok()
}
