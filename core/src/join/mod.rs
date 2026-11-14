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

pub mod approve;
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

/// CPace's password at home without an invitation: 32 zero bytes, which no
/// invitation's secret is (`invite/shape`). It is public, so CPace
/// authenticates nothing by itself there: the member sends message 67 only
/// with the approval of its person's "they match" (`approve::Approved`),
/// and the joiner takes the Welcome only after its own person's
/// (`welcome::Way::Home`).
pub const NO_SECRET: [u8; invitation::SECRET] = [0; invitation::SECRET];

/// The exporter of a pairing session of 0.6: 32 bytes of the TLS label
/// [`crate::alpn::PAIR_EXPORTER`] with an empty context, from a session
/// that negotiated `cbb-pair/3`. It is CPace's session identifier and what
/// the short code, the session mark and the admin key's proof take. Every
/// entry point of the pairing takes it, not bytes, and it has two makers:
/// `tls::bykey::pairing_exporter`, from the core's own TLS session, and
/// [`PairExporter::exported_by_platform_tls`], for a device whose platform
/// runs the pairing TLS.
pub struct PairExporter([u8; crate::alpn::PAIR_EXPORTER_LEN]);

impl PairExporter {
    /// The exporter of a pairing session whose TLS the platform runs (the
    /// phone kits' TLSTransport): the caller states that `bytes` are 32
    /// bytes it exported with the label [`crate::alpn::PAIR_EXPORTER`] and
    /// an empty context, from a session that negotiated `cbb-pair/3`.
    pub fn exported_by_platform_tls(bytes: [u8; crate::alpn::PAIR_EXPORTER_LEN]) -> PairExporter {
        PairExporter(bytes)
    }

    /// From the core's own TLS session (`tls::bykey::pairing_exporter`).
    #[cfg(feature = "tls")]
    pub(crate) fn from_core_tls(bytes: [u8; crate::alpn::PAIR_EXPORTER_LEN]) -> PairExporter {
        PairExporter(bytes)
    }

    /// Any 32 bytes, for tests.
    #[cfg(test)]
    pub(crate) fn for_tests(bytes: [u8; crate::alpn::PAIR_EXPORTER_LEN]) -> PairExporter {
        PairExporter(bytes)
    }

    /// The bytes.
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for PairExporter {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}

impl core::fmt::Debug for PairExporter {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PairExporter")
    }
}

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
pub fn sign_admin_pop(admin: &dyn ExternalKey, exporter: &PairExporter) -> crate::error::Result<[u8; 64]> {
    crate::records::key::sign_es256(admin, LABEL_ADMIN_POP, exporter.bytes())
}

/// Checks an admin key's proof over this session's exporter.
pub fn verify_admin_pop(admin: &Key, exporter: &PairExporter, pop: &[u8]) -> bool {
    crate::records::key::verify_es256(admin, LABEL_ADMIN_POP, exporter.bytes(), pop).is_ok()
}
