// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The 0.6 wire format: one strict CBOR profile for every message, record,
//! statement, command, grant, credential and copy header, and the pieces
//! every kind shares (keys, the signed envelope, padded frames, the copy's
//! signature, the TLS key container).
//!
//! This is the format level only: the bytes, their one encoding, the
//! envelope's shape and the signatures. What each field of each kind means
//! and which values it takes is the business of the modules that read that
//! kind (records, commands and so on); they refuse with a [`Rule`] of their
//! own, named as the vectors name it (`records/device/name`).
//!
//! Nothing here does I/O or needs the standard library, so the board runs
//! the same reader as the service and the phones.

pub mod cbor;
pub mod container;
pub mod copy;
pub mod envelope;
pub mod frame;
#[cfg(any(test, feature = "fuzzing"))]
#[allow(clippy::panic, reason = "a fuzz target reports a broken promise by panicking")]
pub mod fuzz;
pub mod grant;
pub mod key;
pub mod print;
pub mod sig;

#[cfg(test)]
mod tests;

pub use cbor::{Encoder, Value, decode};
pub use envelope::Envelope;
pub use key::{Alg, DeviceId, GroupId, Key, KeyHash};

/// Why an item was refused: the name of the rule it broke, as the format's
/// tables and the vectors name it (`cbor/shortest`, `sig/low-s`,
/// `records/device/name`). The format level uses the constants below; the
/// readers of each kind make their own with [`Rule::field`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Rule(&'static str);

impl Rule {
    /// A major type other than 0, 2, 3, 4 and 5: a negative integer.
    pub const NEGATIVE: Rule = Rule("cbor/negative");
    /// A tag.
    pub const TAG: Rule = Rule("cbor/tag");
    /// A float or a simple value (`false`, `true`, `null`, a break).
    pub const SIMPLE: Rule = Rule("cbor/simple");
    /// An indefinite length.
    pub const INDEFINITE: Rule = Rule("cbor/indefinite");
    /// Additional information 28 to 30.
    pub const RESERVED: Rule = Rule("cbor/reserved");
    /// An integer, length or count not in its shortest form.
    pub const SHORTEST: Rule = Rule("cbor/shortest");
    /// An integer of 2^63 or more.
    pub const INT_RANGE: Rule = Rule("cbor/int-range");
    /// A map key that is not an unsigned integer up to 65535.
    pub const MAP_KEY: Rule = Rule("cbor/map-key");
    /// Map keys not strictly increasing.
    pub const MAP_ORDER: Rule = Rule("cbor/map-order");
    /// Text that is not UTF-8.
    pub const UTF8: Rule = Rule("cbor/utf8");
    /// Containers nested more than 8 deep.
    pub const DEPTH: Rule = Rule("cbor/depth");
    /// An array or map of more than 4096 elements.
    pub const COUNT: Rule = Rule("cbor/count");
    /// Bytes after the item.
    pub const TRAILING: Rule = Rule("cbor/trailing");
    /// The item ends before its bytes do.
    pub const TRUNCATED: Rule = Rule("cbor/truncated");

    /// An envelope that is not `[body, sig]` or `[body, sig, sig2]` with
    /// `sig2` exactly when the body names `signer2`.
    pub const ENV_SHAPE: Rule = Rule("env/shape");
    /// A body over its kind's ceiling (section 13).
    pub const ENV_SIZE: Rule = Rule("env/size");
    /// A second signature over its ceiling of 4 KiB.
    pub const ENV_SIG2: Rule = Rule("env/sig2");
    /// A signature that is not 64 bytes.
    pub const SIG_SIZE: Rule = Rule("sig/size");
    /// `r` or `s` zero, or not below the group order.
    pub const SIG_RANGE: Rule = Rule("sig/range");
    /// A high `s`.
    pub const SIG_LOW_S: Rule = Rule("sig/low-s");
    /// A signature that does not verify.
    pub const SIG_VERIFY: Rule = Rule("sig/verify");

    /// An ES256 key of the wrong size, not uncompressed, or off the curve.
    pub const KEYS_ES256: Rule = Rule("keys/es256");
    /// An X-Wing key of the wrong size.
    pub const KEYS_XWING: Rule = Rule("keys/xwing");
    /// An X25519 key of the wrong size.
    pub const KEYS_X25519: Rule = Rule("keys/x25519");
    /// An SLH-DSA-SHA2-128s key that is not 32 bytes.
    pub const KEYS_SLH_DSA: Rule = Rule("keys/slh-dsa");
    /// A Key that is not `[alg, pub]`.
    pub const KEYS_SHAPE: Rule = Rule("keys/shape");

    /// A frame length off the grid, zero, or over the limit.
    pub const FRAME_GRID: Rule = Rule("frame/grid");
    /// Padding that is not zeros, or not the one padding of its message.
    pub const FRAME_PAD: Rule = Rule("frame/pad");
    /// A message that is not a map with its type in field 0.
    pub const FRAME_MESSAGE: Rule = Rule("frame/message");

    /// A message `grant` without its grant envelope, or a grant without its
    /// signer's key hash.
    pub const GRANTS_SHAPE: Rule = Rule("grants/shape");
    /// A key container that is not the template with its key.
    pub const CONTAINER: Rule = Rule("container/template");

    /// A field default written out (section 1, `form/default`).
    pub const FORM_DEFAULT: Rule = Rule("form/default");
    /// A critical field a command, grant or credential reader does not know.
    pub const FORM_CRITICAL: Rule = Rule("form/critical");

    /// A rule of a kind's own fields, named as the vectors name it
    /// (`records/device/name`, `commands/expires`).
    pub const fn field(name: &'static str) -> Rule {
        Rule(name)
    }

    /// The rule's name.
    pub const fn name(self) -> &'static str {
        self.0
    }
}

impl core::fmt::Display for Rule {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.0)
    }
}

/// SHA-256 over the concatenated parts.
pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// A character a list must not show as it is: the C0 and C1 controls and
/// DEL, the line and paragraph separators (U+2028, U+2029) and the bidi
/// controls (U+202A to U+202E, U+2066 to U+2069). The printer escapes
/// them, and a record's name refuses them.
pub fn is_hidden(c: char) -> bool {
    matches!(u32::from(c), 0..=0x1f | 0x7f..=0x9f | 0x2028..=0x202e | 0x2066..=0x2069)
}

/// A device's name (section 4.1): 1 to 64 bytes, no hidden character.
pub fn name_ok(name: &str) -> bool {
    (1..=64).contains(&name.len()) && !name.chars().any(is_hidden)
}

/// The fields below 256 a `device` record of 0.6 may carry (sections 3.2
/// and 4.1): the common ones without `expires_ms` and `signer2`, and the
/// device's own without `accepts` (15, gone). Any other field below 256
/// makes a reader hold the record. The record reader and the admin's
/// record in a grant both read this one list.
pub const DEVICE_FIELDS: [u16; 22] = [1, 2, 3, 4, 5, 6, 10, 11, 12, 13, 14, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26];
