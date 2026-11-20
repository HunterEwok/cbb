// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The tables of the member connection's own messages (format sections 9.2
//! and 9.3): the hello, ping and bye, the IDs a member holds, the signed
//! releases and entry points it passes on, the blob's chunks it asks for,
//! the devices it reaches and the attestations of its keys. The copy (t 2)
//! is read by the copy's reader (`crate::format::copy`), as it is inside
//! the hello; the intro (t 8) by the join's (`crate::join::intro`).

use super::{Field, Table, Ty};

const fn f(n: u16, rule: &'static str, ty: Ty, needed: bool) -> Field {
    Field { n, rule, ty, needed }
}

pub const T_HELLO: u64 = 1;
pub const T_PING: u64 = 3;
pub const T_BYE: u64 = 4;
pub const T_HAVE: u64 = 6;
pub const T_RELEASE: u64 = 12;
pub const T_GET: u64 = 13;
pub const T_MISSING: u64 = 14;
pub const T_REACH: u64 = 18;
pub const T_EVIDENCE: u64 = 19;
pub const T_ENTRIES: u64 = 25;
pub const T_WANT: u64 = 30;

/// The most action names a hello offers.
pub const MAX_ACTIONS: usize = 64;
/// The longest action name: lowercase letters, digits and dashes.
pub const MAX_ACTION_NAME: usize = 32;
/// The longest system or program version a hello names.
pub const MAX_VERSION_TEXT: usize = 32;
/// The longest release archive name a hello names (packaging/archive.sh's
/// widest is 61 bytes).
pub const MAX_ARCHIVE: usize = 64;
/// The largest release, keys, channel or entries file a message carries,
/// as published: a body of `release::MAX_BODY` in base64 with its
/// signature, in JSON.
pub const MAX_RELEASE_FILE: usize = 512 << 10;
/// The largest attestation of a key an `evidence` message carries: a
/// chain of certificates or a TPM's quote with its certificates.
pub const MAX_EVIDENCE: usize = 64 << 10;

/// A name, as the other tables give it (format 20.6).
const NAME: Ty = Ty::Text(128);
const B32: Ty = Ty::Bytes(32);
const MS: Ty = Ty::Uint { min: 1, max: (1 << 63) - 1 };
const FILE: Ty = Ty::BytesUpTo(MAX_RELEASE_FILE);

/// The hello (t 1, section 9.3): what a member says of itself when the
/// connection opens. Everything in it is shown or asks for something; what
/// a device may do comes from its records.
pub static HELLO: Table = Table {
    shape: "hello/shape",
    fields: &[
        f(2, "hello/caps", Ty::Uint { min: 1, max: 7 }, false),
        f(3, "hello/os", Ty::Uint { min: 1, max: u32::MAX as u64 }, false),
        f(4, "hello/name", NAME, false),
        f(5, "hello/wall_ms", MS, false),
        f(6, "hello/current", Ty::Copy, false),
        f(7, "hello/records", B32, false),
        f(8, "hello/count", Ty::Uint { min: 1, max: u32::MAX as u64 }, false),
        f(10, "hello/mode", Ty::Uint { min: 1, max: 2 }, false),
        f(11, "hello/muted", Ty::Flag, false),
        f(12, "hello/muted_for_ms", Ty::Uint { min: 1, max: crate::commands::orders::MAX_MUTE_MS }, false),
        f(13, "hello/device", Ty::Map(&HELLO_DEVICE), false),
        f(14, "hello/key_store", Ty::Uint { min: 1, max: 4 }, false),
        f(15, "hello/actions", Ty::Array { of: &Ty::Text(MAX_ACTION_NAME), max: MAX_ACTIONS }, false),
        f(16, "hello/release_seq", MS, false),
        f(17, "hello/release_keys_seq", MS, false),
        f(18, "hello/entries_seq", MS, false),
        f(19, "hello/entries_keys_seq", MS, false),
        f(20, "hello/features", Ty::Uint { min: 1, max: 1 }, false),
        f(21, "hello/keys_epoch", MS, false),
    ],
};

/// The hello's `device` map (field 13), also an Info's
/// (`tables::INFO_DEVICE`): its form, its system's and cbb's versions, its
/// MAC address and the release archive it updates from.
pub static HELLO_DEVICE: Table = Table {
    shape: "hello/device/shape",
    fields: &[
        f(1, "hello/device/form", Ty::Uint { min: 1, max: 12 }, false),
        f(2, "hello/device/os_version", Ty::Text(MAX_VERSION_TEXT), false),
        f(3, "hello/device/version", Ty::Text(MAX_VERSION_TEXT), false),
        f(4, "hello/device/mac", Ty::Bytes(6), false),
        f(5, "hello/device/archive", Ty::Text(MAX_ARCHIVE), false),
    ],
};

pub static PING: Table = Table { shape: "ping/shape", fields: &[] };
pub static BYE: Table = Table { shape: "bye/shape", fields: &[] };

/// `have` (t 6): "I hold these", sorted record IDs (sync by IDs).
pub static HAVE: Table = Table {
    shape: "have/shape",
    fields: &[f(2, "have/ids", Ty::Set { of: &B32, max: crate::records::sync::HAVE_IDS }, true)],
};

/// `want` (t 30): "give me these": the record IDs the asker's set names
/// and lacks (`RecordSet::missing`) and the hash of the list a change of
/// root waits for (`RecordSet::missing_list`), at least one of the two
/// (rule `want/empty`). The answer is message `records`, built only from
/// `RecordSet::for_peer_by_id` and `RecordSet::lists_for_peer`.
pub static WANT: Table = Table {
    shape: "want/shape",
    fields: &[
        f(2, "want/ids", Ty::Set { of: &B32, max: crate::records::sync::HAVE_IDS }, false),
        f(3, "want/list", B32, false),
    ],
};

/// `release` (t 12): the signed release a member passes on, its files as
/// published (docs/protocol.md, "Signed releases").
pub static RELEASE: Table = Table {
    shape: "release/shape",
    fields: &[
        f(2, "release/keys", FILE, true),
        f(3, "release/channel", FILE, true),
        f(4, "release/release", FILE, true),
    ],
};

/// `entries` (t 25): the signed entry points, as `release` carries the
/// release: the keys file and `entries.json`.
pub static ENTRIES: Table =
    Table { shape: "entries/shape", fields: &[f(2, "entries/keys", FILE, true), f(3, "entries/entries", FILE, true)] };

/// `get` (t 13): a range of a blob by its SHA-256; no length cancels.
pub static GET: Table = Table {
    shape: "get/shape",
    fields: &[f(2, "get/sha256", B32, true), f(3, "get/offset", MS, false), f(4, "get/length", MS, false)],
};

/// `missing` (t 14): the answer to a `get` the member cannot serve, with
/// its fields.
pub static MISSING: Table = Table {
    shape: "missing/shape",
    fields: &[f(2, "missing/sha256", B32, true), f(3, "missing/offset", MS, false), f(4, "missing/length", MS, false)],
};

/// `reach` (t 18): the devices a member is connected to, sorted.
pub static REACH: Table = Table {
    shape: "reach/shape",
    fields: &[f(2, "reach/devices", Ty::Set { of: &Ty::Bytes(16), max: crate::records::MAX_DEVICES }, false)],
};

/// `evidence` (t 19): an attestation of one of the sender's keys.
pub static EVIDENCE: Table = Table {
    shape: "evidence/shape",
    fields: &[
        f(2, "evidence/format", Ty::Uint { min: 1, max: 4 }, true),
        f(3, "evidence/key", B32, true),
        f(4, "evidence/data", Ty::BytesUpTo(MAX_EVIDENCE), true),
    ],
};

/// Every table of this file, for the vectors.
pub static ALL: [&Table; 12] =
    [&HELLO, &HELLO_DEVICE, &PING, &BYE, &HAVE, &WANT, &RELEASE, &ENTRIES, &GET, &MISSING, &REACH, &EVIDENCE];

/// The table of message type t, if this file numbers it.
pub fn of(t: u64) -> Option<&'static Table> {
    Some(match t {
        T_HELLO => &HELLO,
        T_PING => &PING,
        T_BYE => &BYE,
        T_HAVE => &HAVE,
        T_WANT => &WANT,
        T_RELEASE => &RELEASE,
        T_GET => &GET,
        T_MISSING => &MISSING,
        T_REACH => &REACH,
        T_EVIDENCE => &EVIDENCE,
        T_ENTRIES => &ENTRIES,
        _ => return None,
    })
}
