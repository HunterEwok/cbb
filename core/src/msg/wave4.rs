// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The tables of the messages wave 4 adds (format sections 9.2 and 9.4):
//! a device's keys statements, a command, a guarded leaf's one-time number,
//! the freshness beacon, the request to seal a copy again, and the roots a
//! leaf needs. What each
//! carries (a statement, a command, a beacon) is read by its own reader;
//! the copy (t 2) is read by the copy's (`crate::format::copy`).

use super::{Field, Table, Ty};

const fn f(n: u16, rule: &'static str, ty: Ty, needed: bool) -> Field {
    Field { n, rule, ty, needed }
}

pub const T_KEYS: u64 = 7;
pub const T_COMMAND: u64 = 9;
pub const T_NONCE: u64 = 21;
pub const T_BEACON: u64 = 22;
pub const T_RESEAL: u64 = 23;
pub const T_ROOTS: u64 = 24;

/// Message `keys`: up to 256 statements, the sender's own and those it
/// passes on.
pub static KEYS: Table = Table {
    shape: "keys-message/shape",
    fields: &[f(2, "keys-message/list", Ty::Array { of: &Ty::Envelope, max: 256 }, true)],
};
/// Message `command`: one command's envelope.
pub static COMMAND: Table = Table { shape: "command/shape", fields: &[f(2, "command/envelope", Ty::Envelope, true)] };
/// Message `nonce`: from a guarded leaf, its one-time number for the peer's
/// next command; to it, without field 2, "give me one".
pub static NONCE: Table = Table { shape: "nonce/shape", fields: &[f(2, "nonce/nonce", Ty::Bytes(16), false)] };
/// Message `beacon`: one beacon's envelope.
pub static BEACON: Table = Table { shape: "beacon/shape", fields: &[f(2, "beacon/envelope", Ty::Envelope, true)] };
/// Message `reseal`: "seal copy 2 to me again, at my epoch 3".
pub static RESEAL: Table = Table {
    shape: "reseal/shape",
    fields: &[
        f(2, "reseal/copy", Ty::Bytes(16), true),
        f(3, "reseal/epoch", Ty::Uint { min: 1, max: (1 << 63) - 1 }, true),
    ],
};
/// Message `roots`, to a leaf: 2 the recovery heads it needs, at most
/// MAX_RECOVERY; 3 two records of its root at one seq, the root's fork,
/// which stops the leaf obeying that root (`grant::fork`). Exactly two.
pub static ROOTS: Table = Table {
    shape: "roots/shape",
    fields: &[
        f(2, "roots/heads", Ty::Array { of: &Ty::Envelope, max: crate::format::grant::MAX_RECOVERY as usize }, false),
        f(3, "roots/fork", Ty::Array { of: &Ty::Envelope, max: 2 }, false),
    ],
};

/// Every table of this file, for the vectors.
pub static ALL: [&Table; 6] = [&KEYS, &COMMAND, &NONCE, &BEACON, &RESEAL, &ROOTS];

/// The table of message type t, if wave 4 numbers it.
pub fn of(t: u64) -> Option<&'static Table> {
    Some(match t {
        T_KEYS => &KEYS,
        T_COMMAND => &COMMAND,
        T_NONCE => &NONCE,
        T_BEACON => &BEACON,
        T_RESEAL => &RESEAL,
        T_ROOTS => &ROOTS,
        _ => return None,
    })
}
