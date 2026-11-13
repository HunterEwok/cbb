// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! What a reader of this version does with an optional field whose value
//! lies outside what this version knows (format 20.5, "one rule for a value
//! from a later version"). Shape always refuses: the CBOR type, the length
//! of a fixed-size key or ID, a key off its curve, an envelope that does not
//! parse, a list out of its order. A needed field out of range refuses too.
//!
//! For an optional field the answer is in [`OPTIONAL`], one row a field,
//! with the reason. The default is to refuse: a value reads as absent only
//! where absent is neutral or stricter, never where absent would grant
//! more, change the mode, or change what the person is shown (an
//! invitation's ID, an admin key and its proof, a flag that allows, an
//! expiry, an address whose absence falls back to another). A test walks
//! every table and finds each optional field here exactly once.

use super::{Table, tables as t, wave4 as w};

/// What a reader of this version does with an optional field's value that
/// is out of range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Later {
    /// Refuses the message (the field's rule).
    Refuse,
    /// Reads as absent; a list keeps the entries it understands and reads
    /// as absent when none is left.
    Absent,
    /// Bits: the bits this version does not know are ignored and grant
    /// nothing; the field reads with the bits it knows, absent when none is
    /// left.
    Bits(u64),
    /// A transport's table (`obfuscation`, `vless`): an unknown field or a
    /// value out of range makes that way unusable, never the message that
    /// carries it. The field reads as the empty map, which the table's
    /// strict reader refuses ([`unusable`]).
    Unusable,
}

/// One optional field's row.
#[derive(Clone, Copy, Debug)]
pub struct Optional {
    pub table: &'static Table,
    pub n: u16,
    pub later: Later,
    /// Why, in a few words: what absent would mean.
    pub why: &'static str,
}

const fn o(table: &'static Table, n: u16, later: Later, why: &'static str) -> Optional {
    Optional { table, n, later, why }
}

use Later::{Absent, Bits, Refuse, Unusable};

/// Every optional field of every message table, with what a value out of
/// range reads as.
pub static OPTIONAL: &[Optional] = &[
    // The Welcome.
    o(&t::WELCOME, 4, Absent, "keys statements also come by sync; none grants nothing"),
    o(&t::WELCOME, 6, Refuse, "a leaf's grant: what it obeys"),
    o(&t::WELCOME, 7, Absent, "server credentials also come with the next period; none reaches no server"),
    o(&t::WELCOME, 10, Refuse, "the recovery cut's list must be carried"),
    o(&t::GRANT, 4, Refuse, "the grant's own reader decides"),
    o(&t::GRANT, 5, Refuse, "absent is the default life: an expiry"),
    // The invitation.
    o(&t::PATH, 2, Refuse, "endpoints: absent would fall back to another address"),
    o(&t::PATH, 3, Refuse, "the hub's key"),
    o(&t::PATH, 4, Refuse, "the guest key"),
    o(&t::PATH, 5, Refuse, "the guest's pre-shared key"),
    o(&t::PATH, 6, Unusable, "absent settings would mean plain WireGuard"),
    o(&t::PROFILE, 2, Bits(0x0f), "rights: unknown bits grant nothing"),
    o(&t::PROFILE, 3, Refuse, "home only: absent would allow more"),
    o(&t::PROFILE, 4, Refuse, "guarded: absent would allow more"),
    // A transport's settings and way.
    o(&t::OBFUSCATION, 6, Refuse, "inside a transport: the way is unusable"),
    o(&t::VLESS, 2, Refuse, "inside a transport: absent is a default port"),
    o(&t::VLESS, 3, Refuse, "inside a transport: absent is a default host"),
    o(&t::VLESS, 4, Refuse, "inside a transport: absent is a default path"),
    // The hub's offer and the hubs.
    o(&t::OFFER, 2, Refuse, "endpoints: absent would fall back to the address dialled"),
    o(&t::OFFER, 3, Unusable, "absent settings would mean plain WireGuard"),
    o(&t::OFFER, 4, Unusable, "the way over VLESS"),
    o(&t::OFFER, 6, Refuse, "moved: changes what the device does"),
    o(&t::OFFER, 7, Refuse, "the hub's next key"),
    o(&t::OFFER, 8, Refuse, "the confirmation tag"),
    o(&t::OFFER, 9, Refuse, "endpoint keys: absent would fall back to the offer's key"),
    o(&t::HUBS, 2, Refuse, "stopped: a mode"),
    o(&t::HUBS, 3, Refuse, "serving: a mode"),
    o(&t::GUEST, 4, Refuse, "the guest's pre-shared key"),
    o(&t::GUEST, 5, Refuse, "an expiry"),
    o(&t::GUEST, 6, Refuse, "the offer"),
    o(&t::GUEST, 7, Refuse, "a reason the person is shown"),
    o(&t::GUEST, 8, Refuse, "the connection it belongs to"),
    o(&t::GUEST, 9, Refuse, "the data"),
    o(&t::GUEST, 10, Refuse, "the device"),
    o(&t::GUEST, 11, Refuse, "an invitation's ID"),
    o(&t::CREDENTIALS, 3, Unusable, "settings for a later version: never applied by 0.6"),
    // Requests that wait.
    o(&t::REQUEST, 5, Refuse, "how long it waited: the person is shown it"),
    o(&t::INFO, 2, Refuse, "the system: a registry number, any in range kept"),
    o(&t::INFO, 3, Bits(0x07), "capabilities: unknown bits grant nothing"),
    o(&t::INFO, 5, Refuse, "an admin key"),
    o(&t::INFO, 6, Refuse, "an admin key's proof"),
    o(&t::INFO, 7, Refuse, "the keys statement"),
    o(&t::INFO, 8, Refuse, "the hello's device map"),
    o(&t::INFO, 9, Refuse, "an invitation's ID"),
    o(&t::DISMISS, 3, Refuse, "the key: absent would dismiss every request of the invitation"),
    // The servers.
    o(&t::FWD_REGISTER, 4, Unusable, "absent settings would mean plain WireGuard"),
    o(&t::FWD_REGISTER, 5, Refuse, "the VLESS user"),
    o(&t::FWD_REGISTERED, 4, Unusable, "the way over VLESS"),
    o(&t::RELAY_CHALLENGE, 3, Refuse, "root: a mode"),
    o(&t::RELAY_REGISTER, 5, Refuse, "the root's key"),
    o(&t::RELAY_ONLINE, 2, Refuse, "who is online: the person is shown it"),
    o(&t::RESULT, 5, Refuse, "a reason the person is shown"),
    o(&t::RESULT, 6, Refuse, "the offer"),
    // Wave 4.
    o(&w::NONCE, 2, Refuse, "the one-time number"),
    o(&w::ROOTS, 2, Refuse, "the recovery heads a leaf needs"),
    o(&w::ROOTS, 3, Refuse, "a root's fork"),
];

/// What a value out of range of field n of the table reads as: its row, or
/// [`Later::Refuse`] (a needed field, or none listed).
pub fn of(table: &Table, n: u16) -> Later {
    OPTIONAL.iter().find(|r| core::ptr::eq(r.table, table) && r.n == n).map_or(Refuse, |r| r.later)
}

/// Reports whether v is the map a transport's table reads as when it is
/// unusable ([`Later::Unusable`]): the empty map.
pub fn unusable(v: &super::Value<'_>) -> bool {
    v.as_map().is_some_and(<[_]>::is_empty)
}

/// Whether a row fits its field: Bits only on an unsigned integer, Unusable
/// only on a transport's map.
#[cfg(test)]
pub(crate) fn fits(r: &Optional) -> bool {
    use super::Ty;
    let Some(f) = r.table.fields.iter().find(|f| f.n == r.n && !f.needed) else { return false };
    match r.later {
        Bits(mask) => matches!(f.ty, Ty::Uint { max, .. } if max == mask),
        Unusable => matches!(f.ty, Ty::Map(m) if core::ptr::eq(m, &t::OBFUSCATION) || core::ptr::eq(m, &t::VLESS)),
        Refuse | Absent => true,
    }
}
