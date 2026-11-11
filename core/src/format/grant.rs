// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! A leaf's grant (format section 7): one signed envelope `[body, sig]`,
//! label `cbb grant v1`, like every other signed thing.
//!
//! Every grant lists the leaf's `commanders`, and a leaf of either kind
//! obeys exactly those keys: an ordinary leaf's are admin keys, a guarded
//! leaf's the devices the root named. The root signs any grant; for an
//! ordinary leaf a key among the commanders of the leaf's current grant
//! signs one too, and the first grant comes from the admitter with the
//! root's record of that admin key. A guarded leaf takes grants from the
//! root only. The leaf keeps two counters, the root's and the admins', so a
//! root grant replaces an admin grant whatever the admin counter is, and an
//! old root grant is never taken again.

use alloc::vec::Vec;

use super::cbor::Value;
use super::envelope::Envelope;
use super::key::{Alg, DeviceId, Key, KeyHash};
use super::{Rule, sig};

/// The largest grant body.
pub const MAX_GRANT: usize = 2048;

/// Message `grant`'s field of the grant envelope.
pub const FIELD_GRANT: u16 = 2;
/// Message `grant`'s field of the root's record of the admin that signed
/// the leaf's first grant.
pub const FIELD_ADMIN: u16 = 3;

/// The grant's field of its counter.
pub const FIELD_COUNTER: u16 = 4;
/// The grant's field of its lifetime (a guarded leaf's only).
pub const FIELD_LIFE: u16 = 11;
/// The grant's field of the keys the leaf obeys.
pub const FIELD_COMMANDERS: u16 = 12;
/// The grant's field of its readers.
pub const FIELD_READERS: u16 = 13;
/// The grant's flag of a guarded leaf.
pub const FIELD_GUARDED: u16 = 15;
/// The most readers of a leaf.
pub const MAX_READERS: usize = 4;
/// The most commanders of a leaf.
pub const MAX_COMMANDERS: usize = 8;

/// A guarded leaf's grant that a root did not sign, or a grant without
/// `guarded` for a leaf that is guarded.
pub const RULE_GUARDED: Rule = Rule::field("grants/guarded");
/// More than eight commanders, one that is not an ES256 Key, or commanders
/// out of order.
pub const RULE_COMMANDERS: Rule = Rule::field("grants/commanders");
/// A lifetime in an ordinary leaf's grant.
pub const RULE_LIFE: Rule = Rule::field("grants/life");
/// More than four readers.
pub const RULE_READERS: Rule = Rule::field("grants/readers");
/// An admin's first grant without the root's record of that admin key, or
/// with one that does not make it an admin that admits.
pub const RULE_ADMIN: Rule = Rule::field("grants/admin");
/// A later grant signed by a key that is neither the root nor among the
/// commanders of the leaf's current grant.
pub const RULE_SIGNER: Rule = Rule::field("grants/signer");
/// A counter not above the leaf's last of its signer's side (the root's or
/// the admins').
pub const RULE_COUNTER: Rule = Rule::field("grants/counter");

/// A commander: its key hash and its uncompressed point.
pub type Commander = (KeyHash, [u8; 65]);

/// What a leaf keeps of the grants it took.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Kept {
    /// Whether the leaf is guarded; once it is, it stays so.
    pub guarded: bool,
    /// The counter of the last root grant, 0 before the first.
    pub root_counter: u64,
    /// The counter of the last admin grant, 0 before the first.
    pub admin_counter: u64,
    /// The commanders of the current grant, sorted by key hash.
    pub commanders: Vec<Commander>,
}

impl Kept {
    /// The point of the commander with this key hash: the keys the leaf
    /// obeys, and for an ordinary leaf the keys that may sign its next
    /// grant.
    pub fn commander(&self, hash: &KeyHash) -> Option<&[u8; 65]> {
        self.commanders.iter().find(|(h, _)| h == hash).map(|(_, p)| p)
    }
}

/// A grant as message `grant` carries it, checked to its signature, its
/// kind and the leaf's kept state.
#[derive(Clone, Debug)]
pub struct Granted<'a> {
    /// The grant envelope; its body is the grant.
    pub grant: Envelope<'a>,
    /// The root's record of the admin that signed the leaf's first grant.
    pub admin: Option<Envelope<'a>>,
    /// Whether the root signed it.
    pub by_root: bool,
    /// Whether the grant is a guarded leaf's.
    pub guarded: bool,
    /// Its counter.
    pub counter: u64,
    /// Its commanders.
    pub commanders: Vec<Commander>,
}

impl Granted<'_> {
    /// The leaf's state once it takes this grant.
    pub fn keep(&self, before: Option<&Kept>) -> Kept {
        let b = before.cloned().unwrap_or_default();
        Kept {
            guarded: b.guarded || self.guarded,
            root_counter: if self.by_root { self.counter } else { b.root_counter },
            admin_counter: if self.by_root { b.admin_counter } else { self.counter },
            commanders: self.commanders.clone(),
        }
    }
}

/// The admin key of the root's record in field 3, if it makes that key an
/// admin with `admit`: a `device` record (type 1) the root signed, with its
/// `admin` Key (20) and the admit bit in its `powers` (21).
fn admin_key(record: &Envelope<'_>, root: &[u8]) -> Result<[u8; 65], Rule> {
    record.verify(root, sig::LABEL_RECORD).map_err(|_| RULE_ADMIN)?;
    let m = &record.map;
    let root_hash = Key::new(Alg::Es256, root).hash();
    let by_root = m.get(3).and_then(Value::as_bytes).and_then(KeyHash::from_slice) == Some(root_hash);
    let device = m.get(1).and_then(Value::as_uint) == Some(1);
    let admits = m.get(21).and_then(Value::as_uint).is_some_and(|p| p & 1 == 1);
    let key = m.get(20).map(Key::from_value).transpose().map_err(|_| RULE_ADMIN)?.ok_or(RULE_ADMIN)?;
    if !(by_root && device && admits && key.alg == Alg::Es256) || key.check().is_err() {
        return Err(RULE_ADMIN);
    }
    key.public.try_into().map_err(|_| RULE_ADMIN)
}

/// The commanders of a grant body: at most eight ES256 Keys, sorted by key
/// hash, each once.
fn commanders(map: &Value<'_>) -> Result<Vec<Commander>, Rule> {
    let list = match map.get(FIELD_COMMANDERS) {
        None => return Ok(Vec::new()),
        Some(v) => v.as_array().ok_or(RULE_COMMANDERS)?,
    };
    if list.len() > MAX_COMMANDERS {
        return Err(RULE_COMMANDERS);
    }
    let mut out: Vec<Commander> = Vec::with_capacity(list.len());
    for x in list {
        let k = Key::from_value(x).map_err(|_| RULE_COMMANDERS)?;
        if k.alg != Alg::Es256 || k.check().is_err() {
            return Err(RULE_COMMANDERS);
        }
        let h = k.hash();
        if out.last().is_some_and(|(prev, _)| prev.0 >= h.0) {
            return Err(RULE_COMMANDERS);
        }
        out.push((h, k.public.try_into().map_err(|_| RULE_COMMANDERS)?));
    }
    Ok(out)
}

/// Reads a grant from the map of message `grant` (or the Welcome's `grant`)
/// for a leaf that keeps `kept` (None before its first grant): field 2 the
/// grant envelope, 3 the root's record of the admin that signed a first
/// grant. A root grant is checked with the root's uncompressed point and
/// must be above the kept root counter. Any other grant is an ordinary
/// leaf's: the first one signed by an admin key that the record in field 3
/// makes an admin with `admit`, a later one by a commander of the kept
/// grant, above the kept admin counter. Then the rules of the two kinds of
/// leaf (design-small-device section 15): a lifetime only in a guarded
/// grant; at most eight commanders and four readers. The grant's other
/// fields are its reader's matter.
pub fn read<'a>(msg: &Value<'a>, root: &[u8], kept: Option<&Kept>) -> Result<Granted<'a>, Rule> {
    let grant = Envelope::from_value(msg.get(FIELD_GRANT).ok_or(Rule::GRANTS_SHAPE)?)?;
    if grant.body.len() > MAX_GRANT {
        return Err(Rule::ENV_SIZE);
    }
    let signer = grant.signer().and_then(Value::as_bytes).and_then(KeyHash::from_slice).ok_or(Rule::GRANTS_SHAPE)?;
    let map = &grant.map;
    let counter = map.get(FIELD_COUNTER).and_then(Value::as_uint).ok_or(Rule::GRANTS_SHAPE)?;
    let guarded = match map.get(FIELD_GUARDED) {
        None => false,
        Some(Value::Uint(1)) => true,
        Some(_) => return Err(Rule::field("grants/guarded-value")),
    };
    let was_guarded = kept.is_some_and(|k| k.guarded);
    let by_root = signer == Key::new(Alg::Es256, root).hash();
    let mut admin = None;
    if by_root {
        grant.verify(root, sig::LABEL_GRANT)?;
        if kept.is_some_and(|k| counter <= k.root_counter) {
            return Err(RULE_COUNTER);
        }
    } else {
        if guarded || was_guarded {
            return Err(RULE_GUARDED);
        }
        match kept {
            None => {
                let record = Envelope::from_value(msg.get(FIELD_ADMIN).ok_or(RULE_ADMIN)?)?;
                let key = admin_key(&record, root)?;
                if Key::new(Alg::Es256, &key).hash() != signer {
                    return Err(RULE_ADMIN);
                }
                grant.verify(&key, sig::LABEL_GRANT)?;
                admin = Some(record);
            }
            Some(k) => {
                let point = k.commander(&signer).ok_or(RULE_SIGNER)?;
                grant.verify(point, sig::LABEL_GRANT)?;
                if counter <= k.admin_counter {
                    return Err(RULE_COUNTER);
                }
            }
        }
    }
    if was_guarded && !guarded {
        return Err(RULE_GUARDED);
    }
    if !guarded && map.get(FIELD_LIFE).is_some() {
        return Err(RULE_LIFE);
    }
    let commanders = commanders(map)?;
    if map.get(FIELD_READERS).and_then(Value::as_array).is_some_and(|r| r.len() > MAX_READERS) {
        return Err(RULE_READERS);
    }
    Ok(Granted { grant, admin, by_root, guarded, counter, commanders })
}

/// A copy to a leaf from a device its grant does not let send it copies.
pub const RULE_COPY_SENDER: Rule = Rule::field("copy/leaf-sender");

/// Whether a leaf takes a copy whose header names origin, by the grant it
/// keeps (owner, 2026-11-11): an ordinary leaf takes copies from its readers
/// (field 13, `[device ID, Key]`), the same devices it seals to; a guarded
/// leaf only from its commanders (field 12, Keys), whose device IDs are
/// their keys' IDs.
pub fn copy_sender(grant: &Value<'_>, origin: &DeviceId) -> Result<(), Rule> {
    let list = |field| grant.get(field).and_then(Value::as_array).unwrap_or(&[]);
    let named = if grant.get(FIELD_GUARDED).is_some() {
        list(FIELD_COMMANDERS).iter().any(|k| Key::from_value(k).is_ok_and(|k| k.device_id() == *origin))
    } else {
        list(FIELD_READERS)
            .iter()
            .any(|r| r.as_array().and_then(|a| a.first()).and_then(Value::as_bytes) == Some(origin.0.as_slice()))
    };
    if named { Ok(()) } else { Err(RULE_COPY_SENDER) }
}
