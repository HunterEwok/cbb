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
//! old root grant is never taken again. An admin grant names the root
//! counter it was made under (field 17) and counts its own from 1 again
//! after each root grant, so one made before a root grant never beats it.
//! A later admin grant also names the grant it replaces (field 18, the
//! SHA-256 of the kept grant's body), so an older one held back is never
//! taken after a newer one.

use alloc::vec::Vec;

use super::cbor::{Value, is_set};
use super::envelope::Envelope;
use super::key::{Alg, DeviceId, GroupId, Key, KeyHash};
use super::{Rule, sha256, sig};

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
/// An admin grant's field of the root counter it was made under (absent:
/// 0, before any root grant); a root grant has none.
pub const FIELD_ROOT_COUNTER: u16 = 17;
/// An admin grant's field of the grant it replaces: the SHA-256 of the
/// body of the leaf's kept grant (every admin grant but the first).
pub const FIELD_REPLACES: u16 = 18;
/// The grant's field of its type (1).
pub const FIELD_TYPE: u16 = 1;
/// The grant's field of its group.
pub const FIELD_GROUP: u16 = 2;
/// The grant's field of its leaf's device ID.
pub const FIELD_LEAF: u16 = 10;
/// The fields of a grant below the optional zone (256): any other is a
/// critical field this version does not know, and `signer2` (8) is one.
pub const FIELDS: [u16; 14] = [1, 2, 3, 4, 6, 10, 11, 12, 13, 14, 15, 16, 17, 18];
/// The longest lifetime of a guarded grant: 40 days.
pub const MAX_LIFE_MS: u64 = 3_456_000_000;
/// The most readers of a leaf.
pub const MAX_READERS: usize = 4;
/// The most commanders of a leaf.
pub const MAX_COMMANDERS: usize = 8;
/// The grant's field of the only peers the leaf connects with.
pub const FIELD_NEIGHBORS: u16 = 14;
/// The most neighbours of a leaf.
pub const MAX_NEIGHBORS: usize = 8;
/// Neighbours that are not a list of at most eight key hashes (bytes 32)
/// in a set.
pub const RULE_NEIGHBORS: Rule = Rule::field("grants/neighbors");

/// A guarded leaf's grant that a root did not sign, or a grant without
/// `guarded` for a leaf that is guarded.
pub const RULE_GUARDED: Rule = Rule::field("grants/guarded");
/// More than eight commanders, one that is not an ES256 Key, or commanders
/// out of order.
pub const RULE_COMMANDERS: Rule = Rule::field("grants/commanders");
/// A lifetime in an ordinary leaf's grant, or a guarded grant's lifetime
/// that is not an integer from 1 to 40 days.
pub const RULE_LIFE: Rule = Rule::field("grants/life");
/// Readers that are not a list of at most four `[device ID, ES256 Key]` in
/// a set.
pub const RULE_READERS: Rule = Rule::field("grants/readers");
/// An admin's first grant without the root's record of that admin key, or
/// with one that does not make it an admin that admits.
pub const RULE_ADMIN: Rule = Rule::field("grants/admin");
/// A later grant signed by a key that is neither the root nor among the
/// commanders of the leaf's current grant.
pub const RULE_SIGNER: Rule = Rule::field("grants/signer");
/// A counter not above the leaf's last of its signer's side (the root's or
/// the admins'), an admin grant made under another root counter than the
/// leaf's, or a root grant that names one.
pub const RULE_COUNTER: Rule = Rule::field("grants/counter");

/// An admin grant after the first that does not name the leaf's kept grant
/// as the one it replaces, or a root grant or a first grant that names one.
pub const RULE_REPLACES: Rule = Rule::field("grants/replaces");

/// A commander: its key hash and its uncompressed point.
pub type Commander = (KeyHash, [u8; 65]);

/// What a leaf keeps of the grants it took.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Kept {
    /// Whether the leaf is guarded; once it is, it stays so.
    pub guarded: bool,
    /// The counter of the last root grant, 0 before the first.
    pub root_counter: u64,
    /// The counter of the last admin grant since the last root grant, 0
    /// before the first.
    pub admin_counter: u64,
    /// The commanders of the current grant, sorted by key hash.
    pub commanders: Vec<Commander>,
    /// The SHA-256 of the current grant's body.
    pub grant_hash: [u8; 32],
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
            admin_counter: if self.by_root { 0 } else { self.counter },
            commanders: self.commanders.clone(),
            grant_hash: sha256(&[self.grant.body]),
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
/// for the leaf `leaf` of group `group` that keeps `kept` (None before its
/// first grant): field 2 the grant envelope, 3 the root's record of the
/// admin that signed a first grant.
///
/// The grant must be of type 1, for this group and this leaf, with no
/// critical field this version does not know (`signer2` among them). A root
/// grant is checked with the root's uncompressed point and must be above
/// the kept root counter. Any other grant is an ordinary leaf's: the first
/// one signed by an admin key that the record in field 3 makes an admin
/// with `admit`; a later one by a commander of the kept grant, made under
/// the kept root counter, above the kept admin counter, naming the kept
/// grant as the one it replaces. Then the rules of the two kinds of leaf
/// (design-small-device section 15): a lifetime only in a guarded grant and
/// within 40 days; at most eight commanders, four readers
/// `[device ID, Key]` and eight neighbours, each list a set.
pub fn read<'a>(
    msg: &Value<'a>,
    root: &[u8],
    leaf: &DeviceId,
    group: &GroupId,
    kept: Option<&Kept>,
) -> Result<Granted<'a>, Rule> {
    let grant = Envelope::from_value(msg.get(FIELD_GRANT).ok_or(Rule::GRANTS_SHAPE)?)?;
    if grant.body.len() > MAX_GRANT {
        return Err(Rule::ENV_SIZE);
    }
    let map = &grant.map;
    if map.as_map().unwrap_or(&[]).iter().any(|(k, _)| *k < 256 && !FIELDS.contains(k)) {
        return Err(Rule::FORM_CRITICAL);
    }
    let bytes_of = |field| map.get(field).and_then(Value::as_bytes);
    if map.get(FIELD_TYPE).and_then(Value::as_uint) != Some(1)
        || bytes_of(FIELD_GROUP) != Some(group.0.as_slice())
        || bytes_of(FIELD_LEAF) != Some(leaf.0.as_slice())
    {
        return Err(Rule::GRANTS_SHAPE);
    }
    let signer = grant.signer().and_then(Value::as_bytes).and_then(KeyHash::from_slice).ok_or(Rule::GRANTS_SHAPE)?;
    let counter = map.get(FIELD_COUNTER).and_then(Value::as_uint).ok_or(Rule::GRANTS_SHAPE)?;
    let guarded = match map.get(FIELD_GUARDED) {
        None => false,
        Some(Value::Uint(1)) => true,
        Some(_) => return Err(Rule::field("grants/guarded-value")),
    };
    let was_guarded = kept.is_some_and(|k| k.guarded);
    let by_root = signer == Key::new(Alg::Es256, root).hash();
    let made_under = match map.get(FIELD_ROOT_COUNTER) {
        None => 0,
        Some(Value::Uint(0)) => return Err(Rule::FORM_DEFAULT),
        Some(v) => v.as_uint().ok_or(Rule::GRANTS_SHAPE)?,
    };
    let replaces = match map.get(FIELD_REPLACES) {
        None => None,
        Some(v) => Some(v.as_bytes().filter(|b| b.len() == 32).ok_or(RULE_REPLACES)?),
    };
    let mut admin = None;
    if by_root {
        grant.verify(root, sig::LABEL_GRANT)?;
        if map.get(FIELD_ROOT_COUNTER).is_some() || kept.is_some_and(|k| counter <= k.root_counter) {
            return Err(RULE_COUNTER);
        }
        if replaces.is_some() {
            return Err(RULE_REPLACES);
        }
    } else {
        if guarded || was_guarded {
            return Err(RULE_GUARDED);
        }
        if made_under != kept.map_or(0, |k| k.root_counter) {
            return Err(RULE_COUNTER);
        }
        match kept {
            None => {
                let record = Envelope::from_value(msg.get(FIELD_ADMIN).ok_or(RULE_ADMIN)?)?;
                let key = admin_key(&record, root)?;
                if Key::new(Alg::Es256, &key).hash() != signer {
                    return Err(RULE_ADMIN);
                }
                grant.verify(&key, sig::LABEL_GRANT)?;
                if replaces.is_some() {
                    return Err(RULE_REPLACES);
                }
                admin = Some(record);
            }
            Some(k) => {
                let point = k.commander(&signer).ok_or(RULE_SIGNER)?;
                grant.verify(point, sig::LABEL_GRANT)?;
                if counter <= k.admin_counter {
                    return Err(RULE_COUNTER);
                }
                if replaces != Some(k.grant_hash.as_slice()) {
                    return Err(RULE_REPLACES);
                }
            }
        }
    }
    if was_guarded && !guarded {
        return Err(RULE_GUARDED);
    }
    match (guarded, map.get(FIELD_LIFE)) {
        (_, None) => {}
        (true, Some(Value::Uint(n))) if (1..=MAX_LIFE_MS).contains(n) => {}
        _ => return Err(RULE_LIFE),
    }
    let commanders = commanders(map)?;
    let list = |field, rule| match map.get(field) {
        None => Ok(&[][..]),
        Some(v) => v.as_array().ok_or(rule),
    };
    let readers = list(FIELD_READERS, RULE_READERS)?;
    let reader_ok = |r: &Value<'_>| match r.as_array() {
        Some([Value::Bytes(id), k]) => {
            id.len() == 16 && Key::from_value(k).is_ok_and(|k| k.alg == Alg::Es256 && k.check().is_ok())
        }
        _ => false,
    };
    if readers.len() > MAX_READERS || !is_set(readers) || !readers.iter().all(reader_ok) {
        return Err(RULE_READERS);
    }
    let neighbors = list(FIELD_NEIGHBORS, RULE_NEIGHBORS)?;
    let neighbor_ok = |n: &Value<'_>| n.as_bytes().is_some_and(|b| b.len() == 32);
    if neighbors.len() > MAX_NEIGHBORS || !is_set(neighbors) || !neighbors.iter().all(neighbor_ok) {
        return Err(RULE_NEIGHBORS);
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
