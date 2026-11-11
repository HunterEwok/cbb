// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The leaf's grant batch (format section 7): the root signs the root of a
//! Merkle tree of grant bodies, and each leaf gets the batch, its own grant
//! and the path of at most 8 sibling hashes from its grant up.
//!
//! A tree leaf is SHA-256(`0x00 ‖ grant body`), the leaves sorted
//! bytewise; a level pairs neighbours, SHA-256(`0x01 ‖ left ‖ right`), and an
//! odd last node goes up unchanged.

use alloc::vec::Vec;

use super::cbor::Value;
use super::envelope::Envelope;
use super::key::{Alg, Key, KeyHash};
use super::{Rule, sha256, sig};

/// The most grants in one batch.
pub const MAX_COUNT: u64 = 256;
/// The longest path (2^8 = 256 grants).
pub const MAX_PATH: usize = 8;
/// The largest grant body.
pub const MAX_GRANT: usize = 2048;

/// The batch's field of the tree's root.
pub const FIELD_MERKLE: u16 = 10;
/// The batch's field of the number of grants.
pub const FIELD_COUNT: u16 = 11;

/// The tree leaf of a grant body.
pub fn leaf(body: &[u8]) -> [u8; 32] {
    sha256(&[&[0], body])
}

fn node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    sha256(&[&[1], left, right])
}

/// The root of the tree over sorted leaves, and each leaf's path.
pub fn tree(leaves: &[[u8; 32]]) -> ([u8; 32], Vec<Vec<[u8; 32]>>) {
    let mut paths: Vec<Vec<[u8; 32]>> = leaves.iter().map(|_| Vec::new()).collect();
    let mut pos: Vec<usize> = (0..leaves.len()).collect();
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    while level.len() > 1 {
        let next: Vec<[u8; 32]> = level
            .chunks(2)
            .map(|pair| match pair {
                [l, r] => node(l, r),
                [one] => *one,
                _ => [0; 32],
            })
            .collect();
        for (path, p) in paths.iter_mut().zip(pos.iter_mut()) {
            if let Some(sib) = level.get(*p ^ 1) {
                path.push(*sib);
            }
            *p /= 2;
        }
        level = next;
    }
    (level.first().copied().unwrap_or([0; 32]), paths)
}

/// Recomputes the root from a leaf, its index among count leaves and its
/// path, which must be used up exactly.
pub fn root_of(leaf: [u8; 32], index: u64, count: u64, path: &[[u8; 32]]) -> Result<[u8; 32], Rule> {
    if count == 0 || count > MAX_COUNT || index >= count || path.len() > MAX_PATH {
        return Err(Rule::GRANTS_BATCH);
    }
    let (mut h, mut idx, mut n) = (leaf, index, count);
    let mut sibs = path.iter();
    while n > 1 {
        let alone = idx.saturating_add(1) == n && n % 2 == 1;
        if !alone {
            let sib = sibs.next().ok_or(Rule::GRANTS_BATCH)?;
            h = if idx % 2 == 0 { node(&h, sib) } else { node(sib, &h) };
        }
        idx /= 2;
        n = n.div_ceil(2);
    }
    if sibs.next().is_some() {
        return Err(Rule::GRANTS_BATCH);
    }
    Ok(h)
}

/// The grant's field of the leaf's commanders (a guarded leaf's only).
pub const FIELD_COMMANDERS: u16 = 12;
/// The grant's field of its lifetime (a guarded leaf's only).
pub const FIELD_LIFE: u16 = 11;
/// The grant's field of its readers.
pub const FIELD_READERS: u16 = 13;
/// The grant's flag of a guarded leaf.
pub const FIELD_GUARDED: u16 = 15;
/// The most readers of a leaf.
pub const MAX_READERS: usize = 4;

/// A guarded leaf's grant in a batch a root did not sign.
pub const RULE_GUARDED: Rule = Rule::field("grants/guarded");
/// Commanders or a lifetime in an ordinary leaf's grant.
pub const RULE_COMMANDERS: Rule = Rule::field("grants/commanders");
/// More than four readers.
pub const RULE_READERS: Rule = Rule::field("grants/readers");
/// An admin's batch without the root's record of that admin key, or with
/// one that does not make it an admin that admits.
pub const RULE_ADMIN: Rule = Rule::field("grants/admin");

/// A grant as message `grant` carries it (fields 2–6), checked to the
/// batch's signature, its place in the batch's tree and its kind.
#[derive(Clone, Debug)]
pub struct Granted<'a> {
    /// The batch envelope.
    pub batch: Envelope<'a>,
    /// The root's record of the admin that signed the batch, when an admin
    /// did.
    pub admin: Option<Envelope<'a>>,
    /// The grant's body.
    pub grant: &'a [u8],
    /// The grant's body read.
    pub map: Value<'a>,
    /// Whether the grant is a guarded leaf's.
    pub guarded: bool,
}

/// The admin key of the root's record in field 6, if it makes that key an
/// admin with `admit`: a `device` record (type 1) the root signed, with its
/// `admin` Key (20) and the admit bit in its `powers` (21).
fn admin_key<'a>(record: &Envelope<'a>, root: &[u8]) -> Result<[u8; 65], Rule> {
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

/// Reads a grant from the map of message `grant` (or the Welcome's `grant`):
/// field 2 the batch envelope, 3 the grant body, 4 the path, 5 the index,
/// 6 the root's record of the admin that signed the batch. Checks the
/// batch's signature (by the root's uncompressed point, or by an admin key
/// that the root's record in field 6 makes an admin with `admit`), the path,
/// and the rules of the two kinds of leaf (design-small-device section 15):
/// a guarded grant only from the root; commanders and a lifetime only in a
/// guarded grant; at most four readers. The grant's other fields are its
/// reader's matter.
pub fn read<'a>(msg: &Value<'a>, root: &[u8]) -> Result<Granted<'a>, Rule> {
    let batch = Envelope::from_value(msg.get(2).ok_or(Rule::GRANTS_BATCH)?)?;
    let signer = batch.signer().and_then(Value::as_bytes).and_then(KeyHash::from_slice).ok_or(Rule::GRANTS_BATCH)?;
    let admin = if signer == Key::new(Alg::Es256, root).hash() {
        batch.verify(root, sig::LABEL_GRANT)?;
        None
    } else {
        let record = Envelope::from_value(msg.get(6).ok_or(RULE_ADMIN)?)?;
        let key = admin_key(&record, root)?;
        if Key::new(Alg::Es256, &key).hash() != signer {
            return Err(RULE_ADMIN);
        }
        batch.verify(&key, sig::LABEL_GRANT)?;
        Some(record)
    };
    let grant = msg.get(3).and_then(Value::as_bytes).ok_or(Rule::GRANTS_BATCH)?;
    if grant.len() > MAX_GRANT {
        return Err(Rule::ENV_SIZE);
    }
    let map = super::cbor::decode(grant)?;
    let mut path = Vec::new();
    if let Some(p) = msg.get(4) {
        for x in p.as_array().ok_or(Rule::GRANTS_BATCH)? {
            let h: [u8; 32] = x.as_bytes().and_then(|b| b.try_into().ok()).ok_or(Rule::GRANTS_BATCH)?;
            path.push(h);
        }
    }
    let index = match msg.get(5) {
        None => 0,
        Some(Value::Uint(0)) => return Err(Rule::FORM_DEFAULT),
        Some(v) => v.as_uint().ok_or(Rule::GRANTS_BATCH)?,
    };
    let merkle = batch.map.get(FIELD_MERKLE).and_then(Value::as_bytes).ok_or(Rule::GRANTS_BATCH)?;
    let count = batch.map.get(FIELD_COUNT).and_then(Value::as_uint).ok_or(Rule::GRANTS_BATCH)?;
    if root_of(leaf(grant), index, count, &path)?.as_slice() != merkle {
        return Err(Rule::GRANTS_BATCH);
    }
    let guarded = match map.get(FIELD_GUARDED) {
        None => false,
        Some(Value::Uint(1)) => true,
        Some(_) => return Err(Rule::field("grants/guarded-value")),
    };
    if guarded && admin.is_some() {
        return Err(RULE_GUARDED);
    }
    if !guarded && (map.get(FIELD_COMMANDERS).is_some() || map.get(FIELD_LIFE).is_some()) {
        return Err(RULE_COMMANDERS);
    }
    if map.get(FIELD_READERS).and_then(Value::as_array).is_some_and(|r| r.len() > MAX_READERS) {
        return Err(RULE_READERS);
    }
    Ok(Granted { batch, admin, grant, map, guarded })
}
