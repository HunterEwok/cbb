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

/// A grant as message `grant` carries it (fields 2–5), checked to the
/// batch's signature and its place in the batch's tree.
#[derive(Clone, Debug)]
pub struct Granted<'a> {
    /// The batch envelope.
    pub batch: Envelope<'a>,
    /// The grant's body.
    pub grant: &'a [u8],
    /// The grant's body read.
    pub map: Value<'a>,
}

/// Reads a grant from the map of message `grant` (or the Welcome's `grant`):
/// field 2 the batch envelope, 3 the grant body, 4 the path, 5 the index;
/// checks the batch's signature by the root's uncompressed point and the
/// path. The grant's own fields are its reader's matter.
pub fn read<'a>(msg: &Value<'a>, root: &[u8]) -> Result<Granted<'a>, Rule> {
    let batch = Envelope::from_value(msg.get(2).ok_or(Rule::GRANTS_BATCH)?)?;
    batch.verify(root, sig::LABEL_GRANT)?;
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
    Ok(Granted { batch, grant, map })
}
