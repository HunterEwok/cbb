// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Another face for each server (A-55): a group gives every server its own
//! period, with its own tag and its own period key, so that two operators
//! who compare what they saw find nothing in common. The device's server
//! key is per period too. What a server sees of one group is then unlinked
//! from what another server sees of it, but for timing and addresses.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use super::credential::Credential;
use crate::format::KeyHash;

/// One server's period: the tag and the period key's point the group shows
/// it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Face {
    pub tag: [u8; 16],
    pub period_key: Vec<u8>,
}

/// Whether two credentials that two servers saw could be linked to one
/// group: the same tag, the same signer, or the same key in them.
pub fn linkable(a: &Credential, b: &Credential) -> bool {
    let tags = |c: &Credential| -> Vec<[u8; 16]> { c.tag.into_iter().chain(core::iter::once(c.group)).collect() };
    let ta = tags(a);
    let keys =
        |c: &Credential| -> Vec<Vec<u8>> { c.key.iter().cloned().chain(core::iter::once(c.signer.clone())).collect() };
    let kb = keys(b);
    tags(b).iter().any(|t| ta.contains(t)) || keys(a).iter().any(|k| kb.contains(k))
}

/// Checks that each server, known by the pin of its TLS key, has a face of
/// its own: no tag and no period key shared between two servers.
pub fn distinct(faces: &BTreeMap<KeyHash, Face>) -> bool {
    let mut tags: Vec<&[u8; 16]> = faces.values().map(|f| &f.tag).collect();
    let mut keys: Vec<&Vec<u8>> = faces.values().map(|f| &f.period_key).collect();
    tags.sort();
    tags.dedup();
    keys.sort();
    keys.dedup();
    tags.len() == faces.len() && keys.len() == faces.len()
}

/// A new face: a random tag; the caller makes a new period key and gives
/// its point.
pub fn new_face(period_key: Vec<u8>) -> Face {
    Face { tag: crate::certs::random_bytes(), period_key }
}
