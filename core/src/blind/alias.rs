// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Another face for each server (A-55): a group gives every server its own
//! period, with its own tag and its own period key, so that two operators
//! who compare what they saw find nothing in common. The device's server
//! key is per face too, that is per period and server: each device derives
//! it from its own server secret and the face's tag ([`server_key`]), so
//! the lists of key hashes two servers see share nothing either. What a
//! server sees of one group is then unlinked from what another server sees
//! of it, but for timing and addresses.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use super::credential::Credential;
use crate::format::KeyHash;

/// One server's period: the tag and the period key's point the group shows
/// it, and this device's server key's point for it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Face {
    pub tag: [u8; 16],
    pub period_key: Vec<u8>,
    pub server_key: Vec<u8>,
}

/// HKDF's info for a server key, the face's tag and a counter after it.
const SERVER_KEY_INFO: &[u8] = b"cbb server key v1";

/// The device's server key for a face: the P-256 scalar of
/// HKDF-SHA256(ikm = its 32-byte server secret, info = `cbb server key v1`
/// ‖ the face's tag ‖ a counter byte from 0), the first counter whose 32
/// bytes are a valid scalar. Returns the scalar's bytes and the point.
pub fn server_key(secret: &[u8; 32], tag: &[u8; 16]) -> ([u8; 32], Vec<u8>) {
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, secret);
    let mut c = 0u8;
    loop {
        let mut d = [0u8; 32];
        // 32 bytes is within HKDF-SHA256's limit.
        let _ = hk.expand_multi_info(&[SERVER_KEY_INFO, tag, &[c]], &mut d);
        if let Ok(sk) = p256::SecretKey::from_slice(&d) {
            let vk = p256::ecdsa::VerifyingKey::from(sk.public_key());
            return (d, vk.to_sec1_point(false).as_bytes().to_vec());
        }
        // A scalar of zero or above the order: about 2^-32 likely.
        c = c.wrapping_add(1);
    }
}

/// Whether two credentials that two servers saw could be linked to one
/// group: the same tag, the same signer, the same key in them, or a key
/// hash in both of their lists.
pub fn linkable(a: &Credential, b: &Credential) -> bool {
    let tags = |c: &Credential| -> Vec<[u8; 16]> { c.tag.into_iter().chain(core::iter::once(c.group)).collect() };
    let ta = tags(a);
    let keys =
        |c: &Credential| -> Vec<Vec<u8>> { c.key.iter().cloned().chain(core::iter::once(c.signer.clone())).collect() };
    let kb = keys(b);
    let hashes = |c: &Credential| -> Vec<[u8; 32]> {
        c.hubs.iter().chain(c.admins.iter()).chain(c.members.iter()).copied().collect()
    };
    let hb = hashes(b);
    tags(b).iter().any(|t| ta.contains(t))
        || keys(a).iter().any(|k| kb.contains(k))
        || hashes(a).iter().any(|h| hb.contains(h))
}

/// Checks that each server, known by the pin of its TLS key, has a face of
/// its own: no tag, no period key and no server key shared between two
/// servers.
pub fn distinct(faces: &BTreeMap<KeyHash, Face>) -> bool {
    fn all_differ<T: Ord>(mut v: Vec<T>) -> bool {
        let n = v.len();
        v.sort();
        v.dedup();
        v.len() == n
    }
    all_differ(faces.values().map(|f| &f.tag).collect())
        && all_differ(faces.values().map(|f| &f.period_key).collect())
        && all_differ(faces.values().map(|f| &f.server_key).collect())
}

/// A new face: a random tag; the caller makes a new period key and gives
/// its point; this device's server key is derived for the tag.
pub fn new_face(period_key: Vec<u8>, server_secret: &[u8; 32]) -> Face {
    let tag = crate::certs::random_bytes();
    let (_, server_key) = server_key(server_secret, &tag);
    Face { tag, period_key, server_key }
}
