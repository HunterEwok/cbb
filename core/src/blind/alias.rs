// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Another face for each server (A-55): a group gives every server its own
//! period, with its own tag and its own period key, so that two operators
//! who compare what they saw find nothing in common. The device's server
//! key is per face too, that is per period and server: each device derives
//! it from its own server secret and the face's tag ([`server_key`]), so
//! the lists of key hashes two servers see share nothing either. Each face
//! counts its credentials' versions from a random start and has an expiry
//! of its own (a random part of a day before the period ends, never after
//! it), so neither links two faces. What a server sees of one group is then
//! unlinked from what another server sees of it, but for timing and
//! addresses.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use super::credential::Credential;
use crate::format::KeyHash;

/// One server's period: the tag and the period key's point the group shows
/// it, this device's server key's point for it, and the face's own version
/// and expiry for its credentials.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Face {
    pub tag: [u8; 16],
    pub period_key: Vec<u8>,
    pub server_key: Vec<u8>,
    /// The version of the face's newest credentials, counted from a random
    /// start.
    pub version: u64,
    pub expires_ms: u64,
}

/// A day.
pub const DAY_MS: u64 = 86_400_000;

impl Face {
    /// The version for the face's next credentials.
    pub fn next_version(&mut self) -> u64 {
        self.version = self.version.saturating_add(1);
        self.version
    }
}

/// A face's expiry for a period from `starts_ms` to `ends_ms`: within the
/// period, a random part of a day (at most the period's length) before its
/// end, so two faces of one period differ and none outlives the period.
pub fn expiry(starts_ms: u64, ends_ms: u64) -> u64 {
    let span = ends_ms.saturating_sub(starts_ms).min(DAY_MS);
    if span == 0 {
        return ends_ms;
    }
    ends_ms.saturating_sub(u64::from_be_bytes(crate::certs::random_bytes::<8>()).checked_rem(span).unwrap_or(0))
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
/// group: the same tag, the same signer, the same key in them, a key hash in
/// both of their lists, the same version or the same expiry.
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
        || a.version == b.version
        || a.expires_ms == b.expires_ms
}

/// Checks that each server, known by the pin of its TLS key, has a face of
/// its own: no tag, no period key, no server key, no version and no expiry
/// shared between two servers.
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
        && all_differ(faces.values().map(|f| f.version).collect())
        && all_differ(faces.values().map(|f| f.expires_ms).collect())
}

/// A new face for a period from `starts_ms` to `ends_ms`: a random tag;
/// the caller makes a new period key and gives its point; this device's
/// server key is derived for the tag; the versions start at a random number
/// below 2^32, the expiry is the face's own ([`expiry`]).
pub fn new_face(period_key: Vec<u8>, server_secret: &[u8; 32], starts_ms: u64, ends_ms: u64) -> Face {
    let tag = crate::certs::random_bytes();
    let (_, server_key) = server_key(server_secret, &tag);
    let start = u64::from(u32::from_be_bytes(crate::certs::random_bytes::<4>())).saturating_add(1);
    Face { tag, period_key, server_key, version: start, expires_ms: expiry(starts_ms, ends_ms) }
}
