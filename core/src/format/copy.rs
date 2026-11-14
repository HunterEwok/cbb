// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The copy's wire form and signature (format section 10): the header
//! hashed into `h`, the copy key K bound by `commit`, the payload and blob
//! keys derived from K under `h`, and the origin's signature over `h`, the
//! digest of the wraps `W` and the payload's hash `P`. A reduced copy (for a
//! leaf) carries the other readers' wraps and the payload as their hashes,
//! and verifies the same.
//!
//! The content inside the payload is a map padded to one of the content
//! steps (1 KiB to 4 MiB).

use alloc::vec::Vec;

use hkdf::Hkdf;
use sha2::Sha256;

use super::cbor::{self, Value};
use super::frame::{pad_is_exact, pad_to};
use super::{Rule, sha256, sig};

/// The copy's header (bytes, a map in the profile).
pub const FIELD_HDR: u16 = 1;
/// The copy's age, outside the signature.
pub const FIELD_AGE: u16 = 2;
/// The wraps, in the order of the header's readers.
pub const FIELD_WRAPS: u16 = 3;
/// The sealed content.
pub const FIELD_PAYLOAD: u16 = 4;
/// The payload's hash, in place of the payload.
pub const FIELD_PAYLOAD_HASH: u16 = 5;
/// The origin's signature.
pub const FIELD_SIG: u16 = 6;

/// The size of a whole wrap to an X-Wing key: its encapsulated key, K and
/// its tag. A wrap's length follows the algorithm of its reader's
/// statement key, so one copy may hold wraps of several algorithms; a
/// reader checks its own wrap's length only (`copies::open`).
pub const WRAP_SIZE: usize = 1168;

/// The shortest whole wrap: K and its tag after an encapsulation of at
/// least one byte. Any longer one is hashed into `W` whatever its
/// algorithm; others' wraps are bounded by the frame alone.
pub const MIN_WRAP: usize = 32 + 16 + 1;

/// The rule a copy of the wrong form breaks.
pub const RULE_SHAPE: Rule = Rule::field("copy/shape");
/// A header whose readers are missing, more than 256, or not a set (each
/// device once, sorted).
pub const RULE_READERS: Rule = Rule::field("copy/readers");
/// The header's field of its readers.
pub const HDR_READERS: u16 = 4;
/// The header's reserved field `reuse`, refused in 0.6.
pub const HDR_REUSE: u16 = 7;
/// A header with `reuse`, which 0.6 refuses.
pub const RULE_REUSE: Rule = Rule::field("copy/reuse");

/// Checks a header's rows (section 10.2) and gives the number of its
/// readers: `id` and `origin` bytes 16, `time` a hybrid time, `readers`
/// 1 to 256 `[device ID, epoch]` in a set, `blob` `[size, bytes 32]` when
/// present, `commit` bytes 32; `reuse` refused; no other critical field.
fn check_header(h: &Value<'_>) -> Result<usize, Rule> {
    let m = h.as_map().ok_or(RULE_SHAPE)?;
    if h.get(HDR_REUSE).is_some() {
        return Err(RULE_REUSE);
    }
    if m.iter().any(|(k, _)| *k < 256 && !(1..=6).contains(k)) {
        return Err(Rule::FORM_CRITICAL);
    }
    let sized = |f, n| h.get(f).and_then(Value::as_bytes).is_some_and(|b| b.len() == n);
    let time_ok = match h.get(3).and_then(Value::as_array) {
        Some([Value::Uint(w), Value::Uint(l)]) => *l <= u64::from(u32::MAX) && (*w, *l) != (0, 0),
        _ => false,
    };
    let blob_ok = match h.get(5) {
        None => true,
        Some(b) => matches!(b.as_array(), Some([Value::Uint(_), Value::Bytes(x)]) if x.len() == 32),
    };
    if !(sized(1, 16) && sized(2, 16) && sized(6, 32) && time_ok && blob_ok) {
        return Err(RULE_SHAPE);
    }
    let readers = h.get(HDR_READERS).and_then(Value::as_array).ok_or(RULE_READERS)?;
    let reader_ok = |r: &Value<'_>| matches!(r.as_array(), Some([Value::Bytes(id), Value::Uint(_)]) if id.len() == 16);
    if readers.is_empty() || readers.len() > MAX_READERS || !cbor::is_set(readers) || !readers.iter().all(reader_ok) {
        return Err(RULE_READERS);
    }
    Ok(readers.len())
}
/// The most readers of a copy.
pub const MAX_READERS: usize = 256;
/// The rule a commitment that does not match K breaks.
pub const RULE_COMMIT: Rule = Rule::field("copy/commit");

/// `h`: SHA-256(`cbb copy v2 ‖ 0x00 ‖ hdr`).
pub fn header_hash(hdr: &[u8]) -> [u8; 32] {
    sha256(&[sig::LABEL_COPY.as_bytes(), &[0], hdr])
}

fn hkdf(k: &[u8; 32], salt: &[u8], info: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    // 32 bytes are well within HKDF-SHA256's limit of 255 · 32.
    let _ = Hkdf::<Sha256>::new(Some(salt), k).expand(info.as_bytes(), &mut out);
    out
}

/// The commitment to the copy key: HKDF(K, salt empty, info
/// `cbb copy commit v2`).
pub fn commit(k: &[u8; 32]) -> [u8; 32] {
    hkdf(k, &[], sig::LABEL_COPY_COMMIT)
}

/// The payload key under header hash h.
pub fn payload_key(k: &[u8; 32], h: &[u8; 32]) -> [u8; 32] {
    hkdf(k, h, sig::LABEL_COPY_PAYLOAD)
}

/// The blob key under header hash h.
pub fn blob_key(k: &[u8; 32], h: &[u8; 32]) -> [u8; 32] {
    hkdf(k, h, sig::LABEL_COPY_BLOB)
}

/// The hash of one wrap as `W` takes it: a whole wrap, of whatever
/// algorithm, is hashed; a 32-byte element of a reduced copy is the hash
/// already; anything between is no wrap.
fn wrap_hash(w: &[u8]) -> Result<[u8; 32], Rule> {
    match w.len() {
        32 => w.try_into().map_err(|_| RULE_SHAPE),
        n if n >= MIN_WRAP => Ok(sha256(&[w])),
        _ => Err(RULE_SHAPE),
    }
}

/// `W`: SHA-256 of the concatenated hashes of the wraps.
pub fn wraps_digest(wrap_hashes: &[[u8; 32]]) -> [u8; 32] {
    let all: Vec<&[u8]> = wrap_hashes.iter().map(|h| h.as_slice()).collect();
    sha256(&all)
}

/// What the origin signs: `h ‖ W ‖ P`.
pub fn signed(h: &[u8; 32], w: &[u8; 32], p: &[u8; 32]) -> Vec<u8> {
    let mut m = Vec::with_capacity(96);
    m.extend_from_slice(h);
    m.extend_from_slice(w);
    m.extend_from_slice(p);
    m
}

/// A copy read from its wire form (a full copy, a mark or a reduced copy).
#[derive(Clone, Debug)]
pub struct Copy<'a> {
    /// The header's bytes.
    pub hdr: &'a [u8],
    /// The header read.
    pub header: Value<'a>,
    /// The age, outside the signature.
    pub age_ms: u64,
    /// The wraps, whole or as hashes.
    pub wraps: Vec<&'a [u8]>,
    /// The payload, when it came whole.
    pub payload: Option<&'a [u8]>,
    /// `h`.
    pub h: [u8; 32],
    /// `W`.
    pub w: [u8; 32],
    /// `P`.
    pub p: [u8; 32],
    /// The origin's signature.
    pub sig: &'a [u8],
}

impl<'a> Copy<'a> {
    /// Reads a copy from its value: the header a map in the profile,
    /// exactly one of the payload and its hash, the wraps whole or hashed.
    pub fn from_value(v: &Value<'a>) -> Result<Self, Rule> {
        let outer = v.as_map().ok_or(RULE_SHAPE)?;
        if outer.iter().any(|(k, _)| *k < 256 && !(FIELD_HDR..=FIELD_SIG).contains(k)) {
            return Err(Rule::FORM_CRITICAL);
        }
        let hdr = v.get(FIELD_HDR).and_then(Value::as_bytes).ok_or(RULE_SHAPE)?;
        let header = cbor::decode(hdr)?;
        if header.as_map().is_none() {
            return Err(RULE_SHAPE);
        }
        let readers = check_header(&header)?;
        let age_ms = match v.get(FIELD_AGE) {
            None => 0,
            Some(Value::Uint(0)) => return Err(Rule::FORM_DEFAULT),
            Some(a) => a.as_uint().ok_or(RULE_SHAPE)?,
        };
        let mut wraps = Vec::new();
        let mut hashes = Vec::new();
        for w in v.get(FIELD_WRAPS).and_then(Value::as_array).ok_or(RULE_SHAPE)? {
            let w = w.as_bytes().ok_or(RULE_SHAPE)?;
            hashes.push(wrap_hash(w)?);
            wraps.push(w);
        }
        if wraps.len() != readers {
            return Err(RULE_SHAPE);
        }
        let (payload, p) = match (v.get(FIELD_PAYLOAD), v.get(FIELD_PAYLOAD_HASH)) {
            (Some(Value::Bytes(pl)), None) => (Some(*pl), sha256(&[pl])),
            (None, Some(Value::Bytes(ph))) => (None, (*ph).try_into().map_err(|_| RULE_SHAPE)?),
            _ => return Err(RULE_SHAPE),
        };
        let sig = v.get(FIELD_SIG).and_then(Value::as_bytes).ok_or(RULE_SHAPE)?;
        Ok(Copy { hdr, h: header_hash(hdr), header, age_ms, w: wraps_digest(&hashes), wraps, payload, p, sig })
    }

    /// Verifies the origin's signature by its uncompressed point.
    pub fn verify(&self, origin: &[u8]) -> Result<(), Rule> {
        sig::verify_es256(origin, sig::LABEL_COPY_SIG, &signed(&self.h, &self.w, &self.p), self.sig)
    }

    /// Checks the header's `commit` against the copy key a reader opened.
    pub fn check_commit(&self, k: &[u8; 32]) -> Result<(), Rule> {
        match self.header.get(6).and_then(Value::as_bytes) {
            Some(c) if c == commit(k).as_slice() => Ok(()),
            _ => Err(RULE_COMMIT),
        }
    }
}

/// The content's sizes: 1, 4, 16, 64 and 256 KiB, then 1, 2, 3 and 4 MiB.
pub const CONTENT_STEPS: [usize; 9] =
    [1 << 10, 4 << 10, 16 << 10, 64 << 10, 256 << 10, 1 << 20, 2 << 20, 3 << 20, 4 << 20];

/// The rule of a content not padded to its step.
pub const RULE_CONTENT_PAD: Rule = Rule::field("copy/content-pad");

fn step_at_least(n: usize) -> Option<usize> {
    CONTENT_STEPS.iter().copied().find(|s| *s >= n)
}

fn content_fits(base: usize, entries: usize) -> Option<(usize, usize)> {
    if CONTENT_STEPS.contains(&base) {
        return None;
    }
    pad_to(base, entries, step_at_least)
}

/// Pads a content map (field 0 its type, no field 1) to its step and
/// encodes it; None when it is larger than 4 MiB. As with frames, a content
/// that is a step's size by itself carries no `pad`.
pub fn write_content(content: &Value<'_>) -> Option<Vec<u8>> {
    let entries: Vec<(u16, Value<'_>)> = content.as_map()?.iter().filter(|(k, _)| *k != 1).cloned().collect();
    let base = Value::Map(entries.clone()).encode();
    if CONTENT_STEPS.contains(&base.len()) {
        return Some(base);
    }
    let (plen, _) = content_fits(base.len(), entries.len())?;
    let zeros = alloc::vec![0u8; plen];
    let mut all = entries;
    all.push((1, Value::Bytes(&zeros)));
    Some(Value::Map(all).encode())
}

/// Reads a content opened from a payload: a map with its type in field 0
/// and the one padding of its step in field 1.
pub fn read_content(b: &[u8]) -> Result<Value<'_>, Rule> {
    let v = cbor::decode(b)?;
    let entries = v.as_map().ok_or(RULE_SHAPE)?;
    v.get(0).and_then(Value::as_uint).ok_or(RULE_SHAPE)?;
    let exact = match v.get(1) {
        None => CONTENT_STEPS.contains(&b.len()),
        Some(Value::Bytes(zeros)) => pad_is_exact(b.len(), zeros, entries.len(), content_fits),
        Some(_) => false,
    };
    if !exact {
        return Err(RULE_CONTENT_PAD);
    }
    Ok(v)
}
