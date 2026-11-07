// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Copies sealed end to end (docs/protocol.md, section 4, "Event"): the
//! device that copies seals each copy to the devices of the group that read
//! copies and signs it, so the members that pass it on, a hub among them,
//! neither read nor change it. This module seals, checks and opens a copy
//! and its blob of images and files; the member's engine (crate::clip on
//! the lite member, the kits on the phones, Go's package clip) decides what
//! to do with it.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hmac::{Hmac, Mac};
use serde::de::IgnoredAny;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::certs::{self, Cert, b64, is_id};
use crate::clip::{Kind, MAX_TEXT, Via, check_text};
use crate::error::{Error, Result};
use crate::group::Records;
use crate::hlc::Timestamp;
use crate::media::{MAX_ALT_TEXT, MAX_MEDIA, Manifest};
use crate::seal;

/// The length of a wrap's key: the encapsulated key, the copy's key and
/// its tag.
pub const WRAP_SIZE: usize = seal::ENC_SIZE + KEY_SIZE + TAG;
/// The length of a copy's key.
pub const KEY_SIZE: usize = 32;
/// The most readers a copy is sealed to: the group's most devices.
pub const MAX_READERS: usize = 256;
/// A blob's segment before sealing, and after.
pub const SEGMENT: usize = 64 << 10;
pub const SEALED_SEGMENT: usize = SEGMENT + TAG;
/// The most segments a blob has: 1 GiB of parts.
pub const MAX_SEGMENTS: u64 = (MAX_MEDIA as u64).div_ceil(SEGMENT as u64);
/// The largest Content, padding included.
pub const MAX_CONTENT: usize = 4 << 20;
const TAG: usize = 16;
/// The sizes a Content is padded to.
const STEPS: [usize; 9] = [1 << 10, 4 << 10, 16 << 10, 64 << 10, 256 << 10, 1 << 20, 2 << 20, 3 << 20, 4 << 20];

const HEADER: &[u8] = b"cbb copy v1";
const SIGNED: &[u8] = b"cbb copy sig v1";
const PAYLOAD_INFO: &[u8] = b"cbb copy payload v1";
const BLOB_INFO: &[u8] = b"cbb copy blob v1";
const BLOB_AAD: &[u8] = b"cbb blob";

/// The size of a sealed blob of n bytes of parts.
pub fn blob_size(n: u64) -> u64 {
    n.div_ceil(SEGMENT as u64).saturating_mul(SEALED_SEGMENT as u64)
}

/// A reader's sealed copy of the copy's key.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Wrap {
    pub to: String,
    #[serde(with = "b64")]
    pub key: Vec<u8>,
}

/// The sealed blob of a copy's images and files.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Blob {
    pub size: i64,
    #[serde(with = "b64")]
    pub sha256: Vec<u8>,
}

/// One copy as it travels between members: the event of the member
/// protocol.
#[derive(Clone, PartialEq, Debug, Default, Serialize, Deserialize)]
pub struct Sealed {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub origin: String,
    #[serde(default)]
    pub time: Timestamp,
    #[serde(rename = "age_ms", default)]
    pub age: i64,
    #[serde(with = "b64", default)]
    pub cert: Vec<u8>,
    #[serde(with = "b64", default, skip_serializing_if = "Vec::is_empty")]
    pub issuer: Vec<u8>,
    #[serde(default)]
    pub wraps: Vec<Wrap>,
    #[serde(with = "b64", default, skip_serializing_if = "Vec::is_empty")]
    pub payload: Vec<u8>,
    /// In a mark, in place of payload.
    #[serde(with = "b64", default, skip_serializing_if = "Vec::is_empty")]
    pub payload_sha256: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blob: Option<Blob>,
    #[serde(with = "b64", default)]
    pub sig: Vec<u8>,
    // The fields of a copy in the open, which no member takes.
    #[serde(default, skip_serializing)]
    kind: Option<IgnoredAny>,
    #[serde(default, skip_serializing)]
    text: Option<IgnoredAny>,
    #[serde(default, skip_serializing)]
    via: Option<IgnoredAny>,
    #[serde(default, skip_serializing)]
    media: Option<IgnoredAny>,
}

/// What only a copy's readers see.
#[derive(Clone, PartialEq, Debug, Default)]
pub struct Content {
    pub kind: Kind,
    pub via: Via,
    pub text: String,
    /// The manifest of a media copy, which only it has.
    pub media: Option<Manifest>,
}

/// A copy sealed but not yet signed: the origin signs `to_sign` with its
/// member key and puts the signature in `sealed.sig`.
pub struct Draft {
    pub sealed: Sealed,
    pub to_sign: Vec<u8>,
}

fn put(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_be_bytes());
    out.extend_from_slice(b);
}

fn mac(key: &[u8]) -> Result<Hmac<Sha256>> {
    // HMAC takes a key of any length; the error is never expected.
    Hmac::<Sha256>::new_from_slice(key).map_err(|_| Error::msg("HMAC refused its key"))
}

fn hkdf(key: &[u8; KEY_SIZE], info: &[u8]) -> Result<[u8; 32]> {
    // HKDF-SHA256 with no salt and one block. HMAC pads its key with zeros
    // to the block, so the empty key is the salt of 32 zero bytes that
    // RFC 5869 takes for none.
    let mut ext = mac(&[])?;
    ext.update(key);
    let prk = ext.finalize().into_bytes();
    let mut exp = mac(&prk)?;
    exp.update(info);
    exp.update(&[1]);
    Ok(exp.finalize().into_bytes().into())
}

fn cipher(key: &[u8; 32]) -> ChaCha20Poly1305 {
    ChaCha20Poly1305::new(key.into())
}

fn segment_nonce(i: u64) -> Nonce {
    // Four zero bytes, then the index: each segment's nonce is its place.
    let mut n = Nonce::default();
    if let Some(tail) = n.get_mut(4..) {
        tail.copy_from_slice(&i.to_be_bytes());
    }
    n
}

/// The payload's nonce: zeros, since the payload key seals nothing else.
fn payload_nonce() -> Nonce {
    Nonce::default()
}

fn segment_aad(last: bool) -> [u8; 9] {
    let mut a = [0u8; 9];
    a[..8].copy_from_slice(BLOB_AAD);
    a[8] = u8::from(last);
    a
}

/// Seals the segment i of a blob, at most SEGMENT bytes, which the caller
/// pads with zeros to SEGMENT when it is the last; last says whether it is.
pub fn seal_segment(key: &[u8; KEY_SIZE], i: u64, last: bool, plain: &[u8]) -> Result<Vec<u8>> {
    if plain.len() > SEGMENT || i >= MAX_SEGMENTS {
        return Err(Error::msg("a blob's segment is too large or too far"));
    }
    let mut seg = Vec::with_capacity(SEGMENT);
    seg.extend_from_slice(plain);
    seg.resize(SEGMENT, 0);
    cipher(&hkdf(key, BLOB_INFO)?)
        .encrypt(&segment_nonce(i), Payload { msg: &seg, aad: &segment_aad(last) })
        .map_err(|_| Error::msg("a blob's segment cannot be sealed"))
}

/// Opens the segment i of a blob: SEALED_SEGMENT bytes, the last one
/// flagged as such.
pub fn open_segment(key: &[u8; KEY_SIZE], i: u64, last: bool, sealed: &[u8]) -> Result<Vec<u8>> {
    if sealed.len() != SEALED_SEGMENT {
        return Err(Error::msg("a blob's segment is not 65552 bytes"));
    }
    cipher(&hkdf(key, BLOB_INFO)?)
        .decrypt(&segment_nonce(i), Payload { msg: sealed, aad: &segment_aad(last) })
        .map_err(|_| Error::msg("a blob's segment does not open: it was changed or is from another copy"))
}

fn kind_byte(k: Kind) -> u8 {
    match k {
        Kind::Text => 1,
        Kind::Secret => 2,
        Kind::Media => 3,
    }
}

fn via_byte(v: Via) -> u8 {
    match v {
        Via::Copy => 0,
        Via::Phone => 1,
        Via::Universal => 2,
    }
}

impl Content {
    /// Checks the rules a copy's content keeps, whatever its blob.
    pub fn validate(&self) -> Result<()> {
        if (self.kind == Kind::Media) != self.media.is_some() {
            return Err(Error::msg("only a media copy has a manifest, and it always does"));
        }
        if let Some(m) = &self.media {
            m.validate()?;
            if self.text.is_empty() {
                return Ok(());
            }
            if self.text.len() > MAX_ALT_TEXT {
                return Err(Error::msg(format!(
                    "a media copy's text of {} bytes is larger than 256 KiB",
                    self.text.len()
                )));
            }
        }
        check_text(&self.text)
    }

    /// The Content in binary, padded to its step.
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let manifest = match &self.media {
            Some(m) => crate::strict::canonicalize(
                &serde_json::to_vec(m).map_err(|e| Error::with("the manifest does not encode", e))?,
            )?,
            None => Vec::new(),
        };
        let mut out = Vec::new();
        out.push(1);
        out.push(kind_byte(self.kind));
        out.push(via_byte(self.via));
        put(&mut out, self.text.as_bytes());
        put(&mut out, &manifest);
        let step = STEPS
            .iter()
            .copied()
            .find(|&s| s >= out.len())
            .ok_or_else(|| Error::msg("the copy is larger than 4 MiB with its manifest"))?;
        out.resize(step, 0);
        Ok(out)
    }

    /// Reads a Content that opened, refusing what breaks its rules.
    pub fn decode(b: &[u8]) -> Result<Content> {
        if !STEPS.contains(&b.len()) {
            return Err(Error::msg("the copy's content is not of a size it is padded to"));
        }
        let bad = || Error::msg("the copy's content is cut short");
        let take = |at: &mut usize, n: usize| -> Result<&[u8]> {
            let end = at.checked_add(n).filter(|&e| e <= b.len()).ok_or_else(bad)?;
            let s = b.get(*at..end).ok_or_else(bad)?;
            *at = end;
            Ok(s)
        };
        let mut at = 0;
        let &[version, kind, via] = take(&mut at, 3)? else {
            return Err(bad());
        };
        if version != 1 {
            return Err(Error::msg(format!("the copy's content is of version {version}")));
        }
        let kind = match kind {
            1 => Kind::Text,
            2 => Kind::Secret,
            3 => Kind::Media,
            k => return Err(Error::msg(format!("the copy's content has an unknown kind {k}"))),
        };
        let via = match via {
            0 => Via::Copy,
            1 => Via::Phone,
            2 => Via::Universal,
            v => return Err(Error::msg(format!("the copy's content has an unknown way {v}"))),
        };
        let len = |at: &mut usize| -> Result<usize> {
            let l: [u8; 4] = take(at, 4)?.try_into().map_err(|_| bad())?;
            Ok(u32::from_be_bytes(l) as usize)
        };
        let n = len(&mut at)?;
        if n > MAX_TEXT {
            return Err(Error::msg("the copy's text is larger than 1 MiB"));
        }
        let text = core::str::from_utf8(take(&mut at, n)?)
            .map_err(|_| Error::msg("the copy's text is not UTF-8"))?
            .to_string();
        let n = len(&mut at)?;
        let manifest = take(&mut at, n)?;
        let media = if kind == Kind::Media {
            Some(Manifest::parse(manifest)?)
        } else if n != 0 {
            return Err(Error::msg("a copy that is not media has a manifest"));
        } else {
            None
        };
        if b.get(at..).unwrap_or_default().iter().any(|&x| x != 0) {
            return Err(Error::msg("the copy's padding is not zeros"));
        }
        if STEPS.iter().find(|&&s| s >= at) != Some(&b.len()) {
            return Err(Error::msg("the copy's content is padded past its step"));
        }
        let c = Content { kind, via, text, media };
        c.validate()?;
        Ok(c)
    }
}

fn header_hash(id: &str, origin: &str, time: &Timestamp, readers: &[&str], blob: Option<&Blob>) -> [u8; 32] {
    let mut h = Vec::new();
    h.extend_from_slice(HEADER);
    put(&mut h, id.as_bytes());
    put(&mut h, origin.as_bytes());
    put(&mut h, time.to_string().as_bytes());
    h.extend_from_slice(&(readers.len() as u32).to_be_bytes());
    for r in readers {
        put(&mut h, r.as_bytes());
    }
    match blob {
        Some(b) => {
            h.extend_from_slice(&(b.size as u64).to_be_bytes());
            h.extend_from_slice(&b.sha256);
        }
        None => h.extend_from_slice(&[0u8; 40]),
    }
    certs::sha256(&h)
}

impl Sealed {
    /// Reports whether this is a mark: a secret without its payload.
    pub fn is_mark(&self) -> bool {
        self.payload.is_empty()
    }

    /// The SHA-256 of the payload the copy has or stands for.
    pub fn payload_hash(&self) -> [u8; 32] {
        if self.is_mark() {
            let mut h = [0u8; 32];
            if self.payload_sha256.len() == 32 {
                h.copy_from_slice(&self.payload_sha256);
            }
            return h;
        }
        certs::sha256(&self.payload)
    }

    /// The mark of the copy: the same, without its payload.
    pub fn mark(&self) -> Sealed {
        let mut m = self.clone();
        m.payload_sha256 = self.payload_hash().to_vec();
        m.payload = Vec::new();
        m
    }

    /// Checks the copy as a receiver must before anything else.
    pub fn validate(&self) -> Result<()> {
        if self.kind.is_some() || self.text.is_some() || self.via.is_some() || self.media.is_some() {
            return Err(Error::msg("a copy in the open is never taken"));
        }
        if !is_id(&self.id) {
            return Err(Error::msg("bad event ID"));
        }
        if !is_id(&self.origin) {
            return Err(Error::msg("bad origin device ID"));
        }
        if self.time.is_zero() || !self.time.valid() {
            return Err(Error::msg("bad timestamp"));
        }
        if self.age < 0 {
            return Err(Error::msg(format!("negative event age {} ms", self.age)));
        }
        let cert = Cert::parse(&self.cert).map_err(|e| e.context("the copy's certificate"))?;
        if cert.common_name.as_deref() != Some(self.origin.as_str()) {
            return Err(Error::msg("the copy's certificate is not of its origin"));
        }
        if !self.issuer.is_empty() {
            Cert::parse(&self.issuer).map_err(|e| e.context("the copy's issuer"))?;
        }
        if self.wraps.is_empty() || self.wraps.len() > MAX_READERS {
            return Err(Error::msg(format!("a copy for {} readers, not 1 to {MAX_READERS}", self.wraps.len())));
        }
        if self.wraps.iter().any(|w| !is_id(&w.to) || w.key.len() != WRAP_SIZE) {
            return Err(Error::msg("a copy's wrap is not for a device or not of 1168 bytes"));
        }
        if self.wraps.windows(2).any(|p| matches!(p, [x, y] if x.to >= y.to)) {
            return Err(Error::msg("a copy's wraps are not sorted, each device once"));
        }
        match (self.payload.is_empty(), self.payload_sha256.is_empty()) {
            (false, true) => {
                if !STEPS.iter().any(|&s| s.checked_add(TAG) == Some(self.payload.len())) {
                    return Err(Error::msg("a copy's payload is not of a size it is padded to"));
                }
            }
            (true, false) if self.payload_sha256.len() == 32 => {}
            _ => return Err(Error::msg("a copy has neither a payload nor its hash, or both")),
        }
        if let Some(b) = &self.blob {
            let n = b.size as u64;
            if b.size <= 0
                || !n.is_multiple_of(SEALED_SEGMENT as u64)
                || n.checked_div(SEALED_SEGMENT as u64).is_none_or(|k| k > MAX_SEGMENTS)
                || b.sha256.len() != 32
            {
                return Err(Error::msg("a copy's blob is not of whole segments within 1 GiB, or has no SHA-256"));
            }
        }
        if self.sig.is_empty() {
            return Err(Error::msg("a copy is not signed"));
        }
        Ok(())
    }

    fn readers(&self) -> Vec<&str> {
        self.wraps.iter().map(|w| w.to.as_str()).collect()
    }

    /// The hash of the copy's header, which its payload and wraps are
    /// sealed under.
    pub fn header_hash(&self) -> [u8; 32] {
        header_hash(&self.id, &self.origin, &self.time, &self.readers(), self.blob.as_ref())
    }

    /// What the origin signs.
    pub fn to_sign(&self) -> Vec<u8> {
        let mut s = Vec::new();
        s.extend_from_slice(SIGNED);
        s.extend_from_slice(&self.header_hash());
        s.extend_from_slice(&(self.wraps.len() as u32).to_be_bytes());
        for w in &self.wraps {
            put(&mut s, &w.key);
        }
        s.extend_from_slice(&self.payload_hash());
        s
    }

    /// Checks the copy's origin against the group's records at t, Unix
    /// seconds: its certificate, through its issuer, verifies to a root on
    /// the path, the records take it, its key is one of the origin's, the
    /// origin does not only pass copies on, and it signed the copy. A member does this before it passes a copy on.
    pub fn check(&self, records: &Records, t: i64) -> Result<()> {
        self.validate()?;
        let mut chain = alloc::vec![Cert::parse(&self.cert)?];
        if !self.issuer.is_empty() {
            chain.push(Cert::parse(&self.issuer)?);
        }
        let (dev, used) = certs::member_chain(chain, &records.path_certs(), t, certs::Usage::Client)
            .map_err(|e| e.context("the copy's origin is not a member of the group"))?;
        if dev.as_str() != self.origin {
            return Err(Error::msg("the copy's certificate is not of its origin"));
        }
        if let Some(r) = records.refused(&used) {
            return Err(Error::msg(format!("the copy's origin is refused: {}", r.why())));
        }
        let leaf = used.first().ok_or_else(|| Error::msg("the copy's certificate chain is empty"))?;
        let key = leaf.key_hash();
        let devices = records.devices();
        let Some(d) = devices.iter().find(|d| d.id == self.origin && d.keys.contains(&key)) else {
            return Err(Error::msg("the copy's certificate is not one its origin's records name"));
        };
        if d.forward_only {
            return Err(Error::msg("the copy's origin only passes copies on"));
        }
        if !leaf.verifies(&self.to_sign(), &self.sig) {
            return Err(Error::msg("the copy's signature does not verify"));
        }
        Ok(())
    }

    /// Opens the copy with the reader me's secret for sealed messages: its
    /// content, and the copy's key, which opens its blob.
    pub fn open(&self, me: &str, secret: &[u8]) -> Result<(Content, [u8; KEY_SIZE])> {
        if self.is_mark() {
            return Err(Error::msg("a mark has no content"));
        }
        let w = self
            .wraps
            .iter()
            .find(|w| w.to == me)
            .ok_or_else(|| Error::msg("the copy is not sealed to this device"))?;
        let h = self.header_hash();
        let k = seal::open(secret, &h, &w.key)
            .map_err(|_| Error::msg("the copy's key does not open with this device's key"))?;
        let k: [u8; KEY_SIZE] = k.as_slice().try_into().map_err(|_| Error::msg("the copy's key is not 32 bytes"))?;
        let plain = cipher(&hkdf(&k, PAYLOAD_INFO)?)
            .decrypt(&payload_nonce(), Payload { msg: &self.payload, aad: &h })
            .map_err(|_| Error::msg("the copy does not open: it was changed"))?;
        let c = Content::decode(&plain)?;
        let size = c.media.as_ref().map_or(0, |m| m.size);
        match &self.blob {
            Some(b) if size > 0 && b.size as u64 == blob_size(size as u64) => {}
            None if size == 0 => {}
            _ => return Err(Error::msg("the copy's blob does not fit its manifest")),
        }
        Ok((c, k))
    }
}

/// A random key for a copy.
pub fn new_key() -> [u8; KEY_SIZE] {
    certs::random_bytes()
}

/// The devices a copy is sealed to by the records: those with a key that
/// stands, a key for sealed messages, the role full, phone or lite, not
/// frozen, and not only passing copies on; with secret, none that the
/// records keep secrets from. Each as its device ID and seal key, sorted.
pub fn readers(records: &Records, secret: bool) -> Vec<(String, Vec<u8>)> {
    let mut out: Vec<(String, Vec<u8>)> = records
        .devices()
        .into_iter()
        .filter(|d| {
            !d.keys.is_empty()
                && !d.seal.is_empty()
                && matches!(d.role.as_str(), "full" | "phone" | "lite")
                && !d.frozen
                && !d.forward_only
                && !(secret && records.no_secrets_to(&d.id))
        })
        .map(|d| (d.id, d.seal))
        .collect();
    out.sort();
    out.truncate(MAX_READERS);
    out
}

/// Seals a copy: its content, under the copy's key, to readers (device ID
/// and seal key each), with the blob the caller sealed under the same key.
/// The origin then signs `to_sign`.
#[allow(clippy::too_many_arguments, reason = "every part of a copy is its own argument")]
pub fn seal(
    id: &str,
    origin: &str,
    time: Timestamp,
    cert: &[u8],
    issuer: &[u8],
    readers: &[(String, Vec<u8>)],
    content: &Content,
    blob: Option<Blob>,
    key: &[u8; KEY_SIZE],
) -> Result<Draft> {
    seal_with(id, origin, time, cert, issuer, readers, content, blob, key, |_, public, aad, msg| {
        seal::seal(public, aad, msg)
    })
}

/// seal with a fixed seed for each reader's encapsulation, for the vectors.
#[allow(clippy::too_many_arguments, reason = "every part of a copy is its own argument")]
pub fn seal_with_seeds(
    id: &str,
    origin: &str,
    time: Timestamp,
    cert: &[u8],
    issuer: &[u8],
    readers: &[(String, Vec<u8>)],
    content: &Content,
    blob: Option<Blob>,
    key: &[u8; KEY_SIZE],
    seeds: &[[u8; 32]],
) -> Result<Draft> {
    seal_with(id, origin, time, cert, issuer, readers, content, blob, key, |i, public, aad, msg| {
        let seed = seeds.get(i).ok_or_else(|| Error::msg("a seed for each reader"))?;
        seal::seal_with_seed(public, aad, msg, *seed)
    })
}

#[allow(clippy::too_many_arguments, reason = "every part of a copy is its own argument")]
fn seal_with(
    id: &str,
    origin: &str,
    time: Timestamp,
    cert: &[u8],
    issuer: &[u8],
    readers: &[(String, Vec<u8>)],
    content: &Content,
    blob: Option<Blob>,
    key: &[u8; KEY_SIZE],
    wrap: impl Fn(usize, &[u8], &[u8], &[u8]) -> Result<Vec<u8>>,
) -> Result<Draft> {
    if readers.is_empty() || readers.len() > MAX_READERS {
        return Err(Error::msg(format!("a copy for {} readers, not 1 to {MAX_READERS}", readers.len())));
    }
    let mut readers: Vec<&(String, Vec<u8>)> = readers.iter().collect();
    readers.sort_by(|a, b| a.0.cmp(&b.0));
    readers.dedup_by(|a, b| a.0 == b.0);
    let ids: Vec<&str> = readers.iter().map(|r| r.0.as_str()).collect();
    let h = header_hash(id, origin, &time, &ids, blob.as_ref());
    let plain = content.encode()?;
    let payload = cipher(&hkdf(key, PAYLOAD_INFO)?)
        .encrypt(&payload_nonce(), Payload { msg: &plain, aad: &h })
        .map_err(|_| Error::msg("the copy cannot be sealed"))?;
    let mut wraps = Vec::with_capacity(readers.len());
    for (i, (to, public)) in readers.iter().enumerate() {
        seal::check_public_key(public).map_err(|e| e.context("a reader's key for sealed messages"))?;
        wraps.push(Wrap { to: to.clone(), key: wrap(i, public, &h, key)? });
    }
    let sealed = Sealed {
        id: id.to_string(),
        origin: origin.to_string(),
        time,
        cert: cert.to_vec(),
        issuer: issuer.to_vec(),
        wraps,
        payload,
        blob,
        ..Sealed::default()
    };
    let to_sign = sealed.to_sign();
    Ok(Draft { sealed, to_sign })
}

#[cfg(test)]
mod tests;
