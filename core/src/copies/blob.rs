// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! A copy's blob in 0.6: the bytes of its images or files, sealed apart
//! from the payload under the blob key (`format::copy::blob_key`), which
//! comes from the copy key K alone. The parts that hold bytes go one after
//! another in the manifest's order, then zeros up to a whole segment of
//! 64 KiB; each segment is sealed with ChaCha20-Poly1305, the nonce 4 zero
//! bytes and the segment's number in 8 bytes big-endian, the associated
//! data `cbb blob` and one byte, 1 for the last segment and 0 for the
//! others, so that a blob cannot be cut short. The header's field 5 holds
//! the sealed blob's size and SHA-256 under the origin's signature.

use alloc::vec::Vec;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};

use crate::error::Error;
use crate::format::sha256;
use crate::media::MAX_MEDIA;

/// A segment before sealing, and after.
pub const SEGMENT: usize = 64 << 10;
pub const SEALED_SEGMENT: usize = SEGMENT + 16;
/// The most segments a blob has: 1 GiB of parts.
pub const MAX_SEGMENTS: u64 = (MAX_MEDIA as u64).div_ceil(SEGMENT as u64);

const AAD: &[u8; 8] = b"cbb blob";

/// The size of the sealed blob of n bytes of parts.
pub fn sealed_size(n: u64) -> u64 {
    n.div_ceil(SEGMENT as u64).saturating_mul(SEALED_SEGMENT as u64)
}

/// The number of segments of a sealed blob of `size` bytes, or None when
/// no sealed blob is that long.
pub fn segments(size: u64) -> Option<u64> {
    let n = size.checked_div(SEALED_SEGMENT as u64)?;
    (size != 0 && size.is_multiple_of(SEALED_SEGMENT as u64) && n <= MAX_SEGMENTS).then_some(n)
}

fn nonce(i: u64) -> Nonce {
    let mut n = Nonce::default();
    if let Some(tail) = n.get_mut(4..) {
        tail.copy_from_slice(&i.to_be_bytes());
    }
    n
}

fn aad(last: bool) -> [u8; 9] {
    let mut a = [0u8; 9];
    a[..8].copy_from_slice(AAD);
    a[8] = u8::from(last);
    a
}

/// Seals segment i: at most [`SEGMENT`] bytes, padded with zeros.
pub fn seal_segment(blob_key: &[u8; 32], i: u64, last: bool, plain: &[u8]) -> Result<Vec<u8>, Error> {
    if plain.len() > SEGMENT || i >= MAX_SEGMENTS {
        return Err(Error::msg("a blob's segment is too large or too far"));
    }
    let mut seg = Vec::with_capacity(SEGMENT);
    seg.extend_from_slice(plain);
    seg.resize(SEGMENT, 0);
    ChaCha20Poly1305::new(blob_key.into())
        .encrypt(&nonce(i), Payload { msg: &seg, aad: &aad(last) })
        .map_err(|_| Error::msg("a blob's segment cannot be sealed"))
}

/// Opens segment i: [`SEALED_SEGMENT`] bytes, the last one flagged so.
pub fn open_segment(blob_key: &[u8; 32], i: u64, last: bool, sealed: &[u8]) -> Result<Vec<u8>, Error> {
    if sealed.len() != SEALED_SEGMENT {
        return Err(Error::msg("a blob's segment is not 65552 bytes"));
    }
    ChaCha20Poly1305::new(blob_key.into())
        .decrypt(&nonce(i), Payload { msg: sealed, aad: &aad(last) })
        .map_err(|_| Error::msg("a blob's segment does not open: it was changed or is from another copy"))
}

/// Seals the parts' bytes whole: the sealed blob, whose size and SHA-256
/// go into the copy's header.
pub fn seal(blob_key: &[u8; 32], parts: &[u8]) -> Result<Vec<u8>, Error> {
    if parts.is_empty() || parts.len() as u64 > MAX_MEDIA as u64 {
        return Err(Error::msg("a blob holds 1 byte to 1 GiB"));
    }
    let n = parts.len().div_ceil(SEGMENT);
    let mut out = Vec::with_capacity(n.saturating_mul(SEALED_SEGMENT));
    for (i, chunk) in parts.chunks(SEGMENT).enumerate() {
        out.extend_from_slice(&seal_segment(blob_key, i as u64, i.checked_add(1) == Some(n), chunk)?);
    }
    Ok(out)
}

/// Opens a sealed blob whole against the header's `[size, sha256]` and the
/// manifest's size `n`: the parts' bytes.
pub fn open(blob_key: &[u8; 32], header: (u64, [u8; 32]), n: u64, sealed: &[u8]) -> Result<Vec<u8>, Error> {
    let (size, hash) = header;
    if sealed.len() as u64 != size || sealed_size(n) != size || segments(size).is_none() {
        return Err(Error::msg("the blob's size does not match its copy"));
    }
    if sha256(&[sealed]) != hash {
        return Err(Error::msg("the blob's SHA-256 does not match its copy"));
    }
    let count = sealed.len() / SEALED_SEGMENT;
    let mut out = Vec::with_capacity(count.saturating_mul(SEGMENT));
    for (i, seg) in sealed.chunks(SEALED_SEGMENT).enumerate() {
        out.extend_from_slice(&open_segment(blob_key, i as u64, i.checked_add(1) == Some(count), seg)?);
    }
    out.truncate(usize::try_from(n).map_err(|_| Error::msg("the blob is too large for this device"))?);
    Ok(out)
}
