// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The key container for TLS (format section 12): one fixed certificate
//! template, a function of the P-256 key alone. TLS needs a certificate; the
//! member checks only that it is the template with a key in its slot, and
//! then the key against the records. CertificateVerify proves the key, so
//! the container's own signature is the constant `r = 1, s = 1` and readers
//! do not read its value.

use super::{Rule, sha256};

/// The TBSCertificate's length, its header included.
pub const TBS_LEN: usize = 195;
/// Where the serial starts in the TBSCertificate.
pub const SERIAL_AT: usize = 10;
/// Where the key's point starts in the TBSCertificate.
pub const KEY_AT: usize = 130;
/// The whole container's length as 0.6 writers write it.
pub const LEN: usize = 221;

/// ecdsa-with-SHA256.
const ALG: [u8; 12] = [0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
/// The name CN=cbb, as issuer and subject.
const NAME: [u8; 16] = [0x30, 0x0e, 0x31, 0x0c, 0x30, 0x0a, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x03, b'c', b'b', b'b'];
/// The constant signature: a BIT STRING of the DER ECDSA signature r = 1, s = 1.
const SIG: [u8; 11] = [0x03, 0x09, 0x00, 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];

/// The serial of a point: the first 16 bytes of its SHA-256, the first
/// byte's top bits 01 (a positive number of 16 bytes).
pub fn serial(point: &[u8]) -> [u8; 16] {
    let h = sha256(&[point]);
    let mut s = [0u8; 16];
    s.copy_from_slice(h.get(..16).unwrap_or(&[0; 16]));
    s[0] = 0x40 | (s[0] & 0x3f);
    s
}

/// The TBSCertificate of a point.
pub fn tbs(point: &[u8; 65]) -> [u8; TBS_LEN] {
    let mut t = [0u8; TBS_LEN];
    let mut parts: [&[u8]; 14] = [
        &[0x30, 0x81, 0xc0, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x10],
        &[],
        &ALG,
        &NAME,
        &[0x30, 0x20, 0x17, 0x0d],
        b"700101000000Z",
        &[0x18, 0x0f],
        b"99991231235959Z",
        &NAME,
        &[0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01],
        &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07],
        &[0x03, 0x42, 0x00],
        point,
        &[],
    ];
    let ser = serial(point);
    parts[1] = &ser;
    let mut at = 0usize;
    for p in parts {
        if let Some(dst) = t.get_mut(at..at.saturating_add(p.len())) {
            dst.copy_from_slice(p);
        }
        at = at.saturating_add(p.len());
    }
    t
}

/// The container of a point, as 0.6 writers write it.
pub fn build(point: &[u8; 65]) -> [u8; LEN] {
    let mut c = [0u8; LEN];
    let head = [0x30, 0x81, 0xda];
    let tbs = tbs(point);
    let mut at = 0usize;
    for p in [&head[..], &tbs[..], &ALG[..], &SIG[..]] {
        if let Some(dst) = c.get_mut(at..at.saturating_add(p.len())) {
            dst.copy_from_slice(p);
        }
        at = at.saturating_add(p.len());
    }
    c
}

/// The longest signature value a reader takes: SEQUENCE { INTEGER r,
/// INTEGER s } with two integers of 33 bytes.
pub const MAX_SIG: usize = 72;

/// Reads a container: the TBSCertificate byte for byte the template with
/// its point and that point's serial, the point on the curve, then
/// ecdsa-with-SHA256 and the signature in its form (a BIT STRING with no
/// unused bits holding SEQUENCE { INTEGER, INTEGER }, each integer 1 to 33
/// bytes, every length exact, at most 72 bytes), whatever its value. Writers
/// of 0.6 write the constant signature; a later one may sign for real, and
/// this reader takes it. Returns the point.
pub fn read(cert: &[u8]) -> Result<[u8; 65], Rule> {
    // A SEQUENCE in DER: its length in one byte after 0x81 (128 to 255) or
    // two after 0x82 (256 and up).
    let rest = match cert {
        [0x30, 0x81, len, rest @ ..] if *len >= 0x80 && usize::from(*len) == rest.len() => rest,
        [0x30, 0x82, hi, lo, rest @ ..]
            if usize::from(u16::from_be_bytes([*hi, *lo])) == rest.len() && rest.len() >= 0x100 =>
        {
            rest
        }
        _ => return Err(Rule::CONTAINER),
    };
    let (Some(tbs_got), Some(after)) = (rest.get(..TBS_LEN), rest.get(TBS_LEN..)) else {
        return Err(Rule::CONTAINER);
    };
    let mut point = [0u8; 65];
    point.copy_from_slice(tbs_got.get(KEY_AT..KEY_AT + 65).ok_or(Rule::CONTAINER)?);
    if tbs_got != tbs(&point).as_slice() {
        return Err(Rule::CONTAINER);
    }
    if super::Key::new(super::Alg::Es256, &point).check().is_err() {
        return Err(Rule::CONTAINER);
    }
    let (Some(alg), Some(bits)) = (after.get(..ALG.len()), after.get(ALG.len()..)) else {
        return Err(Rule::CONTAINER);
    };
    if alg != ALG {
        return Err(Rule::CONTAINER);
    }
    match bits {
        [0x03, n, 0x00, sig @ ..] if usize::from(*n) == sig.len() + 1 && well_formed(sig) => Ok(point),
        _ => Err(Rule::CONTAINER),
    }
}

/// Whether a signature value has the form of a DER ECDSA signature:
/// SEQUENCE { INTEGER, INTEGER }, short lengths that are exact, each integer
/// 1 to 33 bytes, at most [`MAX_SIG`] bytes in all.
fn well_formed(sig: &[u8]) -> bool {
    let integer = |b: &[u8]| -> Option<usize> {
        match b {
            [0x02, n, rest @ ..] if (1..=33).contains(n) && rest.len() >= usize::from(*n) => {
                Some(2 + usize::from(*n))
            }
            _ => None,
        }
    };
    match sig {
        [0x30, n, body @ ..] if sig.len() <= MAX_SIG && usize::from(*n) == body.len() => {
            let Some(a) = integer(body) else { return false };
            let Some(rest) = body.get(a..) else { return false };
            integer(rest) == Some(rest.len())
        }
        _ => false,
    }
}
