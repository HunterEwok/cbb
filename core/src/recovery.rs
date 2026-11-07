// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The recovery sheet (docs/protocol.md, section 10, "The recovery key"):
//! the printed form of the group's recovery key. Its QR code carries the
//! key, its admin CA and the group's tag; its text carries the key alone,
//! in Crockford's base32 with a check group, for a person to type into a
//! computer of the group, which has the admin CA in the records.
//!
//! The QR code is `cbb://recover?g=<group>&k=<key>&c=<admin CA>`
//! with k and c in base64url without padding; the text is the key's 32
//! bytes as 52 characters and 4 check characters, in groups of four joined
//! by hyphens.

use alloc::string::String;
use alloc::vec::Vec;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::SecretKey;
use p256::elliptic_curve::sec1::ToSec1Point as _;
use p256::pkcs8::{EncodePrivateKey as _, EncodePublicKey as _};

use crate::certs::{Cert, sha256};

/// The start of the QR code's text.
pub const PREFIX: &str = "cbb://recover?";
/// Crockford's base32 alphabet.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// The key's characters in the text: 256 bits in groups of 5, the last 4 bits zero.
const KEY_CHARS: usize = 52;
/// The check characters after the key: the first 20 bits of the check hash.
const CHECK_CHARS: usize = 4;
/// What the check hash covers before the key.
const CHECK_CONTEXT: &[u8] = b"cbb recovery";
/// The longest admin CA a QR code may carry.
pub const MAX_CERT: usize = 2048;
/// The longest text read: the QR code with the longest admin CA, with room to spare.
pub const MAX_TEXT: usize = 4096;

/// Why read refused a text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    /// Neither the QR code's prefix nor 56 base32 characters.
    NotSheet,
    /// Not base64url, a field missing, repeated or unknown, a character
    /// outside the alphabet, or padding bits that are not zero.
    Damaged,
    /// The check characters do not match the key: a mistyped character.
    Check,
    /// The 32 bytes are not a P-256 private key.
    Key,
    /// The admin CA cannot be read, is not a CA or is too large.
    Cert,
    /// The admin CA is not the key's.
    Mismatch,
    /// The group tag is not 16 hex digits.
    Group,
}

impl Reason {
    /// The reason's name.
    pub fn name(self) -> &'static str {
        match self {
            Reason::NotSheet => "not_sheet",
            Reason::Damaged => "damaged",
            Reason::Check => "check",
            Reason::Key => "key",
            Reason::Cert => "cert",
            Reason::Mismatch => "mismatch",
            Reason::Group => "group",
        }
    }

    /// A sentence for the user.
    pub fn message(self) -> &'static str {
        match self {
            Reason::NotSheet => "this is not a cbb recovery sheet",
            Reason::Damaged => "the recovery key is damaged",
            Reason::Check => "a character of the recovery key is mistyped; check each group of four",
            Reason::Key => "the recovery key is not a valid key",
            Reason::Cert => "the recovery key's certificate is damaged",
            Reason::Mismatch => "the recovery key's certificate is for another key",
            Reason::Group => "the recovery sheet names no group",
        }
    }
}

/// A recovery key read from a sheet.
pub struct Sheet {
    /// The private key.
    pub key: SecretKey,
    /// The admin CA, from the QR code; the text has none.
    pub cert: Option<Vec<u8>>,
    /// The group's tag, from the QR code; the text has none.
    pub group: Option<String>,
}

impl Sheet {
    /// The key's 32 bytes.
    pub fn scalar(&self) -> [u8; 32] {
        self.key.to_bytes().into()
    }

    /// The key as PKCS #8 DER.
    pub fn pkcs8(&self) -> Option<Vec<u8>> {
        self.key.to_pkcs8_der().ok().map(|d| d.as_bytes().to_vec())
    }

    /// The public key, uncompressed.
    pub fn public(&self) -> Vec<u8> {
        self.key.public_key().to_sec1_point(false).as_bytes().to_vec()
    }

    /// The hash of the public key, as the `recovery` record's `admin`
    /// names it: SHA-256 over its SubjectPublicKeyInfo.
    pub fn admin(&self) -> Option<[u8; 32]> {
        spki_hash(&self.key)
    }
}

fn spki_hash(key: &SecretKey) -> Option<[u8; 32]> {
    key.public_key().to_public_key_der().ok().map(|d| sha256(d.as_bytes()))
}

/// Reads a private key of 32 bytes.
pub fn secret_key(scalar: &[u8]) -> Option<SecretKey> {
    let bytes: [u8; 32] = scalar.try_into().ok()?;
    SecretKey::from_bytes(&bytes.into()).ok()
}

/// The key as the sheet's text: 14 groups of four characters.
pub fn text(key: &SecretKey) -> String {
    let scalar: [u8; 32] = key.to_bytes().into();
    let mut chars = encode32(&scalar);
    chars.extend(check(&scalar));
    let mut out = String::with_capacity(chars.len().saturating_mul(5));
    for (i, group) in chars.chunks(4).enumerate() {
        if i > 0 {
            out.push('-');
        }
        out.extend(group.iter().map(|&c| char::from(c)));
    }
    out
}

/// The QR code's text for a key, its admin CA and the group's tag. It
/// refuses an admin CA that is not the key's, and a group that is not a
/// tag.
pub fn qr(key: &SecretKey, cert: &[u8], group: &str) -> Result<String, Reason> {
    check_cert(key, cert)?;
    if !is_tag(group) {
        return Err(Reason::Group);
    }
    let scalar: [u8; 32] = key.to_bytes().into();
    Ok(alloc::format!("{PREFIX}g={group}&k={}&c={}", URL_SAFE_NO_PAD.encode(scalar), URL_SAFE_NO_PAD.encode(cert)))
}

/// Reads a sheet's QR code or its text.
pub fn read(text: &str) -> Result<Sheet, Reason> {
    if text.len() > MAX_TEXT {
        return Err(Reason::NotSheet);
    }
    let text = text.trim();
    match text.strip_prefix(PREFIX) {
        Some(query) => read_qr(query),
        None => read_text(text),
    }
}

fn read_qr(query: &str) -> Result<Sheet, Reason> {
    let (mut g, mut k, mut c) = (None, None, None);
    for pair in query.split('&') {
        let (name, value) = pair.split_once('=').ok_or(Reason::Damaged)?;
        let slot = match name {
            "g" => &mut g,
            "k" => &mut k,
            "c" => &mut c,
            _ => return Err(Reason::Damaged),
        };
        if slot.replace(value).is_some() {
            return Err(Reason::Damaged);
        }
    }
    let (g, k, c) = (g.ok_or(Reason::Damaged)?, k.ok_or(Reason::Damaged)?, c.ok_or(Reason::Damaged)?);
    let scalar = URL_SAFE_NO_PAD.decode(k).map_err(|_| Reason::Damaged)?;
    let cert = URL_SAFE_NO_PAD.decode(c).map_err(|_| Reason::Damaged)?;
    let key = secret_key(&scalar).ok_or(Reason::Key)?;
    check_cert(&key, &cert)?;
    if !is_tag(g) {
        return Err(Reason::Group);
    }
    Ok(Sheet { key, cert: Some(cert), group: Some(g.into()) })
}

fn read_text(text: &str) -> Result<Sheet, Reason> {
    let mut chars = Vec::with_capacity(KEY_CHARS.saturating_add(CHECK_CHARS));
    for c in text.chars() {
        if c == '-' || c.is_whitespace() {
            continue;
        }
        let c = match c.to_ascii_uppercase() {
            'I' | 'L' => '1',
            'O' => '0',
            c => c,
        };
        if !c.is_ascii() || !ALPHABET.contains(&(c as u8)) {
            return Err(if chars.is_empty() { Reason::NotSheet } else { Reason::Damaged });
        }
        chars.push(c as u8);
    }
    if chars.len() != KEY_CHARS.saturating_add(CHECK_CHARS) {
        return Err(Reason::NotSheet);
    }
    let (key_chars, check_chars) = chars.split_at(KEY_CHARS);
    let scalar = decode32(key_chars).ok_or(Reason::Damaged)?;
    if check(&scalar).as_slice() != check_chars {
        return Err(Reason::Check);
    }
    let key = secret_key(&scalar).ok_or(Reason::Key)?;
    Ok(Sheet { key, cert: None, group: None })
}

fn check_cert(key: &SecretKey, der: &[u8]) -> Result<(), Reason> {
    if der.len() > MAX_CERT {
        return Err(Reason::Cert);
    }
    let cert = Cert::parse(der).map_err(|_| Reason::Cert)?;
    if !cert.is_ca || !cert.p256 {
        return Err(Reason::Cert);
    }
    if spki_hash(key) != Some(cert.key_hash()) {
        return Err(Reason::Mismatch);
    }
    Ok(())
}

fn is_tag(s: &str) -> bool {
    s.len() == 16 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The four check characters: the first 20 bits of SHA-256 over the
/// context and the key.
fn check(scalar: &[u8; 32]) -> [u8; CHECK_CHARS] {
    let mut data = Vec::with_capacity(CHECK_CONTEXT.len().saturating_add(32));
    data.extend_from_slice(CHECK_CONTEXT);
    data.extend_from_slice(scalar);
    let h = sha256(&data);
    let mut out = [0u8; CHECK_CHARS];
    let mut acc: u32 = 0;
    for &b in h.iter().take(3) {
        acc = (acc << 8) | u32::from(b);
    }
    // 24 bits in acc; the first 20 make four characters.
    for (i, slot) in out.iter_mut().enumerate() {
        let shift = 19u32.saturating_sub(u32::try_from(i).unwrap_or(0).saturating_mul(5));
        *slot = symbol(acc >> shift);
    }
    out
}

fn symbol(v: u32) -> u8 {
    ALPHABET.get((v & 31) as usize).copied().unwrap_or(b'0')
}

fn value(c: u8) -> Option<u32> {
    ALPHABET.iter().position(|&a| a == c).and_then(|p| u32::try_from(p).ok())
}

/// 32 bytes as 52 base32 characters, the last 4 bits zero.
fn encode32(data: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(KEY_CHARS);
    let (mut acc, mut bits): (u32, u32) = (0, 0);
    for &b in data {
        acc = (acc << 8) | u32::from(b);
        bits = bits.saturating_add(8);
        while bits >= 5 {
            bits = bits.saturating_sub(5);
            out.push(symbol(acc >> bits));
        }
        acc &= (1u32 << bits).saturating_sub(1);
    }
    if bits > 0 {
        out.push(symbol(acc << 5u32.saturating_sub(bits)));
    }
    out
}

/// 52 base32 characters as 32 bytes; None when the last 4 bits are not
/// zero, so that each key has one text.
fn decode32(chars: &[u8]) -> Option<[u8; 32]> {
    let mut out = Vec::with_capacity(32);
    let (mut acc, mut bits): (u32, u32) = (0, 0);
    for &c in chars {
        acc = (acc << 5) | value(c)?;
        bits = bits.saturating_add(5);
        if bits >= 8 {
            bits = bits.saturating_sub(8);
            out.push(u8::try_from((acc >> bits) & 0xff).ok()?);
        }
        acc &= (1u32 << bits).saturating_sub(1);
    }
    if acc != 0 {
        return None;
    }
    out.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> SecretKey {
        secret_key(&[byte; 32]).unwrap()
    }

    #[test]
    fn text_round_trip() {
        for b in [1u8, 0x42, 0x7f, 0xa5] {
            let k = key(b);
            let t = text(&k);
            assert_eq!(t.len(), 14 * 4 + 13, "{t}");
            let s = read(&t).unwrap();
            assert_eq!(s.scalar(), [b; 32]);
            assert!(s.cert.is_none() && s.group.is_none());
            // Lower case, spaces in place of hyphens, and the look-alikes.
            let loose = t.to_lowercase().replace('-', " ").replace('1', "l").replace('0', "o");
            assert_eq!(read(&loose).unwrap().scalar(), [b; 32], "{loose}");
        }
    }

    fn vectors() -> serde_json::Value {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../testdata/interop/recovery-sheet.json");
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap()
    }

    fn b64(v: &serde_json::Value) -> Vec<u8> {
        base64::engine::general_purpose::STANDARD.decode(v.as_str().unwrap()).unwrap()
    }

    /// The sheet's QR code, text and hash, and the readers' answers, as
    /// testdata/interop/recovery-sheet.json has them for the kits too.
    #[test]
    fn matches_the_vectors() {
        let v = vectors();
        let s = &v["sheet"];
        let k = secret_key(&b64(&s["key"])).unwrap();
        assert_eq!(text(&k), s["text"].as_str().unwrap());
        assert_eq!(qr(&k, &b64(&s["cert"]), s["group"].as_str().unwrap()).unwrap(), s["qr"].as_str().unwrap());
        let read_qr = read(s["qr"].as_str().unwrap()).unwrap();
        assert_eq!(read_qr.admin().unwrap().to_vec(), b64(&s["admin"]));
        assert_eq!(read_qr.cert.unwrap(), b64(&s["cert"]));
        assert_eq!(read_qr.group.unwrap(), s["group"].as_str().unwrap());
        for c in v["texts"].as_array().unwrap() {
            assert_eq!(text(&secret_key(&b64(&c["key"])).unwrap()), c["text"].as_str().unwrap());
        }
        for c in v["read"].as_array().unwrap() {
            assert_eq!(read(c["text"].as_str().unwrap()).unwrap().scalar().to_vec(), b64(&c["key"]), "{c}");
        }
        for c in v["refused"].as_array().unwrap() {
            let got = read(c["text"].as_str().unwrap()).err().map(Reason::name);
            assert_eq!(got, c["reason"].as_str(), "{c}");
        }
    }

    #[test]
    fn a_typo_fails_the_check() {
        let t = text(&key(0x42));
        let mut bytes = t.into_bytes();
        bytes[5] = if bytes[5] == b'Z' { b'Y' } else { b'Z' };
        assert_eq!(read(core::str::from_utf8(&bytes).unwrap()).err(), Some(Reason::Check));
    }

    #[test]
    fn refuses_bad_texts() {
        assert_eq!(read("hello").err(), Some(Reason::NotSheet));
        assert_eq!(read("").err(), Some(Reason::NotSheet));
        assert_eq!(read(&"0".repeat(55)).err(), Some(Reason::NotSheet));
        assert_eq!(read(&alloc::format!("0{}", "U".repeat(55))).err(), Some(Reason::Damaged));
        // All zeros: the check matches nothing, and zero is no key.
        let zero = [0u8; 32];
        let mut chars = encode32(&zero);
        chars.extend(check(&zero));
        assert_eq!(read(core::str::from_utf8(&chars).unwrap()).err(), Some(Reason::Key));
        // Padding bits set.
        let mut chars = encode32(&[0x42; 32]);
        let last = chars.last_mut().unwrap();
        *last = symbol(value(*last).unwrap() | 1);
        assert!(read(core::str::from_utf8(&chars).unwrap()).is_err());
        assert_eq!(read(&"0".repeat(MAX_TEXT + 1)).err(), Some(Reason::NotSheet));
    }

    #[test]
    fn base32_matches_its_inverse() {
        for b in 0..=255u8 {
            let data: [u8; 32] = core::array::from_fn(|i| b.wrapping_mul(u8::try_from(i).unwrap()).wrapping_add(7));
            let chars = encode32(&data);
            assert_eq!(chars.len(), KEY_CHARS);
            assert_eq!(decode32(&chars), Some(data));
        }
    }
}
