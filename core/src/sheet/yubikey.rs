// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The recovery secret on a YubiKey: the bytes, without the card.
//!
//! A YubiKey 5 holds the same thing as the sheet: its version and the
//! 32-byte secret, sealed to a P-256 key the card made in PIV's retired
//! slot 95, which never leaves the card and only does ECDH after the PIN
//! and a touch. The sealed bytes are the value of PIV's data object
//! `5FC121`, which the card shows only after the PIN:
//!
//! `CBBR` ‖ version (1 byte, 1) ‖ E (65 bytes, an uncompressed P-256
//! point) ‖ ciphertext (49 bytes)
//!
//! Sealing (the phone, from the sheet or when the group is made): a fresh
//! key e with its point E; Z the x coordinate of e times the card's point;
//! K = HKDF-SHA256(salt E ‖ card's point, Z, info [`LABEL`], 32 bytes); the
//! ciphertext is ChaCha20-Poly1305 under K with a nonce of 12 zero bytes
//! (K seals once), associated data [`LABEL`] ‖ 0x00 ‖ version byte ‖
//! card's point, of the sheet's version character `1` and the secret.
//! Opening: the card gives Z for E, and [`open`] does the rest. The card's
//! commands are each device's own (`member/src/piv.rs`, the phone kits).

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use p256::elliptic_curve::sec1::ToSec1Point as _;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

/// The PIV data object that holds the sealed secret: Iris, which needs the
/// PIN to read and which no YubiKey tool uses.
pub const OBJECT: [u8; 3] = [0x5f, 0xc1, 0x21];
/// The retired PIV slot of the card's key.
pub const SLOT: u8 = 0x95;
/// The object's first bytes.
pub const PREFIX: &[u8; 4] = b"CBBR";
/// The object's version.
pub const VERSION: u8 = 1;
/// The label of the key and of the associated data.
pub const LABEL: &str = "cbb recovery yubikey v1";
/// An uncompressed P-256 point.
pub const POINT: usize = 65;
/// The sealed version character and secret, with the tag.
pub const CIPHERTEXT: usize = 1 + 32 + 16;
/// The object's value.
pub const LEN: usize = PREFIX.len() + 1 + POINT + CIPHERTEXT;
const _: () = assert!(LEN == 119);

/// Why a YubiKey's object or key was refused, in the words an app shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    /// The object is not cbb's: the card holds something else there.
    NotCbb,
    /// A later version: "this YubiKey needs a newer cbb".
    Newer,
    /// cbb's prefix and version, and bytes that do not read.
    Damaged,
    /// The object does not open with this card's key, or it is sealed to
    /// another recovery secret than the group's.
    OtherKey,
    /// The card's key is not a P-256 point.
    CardKey,
}

impl Reason {
    /// What the app tells the person.
    pub fn message(&self) -> &'static str {
        match self {
            Reason::NotCbb => "this YubiKey already holds something in the place cbb uses",
            Reason::Newer => "this YubiKey needs a newer cbb",
            Reason::Damaged => "the recovery key on this YubiKey is damaged",
            Reason::OtherKey => "this YubiKey holds another recovery key",
            Reason::CardKey => "this YubiKey's key is not one cbb uses",
        }
    }
}

/// The parts of an object that reads.
pub struct Sealed<'a> {
    /// The sealing key's point, to give the card.
    pub e: &'a [u8],
    ciphertext: &'a [u8],
}

/// Reads an object's value: cbb's prefix, then its version, then its
/// length and point. A value that does not start with the prefix is not
/// cbb's, whatever follows; one of a later version is not read further.
pub fn read(object: &[u8]) -> Result<Sealed<'_>, Reason> {
    let Some(rest) = object.strip_prefix(PREFIX.as_slice()) else { return Err(Reason::NotCbb) };
    let Some((&version, rest)) = rest.split_first() else { return Err(Reason::Damaged) };
    if version != VERSION {
        return Err(Reason::Newer);
    }
    if rest.len() != POINT + CIPHERTEXT {
        return Err(Reason::Damaged);
    }
    let (e, ciphertext) = rest.split_at(POINT);
    if point(e).is_none() {
        return Err(Reason::Damaged);
    }
    Ok(Sealed { e, ciphertext })
}

/// Whether an object's value is cbb's of a version this program knows:
/// what a device asks before it writes anything to a card.
pub fn is_ours(object: &[u8]) -> bool {
    object.starts_with(PREFIX) && object.get(PREFIX.len()) == Some(&VERSION)
}

fn point(b: &[u8]) -> Option<p256::PublicKey> {
    if b.len() != POINT || b.first() != Some(&4) {
        return None;
    }
    p256::PublicKey::from_sec1_bytes(b).ok()
}

/// The x coordinate of scalar times point: ECDH as PIV's GENERAL
/// AUTHENTICATE gives it.
pub fn ecdh(scalar: &p256::SecretKey, point: &[u8]) -> Result<Zeroizing<[u8; 32]>, Reason> {
    let p = self::point(point).ok_or(Reason::CardKey)?;
    // Point times scalar on the curve: no integer arithmetic.
    #[allow(clippy::arithmetic_side_effects)]
    let shared = (p.to_projective() * *scalar.to_nonzero_scalar()).to_affine();
    let shared = p256::PublicKey::from_affine(shared).map_err(|_| Reason::CardKey)?;
    let enc = shared.to_sec1_point(false);
    let mut z = Zeroizing::new([0u8; 32]);
    z.copy_from_slice(enc.as_bytes().get(1..33).ok_or(Reason::CardKey)?);
    Ok(z)
}

fn key(z: &[u8; 32], e: &[u8], card: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut salt = alloc::vec::Vec::with_capacity(2 * POINT);
    salt.extend_from_slice(e);
    salt.extend_from_slice(card);
    let mut k = Zeroizing::new([0u8; 32]);
    // 32 bytes are always within HKDF-SHA256's length.
    let _ = Hkdf::<Sha256>::new(Some(&salt), z).expand(LABEL.as_bytes(), k.as_mut());
    k
}

fn aad(card: &[u8]) -> alloc::vec::Vec<u8> {
    let mut a = alloc::vec::Vec::with_capacity(LABEL.len().saturating_add(2 + POINT));
    a.extend_from_slice(LABEL.as_bytes());
    a.push(0);
    a.push(VERSION);
    a.extend_from_slice(card);
    a
}

/// Seals secret to the card's point with the fresh key e (the caller's
/// random scalar, wiped by its owner): the object's value.
pub fn seal(secret: &[u8; 32], card: &[u8], e: &p256::SecretKey) -> Result<[u8; LEN], Reason> {
    let z = ecdh(e, card)?;
    let ep = e.public_key().to_sec1_point(false);
    let ep = ep.as_bytes();
    let k = key(&z, ep, card);
    let mut plain = Zeroizing::new(alloc::vec::Vec::with_capacity(33));
    plain.push(super::VERSION);
    plain.extend_from_slice(secret);
    let ct = ChaCha20Poly1305::new((&*k).into())
        .encrypt(&Nonce::default(), Payload { msg: plain.as_ref(), aad: &aad(card) })
        .map_err(|_| Reason::CardKey)?;
    let mut out = alloc::vec::Vec::with_capacity(LEN);
    for part in [PREFIX.as_slice(), &[VERSION], ep, &ct] {
        out.extend_from_slice(part);
    }
    out.try_into().map_err(|_| Reason::CardKey)
}

/// Opens an object's value with Z, which the card gave for its E after the
/// PIN and a touch: the secret, for one signing.
pub fn open(z: &[u8; 32], card: &[u8], object: &[u8]) -> Result<Zeroizing<[u8; 32]>, Reason> {
    let s = read(object)?;
    if point(card).is_none() {
        return Err(Reason::CardKey);
    }
    let k = key(z, s.e, card);
    let mut plain = ChaCha20Poly1305::new((&*k).into())
        .decrypt(&Nonce::default(), Payload { msg: s.ciphertext, aad: &aad(card) })
        .map_err(|_| Reason::OtherKey)?;
    let out = match plain.split_first() {
        Some((&v, secret)) if v == super::VERSION && secret.len() == 32 => {
            let mut out = Zeroizing::new([0u8; 32]);
            out.copy_from_slice(secret);
            Ok(out)
        }
        _ => Err(Reason::Damaged),
    };
    plain.zeroize();
    out
}

/// Checks an opened secret against the group: K1 and K2 from it must be
/// the group's recovery keys, or the card holds another group's.
pub fn check(secret: &[u8; 32], recovery: &crate::records::key::Recovery) -> Result<(), Reason> {
    let read = super::Read { secret: Zeroizing::new(*secret), group: None };
    super::check_keys(&read, recovery).then_some(()).ok_or(Reason::OtherKey)
}

#[cfg(test)]
mod tests;
