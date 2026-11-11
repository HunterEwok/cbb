// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Keys, their hashes and IDs, and the one form of an ES256 signature
//! (format-0.6 sections 2 and 3.1). They move to the format's codec
//! (`crate::format::key`, `crate::format::sig`) once it is in the tree.

use alloc::vec::Vec;
use core::fmt;

use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature, VerifyingKey};

use super::Rule;
use super::cbor;
use crate::certs::sha256;
use crate::identity::ExternalKey;

/// ES256: ECDSA P-256 with SHA-256; a 65-byte uncompressed point.
pub const ALG_ES256: u64 = 1;
/// X-Wing KEM; a 1216-byte public key.
pub const ALG_XWING: u64 = 2;
/// X25519 (WireGuard); a 32-byte public key.
pub const ALG_X25519: u64 = 3;

/// The size of an X-Wing public key.
pub const XWING_PUBLIC: usize = 1216;

/// A key as the format writes it: `[alg, pub]`.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Key {
    pub alg: u64,
    pub public: Vec<u8>,
}

/// What reading a key found.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KeyCheck {
    /// An algorithm of 0.6 with a key of the right form.
    Good,
    /// An algorithm this version does not know: an object that names it
    /// where a key is wanted is held, not refused (section 3.3).
    Unknown,
}

impl Key {
    pub fn es256(public: Vec<u8>) -> Key {
        Key { alg: ALG_ES256, public }
    }

    /// The key's encoding, the bytes its hash is taken over.
    pub fn encode(&self) -> Vec<u8> {
        cbor::array([cbor::uint(self.alg), cbor::bytes(&self.public)])
    }

    /// SHA-256 over the key's encoding.
    pub fn hash(&self) -> KeyHash {
        KeyHash(sha256(&self.encode()))
    }

    /// The first 16 bytes of the key's hash: a device ID, or, for a group's
    /// first root key, the group ID.
    pub fn device_id(&self) -> DeviceId {
        DeviceId::of(&self.hash())
    }

    /// Checks the key against its algorithm's form: `keys/es256` for a
    /// signature key that is not a point on the curve, `keys/xwing` and
    /// `keys/x25519` for a key of the wrong size.
    pub fn check(&self) -> Result<KeyCheck, Rule> {
        match self.alg {
            ALG_ES256 => {
                if self.public.len() != 65
                    || self.public.first() != Some(&4)
                    || p256::PublicKey::from_sec1_bytes(&self.public).is_err()
                {
                    return Err(Rule::new("keys/es256"));
                }
                Ok(KeyCheck::Good)
            }
            ALG_XWING if self.public.len() != XWING_PUBLIC => Err(Rule::new("keys/xwing")),
            ALG_X25519 if self.public.len() != 32 => Err(Rule::new("keys/x25519")),
            ALG_XWING | ALG_X25519 => Ok(KeyCheck::Good),
            0 => Err(Rule::new("keys/alg")),
            _ => Ok(KeyCheck::Unknown),
        }
    }

    /// Checks a key where a signature key is wanted: ES256 or, from a later
    /// version, an algorithm this one does not know (held).
    pub fn check_signer(&self) -> Result<KeyCheck, Rule> {
        match self.check()? {
            KeyCheck::Good if self.alg == ALG_ES256 => Ok(KeyCheck::Good),
            KeyCheck::Good => Err(Rule::new("keys/alg")),
            KeyCheck::Unknown => Ok(KeyCheck::Unknown),
        }
    }
}

macro_rules! bytes_type {
    ($name:ident, $n:expr) => {
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
        pub struct $name(pub [u8; $n]);

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                for b in self.0.iter().take(6) {
                    write!(f, "{b:02x}")?;
                }
                Ok(())
            }
        }
    };
}

bytes_type!(KeyHash, 32);
bytes_type!(RecordId, 32);
bytes_type!(DeviceId, 16);

/// A group's ID: the device ID of its first root key.
pub type GroupId = DeviceId;

impl DeviceId {
    /// The first 16 bytes of a key hash.
    pub fn of(h: &KeyHash) -> DeviceId {
        let mut id = [0u8; 16];
        for (d, s) in id.iter_mut().zip(h.0.iter()) {
            *d = *s;
        }
        #[cfg(test)]
        tests_hook::shorten(&mut id);
        DeviceId(id)
    }
}

/// The message a signature covers: `label ‖ 0x00 ‖ body`.
pub fn signed_message(label: &str, body: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(label.len().saturating_add(1).saturating_add(body.len()));
    m.extend_from_slice(label.as_bytes());
    m.push(0);
    m.extend_from_slice(body);
    m
}

/// Half the order of P-256, big-endian: the largest low S.
const HALF_N: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xde, 0x73, 0x7d,
    0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xb5, 0xc5, 0x92, 0xa8, 0x7c, 0x50,
];

/// Checks an ES256 signature in the one form the format takes: 64 bytes
/// `r ‖ s`, both in range, s low (`sig/size`, `sig/range`, `sig/low-s`,
/// `sig/verify`).
pub fn verify_es256(key: &Key, label: &str, body: &[u8], sig: &[u8]) -> Result<(), Rule> {
    if sig.len() != 64 {
        return Err(Rule::new("sig/size"));
    }
    let s = sig.get(32..).unwrap_or_default();
    if s > HALF_N.as_slice() {
        return Err(Rule::new("sig/low-s"));
    }
    // from_slice refuses r or s of zero or not below the order.
    let Ok(signature) = Signature::from_slice(sig) else { return Err(Rule::new("sig/range")) };
    if key.alg != ALG_ES256 {
        return Err(Rule::new("sig/verify"));
    }
    let Ok(vk) = VerifyingKey::from_sec1_bytes(&key.public) else { return Err(Rule::new("sig/verify")) };
    let digest = sha256(&signed_message(label, body));
    vk.verify_prehash(&digest, &signature).map_err(|_| Rule::new("sig/verify"))
}

/// Signs body under label with key, which signs a SHA-256 digest in DER
/// (a hardware key or a key in a file); the signature is turned into the
/// format's 64 bytes with a low S.
pub fn sign_es256(key: &dyn ExternalKey, label: &str, body: &[u8]) -> crate::error::Result<[u8; 64]> {
    let digest = sha256(&signed_message(label, body));
    let der = key.sign_digest(&digest)?;
    let sig = Signature::from_der(&der).map_err(|_| crate::error::Error::msg("the key's signature is not DER"))?;
    let sig = sig.normalize_s();
    let mut out = [0u8; 64];
    for (d, s) in out.iter_mut().zip(sig.to_bytes().iter()) {
        *d = *s;
    }
    Ok(out)
}

/// The tests make two keys with one device ID by keeping fewer of a hash's
/// bytes, since a real collision of 128 bits cannot be made.
#[cfg(test)]
pub mod tests_hook {
    use std::cell::Cell;

    std::thread_local! {
        static KEEP: Cell<usize> = const { Cell::new(16) };
    }

    /// Keeps only n bytes of each device ID on this thread until the guard
    /// goes.
    pub fn keep(n: usize) -> Guard {
        KEEP.with(|k| k.set(n));
        Guard
    }

    pub struct Guard;

    impl Drop for Guard {
        fn drop(&mut self) {
            KEEP.with(|k| k.set(16));
        }
    }

    pub(super) fn shorten(id: &mut [u8; 16]) {
        let n = KEEP.with(|k| k.get());
        for b in id.iter_mut().skip(n) {
            *b = 0;
        }
    }
}
