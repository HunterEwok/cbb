// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Keys, their hashes and IDs, and ES256 signatures in the format's one
//! form (format-0.6 sections 2 and 3.1), on the format's codec
//! (`crate::format::key`, `crate::format::sig`). The records keep their keys
//! owned; a key is written and hashed as the format writes it.

use alloc::vec::Vec;

use p256::ecdsa::Signature;

use super::Rule;
use crate::certs::sha256;
use crate::format::cbor::Value;
use crate::format::key::{self as fkey, Alg};
use crate::format::sig;
use crate::identity::ExternalKey;

pub use crate::format::key::{DeviceId, GroupId, KeyHash};

/// ES256: ECDSA P-256 with SHA-256; a 65-byte uncompressed point.
pub const ALG_ES256: u64 = 1;
/// X-Wing KEM; a 1216-byte public key.
pub const ALG_XWING: u64 = 2;
/// X25519 (WireGuard); a 32-byte public key.
pub const ALG_X25519: u64 = 3;

/// SLH-DSA-SHA2-128s (FIPS 205): the recovery key's second half (E-6); a
/// 32-byte public key. It names no record's signer: it rides in the Group
/// ID, the Welcome and a recovery head's `signer2`.
pub const ALG_SLH_DSA: u64 = 4;
/// The size of an SLH-DSA-SHA2-128s public key.
pub const SLH_DSA_PUBLIC: usize = 32;

/// The size of an X-Wing public key.
pub const XWING_PUBLIC: usize = 1216;

/// A key as the format writes it: `[alg, pub]`.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Key {
    alg: u64,
    public: Vec<u8>,
    /// SHA-256 over the key's encoding, taken once when the key is made:
    /// the fields are private and never change, so it cannot go stale.
    hash: KeyHash,
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
    /// The key of algorithm `alg` with public bytes `public`; its hash is
    /// taken here, once.
    pub fn new(alg: u64, public: Vec<u8>) -> Key {
        let hash = fkey::Key::new(Alg::from_number(alg), &public).hash();
        Key { alg, public, hash }
    }

    pub fn es256(public: Vec<u8>) -> Key {
        Key::new(ALG_ES256, public)
    }

    /// The key a reader found in a body.
    pub fn read(v: &Value<'_>) -> Result<Key, Rule> {
        let k = fkey::Key::from_value(v)?;
        Ok(Key::new(k.alg.number(), k.public.to_vec()))
    }

    /// The key's algorithm number.
    pub fn alg(&self) -> u64 {
        self.alg
    }

    /// The key's public bytes.
    pub fn public(&self) -> &[u8] {
        &self.public
    }

    /// The format's view of the key.
    fn format(&self) -> fkey::Key<'_> {
        fkey::Key::new(Alg::from_number(self.alg), &self.public)
    }

    /// The key as a value of the profile.
    pub fn to_value(&self) -> Value<'_> {
        self.format().to_value()
    }

    /// The key's encoding, the bytes its hash is taken over.
    pub fn encode(&self) -> Vec<u8> {
        self.format().encode()
    }

    /// SHA-256 over the key's encoding, taken when the key was made.
    pub fn hash(&self) -> KeyHash {
        self.hash
    }

    /// The first 16 bytes of the key's hash: a device ID.
    pub fn device_id(&self) -> DeviceId {
        DeviceId::of(&self.hash())
    }

    /// Checks the key against its algorithm's form: `keys/es256` for a
    /// signature key that is not a point on the curve, `keys/xwing` and
    /// `keys/x25519` for a key of the wrong size.
    pub fn check(&self) -> Result<KeyCheck, Rule> {
        if self.alg == 0 {
            return Err(Rule::new("keys/alg"));
        }
        self.format().check()?;
        Ok(match Alg::from_number(self.alg) {
            Alg::Unknown(_) => KeyCheck::Unknown,
            _ => KeyCheck::Good,
        })
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

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                for b in self.0.iter().take(6) {
                    write!(f, "{b:02x}")?;
                }
                Ok(())
            }
        }
    };
}

bytes_type!(RecordId, 32);

impl RecordId {
    /// An ID read from 32 bytes.
    pub fn from_slice(b: &[u8]) -> Option<RecordId> {
        b.try_into().ok().map(RecordId)
    }
}

// The state starts from empty values; the format's types have no default
// of their own.
#[allow(clippy::derivable_impls, reason = "the type is the format's, which has no default")]
impl Default for KeyHash {
    fn default() -> KeyHash {
        KeyHash([0; 32])
    }
}

#[allow(clippy::derivable_impls, reason = "the type is the format's, which has no default")]
impl Default for DeviceId {
    fn default() -> DeviceId {
        DeviceId([0; 16])
    }
}

impl DeviceId {
    /// The first 16 bytes of a key hash.
    pub fn of(h: &KeyHash) -> DeviceId {
        #[cfg(test)]
        {
            let mut id = h.id();
            tests_hook::shorten(&mut id.0);
            id
        }
        #[cfg(not(test))]
        h.id()
    }
}

/// The group's recovery key (E-6): a pair, K1 (ES256) and K2
/// (SLH-DSA-SHA2-128s), both fixed in the Group ID. A recovery head carries
/// both signatures and both are required; everywhere else the recovery key
/// is named by K1's hash.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Recovery {
    pub k1: Key,
    pub k2: Key,
}

impl Recovery {
    /// The pair, when K1 is an ES256 key and K2 an SLH-DSA-SHA2-128s key of
    /// the right sizes.
    pub fn new(k1: Key, k2: Key) -> Option<Recovery> {
        let ok = k1.check().is_ok_and(|c| c == KeyCheck::Good)
            && k1.alg == ALG_ES256
            && k2.alg == ALG_SLH_DSA
            && k2.public.len() == SLH_DSA_PUBLIC;
        ok.then_some(Recovery { k1, k2 })
    }

    /// K1's hash: the recovery key's name as a signer.
    pub fn hash(&self) -> KeyHash {
        self.k1.hash()
    }

    /// K2's hash: a recovery head's `signer2`.
    pub fn hash2(&self) -> KeyHash {
        self.k2.hash()
    }
}

/// The label of the Group ID's hash.
pub const LABEL_GROUP: &str = "cbb group v3";

/// The Group ID: the first 16 bytes of SHA-256 over the label, a zero
/// byte, and the encodings of the group's first root key and the two
/// halves of its recovery key (rule 33, E-6). It commits to all three: a
/// recovery key that is not the group's gives another Group ID, so no
/// admitter can pin a false one. Each key is one self-delimiting item, so
/// the three cannot be cut another way; a second preimage costs 2^128.
pub fn group_id(root: &Key, recovery: &Recovery) -> GroupId {
    let mut m = Vec::new();
    m.extend_from_slice(LABEL_GROUP.as_bytes());
    m.push(0);
    m.extend_from_slice(&root.encode());
    m.extend_from_slice(&recovery.k1.encode());
    m.extend_from_slice(&recovery.k2.encode());
    DeviceId::of(&KeyHash(sha256(&m)))
}

/// Checks an ES256 signature in the one form the format takes: 64 bytes
/// `r ‖ s`, both in range, s low (`sig/size`, `sig/range`, `sig/low-s`,
/// `sig/verify`).
pub fn verify_es256(key: &Key, label: &str, body: &[u8], s: &[u8]) -> Result<(), Rule> {
    sig::check_form(s)?;
    if key.alg != ALG_ES256 {
        return Err(Rule::new("sig/verify"));
    }
    Ok(sig::verify_es256(&key.public, label, body, s)?)
}

/// Signs body under label with key, which signs a SHA-256 digest in DER
/// (a hardware key or a key in a file); the signature is turned into the
/// format's 64 bytes with a low S.
pub fn sign_es256(key: &dyn ExternalKey, label: &str, body: &[u8]) -> crate::error::Result<[u8; 64]> {
    let digest = sha256(&sig::message(label, body));
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

#[cfg(test)]
mod hash_tests {
    use super::*;

    /// The hash a key keeps is the hash of its encoding, however the key
    /// was made: by its parts, as ES256, read from a body, or cloned.
    #[test]
    fn a_keys_kept_hash_is_its_encodings_hash() {
        let es = crate::testkit::k("some key").key;
        let keys = [
            es.clone(),
            Key::new(ALG_XWING, alloc::vec![3; XWING_PUBLIC]),
            Key::new(ALG_SLH_DSA, alloc::vec![9; SLH_DSA_PUBLIC]),
            Key::new(77, alloc::vec![1, 2, 3]),
            Key::read(&crate::format::cbor::decode(&es.encode()).unwrap()).unwrap(),
            Key::es256(es.public().to_vec()),
        ];
        for k in keys.iter().chain(keys.clone().iter()) {
            assert_eq!(k.hash(), KeyHash(crate::certs::sha256(&k.encode())));
            assert_eq!(k.hash(), k.format().hash());
        }
        assert_eq!(keys[0], keys[4]);
        assert_eq!(keys[0], keys[5]);
    }
}
