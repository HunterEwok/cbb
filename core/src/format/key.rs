// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Keys (format section 2): a Key is the array `[alg, pub]`; its hash is
//! SHA-256 over that array's encoding; a device's ID and a group's ID are
//! the first 16 bytes of such a hash.

use alloc::vec::Vec;

use super::cbor::{Encoder, Value};
use super::{Rule, sha256};

/// The algorithms of the registry (section 14).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Alg {
    /// ECDSA P-256 with SHA-256; a 65-byte uncompressed point.
    Es256,
    /// The X-Wing KEM; a 1216-byte key.
    XWing,
    /// X25519 (WireGuard); a 32-byte key.
    X25519,
    /// A number this version does not know (4 is kept for a post-quantum
    /// signature). A record naming one where a key is wanted is held.
    Unknown(u64),
}

impl Alg {
    /// The algorithm of a registry number.
    pub fn from_number(n: u64) -> Alg {
        match n {
            1 => Alg::Es256,
            2 => Alg::XWing,
            3 => Alg::X25519,
            n => Alg::Unknown(n),
        }
    }

    /// The registry number.
    pub fn number(self) -> u64 {
        match self {
            Alg::Es256 => 1,
            Alg::XWing => 2,
            Alg::X25519 => 3,
            Alg::Unknown(n) => n,
        }
    }

    /// The size of the public key, for the algorithms this version knows.
    pub fn key_size(self) -> Option<usize> {
        match self {
            Alg::Es256 => Some(65),
            Alg::XWing => Some(1216),
            Alg::X25519 => Some(32),
            Alg::Unknown(_) => None,
        }
    }
}

/// A Key as the format writes it: `[alg, pub]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Key<'a> {
    /// The algorithm.
    pub alg: Alg,
    /// The public key's bytes.
    pub public: &'a [u8],
}

/// The SHA-256 of a Key's encoding: how records, commands and statements
/// name a signer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyHash(pub [u8; 32]);

/// The first 16 bytes of a member key's hash: a device's ID.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeviceId(pub [u8; 16]);

/// The first 16 bytes of the group's first root key's hash.
pub type GroupId = DeviceId;

impl KeyHash {
    /// The first 16 bytes: the ID of the device or group whose key it is.
    pub fn id(&self) -> DeviceId {
        let mut id = [0u8; 16];
        id.copy_from_slice(self.0.get(..16).unwrap_or(&[0; 16]));
        DeviceId(id)
    }

    /// A key hash read from 32 bytes.
    pub fn from_slice(b: &[u8]) -> Option<KeyHash> {
        b.try_into().ok().map(KeyHash)
    }
}

impl DeviceId {
    /// An ID read from 16 bytes.
    pub fn from_slice(b: &[u8]) -> Option<DeviceId> {
        b.try_into().ok().map(DeviceId)
    }
}

impl<'a> Key<'a> {
    /// A Key of a known algorithm, without checks.
    pub fn new(alg: Alg, public: &'a [u8]) -> Self {
        Key { alg, public }
    }

    /// Reads a Key from its value: an array of an algorithm number and
    /// bytes. The size and the point are checked by [`Key::check`], since a
    /// key of an unknown algorithm is held, not refused.
    pub fn from_value(v: &Value<'a>) -> Result<Self, Rule> {
        match v.as_array() {
            Some([Value::Uint(alg), Value::Bytes(public)]) => Ok(Key { alg: Alg::from_number(*alg), public }),
            _ => Err(Rule::KEYS_SHAPE),
        }
    }

    /// Checks the key's bytes against its algorithm: the size, and for
    /// ES256 an uncompressed point on the curve. A key of an unknown
    /// algorithm passes: the caller decides whether it holds or refuses.
    pub fn check(&self) -> Result<(), Rule> {
        match self.alg {
            Alg::Es256 => {
                if self.public.len() != 65 || self.public.first() != Some(&0x04) {
                    return Err(Rule::KEYS_ES256);
                }
                p256::ecdsa::VerifyingKey::from_sec1_bytes(self.public).map_err(|_| Rule::KEYS_ES256)?;
                Ok(())
            }
            Alg::XWing if self.public.len() != 1216 => Err(Rule::KEYS_XWING),
            Alg::X25519 if self.public.len() != 32 => Err(Rule::KEYS_X25519),
            _ => Ok(()),
        }
    }

    /// Writes the key into an encoder.
    pub fn write(&self, e: &mut Encoder) {
        e.array(2).uint(self.alg.number()).bytes(self.public);
    }

    /// The key's encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        self.write(&mut e);
        e.finish()
    }

    /// The key as a value.
    pub fn to_value(&self) -> Value<'a> {
        Value::Array(alloc::vec![Value::Uint(self.alg.number()), Value::Bytes(self.public)])
    }

    /// SHA-256 over the key's encoding.
    pub fn hash(&self) -> KeyHash {
        KeyHash(sha256(&[&self.encode()]))
    }

    /// The ID of the device (or group) whose key this is.
    pub fn device_id(&self) -> DeviceId {
        self.hash().id()
    }
}
