// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The signed envelope (format section 3.1): `[body, sig]`, or
//! `[body, sig, sig2]` exactly when the body names `signer2` (field 8).
//! The body is the encoding of the object's map, kept as bytes so that it is
//! signed and passed on unchanged.

use alloc::vec::Vec;

use p256::ecdsa::SigningKey;

use super::cbor::{self, Encoder, Value};
use super::{Rule, sha256, sig};

/// The body's field of its type.
const FIELD_TYPE: u16 = 1;
/// The body's field of the signer: a key hash, or a Key in a credential.
pub const FIELD_SIGNER: u16 = 3;
/// The body's field naming a second signer: a recovery head's K2 (E-6),
/// room elsewhere in 0.6.
pub const FIELD_SIGNER2: u16 = 8;
/// The largest second signature: room for a later algorithm's, a
/// post-quantum one among them. Its length is not fixed at 64, and it is
/// outside the record's ID, so a record's size is counted from its body.
pub const MAX_SIG2: usize = 4096;
/// The largest second signature of a recovery head (record type 13): the
/// recovery key's K2 signs every head (E-6), an SLH-DSA-SHA2-128s
/// signature of 7856 bytes, with room for a larger parameter set.
pub const MAX_SIG2_HEAD: usize = 32 * 1024;
/// The record type of a recovery head, the one body whose second signature
/// may reach [`MAX_SIG2_HEAD`].
const TYPE_RECOVERY_HEAD: u64 = 13;

/// An envelope read and checked for its form: the profile on the envelope
/// and the body, its shape, and the body a map. The signature is checked by
/// [`Envelope::verify`] once the caller found the signer's key.
#[derive(Clone, Debug)]
pub struct Envelope<'a> {
    /// The body's bytes, as signed.
    pub body: &'a [u8],
    /// The signature of the body's signer.
    pub sig: &'a [u8],
    /// The second signature, present exactly when the body has `signer2`.
    pub sig2: Option<&'a [u8]>,
    /// The body read: a map.
    pub map: Value<'a>,
}

impl<'a> Envelope<'a> {
    /// Reads an envelope from its encoding, with no ceiling on its size.
    pub fn parse(b: &'a [u8]) -> Result<Self, Rule> {
        Self::from_value(&cbor::decode(b)?)
    }

    /// Reads an envelope whose encoding is at most max bytes (the ceilings
    /// of section 13 are on the body; the envelope adds a few bytes and the
    /// signatures).
    pub fn parse_limited(b: &'a [u8], max_body: usize) -> Result<Self, Rule> {
        // A body of max bytes takes at most a 9-byte head; the signature is
        // 64 bytes with its head, a second one at most MAX_SIG2_HEAD with
        // its 3-byte head; the array head is one byte.
        if b.len() > max_body.saturating_add(1 + 9 + 66 + 3 + MAX_SIG2_HEAD) {
            return Err(Rule::ENV_SIZE);
        }
        let e = Self::parse(b)?;
        if e.body.len() > max_body {
            return Err(Rule::ENV_SIZE);
        }
        Ok(e)
    }

    /// Reads an envelope already read as a value (an element of a message
    /// or a list).
    pub fn from_value(v: &Value<'a>) -> Result<Self, Rule> {
        let (body, sig, sig2) = match v.as_array() {
            Some([Value::Bytes(b), Value::Bytes(s)]) => (*b, *s, None),
            Some([Value::Bytes(b), Value::Bytes(s), Value::Bytes(s2)]) => (*b, *s, Some(*s2)),
            _ => return Err(Rule::ENV_SHAPE),
        };
        let map = cbor::decode(body)?;
        if map.as_map().is_none() {
            return Err(Rule::ENV_SHAPE);
        }
        if map.get(FIELD_SIGNER2).is_some() != sig2.is_some() {
            return Err(Rule::ENV_SHAPE);
        }
        let head = map.get(FIELD_TYPE).and_then(Value::as_uint) == Some(TYPE_RECOVERY_HEAD);
        let max = if head { MAX_SIG2_HEAD } else { MAX_SIG2 };
        if sig2.is_some_and(|s| s.len() > max) {
            return Err(Rule::ENV_SIG2);
        }
        Ok(Envelope { body, sig, sig2, map })
    }

    /// The body's `signer` field.
    pub fn signer(&self) -> Option<&Value<'a>> {
        self.map.get(FIELD_SIGNER)
    }

    /// Verifies the first signature by the uncompressed point public under
    /// the kind's label. In 0.6 nobody checks `sig2`.
    pub fn verify(&self, public: &[u8], label: &str) -> Result<(), Rule> {
        sig::verify_es256(public, label, self.body, self.sig)
    }

    /// The ID of the body: SHA-256 over its bytes.
    pub fn id(&self) -> [u8; 32] {
        body_id(self.body)
    }
}

/// The ID of a record, statement or credential: SHA-256 over the body.
pub fn body_id(body: &[u8]) -> [u8; 32] {
    sha256(&[body])
}

/// Writes an envelope of a body and its signatures.
pub fn write(body: &[u8], sig: &[u8], sig2: Option<&[u8]>) -> Vec<u8> {
    let mut e = Encoder::new();
    e.array(if sig2.is_some() { 3 } else { 2 }).bytes(body).bytes(sig);
    if let Some(s2) = sig2 {
        e.bytes(s2);
    }
    e.finish()
}

/// Signs body under label and writes the envelope `[body, sig]`.
pub fn sign(key: &SigningKey, label: &str, body: &[u8]) -> Vec<u8> {
    write(body, &sig::sign_es256(key, label, body), None)
}
