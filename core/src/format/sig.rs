// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Signatures (format sections 2, 3.1 and 14): ES256 over
//! `label ‖ 0x00 ‖ data`, 64 bytes `r ‖ s` with 1 ≤ r < n and a low
//! 1 ≤ s ≤ (n − 1)/2, so that each signature has one form.

use alloc::vec::Vec;

use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};

use super::Rule;

/// Records.
pub const LABEL_RECORD: &str = "cbb record v3";
/// Keys statements.
pub const LABEL_KEYS: &str = "cbb keys v1";
/// Commands, and the associated data of their sealed orders.
pub const LABEL_COMMAND: &str = "cbb command v3";
/// Grants.
pub const LABEL_GRANT: &str = "cbb grant v1";
/// Server credentials.
pub const LABEL_CREDENTIAL: &str = "cbb credential v2";
/// Server cards.
pub const LABEL_SERVER_CARD: &str = "cbb server card v1";
/// Beacons.
pub const LABEL_BEACON: &str = "cbb beacon v1";
/// The admin key's proof at pairing.
pub const LABEL_ADMIN_POP: &str = "cbb admin pop v1";
/// The copy header hash `h`.
pub const LABEL_COPY: &str = "cbb copy v2";
/// The copy signature.
pub const LABEL_COPY_SIG: &str = "cbb copy sig v2";
/// HKDF info of the payload key.
pub const LABEL_COPY_PAYLOAD: &str = "cbb copy payload v2";
/// HKDF info of the blob key.
pub const LABEL_COPY_BLOB: &str = "cbb copy blob v2";
/// HKDF info of the key commitment.
pub const LABEL_COPY_COMMIT: &str = "cbb copy commit v2";
/// The set digest.
pub const LABEL_SET: &str = "cbb set v3";

/// The order n of P-256, big-endian.
const N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbc, 0xe6, 0xfa,
    0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];
/// (n − 1) / 2, big-endian: the highest low `s`.
const HALF_N: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xde, 0x73, 0x7d,
    0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8,
];

/// The signed message: `label ‖ 0x00 ‖ data`.
pub fn message(label: &str, data: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(label.len().saturating_add(1).saturating_add(data.len()));
    m.extend_from_slice(label.as_bytes());
    m.push(0);
    m.extend_from_slice(data);
    m
}

/// Checks the form of a signature: 64 bytes, r and s in range, s low.
pub fn check_form(sig: &[u8]) -> Result<(), Rule> {
    let (Some(r), Some(s)) = (sig.get(..32), sig.get(32..)) else {
        return Err(Rule::SIG_SIZE);
    };
    if sig.len() != 64 {
        return Err(Rule::SIG_SIZE);
    }
    let zero = [0u8; 32];
    if r == zero || s == zero || r >= N.as_slice() {
        return Err(Rule::SIG_RANGE);
    }
    if s > HALF_N.as_slice() {
        return Err(Rule::SIG_LOW_S);
    }
    Ok(())
}

/// Verifies an ES256 signature of the profile by the uncompressed point
/// public over `label ‖ 0x00 ‖ data`.
pub fn verify_es256(public: &[u8], label: &str, data: &[u8], sig: &[u8]) -> Result<(), Rule> {
    check_form(sig)?;
    let key = VerifyingKey::from_sec1_bytes(public).map_err(|_| Rule::SIG_VERIFY)?;
    let sig = Signature::from_slice(sig).map_err(|_| Rule::SIG_RANGE)?;
    key.verify(&message(label, data), &sig).map_err(|_| Rule::SIG_VERIFY)
}

/// Signs `label ‖ 0x00 ‖ data` with key: RFC 6979, then the low `s`.
pub fn sign_es256(key: &SigningKey, label: &str, data: &[u8]) -> [u8; 64] {
    let sig: Signature = key.sign(&message(label, data));
    let sig = sig.normalize_s();
    let mut out = [0u8; 64];
    out.copy_from_slice(&sig.to_bytes());
    out
}

/// The uncompressed point of a signing key, 65 bytes.
pub fn public_point(key: &SigningKey) -> [u8; 65] {
    let mut out = [0u8; 65];
    out.copy_from_slice(VerifyingKey::from(key).to_sec1_point(false).as_bytes());
    out
}
