// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The recovery key as a pair (E-6): K1, ES256 as every other key, and K2,
//! SLH-DSA-SHA2-128s (FIPS 205, algorithm 4 of the registry), both made
//! from one 32-byte recovery secret under two labels, so the sheet and
//! what the user types stay one secret. Every recovery head carries both
//! signatures and both are required; the verifier is the core's one
//! (`crate::slhdsa`), the signer is here.
//!
//! The second signer signs first, over the body; the first signature then
//! covers the body and the SHA-256 of the second (audit Q-1), so a second
//! signature cannot be swapped on the way.

use alloc::vec::Vec;

use sha2::{Digest, Sha256, Sha512};
use slh_dsa::{Sha2_128s, SigningKey};
use zeroize::Zeroize;

use super::key::{ALG_SLH_DSA, Key};
use crate::error::{Error, Result};

/// The label K1's scalar is made under from the recovery secret.
pub const LABEL_K1: &str = "cbb recovery key es256 v1";
/// The label K2's three seeds are made under from the recovery secret;
/// the parameter set is in the label.
pub const LABEL_K2: &str = "cbb recovery key slh-dsa-sha2-128s v1";
/// The context of every SLH-DSA signature on a record: each use of the
/// one verifier passes its own, so a signature of one never stands for
/// another.
pub const CONTEXT_RECORD: &[u8] = b"cbb record v3";
/// The context of the recovery key's second signature on a fetch proof.
pub const CONTEXT_FETCH: &[u8] = b"cbb recovery fetch v3";

/// The stack, in bytes, that verifying one change of root's two
/// signatures needs: measured at 23.8 KiB on riscv32imac (opt-level s) and
/// below 32 KiB on a 64-bit host, where the test
/// `the_stack_a_verify_needs` holds it within a margin. A board sizes the
/// task that verifies from it. Heads are verified one at a time, never
/// recursively over a chain.
pub const VERIFY_STACK: usize = 32 * 1024;

/// K2: the recovery key's SLH-DSA half. Deterministic signing (FIPS 205's
/// randomizer is the public seed), so a head signed twice is one head.
pub struct PqKey(SigningKey<Sha2_128s>);

impl PqKey {
    /// The key of three 16-byte seeds (FIPS 205 `slh_keygen_internal`).
    pub fn from_seeds(sk_seed: &[u8; 16], sk_prf: &[u8; 16], pk_seed: &[u8; 16]) -> PqKey {
        PqKey(SigningKey::slh_keygen_internal(sk_seed, sk_prf, pk_seed))
    }

    /// The public key's 32 bytes.
    pub fn public(&self) -> Vec<u8> {
        self.0.as_ref().to_bytes().to_vec()
    }

    /// The public key as the format writes it: `[4, pub]`.
    pub fn key(&self) -> Key {
        Key { alg: ALG_SLH_DSA, public: self.public() }
    }

    /// The signature of msg under the context ctx (at most 255 bytes).
    pub fn sign(&self, msg: &[u8], ctx: &[u8]) -> Result<Vec<u8>> {
        let sig = self.0.try_sign_with_context(msg, ctx, None).map_err(|_| Error::msg("the context is too long"))?;
        Ok(sig.to_bytes().to_vec())
    }
}

/// The recovery key's two halves from its 32-byte secret: K1's P-256
/// scalar is SHA-256 over [`LABEL_K1`], a zero byte, the secret and a
/// counter byte, the first counter that gives a valid scalar; K2's seeds are
/// the first 48 bytes of SHA-512 over [`LABEL_K2`], a zero byte and the
/// secret, in the order sk_seed, sk_prf, pk_seed.
pub fn recovery_keys(secret: &[u8; 32]) -> Result<(p256::SecretKey, PqKey)> {
    let mut k1 = None;
    for counter in 0u8..=255 {
        let mut h = Sha256::new();
        h.update(LABEL_K1.as_bytes());
        h.update([0]);
        h.update(secret);
        h.update([counter]);
        let mut d: [u8; 32] = h.finalize().into();
        let key = p256::SecretKey::from_bytes(&d.into()).ok();
        d.zeroize();
        if key.is_some() {
            k1 = key;
            break;
        }
    }
    let k1 = k1.ok_or_else(|| Error::msg("no scalar came of the recovery secret"))?;
    let mut h = Sha512::new();
    h.update(LABEL_K2.as_bytes());
    h.update([0]);
    h.update(secret);
    let mut d: [u8; 64] = h.finalize().into();
    let mut seeds = [[0u8; 16]; 3];
    for (s, chunk) in seeds.iter_mut().zip(d.chunks_exact(16)) {
        s.copy_from_slice(chunk);
    }
    let k2 = PqKey::from_seeds(&seeds[0], &seeds[1], &seeds[2]);
    d.zeroize();
    seeds.zeroize();
    Ok((k1, k2))
}

/// Whether sig is K2's signature of msg under ctx.
pub fn verify(k2: &Key, msg: &[u8], sig: &[u8], ctx: &[u8]) -> bool {
    k2.alg == ALG_SLH_DSA && crate::slhdsa::verify(&k2.public, msg, sig, ctx)
}
