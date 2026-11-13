// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! SLH-DSA-SHA2-128s (FIPS 205), pure, as the core's one post-quantum
//! signature verifier: the second half of the release files' signatures
//! and of the recovery key. Each use passes its own context, so that a signature of one never
//! stands for the other.

use slh_dsa::{Sha2_128s, Signature, VerifyingKey};

/// The size of a public key.
pub const PUBLIC_SIZE: usize = 32;
/// The size of a signature.
pub const SIG_SIZE: usize = 7856;

/// The SubjectPublicKeyInfo of a key up to its 32 bytes (the OID
/// 2.16.840.1.101.3.4.3.20, no parameters).
pub const SPKI_PREFIX: [u8; 18] =
    [0x30, 0x30, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x14, 0x03, 0x21, 0x00];

/// The 32 bytes of the key in spki, a SubjectPublicKeyInfo.
pub fn from_spki(spki: &[u8]) -> Option<&[u8]> {
    spki.strip_prefix(&SPKI_PREFIX[..]).filter(|k| k.len() == PUBLIC_SIZE)
}

/// Whether sig is public's signature of msg under the context ctx (at most
/// 255 bytes).
pub fn verify(public: &[u8], msg: &[u8], sig: &[u8], ctx: &[u8]) -> bool {
    if public.len() != PUBLIC_SIZE || sig.len() != SIG_SIZE {
        return false;
    }
    let Ok(key) = VerifyingKey::<Sha2_128s>::try_from(public) else { return false };
    let Ok(sig) = Signature::<Sha2_128s>::try_from(sig) else { return false };
    key.try_verify_with_context(msg, ctx, &sig).is_ok()
}
