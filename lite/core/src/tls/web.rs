// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The provider of provider.rs with what a public web server's certificate
//! needs as well: RSA signatures (PKCS #1 v1.5 in certificates, PSS in the
//! TLS 1.3 handshake) with SHA-256, SHA-384 or SHA-512, and ECDSA on P-384
//! and with SHA-384. The VLESS client (crate::vless) checks the TLS web
//! server in front of a forwarder with it, against the roots of the system.
//!
//! RSA only verifies here: the public key's power of the signature, then
//! the encoding of RFC 8017 compared in full. Every input is public, so
//! nothing needs constant time. The keys are 2048 to 8192 bits, with an odd
//! exponent from 3 to below 2^33, as webpki's other providers take them.

use alloc::vec::Vec;

use crypto_bigint::modular::{BoxedMontyForm, BoxedMontyParams};
use crypto_bigint::{BoxedUint, Odd};
use der::asn1::UintRef;
use der::{Decode, Reader, SliceReader};
use rustls::SignatureScheme;
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm, alg_id};
use sha2::{Digest, Sha256, Sha384, Sha512};

use super::provider::EcdsaP256Sha256;

/// The members' provider that also verifies a public web server.
pub fn provider() -> CryptoProvider {
    CryptoProvider { signature_verification_algorithms: ALGORITHMS, ..super::provider() }
}

static ALGORITHMS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[
        &EcdsaP256Sha256,
        &Ecdsa(Curve::P256, Hash::Sha384),
        &Ecdsa(Curve::P384, Hash::Sha256),
        &Ecdsa(Curve::P384, Hash::Sha384),
        &Rsa(Padding::Pkcs1, Hash::Sha256),
        &Rsa(Padding::Pkcs1, Hash::Sha384),
        &Rsa(Padding::Pkcs1, Hash::Sha512),
        &Rsa(Padding::Pss, Hash::Sha256),
        &Rsa(Padding::Pss, Hash::Sha384),
        &Rsa(Padding::Pss, Hash::Sha512),
    ],
    // TLS 1.3 signs the handshake with ECDSA or RSA-PSS only.
    mapping: &[
        (SignatureScheme::ECDSA_NISTP256_SHA256, &[&EcdsaP256Sha256]),
        (SignatureScheme::ECDSA_NISTP384_SHA384, &[&Ecdsa(Curve::P384, Hash::Sha384)]),
        (SignatureScheme::RSA_PSS_SHA256, &[&RsaPssRsae(Hash::Sha256)]),
        (SignatureScheme::RSA_PSS_SHA384, &[&RsaPssRsae(Hash::Sha384)]),
        (SignatureScheme::RSA_PSS_SHA512, &[&RsaPssRsae(Hash::Sha512)]),
    ],
};

#[derive(Debug, Clone, Copy)]
enum Hash {
    Sha256,
    Sha384,
    Sha512,
}

impl Hash {
    fn len(self) -> usize {
        match self {
            Hash::Sha256 => 32,
            Hash::Sha384 => 48,
            Hash::Sha512 => 64,
        }
    }

    fn digest(self, parts: &[&[u8]]) -> Vec<u8> {
        fn run<D: Digest>(parts: &[&[u8]]) -> Vec<u8> {
            let mut d = D::new();
            for p in parts {
                d.update(p);
            }
            d.finalize().to_vec()
        }
        match self {
            Hash::Sha256 => run::<Sha256>(parts),
            Hash::Sha384 => run::<Sha384>(parts),
            Hash::Sha512 => run::<Sha512>(parts),
        }
    }

    /// The DER of the DigestInfo before the hash (RFC 8017, section 9.2).
    fn digest_info(self) -> &'static [u8] {
        match self {
            Hash::Sha256 => &[
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00,
                0x04, 0x20,
            ],
            Hash::Sha384 => &[
                0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00,
                0x04, 0x30,
            ],
            Hash::Sha512 => &[
                0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00,
                0x04, 0x40,
            ],
        }
    }
}

// ECDSA

#[derive(Debug, Clone, Copy)]
enum Curve {
    P256,
    P384,
}

#[derive(Debug)]
struct Ecdsa(Curve, Hash);

impl SignatureVerificationAlgorithm for Ecdsa {
    fn verify_signature(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), InvalidSignature> {
        use p256::ecdsa::signature::hazmat::PrehashVerifier;
        let prehash = self.1.digest(&[message]);
        let ok = match self.0 {
            Curve::P256 => {
                let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key).map_err(|_| InvalidSignature)?;
                let sig = p256::ecdsa::Signature::from_der(signature).map_err(|_| InvalidSignature)?;
                key.verify_prehash(&prehash, &sig).is_ok()
            }
            Curve::P384 => {
                let key = p384::ecdsa::VerifyingKey::from_sec1_bytes(public_key).map_err(|_| InvalidSignature)?;
                let sig = p384::ecdsa::Signature::from_der(signature).map_err(|_| InvalidSignature)?;
                key.verify_prehash(&prehash, &sig).is_ok()
            }
        };
        if ok { Ok(()) } else { Err(InvalidSignature) }
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        match self.0 {
            Curve::P256 => alg_id::ECDSA_P256,
            Curve::P384 => alg_id::ECDSA_P384,
        }
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        match self.1 {
            Hash::Sha256 => alg_id::ECDSA_SHA256,
            Hash::Sha384 => alg_id::ECDSA_SHA384,
            Hash::Sha512 => alg_id::ECDSA_SHA512,
        }
    }
}

// RSA

#[derive(Debug, Clone, Copy)]
enum Padding {
    Pkcs1,
    Pss,
}

/// RSA in a certificate: the signature algorithm names the padding.
#[derive(Debug)]
struct Rsa(Padding, Hash);

impl SignatureVerificationAlgorithm for Rsa {
    fn verify_signature(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), InvalidSignature> {
        rsa_verify(self.0, self.1, public_key, message, signature)
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::RSA_ENCRYPTION
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        match (self.0, self.1) {
            (Padding::Pkcs1, Hash::Sha256) => alg_id::RSA_PKCS1_SHA256,
            (Padding::Pkcs1, Hash::Sha384) => alg_id::RSA_PKCS1_SHA384,
            (Padding::Pkcs1, Hash::Sha512) => alg_id::RSA_PKCS1_SHA512,
            (Padding::Pss, Hash::Sha256) => alg_id::RSA_PSS_SHA256,
            (Padding::Pss, Hash::Sha384) => alg_id::RSA_PSS_SHA384,
            (Padding::Pss, Hash::Sha512) => alg_id::RSA_PSS_SHA512,
        }
    }
}

/// RSA-PSS in the TLS 1.3 handshake (rsa_pss_rsae_*): an ordinary RSA key.
#[derive(Debug)]
struct RsaPssRsae(Hash);

impl SignatureVerificationAlgorithm for RsaPssRsae {
    fn verify_signature(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), InvalidSignature> {
        rsa_verify(Padding::Pss, self.0, public_key, message, signature)
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::RSA_ENCRYPTION
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        Rsa(Padding::Pss, self.0).signature_alg_id()
    }
}

const MIN_BITS: usize = 2048;
const MAX_BITS: usize = 8192;

/// The RSAPublicKey of RFC 8017, appendix A.1.1: the modulus and the
/// exponent, each without leading zeros.
fn rsa_key(der: &[u8]) -> Result<(&[u8], &[u8]), InvalidSignature> {
    let mut r = SliceReader::new(der).map_err(|_| InvalidSignature)?;
    let key = r
        .sequence(|r| {
            let n = UintRef::decode(r)?;
            let e = UintRef::decode(r)?;
            Ok::<_, der::Error>((n.as_bytes(), e.as_bytes()))
        })
        .map_err(|_| InvalidSignature)?;
    r.finish().map_err(|_| InvalidSignature)?;
    Ok(key)
}

fn bit_len(be: &[u8]) -> usize {
    match be.first() {
        Some(&b) => be.len().saturating_mul(8).saturating_sub(b.leading_zeros() as usize),
        None => 0,
    }
}

fn rsa_verify(padding: Padding, hash: Hash, key: &[u8], message: &[u8], sig: &[u8]) -> Result<(), InvalidSignature> {
    let (n, e) = rsa_key(key)?;
    let mod_bits = bit_len(n);
    if !(MIN_BITS..=MAX_BITS).contains(&mod_bits) {
        return Err(InvalidSignature);
    }
    // An odd exponent of 2 to 33 bits: 3 at the least, below 2^33.
    if !(2..=33).contains(&bit_len(e)) || e.last().is_none_or(|b| b & 1 == 0) {
        return Err(InvalidSignature);
    }
    // The signature is exactly as long as the modulus, and less than it.
    if sig.len() != n.len() || sig >= n {
        return Err(InvalidSignature);
    }
    let em = rsa_power(n, e, sig)?;
    let ok = match padding {
        Padding::Pkcs1 => pkcs1_matches(hash, &em, message),
        Padding::Pss => pss_matches(hash, &em, mod_bits, message),
    };
    if ok { Ok(()) } else { Err(InvalidSignature) }
}

/// sig^e mod n, big-endian in as many bytes as n.
fn rsa_power(n: &[u8], e: &[u8], sig: &[u8]) -> Result<Vec<u8>, InvalidSignature> {
    let bits = u32::try_from(n.len()).ok().and_then(|l| l.checked_mul(8)).ok_or(InvalidSignature)?;
    let modulus = BoxedUint::from_be_slice(n, bits).map_err(|_| InvalidSignature)?;
    let modulus = Odd::new(modulus).into_option().ok_or(InvalidSignature)?;
    let params = BoxedMontyParams::new_vartime(modulus);
    let s = BoxedUint::from_be_slice(sig, bits).map_err(|_| InvalidSignature)?;
    let exponent = BoxedUint::from_be_slice_vartime(e);
    let m = BoxedMontyForm::new(s, &params).pow(&exponent).retrieve().to_be_bytes();
    // The power is less than n, so the bytes before the last k are zeros.
    let (zeros, em) = m.split_at_checked(m.len().saturating_sub(n.len())).ok_or(InvalidSignature)?;
    if em.len() != n.len() || zeros.iter().any(|&b| b != 0) {
        return Err(InvalidSignature);
    }
    Ok(em.to_vec())
}

/// EMSA-PKCS1-v1_5 (RFC 8017, section 9.2), built and compared in full:
/// 00 01, at least eight FF, 00, the DigestInfo and the hash.
fn pkcs1_matches(hash: Hash, em: &[u8], message: &[u8]) -> bool {
    let info = hash.digest_info();
    let digest = hash.digest(&[message]);
    let t_len = info.len().saturating_add(digest.len());
    let ps_len = match em.len().checked_sub(t_len.saturating_add(3)) {
        Some(l) if l >= 8 => l,
        _ => return false,
    };
    let mut want = Vec::with_capacity(em.len());
    want.extend_from_slice(&[0x00, 0x01]);
    want.extend(core::iter::repeat_n(0xff, ps_len));
    want.push(0x00);
    want.extend_from_slice(info);
    want.extend_from_slice(&digest);
    want == em
}

/// EMSA-PSS-VERIFY (RFC 8017, section 9.1.2) with MGF1 of the same hash
/// and a salt as long as the hash, which TLS 1.3 requires (RFC 8446,
/// section 4.2.3) and webpki's PSS identifiers name.
fn pss_matches(hash: Hash, em: &[u8], mod_bits: usize, message: &[u8]) -> bool {
    let em_bits = mod_bits.saturating_sub(1);
    let em_len = em_bits.div_ceil(8);
    // With a modulus of 8k+1 bits the encoding is a byte shorter than it.
    let em = match (em.len().checked_sub(em_len), em.split_first()) {
        (Some(0), _) => em,
        (Some(1), Some((0, rest))) => rest,
        _ => return false,
    };
    let h_len = hash.len();
    if em_len < h_len.saturating_mul(2).saturating_add(2) {
        return false;
    }
    let Some((0xbc, body)) = em.split_last() else {
        return false;
    };
    let Some((masked, h)) = body.split_at_checked(body.len().saturating_sub(h_len)) else {
        return false;
    };
    // The bits of the first byte above emBits are zeros.
    let top = em_len.saturating_mul(8).saturating_sub(em_bits);
    let top_mask = u8::MAX.checked_shr(top as u32).unwrap_or(0);
    if masked.first().is_none_or(|&b| b & !top_mask != 0) {
        return false;
    }
    let mut db = mgf1(hash, h, masked.len());
    for (d, m) in db.iter_mut().zip(masked) {
        *d ^= m;
    }
    if let Some(first) = db.first_mut() {
        *first &= top_mask;
    }
    // DB is zeros, 01, then the salt.
    let Some((zeros, rest)) = db.split_at_checked(masked.len().saturating_sub(h_len).saturating_sub(1)) else {
        return false;
    };
    let Some((0x01, salt)) = rest.split_first() else {
        return false;
    };
    if zeros.iter().any(|&b| b != 0) || salt.len() != h_len {
        return false;
    }
    let m_hash = hash.digest(&[message]);
    hash.digest(&[&[0u8; 8], &m_hash, salt]) == h
}

/// MGF1 (RFC 8017, appendix B.2.1).
fn mgf1(hash: Hash, seed: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len.saturating_add(hash.len()));
    let mut counter = 0u32;
    while out.len() < len {
        out.extend_from_slice(&hash.digest(&[seed, &counter.to_be_bytes()]));
        counter = counter.wrapping_add(1);
    }
    out.truncate(len);
    out
}

#[cfg(test)]
mod tests {
    use alloc::string::String;
    use alloc::vec;

    use super::*;

    #[derive(serde::Deserialize)]
    struct Vector {
        alg: String,
        key: String,
        msg: String,
        sig: String,
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    fn algorithm(name: &str) -> &'static dyn SignatureVerificationAlgorithm {
        match name {
            "rsa_pkcs1_sha256" => &Rsa(Padding::Pkcs1, Hash::Sha256),
            "rsa_pkcs1_sha384" => &Rsa(Padding::Pkcs1, Hash::Sha384),
            "rsa_pkcs1_sha512" => &Rsa(Padding::Pkcs1, Hash::Sha512),
            "rsa_pss_sha256" => &RsaPssRsae(Hash::Sha256),
            "rsa_pss_sha384" => &RsaPssRsae(Hash::Sha384),
            "rsa_pss_sha512" => &RsaPssRsae(Hash::Sha512),
            "ecdsa_p256_sha256" => &EcdsaP256Sha256,
            "ecdsa_p256_sha384" => &Ecdsa(Curve::P256, Hash::Sha384),
            "ecdsa_p384_sha256" => &Ecdsa(Curve::P384, Hash::Sha256),
            "ecdsa_p384_sha384" => &Ecdsa(Curve::P384, Hash::Sha384),
            _ => panic!("unknown algorithm {name}"),
        }
    }

    /// web-vectors.json: signatures made with Go's crypto/rsa and
    /// crypto/ecdsa (keys of 2048, 2049, 3072 and 4096 bits, PSS with a
    /// salt as long as the hash). Each verifies, and stops verifying when
    /// the message, the signature or the key changes by a bit.
    #[test]
    fn verifies_what_go_signed() {
        let vectors: Vec<Vector> = serde_json::from_str(include_str!("web-vectors.json")).unwrap();
        assert_eq!(vectors.len(), 28);
        for v in &vectors {
            let alg = algorithm(&v.alg);
            let (key, msg, sig) = (hex(&v.key), hex(&v.msg), hex(&v.sig));
            assert!(alg.verify_signature(&key, &msg, &sig).is_ok(), "{} does not verify", v.alg);
            let mut m = msg.clone();
            m[0] ^= 1;
            assert!(alg.verify_signature(&key, &m, &sig).is_err(), "{}: another message verifies", v.alg);
            let mut s = sig.clone();
            let last = s.len() - 1;
            s[last] ^= 1;
            assert!(alg.verify_signature(&key, &msg, &s).is_err(), "{}: another signature verifies", v.alg);
            let mut k = key.clone();
            k[20] ^= 1;
            assert!(alg.verify_signature(&k, &msg, &sig).is_err(), "{}: another key verifies", v.alg);
        }
    }

    /// A PKCS #1 signature does not pass as PSS, nor the other way round,
    /// nor with another hash.
    #[test]
    fn rsa_keeps_padding_and_hash_apart() {
        let vectors: Vec<Vector> = serde_json::from_str(include_str!("web-vectors.json")).unwrap();
        for v in vectors.iter().filter(|v| v.alg.starts_with("rsa_")) {
            let (key, msg, sig) = (hex(&v.key), hex(&v.msg), hex(&v.sig));
            for other in ["rsa_pkcs1_sha256", "rsa_pkcs1_sha512", "rsa_pss_sha256", "rsa_pss_sha512"] {
                if other != v.alg {
                    assert!(algorithm(other).verify_signature(&key, &msg, &sig).is_err(), "{} as {other}", v.alg);
                }
            }
        }
    }

    /// Keys outside the sizes, an even or tiny exponent, and a signature
    /// not exactly as long as the modulus are refused.
    #[test]
    fn rsa_refuses_odd_keys() {
        fn key(n: &[u8], e: &[u8]) -> Vec<u8> {
            fn int(b: &[u8]) -> Vec<u8> {
                let mut v = Vec::from(b);
                if v[0] & 0x80 != 0 {
                    v.insert(0, 0);
                }
                let mut out = vec![0x02];
                push_len(&mut out, v.len());
                out.extend(v);
                out
            }
            fn push_len(out: &mut Vec<u8>, len: usize) {
                if len < 128 {
                    out.push(len as u8);
                } else if len < 256 {
                    out.extend([0x81, len as u8]);
                } else {
                    out.extend([0x82, (len >> 8) as u8, len as u8]);
                }
            }
            let body = [int(n), int(e)].concat();
            let mut out = vec![0x30];
            push_len(&mut out, body.len());
            out.extend(body);
            out
        }
        let alg = Rsa(Padding::Pkcs1, Hash::Sha256);
        let mut small = vec![0xc5u8; 128];
        small[127] = 0x01;
        assert!(alg.verify_signature(&key(&small, &[1, 0, 1]), b"m", &[1; 128]).is_err());
        let mut n = vec![0xc5u8; 256];
        n[255] = 0x01;
        assert!(alg.verify_signature(&key(&n, &[1, 0, 0]), b"m", &[1; 256]).is_err());
        assert!(alg.verify_signature(&key(&n, &[1]), b"m", &[1; 256]).is_err());
        assert!(alg.verify_signature(&key(&n, &[1, 0, 1]), b"m", &[1; 255]).is_err());
        assert!(alg.verify_signature(&key(&n, &[1, 0, 1]), b"m", &n).is_err());
    }
}
