// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Encrypting a message for one device: HPKE (RFC 9180) in base mode with
//! X-Wing (ML-KEM-768 and X25519, KEM 0x647a), HKDF-SHA256 and
//! ChaCha20-Poly1305, and a fixed info string. Each device keeps a 32-byte
//! secret; its public key is 1216 bytes. A sealed message is the 1120-byte
//! encapsulated key followed by the ciphertext, which is 16 bytes longer
//! than the message. The same is in Go (internal/seal); both are checked on
//! testdata/interop/seal-go.json and seal-rust.json.

use alloc::vec::Vec;

use chacha20::ChaCha20Rng;
use chacha20::rand_core::SeedableRng;
use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::XWing;
use hpke::{Deserializable, Kem, OpModeR, OpModeS, Serializable};

use crate::error::Error;

/// The size of a device's secret.
pub const SECRET_SIZE: usize = 32;
/// The size of a public key.
pub const PUBLIC_KEY_SIZE: usize = 1216;
/// The size of the encapsulated key at the start of a sealed message.
pub const ENC_SIZE: usize = 1120;
/// How much longer a sealed message is than the message.
pub const OVERHEAD: usize = ENC_SIZE + 16;
/// HPKE's info for every sealed message.
pub const INFO: &[u8] = b"cbb seal v1";

type PrivateKey = <XWing as Kem>::PrivateKey;
type PublicKey = <XWing as Kem>::PublicKey;
type EncappedKey = <XWing as Kem>::EncappedKey;

/// The error of a sealed message that does not open: sealed to another key,
/// with other associated data, or changed on the way.
fn not_open() -> Error {
    Error::msg("seal: the message does not open with this key").answer()
}

fn private_key(secret: &[u8]) -> Result<PrivateKey, Error> {
    if secret.len() != SECRET_SIZE {
        return Err(Error::msg(alloc::format!("seal: a secret is {SECRET_SIZE} bytes, not {}", secret.len())));
    }
    PrivateKey::from_bytes(secret).map_err(|_| Error::msg("seal: cannot read the secret"))
}

fn public_key_of(b: &[u8]) -> Result<PublicKey, Error> {
    if b.len() != PUBLIC_KEY_SIZE {
        return Err(Error::msg(alloc::format!("seal: a public key is {PUBLIC_KEY_SIZE} bytes, not {}", b.len())));
    }
    PublicKey::from_bytes(b).map_err(|_| Error::msg("seal: cannot read the public key"))
}

fn random_seed() -> Result<[u8; 32], Error> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|_| Error::msg("seal: the system has no randomness"))?;
    Ok(seed)
}

/// Makes a new secret.
pub fn generate_secret() -> Result<[u8; SECRET_SIZE], Error> {
    random_seed()
}

/// The public key of a secret.
pub fn public_key(secret: &[u8]) -> Result<Vec<u8>, Error> {
    let k = private_key(secret)?;
    Ok(XWing::sk_to_pk(&k).to_bytes().to_vec())
}

/// Whether b is a public key that seal takes.
pub fn check_public_key(b: &[u8]) -> Result<(), Error> {
    public_key_of(b).map(|_| ())
}

/// Encrypts msg for the holder of public, bound to aad, which is not
/// encrypted but must be the same when the message is opened.
pub fn seal(public: &[u8], aad: &[u8], msg: &[u8]) -> Result<Vec<u8>, Error> {
    seal_with_seed(public, aad, msg, random_seed()?)
}

/// seal with the randomness drawn from seed: for the vectors only, since the
/// same seed twice gives the same encapsulated key.
#[doc(hidden)]
pub fn seal_with_seed(public: &[u8], aad: &[u8], msg: &[u8], seed: [u8; 32]) -> Result<Vec<u8>, Error> {
    let pk = public_key_of(public)?;
    let mut rng = ChaCha20Rng::from_seed(seed);
    let (enc, ct) = hpke::single_shot_seal_with_rng::<ChaCha20Poly1305, HkdfSha256, XWing>(
        &OpModeS::Base,
        &pk,
        INFO,
        msg,
        aad,
        &mut rng,
    )
    .map_err(|_| Error::msg("seal: cannot seal the message"))?;
    let mut out = Vec::new();
    out.try_reserve_exact(ENC_SIZE.saturating_add(ct.len())).map_err(|_| Error::msg("seal: out of memory"))?;
    out.extend_from_slice(&enc.to_bytes());
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypts a message that seal sealed to secret's public key with the same
/// aad.
pub fn open(secret: &[u8], aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, Error> {
    let k = private_key(secret)?;
    if sealed.len() < OVERHEAD {
        return Err(not_open());
    }
    let (enc, ct) = sealed.split_at(ENC_SIZE);
    let enc = EncappedKey::from_bytes(enc).map_err(|_| not_open())?;
    hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, XWing>(&OpModeR::Base, &k, &enc, INFO, ct, aad)
        .map_err(|_| not_open())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::{String, ToString};
    use serde_json::{Value, json};

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| alloc::format!("{x:02x}")).collect()
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    fn dir() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../testdata/interop")
    }

    #[test]
    fn round_trip() {
        let secret = generate_secret().unwrap();
        let public = public_key(&secret).unwrap();
        assert_eq!(public.len(), PUBLIC_KEY_SIZE);
        for msg in [&b""[..], b"x", &[7u8; 5000]] {
            let sealed = seal(&public, b"header", msg).unwrap();
            assert_eq!(sealed.len(), msg.len() + OVERHEAD);
            assert_eq!(open(&secret, b"header", &sealed).unwrap(), msg);
            assert!(open(&secret, b"other", &sealed).is_err());
            assert!(open(&generate_secret().unwrap(), b"header", &sealed).is_err());
        }
        assert!(public_key(&[0u8; 31]).is_err());
        assert!(seal(&public[1..], b"", b"").is_err());
        assert!(open(&secret, b"", &[0u8; OVERHEAD - 1]).is_err());
    }

    /// testdata/interop/seal-rust.json: the same seeds give the same file,
    /// so it is written again (CBB_UPDATE_VECTORS=1) only when the inputs
    /// change.
    fn rust_vectors() -> Value {
        let secret = [0x5au8; SECRET_SIZE];
        let public = public_key(&secret).unwrap();
        let inputs: [(&str, &str, String); 5] = [
            ("empty", "", String::new()),
            ("text", "group a to b id 1", "hello from rust".to_string()),
            ("no associated data", "", "only the message".to_string()),
            ("utf-8", "\u{437}\u{430}\u{433}\u{43e}\u{43b}\u{43e}\u{432}\u{43e}\u{43a}", "\u{442}\u{435}\u{43a}\u{441}\u{442} \u{434}\u{43b}\u{44f} \u{432}\u{441}\u{442}\u{430}\u{432}\u{43a}\u{438} \u{2713}".to_string()),
            ("long", "header", "0123456789abcdef".repeat(256)),
        ];
        let mut cases = Vec::new();
        for (i, (name, aad, msg)) in inputs.iter().enumerate() {
            let sealed = seal_with_seed(&public, aad.as_bytes(), msg.as_bytes(), [i as u8; 32]).unwrap();
            cases.push(json!({"name": name, "secret": hex(&secret), "public": hex(&public),
                "aad": hex(aad.as_bytes()), "msg": hex(msg.as_bytes()), "sealed": hex(&sealed)}));
        }
        let sealed = seal_with_seed(&public, b"header", b"secret text", [0xa5; 32]).unwrap();
        let flip = |i: usize| {
            let mut b = sealed.clone();
            b[i] ^= 1;
            b
        };
        let mut extra = sealed.clone();
        extra.push(0);
        let other = [0x33u8; SECRET_SIZE];
        type Refusal<'a> = (&'a str, &'a [u8], &'a [u8], Vec<u8>);
        let refused: [Refusal; 10] = [
            ("other associated data", &secret, b"headeR", sealed.clone()),
            ("no associated data", &secret, b"", sealed.clone()),
            ("another key", &other, b"header", sealed.clone()),
            ("encapsulated key changed", &secret, b"header", flip(0)),
            ("x25519 share changed", &secret, b"header", flip(ENC_SIZE - 1)),
            ("ciphertext changed", &secret, b"header", flip(ENC_SIZE)),
            ("tag changed", &secret, b"header", flip(sealed.len() - 1)),
            ("cut", &secret, b"header", sealed[..sealed.len() - 1].to_vec()),
            ("shorter than the overhead", &secret, b"header", sealed[..OVERHEAD - 1].to_vec()),
            ("extra byte", &secret, b"header", extra),
        ];
        let refused: Vec<Value> = refused
            .iter()
            .map(|(name, s, aad, b)| json!({"name": name, "secret": hex(s), "aad": hex(aad), "sealed": hex(b)}))
            .collect();
        json!({"info": core::str::from_utf8(INFO).unwrap(), "cases": cases, "refused": refused})
    }

    #[test]
    fn vectors() {
        let rust = rust_vectors();
        let path = dir().join("seal-rust.json");
        if std::env::var("CBB_UPDATE_VECTORS").as_deref() == Ok("1") {
            let mut s = serde_json::to_string_pretty(&rust).unwrap();
            s.push('\n');
            std::fs::write(&path, s).unwrap();
        }
        let written: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(written, rust, "seal-rust.json is not what these seeds give; CBB_UPDATE_VECTORS=1 writes it");
        for name in ["seal-go.json", "seal-rust.json"] {
            let v: Value = serde_json::from_str(&std::fs::read_to_string(dir().join(name)).unwrap()).unwrap();
            assert_eq!(v["info"], core::str::from_utf8(INFO).unwrap());
            let cases = v["cases"].as_array().unwrap();
            let refused = v["refused"].as_array().unwrap();
            assert!(!cases.is_empty() && !refused.is_empty());
            for c in cases {
                let secret = unhex(c["secret"].as_str().unwrap());
                assert_eq!(public_key(&secret).unwrap(), unhex(c["public"].as_str().unwrap()), "{name} {}", c["name"]);
                let got = open(&secret, &unhex(c["aad"].as_str().unwrap()), &unhex(c["sealed"].as_str().unwrap()));
                assert_eq!(got.unwrap(), unhex(c["msg"].as_str().unwrap()), "{name} {}", c["name"]);
            }
            for r in refused {
                let got = open(
                    &unhex(r["secret"].as_str().unwrap()),
                    &unhex(r["aad"].as_str().unwrap()),
                    &unhex(r["sealed"].as_str().unwrap()),
                );
                assert!(got.is_err(), "{name} {} opened", r["name"]);
            }
        }
    }
}
