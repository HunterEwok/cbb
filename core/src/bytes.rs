// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Bytes as the core writes and makes them: hex, SHA-256, base64 for JSON
//! (Go's encoding of []byte) and random bytes from the platform.

use alloc::format;
use alloc::string::String;

use sha2::{Digest, Sha256};

/// Random bytes from the platform. A platform without randomness cannot
/// make keys or IDs at all, so that stops the program instead of going on.
#[allow(clippy::expect_used, reason = "no randomness means no keys; there is nothing to go on with")]
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).expect("the system has no randomness");
    b
}

/// b in lowercase hex.
pub fn hex(b: &[u8]) -> String {
    b.iter().map(|c| format!("{c:02x}")).collect()
}

/// SHA-256 over b.
pub fn sha256(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

/// Serde helpers for byte strings as standard base64, Go's encoding of
/// []byte in JSON.
pub mod b64 {
    use alloc::string::String;
    use alloc::vec::Vec;
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(b: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(b))
    }

    /// Standard base64 with padding.
    pub fn encode(b: &[u8]) -> String {
        STANDARD.encode(b)
    }

    /// The bytes of standard base64 with padding.
    pub fn decode_str(s: &str) -> Option<Vec<u8>> {
        STANDARD.decode(s).ok()
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = Option::<String>::deserialize(d)?.unwrap_or_default();
        STANDARD.decode(s).map_err(serde::de::Error::custom)
    }

    pub mod opt {
        use super::*;

        pub fn serialize<S: Serializer>(b: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
            match b {
                Some(b) => s.serialize_str(&STANDARD.encode(b)),
                None => s.serialize_none(),
            }
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
            match Option::<String>::deserialize(d)? {
                Some(s) => STANDARD.decode(s).map(Some).map_err(serde::de::Error::custom),
                None => Ok(None),
            }
        }
    }

    /// A secret in base64, read into a buffer wiped when dropped; the
    /// base64 text is wiped as well.
    pub mod secret {
        use super::*;
        use zeroize::{Zeroize, Zeroizing};

        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Zeroizing<Vec<u8>>, D::Error> {
            let mut s = Option::<String>::deserialize(d)?.unwrap_or_default();
            let b = STANDARD.decode(&s).map(Zeroizing::new).map_err(serde::de::Error::custom);
            s.zeroize();
            b
        }

        /// The same for an optional secret.
        pub mod opt {
            use super::*;

            pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Zeroizing<Vec<u8>>>, D::Error> {
                match Option::<String>::deserialize(d)? {
                    Some(mut s) => {
                        let b = STANDARD.decode(&s).map(|b| Some(Zeroizing::new(b))).map_err(serde::de::Error::custom);
                        s.zeroize();
                        b
                    }
                    None => Ok(None),
                }
            }
        }
    }

    pub mod list {
        use super::*;
        use serde::ser::SerializeSeq;

        pub fn serialize<S: Serializer>(v: &[Vec<u8>], s: S) -> Result<S::Ok, S::Error> {
            let mut seq = s.serialize_seq(Some(v.len()))?;
            for b in v {
                seq.serialize_element(&STANDARD.encode(b))?;
            }
            seq.end()
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Vec<u8>>, D::Error> {
            let v = Option::<Vec<String>>::deserialize(d)?.unwrap_or_default();
            v.into_iter().map(|s| STANDARD.decode(s).map_err(serde::de::Error::custom)).collect()
        }
    }

    pub mod hashes {
        use super::*;
        use serde::ser::SerializeSeq;

        pub fn serialize<S: Serializer>(v: &[[u8; 32]], s: S) -> Result<S::Ok, S::Error> {
            let mut seq = s.serialize_seq(Some(v.len()))?;
            for b in v {
                seq.serialize_element(&STANDARD.encode(b))?;
            }
            seq.end()
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<[u8; 32]>, D::Error> {
            let v = Option::<Vec<String>>::deserialize(d)?.unwrap_or_default();
            v.into_iter()
                .map(|s| {
                    let raw = STANDARD.decode(s).map_err(serde::de::Error::custom)?;
                    raw.try_into().map_err(|_| serde::de::Error::custom("a key hash is not 32 bytes"))
                })
                .collect()
        }
    }

    pub mod opt_hash {
        use super::*;

        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; 32]>, D::Error> {
            match Option::<String>::deserialize(d)? {
                Some(s) => {
                    let raw = STANDARD.decode(s).map_err(serde::de::Error::custom)?;
                    raw.try_into().map(Some).map_err(|_| serde::de::Error::custom("a key hash is not 32 bytes"))
                }
                None => Ok(None),
            }
        }
    }
}
