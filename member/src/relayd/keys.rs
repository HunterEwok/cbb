// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The relay's own keys, as Go's relay.LoadKeys keeps them: the TLS key of
//! the registrations, which members pin, and the WireGuard key of the
//! tunnels, which the registration gives them, in one PEM file, the one file
//! the relay keeps: nothing about the groups is ever written.

use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use p256::ecdsa::{Signature, VerifyingKey, signature::Signer};

use crate::certs;
use crate::error::{Error, Result};

/// The PEM type of the WireGuard key in the key file. It does not end in
/// "PRIVATE KEY", so a TLS key's parser never takes it.
const WG_BLOCK: &str = "CBB WIREGUARD KEY";

/// The relay's keys.
pub struct Keys {
    /// Its certificate, DER, and the PKCS #8 P-256 key of it.
    pub cert: Vec<u8>,
    pub key: Vec<u8>,
    /// Its WireGuard private key.
    pub wireguard: [u8; 32],
}

impl Keys {
    /// Makes new keys: a self-signed P-256 certificate, which only its pin
    /// names, and a WireGuard key.
    pub fn new() -> Result<Keys> {
        let der = cbb_core::identity::new_key()?;
        let key = cbb_core::identity::signing_key(&der)?;
        let point = VerifyingKey::from(&key).to_sec1_point(false);
        let cert = certs::server_cert_by(point.as_bytes(), &mut |tbs| {
            let sig: Signature = key.sign(tbs);
            Ok(sig.to_der().as_bytes().to_vec())
        })?;
        let mut wireguard = certs::random_bytes::<32>();
        // Clamped as an X25519 private key, as WireGuard's are.
        wireguard[0] &= 248;
        wireguard[31] = (wireguard[31] & 127) | 64;
        Ok(Keys { cert, key: der, wireguard })
    }

    /// The pin of the relay's key, which members are given with its
    /// address: the SHA-256 of its SubjectPublicKeyInfo, in base64.
    pub fn pin(&self) -> Result<String> {
        let c = certs::Cert::parse(&self.cert)?;
        Ok(STANDARD.encode(c.key_hash()))
    }

    /// The keys as the key file holds them.
    fn to_pem(&self) -> String {
        [("PRIVATE KEY", &self.key[..]), ("CERTIFICATE", &self.cert[..]), (WG_BLOCK, &self.wireguard[..])]
            .iter()
            .map(|(t, b)| pem(t, b))
            .collect()
    }

    /// Reads the keys from a key file.
    fn from_pem(data: &str) -> Result<Keys> {
        let (mut key, mut cert, mut wg) = (None, None, None);
        for (t, b) in blocks(data)? {
            match t.as_str() {
                "PRIVATE KEY" if key.is_none() => key = Some(b),
                "CERTIFICATE" if cert.is_none() => cert = Some(b),
                WG_BLOCK if b.len() == 32 => wg = b.try_into().ok(),
                _ => {}
            }
        }
        let (Some(key), Some(cert)) = (key, cert) else {
            return Err(Error::msg("it holds no key and certificate"));
        };
        let signing = cbb_core::identity::signing_key(&key)?;
        let c = certs::Cert::parse(&cert)?;
        if c.public_key() != VerifyingKey::from(&signing).to_sec1_point(false).as_bytes() {
            return Err(Error::msg("its key is not the one of its certificate"));
        }
        let wireguard: [u8; 32] = wg.ok_or_else(|| Error::msg("no WireGuard key"))?;
        if wireguard == [0; 32] {
            return Err(Error::msg("no WireGuard key"));
        }
        Ok(Keys { cert, key, wireguard })
    }

    /// Reads the keys from path, and makes them first if the file does not
    /// exist.
    pub fn load(path: &Path) -> Result<Keys> {
        match std::fs::read_to_string(path) {
            Ok(data) => Keys::from_pem(&data).map_err(|e| Error::msg(format!("{}: {e}", path.display()))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let k = Keys::new()?;
                if let Some(dir) = path.parent() {
                    std::fs::create_dir_all(dir)
                        .map_err(|e| Error::with(format!("cannot make {}", dir.display()), e))?;
                }
                crate::files::write_atomic(path, k.to_pem().as_bytes(), 0o600)?;
                Ok(k)
            }
            Err(e) => Err(Error::with(format!("cannot read {}", path.display()), e)),
        }
    }
}

fn pem(t: &str, b: &[u8]) -> String {
    let body = STANDARD.encode(b);
    let lines: Vec<&str> = body.as_bytes().chunks(64).map(|c| std::str::from_utf8(c).unwrap_or("")).collect();
    format!("-----BEGIN {t}-----\n{}\n-----END {t}-----\n", lines.join("\n"))
}

/// The PEM blocks of data, with their types.
fn blocks(data: &str) -> Result<Vec<(String, Vec<u8>)>> {
    let mut out = Vec::new();
    let mut cur: Option<(String, String)> = None;
    for line in data.lines().map(str::trim) {
        if let Some(t) = line.strip_prefix("-----BEGIN ").and_then(|l| l.strip_suffix("-----")) {
            cur = Some((t.to_string(), String::new()));
        } else if let Some(t) = line.strip_prefix("-----END ").and_then(|l| l.strip_suffix("-----")) {
            match cur.take() {
                Some((open, body)) if open == t => {
                    let b = STANDARD.decode(body).map_err(|_| Error::msg(format!("a {t} block is not base64")))?;
                    out.push((open, b));
                }
                _ => return Err(Error::msg("a PEM block does not end")),
            }
        } else if let Some((_, body)) = cur.as_mut() {
            body.push_str(line);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn made_once_then_read() {
        let dir = std::env::temp_dir().join(format!("cbb-relay-keys-{}", certs::random_id()));
        let path = dir.join("relay.pem");
        let k = Keys::load(&path).unwrap();
        let again = Keys::load(&path).unwrap();
        assert_eq!((&k.cert, &k.key, k.wireguard), (&again.cert, &again.key, again.wireguard));
        assert_eq!(k.pin().unwrap().len(), 44);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("CBB WIREGUARD KEY") && !text.contains("WIREGUARD PRIVATE KEY"));
        std::fs::write(
            &path,
            text.replace("-----BEGIN CBB WIREGUARD KEY-----", "-----BEGIN OTHER-----")
                .replace("-----END CBB WIREGUARD KEY-----", "-----END OTHER-----"),
        )
        .unwrap();
        assert!(Keys::load(&path).is_err(), "a file without a WireGuard key is taken");
        let _ = std::fs::remove_dir_all(dir);
    }
}
