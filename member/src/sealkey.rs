// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The member's secret for sealed messages (docs/protocol.md, section 15,
//! "Sealed commands"), in seal.json next to its identity as the full
//! member's file keeps it without a TPM. Its public key goes in the hello,
//! and a root records it in this member's device record, so that commands
//! for it are sealed to it.

use std::io;
use std::path::Path;
use std::sync::OnceLock;

use cbb_core::seal;
use serde::{Deserialize, Serialize};

use crate::certs::b64;
use crate::error::{Context, Error, Result};
use crate::files;

/// The file next to the identity that keeps the secret.
pub const FILE_NAME: &str = "seal.json";

#[derive(Serialize, Deserialize)]
struct File {
    v: i64,
    #[serde(with = "b64")]
    secret: Vec<u8>,
}

/// The secret and its public key, once the service loaded them.
static KEYS: OnceLock<(Vec<u8>, Vec<u8>)> = OnceLock::new();

/// Reads dir/seal.json, making it on first use, and returns the secret.
pub fn load(dir: &Path) -> Result<Vec<u8>> {
    let path = dir.join(FILE_NAME);
    let data = match std::fs::read(&path) {
        Ok(d) => d,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let secret = seal::generate_secret().map_err(|e| e.context("cannot make a key for sealed messages"))?;
            let f = File { v: 1, secret: secret.to_vec() };
            let data = serde_json::to_vec_pretty(&f).context("cannot encode the key for sealed messages")?;
            files::write_atomic(&path, &data, 0o600)?;
            return Ok(f.secret);
        }
        Err(e) => return Err(Error::with(format!("cannot read {}", path.display()), e)),
    };
    let f: File = serde_json::from_slice(&data).context(format!("{} is damaged", path.display()))?;
    if f.v != 1 {
        return Err(Error::msg(format!("{} is of unknown version {}", path.display(), f.v)));
    }
    if seal::public_key(&f.secret).is_err() {
        return Err(Error::msg(format!(
            "{} is damaged: the secret is not {} bytes",
            path.display(),
            seal::SECRET_SIZE
        )));
    }
    Ok(f.secret)
}

/// Keeps the secret for the rest of the run: the hello offers its public
/// key, and commands sealed to it open with it.
pub fn set(secret: Vec<u8>) -> Result<()> {
    let public = seal::public_key(&secret).map_err(|e| e.context("the key for sealed messages"))?;
    let _ = KEYS.set((secret, public));
    Ok(())
}

/// The public key the hello offers, once the service loaded the secret.
pub fn public() -> Option<&'static [u8]> {
    KEYS.get().map(|(_, p)| p.as_slice())
}

/// The secret that opens commands sealed to this member.
pub fn secret() -> Option<&'static [u8]> {
    KEYS.get().map(|(s, _)| s.as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn made_once_and_kept() {
        let dir = std::env::temp_dir().join(format!("cbb-seal-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let a = load(&dir).unwrap();
        assert_eq!(load(&dir).unwrap(), a);
        assert_eq!(std::fs::metadata(dir.join(FILE_NAME)).unwrap().permissions().mode() & 0o777, 0o600);
        std::fs::write(dir.join(FILE_NAME), br#"{"v":1,"secret":"AAAA"}"#).unwrap();
        assert!(load(&dir).is_err());
        std::fs::write(dir.join(FILE_NAME), br#"{"v":2,"secret":"AAAA"}"#).unwrap();
        assert!(load(&dir).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
