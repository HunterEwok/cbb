// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The device's sealing keys, one per epoch, in `epochs.json`: the core's
//! `KeyStore` (`cbb_core::keystore`) over a file. The core decides when an
//! epoch is made and when one is erased (`keystore::rotate`); this keeps
//! them. Each secret is sealed with AES-256-GCM under the device's local
//! key (`set::local_key`, itself sealed by the hardware where it can be),
//! bound to its epoch, so the file alone opens nothing, and a secret moved
//! to another epoch does not open.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine as _;
use cbb_core::identity::ExternalKey;
use cbb_core::keystore::{Epoch, KeyStore};
use cbb_core::secret::Zeroizing;
use serde::{Deserialize, Serialize};

use crate::error::{Context, Error, Result};
use crate::files;

/// The file's name in the state directory.
pub const FILE_NAME: &str = "epochs.json";

#[derive(Serialize, Deserialize)]
struct File {
    v: u32,
    epochs: Vec<Stored>,
}

#[derive(Serialize, Deserialize)]
struct Stored {
    epoch: u64,
    made_ms: u64,
    statement: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    behind_since_ms: Option<u64>,
    nonce: String,
    secret: String,
}

/// The sealing keys a device holds, kept in its state directory.
pub struct FileStore {
    path: PathBuf,
    local: Zeroizing<[u8; 32]>,
    member: Arc<dyn ExternalKey>,
    epochs: BTreeMap<u64, (Epoch, Zeroizing<[u8; 32]>)>,
}

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

fn aad(epoch: u64) -> Vec<u8> {
    let mut a = b"cbb epoch secret".to_vec();
    a.extend_from_slice(&epoch.to_be_bytes());
    a
}

impl FileStore {
    /// Opens the store in dir, with the device's local key and member key;
    /// a directory without the file holds no epoch yet.
    pub fn load(dir: &Path, local: &[u8; 32], member: Arc<dyn ExternalKey>) -> Result<FileStore> {
        let path = dir.join(FILE_NAME);
        let mut s = FileStore { path, local: Zeroizing::new(*local), member, epochs: BTreeMap::new() };
        let data = match std::fs::read(&s.path) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(s),
            Err(e) => return Err(Error::with(format!("cannot read {}", s.path.display()), e)),
        };
        let damaged = || format!("{} is damaged", s.path.display());
        let f: File = serde_json::from_slice(&data).context(damaged())?;
        if f.v != 1 {
            return Err(Error::msg(format!("{} is of unknown version {}", s.path.display(), f.v)));
        }
        let gcm = Aes256Gcm::new((&*s.local).into());
        for e in f.epochs {
            let nonce: [u8; 12] =
                b64().decode(&e.nonce).ok().and_then(|n| n.try_into().ok()).ok_or_else(|| Error::msg(damaged()))?;
            let sealed = b64().decode(&e.secret).context(damaged())?;
            let plain = Zeroizing::new(
                gcm.decrypt(&Nonce::from(nonce), Payload { msg: &sealed, aad: &aad(e.epoch) })
                    .map_err(|_| Error::msg(format!("{}: a sealing key does not open", s.path.display())))?,
            );
            let secret: [u8; 32] = plain.as_slice().try_into().map_err(|_| Error::msg(damaged()))?;
            let statement = b64().decode(&e.statement).context(damaged())?;
            let epoch = Epoch { epoch: e.epoch, made_ms: e.made_ms, statement, behind_since_ms: e.behind_since_ms };
            s.epochs.insert(e.epoch, (epoch, Zeroizing::new(secret)));
        }
        Ok(s)
    }

    fn save(&self) -> Result<()> {
        let gcm = Aes256Gcm::new((&*self.local).into());
        let mut out = Vec::with_capacity(self.epochs.len());
        for (e, secret) in self.epochs.values() {
            let mut nonce = [0u8; 12];
            getrandom::fill(&mut nonce).map_err(|_| Error::msg("the system has no randomness"))?;
            let sealed = gcm
                .encrypt(&Nonce::from(nonce), Payload { msg: secret.as_slice(), aad: &aad(e.epoch) })
                .map_err(|_| Error::msg("cannot seal a sealing key"))?;
            out.push(Stored {
                epoch: e.epoch,
                made_ms: e.made_ms,
                statement: b64().encode(&e.statement),
                behind_since_ms: e.behind_since_ms,
                nonce: b64().encode(nonce),
                secret: b64().encode(sealed),
            });
        }
        let data = serde_json::to_vec_pretty(&File { v: 1, epochs: out }).context("cannot encode the sealing keys")?;
        files::write_atomic(&self.path, &data, 0o600)
    }

    /// The statements of the epochs held, newest last: the device's own,
    /// which it passes on in message `keys`.
    pub fn statements(&self) -> Vec<Vec<u8>> {
        self.epochs.values().map(|(e, _)| e.statement.clone()).collect()
    }
}

impl KeyStore for FileStore {
    fn member(&self) -> &dyn ExternalKey {
        &*self.member
    }

    fn sealing(&self, epoch: u64) -> Option<[u8; 32]> {
        self.epochs.get(&epoch).map(|(_, s)| **s)
    }

    fn epochs(&self) -> Vec<Epoch> {
        self.epochs.values().map(|(e, _)| e.clone()).collect()
    }

    fn put(&mut self, epoch: Epoch, secret: [u8; 32]) -> cbb_core::error::Result<()> {
        let n = epoch.epoch;
        let old = self.epochs.insert(n, (epoch, Zeroizing::new(secret)));
        if let Err(e) = self.save() {
            match old {
                Some(o) => self.epochs.insert(n, o),
                None => self.epochs.remove(&n),
            };
            return Err(cbb_core::error::Error::msg(e.to_string()));
        }
        Ok(())
    }

    fn erase(&mut self, epoch: u64) -> cbb_core::error::Result<()> {
        if self.epochs.remove(&epoch).is_some() {
            self.save().map_err(|e| cbb_core::error::Error::msg(e.to_string()))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cbb_core::keystore::{WEEK_MS, rotate};
    use cbb_core::records::GroupId;

    struct K(p256::ecdsa::SigningKey);

    impl ExternalKey for K {
        fn public(&self) -> Vec<u8> {
            self.0.verifying_key().to_sec1_point(false).as_bytes().to_vec()
        }
        fn sign_digest(&self, d: &[u8; 32]) -> cbb_core::error::Result<Vec<u8>> {
            use p256::ecdsa::signature::hazmat::PrehashSigner as _;
            let s: p256::ecdsa::Signature = self.0.sign_prehash(d).unwrap();
            Ok(s.to_der().as_bytes().to_vec())
        }
    }

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("cbb-epochs-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn member() -> Arc<dyn ExternalKey> {
        Arc::new(K(p256::ecdsa::SigningKey::from_slice(&[5; 32]).unwrap()))
    }

    #[test]
    fn the_epochs_survive_a_restart_and_are_erased_for_good() {
        let dir = temp("restart");
        let local = [9u8; 32];
        let group = GroupId::default();
        let mut s = FileStore::load(&dir, &local, member()).unwrap();
        let r = rotate(&mut s, &group, 1_000, Some(1_000)).unwrap();
        assert!(r.made.is_some());
        let first = s.sealing(1).unwrap();
        // A restart reads the same secret back.
        let s2 = FileStore::load(&dir, &local, member()).unwrap();
        assert_eq!(s2.sealing(1), Some(first));
        assert_eq!(s2.statements(), vec![r.made.unwrap()]);
        // The file alone opens nothing: no secret in it as it is.
        let raw = std::fs::read(dir.join(FILE_NAME)).unwrap();
        assert!(!raw.windows(32).any(|w| w == first));
        assert!(!String::from_utf8_lossy(&raw).contains(&b64().encode(first)));
        // Another local key does not open it.
        assert!(FileStore::load(&dir, &[8; 32], member()).is_err());
        // Two weeks on: epoch 2, then epoch 1 erased from the file too.
        let mut s = s2;
        rotate(&mut s, &group, 1_000 + WEEK_MS, Some(1_000 + WEEK_MS)).unwrap();
        rotate(&mut s, &group, 1_000 + 2 * WEEK_MS + 1, Some(1_000 + 2 * WEEK_MS + 1)).unwrap();
        let s3 = FileStore::load(&dir, &local, member()).unwrap();
        assert_eq!(s3.sealing(1), None);
        assert!(s3.sealing(3).is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_secret_moved_to_another_epoch_does_not_open() {
        let dir = temp("moved");
        let local = [9u8; 32];
        let mut s = FileStore::load(&dir, &local, member()).unwrap();
        rotate(&mut s, &GroupId::default(), 1_000, Some(1_000)).unwrap();
        let text = std::fs::read_to_string(dir.join(FILE_NAME)).unwrap();
        std::fs::write(dir.join(FILE_NAME), text.replace("\"epoch\": 1", "\"epoch\": 2")).unwrap();
        assert!(FileStore::load(&dir, &local, member()).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
