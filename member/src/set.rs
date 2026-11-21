// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The group's records v3 in the state directory: the set file
//! (`cbb_core::setfile`) in group.cbor, pinned and marked under the
//! device's local key, which local.json keeps sealed by the hardware where
//! it can be (as seal.json keeps the secret for sealed messages). A state
//! directory of a group made before 0.6 moves aside to before-0.6 first
//! ([`leave_group_before_0_6`]): 0.6 reads no older group, and such a group
//! is made again.

use std::io;
use std::path::Path;

use cbb_core::records::RecordSet;
use cbb_core::setfile;
use serde::{Deserialize, Serialize};

use crate::error::{Context, Error, Result};
use crate::files;

/// The set file in the state directory.
pub const FILE_NAME: &str = "group.cbor";

/// The file that keeps the device's local key, which marks the records the
/// device checked and pins the group's keys (docs/core-api.md, "The group
/// (records v3)").
pub const LOCAL_FILE: &str = "local.json";

/// Where a group made before 0.6 goes, in the state directory.
pub const OLD_GROUP_DIR: &str = "before-0.6";

/// The files of a group made before 0.6, as its member wrote them: the
/// identity and the records first among those whose presence says so.
const OLD_GROUP_FILES: [&str; 7] = [
    "identity.json",
    "credentials.json",
    "server-keys.json",
    "seal.json",
    "signed.json",
    "tunnel.json",
    "records.json",
];

#[derive(Serialize, Deserialize)]
struct LocalFile {
    v: i64,
    #[serde(flatten)]
    sealed: crate::keys::Sealed,
}

/// Reads the device's local key from dir/local.json, making it on first
/// use.
pub fn local_key(dir: &Path) -> Result<[u8; 32]> {
    let path = dir.join(LOCAL_FILE);
    let data = match std::fs::read(&path) {
        Ok(d) => d,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let mut key = [0u8; 32];
            getrandom::fill(&mut key)
                .map_err(|_| Error::msg("cannot make the local key: the system has no randomness"))?;
            // Sealed by the hardware where it can be; a helper that fails
            // leaves it in the file, as a device with no hardware keeps it.
            let sealed = match crate::keys::seal(&key) {
                Ok(s) => s,
                Err(e) => {
                    crate::service::log_line(&format!("cbb: the local key stays in a file: {}", e.for_log()));
                    None
                }
            }
            .unwrap_or_else(|| crate::keys::Sealed { secret: key.to_vec(), ..Default::default() });
            let data = serde_json::to_vec_pretty(&LocalFile { v: 1, sealed }).context("cannot encode the local key")?;
            files::write_atomic(&path, &data, 0o600)?;
            return Ok(key);
        }
        Err(e) => return Err(Error::with(format!("cannot read {}", path.display()), e)),
    };
    let mut f: LocalFile = serde_json::from_slice(&data).context(format!("{} is damaged", path.display()))?;
    if f.v != 1 {
        return Err(Error::msg(format!("{} is of unknown version {}", path.display(), f.v)));
    }
    let secret = cbb_core::secret::Zeroizing::new(if f.sealed.is_sealed() {
        crate::keys::unseal(&f.sealed).map_err(|e| e.context(path.display().to_string()))?
    } else {
        std::mem::take(&mut f.sealed.secret)
    });
    secret
        .as_slice()
        .try_into()
        .map_err(|_| Error::msg(format!("{} is damaged: the key is not 32 bytes", path.display())))
}

/// The group's set from dir/group.cbor, its records' marks and its pin
/// checked under local; None when the device is in no group.
pub fn load(dir: &Path, local: &[u8; 32]) -> Result<Option<RecordSet>> {
    let path = dir.join(FILE_NAME);
    let data = match std::fs::read(&path) {
        Ok(d) => d,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(Error::with(format!("cannot read {}", path.display()), e)),
    };
    setfile::load(&data, Some(local)).map(Some).map_err(|e| e.context(format!("cannot read {}", path.display())))
}

/// Writes the set to dir/group.cbor in one step, marked and pinned under
/// local.
pub fn save(dir: &Path, set: &RecordSet, local: &[u8; 32]) -> Result<()> {
    files::write_atomic(&dir.join(FILE_NAME), &setfile::save(set, Some(local)), 0o600)
}

/// Moves a group made before 0.6 out of the state directory, so the device
/// starts in no group: 0.6 reads only records v3, with no migration, so
/// such a group is made again. The records go last, so that a start cut
/// short moves the rest at the next one; the device's settings stay.
/// Whether a group moved.
pub fn leave_group_before_0_6(dir: &Path) -> Result<bool> {
    if !OLD_GROUP_FILES.iter().any(|n| dir.join(n).exists()) {
        return Ok(false);
    }
    let to = dir.join(OLD_GROUP_DIR);
    std::fs::create_dir_all(&to).context(format!("cannot create {}", to.display()))?;
    for name in OLD_GROUP_FILES {
        match std::fs::rename(dir.join(name), to.join(name)) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(Error::with(format!("cannot move {}", dir.join(name).display()), e)),
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("cbb-set-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// An empty set of a group whose keys are made from fixed bytes.
    fn empty() -> RecordSet {
        use cbb_core::records::{Key, Recovery, key::ALG_SLH_DSA, pq};
        let point = |k: &p256::SecretKey| {
            p256::ecdsa::SigningKey::from(k).verifying_key().to_sec1_point(false).as_bytes().to_vec()
        };
        let (k1, k2) = pq::recovery_keys(&[1; 32]).unwrap();
        let root = p256::SecretKey::from_slice(&[2; 32]).unwrap();
        let recovery = Recovery::new(Key::es256(point(&k1)), Key::new(ALG_SLH_DSA, k2.public())).unwrap();
        RecordSet::new(Key::es256(point(&root)), recovery)
    }

    #[test]
    fn the_local_key_is_made_once_and_kept() {
        let dir = temp("local");
        let a = local_key(&dir).unwrap();
        assert_eq!(local_key(&dir).unwrap(), a);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(dir.join(LOCAL_FILE)).unwrap().permissions().mode() & 0o777, 0o600);
        }
        std::fs::write(dir.join(LOCAL_FILE), br#"{"v":1,"secret":"AAAA"}"#).unwrap();
        assert!(local_key(&dir).is_err());
        std::fs::write(dir.join(LOCAL_FILE), br#"{"v":2,"secret":"AAAA"}"#).unwrap();
        assert!(local_key(&dir).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_set_is_saved_and_read_back_under_its_local_key() {
        let dir = temp("file");
        let local = local_key(&dir).unwrap();
        assert!(load(&dir, &local).unwrap().is_none());
        let set = empty();
        save(&dir, &set, &local).unwrap();
        let back = load(&dir, &local).unwrap().unwrap();
        assert_eq!(back.digest(), set.digest());
        assert_eq!(back.root(), set.root());
        // Under another local key the pin does not hold: refused whole.
        assert!(load(&dir, &[7; 32]).is_err());
        std::fs::write(dir.join(FILE_NAME), b"not cbor").unwrap();
        assert!(load(&dir, &local).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_group_before_0_6_moves_aside() {
        let dir = temp("old");
        assert!(!leave_group_before_0_6(&dir).unwrap());
        std::fs::write(dir.join("identity.json"), b"{}").unwrap();
        std::fs::write(dir.join("records.json"), br#"{"v":2,"records":[]}"#).unwrap();
        std::fs::write(dir.join("seal.json"), b"{}").unwrap();
        std::fs::write(dir.join("sync.json"), br#"{"off":true}"#).unwrap();
        assert!(leave_group_before_0_6(&dir).unwrap());
        for name in ["identity.json", "records.json", "seal.json"] {
            assert!(!dir.join(name).exists(), "{name} stayed");
            assert!(dir.join(OLD_GROUP_DIR).join(name).exists(), "{name} did not move");
        }
        assert!(dir.join("sync.json").exists());
        assert!(!leave_group_before_0_6(&dir).unwrap());
        // A start cut short after the identity moved: the records follow.
        std::fs::write(dir.join("records.json"), b"[]").unwrap();
        assert!(leave_group_before_0_6(&dir).unwrap());
        assert!(!dir.join("records.json").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
