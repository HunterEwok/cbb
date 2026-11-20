// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The device's own keys in the state directory, in keys.json: the member
//! key, which TLS by key shows and which names the device (its ID is the
//! key's hash, cut to 16 bytes), and the keys the records may give it: an
//! admin key, a root key and a spare admin key the member keeps for a
//! change of root. Each is in the TPM or the Secure Enclave where the
//! machine has one (keys.rs), else PKCS #8 in the file. No certificate
//! and nothing of the group is here: the group is the set (set.rs).

use std::io;
use std::path::Path;
use std::sync::Arc;

use base64::Engine as _;
use cbb_core::identity::{ExternalKey, FileKey, HeldKey, new_key};
use cbb_core::records::{DeviceId, Key, KeyHash};
use serde::{Deserialize, Serialize};

use crate::error::{Context, Error, Result};
use crate::files;

/// The file in the state directory.
pub const FILE_NAME: &str = "keys.json";

/// Which of the device's keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Which {
    Member,
    Admin,
    Root,
    Spare,
}

/// One key as the file keeps it: PKCS #8, or what loads it in the
/// hardware.
#[derive(Serialize, Deserialize, Clone, Default, PartialEq)]
struct Stored {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pkcs8: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tpm: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    se: Option<String>,
}

impl std::fmt::Debug for Stored {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(if self.pkcs8.is_empty() { "Stored(held)" } else { "Stored(file)" })
    }
}

#[derive(Serialize, Deserialize, Default)]
struct File {
    v: i64,
    member: Stored,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    admin: Option<Stored>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    root: Option<Stored>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    spare: Option<Stored>,
}

/// The device's keys, opened.
pub struct Own {
    pub member: Arc<dyn ExternalKey>,
    pub admin: Option<Arc<dyn ExternalKey>>,
    pub root: Option<Arc<dyn ExternalKey>>,
    pub spare: Option<Arc<dyn ExternalKey>>,
    /// The member key as PKCS #8 when the file holds it, for TLS.
    member_pkcs8: Option<cbb_core::secret::Zeroizing<Vec<u8>>>,
}

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

/// Opens a stored key; held keys through open.
fn open(s: &Stored, open: &dyn Fn(&HeldKey) -> Result<Arc<dyn ExternalKey>>) -> Result<Arc<dyn ExternalKey>> {
    match (&s.pkcs8, &s.tpm, &s.se) {
        (p, None, None) if !p.is_empty() => {
            let der = cbb_core::secret::Zeroizing::new(b64().decode(p).context("a key is not base64")?);
            Ok(Arc::new(FileKey::new(&der)?))
        }
        (p, Some(t), None) if p.is_empty() => open(&HeldKey::Tpm(t.clone())),
        (p, None, Some(se)) if p.is_empty() => {
            open(&HeldKey::SecureEnclave(b64().decode(se).context("a key is not base64")?))
        }
        _ => Err(Error::msg("a key is kept in no place or in two")),
    }
}

/// How a new key is kept: in the hardware where it can be, else in the
/// file.
fn store(key: &Arc<dyn ExternalKey>, pkcs8: Option<&[u8]>) -> Stored {
    match (key.held(), pkcs8) {
        (Some(HeldKey::Tpm(t)), _) => Stored { tpm: Some(t), ..Stored::default() },
        (Some(HeldKey::SecureEnclave(b)), _) => Stored { se: Some(b64().encode(b)), ..Stored::default() },
        (None, Some(der)) => Stored { pkcs8: b64().encode(der), ..Stored::default() },
        (None, None) => Stored::default(),
    }
}

/// A new key, how the file keeps it, and its PKCS #8 when the file holds
/// it.
type Made = (Arc<dyn ExternalKey>, Stored, Option<cbb_core::secret::Zeroizing<Vec<u8>>>);

/// A new key: in the hardware where make gives one, else PKCS #8.
fn make(hardware: &dyn Fn() -> Option<Arc<dyn ExternalKey>>) -> Result<Made> {
    if let Some(k) = hardware() {
        let s = store(&k, None);
        if s != Stored::default() {
            return Ok((k, s, None));
        }
    }
    let der = cbb_core::secret::Zeroizing::new(new_key()?);
    let k: Arc<dyn ExternalKey> = Arc::new(FileKey::new(&der)?);
    let s = store(&k, Some(&der));
    Ok((k, s, Some(der)))
}

impl Own {
    /// The keys an app holds itself (a phone's, signing through its
    /// callback): nothing is kept in a file.
    pub fn from_keys(
        member: Arc<dyn ExternalKey>,
        admin: Option<Arc<dyn ExternalKey>>,
        root: Option<Arc<dyn ExternalKey>>,
    ) -> Own {
        Own { member, admin, root, spare: None, member_pkcs8: None }
    }

    /// The keys in dir/keys.json, made on first use with a member key
    /// alone.
    pub fn load(dir: &Path) -> Result<Own> {
        Own::load_with(dir, &crate::keys::open, &|| crate::keys::new_device_key().0)
    }

    /// load, with the hardware's opener and maker given.
    pub fn load_with(
        dir: &Path,
        opener: &dyn Fn(&HeldKey) -> Result<Arc<dyn ExternalKey>>,
        hardware: &dyn Fn() -> Option<Arc<dyn ExternalKey>>,
    ) -> Result<Own> {
        let path = dir.join(FILE_NAME);
        let f: File = match std::fs::read(&path) {
            Ok(d) => serde_json::from_slice(&d).context(format!("{} is damaged", path.display()))?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let (member, stored, der) = make(hardware)?;
                let f = File { v: 1, member: stored, ..File::default() };
                write(&path, &f)?;
                return Ok(Own { member, admin: None, root: None, spare: None, member_pkcs8: der });
            }
            Err(e) => return Err(Error::with(format!("cannot read {}", path.display()), e)),
        };
        if f.v != 1 {
            return Err(Error::msg(format!("{} is of unknown version {}", path.display(), f.v)));
        }
        let what = |w: &str| format!("cannot open this device's {w} key ({})", path.display());
        let member_pkcs8 = if f.member.pkcs8.is_empty() {
            None
        } else {
            Some(cbb_core::secret::Zeroizing::new(b64().decode(&f.member.pkcs8).context(what("member"))?))
        };
        let opt = |s: &Option<Stored>, w: &str| {
            s.as_ref().map(|s| open(s, opener).map_err(|e| e.context(what(w)))).transpose()
        };
        Ok(Own {
            member: open(&f.member, opener).map_err(|e| e.context(what("member")))?,
            admin: opt(&f.admin, "admin")?,
            root: opt(&f.root, "root")?,
            spare: opt(&f.spare, "spare admin")?,
            member_pkcs8,
        })
    }

    /// Makes a new key of which (not the member key) and keeps it in
    /// dir/keys.json, in place of the one the file had.
    pub fn make(&mut self, dir: &Path, which: Which) -> Result<Arc<dyn ExternalKey>> {
        self.make_with(dir, which, &|| crate::keys::new_device_key().0)
    }

    /// make, with the hardware's maker given.
    pub fn make_with(
        &mut self,
        dir: &Path,
        which: Which,
        hardware: &dyn Fn() -> Option<Arc<dyn ExternalKey>>,
    ) -> Result<Arc<dyn ExternalKey>> {
        if which == Which::Member {
            return Err(Error::msg("the member key names the device: it is made once"));
        }
        let path = dir.join(FILE_NAME);
        let data = std::fs::read(&path).context(format!("cannot read {}", path.display()))?;
        let mut f: File = serde_json::from_slice(&data).context(format!("{} is damaged", path.display()))?;
        let (k, stored, _) = make(hardware)?;
        match which {
            Which::Admin => (f.admin, self.admin) = (Some(stored), Some(k.clone())),
            Which::Root => (f.root, self.root) = (Some(stored), Some(k.clone())),
            Which::Spare => (f.spare, self.spare) = (Some(stored), Some(k.clone())),
            Which::Member => unreachable!("refused above"),
        }
        write(&path, &f)?;
        Ok(k)
    }

    /// Forgets a key of which (not the member key) in dir/keys.json.
    pub fn forget(&mut self, dir: &Path, which: Which) -> Result<()> {
        let path = dir.join(FILE_NAME);
        let data = std::fs::read(&path).context(format!("cannot read {}", path.display()))?;
        let mut f: File = serde_json::from_slice(&data).context(format!("{} is damaged", path.display()))?;
        match which {
            Which::Admin => (f.admin, self.admin) = (None, None),
            Which::Root => (f.root, self.root) = (None, None),
            Which::Spare => (f.spare, self.spare) = (None, None),
            Which::Member => return Err(Error::msg("the member key names the device: it is never forgotten")),
        }
        write(&path, &f)
    }

    /// The member key as the records name it.
    pub fn member_key(&self) -> Key {
        Key::es256(self.member.public())
    }

    /// The member key's hash.
    pub fn hash(&self) -> KeyHash {
        self.member_key().hash()
    }

    /// The device's ID.
    pub fn device(&self) -> DeviceId {
        DeviceId::of(&self.hash())
    }

    /// The member key for TLS by key.
    pub fn tls_key(&self) -> Result<cbb_core::tls::bykey::OwnKey> {
        match &self.member_pkcs8 {
            Some(der) => cbb_core::tls::bykey::OwnKey::pkcs8(der),
            None => cbb_core::tls::bykey::OwnKey::external(self.member.clone()),
        }
    }
}

fn write(path: &Path, f: &File) -> Result<()> {
    let data =
        cbb_core::secret::Zeroizing::new(serde_json::to_vec_pretty(f).context("cannot encode the device's keys")?);
    files::write_atomic(path, &data, 0o600)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("cbb-own-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn no_hardware() -> Option<Arc<dyn ExternalKey>> {
        None
    }

    fn no_opener(_: &HeldKey) -> Result<Arc<dyn ExternalKey>> {
        Err(Error::msg("no hardware here"))
    }

    #[test]
    fn the_member_key_is_made_once_and_names_the_device() {
        let dir = temp("member");
        let a = Own::load_with(&dir, &no_opener, &no_hardware).unwrap();
        let b = Own::load_with(&dir, &no_opener, &no_hardware).unwrap();
        assert_eq!(a.member.public(), b.member.public());
        assert_eq!(a.device(), b.device());
        assert!(a.admin.is_none() && a.root.is_none() && a.spare.is_none());
        assert_eq!(a.tls_key().unwrap().point().as_slice(), a.member.public().as_slice());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(dir.join(FILE_NAME)).unwrap().permissions().mode() & 0o777, 0o600);
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn keys_are_made_kept_and_forgotten() {
        let dir = temp("roles");
        let mut own = Own::load_with(&dir, &no_opener, &no_hardware).unwrap();
        let admin = own.make_with(&dir, Which::Admin, &no_hardware).unwrap();
        let spare = own.make_with(&dir, Which::Spare, &no_hardware).unwrap();
        assert!(own.make_with(&dir, Which::Member, &no_hardware).is_err());
        let back = Own::load_with(&dir, &no_opener, &no_hardware).unwrap();
        assert_eq!(back.admin.as_ref().unwrap().public(), admin.public());
        assert_eq!(back.spare.as_ref().unwrap().public(), spare.public());
        assert_ne!(admin.public(), spare.public());
        own.forget(&dir, Which::Spare).unwrap();
        let back = Own::load_with(&dir, &no_opener, &no_hardware).unwrap();
        assert!(back.spare.is_none() && back.admin.is_some());
        assert!(own.forget(&dir, Which::Member).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_damaged_file_is_refused() {
        let dir = temp("bad");
        std::fs::write(dir.join(FILE_NAME), br#"{"v":2,"member":{"pkcs8":"AAAA"}}"#).unwrap();
        assert!(Own::load_with(&dir, &no_opener, &no_hardware).is_err());
        std::fs::write(dir.join(FILE_NAME), br#"{"v":1,"member":{}}"#).unwrap();
        assert!(Own::load_with(&dir, &no_opener, &no_hardware).is_err());
        std::fs::write(dir.join(FILE_NAME), br#"{"v":1,"member":{"tpm":{},"se":"AAAA"}}"#).unwrap();
        assert!(Own::load_with(&dir, &no_opener, &no_hardware).is_err());
        // A held key with no hardware to open it says so.
        std::fs::write(dir.join(FILE_NAME), br#"{"v":1,"member":{"tpm":{"blob":"x"}}}"#).unwrap();
        let e = Own::load_with(&dir, &no_opener, &no_hardware).err().unwrap();
        assert!(e.for_log().contains("member key"), "{}", e.for_log());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
