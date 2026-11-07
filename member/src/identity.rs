// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The identity in the state directory, in identity.json (the format of the
//! Go member's file, see cbb_core::identity). A device key in the TPM or the
//! Secure Enclave opens through cbb-helper (keys.rs). The parts only an
//! admin holds (the group CA key on the computer that made the group, an
//! admin key and its CA, a claim) stay in the file as Go writes them: the
//! core's identity leaves them out, and admin.rs reads them.

use std::path::Path;

pub use cbb_core::identity::*;

use crate::error::{Context, Error, Result, Wrap};
use crate::files;

/// The name of the identity file in the state directory.
pub const FILE_NAME: &str = "identity.json";

/// The fields of the identity file that only an admin holds, which the
/// core's identity leaves out (Go's identityFile).
pub const ADMIN_FIELDS: [&str; 10] = [
    "group_ca_key",
    "root_key",
    "admin_key",
    "admin_key_tpm",
    "admin_key_se",
    "admin_ca",
    "prev_cert",
    "prev_issuer",
    "claim",
    "claim_key",
];

/// The admin's fields of the identity file in dir, by name; empty when
/// there is no file or it has none.
pub fn admin_fields(dir: &Path) -> Result<serde_json::Map<String, serde_json::Value>> {
    let path = dir.join(FILE_NAME);
    let data = match std::fs::read(&path) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Default::default()),
        Err(e) => return Err(Error::with(format!("cannot read {}", path.display()), e)),
    };
    let mut all: serde_json::Map<String, serde_json::Value> =
        serde_json::from_slice(&data).map_err(|e| Error::with(format!("{} is damaged", path.display()), e))?;
    all.retain(|k, _| ADMIN_FIELDS.contains(&k.as_str()));
    Ok(all)
}

/// Writes ident to dir/identity.json with the admin's fields: those of
/// fields, and the others as the file had them for the same device of the
/// same group. A field set to null in fields goes.
pub fn save_with(ident: &Identity, dir: &Path, fields: serde_json::Map<String, serde_json::Value>) -> Result<()> {
    let mut out: serde_json::Map<String, serde_json::Value> =
        serde_json::from_slice(&ident.to_file()?).context("cannot encode the identity")?;
    let path = dir.join(FILE_NAME);
    let old: Option<serde_json::Map<String, serde_json::Value>> =
        std::fs::read(&path).ok().and_then(|d| serde_json::from_slice(&d).ok());
    if let Some(old) = old
        && old.get("device") == out.get("device")
        && old.get("group_ca") == out.get("group_ca")
    {
        for k in ADMIN_FIELDS {
            if let Some(v) = old.get(k)
                && !fields.contains_key(k)
            {
                out.insert(k.into(), v.clone());
            }
        }
    }
    for (k, v) in fields {
        if !ADMIN_FIELDS.contains(&k.as_str()) {
            return Err(Error::msg(format!("{k} is not an admin's field of the identity file")));
        }
        if v.is_null() {
            out.remove(&k);
        } else {
            out.insert(k, v);
        }
    }
    let mut data = serde_json::to_vec_pretty(&out).context("cannot encode the identity")?;
    data.push(b'\n');
    files::write_atomic(&path, &data, 0o600)
}

/// Reading and writing the identity file.
pub trait Stored: Sized {
    /// Writes the identity to dir/identity.json, readable only by its
    /// owner, replacing the file in one step; the admin's fields the file
    /// had for this device stay.
    fn save(&self, dir: &Path) -> Result<()>;
    /// Reads the identity from dir/identity.json; None if there is none.
    fn load(dir: &Path) -> Result<Option<Self>>;
}

impl Stored for Identity {
    fn save(&self, dir: &Path) -> Result<()> {
        save_with(self, dir, Default::default())
    }

    fn load(dir: &Path) -> Result<Option<Identity>> {
        let path = dir.join(FILE_NAME);
        let data = match std::fs::read(&path) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(Error::with(format!("cannot read {}", path.display()), e)),
        };
        let id = Identity::from_file_with(&data, &crate::keys::open).wrap(format!("{} is damaged", path.display()))?;
        Ok(Some(id))
    }
}
