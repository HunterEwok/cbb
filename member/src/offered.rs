// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The admin keys devices offered when they paired with this device, the
//! group's root, with their proof checked then (`cbb_core::join::info`,
//! field 5): kept by device in `offered.json`, so that `cbb admin` makes a
//! device an admin later by writing the key into its record. Only the
//! root keeps them: a device another admin admitted pairs with the root to
//! become an admin. Nothing of it is secret; it is the root's own state,
//! never sent.

use std::collections::BTreeMap;
use std::path::Path;

use base64::Engine as _;

use crate::error::{Context, Error, Result};
use crate::files;

/// The file's name in the state directory.
pub const FILE_NAME: &str = "offered.json";

/// The most devices it keeps a key for, as many as a group has.
const MAX: usize = 256;

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

fn read(dir: &Path) -> Result<BTreeMap<String, String>> {
    let path = dir.join(FILE_NAME);
    match std::fs::read(&path) {
        Ok(d) => serde_json::from_slice(&d).context(format!("{} is damaged", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
        Err(e) => Err(Error::with(format!("cannot read {}", path.display()), e)),
    }
}

/// Keeps the admin key point the device `id` offered, in place of one
/// it offered before.
pub fn keep(dir: &Path, id: &str, point: &[u8]) -> Result<()> {
    let mut m = read(dir)?;
    if m.len() >= MAX && !m.contains_key(id) {
        return Err(Error::msg("this device keeps the admin keys of as many devices as a group has already"));
    }
    m.insert(id.to_ascii_lowercase(), b64().encode(point));
    let data = serde_json::to_vec_pretty(&m).context("cannot encode the offered admin keys")?;
    files::write_atomic(&dir.join(FILE_NAME), &data, 0o600)
}

/// The admin key point the device `id` offered, if it paired with this
/// device offering one.
pub fn get(dir: &Path, id: &str) -> Result<Option<Vec<u8>>> {
    let m = read(dir)?;
    m.get(&id.to_ascii_lowercase())
        .map(|s| b64().decode(s).map_err(|_| Error::msg(format!("{FILE_NAME} holds a key that is not base64"))))
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_a_key_by_device() {
        let dir = std::env::temp_dir().join(format!("cbb-offered-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(get(&dir, "ab").unwrap(), None);
        keep(&dir, "AB", &[4, 1, 2]).unwrap();
        assert_eq!(get(&dir, "ab").unwrap(), Some(vec![4, 1, 2]));
        keep(&dir, "ab", &[4, 3]).unwrap();
        assert_eq!(get(&dir, "AB").unwrap(), Some(vec![4, 3]));
        std::fs::write(dir.join(FILE_NAME), b"{").unwrap();
        assert!(get(&dir, "ab").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
