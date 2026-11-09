// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The group's records in the state directory, in records.json.

use std::path::Path;

pub use cbb_core::authority::Record;
pub use cbb_core::command::{Command, valid_name, valid_os};
pub use cbb_core::group::*;

use crate::certs::Cert;
use crate::error::{Context, Error, Result, Wrap};
use crate::files;

/// The name of the records file in the state directory.
pub const FILE_NAME: &str = "records.json";

/// Reading and writing the records file.
pub trait Stored: Sized {
    /// Writes the records to dir/records.json in one step.
    fn save(&self, dir: &Path) -> Result<()>;
    /// Reads dir/records.json for the group of group_ca; a missing file is
    /// an empty set, and records not valid for the group are left out.
    fn load(dir: &Path, group_ca: &Cert) -> Result<Self>;
}

impl Stored for Records {
    fn save(&self, dir: &Path) -> Result<()> {
        files::write_atomic(&dir.join(FILE_NAME), &self.to_file()?, 0o600)
    }

    fn load(dir: &Path, group_ca: &Cert) -> Result<Records> {
        let path = dir.join(FILE_NAME);
        let data = match std::fs::read(&path) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(new(group_ca)),
            Err(e) => return Err(Error::with(format!("cannot read {}", path.display()), e)),
        };
        Records::from_file_with(&data, group_ca, crate::uptime::wall_ms).wrap(format!("{} is damaged", path.display()))
    }
}

/// Where a group made before 0.6 goes when the device leaves it, in the
/// state directory.
pub const OLD_GROUP_DIR: &str = "before-0.6";

/// Moves a group made before 0.6 out of the state directory, so the device
/// starts in no group: 0.6 reads only records of version 2, with no
/// migration (docs/records-v2.md), so such a group can no longer work and
/// is set up again. Its records file is a JSON array; version 2's is an
/// object. A group made before 0.4, whose group CA certifies no admin CAs,
/// leaves too, with or without records (Go's ErrOldGroup). The records go
/// last, so that a start cut short moves the rest at the next one; the
/// device's settings stay.
pub fn leave_version1_group(dir: &Path) -> Result<bool> {
    let read = |name: &str| match std::fs::read(dir.join(name)) {
        Ok(d) => Ok(Some(d)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(Error::with(format!("cannot read {}", dir.join(name).display()), e)),
    };
    let version1 = read(FILE_NAME)?.is_some_and(|d| d.iter().find(|b| !b.is_ascii_whitespace()) == Some(&b'['));
    if !version1 && !read(crate::identity::FILE_NAME)?.is_some_and(|d| made_before_0_4(&d)) {
        return Ok(false);
    }
    let to = dir.join(OLD_GROUP_DIR);
    std::fs::create_dir_all(&to).context(format!("cannot create {}", to.display()))?;
    // tunnel.json: the tunnel module is only in builds with it.
    // The files of a group as Go's oldGroupFiles lists them, and tunnel.json.
    for name in [
        crate::identity::FILE_NAME,
        "credentials.json",
        "server-keys.json",
        crate::sealkey::FILE_NAME,
        "signed.json",
        "tunnel.json",
        FILE_NAME,
    ] {
        match std::fs::rename(dir.join(name), to.join(name)) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(Error::with(format!("cannot move {}", dir.join(name).display()), e)),
        }
    }
    Ok(true)
}

/// Whether an identity file is of a group made before 0.4: its group CA
/// has a path length of 0, so it certifies no admin CAs.
fn made_before_0_4(identity: &[u8]) -> bool {
    use base64::Engine as _;
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(identity) else { return false };
    let Some(ca) = v["group_ca"].as_str() else { return false };
    let Ok(der) = base64::engine::general_purpose::STANDARD.decode(ca) else { return false };
    Cert::parse(&der).is_ok_and(|c| c.is_ca && c.path_len == Some(0))
}

/// An empty set for the group of group_ca on the wall clock.
pub fn new(group_ca: &Cert) -> Records {
    let mut s = Records::new(group_ca);
    s.set_clock(crate::uptime::wall_ms);
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leaves_a_group_of_0_5() {
        let dir = std::env::temp_dir().join(format!("cbb-records-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // No records, or records of version 2: nothing moves.
        assert!(!leave_version1_group(&dir).unwrap());
        std::fs::write(dir.join(crate::identity::FILE_NAME), b"{}").unwrap();
        std::fs::write(dir.join(FILE_NAME), br#"{"v":2,"records":[]}"#).unwrap();
        assert!(!leave_version1_group(&dir).unwrap());
        assert!(dir.join(crate::identity::FILE_NAME).exists());
        // A group of 0.5: its files move, the settings stay.
        std::fs::write(dir.join(FILE_NAME), b"\n [ ]").unwrap();
        std::fs::write(dir.join("sync.json"), br#"{"off":true}"#).unwrap();
        assert!(leave_version1_group(&dir).unwrap());
        for name in [crate::identity::FILE_NAME, FILE_NAME] {
            assert!(!dir.join(name).exists(), "{name} stayed");
            assert!(dir.join(OLD_GROUP_DIR).join(name).exists(), "{name} did not move");
        }
        assert!(dir.join("sync.json").exists());
        assert!(!leave_version1_group(&dir).unwrap());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Only an identity whose group CA has a path length of 0 is of a group
    /// made before 0.4; TestUpgrade starts the service on one.
    #[test]
    fn a_group_before_0_4() {
        assert!(!made_before_0_4(b"{}"));
        assert!(!made_before_0_4(b"not json"));
        assert!(!made_before_0_4(br#"{"group_ca":"bm90IGEgY2VydA=="}"#));
    }
}
