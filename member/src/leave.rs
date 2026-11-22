// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Leaving the group (cbb leave, D-83): the device deletes its keys and
//! the group's files, keeps its settings, and may join a group again.

use std::path::Path;

use crate::error::{Error, Result};
use crate::identity::Stored as _;
use crate::{actions, identity, records, remotepaste};

/// The answer to a leave in no group.
pub const NOTHING_TO_LEAVE: &str = "this device is in no group, so there is nothing to leave; cbb pair joins one";

/// What a device keeps of its group in the state directory, as Go's
/// groupFiles: its keys, the tunnel's (only in builds with it), the entry
/// points and the revocation list it took, the parts of copies, the logs
/// that name the group's devices, the mute, a group left before 0.6, the
/// group's faces toward its servers and the phones' push registrations,
/// and the records last, so that a leave cut short is seen as a group
/// still.
pub const GROUP_FILES: &[&str] = &[
    identity::FILE_NAME,
    // The secret for sealed commands of a group made before 0.6.
    "seal.json",
    "tunnel.json",
    crate::entries::FILE,
    crate::evidence::STATUS_FILE,
    crate::content::DIR,
    crate::networks::FILE,
    // The hub credentials and server keys of a group made before 0.6.
    "credentials.json",
    "server-keys.json",
    remotepaste::LOG_FILE,
    actions::LOG_FILE,
    crate::mute::FILE_NAME,
    // The log of the records signed in a group made before 0.6.
    "signed.json",
    crate::set::OLD_GROUP_DIR,
    crate::set::LOCAL_FILE,
    crate::offered::FILE_NAME,
    crate::own::FILE_NAME,
    crate::epochs::FILE_NAME,
    crate::sealed::FILE_NAME,
    crate::commands::FILE_NAME,
    crate::mesh::MARKS_FILE,
    crate::mesh::SIGNED_FILE,
    crate::mesh::PUSH_FILE,
    crate::mesh::PUSH_PREVIOUS_FILE,
    crate::faces::FILE,
    crate::faces::PERIOD_KEY_FILE,
    crate::faces::SECRET_FILE,
    crate::faces::FORWARDERS_FILE,
    crate::live::invite::GUEST_FILE,
    records::FILE_NAME,
    crate::set::FILE_NAME,
];

/// Whether dir holds a group, of 0.6 or from before it: its records or
/// the device's identity, as a leave cut short leaves them last.
pub fn in_group(dir: &Path) -> bool {
    matches!(identity::Identity::load(dir), Ok(Some(_)) | Err(_))
        || [records::FILE_NAME, crate::set::FILE_NAME].iter().any(|f| dir.join(f).exists())
}

/// Deletes the group's files from dir and turns remote paste and the quick
/// actions off, since they were allowed to the admins of the group it
/// leaves; the rest of the settings stay.
pub fn leave_group(dir: &Path) -> Result<()> {
    let mut failed = Vec::new();
    for name in GROUP_FILES {
        let path = dir.join(name);
        let res = if path.is_dir() { std::fs::remove_dir_all(&path) } else { std::fs::remove_file(&path) };
        match res {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => failed.push(format!("{}: {e}", path.display())),
        }
    }
    if let Err(e) = remotepaste::save(dir, remotepaste::Settings::default()) {
        failed.push(format!("turning remote paste off: {}", e.for_log()));
    }
    match actions::load(dir) {
        Ok(mut s) if !s.on().is_empty() => {
            s.all_off();
            if let Err(e) = actions::save(dir, &s) {
                failed.push(format!("turning the quick actions off: {}", e.for_log()));
            }
        }
        Ok(_) => {}
        Err(e) => failed.push(format!("turning the quick actions off: {}", e.for_log())),
    }
    if failed.is_empty() { Ok(()) } else { Err(Error::msg(format!("leaving the group: {}", failed.join("; ")))) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deletes_the_group_and_keeps_the_settings() {
        let dir = std::env::temp_dir().join(format!("cbb-leave-{}", std::process::id()));
        std::fs::create_dir_all(dir.join(crate::set::OLD_GROUP_DIR)).unwrap();
        for name in GROUP_FILES.iter().filter(|n| **n != crate::set::OLD_GROUP_DIR) {
            std::fs::write(dir.join(name), b"{}").unwrap();
        }
        std::fs::write(dir.join("sync.json"), br#"{"off":true}"#).unwrap();
        remotepaste::save(&dir, remotepaste::Settings { on: true, enter: true, ..Default::default() }).unwrap();
        let mut set = actions::Settings::default();
        set.set(actions::Action { name: actions::RESTART.into(), on: true, ..Default::default() });
        actions::save(&dir, &set).unwrap();

        leave_group(&dir).unwrap();
        for name in GROUP_FILES {
            assert!(!dir.join(name).exists(), "{name} is left");
        }
        assert!(dir.join("sync.json").exists(), "sync off went");
        assert!(!remotepaste::load(&dir).unwrap().on, "remote paste stayed on");
        assert!(actions::load(&dir).unwrap().on().is_empty(), "an action stayed on");
        leave_group(&dir).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
