// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Leaving the group (cbb leave, D-83): the device deletes its keys and
//! the group's files, keeps its settings, and may join a group again.

use std::path::Path;

use crate::error::{Error, Result};
use crate::{actions, identity, records, remotepaste, sealkey};

/// The answer to a leave in no group.
pub const NOTHING_TO_LEAVE: &str = "this device is in no group, so there is nothing to leave; cbb pair joins one";

/// What a device keeps of its group in the state directory: its keys, the
/// tunnel's (only in builds with it), the logs that name the group's
/// devices, the mute, a group left before 0.6, and the records last, so that a leave
/// cut short is seen as a group still.
pub const GROUP_FILES: &[&str] = &[
    identity::FILE_NAME,
    sealkey::FILE_NAME,
    "tunnel.json",
    remotepaste::LOG_FILE,
    actions::LOG_FILE,
    crate::mute::FILE_NAME,
    records::OLD_GROUP_DIR,
    records::FILE_NAME,
];

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
        std::fs::create_dir_all(dir.join(records::OLD_GROUP_DIR)).unwrap();
        for name in GROUP_FILES.iter().filter(|n| **n != records::OLD_GROUP_DIR) {
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
