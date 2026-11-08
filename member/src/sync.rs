// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Sync on and off (design.md, "Sync on and off"): `sync.json` in the state
//! directory says that sync is off, and until when, as a full member keeps
//! it; without it, sync is on.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{Context, Error, Result};
use crate::files;
use cbb_core::clip::Engine;

/// The file, in the state directory.
pub const FILE_NAME: &str = "sync.json";

/// The longest time sync turns off for, as a mute's: 30 days.
pub const MAX_MS: i64 = crate::mute::MAX_MS;

/// What the file holds: that sync is off, and the Unix milliseconds it
/// turns on again at, 0 for until it is turned on.
#[derive(Serialize, Deserialize, Default)]
struct State {
    off: bool,
    #[serde(default, skip_serializing_if = "is_zero")]
    until_ms: i64,
}

fn is_zero(v: &i64) -> bool {
    *v == 0
}

/// Gives the engine the sync state saved in dir.
pub fn load(dir: &Path, engine: &Engine) -> Result<()> {
    let data = match std::fs::read(dir.join(FILE_NAME)) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).context(format!("cannot read {}", dir.join(FILE_NAME).display())),
    };
    let st: State = serde_json::from_slice(&data).context(FILE_NAME)?;
    engine.set_sync(!st.off, st.until_ms);
    Ok(())
}

/// Writes the engine's sync state to dir; sync on removes the file.
pub fn save(dir: &Path, engine: &Engine) -> Result<()> {
    let path = dir.join(FILE_NAME);
    let (on, until_ms) = engine.sync();
    if on {
        return match std::fs::remove_file(&path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                Err(e).context(format!("cannot remove {}", path.display()))
            }
            _ => Ok(()),
        };
    }
    let data =
        serde_json::to_vec(&State { off: true, until_ms }).map_err(|e| Error::with("encoding sync on or off", e))?;
    files::write_atomic(&path, &data, 0o600).map_err(|e| e.context("saving sync on or off"))
}

/// Turns sync on, or off for ms milliseconds (0 for until it is turned
/// on), and saves it.
pub fn set(dir: &Path, engine: &Engine, on: bool, ms: i64) -> Result<()> {
    if !(0..=MAX_MS).contains(&ms) {
        return Err(Error::msg(
            "sync turns off for at most 30 days; leave the time out to turn it off until cbb sync on",
        ));
    }
    engine.set_sync(on, if on || ms == 0 { 0 } else { crate::uptime::wall_ms() + ms });
    save(dir, engine)
}

/// Reads "on" or "off", as cbb sync takes them.
pub fn parse(name: &str) -> Result<bool> {
    match name {
        "on" => Ok(true),
        "off" => Ok(false),
        _ => Err(Error::msg(format!("sync is on or off, not {name:?}"))),
    }
}

/// What the log says of sync on or off.
pub fn line(engine: &Engine) -> String {
    match engine.sync() {
        (true, _) => "cbb: sync is on: copies go to the group and come from it".into(),
        (false, 0) => "cbb: sync is off until it is turned on: the clipboard is this device's own".into(),
        (false, u) => format!(
            "cbb: sync is off for {} min more: the clipboard is this device's own",
            ((u - crate::uptime::wall_ms()).max(0) + 59_999) / 60_000
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lasts_across_a_restart() {
        let dir = std::env::temp_dir().join(format!("cbb-sync-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let new = || {
            Engine::new(
                &"a".repeat(32),
                cbb_core::hlc::Clock::new(Box::new(crate::uptime::wall_ms), Default::default(), None),
                Box::new(crate::uptime::wall_ms),
                Box::new(crate::uptime::now),
            )
        };
        let e = new();
        set(&dir, &e, false, 3_600_000).unwrap();
        let again = new();
        load(&dir, &again).unwrap();
        let (on, until) = again.sync();
        assert!(!on && until > crate::uptime::wall_ms() + 3_500_000, "off for an hour");
        set(&dir, &e, true, 0).unwrap();
        assert!(!dir.join(FILE_NAME).exists(), "sync on keeps no file");
        assert!(set(&dir, &e, false, MAX_MS + 1).is_err());
        assert!(parse("on").unwrap() && !parse("off").unwrap() && parse("shared").is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
