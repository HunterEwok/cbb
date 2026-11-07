// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The mute (design.md, "Muting a device"): an admin's, which keeps this
//! member's copies from the group, in `mute.json` as a full member keeps it.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{Context, Error, Result};
use crate::files;
use cbb_core::clip::Engine;

/// The file, in the state directory.
pub const FILE_NAME: &str = "mute.json";

/// The longest mute, as a mute command's: 30 days.
pub const MAX_MS: i64 = cbb_core::command::MAX_MUTE_MS;

/// What the file holds: the end of the mute, in Unix milliseconds, 0 for
/// until it is lifted.
#[derive(Serialize, Deserialize, Default)]
struct State {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mute: Option<i64>,
}

/// Gives the engine the mute saved in dir.
pub fn load(dir: &Path, engine: &Engine) -> Result<()> {
    let data = match std::fs::read(dir.join(FILE_NAME)) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).context(format!("cannot read {}", dir.join(FILE_NAME).display())),
    };
    let st: State = serde_json::from_slice(&data).context(FILE_NAME)?;
    if let Some(until) = st.mute {
        engine.set_mute(until);
    }
    Ok(())
}

/// Writes the engine's mute to dir.
pub fn save(dir: &Path, engine: &Engine) -> Result<()> {
    let now = crate::uptime::wall_ms();
    let st = State { mute: engine.mute_left().map(|left| if left == 0 { 0 } else { now + left }) };
    let data = serde_json::to_vec(&st).map_err(|e| Error::with("encoding the mute", e))?;
    files::write_atomic(&dir.join(FILE_NAME), &data, 0o600).map_err(|e| e.context("saving the mute"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lasts_across_a_restart() {
        let dir = std::env::temp_dir().join(format!("cbb-mute-{}", std::process::id()));
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
        e.set_mute(crate::uptime::wall_ms() + 3_600_000);
        save(&dir, &e).unwrap();
        let again = new();
        load(&dir, &again).unwrap();
        assert!(again.mute_left().is_some_and(|left| left > 3_500_000), "the mute");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
