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
/// until it is lifted, and the device whose admin muted this one.
#[derive(Serialize, Deserialize, Default)]
struct State {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mute: Option<i64>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    by: String,
}

fn read(dir: &Path) -> Result<State> {
    match std::fs::read(dir.join(FILE_NAME)) {
        Ok(d) => serde_json::from_slice(&d).context(FILE_NAME),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(State::default()),
        Err(e) => Err(e).context(format!("cannot read {}", dir.join(FILE_NAME).display())),
    }
}

/// Who muted this device, by its ID, while it is muted: "" when it is not,
/// or when a mute of an earlier version did not say. An unknown muter
/// counts as another admin's (Service::own_device_op).
pub fn by(dir: &Path, engine: &Engine) -> Result<String> {
    if engine.mute_left().is_none() {
        return Ok(String::new());
    }
    let st = read(dir)?;
    Ok(if st.by.is_empty() { "?".to_string() } else { st.by })
}

/// Who a mute this device sets on itself is saved as, when `current` (as
/// `by` tells) muted it before: a mute already set keeps its muter, so a
/// later one does not make it the device's own.
pub fn kept_by(current: &str, me: &str) -> String {
    if current.is_empty() { me.to_string() } else { current.to_string() }
}

/// Gives the engine the mute saved in dir.
pub fn load(dir: &Path, engine: &Engine) -> Result<()> {
    let st = read(dir)?;
    if let Some(until) = st.mute {
        engine.set_mute(until);
    }
    Ok(())
}

/// Writes the engine's mute to dir, set by the device `by`.
pub fn save(dir: &Path, engine: &Engine, by: &str) -> Result<()> {
    let now = crate::uptime::wall_ms();
    let mute = engine.mute_left().map(|left| if left == 0 { 0 } else { now + left });
    let st = State { mute, by: if mute.is_some() { by.to_string() } else { String::new() } };
    let data = serde_json::to_vec(&st).map_err(|e| Error::with("encoding the mute", e))?;
    files::write_atomic(&dir.join(FILE_NAME), &data, 0o600).map_err(|e| e.context("saving the mute"))
}

/// The end of a mute for ms from now, 0 for until it is lifted.
pub fn until(ms: i64) -> Result<i64> {
    if !(0..=MAX_MS).contains(&ms) {
        return Err(Error::msg("a mute lasts at most 30 days; leave the time out to mute until cbb unmute"));
    }
    Ok(if ms == 0 { 0 } else { crate::uptime::wall_ms() + ms })
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
        save(&dir, &e, "admin-a").unwrap();
        let again = new();
        load(&dir, &again).unwrap();
        assert!(again.mute_left().is_some_and(|left| left > 3_500_000), "the mute");
        assert_eq!(by(&dir, &again).unwrap(), "admin-a", "who muted it");
        again.unmute();
        save(&dir, &again, "admin-a").unwrap();
        assert_eq!(by(&dir, &again).unwrap(), "", "no muter once the mute ended");
        // A mute saved without its muter counts as another admin's.
        std::fs::write(dir.join(FILE_NAME), br#"{"mute":0}"#).unwrap();
        load(&dir, &again).unwrap();
        assert_eq!(by(&dir, &again).unwrap(), "?");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Muting again keeps who muted it first: another admin's mute, or one
    /// whose muter is unknown, does not become this device's own.
    #[test]
    fn a_second_mute_keeps_the_muter() {
        assert_eq!(kept_by("", "me"), "me");
        assert_eq!(kept_by("me", "me"), "me");
        assert_eq!(kept_by("admin-b", "me"), "admin-b");
        assert_eq!(kept_by("?", "me"), "?");
    }
}
