// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! What the lite member keeps for remote paste (docs/design.md, "Remote
//! paste"), as the full member's internal/remotepaste, in the same files:
//! the switches its own user sets, the cleaning of a text before it goes
//! in, the limits per sender and the log of the last pastes.

use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{Context, Error, Result};
use crate::files;

/// The switches of remote paste on a device, which only its own user turns
/// on: `on` lets the group's admins paste, `enter` lets a paste press Enter,
/// and `console` lets it reach text consoles and root's tmux.
#[derive(Serialize, Deserialize, Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settings {
    pub on: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub enter: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub console: bool,
    /// A target may paste where nothing tells whether the session is
    /// locked, which it refuses otherwise.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub no_lock_check: bool,
}

const SETTINGS_FILE: &str = "paste-receive";
pub const LOG_FILE: &str = "pastes.json";
/// How many pastes the log keeps.
pub const LOG_SIZE: usize = 100;

/// Reads the settings from dir: all off when there are none.
pub fn load(dir: &Path) -> Result<Settings> {
    match std::fs::read(dir.join(SETTINGS_FILE)) {
        Ok(b) => serde_json::from_slice(&b).context(SETTINGS_FILE),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Settings::default()),
        Err(e) => Err(Error::with(format!("cannot read {}", dir.join(SETTINGS_FILE).display()), e)),
    }
}

/// Writes the settings to dir; off turns Enter and consoles off too.
pub fn save(dir: &Path, s: Settings) -> Result<()> {
    let s = if s.on { s } else { Settings::default() };
    let mut b = serde_json::to_vec(&s).context("cannot encode the remote paste settings")?;
    b.push(b'\n');
    files::write_atomic(&dir.join(SETTINGS_FILE), &b, 0o600)
}

/// The text as it may go in: newlines and tabs, without other control
/// characters and without terminal escape sequences, so that a paste cannot
/// move a terminal's cursor or run what the user does not see. CR LF and a
/// lone CR become LF.
pub fn clean(text: &str) -> String {
    let c: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < c.len() {
        let mut n = 1;
        match c[i] {
            '\r' => {
                out.push('\n');
                if c.get(i + 1) == Some(&'\n') {
                    n += 1;
                }
            }
            '\u{1b}' => n = escape_len(&c[i..]),
            '\u{9b}' => n += csi_len(&c[i + 1..]),
            ch @ ('\n' | '\t') => out.push(ch),
            ch if ch < ' ' || ('\u{7f}'..'\u{a0}').contains(&ch) => {}
            ch => out.push(ch),
        }
        i += n;
    }
    out
}

/// The length of the escape sequence at the start of s, which starts with
/// ESC: CSI up to its final byte, OSC, DCS and the like up to BEL or ESC \,
/// or ESC and one character.
fn escape_len(s: &[char]) -> usize {
    match s.get(1) {
        None => s.len(),
        Some('[') => 2 + csi_len(&s[2..]),
        Some(']' | 'P' | 'X' | '^' | '_') => {
            for i in 2..s.len() {
                if s[i] == '\u{7}' {
                    return i + 1;
                }
                if s[i] == '\u{1b}' && s.get(i + 1) == Some(&'\\') {
                    return i + 2;
                }
            }
            s.len()
        }
        Some(_) => 2,
    }
}

/// The length of a CSI sequence's parameters and final byte.
fn csi_len(s: &[char]) -> usize {
    for (i, &c) in s.iter().enumerate() {
        if ('@'..='~').contains(&c) {
            return i + 1;
        }
        if !(' '..='~').contains(&c) {
            return i;
        }
    }
    s.len()
}

/// The limits per sender: at most one paste a second and BURST a minute.
pub const EVERY_MS: i64 = 1_000;
pub const BURST: usize = 30;

/// Counts each sender's pastes.
#[derive(Default)]
pub struct Limiter {
    sent: HashMap<String, Vec<i64>>,
}

impl Limiter {
    /// Whether sender may paste at now_ms; it counts the paste if so.
    pub fn allow(&mut self, sender: &str, now_ms: i64) -> bool {
        self.sent.retain(|_, ts| {
            ts.retain(|t| now_ms - t < 60_000);
            !ts.is_empty()
        });
        let ts = self.sent.get(sender);
        if ts.is_some_and(|ts| ts.len() >= BURST || ts.last().is_some_and(|t| now_ms - t < EVERY_MS)) {
            return false;
        }
        self.sent.entry(sender.to_string()).or_default().push(now_ms);
        true
    }
}

/// One paste in the log: who sent it, when, how long it was and how it
/// ended, never its text.
#[derive(Serialize, Deserialize, Default, Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub time_ms: i64,
    /// The sender's device ID.
    pub by: String,
    /// The sender's name, when known.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    /// The records do not show that the device `by` names signed; `by` is
    /// then only the signer's word.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub unverified: bool,
    /// Bytes of the text.
    pub len: usize,
    /// paste or type.
    pub method: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub enter: bool,
    /// done, refused or failed.
    pub result: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reason: String,
}

/// Adds an entry to the log in dir, keeping the last LOG_SIZE.
pub fn append(dir: &Path, e: Entry) -> Result<()> {
    let mut es = read_log(dir).unwrap_or_default();
    es.push(e);
    if es.len() > LOG_SIZE {
        es.drain(..es.len() - LOG_SIZE);
    }
    let b = serde_json::to_vec(&es).context("cannot encode the paste log")?;
    files::write_atomic(&dir.join(LOG_FILE), &b, 0o600)
}

/// The log in dir, oldest first.
pub fn read_log(dir: &Path) -> Result<Vec<Entry>> {
    match std::fs::read(dir.join(LOG_FILE)) {
        Ok(b) => serde_json::from_slice(&b).context(LOG_FILE),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(Error::with(format!("cannot read {}", dir.join(LOG_FILE).display()), e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cleans_as_the_full_member() {
        // The cases of internal/remotepaste's TestClean.
        for (input, want) in [
            ("ls -l\n", "ls -l\n"),
            ("a\tb\r\nc\rd", "a\tb\nc\nd"),
            ("Grüße, 世界 🙂", "Grüße, 世界 🙂"),
            ("red \x1b[31mtext\x1b[0m", "red text"),
            ("title \x1b]0;pwned\x07ok", "title ok"),
            ("osc \x1b]8;;x\x1b\\link", "osc link"),
            ("csi \u{9b}2Jclear", "csi clear"),
            ("bell\x07 nul\0 del\x7f", "bell nul del"),
            ("esc at the end \x1b", "esc at the end "),
            ("keypad \x1b=on", "keypad on"),
        ] {
            assert_eq!(clean(input), want, "{input:?}");
        }
    }

    #[test]
    fn limits_each_sender() {
        let mut l = Limiter::default();
        let now = 1_761_400_000_000;
        assert!(l.allow("a", now) && !l.allow("a", now + 500), "not one a second");
        assert!(l.allow("b", now), "another sender waits for the first");
        for i in 1..BURST as i64 {
            assert!(l.allow("a", now + i * 1000), "paste {} refused", i + 1);
        }
        assert!(!l.allow("a", now + BURST as i64 * 1000), "more than the burst in a minute");
        assert!(l.allow("a", now + 61_000), "refused after a minute");
    }

    #[test]
    fn keeps_settings_and_log() {
        let dir = std::env::temp_dir().join(format!("cbb-remotepaste-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(load(&dir).unwrap(), Settings::default());
        save(&dir, Settings { on: true, enter: true, ..Default::default() }).unwrap();
        assert_eq!(load(&dir).unwrap(), Settings { on: true, enter: true, ..Default::default() });
        assert_eq!(std::fs::read_to_string(dir.join(SETTINGS_FILE)).unwrap(), "{\"on\":true,\"enter\":true}\n");
        save(&dir, Settings { on: true, no_lock_check: true, ..Default::default() }).unwrap();
        assert_eq!(load(&dir).unwrap(), Settings { on: true, no_lock_check: true, ..Default::default() });
        save(&dir, Settings { on: false, enter: true, console: true, no_lock_check: true }).unwrap();
        assert_eq!(load(&dir).unwrap(), Settings::default(), "Enter stays on when remote paste is off");
        for i in 0..LOG_SIZE + 5 {
            let e = Entry {
                time_ms: i as i64,
                by: i.to_string(),
                len: i,
                method: "paste".into(),
                result: "done".into(),
                ..Default::default()
            };
            append(&dir, e).unwrap();
        }
        let es = read_log(&dir).unwrap();
        assert_eq!((es.len(), es[0].time_ms), (LOG_SIZE, 5));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
