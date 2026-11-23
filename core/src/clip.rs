// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! What a copy is to the clipboards: its kind, how its text reached the
//! member that made it, a member's sync on or off, and a copy as a phone's
//! button and app see it. The copies themselves travel as the core's
//! `copies` seals them (docs/format.md, section 10); the rule of incoming
//! copies is `crate::rule`.

use alloc::format;
use alloc::string::String;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::media::Manifest;

/// The largest text, in bytes, that the group carries.
pub const MAX_TEXT: usize = 1 << 20;

/// Normal text, a secret, such as a password, or images and files.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    #[default]
    Text,
    Secret,
    /// Images or files: a manifest, and maybe a plain-text alternative.
    Media,
}

/// How a text reached the member that made the event.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub enum Via {
    #[default]
    #[serde(rename = "copy")]
    Copy,
    /// Sent from a phone's app.
    #[serde(rename = "phone")]
    Phone,
    #[serde(rename = "universal-clipboard")]
    Universal,
}

/// A copy as a phone's button and app see it: its ID and origin, its age,
/// and its content.
#[derive(Clone, PartialEq, Debug, Default)]
pub struct Event {
    pub id: String,
    pub origin: String,
    /// How long ago, in milliseconds, it was copied.
    pub age: i64,
    pub kind: Kind,
    pub text: String,
    /// The content of a media copy, which only it has.
    pub media: Option<Manifest>,
}

impl Event {
    /// Reports whether this is the mark of a secret: the copy without its
    /// text.
    pub fn is_mark(&self) -> bool {
        self.kind == Kind::Secret && self.text.is_empty()
    }
}

/// Checks a text the group carries: not empty, at most MAX_TEXT bytes.
pub fn check_text(s: &str) -> Result<()> {
    if s.is_empty() {
        return Err(Error::msg("the text is empty"));
    }
    if s.len() > MAX_TEXT {
        return Err(Error::msg(format!("the text of {} bytes is larger than 1 MiB", s.len())));
    }
    Ok(())
}

/// A member's sync, on or off (docs/design.md, "Sync on and off"). It
/// changes nothing else: the member stays connected, keeps the group's
/// current copy and passes copies on either way, and deliberate actions
/// (send) work either way.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Mode {
    /// Sync on: its copies go to the group, and the group's copies reach
    /// its clipboard.
    #[default]
    Shared,
    /// Sync off: neither; the clipboard is the device's own, and the
    /// group's text is at hand on request (current).
    Own,
}

impl Mode {
    pub const ALL: [Mode; 2] = [Mode::Shared, Mode::Own];

    /// Whether the copies a clipboard watcher reports go to the group.
    pub fn sends(self) -> bool {
        self == Mode::Shared
    }

    /// Whether the group's copies are written to the clipboard.
    pub fn receives(self) -> bool {
        self == Mode::Shared
    }

    /// The mode's name, as hellos and the admin's mode command carry it.
    pub fn name(self) -> &'static str {
        match self {
            Mode::Shared => "shared",
            Mode::Own => "own",
        }
    }

    /// Reads a mode's name.
    pub fn parse(s: &str) -> Result<Mode> {
        Mode::ALL
            .into_iter()
            .find(|m| m.name() == s)
            .ok_or_else(|| Error::msg(format!("the sync mode is shared (sync on) or own (sync off), not {s:?}")))
    }
}
