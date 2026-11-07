// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The rule of incoming copies (docs/protocol.md, section 5, "Writing to
//! the clipboard"): whether the group's current copy goes into a member's
//! clipboard, and whether a mute or a pause holds. The lite member's engine
//! (crate::clip) asks it, and the Go service asks it through the core's
//! `copy_verdict`, so that every member keeps one rule; the cases of
//! testdata/interop/copy-verdicts.json pin it, and Go's own copy of it,
//! which a build without the core runs, reads the same cases.

use serde::{Deserialize, Serialize};

use crate::clip::Kind;

/// What a member knows of the group's current copy when it decides.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Incoming {
    /// The member's mode lets the group's copies in.
    pub receives: bool,
    /// Its user paused receiving, and the pause holds.
    #[serde(default)]
    pub paused: bool,
    pub kind: Kind,
    /// Only the mark of a secret came, without its payload.
    #[serde(default)]
    pub mark: bool,
    /// The copy is not sealed to this member, or did not open here.
    #[serde(default)]
    pub unread: bool,
    #[serde(default)]
    pub has_text: bool,
    /// The copy carries images or files.
    #[serde(default)]
    pub has_media: bool,
    /// This member writes images and files to its clipboard (the Go
    /// service does; the lite member takes only a copy's text).
    #[serde(default)]
    pub takes_media: bool,
    /// The clipboard already holds the copy's content.
    #[serde(default)]
    pub held: bool,
    /// How long ago, on this member's clock, the copy was made.
    pub age_ms: i64,
    /// How long a copy stays live: the group's `copies` setting.
    pub window_ms: i64,
    /// How long a secret stays current.
    pub secret_ttl_ms: i64,
}

/// The verdict on an incoming copy: `Write`, or why not.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Write,
    /// The mode keeps the group's copies out.
    Mode,
    /// The user paused receiving.
    Paused,
    /// Only a mark, or a copy this member does not read.
    Unread,
    /// A secret past its time.
    SecretGone,
    /// Images or files without a text, on a member that takes only text.
    NoText,
    /// The clipboard holds it already.
    Held,
    /// Older than the live window: the member's own clipboard stays.
    Old,
}

/// Decides whether the copy goes into the clipboard.
pub fn incoming(i: &Incoming) -> Verdict {
    if !i.receives {
        Verdict::Mode
    } else if i.paused {
        Verdict::Paused
    } else if i.mark || i.unread {
        Verdict::Unread
    } else if i.kind == Kind::Secret && i.age_ms >= i.secret_ttl_ms {
        Verdict::SecretGone
    } else if !i.has_text && !(i.takes_media && i.has_media) {
        Verdict::NoText
    } else if i.held {
        Verdict::Held
    } else if i.age_ms >= i.window_ms {
        Verdict::Old
    } else {
        Verdict::Write
    }
}

/// Whether a mute or a pause set until `until_ms` on the wall clock (0 for
/// until it is lifted, None for none) holds at `now_ms`.
pub fn holds(until_ms: Option<i64>, now_ms: i64) -> bool {
    match until_ms {
        None => false,
        Some(0) => true,
        Some(u) => now_ms < u,
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::String;
    use alloc::vec::Vec;

    use serde::Deserialize;

    use super::*;

    #[derive(Deserialize)]
    struct Case {
        name: String,
        #[serde(default)]
        incoming: Option<Incoming>,
        #[serde(default)]
        verdict: Option<String>,
        #[serde(default)]
        until_ms: Option<i64>,
        #[serde(default)]
        now_ms: i64,
        #[serde(default)]
        holds: Option<bool>,
    }

    /// Every case of testdata/interop/copy-verdicts.json, which Go's copy
    /// of the rule reads too.
    #[test]
    fn vectors() {
        let raw = include_str!("../../testdata/interop/copy-verdicts.json");
        #[derive(Deserialize)]
        struct File {
            cases: Vec<Case>,
        }
        let f: File = serde_json::from_str(raw).unwrap();
        assert!(f.cases.len() > 10);
        for c in f.cases {
            if let Some(i) = &c.incoming {
                let got = serde_json::to_value(incoming(i)).unwrap();
                assert_eq!(got.as_str(), c.verdict.as_deref(), "{}", c.name);
            }
            if let Some(h) = c.holds {
                assert_eq!(holds(c.until_ms, c.now_ms), h, "{}", c.name);
            }
        }
    }
}
