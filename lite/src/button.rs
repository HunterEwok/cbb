// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The one button of a phone's app (docs/design.md, "The one button"), as
//! one rule for every phone: a copy from another device that waits for the
//! phone comes in; otherwise what the phone's clipboard holds goes out,
//! unless it is the group's copy already or what this phone itself sent or
//! took last. The app reads its clipboard only in the second case, as iOS
//! may ask the user first.
//!
//! The clipboard and the group's copy compare by a key: a text by itself,
//! an image by `"\0image:"` and the hex SHA-256 of its PNG or JPEG part,
//! files by `"\0files:"` and the copy's ID.

use std::sync::Mutex;
use std::time::Duration;

use cbb_core::clip::{Event, Kind};

/// What the phone itself sent or took last.
#[derive(Default)]
pub struct Own {
    inner: Mutex<OwnInner>,
}

#[derive(Default)]
struct OwnInner {
    /// The ID of the last copy from another device the phone took.
    taken: Option<String>,
    /// The key of what the phone sent from its clipboard or took into it
    /// last.
    key: Option<String>,
}

impl Own {
    /// The phone took the copy ev into its clipboard, or saved its files,
    /// which leaves the clipboard as it was.
    pub fn took(&self, ev: &Event) {
        let mut st = self.inner.lock().unwrap();
        st.taken = Some(ev.id.clone());
        if !ev.media.as_ref().is_some_and(|m| m.files()) {
            st.key = key_of(ev);
        }
    }

    /// The phone sent what its clipboard holds, by its key.
    pub fn sent(&self, key: &str) {
        self.inner.lock().unwrap().key = Some(key.to_string());
    }

    fn taken(&self) -> Option<String> {
        self.inner.lock().unwrap().taken.clone()
    }

    fn key(&self) -> Option<String> {
        self.inner.lock().unwrap().key.clone()
    }
}

/// The key the button compares the group's copy ev by; None for a copy
/// with nothing the phone could hold.
pub fn key_of(ev: &Event) -> Option<String> {
    if ev.unread || ev.is_mark() {
        return None;
    }
    match (&ev.kind, &ev.media) {
        (Kind::Media, Some(m)) if m.files() => Some(format!("\0files:{}", ev.id)),
        (Kind::Media, Some(m)) => m
            .parts
            .iter()
            .find(|p| p.kind == "image/png" || p.kind == "image/jpeg")
            .and_then(|p| p.sha256.as_ref())
            .map(|sum| format!("\0image:{}", hex(sum))),
        _ if !ev.text.is_empty() => Some(ev.text.clone()),
        _ => None,
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The copy from another device that waits for the phone: the group's
/// current one, not this phone's own, younger than the live window, with
/// something to hold, and not taken yet.
pub fn waiting(current: Option<Event>, me: &str, window: Duration, own: &Own) -> Option<Event> {
    let ev = current?;
    let live = u128::try_from(ev.age.max(0)).unwrap_or(0) < window.as_millis();
    let fresh = own.taken().as_deref() != Some(ev.id.as_str());
    (ev.origin != me && live && fresh && key_of(&ev).is_some()).then_some(ev)
}

/// Whether the button sends the clipboard's key: not empty, not the group's
/// copy already, and not what this phone itself sent or took last. Without
/// the last, a text the phone sent before it shared an image or files would
/// go out again over that newer copy, as the group's copy is then the image
/// or the files.
pub fn sends(board: &str, current: Option<&Event>, own: &Own) -> bool {
    !board.is_empty() && current.and_then(key_of).as_deref() != Some(board) && own.key().as_deref() != Some(board)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use cbb_core::clip::{Event, Kind};
    use cbb_core::media::{Manifest, Part};

    use super::{Own, key_of, sends, waiting};

    const ME: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const PC: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const WINDOW: Duration = Duration::from_secs(60);

    fn text(id: &str, origin: &str, text: &str, age: i64) -> Event {
        Event { id: id.into(), origin: origin.into(), kind: Kind::Text, text: text.into(), age, ..Event::default() }
    }

    fn files(id: &str, origin: &str) -> Event {
        Event {
            id: id.into(),
            origin: origin.into(),
            kind: Kind::Media,
            media: Some(Manifest {
                size: 1,
                parts: vec![Part { path: "a.txt".into(), size: 1, sha256: Some(vec![0; 32]), ..Part::default() }],
            }),
            ..Event::default()
        }
    }

    #[test]
    fn a_copy_waits() {
        let own = Own::default();
        assert!(waiting(Some(text("e", PC, "from the pc", 1_000)), ME, WINDOW, &own).is_some());
        // Past the live window, the phone's own copy, and a copy taken already never wait.
        assert!(waiting(Some(text("e", PC, "from the pc", 60_000)), ME, WINDOW, &own).is_none());
        assert!(waiting(Some(text("e", ME, "sent", 1_000)), ME, WINDOW, &own).is_none());
        own.took(&text("e", PC, "from the pc", 1_000));
        assert!(waiting(Some(text("e", PC, "from the pc", 1_000)), ME, WINDOW, &own).is_none());
        // Nor one with nothing to hold.
        let mut unread = text("f", PC, "", 1_000);
        unread.unread = true;
        assert!(waiting(Some(unread), ME, WINDOW, &Own::default()).is_none());
        assert!(waiting(None, ME, WINDOW, &Own::default()).is_none());
    }

    #[test]
    fn the_button_sends() {
        let own = Own::default();
        let cur = text("e", PC, "from the pc", 90_000);
        // What the phone copied goes, however old, unless it is the group's copy already.
        assert!(sends("on the phone", Some(&cur), &own));
        assert!(sends("first", None, &own));
        assert!(!sends("from the pc", Some(&cur), &own));
        assert!(!sends("", None, &own));
    }

    #[test]
    fn the_button_keeps_what_the_phone_sent() {
        // The phone sent a text, then shared files: the group's copy is the
        // files, the clipboard still the text, which must not go over them.
        let own = Own::default();
        own.sent("sent before");
        let f = files("f", ME);
        assert_eq!(key_of(&f).as_deref(), Some("\0files:f"));
        assert!(!sends("sent before", Some(&f), &own));
        assert!(sends("copied since", Some(&f), &own));
        // Saving files leaves the clipboard, and what it sent, as they were.
        own.took(&files("g", PC));
        assert!(!sends("sent before", Some(&files("g", PC)), &own));
        // Nor a text the phone took and then saw replaced.
        let own = Own::default();
        own.took(&text("e", PC, "from the pc", 1_000));
        assert!(!sends("from the pc", Some(&text("g", PC, "newer", 1_000)), &own));
    }

    #[test]
    fn an_image_by_its_hash() {
        let mut ev = files("i", PC);
        ev.media = Some(Manifest {
            size: 1,
            parts: vec![Part { kind: "image/png".into(), size: 1, sha256: Some(vec![0xab; 32]), ..Part::default() }],
        });
        assert_eq!(key_of(&ev), Some(format!("\0image:{}", "ab".repeat(32))));
    }
}
