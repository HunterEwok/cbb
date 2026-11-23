// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The one button of a phone's app and its opening (docs/design.md, "The
//! one button"; D-128), as one rule for every phone. The gesture swaps
//! the phone's clipboard and the group's copy: what the clipboard holds
//! goes out, unless it is empty, the group's copy already, or what this
//! phone itself sent or took last (the app's own writes are never
//! copies), and the group's copy comes in. Opening the app swaps nothing:
//! a clipboard that changed since the app last saw it goes out, as a
//! watcher reports a copy; otherwise the group's copy comes in.
//!
//! The clipboard and the group's copy compare by a key: a text by itself,
//! an image by `"\0image:"` and the hex SHA-256 of its PNG or JPEG part,
//! files by `"\0files:"` and the copy's ID.

use std::sync::Mutex;

use cbb_core::clip::{Event, Kind};

/// What the phone itself sent or took last.
#[derive(Default)]
pub struct Own {
    inner: Mutex<OwnInner>,
}

#[derive(Default)]
struct OwnInner {
    /// The key of what the phone sent from its clipboard or took into it
    /// last.
    key: Option<String>,
}

impl Own {
    /// The phone took the copy ev into its clipboard, or saved its files,
    /// which leaves the clipboard as it was.
    pub fn took(&self, ev: &Event) {
        let mut st = self.inner.lock().unwrap();
        if !ev.media.as_ref().is_some_and(|m| m.files()) {
            st.key = key_of(ev);
        }
    }

    /// The phone sent what its clipboard holds, by its key.
    pub fn sent(&self, key: &str) {
        self.inner.lock().unwrap().key = Some(key.to_string());
    }

    fn key(&self) -> Option<String> {
        self.inner.lock().unwrap().key.clone()
    }
}

/// The key the button compares the group's copy ev by; None for a copy
/// with nothing the phone could hold.
pub fn key_of(ev: &Event) -> Option<String> {
    if ev.is_mark() {
        return None;
    }
    match (&ev.kind, &ev.media) {
        (Kind::Media, Some(m)) if m.files() => Some(format!("\0files:{}", ev.id)),
        (Kind::Media, Some(m)) => m
            .parts
            .iter()
            .find(|p| p.kind == "image/png" || p.kind == "image/jpeg" || p.kind == "image/gif")
            .and_then(|p| p.sha256.as_ref())
            .map(|sum| format!("\0image:{}", hex(sum))),
        _ if !ev.text.is_empty() => Some(ev.text.clone()),
        _ => None,
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// What a gesture or an opening does: whether the phone's clipboard goes
/// to the group, and the group's copy that comes into it, if any.
pub struct Swap {
    pub sends: bool,
    pub takes: Option<Event>,
}

/// The gesture: the clipboard's key goes out when [`sends`] says so, and
/// the group's copy as it was comes in unless the clipboard holds it.
pub fn swap(board: &str, current: Option<Event>, own: &Own) -> Swap {
    Swap { sends: sends(board, current.as_ref(), own), takes: takes(board, current) }
}

/// The app opened: a clipboard that changed since the app last saw it
/// goes out when [`sends`] says so, and nothing comes in; otherwise the
/// group's copy comes in unless the clipboard holds it.
pub fn opened(board: &str, changed: bool, current: Option<Event>, own: &Own) -> Swap {
    if changed && sends(board, current.as_ref(), own) {
        return Swap { sends: true, takes: None };
    }
    Swap { sends: false, takes: takes(board, current) }
}

/// The group's copy, when it has something the phone can hold and the
/// clipboard does not hold it already.
fn takes(board: &str, current: Option<Event>) -> Option<Event> {
    current.filter(|e| key_of(e).is_some_and(|k| k != board))
}

/// Whether the clipboard's key goes out: not empty, not the group's copy
/// already, and not what this phone itself sent or took last. Without the
/// last, a text the phone took would go back over a newer copy, and a
/// text the phone sent before it shared an image or files would go out
/// again over them.
pub fn sends(board: &str, current: Option<&Event>, own: &Own) -> bool {
    !board.is_empty() && current.and_then(key_of).as_deref() != Some(board) && own.key().as_deref() != Some(board)
}

#[cfg(test)]
mod tests {
    use cbb_core::clip::{Event, Kind};
    use cbb_core::media::{Manifest, Part};

    use super::{Own, key_of, opened, sends, swap};

    const ME: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const PC: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

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
    fn the_gesture_swaps() {
        let own = Own::default();
        // However old the group's copy, the phone's text goes and the group's comes.
        let s = swap("on the phone", Some(text("e", PC, "from the pc", 3_600_000)), &own);
        assert!(s.sends);
        assert_eq!(s.takes.map(|e| e.text).as_deref(), Some("from the pc"));
        // An empty clipboard only takes the group's text.
        let s = swap("", Some(text("e", PC, "from the pc", 1_000)), &own);
        assert!(!s.sends);
        assert!(s.takes.is_some());
        // A clipboard that holds the group's text already changes nothing.
        let s = swap("from the pc", Some(text("e", PC, "from the pc", 1_000)), &own);
        assert!(!s.sends && s.takes.is_none());
        // The first copy of a group only goes.
        let s = swap("first", None, &own);
        assert!(s.sends && s.takes.is_none());
        // Nor does a copy with nothing to hold come in.
        assert!(swap("x", Some(text("f", PC, "", 1_000)), &own).takes.is_none());
    }

    #[test]
    fn what_the_app_wrote_is_no_copy() {
        // The phone took a text and a computer copied a newer one since: the
        // gesture takes the newer one and does not send the app's own write back.
        let own = Own::default();
        own.took(&text("e", PC, "from the pc", 1_000));
        let s = swap("from the pc", Some(text("g", PC, "newer", 1_000)), &own);
        assert!(!s.sends);
        assert_eq!(s.takes.map(|e| e.text).as_deref(), Some("newer"));
    }

    #[test]
    fn opening_listens() {
        let own = Own::default();
        let cur = Some(text("e", PC, "from the pc", 1_000));
        // A clipboard that changed since the app last saw it goes, and nothing comes.
        let s = opened("copied meanwhile", true, cur.clone(), &own);
        assert!(s.sends && s.takes.is_none());
        // One that did not change takes the group's copy, and sends nothing old back.
        let s = opened("old text", false, cur.clone(), &own);
        assert!(!s.sends);
        assert_eq!(s.takes.map(|e| e.text).as_deref(), Some("from the pc"));
        // A change to the group's own text is no copy either.
        let s = opened("from the pc", true, cur, &own);
        assert!(!s.sends && s.takes.is_none());
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
