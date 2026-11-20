// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The clipboard's side of the member of 0.6: what a watcher reports and
//! what the group's copies bring, and the rule between them. A copy's
//! seal, signature and freshness are the core's (`cbb_core::copies`,
//! `mesh`); this keeps the mode, sync turned off, an admin's mute, the
//! clipboard's own content and the group's current copy, and asks the
//! rule of incoming copies (`cbb_core::rule`) whether new content goes into
//! the clipboard. It stands where the engine of 0.5 (`cbb_core::clip`)
//! stands until the service switches.

use std::collections::VecDeque;
use std::sync::Mutex;

use cbb_core::clip::{Kind, Mode, Via};
use cbb_core::content::Content;
use cbb_core::media::Manifest;
use cbb_core::records::DeviceId;
use cbb_core::rule::{self, Incoming, Verdict};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::mesh::Arrived;
use crate::sealed::Blob;

/// How long after a copy content from another member still goes into the
/// clipboard, unless the group sets its own window.
pub const LIVE_WINDOW_MS: u64 = 60_000;
/// How long a secret stays current unless the group says otherwise.
pub const SECRET_TTL_MS: u64 = 60_000;
/// A watcher's report of what this member wrote itself, within this time,
/// is the member's own write coming back, not a copy.
const ECHO_MS: i64 = 10_000;
/// The writes remembered for that.
const WRITTEN: usize = 16;

/// The group's current copy as this member took it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Current {
    /// The copy's ID, which a paste of images or files names.
    pub id: [u8; 16],
    pub content: Content,
    pub origin: DeviceId,
    /// Its blob of images or files, and the member it came from.
    pub blob: Option<Blob>,
    pub from: DeviceId,
    /// When it became current here, on the wall clock.
    pub at_ms: i64,
}

/// What this member's own clipboard holds, as it knows it.
#[derive(Clone)]
struct Local {
    sum: [u8; 32],
    text: String,
    kind: Kind,
    media: Option<Manifest>,
    at: i64,
}

struct Inner {
    mode: Mode,
    /// While sync is off: when it turns back on, 0 for until it is turned on.
    off_until: i64,
    /// An admin's mute until a wall time, 0 for until it is lifted.
    mute: Option<i64>,
    /// What the clipboard holds as this member knows it, and since when.
    local: Option<Local>,
    current: Option<Current>,
    written: VecDeque<([u8; 32], i64)>,
    window_ms: u64,
    secret_ms: u64,
    takes_media: bool,
}

/// One member's clipboard state; safe for concurrent use.
pub struct Board {
    wall: Box<dyn Fn() -> i64 + Send + Sync>,
    inner: Mutex<Inner>,
}

fn sum(text: &str) -> [u8; 32] {
    Sha256::digest(text.as_bytes()).into()
}

fn content(text: &str, kind: Kind, via: Via) -> Result<Content> {
    if kind == Kind::Media {
        return Err(Error::msg("images and files go as media, not as text"));
    }
    cbb_core::clip::check_text(text)?;
    let mut c = Content::text(text, kind == Kind::Secret);
    c.via = match via {
        Via::Phone => 1,
        Via::Universal => 2,
        _ => 0,
    };
    Ok(c)
}

fn local(text: &str, kind: Kind, at: i64) -> Local {
    Local { sum: sum(text), text: text.to_string(), kind, media: None, at }
}

impl Board {
    pub fn new(wall: Box<dyn Fn() -> i64 + Send + Sync>) -> Board {
        Board {
            wall,
            inner: Mutex::new(Inner {
                mode: Mode::Shared,
                off_until: 0,
                mute: None,
                local: None,
                current: None,
                written: VecDeque::new(),
                window_ms: LIVE_WINDOW_MS,
                secret_ms: SECRET_TTL_MS,
                takes_media: false,
            }),
        }
    }

    fn mode_now(&self, st: &mut Inner) -> Mode {
        if st.mode == Mode::Own && st.off_until != 0 && (self.wall)() >= st.off_until {
            st.mode = Mode::Shared;
            st.off_until = 0;
        }
        st.mode
    }

    fn muted(&self, st: &mut Inner) -> bool {
        if !rule::holds(st.mute, (self.wall)()) {
            st.mute = None;
        }
        st.mute.is_some()
    }

    pub fn mode(&self) -> Mode {
        let mut st = self.inner.lock().unwrap();
        self.mode_now(&mut st)
    }

    pub fn set_mode(&self, m: Mode) {
        let mut st = self.inner.lock().unwrap();
        st.mode = m;
        st.off_until = 0;
    }

    /// Turns sync on, or off until `until_ms` (0 for until it is turned on).
    pub fn set_sync(&self, on: bool, until_ms: i64) {
        let mut st = self.inner.lock().unwrap();
        st.mode = if on { Mode::Shared } else { Mode::Own };
        st.off_until = if on { 0 } else { until_ms };
    }

    /// Whether sync is on, and when it turns back on while off.
    pub fn sync(&self) -> (bool, i64) {
        let mut st = self.inner.lock().unwrap();
        let on = self.mode_now(&mut st) == Mode::Shared;
        (on, st.off_until)
    }

    pub fn set_mute(&self, until_ms: i64) {
        self.inner.lock().unwrap().mute = Some(until_ms);
    }

    pub fn unmute(&self) {
        self.inner.lock().unwrap().mute = None;
    }

    /// While muted: when the mute ends, 0 for until it is lifted.
    pub fn mute_left(&self) -> Option<i64> {
        let mut st = self.inner.lock().unwrap();
        if self.muted(&mut st) { st.mute } else { None }
    }

    /// The group's window for incoming copies and lifetime of secrets;
    /// zero keeps the defaults.
    pub fn set_lifetimes(&self, window_ms: u64, secret_ms: u64) {
        let mut st = self.inner.lock().unwrap();
        st.window_ms = if window_ms == 0 { LIVE_WINDOW_MS } else { window_ms };
        st.secret_ms = if secret_ms == 0 { SECRET_TTL_MS } else { secret_ms };
    }

    /// The window and the lifetime of secrets now.
    pub fn lifetimes(&self) -> (u64, u64) {
        let st = self.inner.lock().unwrap();
        (st.window_ms, st.secret_ms)
    }

    pub fn set_takes_media(&self, on: bool) {
        self.inner.lock().unwrap().takes_media = on;
    }

    /// The group's current copy.
    pub fn current(&self) -> Option<Current> {
        self.inner.lock().unwrap().current.clone()
    }

    /// A watcher reported the clipboard changed: the content to send to
    /// the group, or None when it did not change for the group (this
    /// member's own write coming back, the same text again, sync off or a
    /// mute).
    pub fn copied(&self, text: &str, kind: Kind, via: Via) -> Result<Option<Content>> {
        let c = content(text, kind, via)?;
        let mut st = self.inner.lock().unwrap();
        let now = (self.wall)();
        let s = sum(text);
        let echo = st.written.iter().any(|(w, at)| *w == s && now.saturating_sub(*at) <= ECHO_MS);
        if echo || st.local.as_ref().is_some_and(|l| l.sum == s && l.media.is_none()) {
            return Ok(None);
        }
        st.local = Some(local(text, kind, now));
        if !self.mode_now(&mut st).sends() || self.muted(&mut st) {
            return Ok(None);
        }
        Ok(Some(c))
    }

    /// A deliberate send (cbb send, a phone's paste): always content,
    /// unless this member is muted.
    pub fn send(&self, text: &str, kind: Kind, via: Via) -> Result<Content> {
        let c = content(text, kind, via)?;
        let mut st = self.inner.lock().unwrap();
        if self.muted(&mut st) {
            return Err(Error::msg("this device is muted: its copies do not reach the group until the mute ends"));
        }
        let now = (self.wall)();
        st.local = Some(local(text, kind, now));
        Ok(c)
    }

    /// The watcher says what the clipboard holds, without a copy: at its
    /// start, or after a write of its own. Images or files are never only
    /// told.
    pub fn clipboard_is(&self, text: &str, kind: Kind) {
        let mut st = self.inner.lock().unwrap();
        st.local =
            (kind != Kind::Media && cbb_core::clip::check_text(text).is_ok()).then(|| local(text, kind, (self.wall)()));
    }

    /// Images or files this member copied (`Mesh::copy_media` sends them):
    /// they are the clipboard's content now, with their plain-text
    /// alternative.
    pub fn copied_media(&self, manifest: &Manifest, alt: &str) {
        let mut st = self.inner.lock().unwrap();
        let now = (self.wall)();
        let mut l = local(alt, Kind::Media, now);
        l.media = Some(manifest.clone());
        st.local = Some(l);
    }

    /// The text of this member's own clipboard, its kind and when it was
    /// copied, on the wall clock; None when unknown or a secret past its
    /// lifetime. For images or files, their plain-text alternative.
    pub fn local(&self) -> Option<(String, Kind, i64)> {
        let st = self.inner.lock().unwrap();
        let l = st.local.as_ref()?;
        let gone = l.kind == Kind::Secret
            && (self.wall)().saturating_sub(l.at) >= i64::try_from(st.secret_ms).unwrap_or(i64::MAX);
        if gone || l.text.is_empty() {
            return None;
        }
        let kind = if l.kind == Kind::Media { Kind::Text } else { l.kind };
        Some((l.text.clone(), kind, l.at))
    }

    /// The images or files of this member's own clipboard, with their
    /// plain-text alternative and when they were copied.
    pub fn local_media(&self) -> Option<(Manifest, String, i64)> {
        let st = self.inner.lock().unwrap();
        let l = st.local.as_ref()?;
        Some((l.media.clone()?, l.text.clone(), l.at))
    }

    /// New content a peer's copy brought (the core judged it fresh, with
    /// its age): the rule's verdict; it is the group's current copy, and on
    /// `Write` the caller writes it to the clipboard.
    pub fn received(&self, a: &Arrived) -> Verdict {
        let (c, age_ms) = (&a.content, a.age_ms);
        let mut st = self.inner.lock().unwrap();
        let now = (self.wall)();
        let text = c.text.as_deref().unwrap_or_default();
        let held = !text.is_empty() && c.manifest.is_none() && st.local.as_ref().is_some_and(|l| l.sum == sum(text));
        let i = Incoming {
            receives: self.mode_now(&mut st).receives(),
            kind: if c.is_secret() { Kind::Secret } else { Kind::Text },
            mark: false,
            unread: !c.writable(),
            has_text: !text.is_empty(),
            has_media: c.manifest.is_some(),
            takes_media: st.takes_media,
            held,
            age_ms: i64::try_from(age_ms).unwrap_or(i64::MAX),
            before_start: false,
            window_ms: i64::try_from(st.window_ms).unwrap_or(i64::MAX),
            secret_ttl_ms: i64::try_from(st.secret_ms).unwrap_or(i64::MAX),
        };
        let v = rule::incoming(&i);
        st.current =
            Some(Current { id: a.id, content: c.clone(), origin: a.origin, blob: a.blob, from: a.from, at_ms: now });
        if v == Verdict::Write {
            let s = sum(text);
            let mut l = local(text, if c.is_secret() { Kind::Secret } else { Kind::Text }, now);
            if let Some(m) = &c.manifest {
                l.kind = Kind::Media;
                l.media = Some(m.clone());
            }
            st.local = Some(l);
            st.written.push_back((s, now));
            while st.written.len() > WRITTEN {
                st.written.pop_front();
            }
        }
        v
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicI64, Ordering};

    use super::*;

    fn arrived(c: Content, origin: DeviceId, age_ms: u64) -> Arrived {
        Arrived { id: [3; 16], content: c, origin, age_ms, blob: None, from: origin }
    }

    fn board() -> (Board, Arc<AtomicI64>) {
        let t = Arc::new(AtomicI64::new(1_000_000));
        let t2 = t.clone();
        (Board::new(Box::new(move || t2.load(Ordering::SeqCst))), t)
    }

    #[test]
    fn a_copy_goes_out_once_and_its_echo_stays_home() {
        let (b, _) = board();
        assert!(b.copied("hello", Kind::Text, Via::Copy).unwrap().is_some());
        assert!(b.copied("hello", Kind::Text, Via::Copy).unwrap().is_none(), "the same text again");
        let peer = DeviceId([1; 16]);
        assert_eq!(b.received(&arrived(Content::text("from peer", false), peer, 10)), Verdict::Write);
        assert_eq!(b.current().unwrap().origin, peer);
        // The watcher sees the member's own write: not sent back.
        assert!(b.copied("from peer", Kind::Text, Via::Copy).unwrap().is_none());
    }

    #[test]
    fn sync_off_and_a_mute_keep_copies_home() {
        let (b, t) = board();
        b.set_sync(false, 1_000_500);
        assert!(b.copied("a", Kind::Text, Via::Copy).unwrap().is_none());
        assert_eq!(b.received(&arrived(Content::text("x", false), DeviceId([1; 16]), 0)), Verdict::Mode);
        t.store(1_000_600, Ordering::SeqCst);
        assert_eq!(b.sync(), (true, 0), "sync comes back on by itself");
        b.set_mute(0);
        assert!(b.copied("b", Kind::Text, Via::Copy).unwrap().is_none());
        assert!(b.send("c", Kind::Text, Via::Copy).is_err());
        b.unmute();
        assert!(b.send("c", Kind::Text, Via::Copy).is_ok());
    }

    #[test]
    fn the_board_knows_what_the_clipboard_holds() {
        let (b, t) = board();
        b.clipboard_is("told", Kind::Text);
        assert_eq!(b.local().map(|l| l.0), Some("told".into()));
        assert!(b.copied("told", Kind::Text, Via::Copy).unwrap().is_none(), "told already");
        b.copied("pin", Kind::Secret, Via::Copy).unwrap();
        assert_eq!(b.local().map(|l| l.1), Some(Kind::Secret));
        t.fetch_add(SECRET_TTL_MS as i64, Ordering::SeqCst);
        assert!(b.local().is_none(), "a secret past its lifetime");
        let m = Manifest { size: 3, parts: Vec::new() };
        b.copied_media(&m, "a picture");
        assert_eq!(b.local_media().map(|l| (l.0, l.1)), Some((m, "a picture".into())));
        assert_eq!(b.local().map(|l| l.1), Some(Kind::Text), "media shows as its alternative");
    }

    #[test]
    fn an_old_copy_or_a_state_is_not_written() {
        let (b, _) = board();
        let peer = DeviceId([1; 16]);
        assert_eq!(b.received(&arrived(Content::text("old", false), peer, LIVE_WINDOW_MS + 1)), Verdict::Old);
        assert_eq!(b.received(&arrived(Content::state(&[0xa0]), peer, 0)), Verdict::Unread);
        let mut secret = Content::text("pin", true);
        secret.ttl = 0;
        assert_eq!(b.received(&arrived(secret, peer, SECRET_TTL_MS)), Verdict::SecretGone);
    }
}
