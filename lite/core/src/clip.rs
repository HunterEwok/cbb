// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The sync engine: the group's current event on this member and what goes
//! into the member's own clipboard (docs/protocol.md, section 5). It follows
//! Go's package clip, so a lite member behaves as the others do; it only
//! decides, and the caller does the networking.

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::format;
use alloc::string::{String, ToString};
use core::time::Duration;

use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::certs::{is_id, random_bytes, random_id};
use crate::copy::{Blob, KEY_SIZE, Sealed};
use crate::error::{Error, Result};
use crate::hlc::{Clock, Timestamp};
use crate::media::{MAX_ALT_TEXT, Manifest};
use crate::sync::Mutex;

/// The largest text, in bytes, that the group carries.
pub const MAX_TEXT: usize = 1 << 20;
const SECRET_TTL: Duration = Duration::from_secs(60);
/// How long after the copy an event from another member is still written
/// to the local clipboard, unless the group's records set another
/// (`Engine::set_live_window`).
pub const LIVE_WINDOW: Duration = Duration::from_secs(60);
const SECRET_MEMORY: Duration = Duration::from_secs(12 * 3600);
const ECHO_WINDOW: Duration = Duration::from_secs(10);
const MAX_AGE_MS: i64 = 365 * 24 * 3600 * 1000;
const MAX_SECRETS: usize = 4096;
const SEEN_IDS: usize = 4096;
const AHEAD: &str = "the event's time is more than 7 days ahead of this device's clock; check the sender's date";

/// Normal text, a secret, such as a password, or images and files.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    #[default]
    Text,
    Secret,
    /// Images or files: a manifest, and maybe a plain-text alternative,
    /// which is all a lite member takes of them.
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

impl Via {
    fn is_copy(&self) -> bool {
        *self == Via::Copy
    }
}

/// One copy as the engine holds it: its header, and its content once this
/// member opened it. It travels sealed (crate::copy::Sealed).
#[derive(Clone, PartialEq, Debug, Default, Serialize, Deserialize)]
pub struct Event {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub origin: String,
    #[serde(default, skip_serializing_if = "Via::is_copy")]
    pub via: Via,
    #[serde(default)]
    pub time: Timestamp,
    #[serde(rename = "age_ms", default)]
    pub age: i64,
    #[serde(default)]
    pub kind: Kind,
    #[serde(default)]
    pub text: String,
    /// The content of a media event, which only it has.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media: Option<Manifest>,
    /// The copy as it travels, sealed end to end (docs/protocol.md,
    /// section 4); None for an event of an engine without a sealer, as in
    /// tests of the engine alone.
    #[serde(skip)]
    pub sealed: Option<Sealed>,
    /// This member does not know the event's content: it is a mark, or a
    /// copy not sealed to this member. kind, via, text and media are then
    /// empty, and the event is current only for ordering.
    #[serde(skip)]
    pub unread: bool,
    /// The copy's key, which opens its blob, when this member opened it.
    #[serde(skip)]
    pub key: Option<[u8; KEY_SIZE]>,
    /// The sealed blob of a media copy this member makes, which its sealer
    /// names in the copy; the copy's `key` sealed it.
    #[serde(skip)]
    pub blob: Option<Blob>,
}

impl Event {
    /// The engine's event of a copy that arrived sealed, before it is
    /// opened: its header, unread.
    pub fn of(s: Sealed) -> Event {
        Event {
            id: s.id.clone(),
            origin: s.origin.clone(),
            time: s.time,
            age: s.age,
            sealed: Some(s),
            unread: true,
            ..Event::default()
        }
    }

    /// Reports whether this is the mark of a secret: the event without its
    /// payload, or, unsealed, without its text.
    pub fn is_mark(&self) -> bool {
        match &self.sealed {
            Some(s) => s.is_mark(),
            None => self.kind == Kind::Secret && self.text.is_empty(),
        }
    }

    /// The mark of a secret: the event without its payload, or, unsealed,
    /// without its text.
    pub fn mark(&self) -> Event {
        let mut m = self.clone();
        m.text.clear();
        m.key = None;
        m.sealed = self.sealed.as_ref().map(Sealed::mark);
        m
    }

    /// Reports whether f has the payload whose hash the mark self carries.
    fn same_payload(&self, f: &Event) -> bool {
        match (&self.sealed, &f.sealed) {
            (Some(a), Some(b)) => a.payload_hash() == b.payload_hash(),
            (None, None) => true,
            _ => false,
        }
    }

    /// Checks an event received from another member.
    pub fn validate(&self) -> Result<()> {
        if self.unread {
            if self.sealed.is_none() {
                return Err(Error::msg("an unread event without its sealed copy"));
            }
            if !is_id(&self.id) || !is_id(&self.origin) || self.time.is_zero() || !self.time.valid() || self.age < 0 {
                return Err(Error::msg("bad event ID, origin, timestamp or age"));
            }
            return Ok(());
        }
        if !is_id(&self.id) {
            return Err(Error::msg("bad event ID"));
        }
        if !is_id(&self.origin) {
            return Err(Error::msg("bad origin device ID"));
        }
        if self.time.is_zero() || !self.time.valid() {
            return Err(Error::msg("bad timestamp"));
        }
        if self.age < 0 {
            return Err(Error::msg(format!("negative event age {} ms", self.age)));
        }
        if (self.kind == Kind::Media) != self.media.is_some() {
            return Err(Error::msg("only a media event has a manifest, and it always does"));
        }
        if self.is_mark() {
            return Ok(());
        }
        if let Some(m) = &self.media {
            m.validate()?;
            if self.text.is_empty() {
                return Ok(());
            }
            if self.text.len() > MAX_ALT_TEXT {
                return Err(Error::msg(format!(
                    "a media event's text of {} bytes is larger than 256 KiB",
                    self.text.len()
                )));
            }
        }
        check_text(&self.text)
    }

    /// Reports whether self sorts after f: by timestamp, then by ID.
    pub fn later(&self, f: &Event) -> bool {
        if self.time != f.time {
            return self.time > f.time;
        }
        self.id > f.id
    }
}

pub fn check_text(s: &str) -> Result<()> {
    if s.is_empty() {
        return Err(Error::msg("the text is empty"));
    }
    if s.len() > MAX_TEXT {
        return Err(Error::msg(format!("the text of {} bytes is larger than 1 MiB", s.len())));
    }
    Ok(())
}

/// A member's sync, on or off (docs/design.md, "Sync on and off"), as Go's
/// clip.Mode. It changes nothing else: the member stays connected, keeps
/// the group's current event and forwards events either way, and
/// deliberate actions (send) work either way.
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

/// What a member sends when a connection starts.
#[derive(Clone, Debug, Default)]
pub struct Hello {
    pub wall: i64,
    pub current: Option<Event>,
}

/// What to do with an event that came in.
#[derive(Clone, Debug, Default)]
pub struct Outcome {
    /// The event to send on to the other members, if anything is new.
    pub forward: Option<Event>,
    /// Write the event's text to the local clipboard.
    pub write: bool,
    /// Orders the writes.
    pub seq: u64,
}

#[derive(Clone, Default)]
struct Local {
    text: String, // empty when unknown
    kind: Kind,
    at: Duration,
}

type Sum = [u8; 32];

struct Inner {
    current: Event,
    copied_at: Duration,
    local: Local,
    seen: BTreeSet<String>,
    seen_order: VecDeque<String>,
    written: VecDeque<(Sum, Duration)>,
    secrets: BTreeMap<Sum, Duration>,
    seq: u64,
    skews: BTreeMap<String, i64>,
    peers: BTreeMap<String, usize>,
    window: Duration,
    mode: Mode,
    /// While sync is off: the wall time in milliseconds it turns back on
    /// at, 0 for until it is turned on.
    off_until: i64,
    /// An admin's mute, which keeps this member's copies from the group
    /// (design.md, "Muting a device"), until a wall time in milliseconds,
    /// 0 for until it is lifted.
    mute: Option<i64>,
}

/// The state of one member. It is safe for concurrent use.
pub struct Engine {
    self_id: String,
    clock: Clock,
    wall: Box<dyn Fn() -> i64 + Send + Sync>,
    uptime: Box<dyn Fn() -> Duration + Send + Sync>,
    key: [u8; 32],
    seal: Mutex<Option<SealFn>>,
    inner: Mutex<Inner>,
}

/// Seals an event this member makes to the group's readers and signs it
/// (docs/protocol.md, section 4, "Sealing").
pub type SealFn = Box<dyn Fn(&Event) -> Result<Sealed> + Send + Sync>;

impl Engine {
    pub fn new(
        self_id: &str,
        clock: Clock,
        wall: Box<dyn Fn() -> i64 + Send + Sync>,
        uptime: Box<dyn Fn() -> Duration + Send + Sync>,
    ) -> Engine {
        Engine {
            self_id: self_id.to_string(),
            clock,
            wall,
            uptime,
            key: random_bytes::<32>(),
            seal: Mutex::new(None),
            inner: Mutex::new(Inner {
                current: Event::default(),
                copied_at: Duration::ZERO,
                local: Local::default(),
                seen: BTreeSet::new(),
                seen_order: VecDeque::new(),
                written: VecDeque::new(),
                secrets: BTreeMap::new(),
                seq: 0,
                skews: BTreeMap::new(),
                peers: BTreeMap::new(),
                window: LIVE_WINDOW,
                mode: Mode::Shared,
                off_until: 0,
                mute: None,
            }),
        }
    }

    /// Seals each event this member makes from now on with seal; an error
    /// leaves the copy unmade.
    pub fn set_seal(&self, seal: SealFn) {
        *self.seal.lock() = Some(seal);
    }

    /// The sync mode.
    pub fn mode(&self) -> Mode {
        let mut st = self.inner.lock();
        self.mode_now(&mut st)
    }

    /// Changes the sync mode for good, as an admin's mode command does; it
    /// applies to the copies and events that come after.
    pub fn set_mode(&self, m: Mode) {
        self.set_sync(m == Mode::Shared, 0);
    }

    /// Turns sync on, or off until `until_ms` on the wall clock (0 for
    /// until it is turned on).
    pub fn set_sync(&self, on: bool, until_ms: i64) {
        let mut st = self.inner.lock();
        st.mode = if on { Mode::Shared } else { Mode::Own };
        st.off_until = if on { 0 } else { until_ms };
    }

    /// Whether sync is on, and while it is off, the wall time it turns
    /// back on at (0 for until it is turned on).
    pub fn sync(&self) -> (bool, i64) {
        let mut st = self.inner.lock();
        (self.mode_now(&mut st) == Mode::Shared, st.off_until)
    }

    /// The mode now: sync turned off for a while is on again once its time
    /// has passed.
    fn mode_now(&self, st: &mut Inner) -> Mode {
        if st.mode == Mode::Own && st.off_until != 0 && (self.wall)() >= st.off_until {
            st.mode = Mode::Shared;
            st.off_until = 0;
        }
        st.mode
    }

    /// Mutes this member until `until_ms` on the wall clock, 0 for until
    /// [`Engine::unmute`]: its copies, deliberate ones too, stay its own.
    pub fn set_mute(&self, until_ms: i64) {
        self.inner.lock().mute = Some(until_ms);
    }

    /// Ends the mute.
    pub fn unmute(&self) {
        self.inner.lock().mute = None;
    }

    /// Whether this member is muted, and for how many milliseconds more: 0
    /// for until [`Engine::unmute`], at least 1 otherwise.
    pub fn mute_left(&self) -> Option<i64> {
        let mut st = self.inner.lock();
        let now = (self.wall)();
        match self.muted(&mut st) {
            false => None,
            true => Some(st.mute.filter(|u| *u != 0).map_or(0, |u| u.saturating_sub(now).max(1))),
        }
    }

    /// Whether the mute holds now; one that ended is forgotten.
    fn muted(&self, st: &mut Inner) -> bool {
        if !crate::rule::holds(st.mute, (self.wall)()) {
            st.mute = None;
        }
        st.mute.is_some()
    }

    /// Changes how long after the copy an event from another member is
    /// still written to the local clipboard, as the group's records set it
    /// (docs/protocol.md, section 10, "The copies setting"); zero sets
    /// LIVE_WINDOW. It applies to the events that become current after it.
    pub fn set_live_window(&self, d: Duration) {
        self.inner.lock().window = if d.is_zero() { LIVE_WINDOW } else { d };
    }

    /// The live window set_live_window set.
    pub fn live_window(&self) -> Duration {
        self.inner.lock().window
    }

    /// The ID and the sealed copy of the group's current event, live or
    /// not, so that the caller can check its origin against the records
    /// again; None when it has none.
    pub fn current_copy(&self) -> Option<(String, Option<Sealed>)> {
        let st = self.inner.lock();
        (!st.current.id.is_empty()).then(|| (st.current.id.clone(), st.current.sealed.clone()))
    }

    /// Drops the group's current event when it is the event id: its origin
    /// was removed from the group, so its copy no longer counts and is never
    /// written. What the local clipboard holds stays. Reports whether it
    /// dropped one.
    pub fn forget(&self, id: &str) -> bool {
        let mut st = self.inner.lock();
        if id.is_empty() || st.current.id != id {
            return false;
        }
        st.current = Event::default();
        st.copied_at = Duration::ZERO;
        true
    }

    #[allow(clippy::expect_used, reason = "HMAC takes a key of any length, so this never fails")]
    fn sum(&self, text: &str) -> Sum {
        let mut m = Hmac::<Sha256>::new_from_slice(&self.key).expect("HMAC takes a key of any length");
        m.update(text.as_bytes());
        m.finalize().into_bytes().into()
    }

    /// The group's current event with its age as of now, unless there is
    /// none or it is a secret that expired or is known only by its mark.
    pub fn current(&self) -> Option<Event> {
        let st = self.inner.lock();
        let now = (self.uptime)();
        self.live(&st, now).then(|| self.with_age(&st, now))
    }

    /// The text of this member's own clipboard, its kind, and how long ago
    /// it was copied; None when unknown or an expired secret.
    pub fn local(&self) -> Option<(String, Kind, Duration)> {
        let st = self.inner.lock();
        let now = (self.uptime)();
        local_live(&st, now).then(|| (st.local.text.clone(), st.local.kind, now.saturating_sub(st.local.at)))
    }

    /// Records what the local clipboard holds without making an event.
    pub fn clipboard_is(&self, text: &str, kind: Kind) {
        let mut st = self.inner.lock();
        if check_text(text).is_err() {
            st.local = Local::default();
            return;
        }
        let now = (self.uptime)();
        st.local = Local { text: text.to_string(), kind, at: now };
        if kind == Kind::Secret {
            add_secret(&mut st, self.sum(text), now);
        }
    }

    /// Records a change that a clipboard watcher reported, and returns the
    /// event to send, or None when the clipboard did not really change for
    /// the group.
    pub fn copied(&self, text: &str, kind: Kind, via: Via) -> Result<Option<Event>> {
        check_text(text)?;
        if kind == Kind::Media {
            return Err(Error::msg("a lite member makes no media events"));
        }
        let mut st = self.inner.lock();
        let now = (self.uptime)();
        let sum = self.sum(text);
        if local_has(&st, text, now)
            || st.written.iter().any(|(s, at)| *s == sum && now.saturating_sub(*at) <= ECHO_WINDOW)
        {
            return Ok(None);
        }
        if via == Via::Universal && self.live(&st, now) && st.current.text == text {
            st.local = Local { text: text.to_string(), kind: st.current.kind, at: st.copied_at };
            return Ok(None);
        }
        if kind == Kind::Text && has_secret(&st, &sum, now) {
            st.local = Local::default();
            return Ok(None);
        }
        if !self.mode_now(&mut st).sends() || self.muted(&mut st) {
            st.local = Local { text: text.to_string(), kind, at: now };
            if kind == Kind::Secret {
                add_secret(&mut st, sum, now);
            }
            return Ok(None);
        }
        Ok(Some(self.new_event(&mut st, text, kind, via, sum, now)?))
    }

    /// Makes an event from a deliberate action; it always makes one, and the
    /// outcome tells whether to write it to the member's own clipboard.
    pub fn send(&self, text: &str, mut kind: Kind, via: Via) -> Result<(Event, Outcome)> {
        check_text(text)?;
        if kind == Kind::Media {
            return Err(Error::msg("a lite member makes no media events"));
        }
        let mut st = self.inner.lock();
        if self.muted(&mut st) {
            return Err(Error::msg("this device is muted: its copies do not reach the group until the mute ends"));
        }
        let now = (self.uptime)();
        let sum = self.sum(text);
        if has_secret(&st, &sum, now) {
            kind = Kind::Secret;
        }
        let held = local_has(&st, text, now);
        let ev = self.new_event(&mut st, text, kind, via, sum, now)?;
        let mut out = Outcome::default();
        if !held {
            st.seq = st.seq.saturating_add(1);
            out.write = true;
            out.seq = st.seq;
            add_written(&mut st, sum, now);
        }
        Ok((ev, out))
    }

    /// Makes a media event from a deliberate action: images or files, with
    /// their plain-text alternative or "", whose blob the caller sealed
    /// under key (docs/protocol.md, section 4, "The blob"). The member's
    /// own clipboard is not written: it holds them already.
    pub fn send_media(
        &self,
        text: &str,
        media: Manifest,
        via: Via,
        key: [u8; KEY_SIZE],
        blob: Option<Blob>,
    ) -> Result<Event> {
        media.validate()?;
        if text.len() > MAX_ALT_TEXT {
            return Err(Error::msg(format!("a media copy's text of {} bytes is larger than 256 KiB", text.len())));
        }
        if !text.is_empty() {
            check_text(text)?;
        }
        if (media.size > 0) != blob.is_some() {
            return Err(Error::msg("a media copy has a blob when its parts hold bytes, and only then"));
        }
        let mut st = self.inner.lock();
        if self.muted(&mut st) {
            return Err(Error::msg("this device is muted: its copies do not reach the group until the mute ends"));
        }
        let now = (self.uptime)();
        let mut ev = Event {
            id: random_id(),
            origin: self.self_id.clone(),
            via,
            time: self.clock.now(),
            kind: Kind::Media,
            text: text.to_string(),
            media: Some(media),
            key: Some(key),
            blob,
            ..Event::default()
        };
        if let Some(seal) = self.seal.lock().as_ref() {
            ev.sealed = Some(seal(&ev).map_err(|e| e.context("seal the copy"))?);
        }
        add_seen(&mut st, &ev.id);
        st.current = ev.clone();
        st.copied_at = now;
        st.local = Local::default();
        Ok(ev)
    }

    fn new_event(&self, st: &mut Inner, text: &str, kind: Kind, via: Via, sum: Sum, now: Duration) -> Result<Event> {
        let mut ev = Event {
            id: random_id(),
            origin: self.self_id.clone(),
            via,
            time: self.clock.now(),
            kind,
            text: text.to_string(),
            ..Event::default()
        };
        if let Some(seal) = self.seal.lock().as_ref() {
            ev.sealed = Some(seal(&ev).map_err(|e| e.context("seal the copy"))?);
        }
        add_seen(st, &ev.id);
        st.current = ev.clone();
        st.copied_at = now;
        st.local = Local { text: text.to_string(), kind, at: now };
        if kind == Kind::Secret {
            add_secret(st, sum, now);
        }
        Ok(ev)
    }

    /// Applies an event a peer delivered.
    pub fn received(&self, ev: Event) -> Result<Outcome> {
        ev.validate()?;
        if self.clock.ahead(ev.time) {
            return Err(Error::msg(AHEAD));
        }
        let mut st = self.inner.lock();
        Ok(self.receive(&mut st, ev))
    }

    /// Records an open connection to peer and returns the hello to send on
    /// it.
    pub fn connected(&self, peer: &str) -> Hello {
        let mut st = self.inner.lock();
        let n = st.peers.entry(peer.to_string()).or_default();
        *n = n.saturating_add(1);
        let mut h = Hello { wall: (self.wall)(), current: None };
        if !st.current.id.is_empty() {
            let ev = self.with_age(&st, (self.uptime)());
            // A reader sends a secret only as its mark.
            h.current = Some(if ev.kind == Kind::Secret && !ev.unread { ev.mark() } else { ev });
        }
        h
    }

    /// Records that a connection to peer is gone.
    pub fn disconnected(&self, peer: &str) {
        let mut st = self.inner.lock();
        match st.peers.get_mut(peer) {
            Some(n) if *n > 1 => {
                *n = n.saturating_sub(1);
                return;
            }
            _ => {}
        }
        st.peers.remove(peer);
        st.skews.remove(peer);
    }

    /// Applies the hello a peer sent when the connection started.
    pub fn reconcile(&self, peer: &str, mut h: Hello) -> Result<Outcome> {
        if let Some(c) = &h.current {
            c.validate()?;
            // Sealed, a secret may come in a hello from a member that cannot
            // read it, and so cannot tell it from a text.
            if c.sealed.is_none() && c.kind == Kind::Secret && !c.is_mark() {
                return Err(Error::msg("a hello must not carry a secret's text"));
            }
            if self.clock.ahead(c.time) {
                // Taken as no current event; the connection stays.
                h.current = None;
            }
        }
        let mut st = self.inner.lock();
        let known = st.skews.contains_key(peer);
        if h.wall > 0 && (known || st.skews.len() < 1024) {
            let skew = h.wall.saturating_sub((self.wall)());
            st.skews.insert(peer.to_string(), skew);
        }
        let mut out = Outcome::default();
        if let Some(c) = h.current {
            out = self.receive(&mut st, c);
        }
        Ok(out)
    }

    /// For each connected peer, how far its wall clock was ahead of this
    /// member's, in milliseconds, when its hello arrived.
    pub fn skews(&self) -> BTreeMap<String, i64> {
        self.inner.lock().skews.clone()
    }

    fn receive(&self, st: &mut Inner, ev: Event) -> Outcome {
        let now = (self.uptime)();
        let age = Duration::from_millis(ev.age.min(MAX_AGE_MS) as u64);
        if st.seen.contains(&ev.id) {
            if st.current.id != ev.id {
                return Outcome::default();
            }
            // The full event may follow the mark of the same secret: its
            // payload, and its text when this member reads it.
            if st.current.is_mark() && !ev.is_mark() && st.current.same_payload(&ev) {
                if !ev.unread {
                    add_secret(st, self.sum(&ev.text), now);
                }
                st.copied_at = now.saturating_sub(age);
                st.current = ev.clone();
                return self.decide_write(st, Outcome { forward: Some(ev), ..Default::default() }, now);
            }
            return Outcome::default();
        }
        self.clock.observe(ev.time);
        add_seen(st, &ev.id);
        if ev.kind == Kind::Secret && !ev.is_mark() && !ev.unread {
            add_secret(st, self.sum(&ev.text), now);
        }
        let out = Outcome { forward: Some(ev.clone()), ..Default::default() };
        if !st.current.id.is_empty() && !ev.later(&st.current) {
            return out;
        }
        st.current = ev;
        st.copied_at = now.saturating_sub(age);
        self.decide_write(st, out, now)
    }

    /// Decides whether the new current event goes to the local clipboard:
    /// when the mode lets the group's copies in and the event is younger
    /// than the live window. An older one never does: the member's own text,
    /// however old, stays.
    fn decide_write(&self, st: &mut Inner, mut out: Outcome, now: Duration) -> Outcome {
        // Images or files without a text leave this member's clipboard as
        // it is: it never fetches their content (takes_media false).
        let incoming = crate::rule::Incoming {
            receives: self.mode_now(st).receives(),
            kind: st.current.kind,
            mark: st.current.is_mark(),
            unread: st.current.unread,
            has_text: !st.current.text.is_empty(),
            has_media: st.current.media.is_some(),
            takes_media: false,
            held: local_has(st, &st.current.text, now),
            age_ms: ms(now.saturating_sub(st.copied_at)),
            window_ms: ms(st.window),
            secret_ttl_ms: ms(SECRET_TTL),
        };
        if crate::rule::incoming(&incoming) != crate::rule::Verdict::Write {
            return out;
        }
        st.seq = st.seq.saturating_add(1);
        out.write = true;
        out.seq = st.seq;
        let kind = if st.current.kind == Kind::Media { Kind::Text } else { st.current.kind };
        st.local = Local { text: st.current.text.clone(), kind, at: st.copied_at };
        let sum = self.sum(&st.current.text);
        add_written(st, sum, now);
        out
    }

    fn live(&self, st: &Inner, now: Duration) -> bool {
        if st.current.id.is_empty() || st.current.is_mark() || st.current.unread {
            return false;
        }
        st.current.kind != Kind::Secret || now.saturating_sub(st.copied_at) < SECRET_TTL
    }

    fn with_age(&self, st: &Inner, now: Duration) -> Event {
        let mut ev = st.current.clone();
        ev.age = (now.saturating_sub(st.copied_at).as_millis() as i64).min(MAX_AGE_MS);
        ev
    }
}

/// A duration in whole milliseconds, as the rule takes it.
fn ms(d: Duration) -> i64 {
    i64::try_from(d.as_millis()).unwrap_or(i64::MAX)
}

fn local_live(st: &Inner, now: Duration) -> bool {
    !st.local.text.is_empty() && (st.local.kind != Kind::Secret || now.saturating_sub(st.local.at) < SECRET_TTL)
}

fn local_has(st: &Inner, text: &str, now: Duration) -> bool {
    local_live(st, now) && st.local.text == text
}

fn add_seen(st: &mut Inner, id: &str) {
    if st.seen.contains(id) {
        return;
    }
    if st.seen_order.len() >= SEEN_IDS {
        if let Some(old) = st.seen_order.pop_front() {
            st.seen.remove(&old);
        }
    }
    st.seen.insert(id.to_string());
    st.seen_order.push_back(id.to_string());
}

fn add_written(st: &mut Inner, sum: Sum, now: Duration) {
    if st.written.len() >= 8 {
        st.written.pop_front();
    }
    st.written.push_back((sum, now));
}

fn add_secret(st: &mut Inner, sum: Sum, now: Duration) {
    if !st.secrets.contains_key(&sum) && st.secrets.len() >= MAX_SECRETS {
        if let Some(oldest) = st.secrets.iter().min_by_key(|(_, at)| **at).map(|(s, _)| *s) {
            st.secrets.remove(&oldest);
        }
    }
    st.secrets.insert(sum, now);
}

fn has_secret(st: &Inner, sum: &Sum, now: Duration) -> bool {
    st.secrets.get(sum).is_some_and(|at| now.saturating_sub(*at) <= SECRET_MEMORY)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn engine(id: &str, t: Arc<AtomicU64>) -> Engine {
        let t2 = t.clone();
        Engine::new(
            id,
            Clock::new(
                Box::new(move || 1_761_024_000_000 + t2.load(Ordering::SeqCst) as i64),
                Timestamp::default(),
                None,
            ),
            Box::new(|| 1_761_024_000_000),
            Box::new(move || Duration::from_millis(t.load(Ordering::SeqCst))),
        )
    }

    const A: &str = "0123456789abcdef0123456789abcdef";
    const B: &str = "fedcba9876543210fedcba9876543210";

    #[test]
    fn ahead_refused() {
        let now = 1_792_886_400_000; // 2026-10-25
        let e = Engine::new(
            A,
            Clock::new(Box::new(move || now), Timestamp::default(), None),
            Box::new(move || now),
            Box::new(|| Duration::from_secs(3600)),
        );
        let event = |wall| Event {
            id: random_id(),
            origin: B.to_string(),
            via: Via::Copy,
            time: Timestamp { wall, logical: 0 },
            age: 0,
            kind: Kind::Text,
            text: "x".to_string(),
            ..Event::default()
        };
        assert!(e.received(event(crate::hlc::MAX_WALL)).is_err());
        let out = e.reconcile(B, Hello { wall: now, current: Some(event(crate::hlc::MAX_WALL)) }).unwrap();
        assert!(out.forward.is_none() && !out.write);
        assert!(e.received(event(now + 6 * 24 * 3600 * 1000)).is_ok());
    }

    /// A phone's media copy becomes the group's current one with the key
    /// its blob was sealed under, and leaves its own clipboard unwritten.
    #[test]
    fn sends_media() {
        use crate::copy::Blob;
        use crate::media::{Manifest, Part};
        let t = Arc::new(AtomicU64::new(100_000));
        let a = engine(A, t);
        let png = Part { kind: "image/png".into(), size: 3, sha256: Some(alloc::vec![7; 32]), ..Default::default() };
        let m = Manifest { size: 3, parts: alloc::vec![png] };
        let blob = Blob { size: 65_552, sha256: alloc::vec![1; 32] };
        let ev = a.send_media("", m.clone(), Via::Phone, [5; 32], Some(blob.clone())).unwrap();
        assert_eq!((ev.kind, ev.key, ev.blob.clone()), (Kind::Media, Some([5; 32]), Some(blob)));
        assert_eq!(a.current().unwrap().id, ev.id);
        assert!(a.local().is_none());
        // Bytes without a blob, or a blob without bytes, make no copy.
        assert!(a.send_media("", m, Via::Phone, [5; 32], None).is_err());
        let dir = Part { path: "trip".into(), dir: true, ..Default::default() };
        let empty = Manifest { size: 0, parts: alloc::vec![dir] };
        assert!(
            a.send_media("", empty.clone(), Via::Phone, [5; 32], Some(Blob { size: 1, sha256: alloc::vec![1; 32] }))
                .is_err()
        );
        assert!(a.send_media("", empty, Via::Phone, [5; 32], None).is_ok());
    }

    /// A media event becomes the group's current one; a lite member takes
    /// only its text, as a text, and keeps its clipboard when it has none.
    #[test]
    fn media_events() {
        use crate::media::{Manifest, Part};
        let t = Arc::new(AtomicU64::new(100_000));
        let a = engine(A, t.clone());
        a.reconcile(B, Hello { wall: 1_761_024_000_000, current: None }).unwrap();
        a.connected(B);
        let (_, out) = a.send("mine", Kind::Text, Via::Copy).unwrap();
        assert!(out.write);
        let png = Part { kind: "image/png".into(), size: 3, sha256: Some(alloc::vec![7; 32]), ..Default::default() };
        let mut ev = Event {
            id: random_id(),
            origin: B.to_string(),
            via: Via::Copy,
            time: Timestamp { wall: 1_761_024_000_000 + 200_000, logical: 0 },
            age: 0,
            kind: Kind::Media,
            text: String::new(),
            media: Some(Manifest { size: 3, parts: alloc::vec![png] }),
            ..Event::default()
        };
        let out = a.received(ev.clone()).unwrap();
        assert!(out.forward.is_some() && !out.write);
        assert_eq!(a.current().unwrap().kind, Kind::Media);
        assert_eq!(a.local().unwrap().0, "mine");

        ev.id = random_id();
        ev.time.logical = 1;
        ev.text = "a picture".into();
        let out = a.received(ev.clone()).unwrap();
        assert!(out.write);
        assert_eq!(a.local().unwrap(), ("a picture".to_string(), Kind::Text, Duration::ZERO));
        assert!(a.copied("a picture", Kind::Text, Via::Copy).unwrap().is_none());
        assert!(a.send("x", Kind::Media, Via::Copy).is_err());

        let mut bad = ev.clone();
        bad.media = None;
        assert!(bad.validate().is_err());
        bad = ev.clone();
        bad.media.as_mut().unwrap().size = 4;
        assert!(bad.validate().is_err());
        bad = ev;
        bad.media.as_mut().unwrap().parts[0].path = "../x".into();
        assert!(bad.validate().is_err());
    }

    #[test]
    fn two_members_converge() {
        let t = Arc::new(AtomicU64::new(100_000));
        let (a, b) = (engine(A, t.clone()), engine(B, t.clone()));
        let ha = a.connected(B);
        let hb = b.connected(A);
        a.reconcile(B, hb).unwrap();
        b.reconcile(A, ha).unwrap();
        t.fetch_add(60_000, Ordering::SeqCst);

        let (ev, out) = a.send("hello", Kind::Text, Via::Copy).unwrap();
        assert!(out.write);
        let got = b.received(ev.clone()).unwrap();
        assert!(got.write && got.forward.is_some());
        assert_eq!(b.local().unwrap().0, "hello");
        // A duplicate does nothing.
        let again = b.received(ev).unwrap();
        assert!(!again.write && again.forward.is_none());
        // The echo of the write is no new copy.
        assert!(b.copied("hello", Kind::Text, Via::Copy).unwrap().is_none());
    }

    /// A copy from another member is written while it is younger than the
    /// live window, which the group sets, and never after; a forgotten one
    /// never.
    #[test]
    fn live_window() {
        let t = Arc::new(AtomicU64::new(100_000));
        let (a, b) = (engine(A, t.clone()), engine(B, t.clone()));
        b.copied("mine", Kind::Text, Via::Copy).unwrap();
        let old = |text: &str, age: i64| {
            let mut ev = a.copied(text, Kind::Text, Via::Copy).unwrap().unwrap();
            ev.age = age;
            t.fetch_add(1, Ordering::SeqCst);
            ev
        };
        assert!(!b.received(old("a minute old", 60_000)).unwrap().write);
        assert_eq!(b.local().unwrap().0, "mine");
        assert!(b.received(old("40 s old", 40_000)).unwrap().write);
        b.set_live_window(Duration::from_secs(180));
        assert!(b.received(old("two minutes old", 120_000)).unwrap().write);
        b.set_live_window(Duration::from_secs(10));
        assert!(!b.received(old("15 s old", 15_000)).unwrap().write);
        b.set_live_window(Duration::ZERO);
        assert_eq!(b.live_window(), LIVE_WINDOW);

        b.set_mode(Mode::Own);
        let ev = old("from a device removed since", 0);
        b.received(ev.clone()).unwrap();
        assert_eq!(b.current_copy().unwrap().0, ev.id);
        assert!(b.forget(&ev.id) && b.current().is_none() && !b.forget(&ev.id));
        b.set_mode(Mode::Shared);
        assert!(!b.reconcile(A, Hello { wall: 0, current: Some(ev) }).unwrap().write);
    }

    #[test]
    fn modes() {
        let t = Arc::new(AtomicU64::new(100_000));
        let (a, b) = (engine(A, t.clone()), engine(B, t.clone()));
        let (ha, hb) = (a.connected(B), b.connected(A));
        a.reconcile(B, hb).unwrap();
        b.reconcile(A, ha).unwrap();
        for m in Mode::ALL {
            assert_eq!(Mode::parse(m.name()).unwrap(), m);
        }
        assert!(Mode::parse("everything").is_err());

        // Own: a copy stays here, the group's copy does not come in, but it
        // is at hand, and a deliberate send still goes.
        b.set_mode(Mode::Own);
        assert!(b.copied("mine", Kind::Text, Via::Copy).unwrap().is_none());
        assert_eq!(b.local().unwrap().0, "mine");
        let ev = a.copied("theirs", Kind::Text, Via::Copy).unwrap().unwrap();
        let out = b.received(ev).unwrap();
        assert!(!out.write && out.forward.is_some());
        assert_eq!(b.current().unwrap().text, "theirs");
        assert_eq!(b.local().unwrap().0, "mine");
        assert!(b.send("sent", Kind::Text, Via::Copy).is_ok());

        // Sync on again: both ways.
        b.set_mode(Mode::Shared);
        t.fetch_add(1000, Ordering::SeqCst);
        let ev = a.copied("next", Kind::Text, Via::Copy).unwrap().unwrap();
        assert!(b.received(ev).unwrap().write);
        assert!(b.copied("local", Kind::Text, Via::Copy).unwrap().is_some());
        assert_eq!(b.sync(), (true, 0));
    }

    #[test]
    fn sync_off_for_a_while() {
        let t = Arc::new(AtomicU64::new(100_000));
        let w = t.clone();
        let e = Engine::new(
            A,
            Clock::new(Box::new(|| 1_761_024_000_000), Timestamp::default(), None),
            Box::new(move || w.load(Ordering::SeqCst) as i64),
            Box::new(|| Duration::from_secs(100)),
        );
        e.set_sync(false, 160_000);
        assert_eq!(e.sync(), (false, 160_000));
        assert!(e.copied("mine", Kind::Text, Via::Copy).unwrap().is_none());
        t.store(160_000, Ordering::SeqCst);
        assert_eq!(e.mode(), Mode::Shared);
        assert_eq!(e.sync(), (true, 0));
        e.set_sync(false, 0);
        t.store(10_000_000, Ordering::SeqCst);
        assert_eq!(e.sync(), (false, 0));
    }

    #[test]
    fn hellos_carry_only_the_mark_of_a_secret() {
        let t = Arc::new(AtomicU64::new(100_000));
        let a = engine(A, t);
        a.send("hunter2", Kind::Secret, Via::Copy).unwrap();
        let h = a.connected(B);
        let cur = h.current.unwrap();
        assert!(cur.is_mark());
        // A hello with a secret's text is refused.
        let mut bad = cur.clone();
        bad.text = "hunter2".into();
        assert!(a.reconcile(B, Hello { wall: 0, current: Some(bad) }).is_err());
    }

    /// A copy not sealed to this member orders the group's copies but is
    /// never written; a mark takes only the full copy whose payload it names.
    #[test]
    fn sealed_copies() {
        let t = Arc::new(AtomicU64::new(100_000));
        let a = engine(A, t.clone());
        a.reconcile(B, Hello { wall: 1_761_024_000_000, current: None }).unwrap();
        a.connected(B);
        let sealed = |id: &str, logical: u32, payload: &[u8]| {
            let mut s = Sealed::default();
            (s.id, s.origin, s.payload) = (id.into(), B.into(), payload.to_vec());
            s.time = Timestamp { wall: 1_761_024_000_000 + 100_000, logical };
            s
        };
        let unread = Event::of(sealed("11aa0000000000000000000000000000", 0, b"for others"));
        let out = a.received(unread).unwrap();
        assert!(out.forward.is_some() && !out.write);
        assert!(a.current().is_none());

        // The mark of a secret, then a full copy with another payload, then
        // the one it names.
        let full = sealed("22bb0000000000000000000000000000", 1, b"hunter2 sealed");
        let read = |s: Sealed| Event { kind: Kind::Secret, text: "hunter2".into(), unread: false, ..Event::of(s) };
        let out = a.received(Event::of(full.mark())).unwrap();
        assert!(out.forward.is_some() && !out.write);
        let other = sealed("22bb0000000000000000000000000000", 1, b"something else");
        assert!(a.received(read(other)).unwrap().forward.is_none());
        let out = a.received(read(full)).unwrap();
        assert!(out.forward.is_some() && out.write);
        assert_eq!(a.current().unwrap().text, "hunter2");
        // The hello carries the mark only.
        let h = a.connected(B);
        let cur = h.current.unwrap();
        assert!(cur.is_mark() && cur.text.is_empty() && cur.sealed.unwrap().payload.is_empty());
    }

    #[test]
    fn old_events_are_not_written_outside_the_windows() {
        let t = Arc::new(AtomicU64::new(1_000_000));
        let b = engine(B, t.clone());
        let ev = Event {
            id: "77aa0000000000000000000000000000".into(),
            origin: A.into(),
            time: Timestamp { wall: 1_761_024_000_000, logical: 0 },
            age: 120_000,
            text: "old".into(),
            ..Default::default()
        };
        let out = b.received(ev).unwrap();
        assert!(out.forward.is_some() && !out.write);
    }
}
