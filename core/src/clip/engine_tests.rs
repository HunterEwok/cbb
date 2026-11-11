// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The engine's behavior in the cases Go's engine was tested with: echoes,
//! ordering, the live window, sleep and clock steps, skews, secrets, the
//! hello, mute, and a group that converges over links that come and go.

use super::*;
use alloc::vec;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const C: &str = "cccccccccccccccccccccccccccccccc";
const D: &str = "dddddddddddddddddddddddddddddddd";

/// The two clocks a member reads: the wall clock, and the uptime, which
/// counts sleep and does not jump when the wall clock is set.
#[derive(Clone)]
struct World {
    wall: Arc<AtomicI64>, // milliseconds since the Unix epoch
    up: Arc<AtomicU64>,   // milliseconds of uptime
}

impl World {
    fn new() -> World {
        World { wall: Arc::new(AtomicI64::new(1_761_024_000_000)), up: Arc::new(AtomicU64::new(3_600_000)) }
    }

    fn wall(&self) -> i64 {
        self.wall.load(Ordering::SeqCst)
    }

    /// Lets time pass, awake or asleep: both clocks move.
    fn advance(&self, d: Duration) {
        self.wall.fetch_add(d.as_millis() as i64, Ordering::SeqCst);
        self.up.fetch_add(d.as_millis() as u64, Ordering::SeqCst);
    }

    /// Sets the wall clock, as NTP does; the uptime does not jump.
    fn step(&self, ms: i64) {
        self.wall.fetch_add(ms, Ordering::SeqCst);
    }

    fn member(&self, id: &str) -> Engine {
        self.skewed(id, 0)
    }

    fn skewed(&self, id: &str, offset_ms: i64) -> Engine {
        let (w1, w2, up) = (self.wall.clone(), self.wall.clone(), self.up.clone());
        Engine::new(
            id,
            Clock::new(Box::new(move || w1.load(Ordering::SeqCst) + offset_ms), Timestamp::default(), None),
            Box::new(move || w2.load(Ordering::SeqCst) + offset_ms),
            Box::new(move || Duration::from_millis(up.load(Ordering::SeqCst))),
        )
    }

    /// An event from member B, aged as given, stamped at the world's wall
    /// time plus logical, so tests can order events made in the same moment.
    fn event(&self, text: &str, age: Duration, logical: u32) -> Event {
        Event {
            id: random_id(),
            origin: B.into(),
            time: Timestamp { wall: self.wall(), logical },
            age: age.as_millis() as i64,
            kind: Kind::Text,
            text: text.into(),
            ..Event::default()
        }
    }

    /// Opens a connection to peer and reconciles the peer's hello, carrying
    /// cur, as the transport does.
    fn join(&self, e: &Engine, peer: &str, cur: Option<Event>) -> Outcome {
        e.connected(peer);
        e.reconcile(peer, Hello { wall: self.wall(), current: cur }).unwrap()
    }
}

fn secs(s: u64) -> Duration {
    Duration::from_secs(s)
}

fn copy(e: &Engine, text: &str) -> Event {
    e.copied(text, Kind::Text, Via::Copy).unwrap().unwrap_or_else(|| panic!("copying {text:?} made no event"))
}

fn current_text(e: &Engine) -> String {
    e.current().map(|ev| ev.text).unwrap_or_default()
}

fn local_text(e: &Engine) -> String {
    e.local().map(|l| l.0).unwrap_or_default()
}

fn known_secret(e: &Engine, text: &str) -> bool {
    let st = e.inner.lock();
    has_secret(&st, &e.sum(text), e.now())
}

fn nothing(o: &Outcome) -> bool {
    o.forward.is_none() && !o.write && o.seq == 0
}

#[test]
fn copied() {
    let w = World::new();
    let a = w.member(A);
    let ev = copy(&a, "hello");
    assert!(ev.origin == A && ev.text == "hello" && ev.kind == Kind::Text && ev.via == Via::Copy);
    assert!(is_id(&ev.id) && !ev.time.is_zero() && ev.age == 0);
    assert_eq!((local_text(&a), current_text(&a)), ("hello".into(), "hello".into()));
    assert!(a.copied("hello", Kind::Text, Via::Copy).unwrap().is_none(), "copying the current text again");
    for text in ["", &"x".repeat(MAX_TEXT + 1)] {
        assert!(a.copied(text, Kind::Text, Via::Copy).is_err());
    }
}

#[test]
fn echo() {
    let w = World::new();
    let a = w.member(A);
    w.join(&a, B, None);
    let out = a.received(w.event("first", secs(1), 0)).unwrap();
    assert!(out.write && local_text(&a) == "first");
    assert!(a.copied("first", Kind::Text, Via::Copy).unwrap().is_none(), "the echo of a written text");
    // A late echo: the clipboard reports "first" only after "second" arrived.
    w.advance(secs(1));
    a.received(w.event("second", secs(1), 0)).unwrap();
    assert!(a.copied("first", Kind::Text, Via::Copy).unwrap().is_none(), "a late echo of an earlier write");
    w.advance(ECHO_WINDOW + secs(1));
    assert!(a.copied("first", Kind::Text, Via::Copy).unwrap().is_some(), "a text written long ago");
}

#[test]
fn received_ordering() {
    let w = World::new();
    let a = w.member(A);
    w.join(&a, B, None);
    let old = w.event("old", Duration::ZERO, 0);
    let newer = w.event("newer", Duration::ZERO, 1);
    let out = a.received(newer.clone()).unwrap();
    assert!(out.forward.is_some() && out.write && out.seq == 1);
    let out = a.received(old).unwrap();
    assert!(out.forward.is_some() && !out.write);
    assert_eq!(current_text(&a), "newer");
    assert!(nothing(&a.received(newer).unwrap()), "a duplicate");
    w.advance(Duration::from_millis(1));
    assert_eq!(a.received(w.event("third", Duration::ZERO, 0)).unwrap().seq, 2);
}

/// A copied "x"; B's later "x" replaces it in the group state, without a
/// write, and is forwarded. C's "y", made between the two, then loses.
#[test]
fn same_text_newer_event() {
    let w = World::new();
    let a = w.member(A);
    w.join(&a, B, None);
    copy(&a, "x");
    let y = w.event("y", Duration::ZERO, 5);
    w.advance(Duration::from_millis(20));
    let x2 = w.event("x", Duration::ZERO, 0);
    let out = a.received(x2.clone()).unwrap();
    assert!(out.forward.is_some() && !out.write);
    assert!(!a.received(y).unwrap().write);
    assert_eq!(a.current().unwrap().id, x2.id);
}

#[test]
fn local_clipboard() {
    let w = World::new();
    let a = w.member(A);
    w.join(&a, C, None);
    copy(&a, "mine");
    // An old event from a returning member wins the group state but stays
    // off the local clipboard.
    w.advance(secs(3600));
    assert!(!a.received(w.event("stale", secs(20 * 60), 0)).unwrap().write);
    assert_eq!((local_text(&a), current_text(&a)), ("mine".into(), "stale".into()));
    // The user copies the group's text deliberately: a new event, and the
    // local clipboard follows.
    assert!(a.copied("stale", Kind::Text, Via::Copy).unwrap().is_some());
    assert_eq!(local_text(&a), "stale");
    // A written event becomes the local text, with its age.
    w.advance(secs(1));
    assert!(a.received(w.event("fresh", secs(3), 0)).unwrap().write);
    assert_eq!(a.local().unwrap(), ("fresh".into(), Kind::Text, secs(3)));
    a.clipboard_is("from the desktop", Kind::Text);
    assert_eq!(local_text(&a), "from the desktop");
    a.clipboard_is("", Kind::Text);
    assert!(a.local().is_none());
}

#[test]
fn received_validation() {
    let w = World::new();
    let a = w.member(A);
    let good = w.event("ok", Duration::ZERO, 0);
    type Mutate = fn(&mut Event);
    let bad: [(&str, Mutate); 8] = [
        ("short ID", |e| e.id = "abc".into()),
        ("upper-case ID", |e| e.id = "A".repeat(32)),
        ("bad origin", |e| e.origin = "b".into()),
        ("no timestamp", |e| e.time = Timestamp::default()),
        ("past the end", |e| e.time.wall = crate::hlc::MAX_WALL + 1),
        ("negative age", |e| e.age = -1),
        ("empty text", |e| e.text = String::new()),
        ("text over the limit", |e| e.text = "x".repeat(MAX_TEXT + 1)),
    ];
    for (name, mutate) in bad {
        let mut ev = good.clone();
        mutate(&mut ev);
        assert!(a.received(ev).is_err(), "{name} was taken");
    }
    // An age beyond the cap is taken and capped.
    a.received(w.event("very old", secs(3 * 365 * 24 * 3600), 0)).unwrap();
    assert_eq!(a.connected(C).current.unwrap().age, MAX_AGE_MS);
    // An age that would overflow does not make an event live.
    let b = w.member(B);
    w.join(&b, A, None);
    let mut ev = w.event("ancient", Duration::ZERO, 0);
    ev.age = i64::MAX;
    assert!(!b.received(ev).unwrap().write);
    assert_eq!(b.current().unwrap().age, MAX_AGE_MS);
}

#[test]
fn time_and_sleep() {
    // A copy made before a sleep is old after it.
    let w = World::new();
    let laptop = w.member(A);
    copy(&laptop, "before the lid closed");
    w.advance(secs(10 * 3600)); // asleep: uptime counts it
    let h = laptop.connected(B);
    assert_eq!(h.current.as_ref().unwrap().age, 10 * 3600 * 1000);
    let desk = w.member(B);
    w.join(&desk, C, None);
    assert!(!desk.reconcile(A, h).unwrap().write, "a copy from before the sleep was written as live");

    // Setting the wall clock ages nothing.
    let w = World::new();
    let pi = w.member(A);
    w.join(&pi, B, None);
    pi.received(w.event("just copied", Duration::ZERO, 0)).unwrap();
    w.step(6 * 3600 * 1000); // NTP corrects a clock that was behind
    w.advance(secs(2));
    assert_eq!(pi.current().unwrap().age, 2000);
}

/// A member that booted a moment ago, its uptime shorter than the live
/// window, still takes an old copy as old.
#[test]
fn just_booted() {
    let w = World::new();
    w.up.store(10_000, Ordering::SeqCst);
    let pi = w.member(A);
    let out = w.join(&pi, B, Some(w.event("copied before the boot", secs(20 * 60), 0)));
    assert!(out.forward.is_some() && !out.write, "an old copy was written on a member that just booted");
    assert_eq!(pi.connected(C).current.unwrap().age, 20 * 60 * 1000);
    assert!(pi.received(w.event("fresh", secs(5), 1)).unwrap().write);
}

#[test]
fn skew() {
    let w = World::new();
    let a = w.member(A);
    let ahead = w.skewed(B, 10 * 60 * 1000);
    a.connected(B);
    a.reconcile(B, ahead.connected(A)).unwrap();
    assert_eq!(a.skews()[B], 10 * 60 * 1000);
    let ev = copy(&ahead, "from a clock 10 minutes ahead");
    assert!(a.received(ev.clone()).unwrap().write);
    w.advance(secs(1));
    let mine = copy(&a, "after it");
    assert!(mine.later(&ev), "a's later copy sorts before b's");
    a.disconnected(B);
    assert!(!a.skews().contains_key(B));
}

#[test]
fn secret_expires_and_travels_only_as_a_mark() {
    let w = World::new();
    let a = w.member(A);
    assert!(a.copied("hunter2", Kind::Secret, Via::Copy).unwrap().is_some());
    assert!(a.connected(B).current.unwrap().is_mark());
    w.advance(SECRET_TTL);
    assert!(a.current().is_none() && a.local().is_none());
}

#[test]
fn secret_stays_a_secret_when_offered_again() {
    let w = World::new();
    let a = w.member(A);
    w.join(&a, B, None);
    copy(&a, "older text");
    a.copied("pw-1234", Kind::Secret, Via::Phone).unwrap();
    w.advance(secs(120));
    assert!(known_secret(&a, "pw-1234"));
    // A clipboard manager restores it without its mark: not a new copy.
    assert!(a.copied("pw-1234", Kind::Text, Via::Copy).unwrap().is_none());
    // The plain button, with the password still on the phone: a secret.
    let (ev, _) = a.send("pw-1234", Kind::Text, Via::Phone).unwrap();
    assert_eq!(ev.kind, Kind::Secret);
    w.advance(SECRET_MEMORY + secs(60));
    assert!(!known_secret(&a, "pw-1234"));
}

#[test]
fn secret_expires_by_its_age() {
    let w = World::new();
    let b = w.member(B);
    w.join(&b, A, None);
    let sec = Event {
        id: random_id(),
        origin: A.into(),
        time: Timestamp { wall: w.wall(), logical: 0 },
        age: 50_000,
        kind: Kind::Secret,
        text: "pin 1234".into(),
        ..Event::default()
    };
    assert!(b.received(sec).unwrap().write);
    w.advance(secs(10));
    assert!(b.current().is_none(), "the secret outlived its age");
    assert!(known_secret(&b, "pin 1234"));
}

#[test]
fn a_skipped_marked_item_is_remembered() {
    let w = World::new();
    let a = w.member(A);
    a.clipboard_is("from the password manager", Kind::Secret);
    assert!(known_secret(&a, "from the password manager"));
    w.advance(secs(120));
    assert!(a.copied("from the password manager", Kind::Text, Via::Copy).unwrap().is_none());
}

#[test]
fn the_secret_memory_holds_many_by_age() {
    let w = World::new();
    let a = w.member(A);
    for i in 0..40 {
        a.send(&format!("one-time code {i}"), Kind::Secret, Via::Copy).unwrap();
        w.advance(secs(60));
    }
    assert!(known_secret(&a, "one-time code 0"));
}

/// Two desktops whose clipboard managers restore every expired text.
#[test]
fn a_restored_secret_does_not_circulate() {
    let w = World::new();
    let (mac, d1, d2) = (w.member(A), w.member(B), w.member(C));
    for m in [&mac, &d1, &d2] {
        for peer in [A, B, C] {
            w.join(m, peer, None);
        }
    }
    let (sec, _) = mac.send("hunter2", Kind::Secret, Via::Copy).unwrap();
    let mut queue = vec![sec];
    let mut sends = 0;
    for _ in 0..20 {
        if queue.is_empty() {
            break;
        }
        let mut next = Vec::new();
        for ev in &queue {
            for d in [&d1, &d2] {
                if d.received(ev.clone()).unwrap().write {
                    w.advance(SECRET_TTL + secs(1)); // it expires; the manager restores it
                    if let Some(again) = d.copied("hunter2", Kind::Text, Via::Copy).unwrap() {
                        sends += 1;
                        next.push(again);
                    }
                }
            }
        }
        queue = next;
    }
    assert_eq!(sends, 0, "a restored secret was sent again");
}

#[test]
fn a_mark_hides_an_older_text_and_the_full_secret_replaces_it() {
    let w = World::new();
    let b = w.member(B);
    w.join(&b, C, None);
    let older = Event { origin: C.into(), ..w.event("older text", Duration::ZERO, 0) };
    b.received(older).unwrap();
    let full = Event { origin: A.into(), age: 2000, kind: Kind::Secret, ..w.event("pw", Duration::ZERO, 9) };
    let mark = Event { text: String::new(), ..full.clone() };
    let out = w.join(&b, A, Some(mark));
    assert!(!out.write && out.forward.as_ref().is_some_and(Event::is_mark));
    assert!(b.current().is_none(), "a mark left the older text current");
    let out = b.received(full.clone()).unwrap();
    assert!(out.write && out.forward.unwrap().text == "pw" && current_text(&b) == "pw");
    assert!(nothing(&b.received(full).unwrap()), "a second copy of the full secret");
}

#[test]
fn own_mode_keeps_a_secret_a_secret() {
    let w = World::new();
    let e = w.member(A);
    e.set_mode(Mode::Own);
    assert!(e.copied("hunter2", Kind::Secret, Via::Copy).unwrap().is_none());
    // Offered again without its mark, it is still known as a secret.
    assert!(known_secret(&e, "hunter2"));
}

#[test]
fn write_policy() {
    // A live event is written.
    let w = World::new();
    let a = w.member(A);
    w.join(&a, C, None);
    assert!(a.received(w.event("fresh", secs(5), 0)).unwrap().write);

    // An old event reaches a member that stayed connected.
    let w = World::new();
    let a = w.member(A);
    w.join(&a, C, None);
    copy(&a, "copied at home");
    w.advance(secs(3600));
    assert!(!a.received(w.event("copied while away", secs(20 * 60), 0)).unwrap().write);
    assert_eq!(local_text(&a), "copied at home");

    // A member that only lost its peers keeps its clipboard.
    let w = World::new();
    let desk = w.member(A);
    w.join(&desk, B, None);
    copy(&desk, "desk text");
    desk.disconnected(B);
    w.advance(secs(3600));
    assert!(!w.join(&desk, B, Some(w.event("laptop's old copy", secs(50 * 60), 0))).write);

    // A member that wakes up keeps its own text.
    let w = World::new();
    let a = w.member(A);
    copy(&a, "copied before the sleep");
    w.advance(secs(3 * 3600));
    assert!(!w.join(&a, B, Some(w.event("copied while it slept", secs(2 * 3600), 0))).write);
    assert_eq!(local_text(&a), "copied before the sleep");

    // A copy delivered late is written within the live window.
    let w = World::new();
    let a = w.member(A);
    assert!(w.join(&a, B, Some(w.event("copied a moment ago", secs(40), 0))).write);

    // The live window ends.
    let w = World::new();
    let a = w.member(A);
    w.join(&a, B, None);
    assert!(!a.received(w.event("a minute old", LIVE_WINDOW, 0)).unwrap().write);
}

/// The desk adopted a returning laptop's cafe copy without writing it; a
/// clipboard manager on the desk then offers the desk's unchanged text
/// again.
#[test]
fn reoffer_of_local_text() {
    let w = World::new();
    let desk = w.member(A);
    w.join(&desk, C, None);
    copy(&desk, "report draft");
    w.advance(secs(3600));
    desk.received(w.event("cafe link", secs(30 * 60), 0)).unwrap();
    w.advance(secs(5 * 60));
    assert!(desk.copied("report draft", Kind::Text, Via::Copy).unwrap().is_none());
    // A deliberate send of the same text does make one.
    assert_eq!(desk.send("report draft", Kind::Text, Via::Copy).unwrap().0.text, "report draft");
}

/// The member a phone sends to gets the text on its own clipboard too.
#[test]
fn send_from_the_phone() {
    let w = World::new();
    let holder = w.member(A);
    w.join(&holder, B, None);
    copy(&holder, "desk text");
    let (ev, out) = holder.send("from the iPhone", Kind::Text, Via::Phone).unwrap();
    assert!(ev.via == Via::Phone && out.write && out.seq == 1);
    assert_eq!((local_text(&holder), current_text(&holder)), ("from the iPhone".into(), "from the iPhone".into()));
    assert!(holder.copied("from the iPhone", Kind::Text, Via::Copy).unwrap().is_none());
    // Sending what the clipboard already holds needs no write.
    assert!(!holder.send("from the iPhone", Kind::Text, Via::Phone).unwrap().1.write);
}

/// A MacBook writes the group's text during its rejoin window; Universal
/// Clipboard carries it to the iMac, whose agent reports it. That is not a
/// new copy.
#[test]
fn universal_clipboard_relay() {
    let w = World::new();
    let imac = w.member(A);
    w.join(&imac, B, None);
    copy(&imac, "imac text");
    w.advance(secs(3600));
    imac.received(w.event("laptop's cafe copy", secs(3 * 3600), 0)).unwrap(); // adopted, not written
    assert!(imac.copied("laptop's cafe copy", Kind::Text, Via::Universal).unwrap().is_none());
    assert_eq!(local_text(&imac), "laptop's cafe copy");
    let ev = imac.copied("copied on the iPhone", Kind::Text, Via::Universal).unwrap().unwrap();
    assert_eq!(ev.via, Via::Universal);
}

#[test]
fn hello() {
    let w = World::new();
    let a = w.member(A);
    let h = a.connected(B);
    assert!(h.current.is_none() && h.wall == w.wall());
    let ev = copy(&a, "x");
    w.advance(Duration::from_millis(1500));
    let cur = a.connected(C).current.unwrap();
    assert!(cur.id == ev.id && cur.age == 1500 && cur.text == "x");
}

/// The case that broke an earlier design: an event adopted from a hello
/// must be forwarded, or members behind the adopting one keep an older
/// event and a later copy can sort between the two.
#[test]
fn review_chain() {
    let w = World::new();
    let (a, b, c) = (w.member(A), w.skewed(B, 2000), w.member(C));
    w.join(&a, C, None);
    w.join(&c, A, None);
    c.received(copy(&a, "s")).unwrap();
    w.advance(Duration::from_millis(100));
    c.received(copy(&a, "x")).unwrap();
    w.advance(Duration::from_millis(100));
    let xb = copy(&b, "x"); // the same item, from an offline Mac with a clock 2 s ahead
    let (hb, ha) = (b.connected(A), a.connected(B));
    let out = a.reconcile(B, hb).unwrap();
    let fwd = out.forward.unwrap();
    assert_eq!(fwd.id, xb.id);
    c.received(fwd).unwrap();
    b.reconcile(A, ha).unwrap();
    w.advance(Duration::from_millis(600));
    let y = copy(&c, "y");
    for m in [&a, &b] {
        m.received(y.clone()).unwrap();
    }
    for (name, m) in [("a", &a), ("b", &b), ("c", &c)] {
        assert_eq!(current_text(m), "y", "{name}");
    }
}

/// A muted member's copies, deliberate ones too, stay out of the group
/// until the mute ends.
#[test]
fn mute() {
    let w = World::new();
    let e = w.member(A);
    e.set_mute(w.wall() + 3_600_000);
    assert!(e.copied("noise", Kind::Text, Via::Copy).unwrap().is_none());
    assert!(e.send("deliberate", Kind::Text, Via::Copy).is_err());
    assert_eq!(e.mute_left(), Some(3_600_000));
    w.advance(secs(3600));
    assert_eq!(e.mute_left(), None);
    assert!(e.copied("heard", Kind::Text, Via::Copy).unwrap().is_some());
    e.set_mute(0);
    w.advance(secs(30 * 24 * 3600));
    assert_eq!(e.mute_left(), Some(0));
    e.unmute();
    assert_eq!(e.mute_left(), None);
}

/// A small permuted congruential generator, so that each run of the
/// simulation is the same for its seed.
struct Pcg(u64);

impl Pcg {
    fn next(&mut self) -> u32 {
        let old = self.0;
        self.0 = old.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1_442_695_040_888_963_407);
        let xorshifted = (((old >> 18) ^ old) >> 27) as u32;
        xorshifted.rotate_right((old >> 59) as u32)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() as usize) % n
    }
}

/// A group of members over links that go up and down, with random copies
/// and secrets, deliveries in any order, duplicates, lost messages on broken
/// links, skewed clocks, time steps that cross every window, wake-ups and
/// crashes. At the end the links form a connected but incomplete graph, so
/// forwarding is needed; once every message is delivered, all members hold
/// the same current event, and without crashes it is the latest event made.
///
/// CLIP_SIM_SEEDS sets the number of runs, 300 by default.
#[test]
fn convergence() {
    let seeds = std::env::var("CLIP_SIM_SEEDS").ok().and_then(|s| s.parse::<u64>().ok()).filter(|n| *n > 0);
    for seed in 0..seeds.unwrap_or(300) {
        simulate(seed, seed % 2 == 1);
    }
}

struct Message {
    from: &'static str,
    to: &'static str,
    ev: Event,
}

fn simulate(seed: u64, crashes: bool) {
    let mut rng = Pcg(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ 7);
    let w = World::new();
    let ids = [A, B, C, D];
    let mut offsets = BTreeMap::new();
    let saved: Arc<std::sync::Mutex<BTreeMap<String, Timestamp>>> = Arc::default();
    let mut members: BTreeMap<&str, Engine> = BTreeMap::new();
    let start = |id: &'static str, offset: i64, members: &mut BTreeMap<&str, Engine>| {
        let (w1, w2, up) = (w.wall.clone(), w.wall.clone(), w.up.clone());
        let floor = saved.lock().unwrap().get(id).copied().unwrap_or_default();
        let keep = saved.clone();
        let clock = Clock::new(
            Box::new(move || w1.load(Ordering::SeqCst) + offset),
            floor,
            Some(Box::new(move |m| {
                keep.lock().unwrap().insert(id.to_string(), m);
                true
            })),
        );
        members.insert(
            id,
            Engine::new(
                id,
                clock,
                Box::new(move || w2.load(Ordering::SeqCst) + offset),
                Box::new(move || Duration::from_millis(up.load(Ordering::SeqCst))),
            ),
        );
    };
    for id in ids {
        let offset = rng.below(6001) as i64 - 3000; // up to 3 s either way
        offsets.insert(id, offset);
        start(id, offset, &mut members);
    }
    let key = |x: &'static str, y: &'static str| if x > y { (y, x) } else { (x, y) };
    let mut up: BTreeSet<(&str, &str)> = BTreeSet::new();
    let mut queue: Vec<Message> = Vec::new();
    let mut latest: Option<Event> = None;

    fn send_all(
        ids: &[&'static str],
        up: &BTreeSet<(&str, &str)>,
        queue: &mut Vec<Message>,
        from: &'static str,
        except: &str,
        ev: &Event,
    ) {
        for &to in ids {
            let k = if from > to { (to, from) } else { (from, to) };
            if to != from && to != except && up.contains(&k) {
                queue.push(Message { from, to, ev: ev.clone() });
            }
        }
    }
    let connect = |x: &'static str,
                   y: &'static str,
                   up: &mut BTreeSet<(&str, &str)>,
                   queue: &mut Vec<Message>,
                   members: &BTreeMap<&str, Engine>| {
        up.insert(key(x, y));
        let (hx, hy) = (members[x].connected(y), members[y].connected(x));
        if let Some(f) = members[x].reconcile(y, hy).unwrap().forward {
            send_all(&ids, up, queue, x, y, &f);
        }
        if let Some(f) = members[y].reconcile(x, hx).unwrap().forward {
            send_all(&ids, up, queue, y, x, &f);
        }
    };
    let disconnect = |x: &'static str,
                      y: &'static str,
                      up: &mut BTreeSet<(&str, &str)>,
                      queue: &mut Vec<Message>,
                      members: &BTreeMap<&str, Engine>| {
        up.remove(&key(x, y));
        members[x].disconnected(y);
        members[y].disconnected(x);
        queue.retain(|m| key(m.from, m.to) != key(x, y));
    };
    let deliver = |i: usize,
                   rng: &mut Pcg,
                   up: &BTreeSet<(&str, &str)>,
                   queue: &mut Vec<Message>,
                   members: &BTreeMap<&str, Engine>| {
        let m = queue.remove(i);
        let out = members[m.to].received(m.ev.clone()).unwrap();
        if let Some(f) = out.forward {
            send_all(&ids, up, queue, m.to, m.from, &f);
        }
        if rng.below(5) == 0 {
            queue.push(m); // a duplicate
        }
    };

    for (i, &x) in ids.iter().enumerate() {
        for &y in &ids[i + 1..] {
            if rng.below(2) == 0 {
                connect(x, y, &mut up, &mut queue, &members);
            }
        }
    }
    for _ in 0..150 {
        match rng.below(20) {
            0 => w.advance(secs(rng.below(120) as u64)),         // crosses the windows
            1 => w.step((rng.below(7200) as i64 - 3600) * 1000), // NTP sets the clocks
            _ => w.advance(Duration::from_millis(rng.below(3) as u64)),
        }
        let r = rng.below(22);
        if r < 6 {
            let from = ids[rng.below(ids.len())];
            let kind = if rng.below(5) == 0 { Kind::Secret } else { Kind::Text };
            let text = format!("text {}", rng.below(4));
            let via = [Via::Copy, Via::Phone, Via::Universal][rng.below(3)];
            let ev = if rng.below(3) == 0 {
                Some(members[from].send(&text, kind, via).unwrap().0)
            } else {
                members[from].copied(&text, kind, via).unwrap()
            };
            if let Some(ev) = ev {
                if latest.as_ref().is_none_or(|l| ev.later(l)) {
                    latest = Some(ev.clone());
                }
                send_all(&ids, &up, &mut queue, from, "", &ev);
            }
        } else if r < 10 {
            let (x, y) = (ids[rng.below(ids.len())], ids[rng.below(ids.len())]);
            if x == y {
                continue;
            }
            if up.contains(&key(x, y)) {
                disconnect(x, y, &mut up, &mut queue, &members);
            } else {
                connect(x, y, &mut up, &mut queue, &members);
            }
        } else if r == 10 || (r == 11 && crashes) {
            // A member sleeps and wakes, or crashes and starts again.
            let id = ids[rng.below(ids.len())];
            for other in ids {
                if other != id && up.contains(&key(id, other)) {
                    disconnect(id, other, &mut up, &mut queue, &members);
                }
            }
            if r == 11 {
                start(id, offsets[id], &mut members);
            }
        } else if !queue.is_empty() {
            let i = rng.below(queue.len());
            deliver(i, &mut rng, &up, &mut queue, &members);
        }
    }
    // End on a random spanning tree, plus the links that are still up.
    let mut order = ids.to_vec();
    for i in (1..order.len()).rev() {
        let j = rng.below(i + 1);
        order.swap(i, j);
    }
    for i in 1..order.len() {
        let parent = order[rng.below(i)];
        if !up.contains(&key(order[i], parent)) {
            connect(order[i], parent, &mut up, &mut queue, &members);
        }
    }
    while !queue.is_empty() {
        let i = rng.below(queue.len());
        deliver(i, &mut rng, &up, &mut queue, &members);
    }
    let first = members[A].inner.lock().current.clone();
    for id in ids {
        let got = members[id].inner.lock().current.clone();
        assert_eq!(got.id, first.id, "seed {seed}: member {} holds {:?}, a holds {:?}", &id[..1], got.text, first.text);
    }
    if !crashes && let Some(l) = latest {
        assert_eq!(first.id, l.id, "seed {seed}: the group holds {:?}, the latest made was {:?}", first.text, l.text);
    }
}
