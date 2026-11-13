// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Properties of the service's copies over random schedules: the members
//! agree on the group's current copy whatever order its events and hellos
//! come in, with duplicates; each member's clock only moves forward, past
//! what it heard, however its wall clock jumps and across restarts; and
//! the rule of incoming copies keeps its promises.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::Duration;

use proptest::prelude::*;

use cbb_core::clip::{Engine, Event, Kind, Via};
use cbb_core::hlc::{self, Clock, Timestamp};
use cbb_core::rule::{self, Incoming, Verdict};

use crate::nettest::{TempDir, now_ms};

/// The file the service keeps its clock's mark in (service.rs).
const MARK_FILE: &str = "hlc.mark";

/// A member with a wall clock and an uptime the test moves.
struct Member {
    id: String,
    engine: Engine,
    wall: Arc<AtomicI64>,
    up: Arc<AtomicU64>,
}

fn member(i: usize, base: i64) -> Member {
    let wall = Arc::new(AtomicI64::new(base));
    let up = Arc::new(AtomicU64::new(1_000_000));
    let id = format!("{i:032x}");
    let w = wall.clone();
    let clock = Clock::new(Box::new(move || w.load(Ordering::SeqCst)), Timestamp::default(), None);
    let (w, u) = (wall.clone(), up.clone());
    let engine = Engine::new(
        &id,
        clock,
        Box::new(move || w.load(Ordering::SeqCst)),
        Box::new(move || Duration::from_millis(u.load(Ordering::SeqCst))),
    );
    Member { id, engine, wall, up }
}

/// One step of a schedule.
#[derive(Clone, Debug)]
enum Step {
    /// Member m copies a new text, its wall clock first moved by jump ms,
    /// back as well as forward.
    Copy { m: usize, jump: i64 },
    /// One of the events made so far (by index, modulo) reaches member m.
    Deliver { m: usize, ev: usize },
    /// Member a connects to member b: b takes a's hello.
    Hello { a: usize, b: usize },
}

fn step() -> impl Strategy<Value = Step> {
    prop_oneof![
        (0usize..8, -600_000i64..600_000).prop_map(|(m, jump)| Step::Copy { m, jump }),
        (0usize..8, any::<usize>()).prop_map(|(m, ev)| Step::Deliver { m, ev }),
        (0usize..8, 0usize..8).prop_map(|(a, b)| Step::Hello { a, b }),
    ]
}

/// What the test checks while it runs a schedule.
#[derive(Default)]
struct Seen {
    events: Vec<Event>,
    /// Per member: the IDs it took, and the latest time it made or heard.
    took: HashMap<usize, HashSet<String>>,
    latest: HashMap<usize, Timestamp>,
    /// Per member: the texts written to its clipboard, in the order of
    /// their sequence numbers.
    writes: HashMap<usize, Vec<(u64, String)>>,
}

impl Seen {
    fn heard(&mut self, m: usize, t: Timestamp) {
        let l = self.latest.entry(m).or_default();
        if t > *l {
            *l = t;
        }
    }

    /// Member m took ev, with outcome out.
    fn took(&mut self, m: usize, ev: &Event, out: &cbb_core::clip::Outcome) -> Result<(), TestCaseError> {
        let first = self.took.entry(m).or_default().insert(ev.id.clone());
        prop_assert_eq!(out.forward.is_some(), first, "an event is sent on once, when it is new");
        if out.write {
            prop_assert!(first, "a copy is written once");
            self.writes.entry(m).or_default().push((out.seq, ev.text.clone()));
        }
        self.heard(m, ev.time);
        Ok(())
    }
}

/// Runs a schedule among n members; each event then reaches every member,
/// in a random order with duplicates, and the members agree.
fn run(n: usize, steps: &[Step], seed: u64) -> Result<(), TestCaseError> {
    let base = now_ms();
    let ms: Vec<Member> = (0..n).map(|i| member(i, base)).collect();
    let mut seen = Seen::default();
    let mut texts = 0usize;
    for s in steps {
        match *s {
            Step::Copy { m, jump } => {
                let m = m % n;
                let me = &ms[m];
                me.wall.fetch_add(jump, Ordering::SeqCst);
                me.up.fetch_add(1, Ordering::SeqCst);
                texts += 1;
                let text = format!("copy {texts}");
                let Some(ev) = me.engine.copied(&text, Kind::Text, Via::Copy).unwrap() else {
                    return Err(TestCaseError::fail("a new text made no event"));
                };
                // The clock moves past all it made and heard, however the
                // wall clock jumped.
                let before = seen.latest.get(&m).copied().unwrap_or_default();
                prop_assert!(ev.time > before, "{} after {}", ev.time, before);
                prop_assert_eq!(&ev.origin, &me.id);
                seen.took.entry(m).or_default().insert(ev.id.clone());
                seen.heard(m, ev.time);
                seen.events.push(ev);
            }
            Step::Deliver { m, ev } if !seen.events.is_empty() => {
                let m = m % n;
                let ev = seen.events[ev % seen.events.len()].clone();
                let out = ms[m].engine.received(ev.clone()).unwrap();
                if ev.origin == ms[m].id {
                    prop_assert!(out.forward.is_none() && !out.write, "a member's own event comes back to nothing");
                    continue;
                }
                seen.took(m, &ev, &out)?;
            }
            Step::Deliver { .. } => {}
            Step::Hello { a, b } => {
                let (a, b) = (a % n, b % n);
                if a == b {
                    continue;
                }
                let h = ms[a].engine.connected(&ms[b].id);
                let cur = h.current.clone();
                let out = ms[b].engine.reconcile(&ms[a].id, h).unwrap();
                if let Some(ev) = cur
                    && ev.origin != ms[b].id
                {
                    seen.took(b, &ev, &out)?;
                }
                ms[a].engine.disconnected(&ms[b].id);
            }
        }
    }
    // Every event reaches every member, in a random order, some twice.
    let mut order: Vec<(usize, usize)> = (0..n).flat_map(|m| (0..seen.events.len()).map(move |e| (m, e))).collect();
    let dups: Vec<_> = order.iter().step_by(3).copied().collect();
    order.extend(dups);
    shuffle(&mut order, seed);
    for (m, e) in order {
        let ev = seen.events[e].clone();
        let out = ms[m].engine.received(ev.clone()).unwrap();
        if ev.origin != ms[m].id {
            seen.took(m, &ev, &out)?;
        }
    }
    let Some(winner) = seen.events.iter().reduce(|a, b| if b.later(a) { b } else { a }) else {
        return Ok(());
    };
    for (i, me) in ms.iter().enumerate() {
        let cur = me.engine.current().unwrap();
        prop_assert_eq!(&cur.id, &winner.id, "member {} holds another copy", i);
        // Its clipboard got the winner last, unless it made it: the
        // winner was the newest whenever it came, and young.
        let mut w = seen.writes.remove(&i).unwrap_or_default();
        w.sort();
        if winner.origin != me.id {
            prop_assert_eq!(w.last().map(|x| x.1.as_str()), Some(winner.text.as_str()), "member {}", i);
        } else {
            prop_assert!(w.iter().all(|x| x.1 != winner.text));
        }
    }
    Ok(())
}

fn shuffle<T>(v: &mut [T], mut seed: u64) {
    for i in (1..v.len()).rev() {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        v.swap(i, (seed >> 33) as usize % (i + 1));
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 200, failure_persistence: None, ..ProptestConfig::default() })]

    #[test]
    fn members_agree_in_any_order(
        n in 2usize..6,
        steps in prop::collection::vec(step(), 1..60),
        seed in any::<u64>(),
    ) {
        run(n, &steps, seed)?;
    }

    /// A clock only moves forward: past every timestamp it issued and
    /// observed, whatever its wall clock reads, until the largest wall time.
    #[test]
    fn the_clock_moves_forward(
        start in 1_767_225_600_000i64..1_900_000_000_000,
        ops in prop::collection::vec((any::<bool>(), -3_600_000i64..3_600_000, 0i64..7_200_000, any::<u16>()), 1..200),
    ) {
        let wall = Arc::new(AtomicI64::new(start));
        let w = wall.clone();
        let c = Clock::new(Box::new(move || w.load(Ordering::SeqCst)), Timestamp::default(), None);
        let mut last = Timestamp::default();
        for (local, jump, ahead, logical) in ops {
            wall.fetch_add(jump, Ordering::SeqCst);
            if local {
                let t = c.now();
                prop_assert!(t > last, "{t} after {last}");
                prop_assert!(t.wall >= wall.load(Ordering::SeqCst).min(hlc::MAX_WALL));
                last = t;
            } else {
                let r = Timestamp { wall: wall.load(Ordering::SeqCst) + ahead - 3_600_000, logical: u32::from(logical) };
                c.observe(r);
                if r > last {
                    last = r;
                }
                prop_assert!(c.now() > last);
                last = c.now();
            }
        }
    }

    /// The rule of incoming copies: what never writes, and that a copy
    /// written at one age is written at every younger one.
    #[test]
    fn the_rule_keeps_its_promises(
        flags in any::<[bool; 7]>(),
        kind in prop_oneof![Just(Kind::Text), Just(Kind::Secret), Just(Kind::Media)],
        age in 0i64..400_000,
        younger in 0i64..400_000,
        window in 1i64..300_000,
        ttl in 1i64..300_000,
    ) {
        let i = Incoming {
            receives: flags[0], kind, mark: flags[1], unread: flags[2], has_text: flags[3],
            has_media: flags[4], takes_media: flags[5], held: flags[6],
            age_ms: age, window_ms: window, secret_ttl_ms: ttl,
        };
        let v = rule::incoming(&i);
        if v == Verdict::Write {
            prop_assert!(i.receives && !i.mark && !i.unread && !i.held && age < window);
            prop_assert!(i.has_text || (i.takes_media && i.has_media));
            prop_assert!(kind != Kind::Secret || age < ttl);
            let y = Incoming { age_ms: younger.min(age), ..i.clone() };
            prop_assert_eq!(rule::incoming(&y), Verdict::Write);
        }
        if v == Verdict::Old {
            let o = Incoming { age_ms: age.max(younger), ..i.clone() };
            prop_assert_ne!(rule::incoming(&o), Verdict::Write);
        }
        if !i.receives {
            prop_assert_eq!(v, Verdict::Mode);
        }
    }
}

/// The service's clock, kept in the state directory, never goes back
/// across restarts, whatever mark a run saved within the limit ahead; a
/// mark beyond it is the trace of a wrong clock, and the clock starts from
/// the wall time again.
#[test]
fn the_saved_clock_never_goes_back() {
    let mut runner = proptest::test_runner::TestRunner::new(ProptestConfig {
        cases: 64,
        failure_persistence: None,
        ..ProptestConfig::default()
    });
    runner
        .run(&(prop::collection::vec((0usize..30, -60_000i64..3_600_000), 1..6)), |restarts| {
            let dir = TempDir::new("clock");
            let mut last = Timestamp::default();
            for (n, ahead) in restarts {
                // A mark another run saved, ahead of the wall clock: a run
                // saves only marks above the ones before.
                let mark = Timestamp { wall: now_ms() + ahead, logical: 3 };
                if ahead >= 0 && mark > last {
                    std::fs::write(dir.0.join(MARK_FILE), format!("{mark}\n")).unwrap();
                    last = mark;
                }
                let c = crate::service::clock(&dir.0);
                for _ in 0..n {
                    let t = c.now();
                    prop_assert!(t > last, "{t} after {last}");
                    last = t;
                }
            }
            Ok(())
        })
        .unwrap();

    let dir = TempDir::new("clock");
    let far = Timestamp { wall: now_ms() + hlc::MAX_AHEAD + 60_000, logical: 0 };
    std::fs::write(dir.0.join(MARK_FILE), format!("{far}\n")).unwrap();
    let t = crate::service::clock(&dir.0).now();
    assert!(t < far && t.wall >= now_ms() - 1000, "{t}");
}
