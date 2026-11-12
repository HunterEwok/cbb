// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The rules that live for days, walked with a moved clock: a takeover's
//! 72 hours, the weekly change of the sealing keys with a device that
//! sleeps through it, a guarded leaf's 35-day grant, and a clock that goes
//! back. The core reads no clock (records rule 7); these tests play the
//! caller that does, hour by hour or day by day, the way a member's
//! service will: it counts the time it held a claim only while it runs,
//! keeps that time and the counted claims across a restart, turns its keys
//! on its own clock and counts a leaf's running time.
//!
//! What the service must add on its side when it moves to this core
//! (wave 5) is listed in docs/testing.md, "Time".

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use crate::commands::{DEFAULT_LIFE_MS, stale};
use crate::content::Content;
use crate::copies::{self, Ask, Kept, Made, Opened};
use crate::format::cbor;
use crate::format::grant::MAX_LIFE_MS;
use crate::hlc::Timestamp;
use crate::keystore::{self, MemoryStore, WEEK_MS};
use crate::records::body::*;
use crate::records::eval::{ClaimState, State};
use crate::records::set::RecordSet;
use crate::records::{Key, Record, RecordId};
use crate::testkit::{G, K, T0, k, sealing, statement_of, store};

const HOUR: u64 = 3_600_000;
const DAY: u64 = 24 * HOUR;

/// A member as its service runs it: a record set, the time it held each
/// claim (counted only while it runs) and the claims it counted, both kept
/// across a restart as the caller must.
struct Member {
    root: Key,
    set: RecordSet,
    held: BTreeMap<RecordId, u64>,
    counted: BTreeSet<RecordId>,
    on: bool,
}

impl Member {
    fn new(root: &Key, records: &[Record]) -> Member {
        let mut set = RecordSet::new(root.clone());
        set.insert_all(records.iter().cloned());
        Member { root: root.clone(), set, held: BTreeMap::new(), counted: BTreeSet::new(), on: true }
    }

    fn state(&self) -> State {
        self.set.state(&self.held)
    }

    /// dt of the member's running time passes: each pending claim is held
    /// that much longer, and a claim that took effect is counted.
    fn run(&mut self, dt: u64) {
        if !self.on {
            return;
        }
        for c in self.state().claims {
            if c.state == ClaimState::Pending {
                let h = self.held.entry(c.record).or_insert(0);
                *h = h.saturating_add(dt);
            }
        }
        let s = self.state();
        self.set.compact(&s);
        self.counted.extend(self.set.counted().iter().copied());
    }

    /// A restart: the set comes back from the records, the held times and
    /// counted claims from what the caller kept.
    fn restart(&mut self, records: &[Record]) {
        let mut set = RecordSet::new(self.root.clone());
        set.remember_counted(self.counted.iter().copied());
        set.insert_all(records.iter().cloned());
        self.set = set;
    }

    fn take(&mut self, records: &[Record]) {
        self.set.insert_all(records.iter().cloned());
    }

    fn claim(&self) -> ClaimState {
        self.state().claims.first().map_or(ClaimState::Void, |c| c.state)
    }
}

/// A group of a root, a phone admin that may take over and a laptop, and
/// the admin's claim for a new root.
fn claimed() -> (G, Record) {
    let mut g = G::new();
    let (_, a) = g.admin("phone a", "admin a", AdminKind::Phone);
    g.device("laptop", ROLE_MEMBER, RIGHT_READ | RIGHT_SEND, |_| {});
    let seen = g.seen();
    let c = g.rec(&a, Kind::Claim { root: k("new root").key.clone(), seen });
    (g, c)
}

#[test]
fn a_takeover_takes_effect_after_72_hours_of_running_time() {
    assert_eq!(DEFAULT_DELAY_MS, 72 * HOUR);
    let (g, _) = claimed();
    let recs = g.records();
    let mut always = Member::new(&g.set.root().clone(), &recs);
    // Off for a day in the middle: it counts only the hours it ran.
    let mut sleeper = Member::new(&g.set.root().clone(), &recs);
    let mut wall = 0;
    let mut effective_at = BTreeMap::new();
    while wall < 120 * HOUR {
        sleeper.on = !(24 * HOUR..48 * HOUR).contains(&wall);
        for (name, m) in [("always", &mut always), ("sleeper", &mut sleeper)] {
            m.run(HOUR);
            if m.claim() == ClaimState::Effective {
                effective_at.entry(name).or_insert(wall + HOUR);
            }
        }
        wall += HOUR;
        // Before 72 hours, never.
        if wall < 72 * HOUR {
            assert_eq!(always.claim(), ClaimState::Pending, "at {} h", wall / HOUR);
            assert_eq!(always.state().claims[0].left_ms, 72 * HOUR - wall);
        }
    }
    assert_eq!(effective_at["always"], 72 * HOUR);
    assert_eq!(effective_at["sleeper"], 96 * HOUR);
    let s = always.state();
    assert_eq!(s.roots, alloc::vec![k("root").hash, k("new root").hash]);
}

#[test]
fn a_restart_keeps_the_held_time_and_the_counted_takeover() {
    let (mut g, c) = claimed();
    let mut m = Member::new(&g.set.root().clone(), &g.records());
    for _ in 0..50 {
        m.run(HOUR);
    }
    // A restart at 50 hours: the held time comes back from what the caller kept.
    m.restart(&g.records());
    assert_eq!(m.state().claims[0].left_ms, 22 * HOUR);
    for _ in 0..22 {
        m.run(HOUR);
    }
    assert_eq!(m.claim(), ClaimState::Effective);
    assert!(m.counted.contains(&c.id()));
    // Counted is final: after a restart that lost the held times, the old
    // root's late cancel does not undo it.
    m.held.clear();
    let late = g.rec(&k("root"), Kind::Resolve(alloc::vec![c.id()]));
    m.restart(&g.records());
    m.take(core::slice::from_ref(&late));
    m.run(HOUR);
    assert_eq!(m.state().roots.len(), 2, "the counted takeover stands");
}

#[test]
fn the_root_cancels_within_the_delay() {
    let (mut g, c) = claimed();
    let mut m = Member::new(&g.set.root().clone(), &g.records());
    for _ in 0..71 {
        m.run(HOUR);
    }
    assert_eq!(m.claim(), ClaimState::Pending);
    let cancel = g.rec(&k("root"), Kind::Resolve(alloc::vec![c.id()]));
    m.take(core::slice::from_ref(&cancel));
    for _ in 0..48 {
        m.run(HOUR);
        assert_ne!(m.claim(), ClaimState::Effective);
    }
    assert_eq!(m.state().roots, alloc::vec![k("root").hash]);
}

#[test]
fn a_clock_that_goes_back_changes_no_claim() {
    // The held time is the member's running time, not the difference of two
    // wall clock readings: a clock set back a day neither undoes held hours
    // nor adds any; the core is handed only the held time.
    let (g, _) = claimed();
    let mut m = Member::new(&g.set.root().clone(), &g.records());
    let mut wall: i64 = 0;
    let mut ran = 0;
    for h in 0..80 {
        wall += if h == 40 { -(DAY as i64) } else { HOUR as i64 };
        m.run(HOUR);
        ran += HOUR;
        if ran < 72 * HOUR {
            assert_eq!(m.claim(), ClaimState::Pending);
        }
    }
    assert!(wall < 72 * HOUR as i64, "the wall clock says less than 72 hours");
    assert_eq!(m.claim(), ClaimState::Effective);
}

/// The phone seals copies; a laptop that sleeps turns its keys only when
/// it runs, on its own clock.
struct Keys {
    g: G,
    phone: K,
    stores: BTreeMap<&'static str, MemoryStore<K>>,
    statements: Vec<crate::records::statement::Statement>,
}

impl Keys {
    fn new() -> Keys {
        let mut g = G::new();
        let phone = g.device("phone", ROLE_PHONE, RIGHT_READ | RIGHT_SEND | RIGHT_SECRETS, |_| {});
        g.device("laptop", ROLE_MEMBER, RIGHT_READ | RIGHT_SEND | RIGHT_SECRETS, |_| {});
        let mut stores = BTreeMap::new();
        let mut statements = Vec::new();
        for name in ["phone", "laptop"] {
            let (s, st) = store(name, &g.gid);
            stores.insert(name, s);
            statements.push(st);
        }
        Keys { g, phone, stores, statements }
    }

    /// A device's keys at its clock now; a new statement is passed on.
    fn rotate(&mut self, name: &'static str, now: u64) -> keystore::Rotated {
        let gid = self.g.gid;
        #[allow(clippy::unwrap_used)]
        let r = keystore::rotate(self.stores.get_mut(name).unwrap(), &gid, now).unwrap();
        if let Some(env) = &r.made {
            self.statements.push(statement_of(env));
        }
        r
    }

    fn sealing(&self) -> BTreeMap<crate::records::DeviceId, crate::records::statement::Sealing> {
        let refs: Vec<&_> = self.statements.iter().collect();
        sealing(&self.g.state(), &refs)
    }
}

fn epochs(s: &MemoryStore<K>) -> Vec<u64> {
    use crate::keystore::KeyStore as _;
    let mut e: Vec<u64> = s.epochs().iter().map(|e| e.epoch).collect();
    e.sort();
    e
}

#[test]
fn the_weekly_key_change_with_a_device_that_sleeps_through_it() {
    let mut w = Keys::new();
    let laptop = k("laptop").key.device_id();
    let content = Content::text("sealed while it slept", false);
    let mut copies = Vec::new();
    // Six weeks, day by day. The phone runs throughout; the laptop sleeps
    // from day 9 to day 30.
    for day in 1..=42u64 {
        let now = T0 + day * DAY;
        w.rotate("phone", now);
        let asleep = (9..30).contains(&day);
        if !asleep {
            let r = w.rotate("laptop", now);
            // Never more than this epoch and the one before.
            assert!(epochs(&w.stores["laptop"]).len() <= 2, "day {day}: {:?}", epochs(&w.stores["laptop"]));
            if day == 30 {
                // Waking after three weeks: one new epoch, the epoch it had
                // been on kept a week for copies sealed to it late, the one
                // before that erased.
                assert!(r.made.is_some(), "no new epoch on waking");
                assert_eq!(r.erased, alloc::vec![1]);
                assert_eq!(epochs(&w.stores["laptop"]), alloc::vec![2, 3]);
            }
        }
        // Each day the phone seals a copy to what it knows of the laptop.
        let state = w.g.state();
        let rs = copies::readers(&state, &w.sealing(), &content, &k("phone").key.device_id(), &[]);
        let m = Made { id: [day as u8; 16], time: Timestamp { wall: now as i64, logical: 0 }, blob: None };
        #[allow(clippy::unwrap_used)]
        let sealed = copies::seal(&w.phone, &rs, &m, &content).unwrap();
        copies.push((day, Kept::new(m, content.clone(), &rs), sealed));
    }
    // On day 42 the laptop opens what it still holds keys for and asks for
    // the rest to be sealed again at its current epoch.
    let state = w.g.state();
    let s = w.sealing();
    let current = s[&laptop].statement.body().epoch;
    let (mut opened, mut resealed) = (0, 0);
    for (day, kept, sealed) in &mut copies {
        let v = cbor::decode(sealed).unwrap();
        let c = copies::check(&v, &state).unwrap();
        match copies::open(&c, &laptop, &w.stores["laptop"]).unwrap() {
            Opened::Content { content: got, .. } => {
                assert_eq!(got, content);
                opened += 1;
            }
            Opened::Reseal { epoch } => {
                assert!(epoch < current, "day {day}");
                let ask =
                    Ask { asker: laptop, epoch: current, leaves: &[], now_ms: Some(T0 + 42 * DAY), group_ttl_ms: DAY };
                let again = copies::reseal(&w.phone, kept, &state, &s, &ask).unwrap();
                let v = cbor::decode(&again).unwrap();
                let c2 = copies::check(&v, &state).unwrap();
                assert!(matches!(copies::open(&c2, &laptop, &w.stores["laptop"]).unwrap(), Opened::Content { .. }));
                resealed += 1;
            }
            other => panic!("day {day}: {other:?}"),
        }
    }
    assert!(opened >= 7 && resealed >= 21, "opened {opened}, sealed again {resealed}");
}

#[test]
fn a_device_clock_that_goes_back_makes_no_epoch_and_erases_nothing() {
    let mut w = Keys::new();
    w.rotate("laptop", T0 + 8 * DAY);
    let before = epochs(&w.stores["laptop"]);
    // Set back by three weeks, then walked forward a day at a time.
    for day in 0..14 {
        let r = w.rotate("laptop", T0 - 21 * DAY + day * DAY);
        assert!(r.made.is_none() && r.erased.is_empty(), "day {day}: {:?}", r.erased);
    }
    assert_eq!(epochs(&w.stores["laptop"]), before);
    assert_eq!(WEEK_MS, 7 * DAY);
}

#[test]
fn a_guarded_grant_lives_35_days_of_the_leafs_running_time() {
    assert_eq!(DEFAULT_LIFE_MS, 35 * DAY);
    assert_eq!(MAX_LIFE_MS, 40 * DAY);
    // The leaf runs except for ten days of no power; its grant counts the
    // running time only, whatever the wall clock says.
    let mut ran = 0;
    let mut stale_at = None;
    for day in 1..=60u64 {
        let powered = !(10..20).contains(&day);
        if powered {
            ran += DAY;
        }
        if stale(true, None, ran) && stale_at.is_none() {
            stale_at = Some(day);
        }
        assert!(!stale(false, None, ran), "an ordinary leaf's grant never goes stale");
        assert_eq!(stale(true, Some(MAX_LIFE_MS), ran), ran >= 40 * DAY);
    }
    assert_eq!(stale_at, Some(45), "35 days of running time, ten of them without power");
}
