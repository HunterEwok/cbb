// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The rules that live for days, walked with a moved clock: the weekly
//! change of the sealing keys with a device that sleeps through it, a
//! guarded leaf's 35-day grant, a clock that goes back, and a change of
//! root by the recovery key (rule 33), which waits for no clock at all.
//! The core reads no clock (records rule 7); these tests play the caller
//! that does, hour by hour or day by day, the way a member's service will:
//! it turns its keys on its own clock and counts a leaf's running time.
//!
//! What the service must add on its side when it moves to this core
//! (wave 5) is listed in docs/testing.md, "Time".

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::commands::{DEFAULT_LIFE_MS, stale};
use crate::content::Content;
use crate::copies::{self, Ask, Kept, Made, Opened};
use crate::format::cbor;
use crate::format::grant::MAX_LIFE_MS;
use crate::hlc::Timestamp;
use crate::keystore::{self, MemoryStore, WEEK_MS};
use crate::records::Record;
use crate::records::body::*;
use crate::records::eval::State;
use crate::records::set::RecordSet;
use crate::testkit::{G, K, T0, k, sealing, statement_of, store};

const HOUR: u64 = 3_600_000;
const DAY: u64 = 24 * HOUR;

/// A member's records as its service keeps them: the records and the
/// lists of the changes of root, from which a restart builds the set again.
fn set_of(records: &[Record], lists: &[Vec<u8>]) -> RecordSet {
    let mut set = RecordSet::new(k("root").key.clone(), k("recovery").key.clone());
    for _ in 0..2 {
        set.insert_all(records.iter().cloned());
        for l in lists {
            let _ = set.insert_list(l);
        }
    }
    set
}

/// A group of a root, its phone and a laptop, and the recovery key's
/// change of root to a new root on a new phone, written at time_ms of the
/// writer's clock: the records and the list.
fn changed(time_ms: u64) -> (G, Vec<Record>, Vec<Vec<u8>>) {
    let mut g = G::new();
    g.device("old phone", ROLE_PHONE, RIGHT_READ | RIGHT_SEND | RIGHT_SECRETS, |d| d.holds_root = true);
    g.device("laptop", ROLE_MEMBER, RIGHT_READ | RIGHT_SEND, |_| {});
    let set = set_of(&g.records(), &[]);
    let mut d = Device::new(k("new phone").key.clone(), "new phone", ROLE_PHONE);
    d.rights = RIGHT_READ | RIGHT_SEND | RIGHT_SECRETS;
    #[allow(clippy::unwrap_used)]
    let w = set.write_change(&set.state(), &k("recovery"), &k("new root"), d, &[], false, time_ms).unwrap();
    let mut recs = g.records();
    recs.extend(w.first);
    recs.push(w.record);
    (g, recs, alloc::vec![w.list.encode().to_vec()])
}

fn roots(s: &State) -> Vec<crate::records::KeyHash> {
    s.roots.clone()
}

#[test]
fn a_change_of_root_takes_effect_at_once_whatever_the_clock() {
    // No wait to count and no clock to read: written at any time on the
    // writer's clock, the change counts as soon as a member holds it.
    for time_ms in [0, T0, T0 + 365 * DAY, u64::MAX / 2] {
        let (_, recs, lists) = changed(time_ms);
        let s = set_of(&recs, &lists).state();
        assert_eq!(roots(&s), alloc::vec![k("root").hash, k("new root").hash], "written at {time_ms}");
        assert!(s.root_device.is_some());
    }
}

#[test]
fn a_restart_keeps_the_change_of_root() {
    // What the caller keeps is the records and the lists; the set built
    // again from them, after any time off, has the same state.
    let (_, recs, lists) = changed(T0);
    let before = set_of(&recs, &lists);
    let after = set_of(&recs, &lists);
    assert_eq!(before.digest(), after.digest());
    assert_eq!(roots(&before.state()), roots(&after.state()));
}

#[test]
fn the_old_root_changes_nothing_after_the_change_at_any_time() {
    // The old root's records written after the change (a removal dated
    // years later, or before the group was made) do not count: its
    // records stop at the list, whatever their time says.
    for time_ms in [0, T0 + 3 * 365 * DAY] {
        let (mut g, mut recs, lists) = changed(T0);
        let laptop = k("laptop").hash;
        let seen = g.seen();
        recs.push(g.rec_at(&k("root"), Kind::Revoke(Removal { keys: alloc::vec![laptop], seen }), time_ms));
        let s = set_of(&recs, &lists).state();
        assert!(s.device_by_key(&laptop).is_some(), "the old root's removal at {time_ms} counted");
        assert_eq!(roots(&s).last(), Some(&k("new root").hash));
    }
}

#[test]
fn a_clock_that_goes_back_changes_no_root() {
    // A change written on a clock set back before the root's own records
    // counts just the same: the order is the chain's, not the clock's.
    let (_, recs, lists) = changed(0);
    let s = set_of(&recs, &lists).state();
    assert_eq!(roots(&s).len(), 2);
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
        let r = keystore::rotate(self.stores.get_mut(name).unwrap(), &gid, now, Some(now)).unwrap();
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
        let rs = copies::readers(&state, &w.sealing(), &content, &k("phone").key.device_id(), &[], Some(now));
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
        match copies::open(&c, &laptop, &w.stores["laptop"], &state).unwrap() {
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
                assert!(matches!(
                    copies::open(&c2, &laptop, &w.stores["laptop"], &state).unwrap(),
                    Opened::Content { .. }
                ));
                resealed += 1;
            }
            other => panic!("day {day}: {other:?}"),
        }
    }
    assert!(opened >= 7 && resealed >= 21, "opened {opened}, sealed again {resealed}");
}

#[test]
fn a_device_clock_that_goes_back_does_not_stop_the_weekly_change() {
    // A clock set back by more than a day: the newest epoch looks made in
    // the future, so a new one is made at once rather than waiting weeks
    // for the clock to catch up; the previous one is kept, as at any
    // change, and from then the weeks count on the clock as it is.
    let mut w = Keys::new();
    w.rotate("laptop", T0 + 8 * DAY);
    assert_eq!(epochs(&w.stores["laptop"]), alloc::vec![1, 2]);
    let mut made = Vec::new();
    for day in 0..14 {
        let r = w.rotate("laptop", T0 - 21 * DAY + day * DAY);
        if r.made.is_some() {
            made.push((day, r.erased.clone()));
        } else {
            assert!(r.erased.is_empty(), "day {day}: {:?}", r.erased);
        }
    }
    assert_eq!(made, alloc::vec![(0, alloc::vec![1]), (7, alloc::vec![2])]);
    assert_eq!(epochs(&w.stores["laptop"]), alloc::vec![3, 4]);
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
