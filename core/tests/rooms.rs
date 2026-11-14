// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Property tests of the rooms (`keep::keep_tiers`): each key keeps the
//! longest run of its first records, whole, within its fixed cap less what
//! it holds first. With f a member's judgment of what it holds, what holds
//! for any records, caps and order:
//!
//! - f(A) is in A, and f(f(A)) = f(A);
//! - for two closed sets X and Y, f(X ∪ Y) is closed;
//! - three or four members that exchange what they hold, pair by pair in
//!   a random order, end equal; the runs here assert a bound on the steps
//!   and print the largest seen (no order on the sets is known to rise at
//!   every step, so termination is checked, not proved);
//! - a key whose records all fit its cap loses none in any order.
//!
//! What does not hold, and is pinned so nobody promises it:
//!
//! - f(f(A) ∪ B) = f(A ∪ B). A record its key cannot fit stops the key's
//!   run, so what comes after it is not kept; once forgotten it stops
//!   nothing, and a later record fits. So one member's end can depend on
//!   the order it got the records in; what members agree on is the end of
//!   their exchange.
//! - that a step moves a member up in the order of its key's records: a
//!   record that comes in and does not fit takes out a later one that
//!   fitted.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicUsize, Ordering};

use cbb_core::records::keep::{self, Item};
use cbb_core::records::{KeyHash, RecordId};
use proptest::prelude::*;

/// A record as the rooms see it: its key, its place, its units, and
/// whether it is a root's early record or a checkpoint.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
struct R {
    key: u8,
    seq: u64,
    n: u8,
    units: u64,
    early: bool,
    checkpoint: bool,
}

impl R {
    fn id(&self) -> RecordId {
        let mut id = [0u8; 32];
        id[0] = self.key;
        id[1..9].copy_from_slice(&self.seq.to_be_bytes());
        id[9] = self.n;
        RecordId(id)
    }

    fn item(&self) -> Item {
        Item {
            signer: KeyHash([self.key; 32]),
            seq: self.seq,
            id: self.id(),
            units: self.units,
            checkpoint: self.checkpoint,
            older: false,
            early: self.early,
        }
    }
}

type Set = BTreeSet<R>;

/// The judgment of one member: each key's newest checkpoint marked, then
/// the rooms with caps and what each key holds first.
fn f(s: &Set, caps: &BTreeMap<u8, u64>, pre: &BTreeMap<u8, u64>) -> Set {
    let mut items: Vec<Item> = s.iter().map(R::item).collect();
    keep::newest_only(&mut items, &[]);
    let pre: BTreeMap<KeyHash, u64> = pre.iter().map(|(k, u)| (KeyHash([*k; 32]), *u)).collect();
    let kept = keep::keep_tiers(&items, |k| caps.get(&k.0[0]).copied(), &pre, &BTreeSet::new());
    s.iter().filter(|r| kept.contains(&r.id())).copied().collect()
}

/// Records of keys 0..keys, a few each, of unequal units; key 0 has early
/// records and checkpoints when `root` is set.
fn records(keys: u8, root: bool) -> impl Strategy<Value = Vec<R>> {
    let one = (0..keys, 1u64..12, 0u8..2, 1u64..4, any::<bool>(), any::<bool>());
    proptest::collection::vec(one, 1..14).prop_map(move |v| {
        let mut out: Vec<R> = v
            .into_iter()
            .map(|(key, seq, n, units, a, b)| R {
                key,
                seq,
                n,
                units,
                early: root && key == 0 && a && !b,
                checkpoint: root && key == 0 && b && !a,
            })
            .collect();
        // One record is one ID.
        out.sort_by_key(R::id);
        out.dedup_by_key(|r| r.id());
        out
    })
}

fn caps(keys: u8) -> impl Strategy<Value = (BTreeMap<u8, u64>, BTreeMap<u8, u64>)> {
    proptest::collection::vec((0u64..10, 0u64..3), keys as usize).prop_map(|v| {
        let caps = v.iter().enumerate().map(|(k, (c, _))| (k as u8, *c)).collect();
        let pre = v.iter().enumerate().map(|(k, (_, p))| (k as u8, *p)).collect();
        (caps, pre)
    })
}

/// A small generator, so that each seed replays exactly.
struct Rng(u64);

impl Rng {
    fn below(&mut self, n: usize) -> usize {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        ((self.0 >> 33) % n.max(1) as u64) as usize
    }
}

/// Members, each given a random part of the records one by one in
/// a random order, judging after each.
fn members(n: usize, recs: &[R], caps: &BTreeMap<u8, u64>, pre: &BTreeMap<u8, u64>, rng: &mut Rng) -> Vec<Set> {
    (0..n)
        .map(|_| {
            let mut s = Set::new();
            let mut mine: Vec<R> = recs.iter().filter(|_| rng.below(3) != 0).copied().collect();
            for i in (1..mine.len()).rev() {
                mine.swap(i, rng.below(i + 1));
            }
            for r in mine {
                s.insert(r);
                s = f(&s, caps, pre);
            }
            s
        })
        .collect()
}

/// The most changes an exchange took in these runs.
static MOST: AtomicUsize = AtomicUsize::new(0);

/// Pairwise exchange (member i takes j's set and judges) in a random
/// order until a whole round of every pair changes nothing; each end of a
/// step closed. The members end equal, within a bound on the changes.
fn exchange(
    m: &mut [Set],
    all: &Set,
    caps: &BTreeMap<u8, u64>,
    pre: &BTreeMap<u8, u64>,
    rng: &mut Rng,
) -> Result<(), TestCaseError> {
    let n = m.len();
    let mut changed = 0usize;
    let bound = n * all.len() * all.len() + n;
    loop {
        let mut pairs: Vec<(usize, usize)> =
            (0..n).flat_map(|i| (0..n).map(move |j| (i, j))).filter(|(i, j)| i != j).collect();
        for i in (1..pairs.len()).rev() {
            pairs.swap(i, rng.below(i + 1));
        }
        let mut quiet = true;
        for (i, j) in pairs {
            let next = f(&m[i].union(&m[j]).copied().collect(), caps, pre);
            prop_assert_eq!(&f(&next, caps, pre), &next, "the union of two closed sets judged is closed");
            if next != m[i] {
                m[i] = next;
                changed += 1;
                quiet = false;
            }
            prop_assert!(changed <= bound, "no end after {} changes", changed);
        }
        if quiet {
            break;
        }
    }
    if MOST.fetch_max(changed, Ordering::Relaxed) < changed {
        std::eprintln!("the most changes an exchange took so far: {changed} ({} members, {} records)", n, all.len());
    }
    prop_assert!(m.iter().all(|s| *s == m[0]), "the members differ at the end: {:?}", m);
    Ok(())
}

fn run_props(
    recs: Vec<R>,
    keys: u8,
    caps: BTreeMap<u8, u64>,
    pre: BTreeMap<u8, u64>,
    seed: u64,
) -> Result<(), TestCaseError> {
    let all: Set = recs.iter().copied().collect();
    let a = f(&all, &caps, &pre);
    prop_assert!(a.is_subset(&all));
    prop_assert_eq!(&f(&a, &caps, &pre), &a);
    let mut rng = Rng(seed);
    for n in [3, 4] {
        let mut m = members(n, &recs, &caps, &pre, &mut rng);
        for s in &m {
            prop_assert!(s.is_subset(&all));
            prop_assert_eq!(&f(s, &caps, &pre), s);
        }
        exchange(&mut m, &all, &caps, &pre, &mut rng)?;
        // A cap that falls (the roster changed): the members judge again
        // and exchange to one end as before.
        let mut lower = caps.clone();
        for c in lower.values_mut() {
            *c = c.saturating_sub(rng.below(4) as u64);
        }
        for s in m.iter_mut() {
            *s = f(s, &lower, &pre);
        }
        exchange(&mut m, &all, &lower, &pre, &mut rng)?;
    }
    // A key whose records all fit loses none, in any order: what it was
    // given stays at every step.
    for k in 0..keys {
        let units: u64 = recs.iter().filter(|r| r.key == k).map(|r| r.units).sum();
        if units.saturating_add(pre.get(&k).copied().unwrap_or(0)) > caps.get(&k).copied().unwrap_or(0) {
            continue;
        }
        let mut order: Vec<R> = recs.clone();
        for i in (1..order.len()).rev() {
            order.swap(i, rng.below(i + 1));
        }
        let mut s = Set::new();
        let mut given = Set::new();
        for r in order {
            s.insert(r);
            given.insert(r);
            s = f(&s, &caps, &pre);
            for g in given.iter().filter(|g| g.key == k) {
                prop_assert!(s.contains(g), "a key within its cap lost {:?}", g);
            }
        }
    }
    Ok(())
}

/// The cases of each property: 512, or ROOMS_CASES for a longer run.
fn cases() -> u32 {
    std::env::var("ROOMS_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(512)
}

proptest! {
    #![proptest_config(ProptestConfig { cases: cases(), failure_persistence: None, ..ProptestConfig::default() })]

    /// One key.
    #[test]
    fn one_key(recs in records(1, false), (caps, pre) in caps(1), seed in any::<u64>()) {
        run_props(recs, 1, caps, pre, seed)?;
    }

    /// Several keys, judged each on its own.
    #[test]
    fn several_keys(recs in records(4, false), (caps, pre) in caps(4), seed in any::<u64>()) {
        run_props(recs, 4, caps, pre, seed)?;
    }

    /// The root's early records and checkpoints: a newer checkpoint moves
    /// the one before it to the end of the root's order.
    #[test]
    fn the_root_s_order_with_checkpoints(recs in records(2, true), (caps, pre) in caps(2), seed in any::<u64>()) {
        run_props(recs, 2, caps, pre, seed)?;
    }
}

/// Pinned: f(f(A) ∪ B) is not f(A ∪ B). One key, cap 2, records of 1, 1,
/// 2 and 1 units in its order; A = {0, 2}, B = {3}. In A record 2 does
/// not fit and stops the run, so f(A) = {0}; f(A) ∪ B keeps 0 and 3; A ∪ B
/// keeps only 0, because 2 still stops what follows it.
#[test]
fn judging_in_steps_is_not_judging_at_once() {
    let r = |seq: u64, units: u64| R { key: 0, seq, n: 0, units, early: false, checkpoint: false };
    let recs = [r(1, 1), r(2, 1), r(3, 2), r(4, 1)];
    let caps = BTreeMap::from([(0u8, 2u64)]);
    let pre = BTreeMap::new();
    let a: Set = [recs[0], recs[2]].into();
    let b: Set = [recs[3]].into();
    let fa = f(&a, &caps, &pre);
    assert_eq!(fa, [recs[0]].into());
    let steps = f(&fa.union(&b).copied().collect(), &caps, &pre);
    let at_once = f(&a.union(&b).copied().collect(), &caps, &pre);
    assert_eq!(steps, [recs[0], recs[3]].into());
    assert_eq!(at_once, [recs[0]].into());
    assert_ne!(steps, at_once);
}

/// Pinned: a step can take a member down in its key's order. One key,
/// cap 2, records of 1, 2 and 1 units; X = {0, 2}, Y = {1}: record 1 comes
/// in, does not fit, and takes out record 2, which fitted.
#[test]
fn a_step_can_take_a_member_down() {
    let r = |seq: u64, units: u64| R { key: 0, seq, n: 0, units, early: false, checkpoint: false };
    let recs = [r(1, 1), r(2, 2), r(3, 1)];
    let caps = BTreeMap::from([(0u8, 2u64)]);
    let pre = BTreeMap::new();
    let x: Set = [recs[0], recs[2]].into();
    let y: Set = [recs[1]].into();
    assert_eq!(f(&x, &caps, &pre), x);
    assert_eq!(f(&y, &caps, &pre), y);
    assert_eq!(f(&x.union(&y).copied().collect(), &caps, &pre), [recs[0]].into());
}
