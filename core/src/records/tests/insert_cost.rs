// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! What a record costs the set that takes it, and that making it cheaper
//! changed nothing. The set asks whether a checkpoint above the counting
//! one keeps a record (`waits_for`, a walk of the set's checkpoints) only
//! where the answer decides; it used to ask before every record. Each set
//! here is filled twice, once asking first as before (`OLD_WAITS`), once
//! as now, and after every step the two give the same answer to the step
//! and hold the same: records, digest, place aside, state, notices and
//! what they ask for. The groups have waiting checkpoints, the place
//! aside, a root's two histories and a change of root, in small rooms so
//! that the rooms cut.

use super::*;
use crate::records::eval::Stop;
use crate::records::keep::small::Small;
use crate::records::set::OLD_WAITS;
use alloc::format;
use alloc::string::String;
use core::time::Duration;

/// A step of a member: a record, a list, or a compaction by its own state.
#[derive(Clone)]
enum Step {
    Rec(Box<Record>),
    List(Vec<u8>),
    Compact,
}

/// A small generator, so that each seed replays exactly.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0 >> 33
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

/// Runs f with the set asking what waits before every record, as it did.
fn the_old_way<T>(f: impl FnOnce() -> T) -> T {
    OLD_WAITS.with(|o| o.set(true));
    let out = f();
    OLD_WAITS.with(|o| o.set(false));
    out
}

/// Everything a member shows of its set, as text.
fn shown(m: &mut RecordSet) -> String {
    let st = m.state();
    let missing = m.missing(&st);
    let ids: Vec<&RecordId> = m.ids().collect();
    let aside: Vec<&RecordId> = m.aside().collect();
    format!(
        "digest {:?}\nids {ids:?}\naside {aside:?}\nstate {st:?}\nnotices {:?}\nstuck {:?}\nlist {:?}\nmissing {missing:?}\nlen {} bytes {}",
        m.digest(),
        m.notices(&st),
        m.stuck_checkpoints(),
        m.missing_list(),
        m.len(),
        m.bytes(),
    )
}

/// What the steps of a run met, so that the test shows it reached them.
#[derive(Default)]
struct Met {
    aside: usize,
    stopped: usize,
    changed: usize,
    turned_away: usize,
}

/// Fills two sets with steps, one the old way, and compares them after
/// every step.
fn both_ways(root: &Key, steps: &[Step], what: &str, met: &mut Met) {
    let mut old = set_of(root);
    let mut new = set_of(root);
    for (i, step) in steps.iter().enumerate() {
        let (a, b) = match step {
            Step::Rec(r) => {
                (format!("{:?}", the_old_way(|| old.insert((**r).clone()))), format!("{:?}", new.insert((**r).clone())))
            }
            Step::List(l) => (format!("{:?}", the_old_way(|| old.insert_list(l))), format!("{:?}", new.insert_list(l))),
            Step::Compact => {
                let (so, sn) = (old.state(), new.state());
                (format!("{:?}", the_old_way(|| old.compact(&so))), format!("{:?}", new.compact(&sn)))
            }
        };
        assert_eq!(a, b, "{what}: step {i} answered differently");
        if b.contains("NoRoom") || b.contains("Settled") {
            met.turned_away += 1;
        }
        let (a, b) = (the_old_way(|| shown(&mut old)), shown(&mut new));
        assert_eq!(a, b, "{what}: after step {i} the sets differ");
        let st = new.state();
        met.aside += usize::from(new.aside().next().is_some());
        met.stopped += usize::from(st.stop != Stop::None);
        met.changed += usize::from(st.roots.len() > 1);
    }
}

/// A member's steps for a group's records and lists: shuffled, some held
/// back to the end (so that checkpoints wait for them), some twice, lists
/// anywhere, compactions now and then.
fn steps_of(recs: &[Record], lists: &[Vec<u8>], rng: &mut Rng) -> Vec<Step> {
    let mut first = Vec::new();
    let mut late = Vec::new();
    for r in recs {
        match rng.below(8) {
            0 => late.push(Step::Rec(Box::new(r.clone()))),
            1 => {
                first.push(Step::Rec(Box::new(r.clone())));
                late.push(Step::Rec(Box::new(r.clone())));
            }
            _ => first.push(Step::Rec(Box::new(r.clone()))),
        }
    }
    for l in lists {
        first.push(Step::List(l.clone()));
        late.push(Step::List(l.clone()));
    }
    for i in (1..first.len()).rev() {
        first.swap(i, rng.below(i + 1));
    }
    let mut out = Vec::new();
    for s in first.into_iter().chain(late) {
        out.push(s);
        if rng.below(9) == 0 {
            out.push(Step::Compact);
        }
    }
    out.push(Step::Compact);
    out
}

/// A random group: devices of the root and of admins, the root's
/// copies, checkpoints of the root that keep a part of what is below
/// their heads (some name records no member gets until late), a second
/// history of the root at one seq for some seeds, and a change of root
/// for some, after which the new root does the same.
fn random_group(seed: u64) -> G {
    let mut rng = Rng(seed);
    let mut g = G::new();
    let mut root = k("root");
    let admins: Vec<K> = (0..3).map(|i| k(&format!("admin {i}"))).collect();
    for (i, a) in admins.iter().enumerate() {
        g.admin(&k(&format!("phone {i}")), a, POWER_ADMIT | POWER_REMOVE);
    }
    let change_at = seed.is_multiple_of(3).then(|| 10 + rng.below(20));
    let fork_at = (seed % 4 == 1).then(|| 5 + rng.below(30));
    let steps = 30 + rng.below(30);
    for step in 0..steps {
        if change_at == Some(step) {
            let list = g.listing();
            let na = k("new root");
            g.change(&na, &list);
            root = na;
            continue;
        }
        if fork_at == Some(step) {
            let mine: Vec<Record> = g.recs.iter().filter(|r| r.body().signer == root.hash).cloned().collect();
            if let Some(r) = mine.get(rng.below(mine.len())) {
                let b = r.body();
                let kind = Kind::Copies { incoming_ms: MIN_INCOMING_MS + 7 + step as u64, seen: vec![] };
                let body =
                    Body { group: g.gid, signer: b.signer, seq: b.seq, prev: b.prev, time_ms: 0, kind, held: false };
                let twin = crate::testkit::sign_by(body, &root);
                g.recs.push(twin);
            }
            continue;
        }
        match rng.below(10) {
            0..=2 => {
                g.device(&root, &k(&format!("root device {seed} {step}")), "d", |_| {});
            }
            3..=5 => {
                let a = admins[rng.below(admins.len())].clone();
                g.device(&a, &k(&format!("admin device {seed} {step}")), "d", |_| {});
            }
            6 => {
                g.rec(&root, Kind::Copies { incoming_ms: MIN_INCOMING_MS + step as u64, seen: vec![] });
            }
            _ => {
                let Some(&(seq, id)) = g.heads.get(&root.hash) else { continue };
                let mut heads = vec![Head { key: root.hash, seq, id }];
                for a in &admins {
                    if rng.below(2) == 0
                        && let Some(&(seq, id)) = g.heads.get(&a.hash)
                    {
                        heads.push(Head { key: a.hash, seq, id });
                    }
                }
                heads.sort_by_key(|h| h.key);
                let below: Vec<RecordId> = g
                    .recs
                    .iter()
                    .filter(|r| heads.iter().any(|h| h.key == r.body().signer && r.body().seq <= h.seq))
                    .map(Record::id)
                    .collect();
                let mut keep: Vec<RecordId> = below.into_iter().filter(|_| rng.below(3) != 0).collect();
                if rng.below(5) == 0 {
                    // A record nobody holds: this checkpoint is never whole.
                    keep.push(RecordId([seed as u8; 32]));
                }
                keep.sort();
                keep.dedup();
                g.rec(&root, Kind::Checkpoint { heads, keep });
            }
        }
    }
    g
}

/// Generated groups in small rooms, each taken in two orders: the old way
/// and the new end alike after every step.
#[test]
fn asking_what_waits_only_where_it_decides_changes_nothing() {
    let _small = Small::new(14, 8, 5);
    let mut met = Met::default();
    for seed in 0..48u64 {
        let g = random_group(seed);
        for order in 0..2u64 {
            let mut rng = Rng(seed.wrapping_mul(31).wrapping_add(order));
            let steps = steps_of(&g.recs, &g.lists, &mut rng);
            both_ways(&g.root.key, &steps, &format!("seed {seed} order {order}"), &mut met);
        }
    }
    // The runs reached the place aside, a stop, a change of root and the
    // rooms turning records away.
    std::eprintln!(
        "steps with something aside {}, stopped {}, after a change {}, turned away {}",
        met.aside,
        met.stopped,
        met.changed,
        met.turned_away
    );
    assert!(met.aside > 0 && met.stopped > 0 && met.changed > 0 && met.turned_away > 0);
}

/// The same in the real rooms, on the pool of every kind of record with a
/// change of root, in several orders.
#[test]
fn the_pool_ends_alike_the_old_way_and_the_new() {
    let (root, recs, lists) = pool();
    for seed in 0..6u64 {
        let mut rng = Rng(seed);
        let steps = steps_of(&recs, &lists, &mut rng);
        both_ways(&root, &steps, &format!("pool order {seed}"), &mut Met::default());
    }
}

/// A group at the ceilings: the root at its 1024 units, admins up to
/// theirs, the set at its 4096, with the root's checkpoints. One record
/// costs the set little more than its signature: the fill checks no
/// signature twice, takes less than verifying every record twice, and the
/// last quarter of the records, against its own signatures, costs no more
/// than four times the first. The times are taken side by side in one
/// loop, so a loaded machine changes neither bound.
#[test]
fn a_full_group_fills_in_about_the_time_of_its_signatures() {
    // Timed: without the debug check after every insert.
    let _unchecked = crate::records::set::Unchecked::new();
    let mut g = G::new();
    let root = k("root");
    let admins: Vec<K> = (0..16).map(|i| k(&format!("admin {i}"))).collect();
    let mut admitted: Vec<RecordId> = Vec::new();
    for (i, a) in admins.iter().enumerate() {
        admitted.push(g.admin(&k(&format!("phone {i}")), a, POWER_ADMIT).id());
    }
    let mut root_devices: Vec<Record> = Vec::new();
    for i in 0..5600usize {
        if i.is_multiple_of(4) {
            root_devices.push(g.device(&root, &k(&format!("root device {i}")), "d", |_| {}));
            if root_devices.len().is_multiple_of(200) {
                // A checkpoint keeping the admins and the newest hundred
                // of the root's devices.
                let (seq, id) = g.heads[&root.hash];
                let mut keep: Vec<RecordId> = root_devices.iter().rev().take(100).map(Record::id).collect();
                keep.extend(admitted.iter().copied());
                keep.sort();
                g.rec(&root, Kind::Checkpoint { heads: vec![Head { key: root.hash, seq, id }], keep });
            }
        } else {
            let a = &admins[i % admins.len()];
            g.rec(a, Kind::Copies { incoming_ms: MIN_INCOMING_MS + i as u64, seen: vec![] });
        }
    }
    let key_of = |r: &Record| -> Key {
        if r.body().signer == root.hash {
            return root.key.clone();
        }
        admins.iter().find(|a| a.hash == r.body().signer).map_or(root.key.clone(), |a| a.key.clone())
    };
    // Each record is inserted and its signature verified alone side by
    // side, timed in the same loop, so that a loaded machine slows both
    // alike: the bounds compare the two, never a time with a constant.
    let mut set = set_of(&g.root.key);
    let quarter = g.recs.len() / 4;
    let (mut fill, mut verify) = (Duration::ZERO, Duration::ZERO);
    let mut laps: Vec<(Duration, Duration)> = Vec::new();
    let (mut lap_fill, mut lap_verify) = (Duration::ZERO, Duration::ZERO);
    let verified = super::super::VERIFIED.with(|n| n.get());
    let mut alone = 0usize;
    for (i, r) in g.recs.iter().enumerate() {
        let t = Instant::now();
        let _ = set.insert(r.clone());
        let f = t.elapsed();
        let t = Instant::now();
        let _ = r.verify(&key_of(r));
        let v = t.elapsed();
        alone += 1;
        (fill, verify, lap_fill, lap_verify) = (fill + f, verify + v, lap_fill + f, lap_verify + v);
        if (i + 1).is_multiple_of(quarter) {
            laps.push((lap_fill, lap_verify));
            (lap_fill, lap_verify) = (Duration::ZERO, Duration::ZERO);
        }
    }
    // The work, counted: the fill checks no signature twice.
    let by_fill = super::super::VERIFIED.with(|n| n.get()) - verified - alone;
    assert!(by_fill <= g.recs.len(), "the fill checked {by_fill} signatures for {} records", g.recs.len());
    // The same fill asking what waits before every record, as before.
    let mut before = set_of(&g.root.key);
    let t = Instant::now();
    the_old_way(|| {
        for r in &g.recs {
            let _ = before.insert(r.clone());
        }
    });
    let old = t.elapsed();
    assert_eq!(before.digest(), set.digest());
    let units: u64 = set.ids().filter_map(|id| set.get(id)).map(|r| keep::units(r.size())).sum();
    std::eprintln!(
        "{} records, {} kept ({units} units): fill {fill:?} (asking first {old:?}), verifying all {verify:?}, quarters {laps:?}",
        g.recs.len(),
        set.len()
    );
    // The twelve admins that sign (every fourth record is the root's)
    // fill their ceilings, and the root keeps its newest devices.
    assert!(units > 12 * crate::records::MAX_ADMIN_RECORDS as u64, "the set is near its room: {units} units");
    assert!(fill < verify * 2, "fill {fill:?} against verifying all {verify:?}");
    // Each quarter against its own signatures: the last no dearer than
    // four times the first.
    let ratio = |(f, v): (Duration, Duration)| f.as_secs_f64() / v.as_secs_f64().max(1e-9);
    let (first, last) = (ratio(laps[0]), ratio(laps[laps.len() - 1]));
    assert!(last < first * 4.0, "the last quarter {last:.2} times its signatures against the first {first:.2}");
}

/// An admin's record that the counting checkpoint left out (the set
/// compacted by it), while a newer
/// root checkpoint keeps it and waits for it, goes aside rather than away:
/// the newer checkpoint then counts with it. The set decides it where the
/// record is pruned, asking only there whether a checkpoint above keeps it.
#[test]
fn a_record_the_counting_checkpoint_left_out_waits_for_the_one_above_that_keeps_it() {
    let mut g = G::new();
    let root = k("root");
    let admin = k("admin 0");
    let admission = g.admin(&k("phone 0"), &admin, POWER_ADMIT);
    let copies = g.rec(&admin, Kind::Copies { incoming_ms: MIN_INCOMING_MS, seen: vec![] });
    // The admin's head, an anchor of both checkpoints.
    let newer = g.rec(&admin, Kind::Copies { incoming_ms: MIN_INCOMING_MS + 1, seen: vec![] });
    // Each checkpoint covers the root's line and the admin's.
    let checkpoint = |g: &mut G, keep: Vec<RecordId>| {
        let mut heads: Vec<Head> = [root.hash, admin.hash]
            .iter()
            .map(|h| (h, g.heads[h]))
            .map(|(h, (seq, id))| Head { key: *h, seq, id })
            .collect();
        heads.sort_by_key(|h| h.key);
        let mut keep = keep;
        keep.sort();
        g.rec(&root, Kind::Checkpoint { heads, keep })
    };
    let first = checkpoint(&mut g, vec![admission.id()]);
    let second = checkpoint(&mut g, vec![admission.id(), copies.id()]);
    for old in [false, true] {
        let mut set = set_of(&g.root.key);
        let run = |set: &mut RecordSet| {
            for r in [&admission, &newer, &first, &second] {
                let _ = set.insert(r.clone());
            }
            let st = set.state();
            assert_eq!(st.checkpoint, Some(first.id()), "the first counts, the second waits");
            // The member compacts by the first: the admin's record is pruned.
            let _ = set.compact(&st);
            let got = set.insert(copies.clone());
            (got, set.state().checkpoint)
        };
        let (got, counting) = if old { the_old_way(|| run(&mut set)) } else { run(&mut set) };
        assert!(matches!(got, Ok(Added::Stored | Added::Waiting)), "{got:?}");
        assert_eq!(counting, Some(second.id()), "the second counts with it");
        assert!(set.get(&copies.id()).is_some());
    }
}
