// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! What building and loading a record set costs as it grows: a member's set
//! at about 1375, 4330 and 6935 records (the auto-checks' groupgen, the last
//! at table A's ceilings), built from peers (every signature checked) and
//! loaded from the device's own marked store (`load_marked`, no
//! signatures); and the records_set fuzzer's two slow inputs
//! (testdata/records-cost), whose large checkpoints' keep lists made each
//! insert walk them all.
//!
//! The cost is counted two ways: heap allocations, which a counting
//! allocator gives exactly and the same on every run, and the best time of
//! three runs, compared only within one run of this file (a ratio between
//! sizes, never a number of seconds), so that a slower or faster machine
//! moves both sides. A set that grows linearly costs the same per record at
//! every size.
//!
//! These tests fail today: insert scans the whole set for a key's twin at a
//! seq, and walks every checkpoint's keep list. They are ignored, with the
//! counts measured on 3bf589c1 in their messages, until the records' fix
//! turns them on. This file is its own test binary, for the counting
//! allocator.

#[allow(dead_code)]
#[path = "set_cost/fuzzed.rs"]
mod fuzzed;
#[allow(dead_code)]
#[path = "set_cost/groupgen.rs"]
mod groupgen;

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::{Duration, Instant};

use cbb_core::records::RecordSet;

struct Counting;

static ALLOCS: AtomicU64 = AtomicU64::new(0);

// SAFETY: every call goes to the system allocator unchanged; the counter
// only counts the calls.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Relaxed);
        // SAFETY: as the caller promised for l.
        unsafe { System.alloc(l) }
    }

    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        // SAFETY: p came from alloc with l.
        unsafe { System.dealloc(p, l) }
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

/// The tests run one at a time, each holding this from its start: the
/// counter counts every thread's allocations.
static ONE: Mutex<()> = Mutex::new(());

fn alone() -> std::sync::MutexGuard<'static, ()> {
    ONE.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// What one run of f costs: the best time of three, and its allocations
/// (the same in each run).
fn cost<T>(f: impl Fn() -> T) -> (Duration, u64) {
    let mut best = Duration::MAX;
    let mut allocs = 0;
    for _ in 0..3 {
        let before = ALLOCS.load(Relaxed);
        let t = Instant::now();
        let out = f();
        best = best.min(t.elapsed());
        allocs = ALLOCS.load(Relaxed) - before;
        drop(out);
    }
    (best, allocs)
}

/// How much more a record costs at the largest size than at the smallest
/// that a linear set may show: the fixed costs (the path of roots, the
/// lists) and the allocator's own growth.
const GROWTH: f64 = 1.15;

struct Size {
    records: usize,
    kept: usize,
    build: (Duration, u64),
    load: (Duration, u64),
}

fn measure(spec: groupgen::Spec) -> Size {
    let g = groupgen::build(spec);
    let build = cost(|| g.set());
    let (set, _) = g.set();
    let local = [7u8; 32];
    let marked: Vec<_> = set.marked(&local).into_iter().map(|(r, m)| (r.clone(), Some(m))).collect();
    // A start as a member makes it: the store's records, its lists, and
    // the rounds a change of root takes to settle.
    let load = cost(|| {
        let mut m = RecordSet::new(g.root.clone(), g.recovery.clone());
        for _ in 0..3 {
            m.load_marked(&local, marked.iter().cloned());
            for l in &g.lists {
                let _ = m.insert_list(l);
            }
        }
        m
    });
    Size { records: g.records.len(), kept: set.ids().count(), build, load }
}

fn sizes() -> [Size; 3] {
    let mut middle = groupgen::ceilings(1);
    middle.admins = 8;
    middle.root_fill = 1060;
    [measure(groupgen::sizes(1)[2]), measure(middle), measure(groupgen::ceilings(1))]
}

fn per(d: Duration, n: usize) -> f64 {
    d.as_secs_f64() * 1e6 / n as f64
}

fn report(s: &[Size]) -> String {
    s.iter()
        .map(|x| {
            format!(
                "{} records ({} kept): build {:.0} us and {:.1} allocations a record, load {:.0} us and {:.1} \
                 allocations a kept record",
                x.records,
                x.kept,
                per(x.build.0, x.records),
                x.build.1 as f64 / x.records as f64,
                per(x.load.0, x.kept),
                x.load.1 as f64 / x.kept as f64,
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}

// Measured on 3bf589c1 (x86, the test profile, four runs), per record from
// 1375 to 6935 records: build 400-430 → 560-597 us (1.39x to 1.47x), 170.7
// → 153.0 allocations; load 156-182 → 213-225 us a kept record (1.17x to
// 1.39x), 71.5 → 65.1 allocations. The allocations do not grow: the scan
// for a twin allocates nothing, so here the time is what shows it.

/// Building a set from peers costs the same per record at every size.
#[test]
#[ignore = "fails until insert stops scanning the set: build grows 1.39x to 1.47x per record from 1375 to 6935 records"]
fn building_the_set_grows_linearly() {
    let _alone = alone();
    let s = sizes();
    let (a, c) = (&s[0], &s[2]);
    let time = per(c.build.0, c.records) / per(a.build.0, a.records);
    let allocs = (c.build.1 as f64 / c.records as f64) / (a.build.1 as f64 / a.records as f64);
    assert!(time <= GROWTH && allocs <= GROWTH, "time {time:.2}x, allocations {allocs:.2}x: {}", report(&s));
}

/// Loading the device's own store costs the same per kept record at every
/// size: no signatures, so all of it is the set's own work.
#[test]
#[ignore = "fails until insert stops scanning the set: load_marked grows 1.17x to 1.39x per kept record from 1071 to 5698"]
fn loading_the_marked_store_grows_linearly() {
    let _alone = alone();
    let s = sizes();
    let (a, c) = (&s[0], &s[2]);
    let time = per(c.load.0, c.kept) / per(a.load.0, a.kept);
    let allocs = (c.load.1 as f64 / c.kept as f64) / (a.load.1 as f64 / a.kept as f64);
    assert!(time <= GROWTH && allocs <= GROWTH, "time {time:.2}x, allocations {allocs:.2}x: {}", report(&s));
}

/// How much more the fuzzer's inputs may cost with their large checkpoints
/// than without: 24 checkpoints of about 2400 IDs each are some 57 000 IDs
/// to decode, hash and keep once, not once for every insert.
const BIG: f64 = 3.0;

// Measured on 3bf589c1 (x86, the test profile), the two fills (49 records,
// each input the same): without the large checkpoints 57 ms and 107 432
// allocations, with them 2.7 s and 976 334 (47x and 9.1x).

/// The fuzzer's two slow inputs: a member's fill costs about the same with
/// their large checkpoints as without.
#[test]
#[ignore = "fails until insert stops walking every checkpoint's keep list: 47x the time, 9.1x the allocations"]
fn large_checkpoints_cost_once() {
    let _alone = alone();
    for (name, data) in [
        ("slow-1", &include_bytes!("../../testdata/records-cost/slow-1.bin")[..]),
        ("slow-2", &include_bytes!("../../testdata/records-cost/slow-2.bin")[..]),
    ] {
        let fill = |big: bool| {
            let (g, cfg) = fuzzed::build(data, big);
            let every = 1 + usize::from(cfg & 7);
            cost(|| (fuzzed::fill(&fuzzed::order(&g, 0), every), fuzzed::fill(&fuzzed::order(&g, 0x5eed), every + 2)))
        };
        let (small, large) = (fill(false), fill(true));
        let time = large.0.as_secs_f64() / small.0.as_secs_f64();
        let allocs = large.1 as f64 / small.1 as f64;
        assert!(
            time <= BIG && allocs <= BIG,
            "{name}: {time:.1}x the time ({:?} against {:?}), {allocs:.1}x the allocations ({} against {})",
            large.0,
            small.0,
            large.1,
            small.1
        );
    }
}

/// The groups and the inputs this file measures are what it says they are,
/// so that the ignored tests measure the right sets once turned on.
#[test]
fn the_measured_sets_are_the_named_ones() {
    let _alone = alone();
    let g = groupgen::build(groupgen::sizes(1)[2]);
    assert_eq!(g.records.len(), 1375);
    for data in [
        &include_bytes!("../../testdata/records-cost/slow-1.bin")[..],
        &include_bytes!("../../testdata/records-cost/slow-2.bin")[..],
    ] {
        let (big, _) = fuzzed::build(data, true);
        let (small, _) = fuzzed::build(data, false);
        assert_eq!(big.recs.len(), 49);
        let size = |g: &fuzzed::G| g.recs.iter().map(|r| r.envelope().len()).sum::<usize>();
        assert!(size(&big) > size(&small) + 1_500_000, "{} against {}", size(&big), size(&small));
    }
}
