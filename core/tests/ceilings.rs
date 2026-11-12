// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Groups of records v3 at their sizes and at the format's ceilings
//! (cbb_core::groupgen): what the evaluation and a member's record set take
//! in time and in memory at their peak, each held to a budget. Measured
//! with a counting allocator, so this file is its own test binary.
//!
//! The budgets are for the tests' unoptimised build on a CI runner, with
//! room to spare; `cargo test --release --test ceilings -- --nocapture`
//! prints the numbers of an optimised build, which the board's
//! measurements compare with.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use std::time::{Duration, Instant};

use cbb_core::groupgen::{self, Group};
use cbb_core::records::eval::Stop;
use cbb_core::records::{MAX_DEVICES, MAX_RECORDS, MAX_SET_BYTES};

struct Counting;

static NOW: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

// SAFETY: every call goes to the system allocator unchanged; the counters
// only add and subtract the sizes asked for.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        // SAFETY: as the caller promised for l.
        let p = unsafe { System.alloc(l) };
        if !p.is_null() {
            let now = NOW.fetch_add(l.size(), Relaxed) + l.size();
            PEAK.fetch_max(now, Relaxed);
        }
        p
    }

    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        // SAFETY: p came from alloc with l.
        unsafe { System.dealloc(p, l) };
        NOW.fetch_sub(l.size(), Relaxed);
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

/// The tests of this binary measure one at a time.
static ONE: Mutex<()> = Mutex::new(());

/// Runs f and gives what it took: its result, the time, and the peak of
/// memory above what was allocated before.
fn measure<T>(f: impl FnOnce() -> T) -> (T, Duration, usize) {
    let base = NOW.load(Relaxed);
    PEAK.store(base, Relaxed);
    let t = Instant::now();
    let out = f();
    let took = t.elapsed();
    (out, took, PEAK.load(Relaxed).saturating_sub(base))
}

/// What a group may take: the time of each of the two ways, and the peak
/// as a multiple of the records' own bytes.
struct Budget {
    time: Duration,
    factor: usize,
}

fn run(g: &Group, budget: &Budget) {
    let bytes = g.bytes();
    let (state, t_eval, m_eval) = measure(|| g.evaluate());
    let ((set, set_state), t_set, m_set) = measure(|| g.set());
    println!(
        "{:>5} records {:>8} bytes {:>5} units | evaluate {:>9.1?} {:>9} B peak | set {:>9.1?} {:>9} B peak, keeps {} records {} bytes",
        g.records.len(),
        bytes,
        g.units(),
        t_eval,
        m_eval,
        t_set,
        m_set,
        set.len(),
        set.bytes()
    );
    // The group is whole, both ways.
    for s in [&state, &set_state] {
        assert_eq!(s.stop, Stop::None, "{:?}", s.conflicts);
        assert_eq!(s.roots.len(), 1 + g.spec.takeovers);
        for h in &g.removed {
            assert!(s.revoked.contains(h));
        }
    }
    assert!(set.len() <= MAX_RECORDS && set.bytes() <= MAX_SET_BYTES);
    assert!(t_eval <= budget.time, "evaluate took {t_eval:?}, over {:?}", budget.time);
    assert!(t_set <= budget.time, "the set took {t_set:?}, over {:?}", budget.time);
    assert!(
        m_eval <= budget.factor * bytes,
        "evaluate's peak {m_eval} B is over {}× the records' {bytes} B",
        budget.factor
    );
    assert!(
        m_set <= budget.factor * bytes,
        "the set's peak {m_set} B is over {}× the records' {bytes} B",
        budget.factor
    );
}

#[test]
fn groups_of_5_100_and_1000_records() {
    let _one = ONE.lock().unwrap_or_else(|e| e.into_inner());
    for spec in groupgen::sizes(1) {
        let g = groupgen::build(spec);
        run(&g, &Budget { time: Duration::from_secs(20), factor: 64 });
    }
}

#[test]
fn a_group_at_the_ceilings() {
    let _one = ONE.lock().unwrap_or_else(|e| e.into_inner());
    let g = groupgen::build(groupgen::ceilings(1));
    // Within a few units of the room, and inside it, so that every record
    // counts and the set's sharing still keeps them all.
    let room = MAX_RECORDS as u64;
    assert!(g.units() <= room && g.units() + 32 >= room, "{} units are not at the room's {room}", g.units());
    let devices: usize = g.evaluate().devices.len() + g.removed.len();
    assert_eq!(devices, MAX_DEVICES);
    run(&g, &Budget { time: Duration::from_secs(60), factor: 16 });
}
