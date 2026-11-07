// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The memory the evaluation takes for a set at the limit on records
//! (docs/protocol.md, section 10, "Limits"): the ESP32 holds the set and the
//! evaluation in its PSRAM, so the peak is held to a few times the set.
//! Measured with a counting allocator, so this file is its own test binary
//! with one test.

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

use cbb_core::authority::{self, Input, Record};
use cbb_core::certs::Cert;

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

/// How many times the records' own bytes the evaluation may take at its
/// peak, on a 64-bit host (on the ESP32's 32 bits the structures are
/// smaller still).
const FACTOR: usize = 8;

#[test]
fn a_set_at_the_limit_fits() {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../testdata/interop/v2-flood.json");
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let mut checked = 0;
    for c in v["cases"].as_array().unwrap() {
        let records: Vec<Record> = serde_json::from_value(c["records"].clone()).unwrap();
        let ca: Vec<u8> =
            serde_json::from_value::<Record>(serde_json::json!({"body": c["group_ca"], "sig": ""})).unwrap().body;
        let ca = Cert::parse(&ca).unwrap();
        let first_seen = BTreeMap::new();
        let input = Input {
            group_ca: &ca,
            group: c["group"].as_str().unwrap(),
            records: &records,
            now_ms: c["now_ms"].as_i64().unwrap(),
            first_seen: &first_seen,
            time_unknown: false,
            sigs: None,
        };
        let size: usize =
            records.iter().map(|r| r.body.len() + r.sig.len() + r.chain.iter().map(Vec::len).sum::<usize>()).sum();
        let base = NOW.load(Relaxed);
        PEAK.store(base, Relaxed);
        let state = authority::evaluate(&input);
        let peak = PEAK.load(Relaxed) - base;
        drop(state);
        assert!(records.len() > authority::MAX_RECORDS);
        assert!(
            peak <= FACTOR * size,
            "{}: the evaluation took {} KiB at its peak for {} KiB of records",
            c["name"],
            peak >> 10,
            size >> 10
        );
        checked += 1;
    }
    assert!(checked >= 2);
}
