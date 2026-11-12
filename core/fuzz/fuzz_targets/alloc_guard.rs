// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! A counting allocator: the peak of live bytes during one input, checked
//! against a bound linear in the input's size.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

pub struct Counting;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(l) };
        if !p.is_null() {
            let now = LIVE.fetch_add(l.size(), Relaxed) + l.size();
            PEAK.fetch_max(now, Relaxed);
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { System.dealloc(p, l) };
        LIVE.fetch_sub(l.size(), Relaxed);
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, new: usize) -> *mut u8 {
        let q = unsafe { System.realloc(p, l, new) };
        if !q.is_null() {
            if new >= l.size() {
                let now = LIVE.fetch_add(new - l.size(), Relaxed) + new - l.size();
                PEAK.fetch_max(now, Relaxed);
            } else {
                LIVE.fetch_sub(l.size() - new, Relaxed);
            }
        }
        q
    }
}

/// Runs f on data and checks that it held at most 512 bytes per input byte
/// plus 8 MiB beyond what was live before.
pub fn bounded(data: &[u8], f: impl FnOnce(&[u8])) {
    let base = LIVE.load(Relaxed);
    PEAK.store(base, Relaxed);
    f(data);
    let extra = PEAK.load(Relaxed).saturating_sub(base);
    let bound = data.len().saturating_mul(512).saturating_add(8 << 20);
    assert!(extra <= bound, "held {extra} bytes for an input of {} (bound {bound})", data.len());
}
