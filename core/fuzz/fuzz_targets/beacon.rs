// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! An admin's beacon.

#![no_main]
#[path = "alloc_guard.rs"]
mod alloc_guard;
#[global_allocator]
static A: alloc_guard::Counting = alloc_guard::Counting;
use cbb_core::beacon;

fn one(data: &[u8]) {
    if let Ok((b, e)) = beacon::read(data) {
        assert_eq!(cbb_core::format::envelope::write(e.body, e.sig, e.sig2), data, "a beacon does not write back");
        let st = cbb_core::records::eval::State::default();
        let _ = beacon::check(data, &st);
        let mut f = beacon::Beacons::default();
        let _ = f.take(b);
        let _ = beacon::message(data);
    }
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| alloc_guard::bounded(data, one));

