// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! A copy's content, the freshness marks and the copy's checks.

#![no_main]
#[path = "alloc_guard.rs"]
mod alloc_guard;
#[global_allocator]
static A: alloc_guard::Counting = alloc_guard::Counting;
use cbb_core::content::Content;
use cbb_core::copies::{self, fresh::Marks};

fn one(data: &[u8]) {
    if let Ok(c) = Content::read(data) {
        let _ = c.check();
        let _ = (c.is_secret(), c.writable(), c.ttl_ms());
        if c.unknown {
            return;
        }
        let w = c.write().expect("a taken known content does not write");
        assert_eq!(Content::read(&w).as_ref(), Ok(&c), "a content written reads another");
        let high = cbb_core::format::copy::read_content(data)
            .ok()
            .and_then(|v| v.as_map().map(|m| m.iter().any(|(k, _)| *k >= 256)))
            .unwrap_or(true);
        if !high {
            assert_eq!(w, data, "a content does not write back");
        }
    }
    if let Ok(m) = Marks::decode(data) {
        // The marks file is the reader's own; it reads leniently: one model.
        assert_eq!(Marks::decode(&m.encode()).as_ref(), Ok(&m), "marks encode to another");
    }
    let _ = copies::message(data);
    if let Ok(v) = cbb_core::format::cbor::decode(data) {
        let st = cbb_core::records::eval::State::default();
        if let Ok(c) = copies::check(&v, &st) {
            let _ = copies::second(&c, &c);
        }
    }
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| alloc_guard::bounded(data, one));

