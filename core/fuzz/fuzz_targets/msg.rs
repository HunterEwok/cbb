// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Every numbered message against its table, and the AmneziaWG settings.

#![no_main]
#[path = "alloc_guard.rs"]
mod alloc_guard;
#[global_allocator]
static A: alloc_guard::Counting = alloc_guard::Counting;
use cbb_core::msg;

fn one(data: &[u8]) {
    let _ = msg::check(data);
    if let Ok(o) = msg::Obfuscation::decode(data, "fuzz") {
        assert_eq!(o.encoding(), data, "an obfuscation does not encode back");
        let _ = o.value();
    }
    if let Ok(v) = cbb_core::format::cbor::decode(data) {
        if let Some(a) = v.as_array() {
            let _ = msg::each_once(a);
            let _ = msg::sorted(a);
        }
    }
    if let Ok(s) = core::str::from_utf8(data) {
        let _ = msg::valid_addr(s);
    }
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| alloc_guard::bounded(data, one));

