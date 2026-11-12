// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The joining messages: Info, Welcome, intro, invitation, waiting and
//! dismiss read one way.

#![no_main]
#[path = "alloc_guard.rs"]
mod alloc_guard;
#[global_allocator]
static A: alloc_guard::Counting = alloc_guard::Counting;
use cbb_core::join::{info::Info, intro::Intro, invitation::Invitation, waiting, welcome::Welcome};

fn one(data: &[u8]) {
    if let Ok(i) = Info::decode(data) {
        // Unknown fields are skipped by design: the model reads one way.
        assert_eq!(Info::decode(&i.encode()).as_ref(), Ok(&i), "an info encodes to another");
        let _ = i.admin_key();
    }
    if let Ok(w) = Welcome::decode(data) {
        assert_eq!(Welcome::decode(&w.encode()).as_ref(), Ok(&w), "a welcome encodes to another");
        let g = cbb_core::format::DeviceId([0; 16]);
        let _ = w.check(&g, &[4; 65], &[4; 65]);
    }
    let _ = Welcome::parts(data);
    let _ = Intro::envelopes(data);
    if let Ok(i) = Intro::read(data) {
        assert_eq!(Intro::read(&i.message()).as_ref(), Ok(&i), "an intro writes another");
    }
    if let Ok(inv) = Invitation::decode(data) {
        assert_eq!(Invitation::decode(&inv.encode()).as_ref(), Ok(&inv), "an invitation encodes to another");
        let t = inv.text();
        assert_eq!(Invitation::parse(&t).as_ref(), Ok(&inv), "an invitation's text reads another");
    }
    if let Ok(s) = core::str::from_utf8(data) {
        if let Ok(inv) = Invitation::parse(s) {
            assert_eq!(Invitation::parse(&inv.text()).as_ref(), Ok(&inv), "an invitation text writes another");
        }
    }
    let _ = waiting::read(data);
    if let Ok((inv, key)) = waiting::read_dismiss(data) {
        let again = waiting::read_dismiss(&waiting::dismiss_message(&inv, key.as_ref()));
        assert_eq!(again, Ok((inv, key)), "a dismiss writes another");
    }
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| alloc_guard::bounded(data, one));

