// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The small parts of meeting at a relay: its errors in short, the pins,
//! the test resolver, and the check of a call's caller.

use super::*;

#[test]
fn problems_in_short() {
    assert!(problem("the relay refused the registration: x", false).contains("refused"));
    assert!(problem("its key is not the one given", true).contains("signed list"));
    assert!(problem("its key is not the one given", false).contains("-key"));
    assert!(problem("reaching the relay: refused", false).contains("could not be reached"));
    assert!(problem("the relay's tunnel does not answer", false).contains("UDP port"));
    assert!(problem("other", false).contains("failed"));
}

#[test]
fn pins() {
    assert!(pin_of(PROJECT_PINS[0]).is_ok());
    assert!(pin_of("AAAA").is_err());
    assert!(pin_of(&("A".repeat(43) + "B")).is_err(), "not canonical");
    assert!(test_resolve("cbb.tools").is_none(), "no port");
}

/// A call is served only when the relay named the device that calls from
/// its port; one it never named waits a moment and is refused.
#[test]
fn the_callers() {
    let calls = Arc::new(Mutex::new(VecDeque::from([(7u16, "00112233445566778899aabbccddeeff".to_string())])));
    let check = caller_check(calls.clone());
    let id = DeviceId::parse("00112233445566778899aabbccddeeff").unwrap();
    let other = DeviceId::random();
    assert!(check(7, &id));
    assert!(calls.lock().unwrap().is_empty(), "a call is taken once");
    calls.lock().unwrap().push_back((8, id.to_string()));
    assert!(!check(8, &other));
    let t = Instant::now();
    assert!(!check(9, &id));
    assert!(t.elapsed() >= CALLER_WAIT);
}
