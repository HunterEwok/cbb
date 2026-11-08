// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! A clock for local durations that counts the time the machine sleeps and
//! does not jump when the wall clock is set: CLOCK_BOOTTIME on Linux,
//! CLOCK_MONOTONIC on the other Unix systems, GetTickCount64 on Windows
//! (docs/protocol.md, conventions).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// The time since boot.
pub fn now() -> Duration {
    crate::sys::since_boot()
}

/// The wall clock in milliseconds since the Unix epoch; in the tests,
/// moved by test_offset_ms.
pub fn wall_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0) + test_offset_ms()
}

/// The milliseconds the Go service's tests move this service's wall clock
/// by, as the Go service's Config.now: the number in the file that
/// CBB_TEST_CLOCK names, read each time, so that a test can move the clock
/// while the service runs; 0 without it, as a release runs.
fn test_offset_ms() -> i64 {
    static FILE: std::sync::OnceLock<Option<std::path::PathBuf>> = std::sync::OnceLock::new();
    let Some(file) = FILE.get_or_init(|| std::env::var_os("CBB_TEST_CLOCK").map(Into::into)) else { return 0 };
    std::fs::read_to_string(file).ok().and_then(|s| s.trim().parse().ok()).unwrap_or(0)
}
