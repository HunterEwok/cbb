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

/// The wall clock in milliseconds since the Unix epoch.
pub fn wall_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}
