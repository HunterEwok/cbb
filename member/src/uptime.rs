// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! A clock for local durations that counts the time the machine sleeps and
//! does not jump when the wall clock is set: CLOCK_BOOTTIME on Linux,
//! CLOCK_MONOTONIC elsewhere (docs/protocol.md, conventions).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// The time since boot.
pub fn now() -> Duration {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let clock = libc::CLOCK_BOOTTIME;
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let clock = libc::CLOCK_MONOTONIC;
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: clock_gettime writes the timespec it is given.
    unsafe { libc::clock_gettime(clock, &mut ts) };
    Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)
}

/// The wall clock in milliseconds since the Unix epoch.
pub fn wall_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}
