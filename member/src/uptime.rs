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
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
        + test_offset_ms()
        + crate::benchtime::clock_offset_ms()
}

/// The milliseconds the Go service's tests move this service's wall clock
/// by, as the Go service's Config.now: the number in the file that
/// CBB_TEST_AHEAD_FILE names in a build with the test hooks, read each time,
/// so that a test can move the clock while the service runs; 0 without it,
/// as a release runs.
fn test_offset_ms() -> i64 {
    static FILE: std::sync::OnceLock<Option<std::path::PathBuf>> = std::sync::OnceLock::new();
    let Some(file) = FILE.get_or_init(|| crate::testhooks::var_os("CBB_TEST_AHEAD_FILE").map(Into::into)) else {
        return 0;
    };
    std::fs::read_to_string(file).ok().and_then(|s| s.trim().parse().ok()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn now_advances() {
        let a = now();
        std::thread::sleep(Duration::from_millis(20));
        let b = now();
        let d = b.saturating_sub(a);
        assert!(
            d >= Duration::from_millis(15) && d <= Duration::from_secs(5),
            "now advanced by {d:?} over a 20 ms sleep"
        );
        assert!(a > Duration::ZERO);
    }

    #[test]
    fn now_counts_like_the_monotonic_clock_awake() {
        // While the machine is awake, the clock runs at the speed of the
        // standard library's monotonic clock.
        let (u0, m0) = (now(), std::time::Instant::now());
        std::thread::sleep(Duration::from_millis(100));
        let (du, dm) = (now().saturating_sub(u0), m0.elapsed());
        let diff = du.as_millis() as i64 - dm.as_millis() as i64;
        assert!(diff.abs() <= 50, "uptime moved {du:?} while the monotonic clock moved {dm:?}");
    }
}
