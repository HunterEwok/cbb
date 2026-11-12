// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! A clock for local durations that counts the time the machine sleeps and
//! does not jump when the wall clock is set: CLOCK_BOOTTIME on Linux,
//! CLOCK_MONOTONIC on the other Unix systems, GetTickCount64 on Windows
//! (docs/protocol.md, conventions).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// The time since boot; in the tests, moved forward by test_run_ms, as if
/// the machine had run that much longer.
pub fn now() -> Duration {
    crate::sys::since_boot().saturating_add(Duration::from_millis(test_run_ms()))
}

/// The wall clock in milliseconds since the Unix epoch; in the tests,
/// moved by test_offset_ms.
pub fn wall_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
        + test_offset_ms()
        + crate::benchtime::clock_offset_ms()
}

/// The milliseconds the Go service's tests move this service's wall clock
/// by, as the Go service's Config.now: the first number in the file that
/// CBB_TEST_AHEAD_FILE names, read each time, so that a test can move the clock
/// while the service runs; 0 without it, as a release runs.
fn test_offset_ms() -> i64 {
    test_clock().0
}

/// The milliseconds the tests move the time since boot forward by: the
/// file's second number, as if the machine had run that much longer (a
/// test that walks a rule of days moves both numbers; one that sets the
/// wall clock moves only the first). It never goes back, whatever the file
/// says, so that the time since boot stays monotonic; 0 without the file.
fn test_run_ms() -> u64 {
    static MOST: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let run = u64::try_from(test_clock().1).unwrap_or(0);
    MOST.fetch_max(run, std::sync::atomic::Ordering::Relaxed).max(run)
}

/// The test clock file's two numbers: the wall clock's offset and the
/// running time's, each 0 when missing.
fn test_clock() -> (i64, i64) {
    static FILE: std::sync::OnceLock<Option<std::path::PathBuf>> = std::sync::OnceLock::new();
    let Some(file) = FILE.get_or_init(|| std::env::var_os("CBB_TEST_AHEAD_FILE").map(Into::into)) else {
        return (0, 0);
    };
    parse_test_clock(&std::fs::read_to_string(file).unwrap_or_default())
}

fn parse_test_clock(s: &str) -> (i64, i64) {
    let mut it = s.split_whitespace().map(|n| n.parse::<i64>().unwrap_or(0));
    (it.next().unwrap_or(0), it.next().unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_test_clock() {
        assert_eq!(parse_test_clock(""), (0, 0));
        assert_eq!(parse_test_clock("3600000\n"), (3_600_000, 0));
        assert_eq!(parse_test_clock("-5 259200000"), (-5, 259_200_000));
        assert_eq!(parse_test_clock("x 7"), (0, 7));
    }

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
