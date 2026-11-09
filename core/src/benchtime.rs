// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The long times of the bench's time-scaled build (docs/testbench-catalogue.md,
//! section 0.1, "time"), as Go's internal/benchtime. Built with the feature
//! `benchtime`, never for a release, the certificates' and credential
//! periods' times run `scale()` times faster, so expiry and renewal play out
//! in minutes; the program sets the scale once at start ([`set_scale`]). In
//! every other build they are the times themselves.

#[cfg(feature = "benchtime")]
static SCALE: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(DEFAULT_SCALE);

/// How many times faster the time-scaled build runs when the program sets
/// no other scale.
pub const DEFAULT_SCALE: u32 = 100_000;

/// Whether this is the time-scaled build.
pub const ENABLED: bool = cfg!(feature = "benchtime");

/// How many times faster long times run: 1 but in the time-scaled build.
pub fn scale() -> i64 {
    #[cfg(feature = "benchtime")]
    return i64::from(SCALE.load(core::sync::atomic::Ordering::Relaxed));
    #[cfg(not(feature = "benchtime"))]
    1
}

/// Sets the scale of the time-scaled build (at least 1, such as 1 for the
/// cases that move only the clock); other builds ignore it.
pub fn set_scale(n: u32) {
    #[cfg(feature = "benchtime")]
    SCALE.store(n.max(1), core::sync::atomic::Ordering::Relaxed);
    #[cfg(not(feature = "benchtime"))]
    let _ = n;
}

/// A long time (in any unit) as this build runs it.
pub fn d(t: i64) -> i64 {
    t.checked_div(scale()).unwrap_or(t)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times_are_themselves_but_in_the_time_scaled_build() {
        if ENABLED {
            set_scale(1000);
            assert_eq!(d(86_400_000), 86_400);
            set_scale(0);
            assert_eq!(scale(), 1);
            set_scale(DEFAULT_SCALE);
        } else {
            set_scale(1000);
            assert_eq!(d(86_400_000), 86_400_000);
        }
    }
}
