// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Builds for tests only, which a release never ships: the bench's
//! time-scaled build (feature `benchtime`), the build whose wall clock Go's
//! service tests move (`testclock`) and the fuzzing build (`fuzzing`).
//!
//! Three guards keep them out of a release (docs/maintaining.md, "Test
//! builds"): such a build does not compile when CBB_RELEASE_BUILD is set, as
//! the release workflow sets it; `cbb version` names it; and its binary
//! carries [`MARKER`], which the release workflow looks for in every
//! program it publishes.

/// The test features this build was made with, empty for a build a release
/// may ship.
pub const FEATURES: &[&str] = &[
    #[cfg(feature = "benchtime")]
    "benchtime",
    #[cfg(feature = "testclock")]
    "testclock",
    #[cfg(feature = "fuzzing")]
    "fuzzing",
];

/// Whether this is a build for tests only.
pub const ENABLED: bool = !FEATURES.is_empty();

/// The text a build for tests only carries in its binary, and only such a
/// build: the release workflow refuses a program that holds it.
#[cfg(any(feature = "benchtime", feature = "testclock", feature = "fuzzing"))]
pub const MARKER: &str = "cbb-test-build-not-for-release";

// The release workflow builds with CBB_RELEASE_BUILD=1: a test feature
// there is a mistake in the build, which stops here.
#[cfg(any(feature = "benchtime", feature = "testclock", feature = "fuzzing"))]
const _: () = assert!(
    option_env!("CBB_RELEASE_BUILD").is_none(),
    "a build for tests only (feature benchtime, testclock or fuzzing) cannot be a release's"
);

/// What `cbb version` adds to its first line: "" for a build a release may
/// ship, or the marker and the test features.
pub fn version_note() -> String {
    #[cfg(any(feature = "benchtime", feature = "testclock", feature = "fuzzing"))]
    return format!(" ({MARKER}: {})", FEATURES.join(", "));
    #[cfg(not(any(feature = "benchtime", feature = "testclock", feature = "fuzzing")))]
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_test_build_says_so() {
        assert_eq!(ENABLED, !version_note().is_empty());
        for f in FEATURES {
            assert!(version_note().contains(f), "{}", version_note());
        }
    }
}
