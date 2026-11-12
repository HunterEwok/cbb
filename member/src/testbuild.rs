// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Builds for tests only, which a release never ships: the bench's
//! time-scaled build (feature `benchtime`), the build that Go's service
//! tests steer through their hooks (`testhooks`: the variables CBB_TEST_*,
//! read through [`env`] and [`env_os`], and a few shorter waits) and the
//! fuzzing build (`fuzzing`). A build without them reads no hook.
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
    #[cfg(feature = "testhooks")]
    "testhooks",
    #[cfg(feature = "fuzzing")]
    "fuzzing",
];

/// Whether this is a build for tests only.
pub const ENABLED: bool = !FEATURES.is_empty();

/// The text a build for tests only carries in its binary, and only such a
/// build: the release workflow refuses a program that holds it.
#[cfg(any(feature = "benchtime", feature = "testhooks", feature = "fuzzing"))]
pub const MARKER: &str = "cbb-test-build-not-for-release";

// The release workflow builds with CBB_RELEASE_BUILD=1: a test feature
// there is a mistake in the build, which stops here.
#[cfg(any(feature = "benchtime", feature = "testhooks", feature = "fuzzing"))]
const _: () = assert!(
    option_env!("CBB_RELEASE_BUILD").is_none(),
    "a build for tests only (feature benchtime, testhooks or fuzzing) cannot be a release's"
);

/// Whether this build reads the tests' hooks: the bench's and the service
/// tests' builds only.
pub const HOOKS: bool = cfg!(any(feature = "benchtime", feature = "testhooks"));

// A build that reads hooks is a test build, which the guards above catch.
const _: () = assert!(!HOOKS || ENABLED);

/// The test hook `name`, an environment variable such as CBB_TEST_RESOLVE:
/// its value in a build that reads hooks ([`HOOKS`]), else always none, so
/// that a release does as it would without the variable.
pub fn env_os(name: &str) -> Option<std::ffi::OsString> {
    if HOOKS { std::env::var_os(name) } else { None }
}

/// [`env_os`] as text; a value that is not UTF-8 is none.
pub fn env(name: &str) -> Option<String> {
    env_os(name)?.into_string().ok()
}

/// What `cbb version` adds to its first line: "" for a build a release may
/// ship, or the marker and the test features.
pub fn version_note() -> String {
    #[cfg(any(feature = "benchtime", feature = "testhooks", feature = "fuzzing"))]
    return format!(" ({MARKER}: {})", FEATURES.join(", "));
    #[cfg(not(any(feature = "benchtime", feature = "testhooks", feature = "fuzzing")))]
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

    #[test]
    fn hooks_only_in_a_test_build() {
        // PATH is set wherever the tests run.
        assert!(std::env::var_os("PATH").is_some());
        assert_eq!(env_os("PATH").is_some(), HOOKS);
        assert_eq!(env("PATH").is_some(), HOOKS);
    }
}
