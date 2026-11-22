// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Where the `cbb` program under test is.

use std::path::PathBuf;

/// The `cbb` binary built with the tests. Cargo bakes its path in at build
/// time; nextest gives the path at run time too, which is the right one when
/// the tests run from an archive unpacked elsewhere, as the CI's parts do.
pub fn cbb() -> PathBuf {
    std::env::var_os("NEXTEST_BIN_EXE_cbb").map_or_else(|| env!("CARGO_BIN_EXE_cbb").into(), PathBuf::from)
}
