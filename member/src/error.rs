// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Errors with a message for the user and the cause behind it (see
//! cbb_core::error), and where the lite member takes debug mode from.

pub use cbb_core::error::*;

/// Takes debug mode from the environment variable CBB_DEBUG (1 or 0), if
/// set; the -debug flag, read later, overrides it.
pub fn from_env() {
    match std::env::var("CBB_DEBUG").as_deref() {
        Ok("1") | Ok("true") | Ok("yes") => set_show_details(true),
        Ok("0") | Ok("false") | Ok("no") => set_show_details(false),
        _ => {}
    }
}
