// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The time that TLS sees. The board has no clock of the day yet; the
//! pairing's certificates are checked by the code, not by their dates, so a
//! fixed time after 1970 serves. Syncing with members needs the real time
//! (their certificates expire), which comes with SNTP later.

use alloc::sync::Arc;

use cbb_core::tls::Clock;
use rustls::pki_types::UnixTime;
use rustls::time_provider::TimeProvider;

#[derive(Debug)]
struct Fixed;

impl TimeProvider for Fixed {
    fn current_time(&self) -> Option<UnixTime> {
        Some(UnixTime::since_unix_epoch(core::time::Duration::from_secs(1_790_000_000)))
    }
}

/// A clock that always says the same time, for the pairing and the self-test.
pub fn fixed() -> Clock {
    Arc::new(Fixed)
}
