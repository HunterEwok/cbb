// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| cbb_core::fuzzing::wire(data));
