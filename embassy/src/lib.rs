// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The lite member's network code on embassy-net, without the chip: the
//! firmware of esp32/ runs it over the ESP32's Wi-Fi, and the program
//! `esp32-on-linux` (the feature `host`) runs the same code on Linux over a TAP
//! interface, so the Go tests can pair with it as the phone (no_std with
//! alloc, as `cbb_core`).

#![no_std]

extern crate alloc;

pub mod pair;
