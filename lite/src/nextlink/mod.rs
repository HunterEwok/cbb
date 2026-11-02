// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The lite member's network through the ZX Spectrum Next's ESP8266
//! (docs/roadmap.md, "The Next's network in the background"): the frames
//! the Next's driver and the Pi exchange on the Pi's UART, and the ESP
//! driven by its AT commands through them.

pub mod esp;
pub mod frame;
pub mod link;
