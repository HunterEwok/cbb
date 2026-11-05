// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The ZX Next's host tests: cbb.drv's bank, and `.cbb` itself on a Next
//! played here (`next`); the tests are in tests/.

pub mod next;
pub mod peers;
pub mod sha256;

/// CRC-32 as zlib computes it, which the lite member's frames carry.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                crc >> 1 ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}
