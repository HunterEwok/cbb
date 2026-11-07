// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The phones' tunnel (src/tunnel.rs) as a program, for the Go test that
//! runs it against a Go hub (internal/tunnel, TestRustPhoneTunnel): each
//! line on stdin is a request, each answer a line on stdout. At the end of
//! stdin every tunnel stops with the process.

use std::io::{BufRead, Write};

fn main() {
    let stdin = std::io::stdin();
    let mut out = std::io::stdout();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        let answer = cbb_ffi::tunnel::call(line.as_bytes());
        if out.write_all(&answer).and_then(|()| out.write_all(b"\n")).and_then(|()| out.flush()).is_err() {
            break;
        }
    }
}
