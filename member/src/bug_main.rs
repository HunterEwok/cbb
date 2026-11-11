// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! cbb-bug takes the apps' sealed bug reports at bug.cbb.tools behind
//! nginx (src/bugd.rs, docs/core-api.md "Bug reports"), as a service of its
//! own on cbb.tools.

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    std::process::exit(cbb_member::bugd::command(&args, &mut std::io::stderr()));
}
