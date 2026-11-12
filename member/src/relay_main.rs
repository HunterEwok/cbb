// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! cbb-relay runs a blind relay (docs/design.md, "Blind relay") as a
//! service of its own: cbb relay starts it in its place, and its systemd
//! unit runs it under a user of its own, apart from cbb and the keys of
//! cbb-helper.

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = cbb_member::relayd::command::command(&args, &mut std::io::stdout(), &mut std::io::stderr());
    std::process::exit(code);
}
