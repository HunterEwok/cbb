// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! cbb-push runs the project's push service on cbb.tools (src/pushd): it
//! passes sealed bodies from the members of a group to a phone's platform.

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = cbb_member::pushd::command::command(&args, &mut std::io::stdout(), &mut std::io::stderr());
    std::process::exit(code);
}
