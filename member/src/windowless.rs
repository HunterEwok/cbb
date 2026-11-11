// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! cbbw.exe: cbb without a console window, which Windows starts at sign-in
//! for the agent (packaging/windows/install.ps1); its log goes to a file
//! (agent.rs), as nothing keeps its standard error.

#![windows_subsystem = "windows"]

fn main() {
    cbb_member::main();
}
