// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! cbb forward and cbb relay: the forwarder and the blind relay are Go
//! programs of their own, cbb-forward and cbb-relay beside cbb. cbb hands
//! the command line to them in its place, so that their systemd units, which
//! run cbb forward or cbb relay under a user of their own, run them apart
//! from this service and from the keys of cbb-helper.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::Global;
use crate::error::{Error, Result};

/// Runs cbb-NAME with args, its key in this device's state directory unless
/// args name another: the program's own -key comes later and wins.
pub(crate) fn run(g: &Global, name: &str, args: &[String]) -> Result<()> {
    let program = format!("cbb-{name}");
    let path = beside(&program).ok_or_else(|| {
        Error::msg(format!(
            "cbb {name} runs {program}, which is not beside this cbb; install it from the release's archive"
        ))
    })?;
    let mut c = Command::new(&path);
    c.arg("-key").arg(key(g, name)).args(args);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let e = c.exec();
        Err(Error::msg(format!("cannot run {}: {e}", path.display())))
    }
    #[cfg(not(unix))]
    {
        let st = c.status().map_err(|e| Error::msg(format!("cannot run {}: {e}", path.display())))?;
        std::process::exit(st.code().unwrap_or(1));
    }
}

/// The key file: in systemd's state directory for the server, or in this
/// device's.
fn key(g: &Global, name: &str) -> PathBuf {
    let dir = std::env::var_os("STATE_DIRECTORY").map(PathBuf::from).unwrap_or_else(|| g.state.clone());
    dir.join(if name == "forward" { "forwarder.pem" } else { "relay.pem" })
}

/// The program beside this one, if it is there.
fn beside(program: &str) -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let exe = std::fs::canonicalize(&exe).unwrap_or(exe);
    let p = exe.with_file_name(format!("{program}{}", std::env::consts::EXE_SUFFIX));
    Path::is_file(&p).then_some(p)
}
