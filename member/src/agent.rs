// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! cbb agent: links the user session's clipboard with the service. The
//! work is Go's (internal/agent: Wayland and X11, the Mac's and Windows'
//! pasteboard, Windows' remote paste target, the session's quick actions),
//! so the agent starts cbb-helper as its child, with the session's whole
//! environment, and hands it the service's socket; it lasts as long as
//! that request, and the helper ends when the agent does, with the channel.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use crate::control::Header;
use crate::error::{Context, Error, Result};
use crate::helper::{self, Helper};

/// How long the agent's request may run: as long as the session.
const FOREVER: Duration = Duration::from_secs(10 * 365 * 24 * 3600);

/// Runs the agent for the service at socket until the helper's agent ends.
pub fn run(socket: &Path) -> Result<()> {
    if let Some(log) = log_file() {
        // Without its log the agent still links the clipboard; it says so
        // where standard error goes.
        if let Err(e) = crate::logfile::set(&log) {
            eprintln!("cbb: the log: {}", e.for_user());
        }
    }
    let path = helper::locate()
        .ok_or_else(|| Error::msg(format!("cbb agent needs {} beside cbb; install cbb again", helper::PROGRAM)))?;
    let h = Helper::for_agent(&path, Arc::new(crate::service::log_line));
    let body = serde_json::to_vec(&serde_json::json!({ "socket": socket.to_string_lossy() }))
        .context("cannot write the agent's request")?;
    h.call(Header { op: "agent".into(), ..Default::default() }, body, FOREVER)?;
    Ok(())
}

/// Where the agent logs when nothing keeps its standard error: on a Mac
/// started by launchd (packaging/macos/tools.cbb.agent.plist),
/// ~/Library/Logs/cbb/agent.log; on Windows started at sign-in without a
/// console, LocalAppData\cbb\agent.log.
fn log_file() -> Option<std::path::PathBuf> {
    #[cfg(target_os = "macos")]
    if std::env::var("XPC_SERVICE_NAME").as_deref() == Ok("tools.cbb.agent") {
        let home = std::env::var_os("HOME")?;
        return Some(Path::new(&home).join("Library/Logs/cbb/agent.log"));
    }
    #[cfg(windows)]
    if !crate::sys::has_stderr() {
        let dir = std::env::var_os("LOCALAPPDATA")?;
        return Some(Path::new(&dir).join("cbb").join("agent.log"));
    }
    None
}
