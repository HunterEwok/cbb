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
    key_in(std::env::var_os("STATE_DIRECTORY").map(PathBuf::from), &g.state, name)
}

/// The key file of server name: in systemd's state directory, if there is
/// one, or in state.
fn key_in(state_directory: Option<PathBuf>, state: &Path, name: &str) -> PathBuf {
    let dir = state_directory.unwrap_or_else(|| state.to_path_buf());
    dir.join(if name == "forward" { "forwarder.pem" } else { "relay.pem" })
}

/// The program beside this one, if it is there.
fn beside(program: &str) -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    beside_of(&std::fs::canonicalize(&exe).unwrap_or(exe), program)
}

/// The program beside exe, if it is there.
fn beside_of(exe: &Path, program: &str) -> Option<PathBuf> {
    let p = exe.with_file_name(format!("{program}{}", std::env::consts::EXE_SUFFIX));
    Path::is_file(&p).then_some(p)
}

/// cbb install, on Windows after winget: runs the installer beside this
/// copy, packaging/windows/install.ps1, with args, and ends with its exit
/// code, as the Go cbb's cmdInstall.
pub(crate) fn install(args: &[String]) -> Result<()> {
    if !cfg!(windows) {
        eprintln!(
            "cbb: cbb install is for Windows; on Linux and macOS run packaging/<os>/install.sh from the release archive, or use Homebrew"
        );
        std::process::exit(2);
    }
    let exe = std::env::current_exe().map_err(|e| Error::msg(format!("cannot find this program: {e}")))?;
    let script = installer(&crate::files::real_path(&exe))?;
    let st = Command::new("powershell.exe")
        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-File"])
        .arg(&script)
        .args(args)
        .status()
        .map_err(|e| Error::msg(format!("running {}: {e}", script.display())))?;
    std::process::exit(st.code().unwrap_or(1))
}

/// The installer beside exe, packaging/windows/install.ps1, or why there is
/// none.
fn installer(exe: &Path) -> Result<PathBuf> {
    let script = exe.with_file_name("packaging").join("windows").join("install.ps1");
    if !script.is_file() {
        return Err(Error::msg(format!(
            "this copy of cbb has no installer beside it ({}); install from the release's zip",
            script.display()
        )));
    }
    Ok(script)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The servers' key files: in systemd's state directory when it names
    /// one, in the device's own otherwise; the forwarder's and the relay's
    /// have names of their own.
    #[test]
    fn key_files() {
        let state = Path::new("/var/lib/cbb");
        assert_eq!(key_in(None, state, "forward"), state.join("forwarder.pem"));
        assert_eq!(key_in(None, state, "relay"), state.join("relay.pem"));
        let unit = PathBuf::from("/var/lib/cbb-relay");
        assert_eq!(key_in(Some(unit.clone()), state, "relay"), unit.join("relay.pem"));
        let g = Global { state: state.to_path_buf(), socket: state.join("sock") };
        assert!(key(&g, "forward").ends_with("forwarder.pem"));
    }

    /// A server program is found only beside cbb, and cbb says where to get
    /// one that is not there instead of running anything else.
    #[test]
    fn programs_beside_cbb() {
        let dir = std::env::temp_dir().join(format!("cbb-servers-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let exe = dir.join("cbb");
        assert_eq!(beside_of(&exe, "cbb-relay"), None);
        let relay = dir.join(format!("cbb-relay{}", std::env::consts::EXE_SUFFIX));
        std::fs::write(&relay, b"").unwrap();
        assert_eq!(beside_of(&exe, "cbb-relay"), Some(relay));
        assert_eq!(beside_of(&exe, "cbb-forward"), None);

        let g = Global { state: dir.clone(), socket: dir.join("sock") };
        let err = run(&g, "no-such-server", &[]).unwrap_err();
        assert!(err.message().contains("cbb-no-such-server, which is not beside this cbb"), "{}", err.message());

        let err = installer(&exe).unwrap_err();
        assert!(err.message().contains("no installer beside it"), "{}", err.message());
        let script = dir.join("packaging").join("windows");
        std::fs::create_dir_all(&script).unwrap();
        std::fs::write(script.join("install.ps1"), b"").unwrap();
        assert_eq!(installer(&exe).unwrap(), script.join("install.ps1"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
