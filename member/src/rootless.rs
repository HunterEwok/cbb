// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Whether this is a rootless install (docs/design.md, "Rootless installs",
//! D-79), as the full member's internal/rootless tells it: the service runs
//! as the user's own systemd user unit, with its files in the user's home,
//! so every program of the user can read its keys. The lite member is never
//! the group's root, an admin or a hub anyway; a rootless one says so in its
//! hello, and it has no console helper and no polkit rule.

use std::path::PathBuf;
use std::sync::OnceLock;

/// The environment variable that install.sh --rootless and the user unit
/// set to 1.
pub const ENV: &str = "CBB_ROOTLESS";

/// Where a rootless install puts the binary, under the home directory.
const BIN: &str = ".local/bin/cbb";

/// Reports whether this program is a rootless install: CBB_ROOTLESS is 1,
/// or it runs from ~/.local/bin/cbb.
pub fn is() -> bool {
    static IS: OnceLock<bool> = OnceLock::new();
    *IS.get_or_init(|| {
        if std::env::var(ENV).as_deref() == Ok("1") {
            return true;
        }
        let (Some(home), Ok(exe)) = (std::env::var_os("HOME"), std::env::current_exe()) else {
            return false;
        };
        let exe = std::fs::canonicalize(&exe).unwrap_or(exe);
        let bin = PathBuf::from(home).join(BIN);
        std::fs::canonicalize(&bin).unwrap_or(bin) == exe
    })
}

/// "sudo " before the commands that change the device's settings, which
/// a rootless install's user runs without it.
pub fn sudo() -> &'static str {
    if is() { "" } else { "sudo " }
}

/// systemctl for the service: the user's own for a rootless install.
pub fn systemctl() -> &'static str {
    if is() { "systemctl --user" } else { "systemctl" }
}

/// journalctl for the service's log.
pub fn journalctl() -> &'static str {
    if is() { "journalctl --user" } else { "journalctl" }
}

/// An XDG base directory: the variable when it names an absolute path,
/// else the default under the home directory.
fn xdg(var: &str, default: &str) -> PathBuf {
    base(std::env::var_os(var), std::env::var_os("HOME"), default)
}

fn base(value: Option<std::ffi::OsString>, home: Option<std::ffi::OsString>, default: &str) -> PathBuf {
    match value.map(PathBuf::from) {
        Some(p) if p.is_absolute() => p,
        _ => PathBuf::from(home.unwrap_or_default()).join(default),
    }
}

/// The state directory: ~/.local/state/cbb.
pub fn state_dir() -> PathBuf {
    xdg("XDG_STATE_HOME", ".local/state").join("cbb")
}

/// The updater's folder: ~/.local/state/cbb-update.
pub fn update_dir() -> PathBuf {
    xdg("XDG_STATE_HOME", ".local/state").join("cbb-update")
}

/// The user's systemd units: ~/.config/systemd/user.
pub fn unit_dir() -> PathBuf {
    xdg("XDG_CONFIG_HOME", ".config").join("systemd/user")
}

/// The control socket, in the user's runtime directory, which the user
/// unit's RuntimeDirectory makes.
pub fn socket() -> PathBuf {
    // SAFETY: getuid has no preconditions and cannot fail.
    socket_in(std::env::var_os("XDG_RUNTIME_DIR"), unsafe { libc::getuid() })
}

fn socket_in(run: Option<std::ffi::OsString>, uid: u32) -> PathBuf {
    let run = match run.map(PathBuf::from) {
        Some(p) if p.is_absolute() => p,
        _ => PathBuf::from(format!("/run/user/{uid}")),
    };
    run.join("cbb/control.sock")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dirs() {
        let home = || Some("/home/u".into());
        assert_eq!(base(None, home(), ".local/state"), PathBuf::from("/home/u/.local/state"));
        assert_eq!(base(Some("relative".into()), home(), ".config"), PathBuf::from("/home/u/.config"));
        assert_eq!(base(Some("/x/state".into()), home(), ".local/state"), PathBuf::from("/x/state"));
        assert_eq!(socket_in(Some("/run/user/7".into()), 1000), PathBuf::from("/run/user/7/cbb/control.sock"));
        assert_eq!(socket_in(None, 1000), PathBuf::from("/run/user/1000/cbb/control.sock"));
    }
}
