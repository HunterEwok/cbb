// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The installer's settings in cbb.env (CBB_PORT, CBB_INTERFACES):
//! systemd, rc.d and procd hand them to the service in its environment,
//! but launchd on a Mac does not, and a cbb run by hand gets them from no
//! one, so each is read from the environment and else from the file, as
//! the Go service's Port did.

use std::path::PathBuf;

/// Where the installer keeps them: ~/.config/cbb/cbb.env for a rootless
/// install, /usr/local/etc/cbb/cbb.env on FreeBSD, /etc/cbb/cbb.env
/// elsewhere.
pub fn file() -> PathBuf {
    if crate::rootless::is() {
        return crate::rootless::config_dir().join("cbb.env");
    }
    if cfg!(target_os = "freebsd") {
        return PathBuf::from("/usr/local/etc/cbb/cbb.env");
    }
    PathBuf::from("/etc/cbb/cbb.env")
}

/// The setting key: from the environment, else its last line in the file;
/// None when neither has it.
pub fn get(key: &str) -> Option<String> {
    if let Ok(v) = std::env::var(key) {
        return Some(v);
    }
    value(&std::fs::read_to_string(file()).unwrap_or_default(), key)
}

/// key's value in lines of KEY=value, the format of systemd's
/// EnvironmentFile: the last line that sets it, without quotes around it.
fn value(text: &str, key: &str) -> Option<String> {
    text.lines()
        .filter_map(|l| l.trim().strip_prefix(key)?.strip_prefix('='))
        .next_back()
        .map(|v| v.trim().trim_matches('"').trim_matches('\'').to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_last_line_of_a_key() {
        let text =
            "# Written by cbb's install.sh\nCBB_PORT=9000\nCBB_PORTS=1\nCBB_INTERFACES=\"eth0 wlan0\"\nCBB_PORT=9001\n";
        assert_eq!(value(text, "CBB_PORT").as_deref(), Some("9001"));
        assert_eq!(value(text, "CBB_INTERFACES").as_deref(), Some("eth0 wlan0"));
        assert_eq!(value(text, "CBB_HOME_CGNAT"), None);
        assert_eq!(value("", "CBB_PORT"), None);
    }
}
