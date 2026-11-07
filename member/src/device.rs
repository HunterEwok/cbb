// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! What this computer is, for the hello's device (docs/protocol.md,
//! section 4, "Device"): a board when the device tree names a model, the
//! distribution's version and the MAC address of its network card.

use std::fs;
use std::sync::OnceLock;

use cbb_core::wire::DeviceInfo;

/// This device, found once.
pub fn own() -> &'static DeviceInfo {
    static OWN: OnceLock<DeviceInfo> = OnceLock::new();
    OWN.get_or_init(|| {
        DeviceInfo {
            form: if fs::metadata("/proc/device-tree/model").is_ok() { "board".into() } else { String::new() },
            os_version: fs::read_to_string("/etc/os-release").map(|s| os_release(&s)).unwrap_or_default(),
            version: env!("CARGO_PKG_VERSION").into(),
            mac: mac(),
        }
        .cleaned()
    })
}

/// The pretty name of os-release, or its name and version when that is too
/// long.
fn os_release(text: &str) -> String {
    let get = |key: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(key).and_then(|v| v.strip_prefix('=')))
            .map(|v| v.trim_matches(|c| c == '"' || c == '\'').to_string())
            .unwrap_or_default()
    };
    let pretty = get("PRETTY_NAME");
    if !pretty.is_empty() && pretty.len() <= 32 {
        return pretty;
    }
    format!("{} {}", get("NAME"), get("VERSION_ID")).trim().to_string()
}

/// The MAC address of the first network card that is up, by its name:
/// wired or wireless, no bridge, container or tunnel.
fn mac() -> String {
    let Ok(dir) = fs::read_dir("/sys/class/net") else { return String::new() };
    let mut names: Vec<String> =
        dir.filter_map(|e| e.ok()).map(|e| e.file_name().to_string_lossy().into_owned()).collect();
    names.sort();
    for name in names.iter().filter(|n| n.starts_with("eth") || n.starts_with("en") || n.starts_with("wl")) {
        let read =
            |f: &str| fs::read_to_string(format!("/sys/class/net/{name}/{f}")).unwrap_or_default().trim().to_string();
        if read("operstate") == "up" {
            return read("address").to_lowercase();
        }
    }
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_release_names() {
        assert_eq!(
            os_release(
                "NAME=\"Raspbian GNU/Linux\"\nVERSION_ID=\"13\"\nPRETTY_NAME=\"Raspbian GNU/Linux 13 (trixie)\"\n"
            ),
            "Raspbian GNU/Linux 13 (trixie)"
        );
        assert_eq!(
            os_release("NAME=SteamOS\nVERSION_ID=3.7\nPRETTY_NAME=\"SteamOS Holo with a very long pretty name\"\n"),
            "SteamOS 3.7"
        );
    }

    #[test]
    fn own_is_clean() {
        assert_eq!(*own(), own().cleaned());
        assert_eq!(own().version, env!("CARGO_PKG_VERSION"));
    }
}
