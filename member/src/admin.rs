// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The group's root and its admins on a computer (docs/design.md, "Full
//! members, admins and the operating system"), as Go's service does them:
//! cbb new makes a group with this computer as its root, and the root or an
//! admin removes, renames, freezes and unfreezes devices, voids two
//! histories, makes admins and sets the key level, each a record it signs
//! (docs/protocol.md, section 10). The keys it signs with are the admin's
//! fields of the identity file (identity::ADMIN_FIELDS): the group CA key
//! of the computer that made the group, a root key it took the group over
//! with, or an admin key, in a file or in the hardware, with its admin CA.
//! The rules and the messages are Go's (internal/service), which stays the
//! reference.

use std::time::Duration;

use crate::error::{Error, Result};

/// The name of this system in a device record and a hello.
pub fn os_name() -> &'static str {
    match std::env::consts::OS {
        "macos" => "macos",
        "windows" => "windows",
        _ => "linux",
    }
}

/// How long a quick action may take on its device, as Go's actionWait.
pub const ACTION_WAIT: Duration = Duration::from_secs(20);

/// The image sets CBB_CONTAINER (packaging/docker/Dockerfile). A container
/// keeps its keys in a file in its volume, which whoever copies the volume
/// has, so it holds no key that admits or removes devices: it is never the
/// group's root and takes no admin key, unless the user allowed it with
/// CBB_KEYS_IN_FILE=yes after reading why not, as Go's keysAllowed.
const CONTAINER_ENV: &str = "CBB_CONTAINER";
const KEYS_IN_FILE_ENV: &str = "CBB_KEYS_IN_FILE";

/// Why this device may not hold a key that admits devices (the group's
/// root's, an admin's, a recovery claim's): a rootless install never, a
/// container only with its user's consent.
pub(crate) fn keys_allowed() -> Result<()> {
    if crate::rootless::is() {
        return Err(Error::msg(
            "this device is installed without root, so every program of its user can read its keys; such a device never holds the group's keys (D-79)",
        ));
    }
    let container = std::env::var_os(CONTAINER_ENV).is_some_and(|v| !v.is_empty());
    if container && std::env::var(KEYS_IN_FILE_ENV).as_deref() != Ok("yes") {
        return Err(Error::msg(format!(
            "this device runs in a container, whose keys are in a file in its volume, where anyone who copies the volume has them; the group's root and admins belong on the devices you hold, so make the group or the admin there. To allow it here anyway, set {KEYS_IN_FILE_ENV}=yes in the container's environment"
        )));
    }
    Ok(())
}

/// Whether the group's key level lets a device whose key is in store be
/// its root, an admin or a hub: the core's rule (`cbb_core::keylevel`),
/// which the phones' apps share.
pub(crate) fn level_allows(level: &str, store: &str, name: &str, hint: &str, consent: bool) -> Result<()> {
    cbb_core::keylevel::allows(level, store, name, hint, consent)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levels_as_go() {
        assert!(level_allows("hardware", "hardware", "a", "", false).is_ok());
        assert!(level_allows("hardware", "file", "a", "", true).is_err());
        assert!(level_allows("files", "file", "a", "h", false).unwrap_err().to_string().contains("h"));
        assert!(level_allows("files", "file", "a", "", true).is_ok());
        assert!(level_allows("proven", "hardware", "a", "", true).is_err());
        assert!(level_allows("files", "rootless", "a", "", true).is_err());
    }
}
