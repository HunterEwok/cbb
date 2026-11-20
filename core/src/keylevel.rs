// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The group's key level (docs/design.md, "Keys in hardware"): where a
//! device's keys must live for it to be the group's root, an admin or a
//! hub. One rule for `cbb` and the phones' apps, with the message a person
//! reads when it says no.

use alloc::format;

use crate::error::{Error, Result};

/// Whether the group's key level lets a device whose key is in store be
/// its root, an admin or a hub: never a rootless install (D-79); at the
/// level `proven` only a key that attestation proves is in hardware; at
/// any other level any hardware; a key in a file only at the level `files`
/// and with the user's consent, which hint says how to give. `name` names
/// the device in the message.
pub fn allows(level: &str, store: &str, name: &str, hint: &str, consent: bool) -> Result<()> {
    let msg = match () {
        _ if store == "rootless" => format!(
            "{name} is installed without root, so every program of its user can read its keys; such a device is never the group's root, an admin or a hub (D-79)"
        ),
        _ if level == "proven" && store != "proven" => format!(
            "attestation does not prove that {name} keeps its key in hardware, and the group's key level lets only such keys be its root, an admin or a hub; on the root, cbb keys hardware lets keys in hardware by the device's own word too"
        ),
        _ if store != "file" => return Ok(()),
        _ if level != "files" => format!(
            "{name} keeps its keys in a file, and the group's key level lets only keys in hardware be its root, an admin or a hub; on the root, cbb keys files lets keys in files too, each time after a warning"
        ),
        _ if !consent => format!(
            "{name} keeps its keys in a file, which a thief with it can copy and then act for it until another admin removes it; to allow it anyway, {hint}"
        ),
        _ => return Ok(()),
    };
    Err(Error::msg(msg))
}

#[cfg(test)]
mod tests {
    use super::allows;

    #[test]
    fn levels() {
        assert!(allows("hardware", "hardware", "a", "", false).is_ok());
        assert!(allows("hardware", "file", "a", "", true).is_err());
        assert!(allows("files", "file", "a", "h", false).unwrap_err().to_string().contains("h"));
        assert!(allows("files", "file", "a", "", true).is_ok());
        assert!(allows("proven", "hardware", "a", "", true).is_err());
        assert!(allows("proven", "proven", "a", "", false).is_ok());
        assert!(allows("files", "rootless", "a", "", true).is_err());
        assert!(allows("proven", "rootless", "a", "", true).unwrap_err().to_string().contains("without root"));
        assert!(allows("hardware", "file", "the phone", "", true).unwrap_err().to_string().contains("the phone"));
    }
}
