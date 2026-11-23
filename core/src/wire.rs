// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! What members say to one another beside the records: their
//! capabilities, the answer to a command as the service hands it on, what a
//! device says about itself, the hub's offer for a tunnel key and the size
//! of a blob's chunks.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::certs::b64;

/// What a member can do (section 4, "Capabilities"): be one of the group's
/// hubs, hold an admin key, and dial other members. A capability gives no
/// right: only a record a root or an admin signed does. Every capability,
/// sorted.
pub const CAPS: [&str; 3] = ["admin", "dials", "hub"];

/// The answer to a command (section 15): `done`, `refused` or `failed`, and
/// why for the last two.
#[derive(Serialize, Deserialize, Default, Debug, Clone, PartialEq)]
pub struct CommandResult {
    #[serde(default)]
    pub id: String,
    /// The receiver of the command, which names itself, so that a sender
    /// takes a result a member in between passed back only from it.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub by: String,
    #[serde(default)]
    pub status: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reason: String,
    /// In the result of a hub command, the new hub's offer (section 11,
    /// "Moving the hub"), kept as it came, so a phone passes it back and
    /// its app reads it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tunnel: Option<Value>,
}

/// The most bytes of a result's reason (section 15).
pub const MAX_REASON: usize = 256;

/// Makes a result's reason one the message carries (section 15): a control
/// character (escape included) becomes a space, and it is cut to MAX_REASON
/// bytes at a character boundary. The member that answers cleans it before
/// it writes the result; the message drops a reason that is not clean.
pub fn clean_reason(s: &str) -> String {
    let mut out: String = s.chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
    if out.len() > MAX_REASON {
        let end = (0..=MAX_REASON).rev().find(|&i| out.is_char_boundary(i)).unwrap_or(0);
        out.truncate(end);
    }
    out
}

/// The largest frame between members.
pub const MAX_FRAME: usize = 7 << 20;

/// The most data a chunk of a blob carries.
pub const MAX_CHUNK_DATA: usize = 256 << 10;
/// A chunk frame's size with its padding at most, its length word apart.
pub const MAX_CHUNK_FRAME: usize = 278_528;

/// What a hello says about the sender's device (section 4, "Device"): its
/// form, its system's version, its own version and its network card's MAC
/// address. Shown, never trusted; any field may be empty.
#[derive(Serialize, Deserialize, Default, Debug, Clone, PartialEq)]
pub struct DeviceInfo {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub form: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub os_version: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub version: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub mac: String,
    /// The release archive this device updates from with cbb update
    /// (cbb-linux-arm64.tar.gz), for its group's hub to fetch (section 16).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub archive: String,
}

/// Whether name is a release archive's, as packaging/archive.sh makes
/// them: cbb and two or three dash-separated words of up to 16 lowercase
/// letters and digits, then .tar.gz or .zip.
pub fn archive_name_valid(name: &str) -> bool {
    let Some(stem) = name.strip_suffix(".tar.gz").or_else(|| name.strip_suffix(".zip")) else { return false };
    let Some(rest) = stem.strip_prefix("cbb-") else { return false };
    let words: Vec<&str> = rest.split('-').collect();
    (2..=3).contains(&words.len())
        && words
            .iter()
            .all(|w| (1..=16).contains(&w.len()) && w.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()))
}

/// The forms a device may name, for its icon.
pub const FORMS: [&str; 12] =
    ["laptop", "desktop", "phone", "tablet", "tv", "board", "server", "router", "console", "watch", "retro", "other"];

impl DeviceInfo {
    /// The same without its invalid fields: an unknown form, a version
    /// longer than 32 bytes or with control characters, a MAC address other
    /// than six lowercase hex bytes with colons.
    pub fn cleaned(&self) -> DeviceInfo {
        let short =
            |s: &str| if s.len() <= 32 && !s.chars().any(char::is_control) { s.to_string() } else { String::new() };
        let mac_ok = self.mac.len() == 17
            && self.mac.split(':').count() == 6
            && self
                .mac
                .split(':')
                .all(|p| p.len() == 2 && p.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
        DeviceInfo {
            form: if FORMS.contains(&self.form.as_str()) { self.form.clone() } else { String::new() },
            os_version: short(&self.os_version),
            version: short(&self.version),
            mac: if mac_ok { self.mac.clone() } else { String::new() },
            archive: if archive_name_valid(&self.archive) { self.archive.clone() } else { String::new() },
        }
    }

    /// Whether it says nothing.
    pub fn is_empty(&self) -> bool {
        *self == DeviceInfo::default()
    }
}

/// The group's hub's offer for a member's tunnel key (section 11).
#[derive(Serialize, Deserialize, Default, Clone, PartialEq)]
pub struct TunnelOffer {
    #[serde(with = "b64")]
    pub hub_key: Vec<u8>,
    #[serde(with = "b64")]
    pub psk: Vec<u8>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<String>,
    /// AmneziaWG's settings, when the hub's tunnel is obfuscated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obfuscation: Option<Value>,
    /// The way to the hub's forwarder over VLESS, then the only way.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vless: Option<Value>,
    /// In an offer a hub passes on, the hub it is for: another of the
    /// group's hubs, or the new hub when the sender hands the hub over
    /// (section 11, "Several hubs" and "Moving the hub").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hub: Option<String>,
    /// In an offer passed on, that the sender is no hub any more.
    #[serde(default, skip_serializing_if = "core::ops::Not::not")]
    pub moved: bool,
    /// The key the hub serves with in the next period, which the member
    /// tries after `hub_key` (section 11, "The hub's key"); empty for none.
    #[serde(with = "b64", default, skip_serializing_if = "Vec::is_empty")]
    pub next_key: Vec<u8>,
    /// The AmneziaWG settings the hub serves with together with `next_key`
    /// (section 11, "The hub's key"); absent for the same as `obfuscation`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_obfuscation: Option<Value>,
    /// The way to the hub's forwarder over VLESS with `next_key`: a new
    /// user ID and the path made for it; absent for the same as `vless`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_vless: Option<Value>,
}

impl core::fmt::Debug for TunnelOffer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TunnelOffer")
            .field("hub_key", &self.hub_key)
            .field("psk", &crate::secret::Redacted(self.psk.len()))
            .field("endpoints", &self.endpoints)
            .field("obfuscation", &self.obfuscation.as_ref().map(|_| "<hidden>"))
            .field("vless", &self.vless.as_ref().map(|_| "<hidden>"))
            .field("hub", &self.hub)
            .field("moved", &self.moved)
            .field("next_key", &self.next_key)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::{CommandResult, DeviceInfo, MAX_REASON, archive_name_valid, clean_reason};

    /// A result's reason keeps its text, loses its control characters and
    /// is cut whole characters at a time.
    #[test]
    fn reasons_are_cleaned() {
        for (input, want) in [
            ("the screen is locked", "the screen is locked"),
            ("", ""),
            ("a\x1b[2Jb\x1b]52;c;ZXZpbA==\x07c", "a [2Jb ]52;c;ZXZpbA== c"),
            ("a\nb\tc\r", "a b c "),
            ("a\u{9b}b", "a b"),
            ("écran verrouillé", "écran verrouillé"),
        ] {
            assert_eq!(clean_reason(input), want, "{input:?}");
        }
        assert_eq!(clean_reason(&"a".repeat(1000)).len(), MAX_REASON);
        let cut = clean_reason(&format!("{}é", "a".repeat(MAX_REASON - 1)));
        assert_eq!(cut, "a".repeat(MAX_REASON - 1));
        assert!(clean_reason(&"é".repeat(MAX_REASON)).len() <= MAX_REASON);
    }

    /// A hello's archive is kept only when it is named as
    /// packaging/archive.sh names them, as Go's archivePattern.
    #[test]
    fn archive_names() {
        for ok in ["cbb-linux-arm64.tar.gz", "cbb-windows-amd64.zip", "cbb-linux-mipsle.tar.gz"] {
            assert!(archive_name_valid(ok), "{ok}");
        }
        for bad in [
            "",
            "cbb.tar.gz",
            "cbb-linux.tar.gz",
            "cbb-a-b-c-d.tar.gz",
            "cbb-Linux-arm64.zip",
            "cbb-linux-arm64.tgz",
            "../cbb-linux-arm64.zip",
        ] {
            assert!(!archive_name_valid(bad), "{bad}");
        }
        let d = DeviceInfo { archive: "cbb-linux-arm64.tar.gz/..".into(), ..Default::default() };
        assert!(d.cleaned().archive.is_empty());
    }

    /// A hub command's result keeps the new hub's offer, so a phone that
    /// passes it back, and its app, read it (section 11, "Moving the hub").
    #[test]
    fn a_result_keeps_its_tunnel() {
        let r: CommandResult = serde_json::from_str(r#"{"id":"c","status":"done","tunnel":{"hub_key":"x"}}"#).unwrap();
        assert_eq!(r.tunnel.as_ref().and_then(|t| t["hub_key"].as_str()), Some("x"));
        let again = serde_json::to_value(&r).unwrap();
        assert_eq!(again["tunnel"]["hub_key"], "x");
        assert!(serde_json::to_value(CommandResult::default()).unwrap().get("tunnel").is_none());
    }
}
