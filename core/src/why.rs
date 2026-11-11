// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Why a device does not sync (docs/apps.md, "Why it does not sync"): from
//! what a member knows about itself, its group and its link away from home,
//! the reasons the screen shows, the one that matters most first, each with
//! a stable code, a level and its parameters. The apps only draw them, in
//! their own words for each code; `cbb status` prints the first. Every app
//! and the command line take them from here, so a reason has one test:
//! testdata/why/vectors.json.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

/// A member certificate that ends within so many milliseconds gets the
/// warning `cert_ending`, as `cbb status` warns (30 days).
pub const CERT_WARNING_MS: i64 = 30 * 24 * 3600 * 1000;

/// What a member knows that bears on its sync. Every field is optional in
/// JSON, so a member fills in what it has; a phone has no quiet networks,
/// for example.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Facts {
    /// The device is in a group.
    pub in_group: bool,
    /// The group's records revoke this device.
    pub removed: bool,
    /// The records freeze this admin computer's admin key.
    pub frozen: bool,
    /// The admin that took the group over from this root while it was away.
    pub taken_over_by: String,
    /// When this device's member certificate ends, in Unix milliseconds;
    /// 0 when unknown.
    pub cert_ends_ms: i64,
    /// How far the group's records stop the exchange: "secrets", "full", or
    /// empty (docs/protocol.md, section 10, "Stopping the exchange").
    pub stop: String,
    /// Sync is off here (the clipboard is this device's own), until
    /// sync_until_ms in Unix milliseconds, 0 for until it is turned on.
    pub sync_off: bool,
    pub sync_until_ms: i64,
    /// An admin muted this device, until muted_until_ms, 0 for until an
    /// admin unmutes it.
    pub muted: bool,
    pub muted_until_ms: i64,
    /// How many records of a later version this member keeps.
    pub newer: usize,
    /// A newer release the group passed around, which this device does not
    /// run yet.
    pub update: String,
    /// The members connected now.
    pub connected: usize,
    /// The other devices of the group, as this member lists them.
    pub devices: Vec<DeviceFacts>,
    /// The interfaces on networks where this computer has not met its
    /// group, where it does not publish itself.
    pub quiet: Vec<String>,
    /// Members at home that could not connect to this device.
    pub unreached: Vec<String>,
    /// Sync away from home; None while it is off.
    pub away: Option<AwayFacts>,
}

/// Another device of the group.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct DeviceFacts {
    pub name: String,
    pub online: bool,
    /// Its sync is off, as its hello said.
    pub sync_off: bool,
    pub muted: bool,
}

/// Sync away from home, as a member's away status says.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct AwayFacts {
    /// This device is a hub of the group, waiting (standby) while a hub
    /// above it serves.
    pub hub: bool,
    pub standby: bool,
    /// The hub this device uses; empty while it knows none.
    pub hub_device: String,
    /// Connected to that hub through the tunnel now.
    pub through: bool,
    /// The hub hides its tunnel (AmneziaWG or VLESS).
    pub hidden: bool,
    /// This device meets the others at a relay: whether it is connected.
    pub relay: bool,
    pub relay_connected: bool,
    /// On a hub with a forwarder: whether the forwarder took its
    /// registration, and whether the list of entry points may be stale.
    pub forwarder: bool,
    pub forwarder_registered: bool,
    pub entries_stale: bool,
    /// What went wrong last, for the user.
    pub error: String,
}

/// How much a reason stops.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    /// Nothing syncs on this device.
    Stop,
    /// Some copies or some devices do not sync.
    Warn,
    /// Worth knowing; sync works.
    Info,
}

/// One reason, as the screen shows it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Reason {
    /// The stable code the apps translate (docs/apps.md lists them).
    pub code: String,
    pub level: Level,
    /// A time, in Unix milliseconds: when sync turns on again, a mute ends
    /// or the certificate ends; 0 when the reason has none.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub until_ms: i64,
    /// A device's name: the hub, the admin that took the group over.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub device: String,
    /// The devices a reason is about, by name.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub devices: Vec<String>,
    /// A version, or a count of records as text.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub value: String,
    /// The member's own words for what went wrong, for the details.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detail: String,
}

fn is_zero(n: &i64) -> bool {
    *n == 0
}

impl Reason {
    fn new(code: &str, level: Level) -> Reason {
        Reason {
            code: code.to_string(),
            level,
            until_ms: 0,
            device: String::new(),
            devices: Vec::new(),
            value: String::new(),
            detail: String::new(),
        }
    }
}

/// The reasons from facts at now_ms (Unix milliseconds), the one that
/// stops the most first; empty when everything syncs. A device in no group
/// has the one reason `not_in_group`; a removed one only `removed`, since
/// nothing else matters until it leaves.
pub fn diagnose(f: &Facts, now_ms: i64) -> Vec<Reason> {
    let mut out = Vec::new();
    if !f.in_group {
        out.push(Reason::new("not_in_group", Level::Stop));
        return out;
    }
    if f.removed {
        out.push(Reason::new("removed", Level::Stop));
        return out;
    }
    if !f.taken_over_by.is_empty() {
        let mut r = Reason::new("taken_over", Level::Stop);
        r.device = f.taken_over_by.clone();
        out.push(r);
    }
    if f.frozen {
        out.push(Reason::new("frozen", Level::Stop));
    }
    if f.cert_ends_ms > 0 && f.cert_ends_ms <= now_ms {
        let mut r = Reason::new("cert_expired", Level::Stop);
        r.until_ms = f.cert_ends_ms;
        out.push(r);
    }
    match f.stop.as_str() {
        "full" => out.push(Reason::new("stopped", Level::Stop)),
        "secrets" => out.push(Reason::new("secrets_stopped", Level::Warn)),
        _ => {}
    }
    if f.sync_off {
        let mut r = Reason::new("sync_off", Level::Stop);
        r.until_ms = f.sync_until_ms;
        out.push(r);
    }
    if f.connected == 0 {
        out.push(not_connected(f));
    }
    if f.muted {
        let mut r = Reason::new("muted", Level::Warn);
        r.until_ms = f.muted_until_ms;
        out.push(r);
    }
    if let Some(a) = &f.away
        && a.forwarder
        && !a.forwarder_registered
    {
        let mut r = Reason::new(if a.entries_stale { "entries_stale" } else { "forwarder_down" }, Level::Warn);
        r.detail = a.error.clone();
        out.push(r);
    }
    if f.newer > 0 {
        let mut r = Reason::new("newer", Level::Warn);
        r.value = f.newer.to_string();
        out.push(r);
    }
    if !f.unreached.is_empty() {
        let mut r = Reason::new("unreached", Level::Warn);
        r.devices = f.unreached.clone();
        out.push(r);
    }
    if f.cert_ends_ms > now_ms && f.cert_ends_ms.saturating_sub(now_ms) < CERT_WARNING_MS {
        let mut r = Reason::new("cert_ending", Level::Warn);
        r.until_ms = f.cert_ends_ms;
        out.push(r);
    }
    let names = |p: fn(&DeviceFacts) -> bool| -> Vec<String> {
        f.devices.iter().filter(|d| p(d)).map(|d| d.name.clone()).collect()
    };
    // Offline devices matter only while some member is connected: with
    // none, the reason above already says why.
    for (code, list) in [
        ("devices_offline", if f.connected > 0 { names(|d| !d.online) } else { Vec::new() }),
        ("devices_sync_off", names(|d| d.sync_off)),
        ("devices_muted", names(|d| d.muted)),
    ] {
        if !list.is_empty() {
            let mut r = Reason::new(code, Level::Info);
            r.devices = list;
            out.push(r);
        }
    }
    if !f.update.is_empty() {
        let mut r = Reason::new("update", Level::Info);
        r.value = f.update.clone();
        out.push(r);
    }
    // Stable: the order above within a level.
    out.sort_by_key(|r| r.level);
    out
}

/// Why no member is connected: the group's only device, a network where it
/// has not met its group, sync away from home off, no hub, the relay or the
/// hub out of reach.
fn not_connected(f: &Facts) -> Reason {
    if f.devices.is_empty() {
        return Reason::new("only_device", Level::Info);
    }
    let Some(a) = &f.away else {
        let mut r = Reason::new(if f.quiet.is_empty() { "away_off" } else { "new_network" }, Level::Stop);
        r.devices = f.quiet.clone();
        return r;
    };
    let mut r = if a.relay {
        Reason::new(if a.relay_connected { "alone" } else { "relay_down" }, Level::Stop)
    } else if a.hub && !a.standby {
        // A serving hub waits for the others to come.
        Reason::new("hub_waiting", Level::Stop)
    } else if a.hub_device.is_empty() {
        Reason::new("no_hub", Level::Stop)
    } else if a.through {
        Reason::new("alone", Level::Stop)
    } else {
        let mut r = Reason::new(if a.hidden { "hub_unreachable" } else { "tunnel_blocked" }, Level::Stop);
        r.device = a.hub_device.clone();
        r
    };
    r.detail = a.error.clone();
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Deserialize)]
    struct Vector {
        name: String,
        now_ms: i64,
        facts: Facts,
        want: Vec<Reason>,
    }

    #[test]
    fn vectors() {
        let vs: Vec<Vector> = serde_json::from_str(include_str!("../../testdata/why/vectors.json")).unwrap();
        assert!(vs.len() >= 20);
        for v in vs {
            assert_eq!(diagnose(&v.facts, v.now_ms), v.want, "{}", v.name);
        }
    }

    #[test]
    fn everything_syncs() {
        let f = Facts {
            in_group: true,
            connected: 1,
            devices: alloc::vec![DeviceFacts { name: "mac".into(), online: true, ..Default::default() }],
            ..Default::default()
        };
        assert!(diagnose(&f, 1).is_empty());
    }
}
