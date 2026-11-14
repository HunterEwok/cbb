// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The local control socket (docs/protocol.md, section 8): a JSON header on
//! one line, then exactly len bytes of payload. cbb serves the
//! operations a member without CA keys has: copy, paste, status, devices
//! and watch, so the Go command line and connectors can talk to it too.

use std::io::{BufRead, BufReader, Read, Write};

use serde::{Deserialize, Serialize};

use crate::error::{Context, Error, Result};

const MAX_HEADER: usize = 64 << 10;
const MAX_PAYLOAD: usize = (1 << 20) + 64;

#[derive(Serialize, Deserialize, Default, Debug, Clone)]
pub struct Header {
    #[serde(default)]
    pub op: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub kind: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub via: String,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub seq: u64,
    #[serde(default, skip_serializing_if = "is_zero_i")]
    pub ttl_ms: i64,
    #[serde(default, skip_serializing_if = "is_zero_us")]
    pub len: usize,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub error: String,
    /// The causes behind error, for debug mode; Go clients ignore it.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub details: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub done: bool,
    /// cbb global on: the user agreed to what the warning says.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub consent: bool,
    /// An admin request on the control socket: what confirms that the user
    /// at the screen asked for it (confirm.rs): on a Mac the external form
    /// of the caller's authorization, on Windows a Windows Hello signature.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub auth: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    /// mode: the device whose mode an admin sets; this device if empty.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub device: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<Status>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub devices: Vec<Device>,
    /// view and arrange (docs/apps.md, "What the member shows"): the
    /// tiles to draw in the answer, and the user's change in an arrange.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub view: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arrange: Option<serde_json::Value>,
    /// Remote paste (docs/protocol.md, section 8): in an inject, paste or
    /// type, and Enter after the text; in paste-receive, the switches.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub method: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub enter: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub console: bool,
    /// In paste-receive on and in an inject: a target may paste where
    /// nothing tells whether the session is locked.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub no_lock_check: bool,
    /// In a watch request, the paste target the watcher offers: desktop,
    /// tmux or console.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub inject: String,
    /// In a watch request: the watcher holds no clipboard and only pastes.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub paste_only: bool,
    /// In a watch request: the watcher's clipboard takes and gives images,
    /// files and formatted text, each fetched with paste-media.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub images: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub files: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub html: bool,
    /// In an injected answer: error is a refusal, not a failure.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub refused: bool,
    /// The underlying error of a failed inject, as Go's watchers send it.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detail: String,
    /// In action-set, the quick action to set: on or off, and for whom.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<Action>,
    /// In actions-off, every device of the group; only an admin does it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub all: bool,
    /// In mute, how long, 0 for until unmute.
    #[serde(default, skip_serializing_if = "is_zero_i")]
    pub for_ms: i64,
    /// In config, the value of the setting name.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub value: String,
    /// In copy-media and paste-media, the next part of the copy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub part: Option<Part>,
    /// In make_admin: the device's admin key may be in a file, which the
    /// user agreed to after the warning.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub allow_file_key: bool,
    /// In sync: on or off.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on: Option<bool>,
    /// The answer to sync and muted: where sync and the mute stand.
    #[serde(flatten, default, skip_serializing_if = "Option::is_none")]
    pub standing: Option<crate::sync::Standing>,
    /// In rename, the device's new name.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub new_name: String,
    /// In the answer to key-level, the admins and hubs below the new level.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub below: Vec<String>,
    /// In pair and join: the code; in pair by QR code, the joiner's
    /// addresses and its certificate's fingerprint; admins lets the window
    /// make a phone an admin, on the root.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub code: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub addrs: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub fingerprint: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub admins: bool,
    /// In the answer to pair: the seconds the window stays open, and an
    /// address of this member for a joiner whose network has no multicast.
    #[serde(default, skip_serializing_if = "is_zero_i")]
    pub expires: i64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub address: String,
    /// In join: the capabilities cbb pair -caps gave, in place of the
    /// service's (name, if not empty, is cbb pair -name's in place of the
    /// service's -name).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caps: Option<Vec<String>>,
    /// In join: wait for a member to dial this device, rather than dial
    /// the member whose code it was given.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub listen: bool,
    /// In away hub: the UDP port (0 for the member port), the forwarder and
    /// its key, AmneziaWG, VLESS, and to keep the hub's settings where the
    /// message gives none; in away hub-off, to stop the group's only hub.
    #[serde(default, skip_serializing_if = "is_zero_i")]
    pub port: i64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub forwarder: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub forwarder_key: String,
    /// away relay: the relay's address, with its key's pin or `default`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub relay: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub relay_key: String,
    /// away hub: plain WireGuard, without AmneziaWG, which a hub offers by
    /// default; it goes with vless_off where there is a forwarder.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub obfuscate_off: bool,
    /// away hub: no VLESS at the forwarder, which a hub with one asks for
    /// by default.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub vless_off: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub keep: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub force: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub forward_only: bool,
    /// In hubs: the table of main hubs, names or device IDs in order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hubs: Vec<String>,
    /// In an inject to a desktop session, the grant its desktop connector
    /// hands the uinput helper, which asks with keys whether it may press
    /// the paste's keys.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub keys: String,
    /// In keyboard on: the keyboard's settings, as Go's control.Keyboard.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keyboard: Option<serde_json::Value>,
    /// In a watch: the watcher runs the quick actions in its user's
    /// session (CBB's agent), which the service hands it with act.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub act: bool,
    /// In an act: the program and arguments of the user's own action;
    /// empty for a preset.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub command: Vec<String>,
    /// The text of a remote invitation: made by invite, used by join.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub invite: String,
    /// In invite: a device to confirm, before it is admitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub joining: Option<Joining>,
}

/// A device that used a remote invitation, for the admin to confirm, as
/// Go's control.Joining.
#[derive(Serialize, Deserialize, Default, Debug, Clone)]
pub struct Joining {
    pub id: String,
    pub name: String,
    pub os: String,
    pub fingerprint: String,
}

/// A part of a copy of images or files on the socket, as Go's
/// control.Part: clipboard data of a type, or a file or folder at a path.
#[derive(Serialize, Deserialize, Default, Debug, Clone, PartialEq, Eq)]
pub struct Part {
    #[serde(rename = "type", default, skip_serializing_if = "String::is_empty")]
    pub kind: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub dir: bool,
    #[serde(default, skip_serializing_if = "is_zero_i")]
    pub size: i64,
}

/// Images and files in the status: this device's largest copy at home and
/// away from home, as Go's control.Media.
#[derive(Serialize, Deserialize, Default, Debug, Clone)]
pub struct Media {
    pub max_copy: i64,
    pub max_copy_away: i64,
    /// Why the last copy's images or files were not fetched, as Go's.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub failed: String,
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}
fn is_zero_i(n: &i64) -> bool {
    *n == 0
}
fn is_zero_us(n: &usize) -> bool {
    *n == 0
}

#[derive(Serialize, Deserialize, Default, Debug, Clone)]
pub struct Status {
    pub device: String,
    /// The interfaces on networks this device has not met its group on,
    /// where it does not publish itself (cbb network makes them known).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub quiet: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub group: String,
    pub role: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub os: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub peers: Vec<Device>,
    pub version: String,
    /// The device left a group made before 0.6 when it started, and is in
    /// no group now (Go's LeftOldGroup).
    #[serde(default, skip_serializing_if = "core::ops::Not::not")]
    pub left_old_group: bool,
    /// The sync mode: shared (sync on) or own (sync off); empty when in no
    /// group. While sync is off, sync_until_ms is when it turns on again,
    /// in Unix milliseconds, 0 for until cbb sync on.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub mode: String,
    #[serde(default, skip_serializing_if = "is_zero_i")]
    pub sync_until_ms: i64,
    /// A panic before the last restart waits for the user to allow or
    /// cancel its bug report (ops `bug`, `bug_allow`, `bug_cancel`).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub bug: bool,
    /// Whether an admin muted this device, until muted_until_ms in Unix
    /// milliseconds, 0 for until an admin unmutes it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub muted: bool,
    #[serde(default, skip_serializing_if = "is_zero_i")]
    pub muted_until_ms: i64,
    /// Sync away from home; None while it is off.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub away: Option<Away>,
    /// Remote paste on this device; None when in no group.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paste: Option<Paste>,
    /// The Bluetooth keyboard, as Go's control.Keyboard, which cbb-helper
    /// gives; None where it was never turned on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keyboard: Option<serde_json::Value>,
    /// The newest signed release the group passed around, and that
    /// version again in update when this device runs an older one.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub release: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub update: String,
    /// The TVs this device is the remote of, as Go's control.TV.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tvs: Vec<serde_json::Value>,
    /// This device's quick actions, the presets in their order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<Action>,
    /// How far the group's records stop the exchange: "secrets" or "full",
    /// empty when nothing stops (docs/protocol.md, section 10, "Stopping
    /// the exchange").
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub stop: String,
    /// The group's records revoke this device: it joins again only after
    /// cbb leave.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub removed: bool,
    /// The records freeze this admin computer's admin key, as Go's.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub frozen: bool,
    /// The admin that took the group over from this root, as Go's.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub taken_over_by: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media: Option<Media>,
    /// The group's key level: which keys may be its root, an admin or a hub.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub key_level: String,
    /// Why this device's own key is in a file although the machine has a
    /// TPM or a Secure Enclave.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub key_problem: String,
    /// How long a copy from another device stays live after it arrives.
    #[serde(default, skip_serializing_if = "is_zero_i")]
    pub incoming_ms: i64,
    /// The claims to take the group over that wait or stop the group.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<Claim>,
    /// The conflicts that stop the group until its root decides.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conflicts: Vec<Conflict>,
    /// How many records of a later version this member keeps.
    #[serde(default, skip_serializing_if = "is_zero_u")]
    pub newer: usize,
    /// When this device's member certificate ends, in Unix milliseconds.
    #[serde(default, skip_serializing_if = "is_zero_i")]
    pub cert_ends_ms: i64,
    /// The members at home that could not connect to this device and sync
    /// with it only because it dials them back, as Go's Unreached.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unreached: Vec<String>,
    /// The member port, as Go's Port; 0 when this device does not listen.
    #[serde(default, skip_serializing_if = "is_zero_i")]
    pub port: i64,
    /// Why this device does not sync, the reason that stops the most first
    /// (cbb_core::why; docs/apps.md, "Why it does not sync"); empty when
    /// everything syncs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub why: Vec<cbb_core::why::Reason>,
}

/// A claim to take the group over, as Go's control.Claim: who claims it
/// (a device's name, or the key hash), pending, competing or disputed, and
/// how long a pending one still waits.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct Claim {
    pub by: String,
    pub state: String,
    #[serde(default, skip_serializing_if = "is_zero_i")]
    pub left_ms: i64,
}

/// A conflict of the group's records, as Go's control.Conflict: admins,
/// claims or two_histories, and the signers' devices.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct Conflict {
    pub kind: String,
    pub devices: Vec<String>,
}

fn is_zero_u(n: &usize) -> bool {
    *n == 0
}

/// A quick action as the device's user set it, with the names of the Go
/// service's status.
#[derive(Serialize, Deserialize, Default, Debug, Clone, PartialEq, Eq)]
pub struct Action {
    pub name: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub on: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub by: Vec<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub any_key: bool,
    /// The program and arguments of a user's own action.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub command: Vec<String>,
}

/// Remote paste on this device: the switches its user set and the targets
/// that run, with the names of the Go service's status.
#[derive(Serialize, Deserialize, Default, Debug, Clone)]
pub struct Paste {
    pub on: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub enter: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub console: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub no_lock_check: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub targets: Vec<String>,
}

/// Sync away from home on a client of the group's hub, with the names of
/// the Go service's status.
#[derive(Serialize, Deserialize, Default, Debug, Clone)]
pub struct Away {
    /// This device is one of the group's hubs; standby while a hub above
    /// it serves; its UDP port and the clients it admitted.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub hub: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub standby: bool,
    #[serde(default, skip_serializing_if = "is_zero_i")]
    pub port: i64,
    #[serde(default, skip_serializing_if = "is_zero_i")]
    pub clients: i64,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub obfuscated: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub vless: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<String>,
    /// The hub; empty until it offered its tunnel.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub hub_device: String,
    /// Connected to the hub through the tunnel now.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub through: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub keys_in_file: bool,
    /// On the hub, its forwarder; None without one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forwarder: Option<Forwarder>,
    /// On a device that meets the others at a relay, its link to it; None
    /// without one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay: Option<Relay>,
    /// What went wrong last, for the user.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub error: String,
    /// The underlying error, for debugging.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detail: String,
    /// The group's servers the service may reach beyond the home network:
    /// its hub, forwarder and relay, which cbb global lets through the
    /// system's limit.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<String>,
}

/// A hub's registration with its forwarder, as Go's control.Forwarder.
#[derive(Serialize, Deserialize, Default, Debug, Clone)]
pub struct Forwarder {
    #[serde(default)]
    pub endpoint: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub registered: bool,
    /// Where the forwarder reaches the hub's port.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub seen: String,
    /// The project's forwarder does not answer and this device holds no
    /// signed entry points that have not expired, so a new list may be what
    /// it needs (docs/protocol.md, section 16).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub entries_stale: bool,
    /// Why the hub is not registered, and the underlying error.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub error: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detail: String,
}

/// A device's link to its blind relay, as Go's control.Relay.
#[derive(Serialize, Deserialize, Default, Debug, Clone)]
pub struct Relay {
    #[serde(default)]
    pub endpoint: String,
    /// Registered, with its tunnel.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub connected: bool,
    /// The other devices of the group on the relay.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub online: Vec<String>,
    /// Why it is not connected, and the underlying error.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub error: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detail: String,
}

#[derive(Serialize, Deserialize, Default, Debug, Clone)]
pub struct Device {
    pub id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub role: String,
    /// What a member can do, from its record, or from its hello while no
    /// record lists it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub caps: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub os: String,
    /// Where its keys live: file, hardware, proven or rootless; empty when
    /// the member does not say.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub store: String,
    #[serde(default, skip_serializing_if = "is_zero_i")]
    pub skew_ms: i64,
    /// What its hello says about its device; empty when it says nothing or
    /// is not connected.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub form: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub os_version: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub version: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub mac: String,
    /// Its sync mode, as its hello says.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub mode: String,
    /// An admin muted it, until muted_until_ms (Unix milliseconds; 0 for
    /// until an admin unmutes it).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub muted: bool,
    #[serde(default, skip_serializing_if = "is_zero_i")]
    pub muted_until_ms: i64,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub admin: bool,
    /// It holds the group's root.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub root: bool,
    /// An admin computer another admin froze.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub frozen: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub online: bool,
    /// When this member last saw it connected, Unix milliseconds.
    #[serde(default, skip_serializing_if = "is_zero_i")]
    pub last_seen_ms: i64,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    #[serde(rename = "self")]
    pub this: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub listed: bool,
    /// The records let it be a hub.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub may_hub: bool,
    /// A hub that only passes the copies on.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub forward_only: bool,
    /// One of the group's hubs, as this device knows: itself while it is a
    /// hub, or a hub whose offer it keeps.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub hub: bool,
}

/// A header and its payload.
#[derive(Default, Debug, Clone)]
pub struct Message {
    pub header: Header,
    pub payload: Vec<u8>,
}

impl Message {
    pub fn new(header: Header, payload: Vec<u8>) -> Message {
        Message { header, payload }
    }
}

/// Writes one message.
pub fn write(w: &mut impl Write, m: &Message) -> Result<()> {
    if m.payload.len() > MAX_PAYLOAD {
        return Err(Error::msg("the text is larger than 1 MiB"));
    }
    let mut h = m.header.clone();
    h.len = m.payload.len();
    let mut buf = serde_json::to_vec(&envelope(&h)?).context("cannot encode a message")?;
    if buf.len() > MAX_HEADER {
        return Err(Error::msg("the header is too long"));
    }
    buf.push(b'\n');
    buf.extend_from_slice(&m.payload);
    w.write_all(&buf).context("the connection to the service broke")?;
    w.flush().context("the connection to the service broke")
}

/// The fields of an answer that stand beside its `ok`, not in it.
const ANSWER_FIELDS: [&str; 6] = ["error", "detail", "details", "done", "len", "seq"];
/// The fields of a request or a message that stand beside its `args`:
/// its payload's length and the sequence number that its answer repeats.
const REQUEST_FIELDS: [&str; 2] = ["len", "seq"];

/// What goes on the wire for h: a request or a watcher's message as
/// `{"op", "args", "len", "seq"}`, an answer as `{"ok", "len", "seq",
/// "done"}` or `{"error", "detail", "seq", "done"}`, the envelope of cbb_member_call
/// (docs/core-api.md, "Operations").
fn envelope(h: &Header) -> Result<serde_json::Value> {
    let serde_json::Value::Object(mut fields) = serde_json::to_value(h).context("cannot encode a message")? else {
        return Err(Error::msg("cannot encode a message"));
    };
    let op = fields.remove("op").and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default();
    let mut out = serde_json::Map::new();
    if op.is_empty() || op == "reply" {
        for k in ANSWER_FIELDS {
            if let Some(v) = fields.remove(k) {
                out.insert(k.to_string(), v);
            }
        }
        if !out.contains_key("error") {
            out.insert("ok".to_string(), serde_json::Value::Object(fields));
        }
    } else {
        for k in REQUEST_FIELDS {
            if let Some(v) = fields.remove(k) {
                out.insert(k.to_string(), v);
            }
        }
        out.insert("op".to_string(), serde_json::Value::String(op));
        out.insert("args".to_string(), serde_json::Value::Object(fields));
    }
    Ok(serde_json::Value::Object(out))
}

/// The header that the envelope v carries: a request's or a message's
/// args, or an answer's ok, with the fields beside them.
fn unwrap_envelope(v: serde_json::Value) -> Result<Header> {
    let serde_json::Value::Object(mut outer) = v else {
        return Err(Error::msg("a bad header: not an object"));
    };
    let inner = match outer.remove("op") {
        Some(op) => {
            let args = outer.remove("args").unwrap_or_default();
            let mut fields = match args {
                serde_json::Value::Object(m) => m,
                serde_json::Value::Null => serde_json::Map::new(),
                _ => return Err(Error::msg("a bad header: args is not an object")),
            };
            fields.insert("op".to_string(), op);
            fields
        }
        None => {
            let mut fields = match outer.remove("ok") {
                Some(serde_json::Value::Object(m)) => m,
                None | Some(serde_json::Value::Null) => serde_json::Map::new(),
                Some(_) => return Err(Error::msg("a bad header: ok is not an object")),
            };
            fields.insert("op".to_string(), serde_json::Value::String("reply".into()));
            fields
        }
    };
    let mut fields = inner;
    for (k, v) in outer {
        if ANSWER_FIELDS.contains(&k.as_str()) {
            fields.insert(k, v);
        }
    }
    serde_json::from_value(serde_json::Value::Object(fields)).context("a bad header")
}

/// Reads messages from a connection.
pub struct Reader<R: Read> {
    r: BufReader<R>,
}

impl<R: Read> Reader<R> {
    pub fn new(r: R) -> Reader<R> {
        Reader { r: BufReader::new(r) }
    }

    /// Reads one message; None at the end of the stream.
    pub fn read(&mut self) -> Result<Option<Message>> {
        let mut line = Vec::new();
        let n =
            (&mut self.r).take(MAX_HEADER as u64 + 1).read_until(b'\n', &mut line).context("the connection broke")?;
        if n == 0 {
            return Ok(None);
        }
        if line.last() != Some(&b'\n') {
            return Err(Error::msg("the header is too long"));
        }
        let header = unwrap_envelope(serde_json::from_slice(&line).context("a bad header")?)?;
        if header.len > MAX_PAYLOAD {
            return Err(Error::msg(format!("a bad payload length {}", header.len)));
        }
        // Read the payload as it arrives, rather than allocating what the
        // header promises before a byte of it came.
        let mut payload = Vec::new();
        (&mut self.r).take(header.len as u64).read_to_end(&mut payload).context("the connection broke")?;
        if payload.len() != header.len {
            return Err(Error::msg("the connection broke in the middle of a message"));
        }
        Ok(Some(Message { header, payload }))
    }
}

/// The answer to a request: op reply, done.
pub fn reply(header: Header, payload: Vec<u8>) -> Message {
    Message::new(Header { op: "reply".into(), done: true, ..header }, payload)
}

/// An answer to a request that more answers follow: op reply, not done.
#[cfg_attr(not(feature = "tunnel"), allow(dead_code))]
pub fn partial(header: Header) -> Message {
    Message::new(Header { op: "reply".into(), done: false, ..header }, Vec::new())
}

/// A failed request.
pub fn failure(e: &Error) -> Message {
    reply(Header { error: e.message().to_string(), details: e.details(), ..Default::default() }, Vec::new())
}

/// The names of the operations that the service dispatches on and that
/// the user confirms each time on the control socket (confirm.rs): one
/// list for both, so that a renamed operation cannot fall out of its tier.
pub mod op {
    pub const NEW: &str = "new";
    pub const LEAVE: &str = "leave";
    pub const TAKE_OVER: &str = "take_over";
    pub const RECOVER: &str = "recover";
    pub const HAND_OVER: &str = "hand_over";
    pub const KEY_LEVEL: &str = "key_level";
    pub const TAKEOVER_DELAY: &str = "takeover_delay";
    pub const MAKE_ADMIN: &str = "make_admin";
}

/// Whether an operation changes the group or this device's place in it, so
/// that the service takes it only on the admin socket, which only root and
/// the service's own user reach, as on a full member.
pub fn is_admin(op: &str) -> bool {
    !matches!(
        op,
        "copy"
            | "paste"
            | "copy_media"
            | "copied_media"
            | "paste_media"
            | "part"
            | "data"
            | "config"
            | "status"
            | "version"
            | "devices"
            | "view"
            | "arrange"
            | "muted"
            | "watch"
            | "copied"
            | "clipboard"
            | "answer"
            | "reply"
            | "write"
            | "inject"
            | "injected"
            | "act"
            | "acted"
            // The signed release cbb update fetched, for the group, and the
            // one held.
            | "release"
            | "release_get"
            | "release_held"
            | "entries"
            | "entries_get"
            // The challenge that confirms an admin action (confirm.rs).
            | "confirm"
            // The uinput helper, as root, through the socket's group; the
            // service checks that it is root.
            | "keys"
            // The user's answer to a bug report (src/bugs.rs).
            | "bug"
            | "bug_allow"
            | "bug_cancel"
    )
}

/// Whether the service takes the request h only on its admin socket, as
/// Go's NeedsAdmin: is_admin of its operation, except turning this device's
/// own sync on or off, which changes nothing for the group (design.md,
/// "Sync on or off").
pub fn needs_admin(h: &Header) -> bool {
    !(h.op == "sync" && h.device.is_empty()) && is_admin(&h.op)
}

/// Whether op, done on this device itself, is one the service also takes
/// on its control socket (Service::own_device_op): muting it or ending its
/// mute.
pub fn is_own_device_op(op: &str) -> bool {
    matches!(op, "mute" | "unmute")
}

/// The admin socket next to the control socket at `socket`.
pub fn admin_socket(socket: &std::path::Path) -> std::path::PathBuf {
    // On Windows it sits in a folder of its own, whose access list lets
    // only the service and the administrators in (Go's adminSocketName).
    if cfg!(windows) { socket.with_file_name("admin").join("admin.sock") } else { socket.with_file_name("admin.sock") }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A request goes as {"op", "args", "len", "seq"}, an answer as {"ok"}
    /// or {"error", "detail"}, as Go's control.TestEnvelope checks, and
    /// both read back.
    #[test]
    fn envelope() {
        let cases = [
            (
                Message::new(
                    Header { op: "mute".into(), device: "pi".into(), for_ms: 5, ..Default::default() },
                    vec![],
                ),
                r#"{"args":{"device":"pi","for_ms":5},"op":"mute"}"#,
            ),
            (
                Message::new(
                    Header { op: "inject".into(), seq: 7, method: "type".into(), ..Default::default() },
                    b"hi".to_vec(),
                ),
                r#"{"args":{"method":"type"},"len":2,"op":"inject","seq":7}"#,
            ),
            (reply(Header { name: "pi".into(), ..Default::default() }, vec![]), r#"{"done":true,"ok":{"name":"pi"}}"#),
            (failure(&Error::msg("no")), r#"{"done":true,"error":"no"}"#),
        ];
        for (m, want) in cases {
            let mut buf = Vec::new();
            write(&mut buf, &m).unwrap();
            let line = String::from_utf8(buf.clone()).unwrap();
            assert_eq!(line.split('\n').next().unwrap(), want);
            let got = Reader::new(&buf[..]).read().unwrap().unwrap();
            assert_eq!(
                (got.header.op, got.header.name, got.header.seq, got.payload),
                (m.header.op, m.header.name, m.header.seq, m.payload)
            );
        }
        for bad in [&b"[]\n"[..], b"{\"op\":\"copy\",\"args\":[]}\n", b"{\"ok\":1}\n"] {
            assert!(Reader::new(bad).read().is_err(), "{}", String::from_utf8_lossy(bad));
        }
    }

    fn json(h: &Header) -> serde_json::Value {
        serde_json::to_value(h).unwrap()
    }

    #[test]
    fn zeros_are_left_out() {
        let v = json(&Header::default());
        for k in ["seq", "ttl_ms", "len", "status"] {
            assert!(v.get(k).is_none(), "{k} in {v}");
        }
        let v = json(&Header { seq: 3, ttl_ms: -1, len: 2, ..Default::default() });
        assert_eq!((v["seq"].as_u64(), v["ttl_ms"].as_i64(), v["len"].as_u64()), (Some(3), Some(-1), Some(2)));
        let s = serde_json::to_value(Status::default()).unwrap();
        assert!(s.get("newer").is_none(), "{s}");
        let s = serde_json::to_value(Status { newer: 4, ..Default::default() }).unwrap();
        assert_eq!(s["newer"].as_u64(), Some(4));
    }

    fn round_trip(m: &Message) -> Result<Option<Message>> {
        let mut buf = Vec::new();
        write(&mut buf, m)?;
        Reader::new(&buf[..]).read()
    }

    #[test]
    fn the_limits_are_inclusive() {
        // A text of 1 MiB with room for its frame.
        let big = Message::new(Header { op: "copy".into(), ..Default::default() }, vec![b'x'; (1 << 20) + 64]);
        let got = round_trip(&big).unwrap().unwrap();
        assert_eq!((got.header.len, got.payload.len()), (MAX_PAYLOAD, MAX_PAYLOAD));
        let over = Message::new(Header::default(), vec![b'x'; MAX_PAYLOAD + 1]);
        assert!(write(&mut Vec::new(), &over).is_err());

        // A header of MAX_HEADER bytes on the wire, its newline aside, is
        // taken; one byte more is not.
        let wire = |h: &Header| serde_json::to_vec(&super::envelope(h).unwrap()).unwrap();
        let at = |n: usize| {
            let one = wire(&Header { op: "x".into(), name: "n".into(), ..Default::default() }).len();
            Message::new(Header { op: "x".into(), name: "n".repeat(n - one + 1), ..Default::default() }, Vec::new())
        };
        let m = at(MAX_HEADER);
        assert_eq!(wire(&m.header).len(), MAX_HEADER);
        assert_eq!(round_trip(&m).unwrap().unwrap().header.name, m.header.name);
        assert!(write(&mut Vec::new(), &at(MAX_HEADER + 1)).is_err());
        let mut line = wire(&at(MAX_HEADER + 1).header);
        line.push(b'\n');
        assert!(Reader::new(&line[..]).read().is_err(), "a header longer than MAX_HEADER");

        // A header that promises more than MAX_PAYLOAD is refused before
        // its payload.
        let promise = |n: usize| {
            let mut b = wire(&Header { op: "copy".into(), len: n, ..Default::default() });
            b.push(b'\n');
            b.extend(std::iter::repeat_n(b'x', n.min(MAX_PAYLOAD)));
            b
        };
        assert!(Reader::new(&promise(MAX_PAYLOAD)[..]).read().unwrap().is_some());
        let e = Reader::new(&promise(MAX_PAYLOAD + 1)[..]).read().unwrap_err();
        assert!(e.message().contains("payload length"), "{}", e.message());
    }

    #[test]
    fn answers_say_whether_more_follow() {
        let base = Header { op: "status".into(), seq: 9, ..Default::default() };
        let r = reply(base.clone(), b"p".to_vec());
        assert_eq!(
            (r.header.op.as_str(), r.header.done, r.header.seq, r.payload.as_slice()),
            ("reply", true, 9, &b"p"[..])
        );
        let p = partial(Header { done: true, ..base });
        assert_eq!((p.header.op.as_str(), p.header.done, p.header.seq), ("reply", false, 9));
        let e = Error::msg("outer").context("why");
        let f = failure(&e);
        assert_eq!((f.header.op.as_str(), f.header.done), ("reply", true));
        assert_eq!((f.header.error.clone(), f.header.details.clone()), (e.message().to_string(), e.details()));
        assert!(!f.header.error.is_empty() && !f.header.details.is_empty());
    }

    #[test]
    fn which_requests_need_the_admin_socket() {
        let h = |op: &str, device: &str| Header { op: op.into(), device: device.into(), ..Default::default() };
        for op in ["copy", "paste", "status", "watch", "reply", "keys"] {
            assert!(!is_admin(op) && !needs_admin(&h(op, "")), "{op}");
        }
        for op in ["pair", "remove", "leave", "mode"] {
            assert!(is_admin(op) && needs_admin(&h(op, "")), "{op}");
        }
        // This device's own sync, but not another's.
        assert!(!needs_admin(&h("sync", "")));
        assert!(needs_admin(&h("sync", "desk")));
        assert!(needs_admin(&h("mode", "desk")));
    }
}
