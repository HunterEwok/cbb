// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The devices of the group as `cbb devices`, `cbb status` and the apps
//! show them (`control::Device`), from the records of 0.6 (`State`) and
//! the hellos of the devices connected now. What a device may do comes
//! from its record; what it says of itself (its form, versions, mode and
//! mute) from its hello, and is only shown.

use std::collections::HashMap;

use cbb_core::format::print::os_name;
use cbb_core::records::body::{
    CAP_ADMIN, CAP_DIALS, CAP_HUB, RIGHT_HUB, ROLE_LEAF, ROLE_MEMBER, ROLE_PHONE, ROLE_WATCH, STORE_FILE,
    STORE_HARDWARE, STORE_PROVEN, STORE_ROOTLESS,
};
use cbb_core::records::eval::DeviceState;
use cbb_core::records::{DeviceId, KeyHash, RecordSet, State};

use crate::control::Device;
use crate::hello::Hello;

/// The names of the hello's `form` numbers (format 9.3), 0 for none.
const FORMS: [&str; 13] = [
    "", "laptop", "desktop", "phone", "tablet", "tv", "board", "server", "router", "console", "watch", "retro", "other",
];

/// The name of a form number; empty for none or one this version does not
/// name.
pub fn form_name(n: u64) -> &'static str {
    usize::try_from(n).ok().and_then(|i| FORMS.get(i)).copied().unwrap_or("")
}

/// The form number of a name, 0 for none.
pub fn form_number(name: &str) -> u64 {
    FORMS.iter().position(|f| !f.is_empty() && *f == name).map_or(0, |i| i as u64)
}

/// A device ID as the views and the commands' targets show it: hex.
pub fn id_text(id: &DeviceId) -> String {
    id.0.iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn role_name(r: u64) -> &'static str {
    match r {
        ROLE_MEMBER => "member",
        ROLE_PHONE => "phone",
        ROLE_WATCH => "watch",
        ROLE_LEAF => "leaf",
        _ => "unknown",
    }
}

pub(crate) fn store_name(s: u64) -> &'static str {
    match s {
        STORE_FILE => "file",
        STORE_HARDWARE => "hardware",
        STORE_ROOTLESS => "rootless",
        STORE_PROVEN => "proven",
        _ => "",
    }
}

fn caps_names(c: u64) -> Vec<String> {
    [("admin", CAP_ADMIN), ("dials", CAP_DIALS), ("hub", CAP_HUB)]
        .iter()
        .filter(|(_, b)| c & b != 0)
        .map(|(n, _)| (*n).to_string())
        .collect()
}

/// The caps' bits of their names, as a computer's service is told them;
/// a name this version does not know counts for nothing.
pub fn caps_number(names: &[String]) -> u64 {
    [("admin", CAP_ADMIN), ("dials", CAP_DIALS), ("hub", CAP_HUB)]
        .iter()
        .filter(|(n, _)| names.iter().any(|x| x == n))
        .fold(0, |c, (_, b)| c | b)
}

fn mac_text(m: &[u8; 6]) -> String {
    m.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":")
}

/// What this device says of itself, as its own hello would.
#[derive(Clone, Debug, Default)]
pub struct Me {
    pub id: DeviceId,
    /// Its mode, `shared` or `own`.
    pub mode: String,
    /// Muted until this wall time, 0 for until it is lifted; None when not
    /// muted.
    pub muted_until_ms: Option<i64>,
    pub form: String,
    pub os_version: String,
    pub version: String,
    pub mac: String,
}

fn from_record(d: &DeviceState, state: &State, is_admin: &dyn Fn(&KeyHash) -> bool) -> Device {
    // An admin key the records name that the set does not count as an
    // admin's (a root's, or the recovery key's) shows as none.
    let admin = d.admin.is_some_and(|h| is_admin(&h));
    Device {
        id: id_text(&d.id),
        name: d.name.clone(),
        role: role_name(d.role).into(),
        caps: caps_names(d.caps),
        os: if d.os == 0 { String::new() } else { os_name(d.os).into() },
        store: store_name(d.store).into(),
        admin,
        root: state.root_device == Some(d.id),
        frozen: d.frozen,
        listed: true,
        may_hub: !d.frozen && (admin || d.rights & RIGHT_HUB != 0),
        hub: state.hubs.contains(&d.id),
        forward_only: crate::writers::is_forward_only(d.rights),
        ..Device::default()
    }
}

fn with_hello(d: &mut Device, h: &Hello, now_ms: i64) {
    d.online = true;
    d.last_seen_ms = now_ms;
    d.form = form_name(h.device.form).into();
    d.os_version.clone_from(&h.device.os_version);
    d.version.clone_from(&h.device.version);
    d.mac = h.device.mac.as_ref().map(mac_text).unwrap_or_default();
    d.mode = match h.mode {
        1 => "shared".into(),
        2 => "own".into(),
        _ => String::new(),
    };
    d.muted = h.muted;
    d.muted_until_ms = if h.muted && h.muted_for_ms > 0 {
        now_ms.saturating_add(i64::try_from(h.muted_for_ms).unwrap_or(i64::MAX))
    } else {
        0
    };
    if d.os.is_empty() && h.os != 0 {
        d.os = os_name(h.os).into();
    }
}

/// The devices of the group: every device the records name, in their
/// order, this device marked and filled from what it knows of itself, the
/// connected ones from their hellos.
pub fn devices(set: &RecordSet, me: &Me, hellos: &HashMap<DeviceId, Hello>, now_ms: i64) -> Vec<Device> {
    devices_in(&set.state(), &|h| set.is_admin(h), me, hellos, now_ms)
}

/// As devices, from the state, with is_admin telling the keys of admins.
fn devices_in(
    state: &State,
    is_admin: &dyn Fn(&KeyHash) -> bool,
    me: &Me,
    hellos: &HashMap<DeviceId, Hello>,
    now_ms: i64,
) -> Vec<Device> {
    state
        .devices
        .iter()
        .map(|rec| {
            let mut d = from_record(rec, state, is_admin);
            if rec.id == me.id {
                d.this = true;
                d.online = true;
                d.last_seen_ms = now_ms;
                (d.form, d.os_version, d.version, d.mac) =
                    (me.form.clone(), me.os_version.clone(), me.version.clone(), me.mac.clone());
                d.mode.clone_from(&me.mode);
                if let Some(until) = me.muted_until_ms {
                    d.muted = true;
                    d.muted_until_ms = until;
                }
            } else if let Some(h) = hellos.get(&rec.id) {
                with_hello(&mut d, h, now_ms);
            }
            d
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use cbb_core::records::Key;
    use cbb_core::records::eval::DeviceState;

    use super::*;
    use crate::hello;

    fn dev(n: u8, name: &str) -> DeviceState {
        let key = Key::es256(vec![n; 65]);
        DeviceState {
            id: key.device_id(),
            key,
            name: name.into(),
            role: ROLE_MEMBER,
            rights: 0,
            skip: 0,
            caps: CAP_ADMIN,
            os: 1,
            store: STORE_HARDWARE,
            proof: 0,
            admin: None,
            powers: 0,
            commands: 0,
            frozen: false,
            replaces: None,
            guarded: false,
            by_root: true,
        }
    }

    #[test]
    fn devices_come_from_the_records_and_the_hellos() {
        let (a, b, c) = (dev(1, "desk"), dev(2, "laptop"), dev(3, "pi"));
        let mut state = State { devices: vec![a.clone(), b.clone(), c.clone()], ..State::default() };
        state.devices.sort_by_key(|d| d.id);
        state.root_device = Some(a.id);
        state.hubs = vec![c.id];
        let me =
            Me { id: a.id, mode: "shared".into(), muted_until_ms: Some(0), form: "desktop".into(), ..Me::default() };
        let mut h = Hello { mode: 2, muted: true, muted_for_ms: 1000, ..Hello::default() };
        h.device = hello::Device { form: form_number("laptop"), version: "0.6.0".into(), ..hello::Device::default() };
        let hellos = HashMap::from([(b.id, h)]);
        let admin_key = Key::es256(vec![9; 65]).hash();
        state.devices[2].admin = Some(admin_key);
        let out = devices_in(&state, &|_| false, &me, &hellos, 5000);
        assert!(out.iter().all(|d| !d.admin), "a key the set counts as no admin's shows as none");
        let out = devices_in(&state, &|h| *h == admin_key, &me, &hellos, 5000);
        assert!(out.iter().any(|d| d.admin));
        let get = |id: &DeviceId| out.iter().find(|d| d.id == id_text(id)).unwrap();
        let desk = get(&a.id);
        assert!(desk.this && desk.root && desk.online && desk.muted);
        assert_eq!((desk.form.as_str(), desk.os.as_str(), desk.store.as_str()), ("desktop", "linux", "hardware"));
        assert_eq!(desk.caps, vec!["admin".to_string()]);
        let laptop = get(&b.id);
        assert!(laptop.online && !laptop.this);
        assert_eq!((laptop.form.as_str(), laptop.mode.as_str(), laptop.muted_until_ms), ("laptop", "own", 6000));
        let pi = get(&c.id);
        assert!(pi.hub && !pi.online && pi.listed);
        assert_eq!(id_text(&c.id).len(), 32);
        let names = vec!["hub".to_string(), "admin".to_string(), "fly".to_string()];
        assert_eq!(caps_number(&names), CAP_ADMIN | CAP_HUB);
        assert_eq!(caps_names(caps_number(&names)), vec!["admin".to_string(), "hub".to_string()]);
    }
}
