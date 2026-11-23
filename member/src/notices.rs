// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The member's notices about the group (docs/apps.md, "Notices"), which
//! the phones' apps take through ffi's `notices` and the computers' apps
//! through the service's status, as `{id, kind, args, dismissable}`.

use cbb_core::certs;
use cbb_core::records::{DeviceId, KeyHash, RecordId, RecordSet};
use serde_json::{Value, json};

use crate::roster::id_text;

/// The share of the root's room that removals waiting for admins take
/// before the root's device says so (docs/apps.md, "Notices").
pub const ROOT_ROOM_WARN_PERCENT: u64 = 50;

/// The notices of set for the device me at now_ms (Unix milliseconds).
/// Only the notices of removed devices that count again
/// (`returned_after_removal`, by the removal's or the change's record ID)
/// may be hidden; the others stay until what they say is over.
/// `root_room_waiting` shows on the root's own device.
pub fn of(set: &RecordSet, me: &DeviceId, now_ms: u64) -> Vec<Value> {
    let st = set.state();
    let device_of = |k: &KeyHash| {
        st.devices.iter().find(|d| d.key.hash() == *k || d.admin.as_ref() == Some(k)).map(|d| id_text(&d.id))
    };
    let notice = |id: String, kind: &str, args: Value, dismissable: bool| json!({ "id": id, "kind": kind, "args": args, "dismissable": dismissable });
    let mut out = Vec::new();
    if set.change_arriving(&st).is_some() {
        out.push(notice("change_arriving".into(), "change_arriving", json!({}), false));
    }
    if !set.removals_waiting(&st).is_empty() {
        out.push(notice("removals_waiting".into(), "removals_waiting", json!({}), false));
    }
    if let Some(w) = set.root_room_waiting(&st, ROOT_ROOM_WARN_PERCENT).filter(|_| st.root_device == Some(*me)) {
        let percent = w.waiting_units.saturating_mul(100).checked_div(w.room.cap.max(1)).unwrap_or(0);
        out.push(notice("root_room_waiting".into(), "root_room_waiting", json!({ "percent": percent }), false));
    }
    let own_admin = st.devices.iter().find(|d| d.id == *me).and_then(|d| d.admin);
    if let Some(o) = own_admin.and_then(|k| set.ack_owed(&st, &k, now_ms)) {
        out.push(notice(
            "ack_owed".into(),
            "ack_owed",
            json!({ "removals": o.removals, "days_left": o.days_left }),
            false,
        ));
    }
    for f in set.frozen_holding(&st) {
        let d = id_text(&f.device);
        out.push(notice(format!("frozen_holding:{d}"), "frozen_holding", json!({ "device": d }), false));
    }
    if !set.stuck_checkpoints().is_empty() {
        out.push(notice("checkpoint_stuck".into(), "checkpoint_stuck", json!({}), false));
    }
    for (id, keys) in set.notices(&st) {
        let devices: Vec<String> = keys.iter().filter_map(device_of).collect();
        let Some(first) = devices.first() else { continue };
        out.push(notice(
            certs::b64::encode(&id.0),
            "returned_after_removal",
            json!({ "device": first, "devices": devices.len() }),
            true,
        ));
    }
    out
}

/// The record ID of a notice the person hides, as `of` gives it.
pub fn record_id(s: &str) -> Option<RecordId> {
    let b = certs::b64::decode_str(s)?;
    Some(RecordId(b.try_into().ok()?))
}
