// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Why this device does not sync: the facts `cbb_core::why` reasons from,
//! gathered from the status a member gives (a computer's control socket
//! and a phone's member alike), and the group's part of that status.

use cbb_core::why::{AwayFacts, DeviceFacts, Facts, Reason};

use crate::control::{Device, Status};

/// The reasons for st, with the group's devices devs (this one among them
/// or not), at now_ms.
pub fn reasons(st: &Status, devs: &[Device], now_ms: i64) -> Vec<Reason> {
    cbb_core::why::diagnose(&facts(st, devs), now_ms)
}

/// The facts in a member's status.
pub fn facts(st: &Status, devs: &[Device]) -> Facts {
    let away = st.away.as_ref().map(|a| AwayFacts {
        hub: a.hub,
        standby: a.standby,
        hub_device: a.hub_device.clone(),
        through: a.through,
        hidden: a.obfuscated || a.vless,
        relay: a.relay.is_some(),
        relay_connected: a.relay.as_ref().is_some_and(|r| r.connected),
        forwarder: a.forwarder.is_some(),
        forwarder_registered: a.forwarder.as_ref().is_some_and(|f| f.registered),
        entries_stale: a.forwarder.as_ref().is_some_and(|f| f.entries_stale),
        error: a
            .forwarder
            .as_ref()
            .map(|f| f.error.clone())
            .filter(|e| !e.is_empty())
            .or_else(|| a.relay.as_ref().map(|r| r.error.clone()).filter(|e| !e.is_empty()))
            .unwrap_or_else(|| a.error.clone()),
    });
    // A hub's own name stands for the hub a device uses: "mac", not its ID.
    let name =
        |id: &str| devs.iter().find(|d| d.id == id && !d.name.is_empty()).map_or(id.to_string(), |d| d.name.clone());
    let mut away = away;
    if let Some(a) = away.as_mut()
        && !a.hub_device.is_empty()
    {
        a.hub_device = name(&a.hub_device);
    }
    Facts {
        in_group: !st.group.is_empty(),
        removed: st.removed,
        frozen: st.frozen,
        stop: st.stop.clone(),
        sync_off: st.mode == "own",
        sync_until_ms: if st.mode == "own" { st.sync_until_ms } else { 0 },
        muted: st.muted,
        muted_until_ms: st.muted_until_ms,
        newer: st.newer,
        update: st.update.clone(),
        connected: st.peers.len(),
        devices: devs
            .iter()
            .filter(|d| !d.this && d.id != st.device)
            .map(|d| DeviceFacts {
                name: if d.name.is_empty() { d.id.clone() } else { d.name.clone() },
                online: d.online,
                sync_off: d.mode == "own",
                muted: d.muted,
            })
            .collect(),
        quiet: st.quiet.clone(),
        unreached: st.unreached.iter().map(|id| name(id)).collect(),
        away,
        ..Facts::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::{Away, Forwarder};

    fn dev(id: &str, name: &str, online: bool) -> Device {
        Device { id: id.into(), name: name.into(), online, ..Default::default() }
    }

    /// A computer's status turns into the facts the core reasons from: its
    /// own row left out, the hub and the unreached members by name, sync
    /// off from the mode.
    #[test]
    fn facts_from_a_status() {
        let st = Status {
            device: "me".into(),
            group: "g".into(),
            mode: "own".into(),
            sync_until_ms: 5,
            unreached: vec!["b".into()],
            away: Some(Away { hub_device: "a".into(), vless: true, ..Default::default() }),
            ..Default::default()
        };
        let mut own = dev("me", "this", true);
        own.this = true;
        let mut b = dev("b", "pi", false);
        b.mode = "own".into();
        let f = facts(&st, &[own, dev("a", "mac", false), b]);
        assert!(f.in_group && f.sync_off && f.sync_until_ms == 5);
        assert_eq!(f.devices.iter().map(|d| d.name.as_str()).collect::<Vec<_>>(), ["mac", "pi"]);
        assert!(f.devices[1].sync_off);
        assert_eq!(f.unreached, ["pi"]);
        let a = f.away.unwrap();
        assert_eq!(a.hub_device, "mac");
        assert!(a.hidden && !a.through);
        let codes: Vec<String> = reasons(&st, &[], 1).into_iter().map(|r| r.code).collect();
        assert_eq!(codes, ["sync_off", "unreached", "only_device"]);
    }

    /// A hub's forwarder error is the detail its reason carries.
    #[test]
    fn a_forwarders_error_is_the_detail() {
        let st = Status {
            group: "g".into(),
            peers: vec![dev("a", "mac", true)],
            away: Some(Away {
                hub: true,
                forwarder: Some(Forwarder { error: "no answer".into(), ..Default::default() }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let r = reasons(&st, &[dev("a", "mac", true)], 1);
        assert_eq!(r.len(), 1);
        assert_eq!((r[0].code.as_str(), r[0].detail.as_str()), ("forwarder_down", "no answer"));
    }
}
