// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Why this device does not sync: the facts `cbb_core::why` reasons from,
//! gathered from the status a member gives (a computer's control socket
//! and a phone's member alike), and the group's part of that status.

use cbb_core::why::{AwayFacts, DeviceFacts, Facts, Reason};

use crate::control::{Device, Status};
use crate::node::Node;

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
        taken_over_by: st.taken_over_by.clone(),
        cert_ends_ms: st.cert_ends_ms,
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
    }
}

/// The group's part of a member's status: the claims and conflicts that
/// wait or stop the group, the records of a later version, and whether an
/// admin froze this computer's admin key or took the group over from it,
/// as Go's statusWithRemoved says.
pub fn group_status(node: &Node) -> Status {
    let ident = node.identity();
    let own: Vec<cbb_core::certs::Cert> = std::iter::once(ident.cert.clone()).chain(ident.issuer.clone()).collect();
    let records = node.records();
    let rs = records.lock().unwrap();
    let st = rs.state();
    // An old root that an admin took the group over from, or a frozen
    // admin, is refused but not removed.
    let taken = rs.taken_over(&own);
    let refused = matches!(rs.refused(&own), Some(cbb_core::group::Refusal::Refused(_)));
    let frozen = taken.is_none() && refused && own.iter().any(|c| rs.frozen(&c.key_hash()));
    // A signer's device for the user, as Go's SignerName.
    let name = |k: &cbb_core::authority::Hash| -> String {
        st.devices
            .iter()
            .find(|d| d.admin.as_ref() == Some(k))
            .or_else(
                || if st.roots.contains(k) { st.devices.iter().find(|d| d.device == st.root_device) } else { None },
            )
            .map_or_else(|| k.text(), |d| d.name.clone())
    };
    Status {
        claims: st
            .claims
            .iter()
            .filter(|c| matches!(c.state, "pending" | "competing" | "disputed"))
            .map(|c| crate::control::Claim { by: name(&c.claimant), state: c.state.into(), left_ms: c.left_ms })
            .collect(),
        conflicts: st
            .conflicts
            .iter()
            .map(|c| crate::control::Conflict { kind: c.kind.into(), devices: c.signers.iter().map(name).collect() })
            .collect(),
        newer: st.newer.len(),
        frozen,
        taken_over_by: taken
            .map(|(dev, _)| st.devices.iter().find(|d| d.device == dev).map_or(dev, |d| d.name.clone()))
            .unwrap_or_default(),
        ..Default::default()
    }
}

/// The group's devices as `facts` reads them (the name, whether a device
/// is online, its sync and mute), lighter than the devices op: one look at
/// the records and the peers, since status answers it on every call.
pub fn devices(node: &Node) -> Vec<Device> {
    let me = node.identity().id.to_string();
    let peers = node.peers();
    let named: Vec<(String, String)> = {
        let records = node.records();
        let rs = records.lock().unwrap();
        rs.state().devices.iter().map(|d| (d.device.clone(), d.name.clone())).collect()
    };
    named
        .into_iter()
        .map(|(id, name)| {
            let peer = peers.iter().find(|p| p.id.as_str() == id);
            Device {
                this: id == me,
                online: peer.is_some() || id == me,
                mode: peer.map(|p| p.mode.clone()).unwrap_or_default(),
                muted: peer.is_some_and(|p| p.muted),
                id,
                name,
                ..Default::default()
            }
        })
        .collect()
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
