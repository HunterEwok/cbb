// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Several hubs on the Rust service (docs/protocol.md, section 11, "Several
//! hubs"), as Go's hubs.go: a hub shares its offer, whether it serves and
//! its clients with the devices that may be hubs, takes theirs, and gives
//! way to a hub above it that serves, after passing that hub's offer on to
//! its own clients. The run loop (away.rs) serves only while no hub above
//! answers.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use cbb_core::certs::b64;
use serde::{Deserialize, Serialize};

use super::Away;
use super::serve::{offer_of, own_offer, wait_clients_left};
use crate::certs::{Cert, DeviceId};
use crate::node::Node;
use crate::tunnel;
use crate::wire::{self, Message, TunnelOffer};

/// How often a hub that serves, with hubs above it, tries them as a
/// client, as Go's hubRecheck.
pub(super) const HUB_RECHECK: Duration = Duration::from_secs(15 * 60);
/// How long a hub that lost the hub above it tries the hubs above before
/// it serves again, as Go's standbyGrace: a minute, or CBB_STANDBY_GRACE
/// seconds, which tests set shorter.
pub(super) fn standby_grace() -> Duration {
    static GRACE: std::sync::OnceLock<Duration> = std::sync::OnceLock::new();
    *GRACE.get_or_init(|| {
        let s = std::env::var("CBB_STANDBY_GRACE").ok().and_then(|v| v.parse().ok()).unwrap_or(60);
        Duration::from_secs(s)
    })
}
/// The clients a share carries at most, as Go's group.MaxHubClients.
const MAX_SHARED: usize = 256;

/// What a hub tells another device that may be a hub (`hubs` message).
#[derive(Serialize, Deserialize, Default)]
struct Share {
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    stopped: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    serving: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    offer: Option<TunnelOffer>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    clients: Vec<Client>,
}

/// A client a hub shares, with its keys.
#[derive(Serialize, Deserialize)]
struct Client {
    #[serde(default)]
    device: String,
    #[serde(with = "b64", default)]
    key: Vec<u8>,
    #[serde(with = "b64", default)]
    psk: Vec<u8>,
}

impl Away {
    /// What this device shares with peer, as Go's hubShare: on a hub, its
    /// offer, whether it serves and its clients, itself among them, for a
    /// peer that may be a hub; on a device that stopped being one, that it
    /// is none, for the computers and the devices that may be hubs.
    pub(super) fn share_for(&self, node: &Node, peer: &DeviceId) -> Option<Message> {
        let may = node.records().lock().unwrap().may_host(peer.as_str());
        let full = node.devices().iter().any(|d| d.id == peer.as_str() && d.role == "full");
        let cur = self.st.lock().unwrap();
        let st = cur.as_ref()?;
        let share = if !st.is_hub && st.retired {
            if !may && !full {
                return None;
            }
            Share { stopped: true, ..Default::default() }
        } else {
            if !may || !st.is_hub || *peer == self.me {
                return None;
            }
            let mut clients = vec![Client { device: self.me.to_string(), key: st.public_key(), psk: st.psk.clone() }];
            for m in st.members.iter().filter(|m| m.device != peer.as_str()) {
                if clients.len() >= MAX_SHARED {
                    break;
                }
                clients.push(Client { device: m.device.clone(), key: m.key.clone(), psk: m.psk.clone() });
            }
            let serving = self.serving.lock().unwrap().is_some();
            Share { serving, offer: own_offer(st, &[]), clients, ..Default::default() }
        };
        serde_json::to_value(&share).ok().map(|v| wire::hubs(&v))
    }

    /// Sends the connected devices, but except, what this device shares
    /// with each: when the hub starts or stops serving, admits a client, or
    /// stops being a hub.
    pub(super) fn share(&self, node: &Node, except: Option<&DeviceId>) {
        for p in node.peers() {
            if Some(&p.id) != except
                && let Some(m) = self.share_for(node, &p.id)
            {
                node.send_to(&p.id, m);
            }
        }
    }

    /// Takes what another hub shared, as Go's hubsShared: its clients, on
    /// this hub, and its offer, which this member keeps as any hub's. A hub
    /// above this one that serves makes this hub, while it serves, give way.
    pub fn hubs_shared(self: &Arc<Self>, node: &Arc<Node>, from: &DeviceId, chain: &[Cert], v: &serde_json::Value) {
        if !node.records().lock().unwrap().hub_peer(from.as_str(), chain) {
            (self.log)(&format!(
                "cbb: ignored what {from} shared as a hub: only the group's root, an admin or a hub its records name can be its hub"
            ));
            return;
        }
        let share: Share = match serde_json::from_value(v.clone()) {
            Ok(s) => s,
            Err(e) => {
                (self.log)(&format!("cbb: ignored what {from} shared as a hub: it does not decode: {e}"));
                return;
            }
        };
        let order = node.hub_order();
        let listed: HashSet<String> = node.devices().into_iter().map(|d| d.id).collect();
        let mut cur = self.st.lock().unwrap();
        let Some(st) = cur.as_mut().filter(|s| s.relay.is_none()) else { return };
        let mut next = st.clone();
        if share.stopped {
            if next.forget_hubs(&|h| h.device != from.as_str()).is_empty() {
                return;
            }
            (self.log)(&format!("cbb: {from} is no hub of the group any more; its offer is forgotten"));
            if let Err(e) = next.save(&self.dir) {
                (self.log)(&format!("cbb: saving the tunnel state: {}", e.for_log()));
                return;
            }
            *st = next;
            drop(cur);
            if self.using.lock().unwrap().as_ref().is_some_and(|(d, _)| d == from.as_str()) {
                node.disconnect(from);
            }
            return;
        }
        let (mut save, mut peers) = (false, false);
        if next.is_hub {
            for c in &share.clients {
                if c.device == self.me.as_str() || !listed.contains(&c.device) {
                    continue;
                }
                match next.take(&c.device, &c.key, &c.psk) {
                    Ok(changed) => (save, peers) = (save || changed, peers || changed),
                    Err(e) => (self.log)(&format!("cbb: a client {from} shared: {}", e.for_log())),
                }
            }
        }
        if let Some(o) = &share.offer {
            let o = TunnelOffer { psk: next.psk.clone(), hub: None, moved: false, ..o.clone() };
            match tunnel::hub_from_offer(from, &o).and_then(|h| next.set_hub(h)) {
                Ok(changed) => save = save || changed,
                Err(e) => {
                    (self.log)(&format!("cbb: the offer {from} shared as a hub: {}", e.for_log()));
                    return;
                }
            }
        }
        if save && let Err(e) = next.save(&self.dir) {
            (self.log)(&format!("cbb: saving the tunnel state: {}", e.for_log()));
            return;
        }
        *st = next;
        if peers {
            self.set_peers(st);
        }
        drop(cur);
        let rank = |d: &str| order.iter().position(|o| o == d).unwrap_or(order.len());
        if share.serving && rank(from.as_str()) < rank(self.me.as_str()) {
            self.give_way(node, from, share.offer);
        }
    }

    /// Makes this hub, while it serves, the client of from, a hub above it
    /// that serves, as Go's giveWayLocked: a client far from home may know
    /// only this hub, so the hub first passes from's offer on to its
    /// connected clients and waits for those through its tunnel to leave.
    fn give_way(self: &Arc<Self>, node: &Arc<Node>, from: &DeviceId, offer: Option<TunnelOffer>) {
        let why = format!("{from}, a hub above this one, serves");
        let psks: Vec<(String, Vec<u8>)> = {
            let cur = self.st.lock().unwrap();
            let Some(st) = cur.as_ref().filter(|s| s.is_hub) else { return };
            if self.serving.lock().unwrap().is_none() || self.giving_way.load(std::sync::atomic::Ordering::SeqCst) {
                return;
            }
            if offer.is_none() {
                drop(cur);
                self.standby(why);
                return;
            }
            st.members.iter().filter(|m| m.device != from.as_str()).map(|m| (m.device.clone(), m.psk.clone())).collect()
        };
        let Some(offer) = offer else { return };
        self.giving_way.store(true, std::sync::atomic::Ordering::SeqCst);
        let (away, node, from) = (self.clone(), node.clone(), from.clone());
        std::thread::spawn(move || {
            let mut sent = Vec::new();
            for (dev, psk) in psks {
                let Ok(id) = DeviceId::parse(&dev) else { continue };
                let o = TunnelOffer { psk, hub: Some(from.to_string()), moved: false, ..offer.clone() };
                if serde_json::to_value(&o).is_ok_and(|v| node.send_to(&id, wire::tunnel(&v))) {
                    sent.push(id);
                }
            }
            (away.log)(&format!(
                "cbb: passed the offer of {from}, a hub above this one, on to {} connected clients",
                sent.len()
            ));
            wait_clients_left(&node, &sent, &away.log);
            away.giving_way.store(false, std::sync::atomic::Ordering::SeqCst);
            away.standby(why);
        });
    }

    /// Asks the run loop to make this hub, while it serves, try the hubs
    /// above it as their client, for why.
    fn standby(&self, why: String) {
        *self.standby.lock().unwrap() = Some(why);
    }

    /// Forgets the offers of devices that may no longer be hubs, and on a
    /// hub the clients the records now refuse, as Go's pruneTunnel.
    pub fn prune(&self, node: &Node) {
        let mut cur = self.st.lock().unwrap();
        let Some(st) = cur.as_mut() else { return };
        let mut next = st.clone();
        let lost = next.forget_hubs(&|h| node.records().lock().unwrap().may_host(&h.device));
        for d in &lost {
            (self.log)(&format!("cbb: {d} is no longer the group's root or an admin; its offer as a hub is forgotten"));
        }
        let listed: HashSet<String> = node.devices().into_iter().map(|d| d.id).collect();
        let gone = next.prune(&|m| {
            if m.chain.is_empty() {
                // Shared or handed over, not met yet: kept while the
                // records list the device.
                return listed.contains(&m.device);
            }
            match m.chain.iter().map(|d| Cert::parse(d)).collect::<std::result::Result<Vec<_>, _>>() {
                Ok(chain) => node.records().lock().unwrap().refused(&chain).is_none(),
                Err(_) => false,
            }
        });
        if lost.is_empty() && gone.is_empty() {
            return;
        }
        for d in &gone {
            (self.log)(&format!("cbb: {d} was removed from the group; the hub drops its tunnel"));
        }
        if let Err(e) = next.save(&self.dir) {
            (self.log)(&format!("cbb: saving the tunnel state: {}", e.for_log()));
        }
        *st = next;
        if !gone.is_empty() {
            self.set_peers(st);
        }
        drop(cur);
        if let Some((d, _)) = self.using.lock().unwrap().clone()
            && lost.contains(&d)
            && let Ok(id) = DeviceId::parse(&d)
        {
            node.disconnect(&id);
        }
    }
}

/// The offer this member passes on for the hub h, with a client's psk.
pub(super) fn passed_on(h: &tunnel::Hub, psk: &[u8]) -> TunnelOffer {
    TunnelOffer { psk: psk.to_vec(), hub: Some(h.device.clone()), ..offer_of(h) }
}
