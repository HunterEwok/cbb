// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Hub commands on the Rust service (docs/protocol.md, section 11, "Moving
//! the hub", "Several hubs", "Stopping a hub"), as Go's movehub.go and
//! stophub.go: an admin makes another computer a hub, moves the hub there,
//! or stops a hub, each with a signed hub command; and this device carries
//! out such a command.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::Away;
use super::serve::{forwarder_of, hub_addrs, own_offer, wait_clients_left};
use crate::admin::{Admin, find_device};
use crate::certs::DeviceId;
use crate::error::{Error, Result};
use crate::node::Node;
use crate::records::Device;
use crate::tunnel::{self, State};
use crate::wire::{self, TunnelOffer};

/// The clients a hub command hands over at most, as Go's
/// group.MaxHubClients.
const MAX_CLIENTS: usize = 256;

const NO_OTHER_HUB: &str = "the group has no other hub, so its devices away from home stop syncing until a device is a hub again; move the hub to another computer instead (cbb global move DEVICE), or stop it anyway with -yes";

/// A hub command's order, as Go's group.HubOrder.
#[derive(Serialize, Deserialize, Default)]
pub struct HubOrder {
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub stop: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forwarder: Option<HubForwarder>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub clients: Vec<Client>,
}

/// The forwarder a hub command gives: its address and its key's pin.
#[derive(Serialize, Deserialize, Clone)]
pub struct HubForwarder {
    #[serde(default)]
    pub endpoint: String,
    #[serde(default)]
    pub key: String,
}

/// A client a hub command hands over.
#[derive(Serialize, Deserialize, Clone)]
pub struct Client {
    #[serde(default)]
    pub device: String,
    #[serde(with = "cbb_core::certs::b64", default)]
    pub key: Vec<u8>,
    #[serde(with = "cbb_core::certs::b64", default)]
    pub psk: Vec<u8>,
}

impl Away {
    /// Carries out a hub command from by, as Go's takeHub: this computer,
    /// with sync away from home on, becomes a hub of the group at the
    /// order's addresses and takes the clients it hands over whose devices
    /// the records list. Returns its offer, without a preshared key.
    pub fn take_hub(&self, node: &Arc<Node>, by: &str, order: &serde_json::Value) -> Result<TunnelOffer> {
        let o: HubOrder =
            serde_json::from_value(order.clone()).map_err(|e| Error::with("the hub order does not decode", e))?;
        let fw = match &o.forwarder {
            Some(f) => forwarder_of(&f.endpoint, &f.key)?,
            None => None,
        };
        let eps = hub_addrs(&o.endpoints, fw.is_some())?;
        if eps.is_empty() && fw.is_none() {
            return Err(Error::msg("the hub needs an address away from home or a forwarder"));
        }
        let listed: std::collections::HashSet<String> = node.devices().into_iter().map(|d| d.id).collect();
        let mut cur = self.st.lock().unwrap();
        let st = match cur.as_mut() {
            None => {
                return Err(Error::msg(
                    "sync away from home is off on this computer; turn it on there first (cbb global on)",
                ));
            }
            Some(st) if st.relay.is_some() => {
                return Err(Error::msg(
                    "this computer meets the others at a blind relay; a group with a relay has no hub",
                ));
            }
            Some(st) => st,
        };
        let mut next = st.clone();
        (next.is_hub, next.retired, next.endpoints, next.forwarder, next.obfuscation) = (true, false, eps, fw, None);
        // The old hub is no hub any more.
        next.hubs.retain(|h| h.device != by);
        let mut taken = 0;
        for c in o.clients.iter().filter(|c| c.device != self.me.as_str()) {
            if !listed.contains(&c.device) {
                (self.log)(&format!(
                    "cbb: the hub command hands over {}, which the records do not list; left out",
                    c.device
                ));
                continue;
            }
            match next.take(&c.device, &c.key, &c.psk) {
                Ok(true) => taken += 1,
                Ok(false) => {}
                Err(e) => (self.log)(&format!("cbb: taking the client {} from the old hub: {}", c.device, e.for_log())),
            }
        }
        next.save(&self.dir).map_err(|e| e.context("saving the tunnel state"))?;
        *st = next;
        let st = st.clone();
        drop(cur);
        // It serves at once, as the hub the command makes it.
        self.stop_serving();
        self.serve(node, &st);
        (self.log)(&format!(
            "cbb: this device is the group's hub for sync away from home now, in place of {by}, with {taken} of its clients"
        ));
        own_offer(&st, &[]).ok_or_else(|| Error::msg("the hub has no offer yet"))
    }

    /// The group's hubs this device knows, as Go's knownHubs: itself while
    /// it is a hub, and the hubs in the group's order whose offers it keeps.
    fn known_hubs(&self, order: &[String]) -> Vec<String> {
        let cur = self.st.lock().unwrap();
        let Some(st) = cur.as_ref() else { return Vec::new() };
        let mut out: Vec<String> =
            st.hubs.iter().filter(|h| order.contains(&h.device)).map(|h| h.device.clone()).collect();
        if st.is_hub {
            out.push(self.me.to_string());
        }
        out
    }

    /// Makes the device target a hub of the group with a hub command, as
    /// Go's makeHub, while this device stays what it is: a hub hands it its
    /// clients, and a device with sync away from home on hands itself and
    /// keeps the new hub's offer.
    pub fn make_hub_on(
        &self,
        admin: &Admin,
        target: &str,
        addrs: &[String],
        fwd: (&str, &str),
        forward_only: bool,
    ) -> Result<()> {
        let d = find_device(admin.node, target)?;
        let may = admin.node.records().lock().unwrap().may_host(&d.id);
        if d.id == self.me.as_str() {
            return Err(Error::msg("-on names this device; cbb global hub makes it a hub here"));
        }
        if d.role != "full" {
            return Err(Error::msg(format!(
                "{} is no computer: a phone is the hub while its app is open (This phone as the hub there), and a lite member or a watch is never one",
                d.name
            )));
        }
        if forward_only && d.admin {
            return Err(Error::msg(format!(
                "{} is an admin, a hub that reads the copies; only a computer that is no admin is made one that only passes them on",
                d.name
            )));
        }
        if !forward_only && !may {
            return Err(Error::msg(format!(
                "{} may not be a hub: only the group's root or an admin with the hub power is one; make it an admin first",
                d.name
            )));
        }
        if d.frozen {
            return Err(Error::msg(format!("{} is frozen; an admin thaws it first", d.name)));
        }
        if forward_only {
            admin.mark_forward_only(&d)?;
        }
        let fw = forwarder_of(fwd.0, fwd.1)?;
        if addrs.is_empty() && fw.is_none() {
            return Err(Error::msg("give the new hub's addresses away from home, or a forwarder"));
        }
        hub_addrs(addrs, fw.is_some())?;
        let forwarder = fw.map(|f| HubForwarder { endpoint: f.endpoint.to_string(), key: f.pin });
        let mut order = HubOrder { endpoints: addrs.to_vec(), forwarder, ..Default::default() };
        let self_psk = {
            let cur = self.st.lock().unwrap();
            cur.as_ref().filter(|st| st.relay.is_none()).map(|st| {
                if st.is_hub {
                    order.clients.extend(st.members.iter().filter(|m| m.device != d.id).map(client_of));
                }
                order.clients.push(Client { device: self.me.to_string(), key: st.public_key(), psk: st.psk.clone() });
                st.psk.clone()
            })
        };
        if order.clients.len() > MAX_CLIENTS {
            order.clients.drain(..order.clients.len() - MAX_CLIENTS);
        }
        let res = admin.hub_command(&d, encode(&order)?)?;
        (self.log)(&format!("cbb: {} is a hub of the group now", d.name));
        let (Some(o), Some(psk)) = (res.tunnel.and_then(|v| serde_json::from_value::<TunnelOffer>(v).ok()), self_psk)
        else {
            return Ok(());
        };
        self.keep_offer(&d, o, psk, |_| {})
    }

    /// Makes the device target the group's hub in place of this one, as
    /// Go's moveHub: it hands over its clients, itself among them, passes
    /// the new hub's offer on to its connected clients and becomes the new
    /// hub's client.
    pub fn move_hub(&self, admin: &Admin, target: &str, addrs: &[String], fwd: (&str, &str)) -> Result<()> {
        let d = find_device(admin.node, target)?;
        if d.id == self.me.as_str() {
            return Err(Error::msg("this device is the hub already"));
        }
        let fw = forwarder_of(fwd.0, fwd.1)?;
        let mut order = HubOrder { endpoints: addrs.to_vec(), ..Default::default() };
        let (psks, self_psk) = {
            let cur = self.st.lock().unwrap();
            let st = cur
                .as_ref()
                .filter(|s| s.is_hub)
                .ok_or_else(|| Error::msg("this device is not the group's hub; cbb global hub makes it the hub"))?;
            // The new hub is reached through this hub's forwarder when the
            // request gives none.
            order.forwarder = fw
                .or_else(|| st.forwarder.clone())
                .map(|f| HubForwarder { endpoint: f.endpoint.to_string(), key: f.pin });
            if order.forwarder.is_none() && addrs.is_empty() {
                return Err(Error::msg(
                    "this hub has no forwarder; give the new hub's addresses away from home, or a forwarder",
                ));
            }
            let psks: Vec<(String, Vec<u8>)> =
                st.members.iter().filter(|m| m.device != d.id).map(|m| (m.device.clone(), m.psk.clone())).collect();
            order.clients.extend(st.members.iter().filter(|m| m.device != d.id).map(client_of));
            // This device is the new hub's client from now on.
            order.clients.push(Client { device: self.me.to_string(), key: st.public_key(), psk: st.psk.clone() });
            (psks, st.psk.clone())
        };
        if order.clients.len() > MAX_CLIENTS {
            return Err(Error::msg(format!("this hub has more than {} clients", MAX_CLIENTS - 1)));
        }
        let res = admin.hub_command(&d, encode(&order)?)?;
        let Some(offer) = res.tunnel.and_then(|v| serde_json::from_value::<TunnelOffer>(v).ok()) else {
            return Err(Error::msg(format!(
                "{} became the hub but sent no offer; turn sync away from home off and on again on this device",
                d.name
            )));
        };
        let new_hub = DeviceId::parse(&d.id)?;
        // Checked before the clients get it.
        tunnel::hub_from_offer(&new_hub, &TunnelOffer { psk: self_psk.clone(), ..offer.clone() })
            .map_err(|e| e.context(format!("the offer of {}", d.name)))?;
        let node = admin.node;
        let mut sent = Vec::new();
        for (dev, psk) in psks {
            let Ok(id) = DeviceId::parse(&dev) else { continue };
            let o = TunnelOffer { psk, hub: Some(d.id.clone()), moved: true, ..offer.clone() };
            if serde_json::to_value(&o).is_ok_and(|v| node.send_to(&id, wire::tunnel(&v))) {
                sent.push(id);
            }
        }
        (self.log)(&format!(
            "cbb: {} is the group's hub now; passed its offer on to {} connected clients",
            d.name,
            sent.len()
        ));
        wait_clients_left(node, &sent, &self.log);
        self.keep_offer(&d, offer, self_psk, |st| {
            // A client from now on, with the offers it keeps.
            let hubs = std::mem::take(&mut st.hubs);
            st.clear_periods();
            (st.is_hub, st.retired, st.endpoints, st.listen_port, st.members) =
                (false, false, Vec::new(), 0, Vec::new());
            (st.forwarder, st.obfuscation) = (None, None);
            st.hubs = hubs;
        })?;
        self.stop_serving();
        Ok(())
    }

    /// Makes the hub target stop being one with a hub command, as Go's
    /// stopHub on another device: without anyway it refuses while the group
    /// has no other hub this device knows.
    pub fn stop_hub_on(&self, admin: &Admin, target: &str, anyway: bool) -> Result<()> {
        let d = find_device(admin.node, target)?;
        let hubs = self.known_hubs(&admin.node.hub_order());
        if !hubs.contains(&d.id) {
            return Err(Error::msg(format!("{} is no hub of the group that this device knows", d.name)));
        }
        if hubs.len() < 2 && !anyway {
            return Err(Error::msg(NO_OTHER_HUB));
        }
        admin.hub_command(&d, encode(&HubOrder { stop: true, ..Default::default() })?)?;
        (self.log)(&format!("cbb: {} is no hub of the group any more", d.name));
        let mut cur = self.st.lock().unwrap();
        if let Some(st) = cur.as_mut() {
            let mut next = st.clone();
            if !next.forget_hubs(&|h| h.device != d.id).is_empty() {
                match next.save(&self.dir) {
                    Ok(()) => *st = next,
                    Err(e) => (self.log)(&format!("cbb: saving the tunnel state: {}", e.for_log())),
                }
            }
        }
        drop(cur);
        if self.using.lock().unwrap().as_ref().is_some_and(|(u, _)| *u == d.id)
            && let Ok(id) = DeviceId::parse(&d.id)
        {
            admin.node.disconnect(&id);
        }
        Ok(())
    }

    /// Keeps the offer o of the new hub d with this device's preshared key
    /// psk, after change makes the state what it is to be.
    fn keep_offer(&self, d: &Device, o: TunnelOffer, psk: Vec<u8>, change: impl FnOnce(&mut State)) -> Result<()> {
        let id = DeviceId::parse(&d.id)?;
        let link = tunnel::hub_from_offer(&id, &TunnelOffer { psk, hub: None, moved: false, ..o })
            .map_err(|e| e.context(format!("the offer of {}", d.name)))?;
        let mut cur = self.st.lock().unwrap();
        let Some(st) = cur.as_mut() else { return Ok(()) }; // turned off meanwhile
        let mut next = st.clone();
        change(&mut next);
        next.set_hub(link)?;
        next.save(&self.dir).map_err(|e| e.context("saving the tunnel state"))?;
        *st = next;
        Ok(())
    }
}

fn client_of(m: &tunnel::Member) -> Client {
    Client { device: m.device.clone(), key: m.key.clone(), psk: m.psk.clone() }
}

fn encode(o: &HubOrder) -> Result<serde_json::Value> {
    serde_json::to_value(o).map_err(|e| Error::with("cannot encode the hub order", e))
}

/// Whether a hub order is a stop order.
pub fn is_stop(order: &serde_json::Value) -> bool {
    serde_json::from_value::<HubOrder>(order.clone()).is_ok_and(|o| o.stop)
}
