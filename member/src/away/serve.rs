// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The Rust service as one of the group's hubs (docs/protocol.md, section
//! 11), as Go's service is one: it admits the tunnel keys its members'
//! hellos offer, answers each with its offer and those of the other hubs it
//! keeps, and serves them on the same Hub the phones run (src/hub.rs). A
//! connection through the tunnel goes to a loopback port of its own, where
//! the node takes the member protocol only, from the device whose tunnel
//! address it came from.

use std::net::{SocketAddr, TcpListener};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::Away;
use crate::certs::{Cert, DeviceId};
use crate::control::{self, Header};
use crate::error::{Context, Error, Result};
use crate::forward::{self, Registration, Report};
use crate::hub::{self, Hub};
use crate::node::{Node, Peer};
use crate::tunnel::{Forwarder, MEMBER_PORT, State};
use crate::wire::{self, Message, TunnelOffer};

/// How long the clients a stopping hub passed the next hub's offer to may
/// take to leave its tunnel, as Go's moveGrace, and the moment after.
const MOVE_GRACE: Duration = Duration::from_secs(10);
const MOVE_LINGER: Duration = Duration::from_secs(1);

/// The pins of the project's forwarder's key this release knows, as Go's
/// forward.projectPins, and what stands for them in a hub request.
const PROJECT_PINS: &[&str] = &["efzUG2YzJBqS8FfojZGwqioECt46VzQcFo3oWpPru/g="];
const PROJECT_KEY: &str = "default";

/// The hub while it serves.
pub(super) struct Serving {
    /// Dropped first: the registration stops before the hub.
    forwarding: Option<Forwarding>,
    hub: Arc<Hub>,
    /// When it started serving.
    pub(super) since: Instant,
}

/// The hub's registration with its forwarder.
struct Forwarding {
    _registration: Registration,
    report: Arc<Mutex<Report>>,
    endpoint: SocketAddr,
}

impl Away {
    /// Makes this device one of the group's hubs with the addresses, port
    /// and AmneziaWG a hub request gives (cbb global hub), as Go's
    /// awayLocked: sync away from home goes on first with consent. Returns
    /// whether the hellos must go again with the keys, which it returns.
    pub fn make_hub(&self, h: &Header) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut fw = forwarder_of(&h.forwarder, &h.forwarder_key)?;
        if !(0..=65535).contains(&h.port) {
            return Err(Error::msg(format!("a bad port {}", h.port)));
        }
        let mut cur = self.st.lock().unwrap();
        if cur.is_none() && !h.consent {
            return Err(Error::msg(
                "sync away from home is off here; turn it on first: cbb global on, or cbb global hub -away-on",
            ));
        }
        let mut st = match cur.clone() {
            Some(st) => st,
            None => State::new(&self.group)?,
        };
        let (mut endpoints, mut port) = (hub_addrs(&h.addrs, fw.is_some())?, h.port as u16);
        if h.keep {
            if !st.is_hub {
                return Err(Error::msg(
                    "this device is not a hub yet, so it has no settings to keep; make it one first: cbb global hub",
                ));
            }
            if h.addrs.is_empty() {
                endpoints = st.endpoints.clone();
            }
            if h.port == 0 {
                port = st.listen_port;
            }
            if h.forwarder.is_empty() {
                fw.clone_from(&st.forwarder);
            }
        }
        if endpoints.is_empty() && fw.is_none() {
            return Err(Error::msg("the hub needs an address away from home or a forwarder"));
        }
        if let Some(f) = fw.as_mut() {
            vless_for(f, h.vless, st.forwarder.as_ref());
        } else if h.vless {
            return Err(Error::msg("VLESS goes to a forwarder; give one with -forwarder and -forwarder-key"));
        }
        // VLESS comes with AmneziaWG: the clients try it over UDP first,
        // and inside VLESS it hides WireGuard's sizes (docs/protocol.md,
        // section 11, "VLESS"). Kept as they are when the hub is set again,
        // so its clients' offers stay good.
        let obfuscation = match (h.obfuscate || h.vless, st.obfuscation.take()) {
            (false, _) => None,
            (true, Some(o)) => Some(o),
            (true, None) => Some(crate::awg::Obfuscation::random()?.to_value()),
        };
        st.is_hub = true;
        st.retired = false;
        st.endpoints = endpoints;
        st.listen_port = port;
        st.forwarder = fw;
        st.relay = None;
        st.obfuscation = obfuscation;
        st.save(&self.dir)?;
        let keys = (st.public_key(), st.psk.clone());
        if cur.is_none() {
            (self.log)("cbb: sync away from home is on");
        }
        *cur = Some(st);
        drop(cur);
        // It serves again with the new settings once the loop sees them.
        self.stop_serving();
        *self.error.lock().unwrap() = None;
        (self.log)("cbb: this device is one of the group's hubs for sync away from home");
        Ok(keys)
    }

    /// Makes this device, a hub, stop being one, as Go's stopHub: without
    /// anyway it refuses while the group has no other hub. The connected
    /// clients get the next hub's offer first and leave this one's tunnel.
    pub fn stop_hub(&self, node: &Node, anyway: bool) -> Result<()> {
        let order = node.hub_order();
        let (next, psks) = {
            let cur = self.st.lock().unwrap();
            let st =
                cur.as_ref().filter(|s| s.is_hub).ok_or_else(|| Error::msg("this device is no hub of the group"))?;
            let next = st.hubs_to_try(&order).into_iter().find(|h| h.device != self.me.as_str());
            if next.is_none() && !anyway {
                return Err(Error::msg(
                    "the group has no other hub, so its devices away from home stop syncing until a device is a hub again; move the hub to another computer instead (cbb global move DEVICE), or stop it anyway with -yes",
                ));
            }
            let psks: Vec<(String, Vec<u8>)> = st
                .members
                .iter()
                .filter(|m| next.as_ref().is_none_or(|n| n.device != m.device))
                .map(|m| (m.device.clone(), m.psk.clone()))
                .collect();
            (next, psks)
        };
        if let Some(n) = &next {
            let mut sent = Vec::new();
            for (dev, psk) in &psks {
                let Ok(id) = DeviceId::parse(dev) else { continue };
                let mut o = offer_of(n);
                (o.psk, o.hub, o.moved) = (psk.clone(), Some(n.device.clone()), true);
                if serde_json::to_value(&o).is_ok_and(|v| node.send_to(&id, wire::tunnel(&v))) {
                    sent.push(id);
                }
            }
            (self.log)(&format!(
                "cbb: passed the offer of {}, the next hub, on to {} connected clients",
                n.device,
                sent.len()
            ));
            wait_clients_left(node, &sent, &self.log);
        }
        let mut cur = self.st.lock().unwrap();
        let Some(st) = cur.as_mut().filter(|s| s.is_hub) else { return Ok(()) };
        let mut next_st = st.clone();
        next_st.is_hub = false;
        next_st.retired = true;
        next_st.endpoints.clear();
        next_st.listen_port = 0;
        next_st.members.clear();
        next_st.forwarder = None;
        next_st.obfuscation = None;
        next_st.clear_periods();
        next_st.save(&self.dir)?;
        *st = next_st;
        drop(cur);
        self.stop_serving();
        // The computers and the devices that may be hubs forget its offer.
        self.share(node, None);
        (self.log)(&match next {
            Some(n) => format!("cbb: this device is no hub of the group any more; its clients go to {}", n.device),
            None => "cbb: this device is no hub of the group any more, and the group has no other".to_string(),
        });
        Ok(())
    }

    /// Admits the tunnel key a member's hello offers, on a hub, and returns
    /// the offers for it: its own and those of the other hubs it passes on,
    /// as Go's tunnelKeyOffered. chain is the member's verified chain.
    pub fn hello(&self, node: &Node, from: &DeviceId, peer: &Peer, chain: &[Cert]) -> Vec<Message> {
        let share = || self.share_for(node, from).into_iter().collect();
        let Some((key, psk)) = peer.tunnel_key.as_ref() else { return share() };
        let mut cur = self.st.lock().unwrap();
        let Some(st) = cur.as_mut().filter(|s| s.is_hub) else {
            drop(cur);
            return share();
        };
        let mut next = st.clone();
        let ders = chain.iter().map(|c| c.der.clone()).collect();
        let (m, changed) = match next.admit(from.as_str(), key, psk, ders) {
            Ok(r) => r,
            Err(e) => {
                (self.log)(&format!("cbb: admitting the tunnel key of {from}: {}", e.for_log()));
                return Vec::new();
            }
        };
        if changed {
            if let Err(e) = next.save(&self.dir) {
                (self.log)(&format!("cbb: saving the tunnel state: {}", e.for_log()));
                return Vec::new();
            }
            (self.log)(&format!("cbb: {from} can reach this hub away from home"));
        }
        *st = next;
        let offers = offers(st, from.as_str(), &m.psk, &node.hub_order());
        if changed {
            self.set_peers(st);
        }
        drop(cur);
        let mut out: Vec<Message> =
            offers.iter().filter_map(|o| serde_json::to_value(o).ok()).map(|v| wire::tunnel(&v)).collect();
        out.extend(self.share_for(node, from));
        if changed {
            // The other hubs learn every client before this one is off.
            self.share(node, Some(from));
        }
        out
    }

    /// Gives the running hub the clients st admits.
    pub(super) fn set_peers(&self, st: &State) {
        let Some(s) = self.serving.lock().unwrap().as_ref().map(|s| s.hub.clone()) else { return };
        if let Err(e) = st.peers().and_then(|p| s.set_peers(p, self.me.as_str())) {
            self.fail(&e.context("the hub could not take its clients"));
        }
    }

    /// Serves as the hub with st unless it serves already, and tells the
    /// other hubs once it starts; on an error it fails closed, and status
    /// says why.
    pub(super) fn serve(&self, node: &Arc<Node>, st: &State) {
        if self.serving.lock().unwrap().is_some() {
            return;
        }
        match self.start_hub(node, st) {
            Ok(s) => {
                *self.serving.lock().unwrap() = Some(s);
                *self.error.lock().unwrap() = None;
                self.share(node, None);
            }
            Err(e) => self.fail(&e),
        }
    }

    fn start_hub(&self, node: &Arc<Node>, st: &State) -> Result<Serving> {
        let port = if st.listen_port == 0 { MEMBER_PORT } else { st.listen_port };
        let ln = TcpListener::bind("127.0.0.1:0").context("cannot open the hub's local port")?;
        let local = ln.local_addr().context("cannot open the hub's local port")?.port();
        let target: hub::Target = Arc::new(move |a| if hub::is_guest(&a) { None } else { Some(local) });
        // Both IPv6 and IPv4 where the system has IPv6, else IPv4 alone.
        let start = |ip: std::net::IpAddr| -> Result<Hub> {
            Hub::start(
                &st.serving_key(),
                self.me.as_str(),
                st.obfuscation.as_ref(),
                st.peers()?,
                SocketAddr::from((ip, port)),
                target.clone(),
                self.log.clone(),
            )
        };
        let hub = start(std::net::Ipv6Addr::UNSPECIFIED.into())
            .or_else(|_| start(std::net::Ipv4Addr::UNSPECIFIED.into()))
            .map_err(|e| e.context(format!("the hub could not listen on UDP port {port}")))?;
        let hub = Arc::new(hub);
        // The members' connections through the tunnel: each checked
        // against the address it came from.
        let (weak, n) = (Arc::downgrade(&hub), Arc::downgrade(node));
        let log = self.log.clone();
        std::thread::spawn(move || {
            for sock in ln.incoming() {
                let (Some(hub), Some(node), Ok(sock)) = (weak.upgrade(), n.upgrade(), sock) else { return };
                let from = sock.peer_addr().ok().and_then(|a| tunnel_addr_of(&hub, a.port()));
                drop(hub);
                let Some(from) = from else { continue };
                let log = log.clone();
                std::thread::spawn(move || {
                    if let Err(e) = node.accept_tunneled(sock, from)
                        && !node.is_closed()
                    {
                        log(&format!("cbb: a connection through the tunnel from {from}: {}", e.for_log()));
                    }
                });
            }
        });
        (self.log)(&format!("cbb: the hub serves on UDP port {}", hub.udp_port()));
        let forwarding = match &st.forwarder {
            Some(f) => Some(self.register(node, st, f, &hub)?),
            None => None,
        };
        Ok(Serving { forwarding, hub, since: Instant::now() })
    }

    /// Keeps the hub registered with its forwarder while it serves, as Go's
    /// registerForwarderLocked: with its member certificate, the roots and
    /// the group's records, which show the forwarder it is the root or an
    /// admin, and hellos from its WireGuard port.
    fn register(&self, node: &Node, st: &State, f: &Forwarder, hub: &Hub) -> Result<Forwarding> {
        let ident = node.identity();
        let key: Arc<dyn cbb_core::identity::ExternalKey> = match &ident.external {
            Some(k) => k.clone(),
            None => Arc::new(cbb_core::identity::FileKey::new(&ident.key)?),
        };
        let (roots, records) = {
            let rs = node.records();
            let rs = rs.lock().unwrap();
            (rs.roots(), rs.all())
        };
        let mut chain = ident.chain();
        for c in std::iter::once(ident.group_ca.clone()).chain(roots) {
            if !chain.contains(&c.der) {
                chain.push(c.der);
            }
        }
        let records = records.iter().filter_map(|r| serde_json::to_value(r).ok()).collect();
        let pins =
            if f.project { PROJECT_PINS.iter().map(|p| pin_bytes(p)).collect() } else { vec![pin_bytes(&f.pin)] };
        let cfg = forward::Config {
            endpoint: f.endpoint,
            pins: pins.into_iter().collect::<Result<_>>()?,
            chain,
            key,
            wg_key: st.serving_key(),
            obfuscation: st.obfuscation.clone(),
            vless_id: Some(f.vless_id.clone()).filter(|id| !id.is_empty()),
            records: Arc::new(Mutex::new(records)),
            send: hub.sender(),
        };
        let report = Arc::new(Mutex::new(Report::default()));
        let registration = Registration::start(cfg, report.clone(), self.log.clone());
        Ok(Forwarding { _registration: registration, report, endpoint: f.endpoint })
    }

    /// Keeps the forwarder's VLESS settings the hub learned as it
    /// registered, as Go's vlessLearnedLocked, and has the members connect
    /// again, so that each gets the offer with them.
    pub(super) fn vless_learned(&self, node: &Node) {
        let got = {
            let serving = self.serving.lock().unwrap();
            serving.as_ref().and_then(|s| s.forwarding.as_ref()).and_then(|f| f.report.lock().unwrap().vless.clone())
        };
        let Some(v) = got else { return };
        let mut cur = self.st.lock().unwrap();
        let Some(st) = cur.as_mut() else { return };
        if st.forwarder.as_ref().is_none_or(|f| f.vless_id.is_empty() || f.vless.as_ref() == Some(&v)) {
            return;
        }
        let mut next = st.clone();
        if let Some(f) = next.forwarder.as_mut() {
            f.vless = Some(v.clone());
        }
        if let Err(e) = next.save(&self.dir) {
            (self.log)(&format!("cbb: saving the tunnel state: {}", e.for_log()));
            return;
        }
        *st = next;
        drop(cur);
        let at = v.get("endpoint").and_then(|e| e.as_str()).unwrap_or_default();
        (self.log)(&format!("cbb: sync away from home: the hub's clients come over VLESS to the forwarder at {at}"));
        node.reconnect();
    }

    /// Stops the hub, with every connection through it.
    pub(super) fn stop_serving(&self) {
        self.serving.lock().unwrap().take();
    }

    /// The hub's side of status.
    pub(super) fn hub_status(&self, st: &State, a: &mut control::Away, standby: bool) {
        a.hub = true;
        a.standby = standby;
        a.port = i64::from(if st.listen_port == 0 { MEMBER_PORT } else { st.listen_port });
        a.clients = st.members.len() as i64;
        a.obfuscated = st.obfuscation.is_some();
        a.endpoints = st.endpoints.iter().map(ToString::to_string).collect();
        let serving = self.serving.lock().unwrap();
        a.forwarder = match serving.as_ref().and_then(|s| s.forwarding.as_ref()) {
            Some(f) => {
                let r = f.report.lock().unwrap().clone();
                let detail = r.error.unwrap_or_default();
                Some(control::Forwarder {
                    endpoint: f.endpoint.to_string(),
                    registered: r.registered,
                    seen: r.seen.unwrap_or_default(),
                    error: forwarder_problem(&detail),
                    detail,
                })
            }
            None => st
                .forwarder
                .as_ref()
                .map(|f| control::Forwarder { endpoint: f.endpoint.to_string(), ..Default::default() }),
        };
    }
}

/// The tunnel address the connection from the loopback port from_port came
/// from: the hub notes it just after it connects, so a moment is given.
fn tunnel_addr_of(hub: &Hub, from_port: u16) -> Option<std::net::Ipv6Addr> {
    let until = Instant::now() + Duration::from_secs(1);
    loop {
        if let Some(a) = hub.tunnel_addr(from_port) {
            return Some(a);
        }
        if Instant::now() > until {
            return None;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Says goodbye to the clients the next hub's offer went to that are
/// connected through this hub's tunnel, and waits up to MOVE_GRACE for them
/// to leave, as Go's waitClientsLeft; those at home stay connected.
pub(super) fn wait_clients_left(node: &Node, sent: &[DeviceId], log: &Arc<dyn Fn(&str) + Send + Sync>) {
    let through: Vec<DeviceId> = node.tunneled().into_iter().filter(|d| sent.contains(d)).collect();
    if through.is_empty() {
        return;
    }
    for d in &through {
        node.disconnect(d);
    }
    let until = Instant::now() + MOVE_GRACE;
    while node.tunneled().iter().any(|d| through.contains(d)) {
        if Instant::now() > until {
            log(&format!(
                "cbb: a client of this hub did not take the new hub's offer in {} s; it gets it at home",
                MOVE_GRACE.as_secs()
            ));
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    std::thread::sleep(MOVE_LINGER);
}

/// The hub's offers for its client `client` with its preshared key psk:
/// its own, then those of the other hubs in the group's order it keeps, as
/// Go's hubOffersLocked; none while the offers wait for the forwarder's
/// VLESS settings.
fn offers(st: &State, client: &str, psk: &[u8], order: &[String]) -> Vec<TunnelOffer> {
    let Some(own) = own_offer(st, psk) else { return Vec::new() };
    let mut out = vec![own];
    for h in &st.hubs {
        if h.device != client && order.contains(&h.device) {
            out.push(super::hubs::passed_on(h, psk));
        }
    }
    out
}

/// The hub's own offer with the preshared key psk, as Go's
/// hubOfferLocked; None while it waits for the forwarder's VLESS settings.
pub(super) fn own_offer(st: &State, psk: &[u8]) -> Option<TunnelOffer> {
    if st.forwarder.as_ref().is_some_and(|f| !f.vless_id.is_empty() && f.vless.is_none()) {
        return None;
    }
    Some(TunnelOffer {
        hub_key: crate::tunnel::public_key_of(&st.serving_key()),
        psk: psk.to_vec(),
        endpoints: st.hub_endpoints().iter().map(ToString::to_string).collect(),
        obfuscation: st.obfuscation.clone(),
        vless: st.forwarder.as_ref().filter(|f| !f.vless_id.is_empty()).and_then(|f| f.vless.clone()),
        next_key: st.next_public(),
        ..Default::default()
    })
}

/// The offer a member keeps as h, without its preshared key.
pub(super) fn offer_of(h: &crate::tunnel::Hub) -> TunnelOffer {
    TunnelOffer {
        hub_key: h.key.clone(),
        endpoints: h.endpoints.iter().map(ToString::to_string).collect(),
        obfuscation: h.obfuscation.clone(),
        vless: h.vless.clone(),
        next_key: h.next.clone(),
        ..Default::default()
    }
}

/// The hub's addresses away from home, as Go's hubAddrs reads them.
pub(super) fn hub_addrs(addrs: &[String], forwarder: bool) -> Result<Vec<SocketAddr>> {
    let mut out = Vec::new();
    for a in addrs {
        let ep: SocketAddr = match a.parse::<SocketAddr>() {
            Ok(ep) if ep.port() != 0 => unmapped(ep),
            _ => {
                return Err(Error::msg(format!(
                    "{a:?} is not an address with a port, such as 203.0.113.7:8764 or [2001:db8::7]:8764"
                )));
            }
        };
        out.push(ep);
    }
    if out.len() > 7 || !forwarder && out.len() > 8 {
        return Err(Error::msg("at most 8 addresses, the forwarder's included"));
    }
    Ok(out)
}

/// The hub's forwarder that a request or a hub command gives, as Go's
/// hubAddrs reads it: its address and its key's pin, or `default` for the
/// project's forwarder, whose pins this release knows; None for none.
pub(super) fn forwarder_of(fwd: &str, key: &str) -> Result<Option<Forwarder>> {
    if fwd.is_empty() {
        if !key.is_empty() {
            return Err(Error::msg("a forwarder's key without its address"));
        }
        return Ok(None);
    }
    let endpoint = match fwd.parse::<SocketAddr>() {
        Ok(ep) if ep.port() != 0 => unmapped(ep),
        _ => {
            return Err(Error::msg(format!(
                "{fwd:?} is not the forwarder's address with a port, such as 203.0.113.9:8764"
            )));
        }
    };
    let (pin, project) = if key == PROJECT_KEY {
        (PROJECT_PINS[0].to_string(), true)
    } else {
        pin_bytes(key)?;
        (key.to_string(), PROJECT_PINS.contains(&key))
    };
    Ok(Some(Forwarder { endpoint, pin, vless_id: String::new(), vless: None, project }))
}

/// Gives the forwarder f the group's VLESS user ID when the hub's clients
/// come over VLESS, as Go's awayLocked: the one old had, with old's
/// settings while the forwarder stays the same, else a new one.
fn vless_for(f: &mut Forwarder, vless: bool, old: Option<&Forwarder>) {
    (f.vless_id, f.vless) = (String::new(), None);
    if !vless {
        return;
    }
    match old.filter(|o| !o.vless_id.is_empty()) {
        Some(o) => {
            f.vless_id.clone_from(&o.vless_id);
            if o.endpoint == f.endpoint && o.pin == f.pin {
                f.vless.clone_from(&o.vless);
            }
        }
        None => f.vless_id = crate::vless::session_id(),
    }
}

/// A forwarder's pin: SHA-256 of its key, 44 characters of base64.
fn pin_bytes(pin: &str) -> Result<[u8; 32]> {
    use base64::Engine as _;
    let e = base64::engine::general_purpose::STANDARD;
    e.decode(pin).ok().filter(|b| e.encode(b) == pin).and_then(|b| <[u8; 32]>::try_from(b).ok()).ok_or_else(|| {
        Error::msg(format!("{pin:?} is not a forwarder's key; cbb forward prints it, 44 characters of base64"))
    })
}

/// An IPv4 address mapped into IPv6 is the IPv4 address.
fn unmapped(ep: SocketAddr) -> SocketAddr {
    match ep {
        SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
            Some(v4) => SocketAddr::from((v4, v6.port())),
            None => ep,
        },
        v4 => v4,
    }
}

/// A short message for status of why the hub is not registered, as Go's
/// forwarderProblem; the whole error goes to the detail.
fn forwarder_problem(detail: &str) -> String {
    if detail.is_empty() {
        String::new()
    } else if let Some(i) = detail.find("the forwarder refused the registration") {
        detail[i..].to_string()
    } else if detail.contains("pin") {
        "the forwarder's key is not the one given with -forwarder-key".to_string()
    } else {
        "the registration with the forwarder failed".to_string()
    }
}
