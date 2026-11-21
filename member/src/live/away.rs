// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Sync away from home on the records of 0.6, the device's side: on each
//! member connection with a device that may be its hub, while sync away
//! from home is on here, this device sends `tunnel` (t 15) with its key
//! toward that hub and the tag of the connection's pre-shared key; the
//! hub's offer comes back in field 6 of a `result` (docs/protocol.md,
//! section 11).

use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use cbb_core::records::DeviceId;

use super::{Live, id_text4};
use crate::away::Away;
use crate::discovery::Peers as _;

impl Live {
    /// Gives this member its sync away from home, which then sends
    /// `tunnel` to its hubs and keeps their offers.
    pub fn with_away(self: &Arc<Self>, away: Arc<Away>) {
        if self.away.set(away).is_err() {
            return;
        }
        let w: Weak<Live> = Arc::downgrade(self);
        self.mesh.on_connected(Box::new(move |peer| {
            if let Some(l) = w.upgrade() {
                l.tunnel_toward(peer);
                if l.hub.lock().unwrap().is_some() && l.handoff.lock().unwrap().is_none() {
                    l.hubs_say(Some(peer), cbb_core::hubkey::HubSays::Serving);
                }
            }
        }));
        let w: Weak<Live> = Arc::downgrade(self);
        self.mesh.on_other(Box::new(move |peer, t, msg| {
            let Some(l) = w.upgrade() else { return };
            match t {
                cbb_core::msg::tables::T_RESULT => l.offered(peer, msg),
                cbb_core::msg::tables::T_TUNNEL => l.tunnel_from(peer, msg),
                cbb_core::msg::tables::T_HUBS => l.hubs_from(peer, msg),
                cbb_core::msg::tables::T_GUEST => l.guest_from(peer, msg),
                _ => {}
            }
        }));
        let w: Weak<Live> = Arc::downgrade(self);
        std::thread::spawn(move || reach_hubs(&w));
        let w: Weak<Live> = Arc::downgrade(self);
        std::thread::spawn(move || serve_hub(&w));
        let w: Weak<Live> = Arc::downgrade(self);
        std::thread::spawn(move || super::relay::meet(&w));
    }

    /// Whether this hub stands by while a hub above it serves.
    pub fn is_standing_by(&self) -> bool {
        self.standing_by.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Sync away from home, once with_away gave it.
    pub fn away(&self) -> Option<&Arc<Away>> {
        self.away.get()
    }

    /// The way over VLESS by which `cbb update` reaches the mirror on the
    /// hub's forwarder (protocol.md section 16): a hub's own forwarder's,
    /// with the group's VLESS user ID, or that of the hub this member goes
    /// through or tries first in the group's order of hubs; None without
    /// sync away from home or without VLESS.
    pub fn update_way(&self) -> Option<serde_json::Value> {
        let order: Vec<String> = self.mesh.hub_order().iter().map(|d| cbb_core::certs::hex(&d.0)).collect();
        self.away.get()?.update_way_in(&order)
    }

    /// Sends `tunnel` to every device connected that may be a hub: sync
    /// away from home was turned on.
    pub fn tunnel_to_hubs(&self) {
        for peer in self.mesh.connected() {
            self.tunnel_toward(&peer);
        }
    }

    /// Turns sync away from home off: its keys go, and the connection
    /// through the tunnel ends after `after`, so that the result of a
    /// command that came on it goes back first.
    pub fn away_off(&self, after: Duration) -> crate::error::Result<()> {
        let Some(away) = self.away.get() else { return Ok(()) };
        let through = away.live_status().filter(|s| s.through).and_then(|s| hub_id(&s.hub_device));
        away.turn_off()?;
        if let Some(hub) = through {
            let mesh = Arc::downgrade(&self.mesh);
            std::thread::spawn(move || {
                std::thread::sleep(after);
                if let Some(m) = mesh.upgrade() {
                    m.disconnect(&hub);
                }
            });
        }
        Ok(())
    }

    /// Sends `tunnel` again to the devices connected that may be hubs and
    /// whose offers are not held, RETUNNEL after it last went to each.
    fn tunnel_again(&self, away: &Away) {
        if !away.is_on() {
            return;
        }
        let connected = self.mesh.connected();
        self.toward.lock().unwrap().retain(|d, _| connected.contains(d));
        let held: Vec<String> = away.hubs_kept().into_iter().map(|h| h.device).collect();
        for peer in connected {
            let due = self.toward.lock().unwrap().get(&peer).is_none_or(|t| t.elapsed() >= RETUNNEL);
            if due && !held.contains(&cbb_core::certs::hex(&peer.0)) {
                self.toward.lock().unwrap().insert(peer, Instant::now());
                self.tunnel_toward(&peer);
            }
        }
    }

    /// Sends `tunnel` to the device peer, connected now, if it may be a hub
    /// and sync away from home is on here.
    fn tunnel_toward(&self, peer: &DeviceId) {
        let Some(away) = self.away.get() else { return };
        if !self.mesh.may_be_hub(peer) {
            return;
        }
        let Some(psk) = self.mesh.tunnel_psk(peer, false) else {
            // A connection whose key exchange was not the hybrid gives no
            // key; the next one may.
            return;
        };
        match away.tunnel_to(peer, psk) {
            Ok(Some(f)) => {
                if self.mesh.send(peer, f) {
                    self.toward.lock().unwrap().insert(*peer, Instant::now());
                }
            }
            Ok(None) => {}
            Err(e) => self.logf(&format!("cbb: the tunnel's key toward hub {}: {}", id_text4(peer), e.for_log())),
        }
    }

    /// A client sent this hub `tunnel`: the key is kept, the hub answers
    /// with its offer confirming the tag, and its tunnel takes the keys.
    fn tunnel_from(&self, peer: &DeviceId, msg: &[u8]) {
        let Some(away) = self.away.get() else { return };
        let Ok((key, confirm)) = cbb_core::hubkey::read(msg) else { return };
        let Some(psk) = self.mesh.tunnel_psk(peer, true) else { return };
        let tag = match away.tunnel_from(peer, key, &confirm, psk) {
            Ok(Some(tag)) => tag,
            Ok(None) => return,
            Err(e) => {
                self.logf(&format!("cbb: the tunnel key of {}: {}", id_text4(peer), e.for_log()));
                return;
            }
        };
        self.give_hub_peers();
        let Some(offer) = away.offer_encoding(&tag) else { return };
        match crate::away::offer_result(&self.mesh.device(), &tag, &offer) {
            Ok(f) => {
                if self.mesh.send(peer, f) {
                    self.guest_offered(peer);
                }
            }
            Err(e) => self.logf(&format!("cbb: the hub's offer: {}", e.for_log())),
        }
    }

    /// Sends `hubs` (t 16) to the device to, or to every device connected
    /// that may be a hub.
    fn hubs_say(&self, to: Option<&DeviceId>, says: cbb_core::hubkey::HubSays) {
        let msg = cbb_core::hubkey::hubs_message(says);
        let Ok(v) = cbb_core::format::cbor::decode(&msg) else { return };
        let f = cbb_core::format::frame::write(&v);
        let peers = to.map_or_else(|| self.mesh.connected().into_iter().collect(), |p| vec![*p]);
        for p in peers.iter().filter(|p| self.mesh.may_be_hub(p)) {
            self.mesh.send(p, f.clone());
        }
    }

    /// Another hub said it serves, or that it stopped being a hub (mesh
    /// takes `hubs` only from a device that may be a hub).
    fn hubs_from(&self, peer: &DeviceId, msg: &[u8]) {
        match cbb_core::hubkey::read_hubs(msg) {
            Ok(cbb_core::hubkey::HubSays::Serving) => {
                self.ladder.lock().unwrap().serving.insert(*peer);
            }
            Ok(cbb_core::hubkey::HubSays::Stopped) => {
                // A hub that says it stopped leaves no grace behind it, as
                // a hub that moves away (D-122): the next one serves at once.
                let mut ladder = self.ladder.lock().unwrap();
                if ladder.serving.remove(peer) {
                    (ladder.above, ladder.lost) = (false, None);
                }
            }
            Err(e) => self.logf(&format!("cbb: ignored message hubs from {}: {e}", id_text4(peer))),
        }
    }

    /// Whether this hub stands by: a hub above it in the order is
    /// connected and said it serves, or was until less than a minute ago
    /// and did not say it stopped.
    pub(super) fn stands_by(&self) -> bool {
        let order = self.mesh.hub_order();
        let me = self.mesh.device();
        let at = order.iter().position(|d| *d == me).unwrap_or(order.len());
        let connected = self.mesh.connected();
        let mut ladder = self.ladder.lock().unwrap();
        ladder.serving.retain(|d| connected.contains(d));
        let above = ladder.serving.iter().any(|d| order.iter().position(|o| o == d).is_some_and(|p| p < at));
        if above {
            ladder.lost = None;
            ladder.above = true;
        } else if ladder.above {
            ladder.above = false;
            ladder.lost = Some(Instant::now());
        }
        above || ladder.lost.is_some_and(|t| t.elapsed() < again_after())
    }

    /// This hub of 0.6 stops being one: each client connected gets an offer
    /// that says the hub moved, so that it takes the next hub in the order,
    /// and then the hub's settings go; its tunnel stops, and it tells the
    /// other hubs, once the loop sees it.
    pub fn stop_being_hub(&self) -> crate::error::Result<()> {
        let away = self.away.get().ok_or_else(|| crate::error::Error::msg("this device is no hub of the group"))?;
        if !away.is_hub_now() {
            return Err(crate::error::Error::msg("this device is no hub of the group"));
        }
        let connected = self.mesh.connected();
        for d in away.held_devices().iter().filter(|d| connected.contains(d)) {
            let Some(psk) = self.mesh.tunnel_psk(d, true) else { continue };
            let Some(offer) = away.moved_encoding(&psk.confirm) else { continue };
            if let Ok(f) = crate::away::offer_result(&self.mesh.device(), &psk.confirm, &offer) {
                self.mesh.send(d, f);
            }
        }
        away.unhub()
    }

    /// This hub moves to the hub `to`, which the order made one (option C
    /// of the move, D-122): it tells the other hubs it stopped, so that the
    /// new hub serves even below it in the order, and keeps serving the
    /// clients that came through its tunnel meanwhile, which meet the new
    /// hub at home or at the group's relay and take its offer there. Once
    /// the new hub said it serves, it sends them `moved` and stops when
    /// none comes through its tunnel any more, or after [`move_linger`];
    /// it stops after that time too when the new hub never said it serves.
    /// A client away with neither home nor a relay holds no offer of the
    /// new hub, and loses the hub until it meets it.
    pub fn hand_hub_to(self: &Arc<Self>, to: DeviceId) -> crate::error::Result<()> {
        let away = self.away.get().ok_or_else(|| crate::error::Error::msg("this device is no hub of the group"))?;
        if !away.is_hub_now() {
            return Err(crate::error::Error::msg("this device is no hub of the group"));
        }
        if self.handoff.lock().unwrap().replace(to).is_some() {
            return Ok(());
        }
        self.hubs_say(None, cbb_core::hubkey::HubSays::Stopped);
        let w = Arc::downgrade(self);
        std::thread::spawn(move || {
            let started = Instant::now();
            let mut serving: Option<Instant> = None;
            loop {
                std::thread::sleep(Duration::from_millis(500));
                let Some(l) = w.upgrade() else { return };
                if l.is_closed() || !l.away.get().is_some_and(|a| a.is_hub_now()) {
                    l.handoff.lock().unwrap().take();
                    return;
                }
                // Moved again meanwhile: the last order counts.
                let Some(to) = *l.handoff.lock().unwrap() else { return };
                if serving.is_none()
                    && l.mesh.connected().contains(&to)
                    && l.ladder.lock().unwrap().serving.contains(&to)
                {
                    l.logf(&format!("cbb: {} serves now; this hub hands its clients over", id_text4(&to)));
                    serving = Some(Instant::now());
                }
                let done = match serving {
                    Some(t) => l.tunnel_clients() == 0 || t.elapsed() >= move_linger(),
                    None => started.elapsed() >= move_linger(),
                };
                if !done {
                    continue;
                }
                if serving.is_none() {
                    l.logf(&format!("cbb: {} did not say it serves; this hub stops all the same", id_text4(&to)));
                }
                l.handoff.lock().unwrap().take();
                match l.stop_being_hub() {
                    Ok(()) => l.logf(&format!("cbb: the hub moved to {}", id_text4(&to))),
                    Err(e) => l.logf(&format!("cbb: the hub's move: {}", e.for_log())),
                }
                return;
            }
        });
        Ok(())
    }

    /// The clients held whose connection with this hub comes through its
    /// tunnel: from the loopback port the tunnel dialed from.
    fn tunnel_clients(&self) -> usize {
        let Some(hub) = self.hub.lock().unwrap().as_ref().map(|r| r.hub.clone()) else { return 0 };
        let Some(away) = self.away.get() else { return 0 };
        away.held_devices()
            .iter()
            .filter_map(|d| self.mesh.peer_addr(d))
            .filter(|a| a.ip().is_loopback() && hub.tunnel_addr(a.port()).is_some())
            .count()
    }

    /// Gives the hub's tunnel, while it runs, the clients and keys held.
    pub(super) fn give_hub_peers(&self) {
        let hub = self.hub.lock().unwrap().as_ref().map(|r| r.hub.clone());
        let (Some(away), Some(hub)) = (self.away.get(), hub) else { return };
        let st = self.mesh.state();
        let mut peers = away.held_peers(&|id| st.device(id).is_some_and(|d| !d.frozen));
        peers.extend(self.guest_peers());
        if let Err(e) = hub.set_peers_at(peers, self.own_tunnel_addr()) {
            self.logf(&format!("cbb: the hub could not take its clients: {}", e.for_log()));
        }
    }

    fn own_tunnel_addr(&self) -> std::net::Ipv6Addr {
        crate::tunnel::addr(&cbb_core::certs::hex(&self.me.0)).unwrap_or(std::net::Ipv6Addr::UNSPECIFIED)
    }

    /// A `result` with a hub's offer came from peer.
    fn offered(&self, peer: &DeviceId, msg: &[u8]) {
        let Some(away) = self.away.get() else { return };
        if !self.mesh.may_be_hub(peer) {
            self.logf(&format!("cbb: ignored an offer from {}: it may not be a hub of the group", id_text4(peer)));
            return;
        }
        let Ok((_, v, _)) = cbb_core::msg::read_noted(msg) else { return };
        let Some(offer) = v.get(6) else { return };
        // A hub that moved or stopped: a connection through its tunnel
        // ends, and the next hub in the order is tried.
        if offer.get(6).is_some() && away.through_hub().is_some_and(|d| hub_id(&d) == Some(*peer)) {
            let (mesh, peer) = (self.mesh.clone(), *peer);
            std::thread::spawn(move || mesh.disconnect(&peer));
        }
        match away.take_offer(peer, offer) {
            Ok(true) => {
                self.logf(&format!("cbb: {} is one of the group's hubs for sync away from home", id_text4(peer)))
            }
            Ok(false) => {}
            Err(e) => self.logf(&format!("cbb: ignored the offer of hub {}: {}", id_text4(peer), e.for_log())),
        }
    }
}

/// How long the service waits after it starts before it tries the tunnel,
/// so that discovery finds the hub at home first.
const FIRST_WAIT: Duration = Duration::from_secs(5);
/// The longest wait between rounds of tries.
const MAX_WAIT: Duration = Duration::from_secs(30);
/// How long the links of one pre-shared key wait for the hub's answer
/// before the next key is tried, besides the time each further endpoint
/// takes.
const KEY_WAIT: Duration = Duration::from_secs(5);
/// A connection through the tunnel that lasted this long resets the wait.
const STEADY: Duration = Duration::from_secs(30);
/// How often `tunnel` goes again to a device connected that may be a hub
/// and whose offer this member does not hold: it may have become a hub, or
/// one by the records, since the connection began.
const RETUNNEL: Duration = Duration::from_secs(15);

/// Dials, through the tunnel, the first hub whose offer is kept that
/// answers, whenever no hub is connected or at home, until the member
/// closes. Each hub is tried with the pre-shared keys of this device's
/// connections with it, one key at a time, newest confirmed first
/// (`DeviceSide::to_try`), each key over every way of the hub at once (its
/// own key and each forwarder face's, and its next key).
fn reach_hubs(w: &Weak<Live>) {
    std::thread::sleep(FIRST_WAIT);
    let mut wait = Duration::from_secs(1);
    loop {
        let Some(l) = w.upgrade() else { return };
        if l.is_closed() {
            return;
        }
        let Some(away) = l.away.get().cloned() else { return };
        l.tunnel_again(&away);
        // The hubs kept, in the order in which they serve; one outside the
        // order is not tried.
        let order = l.mesh.hub_order();
        let mut kept: Vec<(usize, crate::tunnel::Hub, DeviceId)> = away
            .hubs_kept()
            .into_iter()
            .filter_map(|h| {
                let id = hub_id(&h.device)?;
                Some((order.iter().position(|o| *o == id)?, h, id))
            })
            .collect();
        kept.sort_by_key(|(at, ..)| *at);
        let (hubs, ids): (Vec<_>, Vec<_>) = kept.into_iter().map(|(_, h, id)| (h, id)).unzip();
        // A device that joined by invitation reaches the hub through the
        // invitation's guest tunnel until it holds the hub's offer.
        if hubs.is_empty() && !l.is_paused() && l.through_guest(&away) {
            continue;
        }
        let connected = l.mesh.connected();
        if hubs.is_empty() || l.is_paused() || ids.iter().any(|id| connected.contains(id) || l.at_home(id)) {
            drop(l);
            std::thread::sleep(Duration::from_secs(1));
            continue;
        }
        let mut reached = false;
        for (hub, id) in hubs.iter().zip(&ids) {
            if l.is_closed() {
                return;
            }
            let start = Instant::now();
            match l.through_hub(&away, hub, id) {
                Ok(true) => {
                    reached = true;
                    away.failed(None);
                    if start.elapsed() > STEADY {
                        wait = Duration::from_secs(1);
                    }
                    break;
                }
                Ok(false) => {}
                Err(e) => away.failed(Some(&e)),
            }
        }
        drop(l);
        if !reached {
            std::thread::sleep(wait);
            wait = (wait * 2).min(MAX_WAIT);
        }
    }
}

fn hub_id(device: &str) -> Option<DeviceId> {
    super::id_of_hex(device)
}

impl Live {
    /// Tries the hub through the tunnel with each pre-shared key in turn;
    /// once it answers, the member connection runs through it until it
    /// ends. Whether the hub answered.
    fn through_hub(&self, away: &Arc<Away>, hub: &crate::tunnel::Hub, id: &DeviceId) -> crate::error::Result<bool> {
        let Some(secret) = away.secret_toward(id) else { return Ok(false) };
        let psks = away.keys_toward(id);
        if psks.is_empty() {
            // Never met at home: no key to try.
            return Err(crate::error::Error::msg(format!(
                "this device has not met hub {} at home since sync away from home was turned on",
                id_text4(id)
            )));
        }
        let mut ways = hub.ways();
        if !hub.next.is_empty() {
            ways.extend(hub.with_next().ways());
        }
        if let Some(v) = away.tunnel_via() {
            for w in &mut ways {
                w.endpoints = vec![v];
            }
        }
        let mut last = None;
        for psk in psks {
            let mut started = Vec::new();
            for way in &ways {
                match crate::tunnel::Link::start_toward(secret, psk, way, &self.me, self.log.clone()) {
                    Ok(link) => started.push(link),
                    Err(e) => last = Some(e),
                }
            }
            let n = ways.iter().map(|h| h.endpoints.len() + usize::from(h.vless.is_some())).max().unwrap_or(1);
            let until = Instant::now()
                + KEY_WAIT
                + crate::tunnel::ENDPOINT_WAIT.saturating_mul(u32::try_from(n.saturating_sub(1)).unwrap_or(u32::MAX));
            while Instant::now() < until && !started.iter().any(crate::tunnel::Link::answered) && !self.is_closed() {
                std::thread::sleep(Duration::from_millis(50));
            }
            let Some(link) = started.into_iter().find(crate::tunnel::Link::answered) else { continue };
            away.handshaked(id, &psk)?;
            away.set_through(Some(&hub.device));
            let res = self.mesh.dial(link.local(), Some(*id));
            away.set_through(None);
            return res.map(|_| true).or_else(|e| {
                away.failed(Some(&e));
                Ok(true)
            });
        }
        Err(last.unwrap_or_else(|| {
            crate::error::Error::msg(format!(
                "the hub {} does not answer through the tunnel: it may be off, its UDP port closed, or the network on the way down",
                id_text4(id)
            ))
        }))
    }
}

/// Serves as a hub of 0.6 while this device is one: the hub's tunnel with
/// the clients held, each connection through it to this member as a member
/// connection, and the clients' handshakes noted; until the member closes.
fn serve_hub(w: &Weak<Live>) {
    loop {
        let Some(l) = w.upgrade() else { return };
        let Some(away) = l.away.get().cloned() else { return };
        if l.is_closed() {
            l.hub.lock().unwrap().take();
            away.hub_stopped();
            return;
        }
        let settings = away.hub_settings();
        // A hub stands by while a hub above it serves: its clients go to
        // that one.
        // A hub that moves keeps serving its clients until it hands them
        // over, whatever the hubs above it say.
        let standby = settings.is_some() && l.handoff.lock().unwrap().is_none() && l.stands_by();
        l.standing_by.store(standby, std::sync::atomic::Ordering::SeqCst);
        let is_hub = settings.is_some();
        let settings = settings.filter(|_| !standby);
        // Set again with another port, obfuscation or forwarder: it starts
        // again with them.
        let changed = settings.is_some() && l.hub.lock().unwrap().as_ref().is_some_and(|r| r.started != started(&away));
        if changed {
            l.hub.lock().unwrap().take();
            l.logf("cbb: the hub starts again with its new settings");
        }
        let running = l.hub.lock().unwrap().as_ref().map(|r| (r.hub.clone(), r.report.clone()));
        match (settings, running) {
            (None, Some(_)) => {
                l.hub.lock().unwrap().take();
                away.hub_stopped();
                if is_hub {
                    l.logf("cbb: the hub stands by, since a hub above it serves");
                } else {
                    l.note_own_forwarder(&away);
                    l.hubs_say(None, cbb_core::hubkey::HubSays::Stopped);
                    l.logf("cbb: the hub stopped");
                }
            }
            (Some(_), None) if away.rotate_live(&l.hub_period(&away)).1 => {
                // The keys for the period are made before the hub listens,
                // so that its first clients get the offer it serves with.
            }
            (Some(s), None) => match l.start_hub(&away, s) {
                Ok(r) => {
                    l.note_own_forwarder(&away);
                    *l.hub.lock().unwrap() = Some(r);
                    // A hub that moves away, ordered before it served,
                    // serves its clients but tells the other hubs nothing:
                    // it said it stopped, so that the new one serves.
                    if l.handoff.lock().unwrap().is_none() {
                        l.hubs_say(None, cbb_core::hubkey::HubSays::Serving);
                    }
                }
                Err(e) => away.failed(Some(&e)),
            },
            (Some(_), Some((h, report))) => {
                // A new period of the forwarder's face: the next key, and
                // the hub serves with it once due, starting again.
                let (changed, switched) = away.rotate_live(&l.hub_period(&away));
                if switched {
                    l.hub.lock().unwrap().take();
                }
                if changed {
                    let connected = l.mesh.connected();
                    for d in away.held_devices().iter().filter(|d| connected.contains(d)) {
                        l.mesh.disconnect(d);
                    }
                }
                for (key, psk) in h.take_handshakes() {
                    if let Err(e) = away.hub_handshaked(&key, &psk) {
                        l.logf(&format!("cbb: {}", e.for_log()));
                    }
                }
                // The forwarder's VLESS settings change the offer: the
                // clients connected connect again, and take it with their
                // next `tunnel`.
                let r = report.and_then(|r| r.lock().ok().map(|r| r.clone()));
                if r.is_some_and(|r| away.hub_learned(&r)) {
                    let connected = l.mesh.connected();
                    for d in away.held_devices().iter().filter(|d| connected.contains(d)) {
                        l.mesh.disconnect(d);
                    }
                }
            }
            (None, None) => {}
        }
        drop(l);
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// What a hub started with that it starts again for when it changes: its
/// port and obfuscation settings, and its forwarder and the pins it takes
/// there. Its key changes with the period without that.
type Started = (Option<(Option<serde_json::Value>, u16)>, Option<String>, Option<Vec<[u8; 32]>>);

fn started(away: &Away) -> Started {
    (
        away.hub_settings().map(|(_, o, port)| (o, port)),
        away.live_forwarder(false).map(|f| f.endpoint),
        away.hub_forwarder_pins(),
    )
}

/// How long a hub that moves keeps serving its clients after the new hub
/// serves: five minutes, or CBB_TEST_MOVE_LINGER seconds in a build for
/// tests.
fn move_linger() -> Duration {
    crate::testbuild::env("CBB_TEST_MOVE_LINGER")
        .and_then(|v| v.parse().ok())
        .map_or(Duration::from_secs(300), Duration::from_secs)
}

/// How long a hub that lost the hub above it waits before it serves again:
/// a minute, or CBB_TEST_STANDBY_GRACE seconds in a build for tests.
#[cfg(not(test))]
fn again_after() -> Duration {
    crate::away::standby_grace()
}
#[cfg(test)]
fn again_after() -> Duration {
    Duration::from_secs(2)
}

/// The hubs that said they serve (`hubs`, t 16), and whether one above
/// this hub did when last looked at, and since when it is gone.
#[derive(Default)]
pub(super) struct Ladder {
    serving: std::collections::BTreeSet<DeviceId>,
    above: bool,
    lost: Option<Instant>,
}

/// The hub of 0.6 while it serves: its registration with its forwarder,
/// dropped first, and its tunnel, and what it started with.
pub(super) struct HubRun {
    _registration: Option<crate::forward::Registration>,
    started: Started,
    report: Option<Arc<std::sync::Mutex<crate::forward::Report>>>,
    hub: Arc<crate::hub::Hub>,
}

impl Live {
    /// The period a hub of 0.6 serves its key for: the tag, in hex, of its
    /// forwarder's face, else of the project's forwarder's; empty without
    /// one (the hub serves with the key its hello offers).
    fn hub_period(&self, away: &Away) -> String {
        let project = crate::faces::PROJECT_FORWARDER_PINS.iter().filter_map(|p| {
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD.decode(p).ok().and_then(|b| <[u8; 32]>::try_from(b).ok())
        });
        let pins: Vec<[u8; 32]> = away.hub_forwarder_pins().unwrap_or_default().into_iter().chain(project).collect();
        let faces = self.mesh.faces();
        pins.iter().find_map(|p| faces.kept(p).tag()).map(|t| cbb_core::certs::hex(&t)).unwrap_or_default()
    }

    /// On the root, the forwarder its own hub serves with gets a face of its
    /// own (`Mesh::set_hub_forwarders`), and none once it stopped.
    fn note_own_forwarder(&self, away: &Away) {
        if !self.mesh.is_root() {
            return;
        }
        let servers = away.own_forwarder().map(|(address, pin)| crate::faces::Server { pin, address });
        if let Err(e) = self.mesh.set_hub_forwarders(self.me, servers.into_iter().collect()) {
            self.logf(&format!("cbb: the hub's forwarder: {}", e.for_log()));
        }
    }

    /// Starts the hub's tunnel with settings, its connections going to a
    /// loopback port where this member takes them, and its registration with
    /// its forwarder under the hubs' credential of the forwarder's face.
    fn start_hub(
        self: &Arc<Self>,
        away: &Arc<Away>,
        (key, obfuscation, port): ([u8; 32], Option<serde_json::Value>, u16),
    ) -> crate::error::Result<HubRun> {
        use crate::error::Context as _;
        let port = if port == 0 { crate::tunnel::MEMBER_PORT } else { port };
        let ln = std::net::TcpListener::bind("127.0.0.1:0").context("cannot open the hub's local port")?;
        let local = ln.local_addr().context("cannot open the hub's local port")?.port();
        // A guest's connections go to their own port (docs/protocol.md,
        // section 12): its invitation's pairing, or its admitted device.
        let guest_ln = std::net::TcpListener::bind("127.0.0.1:0").context("cannot open the hub's local port")?;
        let guest_port = guest_ln.local_addr().context("cannot open the hub's local port")?.port();
        let st = self.mesh.state();
        let mut peers = away.held_peers(&|id| st.device(id).is_some_and(|d| !d.frozen));
        peers.extend(self.guest_peers());
        let target: crate::hub::Target =
            Arc::new(move |a| Some(if crate::hub::is_guest(&a) { guest_port } else { local }));
        let start = |ip: std::net::IpAddr| {
            crate::hub::Hub::start(
                &key,
                &cbb_core::certs::hex(&self.me.0),
                obfuscation.as_ref(),
                peers.clone(),
                std::net::SocketAddr::from((ip, port)),
                target.clone(),
                self.log.clone(),
            )
        };
        let hub = start(std::net::Ipv6Addr::UNSPECIFIED.into())
            .or_else(|_| start(std::net::Ipv4Addr::UNSPECIFIED.into()))
            .map_err(|e| e.context(format!("the hub could not listen on UDP port {port}")))?;
        let hub = Arc::new(hub);
        let w = Arc::downgrade(self);
        std::thread::spawn(move || {
            for sock in ln.incoming() {
                let (Some(l), Ok(sock)) = (w.upgrade(), sock) else { return };
                let mesh = l.mesh.clone();
                drop(l);
                std::thread::spawn(move || {
                    let _ = mesh.accept(sock);
                });
            }
        });
        let (w, h) = (Arc::downgrade(self), Arc::downgrade(&hub));
        std::thread::spawn(move || {
            for sock in guest_ln.incoming() {
                let (Some(l), Some(hub), Ok(sock)) = (w.upgrade(), h.upgrade(), sock) else { return };
                let from = sock.peer_addr().ok().and_then(|a| hub.tunnel_addr(a.port()));
                drop(hub);
                let Some(from) = from.filter(crate::hub::is_guest) else { continue };
                std::thread::spawn(move || l.serve_guest(sock, from));
            }
        });
        self.logf(&format!("cbb: the hub serves on UDP port {}", hub.udp_port()));
        let pins = away.hub_forwarder_pins().unwrap_or_default();
        let w = Arc::downgrade(self);
        let credential: crate::forward::CredentialFn =
            Arc::new(move || w.upgrade().and_then(|l| pins.iter().find_map(|p| l.mesh.hub_credential(p))));
        let (registration, report) = match away.hub_registration(hub.sender(), credential).transpose()? {
            Some((r, report)) => (Some(r), Some(report)),
            None => (None, None),
        };
        Ok(HubRun { _registration: registration, started: started(away), report, hub })
    }
}
