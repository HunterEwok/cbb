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

use super::Live;
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
            }
        }));
        let w: Weak<Live> = Arc::downgrade(self);
        self.mesh.on_other(Box::new(move |peer, t, msg| {
            if let Some(l) = w.upgrade()
                && t == cbb_core::msg::tables::T_RESULT
            {
                l.offered(peer, msg);
            }
        }));
        let w: Weak<Live> = Arc::downgrade(self);
        std::thread::spawn(move || reach_hubs(&w));
    }

    /// Sync away from home, once with_away gave it.
    pub fn away(&self) -> Option<&Arc<Away>> {
        self.away.get()
    }

    /// Sends `tunnel` to every device connected that may be a hub: sync
    /// away from home was turned on.
    pub fn tunnel_to_hubs(&self) {
        for peer in self.mesh.connected() {
            self.tunnel_toward(&peer);
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
                self.mesh.send(peer, f);
            }
            Ok(None) => {}
            Err(e) => self.logf(&format!("cbb: the tunnel's key toward hub {}: {}", id_text4(peer), e.for_log())),
        }
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
        let hubs = away.hubs_kept();
        let ids: Vec<DeviceId> = hubs.iter().filter_map(|h| hub_id(&h.device)).collect();
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
    super::of(&crate::certs::DeviceId::parse(device).ok()?)
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

fn id_text4(id: &DeviceId) -> String {
    cbb_core::certs::hex(&id.0[..4])
}
