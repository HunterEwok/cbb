// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Sync away from home on the records of 0.6, the device's side: on each
//! member connection with a device that may be its hub, while sync away
//! from home is on here, this device sends `tunnel` (t 15) with its key
//! toward that hub and the tag of the connection's pre-shared key; the
//! hub's offer comes back in field 6 of a `result` (docs/protocol.md,
//! section 11).

use std::sync::{Arc, Weak};

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

fn id_text4(id: &DeviceId) -> String {
    cbb_core::certs::hex(&id.0[..4])
}
