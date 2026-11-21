// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The hub's side of the tunnel's keys on the records of 0.6
//! (`cbb_core::hubkey`, A-22): each client's WireGuard key toward this hub
//! and the pre-shared keys of its member connections with the hub, which
//! the client confirms in `tunnel` (t 15); the hub keeps them in
//! `tunnel.json` (`held`), answers with its offer (field 6 of a `result`)
//! and serves each client under every key it holds.

use cbb_core::format::cbor::Value;
use cbb_core::hubkey::{self, Psk};
use cbb_core::records::DeviceId;

use super::Away;
use crate::error::{Error, Result};
use crate::tunnel::Held;

impl Away {
    /// The client from sent `tunnel` with its key toward this hub and the
    /// tag confirm over a connection whose pre-shared key is psk: when the
    /// tag matches, the key is kept beside the ones held and the tag comes
    /// back for the offer. None while this device is no hub, or for a tag of
    /// another key. A key that another client or the hub itself holds is
    /// refused.
    pub fn tunnel_from(
        &self,
        from: &DeviceId,
        key: [u8; 32],
        confirm: &[u8; 32],
        psk: Psk,
    ) -> Result<Option<[u8; 32]>> {
        let mut cur = self.st.lock().unwrap();
        let Some(st) = cur.as_mut().filter(|s| s.is_hub && !self.moving.load(std::sync::atomic::Ordering::SeqCst))
        else {
            return Ok(None);
        };
        let name = cbb_core::certs::hex(&from.0);
        if st.own_key(&key) || st.held.iter().any(|(d, h)| *d != name && h.key == key) {
            return Err(Error::msg(format!("{name} sent a tunnel key that another device or this hub holds")));
        }
        let mut side = match st.held.get(&name) {
            // A new key toward this hub starts afresh.
            Some(h) if h.key == key => h.side(),
            _ => hubkey::HubSide::default(),
        };
        let Some(tag) = side.tunnel(psk, confirm) else { return Ok(None) };
        let mut next = st.clone();
        next.held.insert(name, Held::of(key, &side));
        if next.held != st.held {
            next.save(&self.dir)?;
            *st = next;
        }
        Ok(Some(tag))
    }

    /// A handshake from the client whose key is key answered under psk: the
    /// hub keeps it among the last handshakes' keys.
    pub fn hub_handshaked(&self, key: &[u8; 32], psk: &[u8; 32]) -> Result<()> {
        let mut cur = self.st.lock().unwrap();
        let Some(st) = cur.as_mut() else { return Ok(()) };
        let Some((name, held)) = st.held.iter().find(|(_, h)| h.key == key) else { return Ok(()) };
        let mut side = held.side();
        side.handshake(psk);
        let (name, kept) = (name.clone(), Held::of(*key, &side));
        if st.held.get(&name) == Some(&kept) {
            return Ok(());
        }
        let mut next = st.clone();
        next.held.insert(name, kept);
        next.save(&self.dir)?;
        *st = next;
        Ok(())
    }

    /// The clients the hub's tunnel serves on the records of 0.6: each with
    /// its key and every pre-shared key held for it, the newest first, at
    /// its tunnel address. Devices that `keep` says no longer belong (not
    /// current members) are left out.
    pub fn held_peers(&self, keep: &dyn Fn(&DeviceId) -> bool) -> Vec<crate::hub::Peer> {
        let cur = self.st.lock().unwrap();
        let Some(st) = cur.as_ref() else { return Vec::new() };
        st.held
            .iter()
            .filter_map(|(name, h)| {
                let id = crate::live::id_of_hex(name)?;
                if !keep(&id) {
                    return None;
                }
                let mut psks = h.side().accepts().into_iter();
                let psk = psks.next()?;
                Some(crate::hub::Peer {
                    key: crate::tunnel::key32(&h.key).ok()?,
                    psk,
                    older_psks: psks.take(crate::hub::MAX_PSKS - 1).collect(),
                    addr: crate::tunnel::addr(name)?,
                    until: None,
                    source: None,
                })
            })
            .collect()
    }

    /// What the hub's tunnel starts with while this device is a hub: the
    /// key it serves under, the group's AmneziaWG settings, and its UDP
    /// port (0 for the member port).
    pub fn hub_settings(&self) -> Option<([u8; 32], Option<serde_json::Value>, u16)> {
        let cur = self.st.lock().unwrap();
        let st = cur.as_ref().filter(|s| s.is_hub)?;
        Some((st.serving_key().ok()?, st.obfuscation.clone(), st.listen_port))
    }

    /// The pins the hub's forwarder's key may have, while this device is a
    /// hub with a forwarder: the project's, or the one it was given.
    pub fn hub_forwarder_pins(&self) -> Option<Vec<[u8; 32]>> {
        let cur = self.st.lock().unwrap();
        let f = cur.as_ref().filter(|s| s.is_hub)?.forwarder.as_ref()?;
        let pins: Result<Vec<[u8; 32]>> = if f.project {
            super::serve::PROJECT_PINS.iter().map(|p| super::serve::pin_bytes(p)).collect()
        } else {
            super::serve::pin_bytes(&f.pin).map(|p| vec![p])
        };
        pins.ok()
    }

    /// Starts the hub's registration with its forwarder on the records of
    /// 0.6, its datagrams going out by send and the hubs' credential of the
    /// forwarder's face asked of credential; None without a forwarder.
    pub fn hub_registration(
        &self,
        send: crate::forward::SendFn,
        credential: crate::forward::CredentialFn,
    ) -> Option<Result<(crate::forward::Registration, std::sync::Arc<std::sync::Mutex<crate::forward::Report>>)>> {
        let pins = self.hub_forwarder_pins()?;
        let cur = self.st.lock().unwrap();
        let st = cur.as_ref()?;
        let f = st.forwarder.as_ref()?;
        let wg_key = match st.serving_key() {
            Ok(k) => k,
            Err(e) => return Some(Err(e)),
        };
        let cfg = crate::forward::Config {
            endpoint: f.endpoint,
            pins: pins.clone(),
            wg_key,
            obfuscation: st.obfuscation.clone(),
            vless_id: Some(f.vless_id.clone()).filter(|id| !id.is_empty()),
            send,
            credential: Some(credential),
            ways: Default::default(),
            learned: Default::default(),
        };
        drop(cur);
        let report = std::sync::Arc::new(std::sync::Mutex::new(crate::forward::Report::default()));
        let r = crate::forward::Registration::start(cfg, report.clone(), self.log.clone());
        *self.hub_report.lock().unwrap() = Some(report.clone());
        Some(Ok((r, report)))
    }

    /// The hub of 0.6 stopped serving: its forwarder leaves its status.
    pub fn hub_stopped(&self) {
        self.hub_report.lock().unwrap().take();
    }

    /// The hub of 0.6's forwarder for its status, entries_held telling
    /// whether this device holds signed entry points that have not
    /// expired; None on a device that is no hub or has no forwarder.
    pub fn live_forwarder(&self, entries_held: bool) -> Option<crate::control::Forwarder> {
        let (endpoint, project) = {
            let cur = self.st.lock().unwrap();
            let f = cur.as_ref().filter(|s| s.is_hub)?.forwarder.as_ref()?;
            (f.endpoint.to_string(), f.project)
        };
        let report = self.hub_report.lock().unwrap().clone();
        let Some(r) = report.and_then(|r| r.lock().ok().map(|r| r.clone())) else {
            return Some(crate::control::Forwarder { endpoint, ..Default::default() });
        };
        let detail = r.error.unwrap_or_default();
        Some(crate::control::Forwarder {
            endpoint,
            registered: r.registered,
            seen: r.seen.unwrap_or_default(),
            error: super::serve::forwarder_problem(&detail),
            entries_stale: super::serve::entries_stale(project, !detail.is_empty(), entries_held),
            detail,
        })
    }

    /// Keeps the VLESS settings the forwarder's answer gave (report), or
    /// forgets the VLESS user ID of a forwarder that registered the hub
    /// without VLESS. Whether the offer changed, so the clients take it
    /// again.
    pub fn hub_learned(&self, report: &crate::forward::Report) -> bool {
        let mut cur = self.st.lock().unwrap();
        let Some(st) = cur.as_mut() else { return false };
        let Some(f) = st.forwarder.as_ref().filter(|f| !f.vless_id.is_empty()) else { return false };
        let vless = match (&report.vless, report.registered) {
            (Some(v), _) if f.vless.as_ref() != Some(v) => Some(v.clone()),
            (None, true) => None,
            _ => return false,
        };
        let mut next = st.clone();
        if let Some(f) = next.forwarder.as_mut() {
            match &vless {
                Some(v) => f.vless = Some(v.clone()),
                None => (f.vless_id, f.vless) = (String::new(), None),
            }
        }
        if let Err(e) = next.save(&self.dir) {
            (self.log)(&format!("cbb: saving the tunnel state: {}", e.for_log()));
            return false;
        }
        *st = next;
        (self.log)(&match vless {
            Some(_) => "cbb: sync away from home: the hub's clients come over VLESS to its forwarder".to_string(),
            None => "cbb: sync away from home: the forwarder has no VLESS, so the hub's clients come over UDP alone"
                .to_string(),
        });
        true
    }

    /// The devices the hub holds keys of, by their IDs.
    pub fn held_devices(&self) -> Vec<DeviceId> {
        let cur = self.st.lock().unwrap();
        cur.as_ref().map(|st| st.held.keys().filter_map(|n| crate::live::id_of_hex(n)).collect()).unwrap_or_default()
    }

    /// The hub's offer as the format's table `offer` encodes it, confirming
    /// the tag confirm; None while this device is no hub or its offer waits
    /// for the forwarder's VLESS settings. The forwarder's endpoint comes
    /// with the key the hub serves there (field 9), so that a client knows
    /// it as the forwarder's.
    pub fn offer_encoding(&self, confirm: &[u8; 32]) -> Option<Vec<u8>> {
        let cur = self.st.lock().unwrap();
        let st = cur.as_ref().filter(|s| s.is_hub)?;
        if st.forwarder.as_ref().is_some_and(|f| !f.vless_id.is_empty() && f.vless.is_none()) {
            return None;
        }
        let hub_key = crate::tunnel::public_key_of(&st.serving_key().ok()?);
        let endpoints: Vec<String> = st.hub_endpoints().iter().map(ToString::to_string).collect();
        let fw = st.forwarder.as_ref().map(|f| f.endpoint.to_string());
        let obfuscation = st.obfuscation.as_ref().and_then(|o| crate::awg::Obfuscation::from_offer(o).ok());
        let obf_cbor = obfuscation.as_ref().map(crate::awg::Obfuscation::to_cbor);
        let vless = st.forwarder.as_ref().filter(|f| !f.vless_id.is_empty()).and_then(|f| f.vless.clone());
        let vless_parts = vless.as_ref().and_then(vless_parts);
        let next = st.next_public();
        let mut m: Vec<(u16, Value<'_>)> = vec![(1, key_value(&hub_key))];
        if !endpoints.is_empty() {
            m.push((2, Value::Array(endpoints.iter().map(|e| Value::Text(e)).collect())));
        }
        if let Some(o) = &obf_cbor {
            m.push((3, cbb_core::format::cbor::decode(o).ok()?));
        }
        if let Some((id, port, host, path)) = &vless_parts {
            let mut v = vec![(1, Value::Bytes(id)), (2, Value::Uint(u64::from(*port))), (3, Value::Text(host))];
            if let Some(p) = path {
                v.push((4, Value::Text(p)));
            }
            m.push((4, Value::Map(v)));
        }
        if next.len() == 32 {
            m.push((7, key_value(&next)));
        }
        m.push((8, Value::Bytes(confirm)));
        if let Some(f) = &fw {
            m.push((9, Value::Array(vec![Value::Map(vec![(1, Value::Text(f)), (2, key_value(&hub_key))])])));
        }
        let v = Value::Map(m);
        let b = v.encode();
        cbb_core::msg::read_map(&cbb_core::msg::tables::OFFER, &v).ok()?;
        Some(b)
    }
}

fn key_value(k: &[u8]) -> Value<'_> {
    cbb_core::format::Key::new(cbb_core::format::Alg::X25519, k).to_value()
}

/// The parts of the tunnel's VLESS settings that the offer carries: the user
/// ID, the web server's port, the site's name and the path.
fn vless_parts(v: &serde_json::Value) -> Option<([u8; 16], u16, String, Option<String>)> {
    let id = cbb_core::vless::parse_id(v.get("id")?.as_str()?).ok()?;
    let port = v.get("endpoint")?.as_str()?.parse::<std::net::SocketAddr>().ok()?.port();
    let host = v.get("server_name")?.as_str()?.to_string();
    let path = v.get("path").and_then(|p| p.as_str()).map(str::to_string);
    Some((id, port, host, path))
}

/// The `result` that answers a client's `tunnel` with the hub's offer: its ID
/// from the tag (`hubkey::offer_id`), the hub, done, and the offer.
pub fn offer_result(hub: &DeviceId, confirm: &[u8; 32], offer: &[u8]) -> Result<Vec<u8>> {
    let offer = cbb_core::format::cbor::decode(offer).map_err(|r| Error::msg(format!("the hub's offer breaks {r}")))?;
    let id = hubkey::offer_id(confirm);
    let v = Value::Map(vec![
        (cbb_core::format::frame::FIELD_T, Value::Uint(cbb_core::msg::tables::T_RESULT)),
        (2, Value::Bytes(&id)),
        (3, Value::Bytes(&hub.0)),
        (4, Value::Uint(1)),
        (6, offer),
    ]);
    Ok(cbb_core::format::frame::write(&v))
}
