// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The device's side of the tunnel's keys toward a hub on the records of
//! 0.6 (`cbb_core::hubkey`, A-22): its WireGuard key toward each hub, from
//! its tunnel secret and the hub's ID, and the pre-shared keys of its
//! member connections with that hub, which it sends `tunnel` (t 15) to
//! confirm and keeps in `tunnel.json` (`toward`).

use cbb_core::format::frame;
use cbb_core::hubkey::{self, Psk};
use cbb_core::records::key::DeviceId;

use super::Away;
use crate::error::{Error, Result};

impl Away {
    /// A member connection with the hub `hub` gave the pre-shared key
    /// `psk`: it is kept beside the earlier ones, and the frame of message
    /// `tunnel` to send that hub, with this device's key toward it and the
    /// key's tag. None while sync away from home is off here.
    pub fn tunnel_to(&self, hub: &DeviceId, psk: Psk) -> Result<Option<Vec<u8>>> {
        let mut cur = self.st.lock().unwrap();
        let Some(st) = cur.as_mut() else { return Ok(None) };
        let secret = st.private_key()?;
        let (_, public) = hubkey::key_for(&secret, &cbb_core::format::DeviceId(hub.0));
        let name = cbb_core::certs::hex(&hub.0);
        let mut next = st.clone();
        let mut side = next.toward.get(&name).map(crate::tunnel::Toward::side).unwrap_or_default();
        let confirm = side.connected(psk);
        next.toward.insert(name, crate::tunnel::Toward::of(&side));
        next.save(&self.dir)?;
        *st = next;
        let msg = hubkey::message(&public, &confirm);
        let v =
            cbb_core::format::cbor::decode(&msg).map_err(|r| Error::msg(format!("the tunnel message breaks {r}")))?;
        Ok(Some(frame::write(&v)))
    }

    /// The hub's offer came back with the tag `confirm`: the key of that
    /// tag is the newest the hub holds, and is tried first. False when the
    /// tag is none of the keys sent to that hub.
    pub fn confirmed_by(&self, hub: &DeviceId, confirm: &[u8; 32]) -> Result<bool> {
        let mut cur = self.st.lock().unwrap();
        let Some(st) = cur.as_mut() else { return Ok(false) };
        let name = cbb_core::certs::hex(&hub.0);
        let mut side = st.toward.get(&name).map(crate::tunnel::Toward::side).unwrap_or_default();
        if !side.confirmed(confirm) {
            return Ok(false);
        }
        let mut next = st.clone();
        next.toward.insert(name, crate::tunnel::Toward::of(&side));
        next.save(&self.dir)?;
        *st = next;
        Ok(true)
    }

    /// The pre-shared keys to try toward the hub, in order
    /// (`DeviceSide::to_try`); none before a `tunnel` went to it.
    pub fn keys_toward(&self, hub: &DeviceId) -> Vec<[u8; 32]> {
        let cur = self.st.lock().unwrap();
        let name = cbb_core::certs::hex(&hub.0);
        cur.as_ref().and_then(|st| st.toward.get(&name)).map(|t| t.side().to_try()).unwrap_or_default()
    }
}

impl Away {
    /// The hubs whose offers are kept, in the order kept; none while sync
    /// away from home is off.
    pub fn hubs_kept(&self) -> Vec<crate::tunnel::Hub> {
        self.st.lock().unwrap().as_ref().map(|st| st.hubs.clone()).unwrap_or_default()
    }

    /// This device's private key toward the hub (`hubkey::key_for`).
    pub fn secret_toward(&self, hub: &DeviceId) -> Option<[u8; 32]> {
        let cur = self.st.lock().unwrap();
        let secret = cur.as_ref()?.private_key().ok()?;
        Some(hubkey::key_for(&secret, &cbb_core::format::DeviceId(hub.0)).0)
    }

    /// A tunnel handshake with the hub answered under the pre-shared key
    /// psk, which is tried right after the confirmed one from now on.
    pub fn handshaked(&self, hub: &DeviceId, psk: &[u8; 32]) -> Result<()> {
        let mut cur = self.st.lock().unwrap();
        let Some(st) = cur.as_mut() else { return Ok(()) };
        let name = cbb_core::certs::hex(&hub.0);
        let mut side = st.toward.get(&name).map(crate::tunnel::Toward::side).unwrap_or_default();
        side.handshake(psk);
        let mut next = st.clone();
        next.toward.insert(name, crate::tunnel::Toward::of(&side));
        if next.toward == st.toward {
            return Ok(());
        }
        next.save(&self.dir)?;
        *st = next;
        Ok(())
    }

    /// Where the tunnel sends its packets in place of the hubs' addresses
    /// (tests), if anywhere.
    pub fn tunnel_via(&self) -> Option<std::net::SocketAddr> {
        self.via
    }

    /// The member connection through the tunnel to the hub is being made
    /// or is up (Some), or ended (None), for cbb global.
    pub fn set_through(&self, hub: Option<&str>) {
        self.through.store(hub.is_some(), std::sync::atomic::Ordering::SeqCst);
        *self.using.lock().unwrap() = hub.map(|h| (h.to_string(), 0));
    }

    /// What went wrong reaching a hub, for cbb global and the log; None
    /// clears it.
    pub fn failed(&self, e: Option<&Error>) {
        match e {
            Some(e) => self.fail(e),
            None => *self.error.lock().unwrap() = None,
        }
    }

    /// What cbb global shows of sync away from home on the records of
    /// 0.6: off, or on with the hubs whose offers are kept, the first of
    /// them shown, and what went wrong last.
    pub fn live_status(&self) -> Option<crate::control::Away> {
        self.live_status_as(false, &[])
    }

    /// live_status, for a hub that stands by (`standby`) as a client of the
    /// hub above it, which it shows as the hub it uses; `order` is the
    /// group's hubs (IDs in hex) as `shown_hub` takes them.
    pub fn live_status_as(&self, standby: bool, order: &[String]) -> Option<crate::control::Away> {
        let st = self.st.lock().unwrap();
        let error = self.error.lock().unwrap().clone();
        let Some(st) = st.as_ref() else {
            return error.map(|(e, d)| crate::control::Away { error: e, detail: d, ..Default::default() });
        };
        let allow = st.destinations().iter().map(ToString::to_string).collect();
        let mut a = crate::control::Away { keys_in_file: true, allow, hub: st.is_hub, ..Default::default() };
        if st.is_hub {
            a.endpoints = st.hub_endpoints().iter().map(ToString::to_string).collect();
            a.clients = i64::try_from(st.held.len()).unwrap_or(i64::MAX);
            a.port = i64::from(if st.listen_port == 0 { crate::tunnel::MEMBER_PORT } else { st.listen_port });
            a.obfuscated = st.obfuscation.is_some();
        }
        let using = self.using.lock().unwrap().as_ref().map(|(d, _)| d.clone());
        if let Some(h) = shown_hub(&st.hubs, using.as_deref(), order).filter(|_| !st.is_hub || standby) {
            a.through = self.through.load(std::sync::atomic::Ordering::SeqCst) && using.is_some();
            a.hub_device = h.device.clone();
            // A hub that stands by keeps showing its own way in.
            if !st.is_hub {
                a.endpoints = h.endpoints.iter().map(ToString::to_string).collect();
                a.obfuscated = h.obfuscation.is_some();
                a.vless = h.vless.is_some();
            }
        }
        if let Some((e, d)) = error {
            (a.error, a.detail) = (e, d);
        }
        Some(a)
    }
}

/// The hub a client's status names: the one its tunnel is using, else the
/// first of `order` it keeps an offer of (the caller puts the hubs this
/// member is connected to first, each part in the group's order of hubs),
/// else the first offer it keeps.
fn shown_hub<'a>(
    hubs: &'a [crate::tunnel::Hub],
    using: Option<&str>,
    order: &[String],
) -> Option<&'a crate::tunnel::Hub> {
    let kept = |d: &str| hubs.iter().find(|h| h.device == d);
    using.and_then(kept).or_else(|| order.iter().find_map(|d| kept(d))).or(hubs.first())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    /// The status names the hub in use, else the first hub of the order
    /// with an offer here, not the first offer kept.
    #[test]
    fn the_status_names_the_hub_by_the_order() {
        let hub = |d: &str| crate::tunnel::Hub { device: d.into(), ..Default::default() };
        let hubs = [hub("mac"), hub("pi")];
        let order = |o: &[&str]| o.iter().map(|d| d.to_string()).collect::<Vec<_>>();
        assert_eq!(shown_hub(&hubs, None, &order(&["pi", "mac"])).unwrap().device, "pi");
        assert_eq!(shown_hub(&hubs, Some("mac"), &order(&["pi", "mac"])).unwrap().device, "mac", "the one in use");
        assert_eq!(shown_hub(&hubs, None, &order(&["deck", "mac"])).unwrap().device, "mac", "one with an offer");
        assert_eq!(shown_hub(&hubs, None, &[]).unwrap().device, "mac", "no order: the first kept");
        assert!(shown_hub(&[], None, &order(&["pi"])).is_none());
    }

    fn psk(n: u8) -> Psk {
        Psk { key: [n; 32], confirm: [n + 100; 32] }
    }

    /// Each connection's key goes in `tunnel` with its tag and is kept
    /// across a restart; the tag the hub confirms makes its key the first
    /// to try; a tag of no key sent changes nothing; nothing goes while
    /// sync away from home is off.
    #[test]
    fn the_keys_toward_a_hub() {
        let dir = std::env::temp_dir().join(format!("cbb-away-toward-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let me = crate::certs::DeviceId::parse(&"d".repeat(32)).unwrap();
        let away = Away::new(dir.clone(), "g".into(), me.clone(), Arc::new(|_: &str| {}));
        let hub = DeviceId([7; 16]);
        assert!(away.tunnel_to(&hub, psk(1)).unwrap().is_none(), "off");
        away.turn_on().unwrap();
        let f = away.tunnel_to(&hub, psk(1)).unwrap().unwrap();
        let msg = frame::read(&f, frame::LIMIT_MEMBER).unwrap();
        let (key, confirm) = hubkey::read(&msg.map.encode()).unwrap();
        assert_eq!(confirm, psk(1).confirm);
        let secret = away.st.lock().unwrap().as_ref().unwrap().private_key().unwrap();
        assert_eq!(key, hubkey::key_for(&secret, &cbb_core::format::DeviceId(hub.0)).1);
        let other = hubkey::key_for(&secret, &cbb_core::format::DeviceId([8; 16])).1;
        assert_ne!(key, other, "a key of its own toward every hub");
        away.tunnel_to(&hub, psk(2)).unwrap();
        assert_eq!(away.keys_toward(&hub), vec![[2; 32], [1; 32]]);
        assert!(!away.confirmed_by(&hub, &[9; 32]).unwrap());
        assert!(away.confirmed_by(&hub, &psk(1).confirm).unwrap());
        assert_eq!(away.keys_toward(&hub), vec![[1; 32], [2; 32]], "the confirmed key first");
        // Kept across a restart.
        let again = Away::new(dir.clone(), "g".into(), me, Arc::new(|_: &str| {}));
        assert_eq!(again.keys_toward(&hub), vec![[1; 32], [2; 32]]);
        assert!(again.keys_toward(&DeviceId([8; 16])).is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
