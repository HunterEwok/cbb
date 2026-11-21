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
    /// What cbb global shows of sync away from home on the records of
    /// 0.6: off, or on with the hubs whose offers are kept, the first of
    /// them shown, and what went wrong last.
    pub fn live_status(&self) -> Option<crate::control::Away> {
        let st = self.st.lock().unwrap();
        let error = self.error.lock().unwrap().clone();
        let Some(st) = st.as_ref() else {
            return error.map(|(e, d)| crate::control::Away { error: e, detail: d, ..Default::default() });
        };
        let allow = st.destinations().iter().map(ToString::to_string).collect();
        let mut a = crate::control::Away { keys_in_file: true, allow, ..Default::default() };
        if let Some(h) = st.hubs.first() {
            a.hub_device = h.device.clone();
            a.endpoints = h.endpoints.iter().map(ToString::to_string).collect();
            a.obfuscated = h.obfuscation.is_some();
            a.vless = h.vless.is_some();
        }
        if let Some((e, d)) = error {
            (a.error, a.detail) = (e, d);
        }
        Some(a)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

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
