// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! A hub's offer on the records of 0.6: field 6 of the `result` that
//! answers this device's `tunnel` (t 15), table `offer` of the format
//! (`cbb_core::msg::tables::OFFER`), read into the hub as `tunnel.json`
//! keeps it (docs/protocol.md, section 11).
//!
//! - The way over VLESS goes to the offer's forwarder endpoint: the first
//!   endpoint that has a key of its own (field 9), else the first. Its port
//!   is `vless/port` when there is one; `vless/host` is the site's name of
//!   TLS and HTTP, the endpoint's host when absent. XHTTP always.
//! - Obfuscation without `obfuscation/key` protects no headers.
//! - The next key keeps the same obfuscation and VLESS.

use std::net::SocketAddr;

use cbb_core::format::cbor::Value;
use cbb_core::records::key::DeviceId;

use super::Away;
use crate::error::{Error, Result};
use crate::tunnel::{Face, Hub};

/// An offer as read: the hub, the tag of the pre-shared key it holds
/// newest, and whether the hub moved to another device.
#[derive(Debug)]
pub struct Offer {
    pub hub: Hub,
    pub confirm: Option<[u8; 32]>,
    pub moved: bool,
}

/// The X25519 key of a field, not all zeros.
fn wg_key(v: &Value<'_>) -> Result<Vec<u8>> {
    let k = cbb_core::format::Key::from_value(v).map_err(|_| Error::msg("the hub's offer has a bad key"))?;
    if k.alg != cbb_core::format::Alg::X25519 || k.public.len() != 32 || k.public.iter().all(|&b| b == 0) {
        return Err(Error::msg("the hub's offer has a bad key"));
    }
    Ok(k.public.to_vec())
}

fn endpoint(v: &Value<'_>) -> Result<SocketAddr> {
    v.as_text()
        .and_then(|t| t.parse::<SocketAddr>().ok())
        .filter(|a| a.port() != 0)
        .ok_or_else(|| Error::msg("the hub's offer has a bad address"))
}

/// A VLESS user ID as text, as the tunnel's settings carry it.
fn user_id(b: &[u8; 16]) -> String {
    let h = cbb_core::certs::hex(b);
    format!("{}-{}-{}-{}-{}", &h[..8], &h[8..12], &h[12..16], &h[16..20], &h[20..])
}

/// Reads the offer `v` (already checked against its table) of the hub
/// `hub`.
pub fn read(hub: &DeviceId, v: &Value<'_>) -> Result<Offer> {
    let key = wg_key(v.get(1).ok_or_else(|| Error::msg("the hub's offer has no key"))?)?;
    let endpoints = match v.get(2) {
        None => Vec::new(),
        Some(e) => e
            .as_array()
            .ok_or_else(|| Error::msg("the hub's offer has a bad address"))?
            .iter()
            .map(endpoint)
            .collect::<Result<Vec<_>>>()?,
    };
    if endpoints.len() > crate::tunnel::MAX_ENDPOINTS {
        return Err(Error::msg("the hub's offer has too many addresses"));
    }
    let faces = match v.get(9) {
        None => Vec::new(),
        Some(f) => f
            .as_array()
            .ok_or_else(|| Error::msg("the hub's offer has a bad endpoint key"))?
            .iter()
            .map(|f| {
                let at = endpoint(f.get(1).ok_or_else(|| Error::msg("the hub's offer has a bad endpoint key"))?)?;
                let key = wg_key(f.get(2).ok_or_else(|| Error::msg("the hub's offer has a bad endpoint key"))?)?;
                Ok(Face { endpoint: at, key })
            })
            .collect::<Result<Vec<_>>>()?,
    };
    if faces.iter().any(|f| !endpoints.contains(&f.endpoint)) {
        return Err(Error::msg("the hub's offer has a key for an endpoint it does not name"));
    }
    let obfuscation = v.get(3).map(crate::awg::Obfuscation::from_cbor).transpose()?.map(|o| o.to_value());
    let vless = match v.get(4) {
        None => None,
        Some(x) => {
            let at =
                faces.first().map(|f| f.endpoint).or_else(|| endpoints.first().copied()).ok_or_else(|| {
                    Error::msg("the hub's offer has a way over VLESS without the forwarder's endpoint")
                })?;
            Some(vless(at, x)?)
        }
    };
    let next = v.get(7).map(wg_key).transpose()?.unwrap_or_default();
    let confirm = v.get(8).and_then(Value::as_bytes).and_then(|b| <[u8; 32]>::try_from(b).ok());
    let hub = Hub {
        device: cbb_core::certs::hex(&hub.0),
        key,
        psk: Vec::new(),
        endpoints,
        next,
        obfuscation,
        vless,
        next_obfuscation: None,
        next_vless: None,
        faces,
    };
    Ok(Offer { hub, confirm, moved: v.get(6).is_some() })
}

/// The tunnel's VLESS settings for the offer's `vless` and the forwarder's
/// endpoint at.
fn vless(at: SocketAddr, v: &Value<'_>) -> Result<serde_json::Value> {
    let bad = || Error::msg("the hub's VLESS settings do not read");
    let id: [u8; 16] = v.get(1).and_then(Value::as_bytes).and_then(|b| b.try_into().ok()).ok_or_else(bad)?;
    let port = match v.get(2) {
        None => at.port(),
        Some(p) => p.as_uint().and_then(|p| u16::try_from(p).ok()).filter(|&p| p != 0).ok_or_else(bad)?,
    };
    let host = match v.get(3) {
        None => at.ip().to_string(),
        Some(h) => h.as_text().ok_or_else(bad)?.to_string(),
    };
    let mut m = serde_json::Map::new();
    m.insert("transport".into(), "xhttp".into());
    m.insert("endpoint".into(), SocketAddr::new(at.ip(), port).to_string().into());
    m.insert("server_name".into(), host.into());
    if let Some(p) = v.get(4) {
        m.insert("path".into(), p.as_text().ok_or_else(bad)?.into());
    }
    m.insert("id".into(), user_id(&id).into());
    let s = serde_json::Value::Object(m);
    crate::vless::check_offer(&s)?;
    Ok(s)
}

impl Away {
    /// Takes the offer `v` of the hub `hub`, the answer to this device's
    /// `tunnel`: its tag confirms the pre-shared key the hub holds newest,
    /// and the hub is kept as the offer gives it, or forgotten when it
    /// moved to another device. Whether what is kept changed; false while
    /// sync away from home is off.
    pub fn take_offer(&self, hub: &DeviceId, v: &Value<'_>) -> Result<bool> {
        let offer = read(hub, v)?;
        if let Some(c) = &offer.confirm
            && !self.confirmed_by(hub, c)?
        {
            (self.log)(&format!(
                "cbb: the offer of hub {} confirms no key this device sent it",
                cbb_core::certs::hex(&hub.0[..4])
            ));
        }
        let mut cur = self.st.lock().unwrap();
        let Some(st) = cur.as_mut() else { return Ok(false) };
        let name = offer.hub.device.clone();
        let mut next = st.clone();
        next.hubs.retain(|h| h.device != name);
        if !offer.moved {
            next.hubs.push(offer.hub);
        }
        if next.hubs == st.hubs {
            return Ok(false);
        }
        next.save(&self.dir)?;
        *st = next;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use cbb_core::format::cbor::Value as V;

    use super::*;

    const ID: [u8; 16] =
        [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x47, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00];

    fn key(b: &[u8; 32]) -> V<'_> {
        V::Array(vec![V::Uint(cbb_core::format::Alg::X25519.number()), V::Bytes(b)])
    }

    /// An offer with every field reads into the hub as tunnel.json keeps
    /// it: the forwarder's endpoint with its own key carries VLESS on the
    /// offer's port and host; obfuscation without its key protects no
    /// headers; the next key alone.
    #[test]
    fn an_offer_reads_into_the_hub() {
        let (k, n, f, c) = ([1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]);
        let s = [V::Uint(20), V::Uint(33), V::Uint(17), V::Uint(25)];
        let h = [(5u64, 9u64), (10, 19), (20, 29), (30, 39)].map(|(a, b)| V::Array(vec![V::Uint(a), V::Uint(b)]));
        let offer = V::Map(vec![
            (1, key(&k)),
            (2, V::Array(vec![V::Text("192.0.2.1:51820"), V::Text("203.0.113.5:8443")])),
            (
                3,
                V::Map(vec![
                    (1, V::Uint(3)),
                    (2, V::Uint(40)),
                    (3, V::Uint(140)),
                    (4, V::Array(s.to_vec())),
                    (5, V::Array(h.to_vec())),
                ]),
            ),
            (
                4,
                V::Map(vec![
                    (1, V::Bytes(&ID)),
                    (2, V::Uint(443)),
                    (3, V::Text("www.example.com")),
                    (4, V::Text("/AbC-12_xyz0123456")),
                ]),
            ),
            (7, key(&n)),
            (8, V::Bytes(&c)),
            (9, V::Array(vec![V::Map(vec![(1, V::Text("203.0.113.5:8443")), (2, key(&f))])])),
        ]);
        assert_eq!(
            cbb_core::msg::check(
                &V::Map(vec![
                    (0, V::Uint(10)),
                    (2, V::Bytes(&[0; 16])),
                    (3, V::Bytes(&[9; 16])),
                    (4, V::Uint(1)),
                    (6, offer.clone())
                ])
                .encode()
            ),
            Ok(10),
            "the offer fits its table"
        );
        let o = read(&DeviceId([9; 16]), &offer).unwrap();
        assert_eq!(o.confirm, Some(c));
        assert!(!o.moved);
        let hub = o.hub;
        assert_eq!(hub.device, "09".repeat(16));
        assert_eq!(hub.key, k.to_vec());
        assert_eq!(hub.next, n.to_vec());
        assert!(hub.psk.is_empty(), "the pre-shared key is never sent");
        let fw: SocketAddr = "203.0.113.5:8443".parse().unwrap();
        assert_eq!(hub.key_at(&fw), &f);
        assert_eq!(hub.key_at(&"192.0.2.1:51820".parse().unwrap()), &k);
        let vl = hub.vless.as_ref().unwrap();
        assert_eq!(vl["endpoint"], "203.0.113.5:443");
        assert_eq!(vl["server_name"], "www.example.com");
        assert_eq!(vl["transport"], "xhttp");
        assert_eq!(vl["id"], "11223344-5566-4788-99aa-bbccddeeff00");
        let ob = crate::awg::Obfuscation::from_offer(hub.obfuscation.as_ref().unwrap()).unwrap();
        assert_eq!(ob.header_key, None, "no key, no header protection");
        assert_eq!(ob.s, [20, 33, 17, 25]);
        assert!(hub.next_obfuscation.is_none() && hub.next_vless.is_none(), "the next key keeps them");
    }

    /// A key of zeros, an endpoint key for an endpoint the offer does not
    /// name, and VLESS with no endpoint are refused.
    #[test]
    fn a_bad_offer_is_refused() {
        let zero = [0u8; 32];
        let k = [1u8; 32];
        assert!(read(&DeviceId([9; 16]), &V::Map(vec![(1, key(&zero))])).is_err());
        let stray = V::Map(vec![
            (1, key(&k)),
            (2, V::Array(vec![V::Text("192.0.2.1:51820")])),
            (9, V::Array(vec![V::Map(vec![(1, V::Text("192.0.2.2:51820")), (2, key(&k))])])),
        ]);
        assert!(read(&DeviceId([9; 16]), &stray).is_err());
        let lone = V::Map(vec![(1, key(&k)), (4, V::Map(vec![(1, V::Bytes(&ID))]))]);
        assert!(read(&DeviceId([9; 16]), &lone).is_err());
    }

    /// The offer is kept per hub and replaces the hub's earlier one; one
    /// that says the hub moved forgets it; nothing while away is off.
    #[test]
    fn the_offer_is_kept_until_the_hub_moves() {
        let dir = std::env::temp_dir().join(format!("cbb-away-offer-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let me = crate::certs::DeviceId::parse(&"d".repeat(32)).unwrap();
        let away = Away::new(dir.clone(), "g".into(), me, Arc::new(|_: &str| {}));
        let hub = DeviceId([9; 16]);
        let offer = |k: &'static [u8; 32]| V::Map(vec![(1, key(k)), (2, V::Array(vec![V::Text("192.0.2.1:51820")]))]);
        static K1: [u8; 32] = [1; 32];
        static K2: [u8; 32] = [2; 32];
        assert!(!away.take_offer(&hub, &offer(&K1)).unwrap(), "off");
        away.turn_on().unwrap();
        assert!(away.take_offer(&hub, &offer(&K1)).unwrap());
        assert!(!away.take_offer(&hub, &offer(&K1)).unwrap(), "the same again");
        assert!(away.take_offer(&hub, &offer(&K2)).unwrap());
        let kept = away.st.lock().unwrap().as_ref().unwrap().hubs.clone();
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].key, K2.to_vec());
        let moved = V::Map(vec![(1, key(&K2)), (6, V::Uint(1))]);
        assert!(away.take_offer(&hub, &moved).unwrap());
        assert!(away.st.lock().unwrap().as_ref().unwrap().hubs.is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
