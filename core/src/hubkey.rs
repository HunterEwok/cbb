// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The tunnel's keys toward a hub (A-22, option (a) of the architecture
//! review): one WireGuard key per hub, and a pre-shared key from the member
//! connection with that hub, switched only when both ends confirmed it.
//!
//! - **The key.** A device derives its WireGuard key toward a hub from its
//!   own tunnel secret (32 random bytes it keeps) and the hub's device ID.
//!   It is stable for that hub and different for every hub, so no two hubs
//!   see one key and a hub cannot link the device to another hub's client.
//!   Its public half goes in `tunnel` (t 15) to that hub only.
//! - **The pre-shared key** is never sent: both ends export it from the TLS
//!   connection with both device IDs in the context (RFC 8446 section 7.5).
//!   That connection's key exchange is X25519MLKEM768, so the tunnel holds
//!   against a later quantum computer as WireGuard's X25519 alone does not.
//!   Each connection gives a new one.
//! - **The switch.** A new pre-shared key is pending on both ends. The
//!   device sends `tunnel` with the new key's confirmation tag; the hub
//!   takes it as pending, keeps its current one too, and answers with the
//!   same tag in its offer. Only then does the device handshake with the new
//!   key; the hub makes it current when a handshake with it succeeds. The
//!   device keeps the one before as a fallback, so a hub that lost its last
//!   switch (restarted from an older state) still lets it in: a switch never
//!   locks a device out away from home. Anything worse is repaired by the
//!   next direct connection, which starts a new switch.
//! - **No client lists between hubs.** Away from home a device uses only
//!   hubs it has met directly; `hubs` carries no clients and no offers.
//!
//! Before 0.6 one key and one pre-shared key went to every hub in the
//! hello, and hubs passed their clients to each other (protocol.md 11).

use alloc::vec::Vec;

use hkdf::Hkdf;
use sha2::Sha256;

use crate::format::{Alg, DeviceId, Rule, Value, cbor};

/// The exporter's label.
pub const EXPORTER_LABEL: &[u8] = b"EXPORTER-cbb-tunnel-v1";
/// HKDF's info for the pre-shared key.
const PSK_INFO: &[u8] = b"cbb tunnel psk v1";
/// HKDF's info for the pre-shared key's confirmation tag.
const CONFIRM_INFO: &[u8] = b"cbb tunnel confirm v1";
/// HKDF's info for the WireGuard key toward a hub, the hub's ID after it.
const KEY_INFO: &[u8] = b"cbb tunnel key v1";
/// The message type of `tunnel`.
pub const T_TUNNEL: u64 = 15;

pub const RULE_TUNNEL: Rule = Rule::field("tunnel/key");
pub const RULE_CONFIRM: Rule = Rule::field("tunnel/confirm");

/// The context of the exporter: the hub's device ID, then the dialing
/// device's.
pub fn context(hub: &DeviceId, device: &DeviceId) -> [u8; 32] {
    let mut c = [0u8; 32];
    c[..16].copy_from_slice(&hub.0);
    c[16..].copy_from_slice(&device.0);
    c
}

fn expand(ikm: &[u8], info: &[&[u8]]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut out = [0u8; 32];
    // 32 bytes is within HKDF-SHA256's limit.
    let _ = hk.expand_multi_info(info, &mut out);
    out
}

/// The pre-shared key and its confirmation tag from the connection's
/// exported secret (32 bytes of [`EXPORTER_LABEL`] with [`context`]).
pub fn psk(exported: &[u8; 32]) -> Psk {
    Psk { key: expand(exported, &[PSK_INFO]), confirm: expand(exported, &[CONFIRM_INFO]) }
}

/// A pre-shared key and the tag both ends send to confirm they hold it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Psk {
    pub key: [u8; 32],
    pub confirm: [u8; 32],
}

/// The device's WireGuard key toward a hub, from its tunnel secret: the
/// private key (clamped by WireGuard) and its public key.
pub fn key_for(secret: &[u8; 32], hub: &DeviceId) -> ([u8; 32], [u8; 32]) {
    let s = x25519_dalek::StaticSecret::from(expand(secret, &[KEY_INFO, &hub.0]));
    let public = x25519_dalek::PublicKey::from(&s);
    (s.to_bytes(), *public.as_bytes())
}

/// The `tunnel` message to a hub, unpadded: field 2 the key (alg 3), field
/// 3 the confirmation tag of this connection's pre-shared key.
pub fn message(public: &[u8; 32], confirm: &[u8; 32]) -> Vec<u8> {
    Value::Map(alloc::vec![
        (0, Value::Uint(T_TUNNEL)),
        (2, Value::Array(alloc::vec![Value::Uint(Alg::X25519.number()), Value::Bytes(public)])),
        (3, Value::Bytes(confirm)),
    ])
    .encode()
}

/// Reads a `tunnel` message: the device's WireGuard key toward this hub and
/// its confirmation tag.
pub fn read(msg: &[u8]) -> Result<([u8; 32], [u8; 32]), Rule> {
    let v = cbor::decode(msg)?;
    if v.get(0).and_then(Value::as_uint) != Some(T_TUNNEL) {
        return Err(RULE_TUNNEL);
    }
    let k = crate::format::Key::from_value(v.get(2).ok_or(RULE_TUNNEL)?).map_err(|_| RULE_TUNNEL)?;
    if k.alg != Alg::X25519 {
        return Err(RULE_TUNNEL);
    }
    let key: [u8; 32] = k.public.try_into().map_err(|_| RULE_TUNNEL)?;
    if key == [0; 32] {
        return Err(RULE_TUNNEL);
    }
    let confirm: [u8; 32] = v.get(3).and_then(Value::as_bytes).and_then(|b| b.try_into().ok()).ok_or(RULE_CONFIRM)?;
    Ok((key, confirm))
}

/// The device's pre-shared keys toward one hub. Kept across restarts.
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct DeviceSide {
    /// The key it handshakes with.
    pub current: Option<[u8; 32]>,
    /// The one before, tried when the current one fails.
    pub previous: Option<[u8; 32]>,
    /// This connection's, until the hub confirms it.
    pub pending: Option<Psk>,
}

impl DeviceSide {
    /// A member connection with the hub gave a new key: it is pending, and
    /// its tag goes in `tunnel`.
    pub fn connected(&mut self, psk: Psk) -> [u8; 32] {
        self.pending = Some(psk);
        psk.confirm
    }

    /// The hub's offer came back with `confirm`: if it is the pending key's
    /// tag, the key becomes current and the current one the fallback.
    /// Returns whether it switched.
    pub fn confirmed(&mut self, confirm: &[u8; 32]) -> bool {
        match self.pending {
            Some(p) if &p.confirm == confirm => {
                self.pending = None;
                if self.current != Some(p.key) {
                    self.previous = self.current;
                    self.current = Some(p.key);
                }
                true
            }
            _ => false,
        }
    }

    /// The keys to try, in order: the current one, then the fallback.
    pub fn to_try(&self) -> Vec<[u8; 32]> {
        self.current.into_iter().chain(self.previous).collect()
    }
}

/// A hub's pre-shared keys for one device. Kept across restarts.
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct HubSide {
    pub current: Option<[u8; 32]>,
    /// Confirmed to the device, not yet used by a handshake.
    pub pending: Option<[u8; 32]>,
}

impl HubSide {
    /// The device sent `tunnel` over a connection whose key is `psk`: if its
    /// tag matches, the key is pending and the hub confirms it with that
    /// tag in its offer; the current key stays.
    pub fn tunnel(&mut self, psk: Psk, confirm: &[u8; 32]) -> Option<[u8; 32]> {
        if &psk.confirm != confirm {
            return None;
        }
        self.pending = Some(psk.key);
        Some(psk.confirm)
    }

    /// The keys a handshake from the device may use: the pending one and
    /// the current one.
    pub fn accepts(&self) -> Vec<[u8; 32]> {
        self.pending.into_iter().chain(self.current).collect()
    }

    /// A handshake with `key` succeeded: a pending key becomes current and
    /// the old one goes.
    pub fn handshake(&mut self, key: &[u8; 32]) {
        if self.pending.as_ref() == Some(key) {
            self.current = self.pending.take();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exported(n: u8) -> [u8; 32] {
        [n; 32]
    }

    /// The device tries its keys in order against what the hub accepts; the
    /// first that fits is the handshake.
    fn handshake(d: &DeviceSide, h: &mut HubSide) -> Option<[u8; 32]> {
        let ok = d.to_try().into_iter().find(|k| h.accepts().contains(k))?;
        h.handshake(&ok);
        Some(ok)
    }

    /// One direct connection: the device sends `tunnel`, the hub confirms.
    fn connect(d: &mut DeviceSide, h: &mut HubSide, n: u8) {
        let p = psk(&exported(n));
        let tag = d.connected(p);
        let back = h.tunnel(p, &tag).expect("the hub takes its own connection's tag");
        assert!(d.confirmed(&back));
    }

    #[test]
    fn one_key_per_hub() {
        let secret = [7u8; 32];
        let (a, b) = (DeviceId([1; 16]), DeviceId([2; 16]));
        assert_eq!(key_for(&secret, &a), key_for(&secret, &a), "stable for a hub");
        assert_ne!(key_for(&secret, &a).1, key_for(&secret, &b).1, "another for another hub");
        assert_ne!(key_for(&secret, &a).1, key_for(&[8; 32], &a).1, "another device, another key");
        let (k, c) = (key_for(&secret, &a).1, psk(&exported(1)).confirm);
        assert_eq!(read(&message(&k, &c)), Ok((k, c)));
        assert!(read(&message(&[0; 32], &c)).is_err());
        let p = psk(&exported(1));
        assert_ne!(p.key, p.confirm, "the tag does not give the key away");
    }

    #[test]
    fn a_switch_needs_both_ends() {
        let (mut d, mut h) = (DeviceSide::default(), HubSide::default());
        connect(&mut d, &mut h, 1);
        assert_eq!(handshake(&d, &mut h), Some(psk(&exported(1)).key));
        assert_eq!(h.current, Some(psk(&exported(1)).key));

        // The next connection breaks after the device sent `tunnel` and
        // before the hub's confirmation came back.
        let p2 = psk(&exported(2));
        let tag = d.connected(p2);
        assert!(h.tunnel(p2, &tag).is_some());
        // The device still handshakes with the old key, and the hub still
        // takes it beside the pending one.
        assert_eq!(handshake(&d, &mut h), Some(psk(&exported(1)).key));
        assert_eq!(h.current, Some(psk(&exported(1)).key), "a handshake with the old key keeps it");
        // A tag of another connection confirms nothing.
        assert!(!d.confirmed(&psk(&exported(9)).confirm));
        assert!(h.tunnel(psk(&exported(3)), &psk(&exported(9)).confirm).is_none());

        // The next connection completes the switch.
        connect(&mut d, &mut h, 3);
        assert_eq!(handshake(&d, &mut h), Some(psk(&exported(3)).key));
        assert_eq!(h.accepts(), alloc::vec![psk(&exported(3)).key], "the hub drops the old key");
    }

    #[test]
    fn a_hub_restarted_from_an_older_state_still_lets_the_device_in() {
        let (mut d, mut h) = (DeviceSide::default(), HubSide::default());
        connect(&mut d, &mut h, 1);
        assert!(handshake(&d, &mut h).is_some());
        let saved = h.clone();
        connect(&mut d, &mut h, 2);
        assert!(handshake(&d, &mut h).is_some());
        // The hub comes back from the state it saved before the switch.
        let mut h = saved;
        assert_eq!(handshake(&d, &mut h), Some(psk(&exported(1)).key), "the device falls back");
        // The next direct connection puts both on a new key.
        connect(&mut d, &mut h, 3);
        assert_eq!(handshake(&d, &mut h), Some(psk(&exported(3)).key));

        // A hub that lost everything: away from home the device is out
        // until a direct connection, which repairs it.
        let mut h = HubSide::default();
        assert_eq!(handshake(&d, &mut h), None);
        connect(&mut d, &mut h, 4);
        assert_eq!(handshake(&d, &mut h), Some(psk(&exported(4)).key));
    }
}
