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
//! - **The switch.** Each end keeps the keys of the last few connections
//!   beside the key of the last tunnel handshake, and a new key is added
//!   beside them, never in their place. The device sends `tunnel` with the
//!   new key's confirmation tag; the hub keeps the key and answers with the
//!   tag in its offer; the device then tries the confirmed key first, and
//!   every other key it keeps after it. A handshake drops, at the hub, the
//!   keys of connections before its own; the device keeps them, for a hub
//!   that comes back from an older saved state. So a lost `tunnel`, a lost
//!   confirmation or a lost step of either end's saved state never leaves
//!   the two ends without a common key: a switch never locks a device out
//!   away from home. Anything worse is repaired by the next direct
//!   connection.
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

/// How many keys of recent connections each end keeps.
pub const KEEP: usize = 4;

/// The device's pre-shared keys toward one hub. Kept across restarts.
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct DeviceSide {
    /// The key of the last tunnel handshake with the hub.
    pub handshaked: Option<[u8; 32]>,
    /// The newest key the hub confirmed.
    pub confirmed: Option<[u8; 32]>,
    /// The keys of the last connections it sent `tunnel` over, newest
    /// first, at most [`KEEP`], whether or not the hub confirmed them.
    pub sent: Vec<Psk>,
}

impl DeviceSide {
    /// A member connection with the hub gave a new key: it is kept, and its
    /// tag goes in `tunnel`.
    pub fn connected(&mut self, psk: Psk) -> [u8; 32] {
        self.sent.retain(|p| p != &psk);
        self.sent.insert(0, psk);
        self.sent.truncate(KEEP);
        psk.confirm
    }

    /// The hub's offer came back with `confirm`: the key of that tag is the
    /// newest the hub holds. Returns whether the tag was one of its keys.
    pub fn confirmed(&mut self, confirm: &[u8; 32]) -> bool {
        match self.sent.iter().find(|p| &p.confirm == confirm) {
            Some(p) => {
                self.confirmed = Some(p.key);
                true
            }
            None => false,
        }
    }

    /// The keys to try, in order: the confirmed one, the last handshake's,
    /// then every key of a recent connection, newest first. The hub holds
    /// one of them unless it lost more of its saved state than the last
    /// [`KEEP`] connections, or missed [`KEEP`] `tunnel` messages in a row.
    pub fn to_try(&self) -> Vec<[u8; 32]> {
        let mut out: Vec<[u8; 32]> = Vec::new();
        for k in self.confirmed.into_iter().chain(self.handshaked).chain(self.sent.iter().map(|p| p.key)) {
            if !out.contains(&k) {
                out.push(k);
            }
        }
        out
    }

    /// A handshake with `key` succeeded: it is the last handshake's key.
    /// The keys of earlier connections stay, for a hub that comes back from
    /// an older saved state.
    pub fn handshake(&mut self, key: &[u8; 32]) {
        self.handshaked = Some(*key);
    }
}

/// A hub's pre-shared keys for one device. Kept across restarts.
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct HubSide {
    /// The key of the last tunnel handshake with the device.
    pub handshaked: Option<[u8; 32]>,
    /// The keys of the last connections the device sent `tunnel` over,
    /// newest first, at most [`KEEP`]. Each new one is added beside the
    /// others, never in their place.
    pub received: Vec<[u8; 32]>,
}

impl HubSide {
    /// The device sent `tunnel` over a connection whose key is `psk`: if its
    /// tag matches, the key is kept and the hub confirms it with that tag in
    /// its offer; the keys it held stay.
    pub fn tunnel(&mut self, psk: Psk, confirm: &[u8; 32]) -> Option<[u8; 32]> {
        if &psk.confirm != confirm {
            return None;
        }
        self.received.retain(|k| k != &psk.key);
        self.received.insert(0, psk.key);
        self.received.truncate(KEEP);
        Some(psk.confirm)
    }

    /// The keys a handshake from the device may use.
    pub fn accepts(&self) -> Vec<[u8; 32]> {
        let mut out = self.received.clone();
        if let Some(h) = self.handshaked
            && !out.contains(&h)
        {
            out.push(h);
        }
        out
    }

    /// A handshake with `key` succeeded: it is the last handshake's key,
    /// and the keys of connections before it go.
    pub fn handshake(&mut self, key: &[u8; 32]) {
        if !self.accepts().contains(key) {
            return;
        }
        self.handshaked = Some(*key);
        if let Some(i) = self.received.iter().position(|k| k == key) {
            self.received.truncate(i.saturating_add(1));
        }
    }
}

#[cfg(test)]
mod tests;
