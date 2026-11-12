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
//!   (the hub 4, the device 8) beside the keys of the last tunnel
//!   handshakes (the hub 2, the device 1), and a new key is added beside
//!   them, never in their place. The device sends `tunnel` with the new
//!   key's confirmation tag; the hub keeps the key and answers with the tag
//!   in its offer; the device then tries the confirmed key first, and every
//!   other key it keeps after it. A handshake drops no key at either end.
//! - **How far back.** The two ends share a key after: a lost `tunnel` or
//!   a lost confirmation (up to 4 confirmations lost and then 4 `tunnel`
//!   messages lost); a hub back from a saved state at most 4 of the
//!   device's connections old; a device back from a saved state that still
//!   holds one of the hub's last 4 received keys or its last 2 handshake
//!   keys (about 3 connections at home with a trip after each). Beyond
//!   that the device is out away from home until its next direct
//!   connection with the hub, which mends it. Nothing more is promised.
//! - **The responder's answer** (for the service, wave 5): WireGuard mixes
//!   the pre-shared key in at the responder's answer, so a hub that accepts
//!   several keys answers once with each key it holds, in the order of
//!   [`HubSide::accepts`], until the device's confirmation of the handshake
//!   shows which one fits; or the device walks [`DeviceSide::to_try`] one
//!   key per initiation.
//! - **The hybrid is required.** The pre-shared key comes only from a
//!   connection whose key exchange was X25519MLKEM768 ([`psk`] takes no
//!   other).
//! - **The hub's key toward forwarders** is per face ([`hub_key_for_face`]):
//!   two forwarders a hub registers with see two keys. The hub serves
//!   WireGuard under that key on that forwarder's endpoints, and its offer
//!   says so per endpoint (`offer` field 9); an endpoint without one uses
//!   the offer's key.
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
/// `hybrid`: the connection's key exchange was X25519MLKEM768 (the TLS
/// session's `kx_group`, see [`hybrid`]); None for any other, whose secret
/// would not hold against a later quantum computer.
pub fn psk(exported: &[u8; 32], hybrid: bool) -> Option<Psk> {
    hybrid.then(|| Psk { key: expand(exported, &[PSK_INFO]), confirm: expand(exported, &[CONFIRM_INFO]) })
}

/// Whether a TLS session's key exchange group is the hybrid one.
#[cfg(feature = "tls")]
pub fn hybrid(group: Option<rustls::NamedGroup>) -> bool {
    group == Some(rustls::NamedGroup::X25519MLKEM768)
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

/// HKDF's info for the hub's own WireGuard key toward a forwarder, the
/// face's tag after it.
const FACE_KEY_INFO: &[u8] = b"cbb hub face key v1";

/// The hub's WireGuard key for one face (one forwarder's period): from its
/// tunnel secret and the face's tag, so that two forwarders it registers
/// with (`forward/register` field 2) see two keys. Returns the private key
/// and its public key.
pub fn hub_key_for_face(secret: &[u8; 32], tag: &[u8; 16]) -> ([u8; 32], [u8; 32]) {
    let s = x25519_dalek::StaticSecret::from(expand(secret, &[FACE_KEY_INFO, tag]));
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

/// How many keys of recent connections the hub keeps.
pub const KEEP: usize = 4;
/// How many keys of recent connections the device keeps: twice the hub's,
/// so that keys the hub took while their confirmations were lost and keys
/// whose `tunnel` the hub never got together still leave a common one.
pub const DEVICE_KEEP: usize = 2 * KEEP;
/// How many keys of recent tunnel handshakes the hub keeps.
pub const KEEP_HANDSHAKES: usize = 2;

/// The device's pre-shared keys toward one hub. Kept across restarts.
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct DeviceSide {
    /// The key of the last tunnel handshake with the hub.
    pub handshaked: Option<[u8; 32]>,
    /// The newest key the hub confirmed.
    pub confirmed: Option<[u8; 32]>,
    /// The keys of the last connections it sent `tunnel` over, newest
    /// first, at most [`DEVICE_KEEP`], whether or not the hub confirmed them.
    pub sent: Vec<Psk>,
}

impl DeviceSide {
    /// A member connection with the hub gave a new key: it is kept, and its
    /// tag goes in `tunnel`.
    pub fn connected(&mut self, psk: Psk) -> [u8; 32] {
        self.sent.retain(|p| p != &psk);
        self.sent.insert(0, psk);
        self.sent.truncate(DEVICE_KEEP);
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
    /// [`KEEP`] connections, or missed [`KEEP`] `tunnel` messages in a row
    /// after [`KEEP`] lost confirmations.
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
    /// The keys of the last tunnel handshakes with the device, newest
    /// first, at most [`KEEP_HANDSHAKES`].
    pub handshaked: Vec<[u8; 32]>,
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
        for h in &self.handshaked {
            if !out.contains(h) {
                out.push(*h);
            }
        }
        out
    }

    /// A handshake with `key` succeeded: it is the newest handshake's key.
    /// No key goes: a device back from an older saved state still holds
    /// one of them.
    pub fn handshake(&mut self, key: &[u8; 32]) {
        if !self.accepts().contains(key) {
            return;
        }
        self.handshaked.retain(|k| k != key);
        self.handshaked.insert(0, *key);
        self.handshaked.truncate(KEEP_HANDSHAKES);
    }
}

#[cfg(test)]
mod tests;
