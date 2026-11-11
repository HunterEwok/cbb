// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The tunnel's keys toward a hub (A-22): one per hub and per connection,
//! bound to the member connection with that hub.
//!
//! - The device's WireGuard key toward a hub is new for every member
//!   connection to it, and its public half goes in message `tunnel` (t 15,
//!   format 9.2) over that connection, to that hub only. So the key changes
//!   by itself, and no two hubs see one key.
//! - The pre-shared key is never sent: both ends export it from the TLS
//!   connection (RFC 8446 section 7.5) with both device IDs in the context.
//!   That connection's key exchange is X25519MLKEM768, so the tunnel holds
//!   against a later quantum computer as WireGuard's own X25519 does not.
//!
//! Before 0.6 one key and one pre-shared key went to every hub in the hello.

use alloc::vec::Vec;

use hkdf::Hkdf;
use sha2::Sha256;

use crate::format::{Alg, DeviceId, Rule, Value, cbor};

/// The exporter's label.
pub const EXPORTER_LABEL: &[u8] = b"EXPORTER-cbb-tunnel-v1";
/// HKDF's info for the pre-shared key.
const PSK_INFO: &[u8] = b"cbb tunnel psk v1";
/// The message type of `tunnel`.
pub const T_TUNNEL: u64 = 15;

pub const RULE_TUNNEL: Rule = Rule::field("tunnel/key");

/// The context of the exporter: the hub's device ID, then the dialing
/// device's.
pub fn context(hub: &DeviceId, device: &DeviceId) -> [u8; 32] {
    let mut c = [0u8; 32];
    c[..16].copy_from_slice(&hub.0);
    c[16..].copy_from_slice(&device.0);
    c
}

/// The pre-shared key from the connection's exported secret (32 bytes of
/// [`EXPORTER_LABEL`] with [`context`]).
pub fn psk(exported: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, exported);
    let mut out = [0u8; 32];
    // 32 bytes is within HKDF-SHA256's limit.
    let _ = hk.expand(PSK_INFO, &mut out);
    out
}

/// A new WireGuard key pair for one connection with one hub: the private
/// key (clamped by WireGuard) and its public key.
pub fn new_key() -> ([u8; 32], [u8; 32]) {
    let secret = x25519_dalek::StaticSecret::from(crate::certs::random_bytes::<32>());
    let public = x25519_dalek::PublicKey::from(&secret);
    (secret.to_bytes(), *public.as_bytes())
}

/// The `tunnel` message to a hub, unpadded: field 2 the key, alg 3.
pub fn message(public: &[u8; 32]) -> Vec<u8> {
    Value::Map(alloc::vec![
        (0, Value::Uint(T_TUNNEL)),
        (2, Value::Array(alloc::vec![Value::Uint(Alg::X25519.number()), Value::Bytes(public)])),
    ])
    .encode()
}

/// Reads a `tunnel` message: the device's WireGuard key toward this hub.
pub fn read(msg: &[u8]) -> Result<[u8; 32], Rule> {
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
    Ok(key)
}
