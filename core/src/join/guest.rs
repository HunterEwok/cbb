// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! `guest` (t 17): an admin and a hub about the guest of an invitation the
//! admin makes through that hub (docs/protocol.md, section 12, "Through the
//! hub"), named by the guest's WireGuard key. The admin keeps the window;
//! the hub lets the guest in and passes the bytes of its pairing
//! connections. Sans-I/O: the messages and their checks only.

use alloc::string::String;
use alloc::vec::Vec;

use crate::format::cbor::{self, Value};
use crate::format::{Alg, Key, Rule};
use crate::msg::tables::{
    GUEST_ADMITTED, GUEST_CLOSE, GUEST_DATA, GUEST_END, GUEST_OPEN, GUEST_OPENED, GUEST_REFUSED, T_GUEST,
};

/// What a `guest` message is the shape of when its fields do not fit its op.
pub const RULE_GUEST: Rule = Rule::field("guest/shape");

/// The most bytes of one `data` message.
pub const MAX_DATA: usize = 16384;

/// What a `guest` message says.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Op {
    /// Admin to hub: let this guest in until `expires_ms`, for the
    /// invitation `invite`.
    Open { psk: [u8; 32], expires_ms: u64, invite: [u8; 16] },
    /// Hub to admin: the guest is in; the hub's offer (table `offer`) gives
    /// the invitation's hub key, endpoints and obfuscation settings.
    Opened { offer: Vec<u8> },
    /// Hub to admin: a sentence for the user.
    Refused { reason: String },
    /// Both ways: bytes of the guest's connection `conn`.
    Data { conn: u32, data: Vec<u8> },
    /// Both ways: that side closed the connection for writing.
    End { conn: u32 },
    /// Admin to hub: the window admitted this device.
    Admitted { device: [u8; 16] },
    /// Admin to hub: the invitation ended without a device.
    Close,
}

/// A `guest` message: what it says about the guest with the key.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Guest {
    pub key: [u8; 32],
    pub op: Op,
}

impl Guest {
    /// The message's encoding (with its type, field 0); a `data` message
    /// holds at most [`MAX_DATA`] bytes, which the caller keeps to.
    pub fn encode(&self) -> Vec<u8> {
        let key = Key::new(Alg::X25519, &self.key);
        let (op, mut rest): (u64, Vec<(u16, Value<'_>)>) = match &self.op {
            Op::Open { psk, expires_ms, invite } => (
                GUEST_OPEN,
                alloc::vec![(4, Value::Bytes(psk)), (5, Value::Uint(*expires_ms)), (11, Value::Bytes(invite))],
            ),
            Op::Opened { offer } => {
                let v = cbor::decode(offer).unwrap_or(Value::Map(Vec::new()));
                (GUEST_OPENED, alloc::vec![(6, v)])
            }
            Op::Refused { reason } => (GUEST_REFUSED, alloc::vec![(7, Value::Text(reason))]),
            Op::Data { conn, data } => {
                (GUEST_DATA, alloc::vec![(8, Value::Uint(u64::from(*conn))), (9, Value::Bytes(data))])
            }
            Op::End { conn } => (GUEST_END, alloc::vec![(8, Value::Uint(u64::from(*conn)))]),
            Op::Admitted { device } => (GUEST_ADMITTED, alloc::vec![(10, Value::Bytes(device))]),
            Op::Close => (GUEST_CLOSE, Vec::new()),
        };
        let mut m = alloc::vec![(0, Value::Uint(T_GUEST)), (2, Value::Uint(op)), (3, key.to_value())];
        m.append(&mut rest);
        Value::Map(m).encode()
    }

    /// Reads a `guest` message, checked against its table, with the fields
    /// its op needs.
    pub fn read(msg: &[u8]) -> Result<Guest, Rule> {
        let (t, v) = crate::msg::read(msg)?;
        if t != T_GUEST {
            return Err(RULE_GUEST);
        }
        let k = Key::from_value(v.get(3).ok_or(RULE_GUEST)?).map_err(|_| RULE_GUEST)?;
        let key: [u8; 32] = k.public.try_into().map_err(|_| RULE_GUEST)?;
        let bytes = |n: u16| v.get(n).and_then(Value::as_bytes).ok_or(RULE_GUEST);
        let uint = |n: u16| v.get(n).and_then(Value::as_uint).ok_or(RULE_GUEST);
        let b32 = |n: u16| -> Result<[u8; 32], Rule> { bytes(n)?.try_into().map_err(|_| RULE_GUEST) };
        let b16 = |n: u16| -> Result<[u8; 16], Rule> { bytes(n)?.try_into().map_err(|_| RULE_GUEST) };
        let conn = || uint(8).and_then(|c| u32::try_from(c).map_err(|_| RULE_GUEST));
        let op = match uint(2)? {
            GUEST_OPEN => Op::Open { psk: b32(4)?, expires_ms: uint(5)?, invite: b16(11)? },
            GUEST_OPENED => Op::Opened { offer: v.get(6).ok_or(RULE_GUEST)?.encode() },
            GUEST_REFUSED => {
                let reason = match v.get(7) {
                    Some(Value::Text(t)) => String::from(*t),
                    _ => return Err(RULE_GUEST),
                };
                Op::Refused { reason }
            }
            GUEST_DATA => Op::Data { conn: conn()?, data: bytes(9)?.to_vec() },
            GUEST_END => Op::End { conn: conn()? },
            GUEST_ADMITTED => Op::Admitted { device: b16(10)? },
            GUEST_CLOSE => Op::Close,
            _ => return Err(RULE_GUEST),
        };
        Ok(Guest { key, op })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each op reads back as written, and a message that lacks a field its
    /// op needs is refused.
    #[test]
    fn guest_messages_read_back() {
        let offer = Value::Map(alloc::vec![
            (1, Key::new(Alg::X25519, &[5; 32]).to_value()),
            (2, Value::Array(alloc::vec![Value::Text("192.0.2.1:8764")])),
        ])
        .encode();
        for op in [
            Op::Open { psk: [2; 32], expires_ms: 1_700_000_000_000, invite: [3; 16] },
            Op::Opened { offer },
            Op::Refused { reason: "not a hub".into() },
            Op::Data { conn: 1, data: alloc::vec![9; 100] },
            Op::End { conn: 2 },
            Op::Admitted { device: [4; 16] },
            Op::Close,
        ] {
            let g = Guest { key: [1; 32], op };
            assert_eq!(Guest::read(&g.encode()), Ok(g.clone()), "{g:?}");
        }
        // An open without its pre-shared key.
        let short = Value::Map(alloc::vec![
            (0, Value::Uint(T_GUEST)),
            (2, Value::Uint(GUEST_OPEN)),
            (3, Key::new(Alg::X25519, &[1; 32]).to_value()),
            (5, Value::Uint(1)),
        ])
        .encode();
        assert!(Guest::read(&short).is_err());
        // Another message type.
        assert!(Guest::read(&crate::hubkey::hubs_message(crate::hubkey::HubSays::Serving)).is_err());
    }

    /// A `data` message holds [`MAX_DATA`] bytes and no more.
    #[test]
    fn a_guest_data_holds_at_its_bound() {
        let data = |n: usize| Guest { key: [1; 32], op: Op::Data { conn: 1, data: alloc::vec![9; n] } }.encode();
        assert!(Guest::read(&data(MAX_DATA)).is_ok());
        let got = crate::msg::check(&data(MAX_DATA + 1)).err().map(|r| r.name());
        assert_eq!(got, Some("guest/data"));
    }
}
