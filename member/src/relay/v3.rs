// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The device's side of the relay's messages of 0.6 (`cbb-relay/3`, format
//! section 9.4): the relay's challenge and welcome read, the requests in
//! the tunnel written and the relay's notes read, each one frame of the
//! format. The registration itself is written by the relay's own code
//! (`relayd::wire3::Register`), so both ends share one writer. Names and
//! tickets are base64 here, as the link keeps them for both protocols.

use base64::Engine as _;
use cbb_core::format::cbor::Value;
use cbb_core::format::{Key, frame};
use cbb_core::msg::tables as t;

use super::{Note, Request};
use crate::error::{Error, Result};

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

fn read(body: &[u8]) -> Result<(u64, Value<'_>)> {
    let (ty, v, _) =
        cbb_core::msg::read_noted(body).map_err(|r| Error::msg(format!("the relay's message breaks {r}")))?;
    Ok((ty, v))
}

fn refused(v: &Value<'_>) -> Error {
    let why = v.get(2).and_then(Value::as_text).unwrap_or("no reason");
    Error::msg(format!("the relay refused the registration: {why}"))
}

/// The size of the frame of head, on the format's grid, within max.
pub fn length(head: [u8; 4], max: usize) -> Result<usize> {
    frame::length(head, max).map_err(|r| Error::msg(format!("the relay's frame breaks {r}")))
}

/// The relay's challenge: its ephemeral key, and whether it wants the
/// period credential and the root.
pub fn challenge(body: &[u8]) -> Result<(Vec<u8>, bool)> {
    let (ty, v) = read(body)?;
    match ty {
        t::T_RELAY_CHALLENGE => {}
        t::T_RELAY_ERROR => return Err(refused(&v)),
        _ => return Err(Error::msg("registering with the relay: not its challenge")),
    }
    let e = v.get(2).and_then(Value::as_bytes).unwrap_or_default().to_vec();
    Ok((e, v.get(3).and_then(Value::as_uint) == Some(1)))
}

/// The relay's welcome: its WireGuard key, the pre-shared key and the
/// device's tunnel address; the relay's reason when it refused.
pub fn welcome(body: &[u8]) -> Result<([u8; 32], [u8; 32], String)> {
    let (ty, v) = read(body)?;
    match ty {
        t::T_RELAY_REGISTERED => {}
        t::T_RELAY_ERROR => return Err(refused(&v)),
        _ => return Err(Error::msg("registering with the relay: not its welcome")),
    }
    let key = v.get(2).and_then(|k| Key::from_value(k).ok()).and_then(|k| <[u8; 32]>::try_from(k.public).ok());
    let psk = v.get(3).and_then(Value::as_bytes).and_then(|b| <[u8; 32]>::try_from(b).ok());
    let addr = v.get(4).and_then(Value::as_text).unwrap_or_default().to_string();
    let (Some(key), Some(psk)) = (key, psk) else { return Err(Error::msg("the relay's keys are not 32 bytes")) };
    Ok((key, psk, addr))
}

fn msg(ty: u64, mut fields: Vec<(u16, Value<'_>)>) -> Vec<u8> {
    fields.insert(0, (frame::FIELD_T, Value::Uint(ty)));
    frame::write(&Value::Map(fields))
}

/// A request in the tunnel as its frame: a watch, a dial of a name or the
/// answer of a ticket.
pub fn request(r: &Request<'_>) -> Result<Vec<u8>> {
    let e = &base64::engine::general_purpose::STANDARD;
    let bytes = |s: &str, n: usize| e.decode(s).ok().filter(|b| b.len() == n);
    if r.watch {
        return Ok(msg(t::T_RELAY_WATCH, vec![]));
    }
    if !r.dial.is_empty() {
        let name = bytes(r.dial, 32).ok_or_else(|| Error::msg("a name at the relay that is not one"))?;
        return Ok(msg(t::T_RELAY_DIAL, vec![(2, Value::Bytes(&name))]));
    }
    let ticket = bytes(r.answer, 16).ok_or_else(|| Error::msg("a ticket that is not one"))?;
    Ok(msg(t::T_RELAY_ANSWER, vec![(2, Value::Bytes(&ticket))]))
}

/// A note of the relay in the tunnel, read from its frame's body.
pub fn note(body: &[u8]) -> Result<Note> {
    let (ty, v) = read(body)?;
    let mut n = Note::default();
    match ty {
        t::T_RELAY_ONLINE => {
            let names = v.get(2).and_then(Value::as_array).unwrap_or(&[]);
            n.online = Some(names.iter().filter_map(Value::as_bytes).map(b64).collect());
        }
        t::T_RELAY_CALL => {
            n.call = v.get(2).and_then(Value::as_bytes).map(b64).unwrap_or_default();
            n.ticket = v.get(3).and_then(Value::as_bytes).map(b64).unwrap_or_default();
        }
        t::T_RELAY_OK => n.ok = true,
        t::T_RELAY_ERROR => n.error = v.get(2).and_then(Value::as_text).unwrap_or("no reason").to_string(),
        _ => return Err(Error::msg("the relay sent a message of another kind")),
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relayd::wire as server;
    use crate::relayd::wire3;

    fn body(f: &[u8]) -> &[u8] {
        &f[4..]
    }

    #[test]
    fn the_relays_messages_read_as_it_writes_them() {
        let (e, root) = challenge(body(&wire3::challenge(&[5; 32], true))).unwrap();
        assert_eq!((e, root), (vec![5; 32], true));
        assert!(!challenge(body(&wire3::challenge(&[5; 32], false))).unwrap().1);
        let w = welcome(body(&wire3::registered(&[9; 32], &[8; 32], "fd00::5"))).unwrap();
        assert_eq!(w, ([9; 32], [8; 32], "fd00::5".to_string()));
        let err = welcome(body(&wire3::error("not listed"))).unwrap_err();
        assert!(err.to_string().contains("not listed"), "{err}");
        assert!(challenge(body(&wire3::error("no"))).is_err());
        assert!(welcome(body(&wire3::challenge(&[5; 32], false))).is_err());

        let name = b64(&[3; 32]);
        let ticket = b64(&[4; 16]);
        let call = wire3::note(&server::Note { call: name.clone(), ticket: ticket.clone(), ..Default::default() });
        let n = note(body(&call.unwrap())).unwrap();
        assert_eq!((n.call.as_str(), n.ticket.as_str()), (name.as_str(), ticket.as_str()));
        let online = wire3::note(&server::Note { online: Some(vec![name.clone()]), ..Default::default() });
        assert_eq!(note(body(&online.unwrap())).unwrap().online, Some(vec![name.clone()]));
        let nobody = wire3::note(&server::Note { online: Some(vec![]), ..Default::default() });
        assert_eq!(note(body(&nobody.unwrap())).unwrap().online, Some(vec![]));
        assert!(note(body(&wire3::note(&server::Note { ok: true, ..Default::default() }).unwrap())).unwrap().ok);
        assert_eq!(note(body(&wire3::error("busy"))).unwrap().error, "busy");
    }

    #[test]
    fn the_requests_read_as_the_relay_takes_them() {
        let name = b64(&[3; 32]);
        let ticket = b64(&[4; 16]);
        let w = request(&Request { watch: true, ..Request::default() }).unwrap();
        assert!(wire3::request(body(&w)).unwrap().watch);
        let d = request(&Request { dial: &name, ..Request::default() }).unwrap();
        assert_eq!(wire3::request(body(&d)).unwrap().dial, name);
        let a = request(&Request { answer: &ticket, ..Request::default() }).unwrap();
        assert_eq!(wire3::request(body(&a)).unwrap().answer, ticket);
        assert!(request(&Request { dial: &ticket, ..Request::default() }).is_err());
        assert!(request(&Request { answer: "", ..Request::default() }).is_err());
        assert_eq!(length(<[u8; 4]>::try_from(&d[..4]).unwrap(), 1 << 16).unwrap(), d.len() - 4);
    }
}
