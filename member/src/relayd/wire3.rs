// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The relay's messages of 0.6 (format section 9.4, `cbb-relay/3`): the
//! registration's (`relay/challenge`, `register`, `registered`, `error`,
//! t 90 to 93) and those inside the tunnel (`watch`, `dial`, `answer`,
//! `online`, `call`, `ok`, t 94 to 99), each one frame of the format. A
//! device is known by its pseudonym, the hash of its server key for the
//! period (32 bytes), and a call by a ticket of 16 bytes; the relay's own
//! code and the link name them in base64.

use std::net::TcpStream;
use std::time::Duration;

use base64::Engine as _;
use cbb_core::format::cbor::Value;
use cbb_core::format::{Alg, Key, frame};
use cbb_core::msg::tables as t;

use super::wire::{Deadline, Note, Request};
use crate::error::{Error, Result};

/// The protocol a device of 0.6 offers.
pub const PROTOCOL: &[u8] = b"cbb-relay/3";
/// The largest frame of a registration: three credentials of 16 KiB.
pub const MAX_FRAME: usize = 64 << 10;

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

fn unb64<const N: usize>(s: &str) -> Option<[u8; N]> {
    base64::engine::general_purpose::STANDARD.decode(s).ok()?.try_into().ok()
}

fn msg(ty: u64, mut fields: Vec<(u16, Value<'_>)>) -> Vec<u8> {
    fields.insert(0, (frame::FIELD_T, Value::Uint(ty)));
    frame::write(&Value::Map(fields))
}

/// Reads one frame of the format exactly: its body, checked against its
/// message's table, and its type.
pub fn read(c: &mut impl std::io::Read, max: usize) -> Result<(u64, Vec<u8>)> {
    let mut head = [0u8; 4];
    c.read_exact(&mut head).map_err(|e| Error::msg(format!("cannot read a frame: {e}")))?;
    let n = frame::length(head, max).map_err(|r| Error::msg(format!("a frame breaks {r}")))?;
    let mut body = vec![0u8; n];
    c.read_exact(&mut body).map_err(|e| Error::msg(format!("cannot read a frame: {e}")))?;
    let (ty, _, _) = cbb_core::msg::read_noted(&body).map_err(|r| Error::msg(format!("a message breaks {r}")))?;
    Ok((ty, body))
}

/// The relay's challenge: its ephemeral X25519 key, and whether the device
/// must show its period credential and its root (a relay with a list of
/// groups).
pub fn challenge(e: &[u8; 32], root: bool) -> Vec<u8> {
    let mut f = vec![(2, Value::Bytes(e))];
    if root {
        f.push((3, Value::Uint(1)));
    }
    msg(t::T_RELAY_CHALLENGE, f)
}

/// What a device registers with.
pub struct Register {
    pub key: [u8; 32],
    pub proof: [u8; 32],
    pub credentials: Vec<Vec<u8>>,
    pub root: Option<Vec<u8>>,
}

impl Register {
    pub fn write(&self) -> Vec<u8> {
        let creds: Vec<Value<'_>> =
            self.credentials.iter().filter_map(|e| cbb_core::format::cbor::decode(e).ok()).collect();
        let mut f = vec![
            (2, Key::new(Alg::X25519, &self.key).to_value()),
            (3, Value::Bytes(&self.proof)),
            (4, Value::Array(creds)),
        ];
        if let Some(r) = &self.root {
            f.push((5, Key::new(Alg::Es256, r).to_value()));
        }
        msg(t::T_RELAY_REGISTER, f)
    }

    /// Reads message `relay/register` (its body).
    pub fn read(body: &[u8]) -> Result<Register> {
        let (ty, v, _) = cbb_core::msg::read_noted(body).map_err(|r| Error::msg(format!("a claim breaks {r}")))?;
        if ty != t::T_RELAY_REGISTER {
            return Err(Error::msg("not a claim"));
        }
        let key = v.get(2).and_then(|k| Key::from_value(k).ok()).and_then(|k| <[u8; 32]>::try_from(k.public).ok());
        let proof = v.get(3).and_then(Value::as_bytes).and_then(|b| <[u8; 32]>::try_from(b).ok());
        let (Some(key), Some(proof)) = (key, proof) else { return Err(Error::msg("a claim without its key")) };
        let credentials = v.get(4).and_then(Value::as_array).unwrap_or(&[]).iter().map(Value::encode).collect();
        let root = v.get(5).and_then(|k| Key::from_value(k).ok()).map(|k| k.public.to_vec());
        Ok(Register { key, proof, credentials, root })
    }
}

/// The relay's welcome: its WireGuard key, the device's pre-shared key and
/// its tunnel address.
pub fn registered(key: &[u8; 32], psk: &[u8; 32], addr: &str) -> Vec<u8> {
    msg(
        t::T_RELAY_REGISTERED,
        vec![(2, Key::new(Alg::X25519, key).to_value()), (3, Value::Bytes(psk)), (4, Value::Text(addr))],
    )
}

/// Why the relay refused, cut to the format's 256 bytes.
pub fn error(reason: &str) -> Vec<u8> {
    let mut r = reason;
    while r.len() > 256 {
        let mut end = 256.min(r.len());
        while !r.is_char_boundary(end) {
            end -= 1;
        }
        r = &r[..end];
    }
    msg(t::T_RELAY_ERROR, vec![(2, Value::Text(r))])
}

/// A note of the relay as its message in the tunnel; None for a note the
/// format does not carry (a name or a ticket that is not one).
pub fn note(n: &Note) -> Option<Vec<u8>> {
    if !n.error.is_empty() {
        return Some(error(&n.error));
    }
    if n.ok {
        return Some(msg(t::T_RELAY_OK, vec![]));
    }
    if !n.call.is_empty() {
        let name: [u8; 32] = unb64(&n.call)?;
        let ticket: [u8; 16] = unb64(&n.ticket)?;
        return Some(msg(t::T_RELAY_CALL, vec![(2, Value::Bytes(&name)), (3, Value::Bytes(&ticket))]));
    }
    let online = n.online.as_ref()?;
    let mut names: Vec<[u8; 32]> = online.iter().filter_map(|s| unb64(s)).collect();
    names.sort();
    names.dedup();
    names.truncate(64);
    let mut f = Vec::new();
    if !names.is_empty() {
        f.push((2, Value::Array(names.iter().map(|n| Value::Bytes(n)).collect())));
    }
    Some(msg(t::T_RELAY_ONLINE, f))
}

/// The request of a connection in the tunnel, as the relay's code takes it.
pub fn request(body: &[u8]) -> Result<Request> {
    let (ty, v, _) = cbb_core::msg::read_noted(body).map_err(|r| Error::msg(format!("a request breaks {r}")))?;
    let field = |n| v.get(n).and_then(Value::as_bytes).map(b64).unwrap_or_default();
    Ok(match ty {
        t::T_RELAY_WATCH => Request { watch: true, ..Request::default() },
        t::T_RELAY_DIAL => Request { dial: field(2), ..Request::default() },
        t::T_RELAY_ANSWER => Request { answer: field(2), ..Request::default() },
        _ => Request::default(),
    })
}

/// Reads the request of a connection in a tunnel, within d.
pub fn read_request(c: &TcpStream, d: Duration) -> Result<Request> {
    let mut r = Deadline::new(c.try_clone().map_err(|e| Error::msg(format!("cannot read a frame: {e}")))?, d);
    let (_, body) = read(&mut r, super::wire::MAX_LINE)?;
    r.clear();
    request(&body)
}

/// Sends a note on a connection in a tunnel, within d.
pub fn send_note(c: &TcpStream, n: &Note, d: Duration) -> Result<()> {
    use std::io::Write as _;
    let f = note(n).ok_or_else(|| Error::msg("a note the format does not carry"))?;
    let mut w = Deadline::new(c.try_clone().map_err(|e| Error::msg(format!("cannot send a frame: {e}")))?, d);
    w.write_all(&f).and_then(|()| w.flush()).map_err(|e| Error::msg(format!("cannot send a frame: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(f: &[u8]) -> &[u8] {
        &f[4..]
    }

    #[test]
    fn each_message_checks_against_its_table() {
        let e = [5u8; 32];
        for (f, ty) in [
            (challenge(&e, true), t::T_RELAY_CHALLENGE),
            (registered(&[9; 32], &[8; 32], "fd00::1"), t::T_RELAY_REGISTERED),
            (error(&"x".repeat(300)), t::T_RELAY_ERROR),
        ] {
            assert_eq!(cbb_core::msg::check(body(&f)), Ok(ty));
        }
        let name = b64(&[3; 32]);
        let ticket = b64(&[4; 16]);
        let call = note(&Note { call: name.clone(), ticket: ticket.clone(), ..Note::default() }).unwrap();
        assert_eq!(cbb_core::msg::check(body(&call)), Ok(t::T_RELAY_CALL));
        let online = note(&Note { online: Some(vec![name.clone(), b64(&[1; 32])]), ..Note::default() }).unwrap();
        assert_eq!(cbb_core::msg::check(body(&online)), Ok(t::T_RELAY_ONLINE));
        let nobody = note(&Note { online: Some(vec![]), ..Note::default() }).unwrap();
        assert_eq!(cbb_core::msg::check(body(&nobody)), Ok(t::T_RELAY_ONLINE));
        let ok = note(&Note { ok: true, ..Note::default() }).unwrap();
        assert_eq!(cbb_core::msg::check(body(&ok)), Ok(t::T_RELAY_OK));
        assert!(note(&Note { call: "not base64 of 32".into(), ticket, ..Note::default() }).is_none());

        // The requests, as a device of 0.6 writes them.
        let dial = msg(t::T_RELAY_DIAL, vec![(2, Value::Bytes(&[3; 32]))]);
        assert_eq!(request(body(&dial)).unwrap().dial, name);
        let answer = msg(t::T_RELAY_ANSWER, vec![(2, Value::Bytes(&[4; 16]))]);
        assert_eq!(request(body(&answer)).unwrap().answer, b64(&[4; 16]));
        assert!(request(body(&msg(t::T_RELAY_WATCH, vec![]))).unwrap().watch);
        assert!(request(body(&msg(t::T_RELAY_DIAL, vec![(2, Value::Bytes(&[3; 31]))]))).is_err());
    }

    /// A peer that sends a byte now and then, each well within the time a
    /// read may wait, still runs out of the request's time.
    #[test]
    fn a_request_has_one_deadline() {
        use std::io::Write as _;
        use std::time::Instant;
        let ln = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut peer = TcpStream::connect(ln.local_addr().unwrap()).unwrap();
        let (c, _) = ln.accept().unwrap();
        let dribble = std::thread::spawn(move || {
            // A frame of 1024 bytes, one byte every 100 ms.
            let _ = peer.write_all(&1024u32.to_be_bytes());
            for _ in 0..30 {
                std::thread::sleep(Duration::from_millis(100));
                if peer.write_all(b" ").is_err() {
                    return;
                }
            }
        });
        let start = Instant::now();
        assert!(read_request(&c, Duration::from_millis(600)).is_err());
        let took = start.elapsed();
        assert!(took < Duration::from_millis(1500), "the request took {took:?}");
        drop(c);
        dribble.join().unwrap();
    }

    #[test]
    fn frames_are_read_exactly() {
        let mut buf = msg(t::T_RELAY_OK, vec![]);
        let n = buf.len();
        buf.extend_from_slice(b"after");
        let mut r = &buf[..];
        assert_eq!(read(&mut r, MAX_FRAME).unwrap().0, t::T_RELAY_OK);
        assert_eq!(r, b"after");
        assert_eq!(n, 4 + 64, "on the grid");
        let mut big = &(u32::try_from(MAX_FRAME + 1).unwrap().to_be_bytes())[..];
        assert!(read(&mut big, MAX_FRAME).is_err());
    }

    /// Over random frames: a frame is never read past its end, nor taken
    /// without its length, cut short, off the grid or over the limit.
    #[test]
    fn random_frames_are_read_exactly() {
        let mut x = 2026u64;
        let mut next = move |n: usize| {
            x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            ((x >> 33) as usize) % n
        };
        let seeds = [
            msg(t::T_RELAY_WATCH, vec![]),
            msg(t::T_RELAY_DIAL, vec![(2, Value::Bytes(&[3; 32]))]),
            msg(t::T_RELAY_ANSWER, vec![(2, Value::Bytes(&[4; 16]))]),
            challenge(&[5; 32], true),
        ];
        let limit = super::super::wire::MAX_LINE;
        for i in 0..20_000 {
            let seed = &seeds[i % seeds.len()][4..];
            let n = match next(5) {
                0 => seed.len(),
                1 => next(limit + 2),
                2 => 0,
                3 => limit + 1 + next(1 << 20),
                _ => seed.len() + 64 * next(4),
            };
            let mut data = u32::try_from(n).unwrap().to_be_bytes().to_vec();
            data.extend_from_slice(seed);
            for _ in 0..next(64) {
                data.push(next(256) as u8);
            }
            data.truncate(next(data.len() + 1).max(data.len().min(next(2) * data.len())));
            let mut r = &data[..];
            let got = read(&mut r, limit);
            if data.len() < 4 + n || frame::length(n.to_be_bytes()[4..].try_into().unwrap(), limit).is_err() {
                assert!(got.is_err(), "a frame of {n} bytes, {} in all", data.len());
                continue;
            }
            if let Ok((_, body)) = got {
                assert_eq!(body, &data[4..4 + n]);
                assert_eq!(r, &data[4 + n..], "read past the frame");
                let _ = request(&body);
            }
        }
    }

    #[test]
    fn a_claim_round_trips() {
        let r = Register { key: [1; 32], proof: [2; 32], credentials: vec![], root: Some(vec![4; 65]) };
        // Without credentials it breaks the table (one at least).
        assert!(Register::read(body(&r.write())).is_err());
        let mut x = std::io::Cursor::new(challenge(&[5; 32], false));
        let (ty, _) = read(&mut x, MAX_FRAME).unwrap();
        assert_eq!(ty, t::T_RELAY_CHALLENGE);
    }
}
