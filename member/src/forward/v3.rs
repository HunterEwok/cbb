// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The forwarder's messages of 0.6 (`cbb-forward/3`, format section 9.4):
//! the registration's (`forward/challenge`, `register`, `registered`,
//! `error`, t 80 to 83) and, on the registration's connection after it,
//! `forward/seen` (t 84), each one frame of the format. Both ends are
//! written here: the hub's in `forward`, the forwarder's for the tests
//! (the forwarder itself is Go's `internal/forward`, held to these by the
//! vectors).

use cbb_core::format::cbor::Value;
use cbb_core::format::{Alg, Key, frame};
use cbb_core::msg::tables as t;

use crate::error::{Error, Result};

/// The protocol of a hub's registration.
pub const PROTOCOL: &[u8] = b"cbb-forward/3";

fn msg(ty: u64, mut fields: Vec<(u16, Value<'_>)>) -> Vec<u8> {
    fields.insert(0, (frame::FIELD_T, Value::Uint(ty)));
    frame::write(&Value::Map(fields))
}

fn read<'a>(body: &'a [u8], what: &str) -> Result<(u64, Value<'a>)> {
    let (ty, v, _) =
        cbb_core::msg::read_noted(body).map_err(|r| Error::msg(format!("the {what}'s message breaks {r}")))?;
    Ok((ty, v))
}

fn refused(v: &Value<'_>) -> Error {
    let why = v.get(2).and_then(Value::as_text).unwrap_or("no reason");
    Error::msg(format!("the forwarder refused the registration: {why}"))
}

/// The forwarder's challenge: its ephemeral X25519 key.
#[cfg(test)]
pub fn challenge(e: &[u8; 32]) -> Vec<u8> {
    msg(t::T_FWD_CHALLENGE, vec![(2, Value::Bytes(e))])
}

/// Reads the forwarder's challenge, its key.
pub fn read_challenge(body: &[u8]) -> Result<[u8; 32]> {
    let (ty, v) = read(body, "forwarder")?;
    match ty {
        t::T_FWD_CHALLENGE => {}
        t::T_FWD_ERROR => return Err(refused(&v)),
        _ => return Err(Error::msg("registering with the forwarder: not its challenge")),
    }
    v.get(2)
        .and_then(Value::as_bytes)
        .and_then(|b| <[u8; 32]>::try_from(b).ok())
        .ok_or_else(|| Error::msg("registering with the forwarder: a bad challenge"))
}

/// What a hub registers with: its WireGuard key and the proof that it
/// holds it, the group's AmneziaWG settings (their encoding, format table
/// `obfuscation`), the group's VLESS user ID, and the period's hubs'
/// credential of the forwarder's face.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Register {
    pub key: [u8; 32],
    pub proof: [u8; 32],
    pub obfuscation: Option<Vec<u8>>,
    pub vless: Option<[u8; 16]>,
    pub credentials: Vec<Vec<u8>>,
}

impl Register {
    pub fn write(&self) -> Vec<u8> {
        let creds: Vec<Value<'_>> =
            self.credentials.iter().filter_map(|e| cbb_core::format::cbor::decode(e).ok()).collect();
        let obf = self.obfuscation.as_deref().and_then(|b| cbb_core::format::cbor::decode(b).ok());
        let mut f = vec![(2, Key::new(Alg::X25519, &self.key).to_value()), (3, Value::Bytes(&self.proof))];
        if let Some(o) = obf {
            f.push((4, o));
        }
        if let Some(id) = &self.vless {
            f.push((5, Value::Bytes(id)));
        }
        f.push((6, Value::Array(creds)));
        msg(t::T_FWD_REGISTER, f)
    }

    /// Reads message `forward/register` (its body), as the forwarder does.
    #[cfg(test)]
    pub fn read(body: &[u8]) -> Result<Register> {
        let (ty, v) = read(body, "hub")?;
        if ty != t::T_FWD_REGISTER {
            return Err(Error::msg("not a registration"));
        }
        let key = v.get(2).and_then(|k| Key::from_value(k).ok()).and_then(|k| <[u8; 32]>::try_from(k.public).ok());
        let proof = v.get(3).and_then(Value::as_bytes).and_then(|b| <[u8; 32]>::try_from(b).ok());
        let (Some(key), Some(proof)) = (key, proof) else { return Err(Error::msg("a registration without its key")) };
        Ok(Register {
            key,
            proof,
            obfuscation: v.get(4).map(Value::encode),
            vless: v.get(5).and_then(Value::as_bytes).and_then(|b| <[u8; 16]>::try_from(b).ok()),
            credentials: v.get(6).and_then(Value::as_array).unwrap_or(&[]).iter().map(Value::encode).collect(),
        })
    }
}

/// How the hub's clients reach the forwarder over VLESS with XHTTP: the
/// group's user ID, and the web server's port, site and path.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Way {
    pub user: [u8; 16],
    pub port: Option<u16>,
    pub host: String,
    pub path: String,
}

/// The forwarder's answer: the registration's ID for the hellos, the key of
/// their mask, and the way over VLESS when the hub asked for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Registered {
    pub id: u64,
    pub mask: [u8; 32],
    pub vless: Option<Way>,
}

impl Registered {
    #[cfg(test)]
    pub fn write(&self) -> Vec<u8> {
        let mut f = vec![(2, Value::Uint(self.id)), (3, Value::Bytes(&self.mask))];
        let way;
        if let Some(w) = &self.vless {
            let mut m = vec![(1, Value::Bytes(&w.user))];
            if let Some(p) = w.port {
                m.push((2, Value::Uint(u64::from(p))));
            }
            if !w.host.is_empty() {
                m.push((3, Value::Text(&w.host)));
            }
            if !w.path.is_empty() {
                m.push((4, Value::Text(&w.path)));
            }
            way = Value::Map(m);
            f.push((4, way));
        }
        msg(t::T_FWD_REGISTERED, f)
    }

    /// Reads the forwarder's answer; its reason when it refused.
    pub fn read(body: &[u8]) -> Result<Registered> {
        let (ty, v) = read(body, "forwarder")?;
        match ty {
            t::T_FWD_REGISTERED => {}
            t::T_FWD_ERROR => return Err(refused(&v)),
            _ => return Err(Error::msg("registering with the forwarder: not its answer")),
        }
        let id = v.get(2).and_then(Value::as_uint).unwrap_or(0);
        let mask = v.get(3).and_then(Value::as_bytes).and_then(|b| <[u8; 32]>::try_from(b).ok());
        let Some(mask) = mask else {
            return Err(Error::msg("registering with the forwarder: no key for the hellos' mask"));
        };
        let vless = v.get(4).and_then(|w| {
            Some(Way {
                user: w.get(1).and_then(Value::as_bytes).and_then(|b| <[u8; 16]>::try_from(b).ok())?,
                port: w.get(2).and_then(Value::as_uint).and_then(|p| u16::try_from(p).ok()),
                host: w.get(3).and_then(Value::as_text).unwrap_or_default().to_string(),
                path: w.get(4).and_then(Value::as_text).unwrap_or_default().to_string(),
            })
        });
        Ok(Registered { id, mask, vless })
    }
}

/// Why the forwarder refused, cut to the format's 256 bytes.
#[cfg(test)]
pub fn error(reason: &str) -> Vec<u8> {
    let mut end = reason.len().min(256);
    while !reason.is_char_boundary(end) {
        end -= 1;
    }
    msg(t::T_FWD_ERROR, vec![(2, Value::Text(&reason[..end]))])
}

/// Where the forwarder sees the hub's WireGuard port.
#[cfg(test)]
pub fn seen(addr: &str) -> Vec<u8> {
    msg(t::T_FWD_SEEN, vec![(2, Value::Text(addr))])
}

/// Reads a message after the registration: where the forwarder sees the
/// hub (None for another kind, which the hub passes over).
pub fn read_seen(body: &[u8]) -> Option<String> {
    let (ty, v) = read(body, "forwarder").ok()?;
    (ty == t::T_FWD_SEEN).then(|| v.get(2).and_then(Value::as_text).map(str::to_string)).flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(f: &[u8]) -> &[u8] {
        &f[4..]
    }

    #[test]
    fn each_message_reads_as_written_and_checks_against_its_table() {
        let e = [5u8; 32];
        assert_eq!(read_challenge(body(&challenge(&e))).unwrap(), e);
        let r = Register {
            key: [7; 32],
            proof: [6; 32],
            obfuscation: None,
            vless: Some([3; 16]),
            credentials: crate::nettest::blind::Blind::new(1).hub_credential(0, 1, &[0]).credentials,
        };
        let f = r.write();
        assert_eq!(cbb_core::msg::check(body(&f)), Ok(t::T_FWD_REGISTER));
        assert_eq!(Register::read(body(&f)).unwrap(), r);
        for a in [
            Registered { id: 9, mask: [8; 32], vless: None },
            Registered {
                id: 1 << 40,
                mask: [8; 32],
                vless: Some(Way { user: [3; 16], port: Some(443), host: "cbb.tools".into(), path: "/p/x".into() }),
            },
        ] {
            let f = a.write();
            assert_eq!(cbb_core::msg::check(body(&f)), Ok(t::T_FWD_REGISTERED));
            assert_eq!(Registered::read(body(&f)).unwrap(), a);
        }
        let no = Registered::read(body(&error(&"x".repeat(300)))).unwrap_err();
        assert!(no.to_string().contains(&"x".repeat(256)) && !no.to_string().contains(&"x".repeat(257)), "{no}");
        assert!(read_challenge(body(&error("full"))).unwrap_err().to_string().contains("full"));
        assert_eq!(read_seen(body(&seen("203.0.113.9:51820"))).as_deref(), Some("203.0.113.9:51820"));
        assert_eq!(read_seen(body(&challenge(&e))), None);
        assert!(Register::read(body(&challenge(&e))).is_err());
    }
}
