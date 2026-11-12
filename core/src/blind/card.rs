// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! A server card (A-54, format section 8, label `cbb server card v1`): an
//! operator's signed word on its server, its name, addresses, TLS keys,
//! what it is and which ways around a block it offers, until when. A group
//! adds a server by its card (a QR code or a link from the operator); the
//! operator then changes keys and addresses with a new version, and nobody
//! types them again. The project's own list stays apart, signed by the
//! project's key, and the apps show whose server it is.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::format::sig::LABEL_SERVER_CARD;
use crate::format::{Alg, Envelope, Key, KeyHash, Rule, Value};

/// A card's body ceiling: as a credential's.
pub const MAX_BODY: usize = 16 * 1024;
pub const MAX_ENDPOINTS: usize = 8;
pub const MAX_KEYS: usize = 4;

/// What the server is (field 13).
pub const KIND_FORWARDER: u64 = 1;
pub const KIND_RELAY: u64 = 2;
/// The ways it offers (field 14).
pub const PATH_WIREGUARD: u64 = 1;
pub const PATH_AMNEZIAWG: u64 = 2;
pub const PATH_VLESS: u64 = 4;

pub const RULE_SHAPE: Rule = Rule::field("card/shape");
pub const RULE_NAME: Rule = Rule::field("card/name");
pub const RULE_ENDPOINTS: Rule = Rule::field("card/endpoints");
pub const RULE_KEYS: Rule = Rule::field("card/keys");
pub const RULE_KINDS: Rule = Rule::field("card/kinds");
pub const RULE_PATHS: Rule = Rule::field("card/paths");

/// A server card.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Card {
    /// The operator's key, its point.
    pub operator: Vec<u8>,
    pub version: u64,
    pub expires_ms: u64,
    pub name: String,
    /// `host:port`, or a host name with its port.
    pub endpoints: Vec<String>,
    /// The server's TLS keys, points.
    pub keys: Vec<Vec<u8>>,
    pub kinds: u64,
    pub paths: u64,
}

impl Card {
    /// The body's encoding, as the operator signs it.
    pub fn body(&self) -> Vec<u8> {
        let es = Alg::Es256.number();
        let mut m: Vec<(u16, Value<'_>)> = alloc::vec![
            (1, Value::Uint(1)),
            (3, Value::Array(alloc::vec![Value::Uint(es), Value::Bytes(&self.operator)])),
            (4, Value::Uint(self.version)),
            (7, Value::Uint(self.expires_ms)),
            (10, Value::Text(&self.name)),
            (11, Value::Array(self.endpoints.iter().map(|e| Value::Text(e)).collect())),
            (
                12,
                Value::Array(
                    self.keys.iter().map(|k| Value::Array(alloc::vec![Value::Uint(es), Value::Bytes(k)])).collect()
                )
            ),
            (13, Value::Uint(self.kinds)),
        ];
        if self.paths != 0 {
            m.push((14, Value::Uint(self.paths)));
        }
        Value::Map(m).encode()
    }

    /// Signs the card with the operator's key.
    pub fn sign(&self, operator: &dyn crate::identity::ExternalKey) -> crate::error::Result<Vec<u8>> {
        let body = self.body();
        let sig = crate::records::key::sign_es256(operator, LABEL_SERVER_CARD, &body)?;
        Ok(crate::format::envelope::write(&body, &sig, None))
    }

    /// Reads a card: its form, its fields, its signature by the operator's
    /// key in it.
    pub fn read(b: &[u8]) -> Result<Card, Rule> {
        let env = Envelope::parse_limited(b, MAX_BODY)?;
        if env.sig2.is_some() {
            return Err(Rule::FORM_CRITICAL);
        }
        let m = &env.map;
        for (k, _) in m.as_map().unwrap_or(&[]) {
            if !matches!(k, 1 | 3 | 4 | 7 | 10..=14) && *k < 256 {
                return Err(Rule::FORM_CRITICAL);
            }
        }
        if m.get(1).and_then(Value::as_uint) != Some(1) {
            return Err(RULE_SHAPE);
        }
        let op = Key::from_value(m.get(3).ok_or(RULE_SHAPE)?).map_err(|_| RULE_SHAPE)?;
        if op.alg != Alg::Es256 || op.check().is_err() {
            return Err(RULE_SHAPE);
        }
        let version = m.get(4).and_then(Value::as_uint).filter(|v| *v >= 1).ok_or(RULE_SHAPE)?;
        let expires_ms = m.get(7).and_then(Value::as_uint).filter(|v| *v >= 1).ok_or(RULE_SHAPE)?;
        let name = m.get(10).and_then(Value::as_text).filter(|n| crate::join::info::valid_name(n)).ok_or(RULE_NAME)?;
        let eps = m.get(11).and_then(Value::as_array).ok_or(RULE_ENDPOINTS)?;
        if eps.is_empty() || eps.len() > MAX_ENDPOINTS || !crate::msg::each_once(eps) {
            return Err(RULE_ENDPOINTS);
        }
        let mut endpoints = Vec::new();
        for e in eps {
            let t = e.as_text().filter(|t| valid_endpoint(t)).ok_or(RULE_ENDPOINTS)?;
            endpoints.push(t.to_string());
        }
        let ks = m.get(12).and_then(Value::as_array).ok_or(RULE_KEYS)?;
        if ks.is_empty() || ks.len() > MAX_KEYS || !crate::msg::sorted(ks) {
            return Err(RULE_KEYS);
        }
        let mut keys = Vec::new();
        for k in ks {
            let k = Key::from_value(k).map_err(|_| RULE_KEYS)?;
            if k.alg != Alg::Es256 || k.check().is_err() {
                return Err(RULE_KEYS);
            }
            keys.push(k.public.to_vec());
        }
        let kinds = m.get(13).and_then(Value::as_uint).ok_or(RULE_KINDS)?;
        if kinds == 0 || kinds & !(KIND_FORWARDER | KIND_RELAY) != 0 {
            return Err(RULE_KINDS);
        }
        let paths = match m.get(14) {
            None => 0,
            Some(p) => p
                .as_uint()
                .filter(|p| *p != 0 && p & !(PATH_WIREGUARD | PATH_AMNEZIAWG | PATH_VLESS) == 0)
                .ok_or(RULE_PATHS)?,
        };
        env.verify(op.public, LABEL_SERVER_CARD)?;
        Ok(Card {
            operator: op.public.to_vec(),
            version,
            expires_ms,
            name: name.to_string(),
            endpoints,
            keys,
            kinds,
            paths,
        })
    }

    /// The operator's key hash, by which a group knows the card's later
    /// versions.
    pub fn operator_hash(&self) -> KeyHash {
        Key::new(Alg::Es256, &self.operator).hash()
    }

    /// The pins of the server's TLS keys.
    pub fn pins(&self) -> Vec<KeyHash> {
        self.keys.iter().map(|k| Key::new(Alg::Es256, k).hash()).collect()
    }

    /// Whether `newer` may replace this card: the same operator, a higher
    /// version.
    pub fn replaced_by(&self, newer: &Card) -> bool {
        newer.operator == self.operator && newer.version > self.version
    }
}

/// `host:port`: a public IP address with its port (an `addr`, see
/// [`public_ip`]), or a DNS name (lower-case letters, digits, hyphens and
/// dots, at most 253 bytes, no label starting or ending with a hyphen, its
/// last label neither all digits nor starting with `0x`, so no resolver
/// reads it as a number, nor `localhost` or `local`) with its port.
fn valid_endpoint(t: &str) -> bool {
    if let Ok(a) = t.parse::<core::net::SocketAddr>() {
        return public_ip(a.ip()) && crate::msg::valid_addr(t);
    }
    let Some((host, port)) = t.rsplit_once(':') else { return false };
    let last = host.rsplit('.').next().unwrap_or_default();
    port.parse::<u16>().is_ok_and(|p| p != 0)
        && !(port.len() > 1 && port.starts_with('0'))
        && !host.is_empty()
        && host.len() <= 253
        && !last.bytes().all(|b| b.is_ascii_digit())
        && !last.starts_with("0x")
        && last != "localhost"
        && last != "local"
        && host.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && !l.starts_with('-')
                && !l.ends_with('-')
        })
}

/// Whether an IPv4 address may stand in a card: none of this network
/// (0/8), private (10/8, 172.16/12, 192.168/16), shared (100.64/10),
/// loopback (127/8), link-local (169.254/16), multicast (224/4) or
/// reserved (240/4).
fn public_v4(a: core::net::Ipv4Addr) -> bool {
    let [x, y, ..] = a.octets();
    !(x == 0
        || x == 10
        || x == 127
        || x >= 224
        || (x == 172 && (16..32).contains(&y))
        || (x == 192 && y == 168)
        || (x == 100 && (64..128).contains(&y))
        || (x == 169 && y == 254))
}

/// Whether an address may stand in a card, which is for a public server:
/// a public IPv4 address ([`public_v4`]), or an IPv6 address that is not
/// loopback, unspecified, multicast, link-local, site-local (fec0::/10) or
/// unique-local (fc00::/7), nor carries a refused IPv4 address in a
/// translated (::ffff:0:0/96), NAT64 (64:ff9b::/96) or 6to4 (2002::/16)
/// form.
fn public_ip(ip: core::net::IpAddr) -> bool {
    match ip {
        core::net::IpAddr::V4(v4) => public_v4(v4),
        core::net::IpAddr::V6(v6) => {
            let o = v6.octets();
            let s = v6.segments();
            let embedded =
                |b: &[u8]| -> bool { <[u8; 4]>::try_from(b).is_ok_and(|q| public_v4(core::net::Ipv4Addr::from(q))) };
            let first = s.first().copied().unwrap_or(0);
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (first & 0xffc0) == 0xfe80
                || (first & 0xffc0) == 0xfec0
                || (first & 0xfe00) == 0xfc00
                || (s.get(..6) == Some(&[0, 0, 0, 0, 0xffff, 0][..]) && !embedded(o.get(12..).unwrap_or_default()))
                || (s.get(..6) == Some(&[0x64, 0xff9b, 0, 0, 0, 0][..]) && !embedded(o.get(12..).unwrap_or_default()))
                || (first == 0x2002 && !embedded(o.get(2..6).unwrap_or_default())))
        }
    }
}
