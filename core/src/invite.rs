// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The remote invitation (docs/protocol.md, section 12): what a device that
//! shares no network with the group needs to join it through the hub's
//! tunnel. parse reads its text exactly as Go's internal/invite does, and
//! both are checked on testdata/interop/invites.json, so that a text one
//! takes the other takes too.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::net::SocketAddr;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Map, Value};
use zeroize::Zeroize;

use crate::strict;

/// The start of an invitation's text.
pub const PREFIX: &str = "cbb://invite#";
/// The shortest pairing secret an invitation carries.
pub const MIN_SECRET: usize = 16;
/// The longest pairing secret an invitation carries.
pub const MAX_SECRET: usize = 64;
/// The most hub addresses an invitation holds.
pub const MAX_ENDPOINTS: usize = 8;

/// Why parse refused a text, the same as Go's invite.Reason.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    /// Not the invitation's prefix.
    NotInvitation,
    /// Not standard base64, not strict JSON, a field missing, unknown or of another type.
    Damaged,
    /// A `v` other than 1.
    Version,
    /// `g` is not a group tag.
    Group,
    /// `h` is not a device ID.
    Hub,
    /// `hk`, `k` or `psk` is not 32 bytes, or all zeros.
    Key,
    /// `ep` is empty, longer than 8, or holds an address that is not ip:port.
    Endpoints,
    /// `s` is shorter than 16 bytes or longer than 64.
    Secret,
    /// `exp` is not after 0.
    Expiry,
    /// `o` is damaged.
    Obfuscation,
    /// `x` is damaged.
    Vless,
}

impl Reason {
    /// The reason's name, as Go and the vectors write it.
    pub fn name(self) -> &'static str {
        match self {
            Reason::NotInvitation => "not_invitation",
            Reason::Damaged => "damaged",
            Reason::Version => "version",
            Reason::Group => "group",
            Reason::Hub => "hub",
            Reason::Key => "key",
            Reason::Endpoints => "endpoints",
            Reason::Secret => "secret",
            Reason::Expiry => "expiry",
            Reason::Obfuscation => "obfuscation",
            Reason::Vless => "vless",
        }
    }

    /// A sentence for the user.
    pub fn message(self) -> &'static str {
        match self {
            Reason::NotInvitation => "this is not a cbb invitation",
            Reason::Damaged => "the invitation is damaged",
            Reason::Version => "the invitation is of another version; update cbb",
            Reason::Group => "the invitation names no group",
            Reason::Hub => "the invitation names no hub",
            Reason::Key => "the invitation lacks a key",
            Reason::Endpoints => "the invitation has no hub address, too many, or one that is not ip:port",
            Reason::Secret => "the invitation's secret is too short or too long",
            Reason::Expiry => "the invitation has no expiry",
            Reason::Obfuscation => "the invitation's obfuscation settings are damaged",
            Reason::Vless => "the invitation's VLESS settings are damaged",
        }
    }
}

impl core::fmt::Display for Reason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.message())
    }
}

/// A range of a message's type field, inclusive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Range {
    pub min: u32,
    pub max: u32,
}

impl Range {
    fn overlaps(self, o: Range) -> bool {
        self.min <= o.max && o.min <= self.max
    }
}

/// The hub's AmneziaWG settings (docs/protocol.md, section 11,
/// "Obfuscation"), checked as Go's tunnel.Obfuscation.Check.
#[derive(Clone, PartialEq, Eq)]
pub struct Obfuscation {
    pub jc: u32,
    pub jmin: u32,
    pub jmax: u32,
    pub s: [u32; 4],
    pub h: [Range; 4],
    pub header_protection_key: [u8; 32],
}

impl core::fmt::Debug for Obfuscation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Obfuscation")
            .field("jc", &self.jc)
            .field("jmin", &self.jmin)
            .field("jmax", &self.jmax)
            .field("s", &self.s)
            .field("h", &self.h)
            .field("header_protection_key", &crate::secret::Redacted(self.header_protection_key.len()))
            .finish()
    }
}

/// An invitation that parse took.
#[derive(Clone, PartialEq, Eq)]
pub struct Invitation {
    pub group: String,
    pub hub: String,
    pub hub_key: [u8; 32],
    pub endpoints: Vec<SocketAddr>,
    pub guest_key: [u8; 32],
    pub guest_psk: [u8; 32],
    pub secret: Vec<u8>,
    /// When it expires, Unix seconds.
    pub expires: i64,
    pub obfuscation: Option<Obfuscation>,
    /// The way to the hub's forwarder over VLESS with XHTTP, as the hub's
    /// offer gives it (docs/protocol.md, section 11, "VLESS"), for a guest
    /// whose network lets no UDP through.
    pub vless: Option<Vless>,
}

impl Drop for Invitation {
    fn drop(&mut self) {
        self.guest_key.zeroize();
        self.guest_psk.zeroize();
        self.secret.zeroize();
    }
}

impl Drop for Obfuscation {
    fn drop(&mut self) {
        self.header_protection_key.zeroize();
    }
}

impl core::fmt::Debug for Invitation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Invitation")
            .field("group", &self.group)
            .field("hub", &self.hub)
            .field("hub_key", &self.hub_key)
            .field("endpoints", &self.endpoints)
            .field("guest_key", &crate::secret::Redacted(self.guest_key.len()))
            .field("guest_psk", &crate::secret::Redacted(self.guest_psk.len()))
            .field("secret", &crate::secret::Redacted(self.secret.len()))
            .field("expires", &self.expires)
            .field("obfuscation", &self.obfuscation)
            .field("vless", &self.vless)
            .finish()
    }
}

/// The VLESS settings of an invitation: those of the hub's offer, with
/// XHTTP only.
#[derive(Clone, PartialEq, Eq)]
pub struct Vless {
    /// The web server's address, `ip:port`.
    pub endpoint: String,
    /// The site's name, which its certificate must carry.
    pub server_name: String,
    /// The path the web server passes to the forwarder.
    pub path: String,
    /// The group's VLESS user ID, a UUID in lowercase.
    pub id: String,
}

impl core::fmt::Debug for Vless {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Vless")
            .field("endpoint", &self.endpoint)
            .field("server_name", &self.server_name)
            .field("path", &self.path)
            .field("id", &crate::secret::Redacted(self.id.len()))
            .finish()
    }
}

impl Vless {
    /// The settings as a hub's offer carries them, which the tunnels take.
    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("transport".into(), Value::from("xhttp"));
        m.insert("endpoint".into(), Value::from(self.endpoint.as_str()));
        m.insert("server_name".into(), Value::from(self.server_name.as_str()));
        m.insert("path".into(), Value::from(self.path.as_str()));
        m.insert("id".into(), Value::from(self.id.as_str()));
        Value::Object(m)
    }
}

/// The VLESS settings of a hub's offer for an invitation: None for none or
/// for REALITY, which a phone or cbb cannot speak.
pub fn vless_from_offer(v: &Value) -> Option<Vless> {
    let o = v.as_object()?;
    // An offer's REALITY fields come absent or null with XHTTP.
    let o: Map<String, Value> = o.iter().filter(|(_, v)| !v.is_null()).map(|(k, v)| (k.clone(), v.clone())).collect();
    vless_fields(&o).ok()
}

const VLESS_FIELDS: [&str; 5] = ["transport", "endpoint", "server_name", "path", "id"];

/// Reads `x` as Go's decoder does: an unknown field or one of another type
/// is damage, a missing one makes the settings refused.
fn vless_fields(o: &Map<String, Value>) -> Result<Vless, Reason> {
    if o.keys().any(|k| !VLESS_FIELDS.contains(&k.as_str())) {
        return Err(Reason::Damaged);
    }
    if o.values().any(|v| !v.is_string()) {
        return Err(Reason::Damaged);
    }
    let s = |k: &str| o.get(k).and_then(Value::as_str).ok_or(Reason::Vless);
    let (transport, endpoint, server_name, path, id) =
        (s("transport")?, s("endpoint")?, s("server_name")?, s("path")?, s("id")?);
    if transport != "xhttp" || parse_endpoint(endpoint).is_none() {
        return Err(Reason::Vless);
    }
    crate::vless::check_server_name(server_name).map_err(|_| Reason::Vless)?;
    crate::vless::check_path(path).map_err(|_| Reason::Vless)?;
    crate::vless::parse_id(id).map_err(|_| Reason::Vless)?;
    Ok(Vless {
        endpoint: endpoint.to_string(),
        server_name: server_name.to_string(),
        path: path.to_string(),
        id: id.to_string(),
    })
}

impl Invitation {
    /// Whether it has expired at now, Unix seconds. With no known time the
    /// caller does not know, and must not join on it.
    pub fn expired(&self, now: i64) -> bool {
        now >= self.expires
    }

    /// The invitation as the core's entry point answers it, and as the
    /// valid cases of testdata/interop/invites.json write it: keys and the
    /// secret in base64, addresses as ip:port, ranges as "min-max".
    pub fn to_json(&self) -> Value {
        let b64 = |b: &[u8]| Value::from(STANDARD.encode(b));
        let eps: Vec<Value> = self.endpoints.iter().map(|e| Value::from(e.to_string())).collect();
        let mut m = Map::new();
        m.insert("group".into(), Value::from(self.group.as_str()));
        m.insert("hub".into(), Value::from(self.hub.as_str()));
        m.insert("hub_key".into(), b64(&self.hub_key));
        m.insert("endpoints".into(), Value::Array(eps));
        m.insert("guest_key".into(), b64(&self.guest_key));
        m.insert("guest_psk".into(), b64(&self.guest_psk));
        m.insert("secret".into(), b64(&self.secret));
        m.insert("expires".into(), Value::from(self.expires));
        m.insert("obfuscation".into(), self.obfuscation.as_ref().map_or(Value::Null, Obfuscation::to_json));
        m.insert("vless".into(), self.vless.as_ref().map_or(Value::Null, Vless::to_json));
        Value::Object(m)
    }
}

impl Invitation {
    /// The invitation's text, `cbb://invite#` and its JSON in standard
    /// base64, with the fields in the order Go's invite.String writes them,
    /// so that both make the same text of one invitation.
    pub fn to_text(&self) -> String {
        let b64 = |b: &[u8]| STANDARD.encode(b);
        let eps: Vec<String> = self.endpoints.iter().map(|e| alloc::format!("\"{e}\"")).collect();
        let mut j = alloc::format!(
            "{{\"v\":1,\"g\":\"{}\",\"h\":\"{}\",\"hk\":\"{}\",\"ep\":[{}],\"k\":\"{}\",\"psk\":\"{}\",\"s\":\"{}\",\"exp\":{}",
            self.group,
            self.hub,
            b64(&self.hub_key),
            eps.join(","),
            b64(&self.guest_key),
            b64(&self.guest_psk),
            b64(&self.secret),
            self.expires
        );
        if let Some(o) = &self.obfuscation {
            let [s1, s2, s3, s4] = o.s;
            let [h1, h2, h3, h4] = o.h;
            j.push_str(&alloc::format!(
                ",\"o\":{{\"jc\":{},\"jmin\":{},\"jmax\":{},\"s1\":{s1},\"s2\":{s2},\"s3\":{s3},\"s4\":{s4},\"h1\":\"{}-{}\",\"h2\":\"{}-{}\",\"h3\":\"{}-{}\",\"h4\":\"{}-{}\",\"header_protection_key\":\"{}\"}}",
                o.jc,
                o.jmin,
                o.jmax,
                h1.min,
                h1.max,
                h2.min,
                h2.max,
                h3.min,
                h3.max,
                h4.min,
                h4.max,
                b64(&o.header_protection_key)
            ));
        }
        if let Some(x) = &self.vless {
            j.push_str(&alloc::format!(
                ",\"x\":{{\"transport\":\"xhttp\",\"endpoint\":\"{}\",\"server_name\":\"{}\",\"path\":\"{}\",\"id\":\"{}\"}}",
                x.endpoint, x.server_name, x.path, x.id
            ));
        }
        j.push('}');
        alloc::format!("{PREFIX}{}", STANDARD.encode(j.as_bytes()))
    }
}

/// The WireGuard public key of a guest's private key (X25519), which the
/// hub admits as the guest's peer.
pub fn guest_public(private: &[u8; 32]) -> [u8; 32] {
    x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(*private)).to_bytes()
}

impl Obfuscation {
    /// The settings as a hub's offer carries them.
    pub fn to_json(&self) -> Value {
        let r = |r: Range| Value::from(alloc::format!("{}-{}", r.min, r.max));
        let mut m = Map::new();
        for (k, v) in [("jc", self.jc), ("jmin", self.jmin), ("jmax", self.jmax)] {
            m.insert(k.into(), Value::from(v));
        }
        for (i, (s, h)) in self.s.iter().zip(self.h.iter()).enumerate() {
            let n = i.saturating_add(1);
            m.insert(alloc::format!("s{n}"), Value::from(*s));
            m.insert(alloc::format!("h{n}"), r(*h));
        }
        m.insert("header_protection_key".into(), Value::from(STANDARD.encode(self.header_protection_key)));
        Value::Object(m)
    }
}

const FIELDS: [&str; 11] = ["v", "g", "h", "hk", "ep", "k", "psk", "s", "exp", "o", "x"];
const REQUIRED: [&str; 9] = ["v", "g", "h", "hk", "ep", "k", "psk", "s", "exp"];

/// Reads an invitation's text and checks it; spaces, tabs and line breaks
/// around it are ignored. It does not check the expiry.
pub fn parse(text: &str) -> Result<Invitation, Reason> {
    let text = text.trim_matches([' ', '\t', '\r', '\n']);
    let enc = text.strip_prefix(PREFIX).ok_or(Reason::NotInvitation)?;
    let data = STANDARD.decode(enc).map_err(|_| Reason::Damaged)?;
    strict::check(&data, &["v"]).map_err(|_| Reason::Damaged)?;
    let obj: Map<String, Value> = serde_json::from_slice(&data).map_err(|_| Reason::Damaged)?;
    let version = obj.get("v").and_then(Value::as_i64).ok_or(Reason::Damaged)?;
    if version != 1 {
        return Err(Reason::Version);
    }
    strict::check(&data, &REQUIRED).map_err(|_| Reason::Damaged)?;
    if obj.keys().any(|k| !FIELDS.contains(&k.as_str())) {
        return Err(Reason::Damaged);
    }
    let string = |k: &str| obj.get(k).and_then(Value::as_str).ok_or(Reason::Damaged);
    // Every field has its type before any value is checked, as Go's
    // decoder does.
    let group = string("g")?;
    let hub = string("h")?;
    let (hk, k, psk, s) = (string("hk")?, string("k")?, string("psk")?, string("s")?);
    let eps = obj.get("ep").and_then(Value::as_array).ok_or(Reason::Damaged)?;
    let eps: Vec<&str> = eps.iter().map(|e| e.as_str().ok_or(Reason::Damaged)).collect::<Result<_, _>>()?;
    let expires = obj.get("exp").and_then(Value::as_i64).ok_or(Reason::Damaged)?;
    let obf = match obj.get("o") {
        None => None,
        Some(Value::Object(o)) => Some(obfuscation_fields(o)?),
        Some(_) => return Err(Reason::Damaged),
    };
    let x = match obj.get("x") {
        None => None,
        Some(Value::Object(x)) => Some(x),
        Some(_) => return Err(Reason::Damaged),
    };

    if !is_hex(group, 16) {
        return Err(Reason::Group);
    }
    if !is_hex(hub, 32) {
        return Err(Reason::Hub);
    }
    let hub_key = key(hk).ok_or(Reason::Key)?;
    let guest_key = key(k).ok_or(Reason::Key)?;
    let guest_psk = key(psk).ok_or(Reason::Key)?;
    if eps.is_empty() || eps.len() > MAX_ENDPOINTS {
        return Err(Reason::Endpoints);
    }
    let endpoints = eps.iter().map(|e| parse_endpoint(e).ok_or(Reason::Endpoints)).collect::<Result<Vec<_>, _>>()?;
    let secret = base64_strict(s).filter(|b| (MIN_SECRET..=MAX_SECRET).contains(&b.len())).ok_or(Reason::Secret)?;
    if expires <= 0 {
        return Err(Reason::Expiry);
    }
    let obfuscation = obf.map(|o| o.read().ok_or(Reason::Obfuscation)).transpose()?;
    let vless = x.map(vless_fields).transpose()?;
    Ok(Invitation {
        group: group.to_string(),
        hub: hub.to_string(),
        hub_key,
        endpoints,
        guest_key,
        guest_psk,
        secret,
        expires,
        obfuscation,
        vless,
    })
}

/// Reads an address as ip:port in its canonical form (an IPv6 address in
/// brackets, without a zone), with a port that is not 0.
pub fn parse_endpoint(s: &str) -> Option<SocketAddr> {
    let a: SocketAddr = s.parse().ok()?;
    if a.port() == 0 || a.to_string() != s {
        return None;
    }
    if let SocketAddr::V6(v6) = a
        && (v6.scope_id() != 0 || v6.flowinfo() != 0)
    {
        return None;
    }
    Some(a)
}

fn is_hex(s: &str, n: usize) -> bool {
    s.len() == n && s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

/// Standard base64 in its one form: padded, no stray bits.
fn base64_strict(s: &str) -> Option<Vec<u8>> {
    let b = STANDARD.decode(s).ok()?;
    (STANDARD.encode(&b) == s).then_some(b)
}

fn key(s: &str) -> Option<[u8; 32]> {
    let k: [u8; 32] = base64_strict(s)?.try_into().ok()?;
    (k != [0u8; 32]).then_some(k)
}

/// The fields of `o` with their JSON types, before their values are checked.
struct ObfFields {
    ints: [Option<i64>; 7],
    strs: [Option<String>; 5],
}

const OBF_INTS: [&str; 7] = ["jc", "jmin", "jmax", "s1", "s2", "s3", "s4"];
const OBF_STRS: [&str; 5] = ["h1", "h2", "h3", "h4", "header_protection_key"];

/// AmneziaWG's settings as a hub's offer carries them, checked as parse
/// checks an invitation's.
pub fn obfuscation_from_json(v: &Value) -> Option<Obfuscation> {
    obfuscation_fields(v.as_object()?).ok()?.read()
}

fn obfuscation_fields(o: &Map<String, Value>) -> Result<ObfFields, Reason> {
    if o.keys().any(|k| !OBF_INTS.contains(&k.as_str()) && !OBF_STRS.contains(&k.as_str())) {
        return Err(Reason::Damaged);
    }
    let mut f = ObfFields { ints: [None; 7], strs: Default::default() };
    for (slot, name) in f.ints.iter_mut().zip(OBF_INTS) {
        if let Some(v) = o.get(name) {
            *slot = Some(v.as_i64().ok_or(Reason::Damaged)?);
        }
    }
    for (slot, name) in f.strs.iter_mut().zip(OBF_STRS) {
        if let Some(v) = o.get(name) {
            *slot = Some(v.as_str().ok_or(Reason::Damaged)?.to_string());
        }
    }
    Ok(f)
}

// The bounds of Go's tunnel.Obfuscation.Check.
const MAX_JUNK_COUNT: u32 = 16;
const MAX_JUNK_SIZE: u32 = 1000;
const MIN_PADDING: u32 = 16;
const MAX_PADDING: u32 = 64;
/// WireGuard's highest message type; the headers stay above it.
const MSG_DATA: u32 = 4;

impl ObfFields {
    fn read(self) -> Option<Obfuscation> {
        let mut n = [0u32; 7];
        for (dst, v) in n.iter_mut().zip(self.ints) {
            *dst = u32::try_from(v?).ok()?;
        }
        let [h1, h2, h3, h4, hk] = self.strs;
        let h = [parse_range(&h1?)?, parse_range(&h2?)?, parse_range(&h3?)?, parse_range(&h4?)?];
        let header_protection_key = key(&hk?)?;
        let [jc, jmin, jmax, s1, s2, s3, s4] = n;
        let o = Obfuscation { jc, jmin, jmax, s: [s1, s2, s3, s4], h, header_protection_key };
        o.check().then_some(o)
    }
}

impl Obfuscation {
    fn check(&self) -> bool {
        if self.jc > MAX_JUNK_COUNT || self.jmin > self.jmax || self.jmax > MAX_JUNK_SIZE {
            return false;
        }
        // The three handshake messages keep three sizes once padded. The
        // paddings are at most 64 here, so the sums cannot overflow.
        let [s1, s2, s3, _] = self.s;
        if self.s.iter().any(|s| !(MIN_PADDING..=MAX_PADDING).contains(s)) {
            return false;
        }
        let (a, b, c) = (148u32.saturating_add(s1), 92u32.saturating_add(s2), 64u32.saturating_add(s3));
        if a == b || a == c || b == c {
            return false;
        }
        for (i, h) in self.h.iter().enumerate() {
            if h.min > h.max || h.min <= MSG_DATA {
                return false;
            }
            if self.h.iter().skip(i.saturating_add(1)).any(|o| h.overlaps(*o)) {
                return false;
            }
        }
        true
    }
}

/// Reads "min-max": two decimal numbers of 32 bits, without a sign or a
/// leading zero, the first not above the second.
pub fn parse_range(s: &str) -> Option<Range> {
    let (lo, hi) = s.split_once('-')?;
    let (min, max) = (parse_u32(lo)?, parse_u32(hi)?);
    (min <= max).then_some(Range { min, max })
}

fn parse_u32(s: &str) -> Option<u32> {
    if s.is_empty() || s.len() > 10 || (s.len() > 1 && s.starts_with('0')) || !s.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Every text of testdata/interop/invites.json parses, or is refused,
    /// as in Go.
    #[test]
    fn vectors() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../testdata/interop/invites.json");
        let v: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let valid = v["valid"].as_array().unwrap();
        let refused = v["refused"].as_array().unwrap();
        assert!(valid.len() > 3 && refused.len() > 30);
        for c in valid {
            let name = c["name"].as_str().unwrap();
            let got = parse(c["text"].as_str().unwrap()).unwrap_or_else(|r| panic!("{name}: {r:?}"));
            let mut want = got.to_json();
            want["name"] = json!(name);
            want["text"] = c["text"].clone();
            assert_eq!(&want, c, "{name}");
            // The core's text reads back the same; where Go wrote the text
            // as it writes it, the core writes the same bytes.
            assert_eq!(parse(&got.to_text()).as_ref(), Ok(&got), "{name}");
            if name != "fields in another order" {
                assert_eq!(got.to_text(), c["text"].as_str().unwrap().trim(), "{name}: the text the core writes");
            }
            if let Some(o) = &got.obfuscation {
                assert_eq!(obfuscation_from_json(&o.to_json()).as_ref(), Some(o), "{name}");
            }
        }
        for c in refused {
            let name = c["name"].as_str().unwrap();
            let got = parse(c["text"].as_str().unwrap());
            assert_eq!(got.map_err(Reason::name), Err(c["reason"].as_str().unwrap()), "{name}");
        }
    }

    #[test]
    fn expiry() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../testdata/interop/invites.json");
        let v: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let inv = parse(v["valid"][0]["text"].as_str().unwrap()).unwrap();
        assert!(!inv.expired(inv.expires - 1));
        assert!(inv.expired(inv.expires));
    }
}
