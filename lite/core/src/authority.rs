// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The group's authority records of version 2 (docs/records-v2.md): the
//! record, its closed canonical body, its signature, and the one rule that
//! turns a set of records into the group's state, as Go's
//! internal/authority. Both are checked on testdata/interop/v2-records.json
//! and v2-flood.json.
//! What the set says depends on the records alone, never on the order in
//! which they arrived.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::cmp::Ordering;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::certs::{self, Cert, b64, sha256};
use crate::error::{Error, Result};
use crate::{seal, strict};

/// The largest record body a member takes (8 KiB).
pub const MAX_BODY: usize = 8 << 10;

/// The largest body of a checkpoint (64 KiB), which lists the live records
/// of the whole group.
pub const MAX_CHECKPOINT_BODY: usize = 64 << 10;

/// The one signature algorithm of version 2: ECDSA P-256 with SHA-256, DER.
pub const ALG_ES256: &str = "es256";

/// How many records of a later version a state lists.
pub const MAX_NEWER: usize = 16;
/// The largest seq a signer gives a record.
pub const MAX_SEQ: i64 = (1 << 31) - 1;

/// The kinds of a conflict (docs/protocol.md, section 10, "The state").
pub const CONFLICT_ADMINS: &str = "admins";
pub const CONFLICT_CLAIMS: &str = "claims";
pub const CONFLICT_TWO_HISTORIES: &str = "two_histories";
/// The longest takeover delay the root may set (7 days), in milliseconds.
pub const MAX_DELAY: i64 = 7 * 24 * 3600 * 1000;
/// The takeover delay without a settings record (72 hours).
pub const DEFAULT_DELAY: i64 = 72 * 3600 * 1000;

pub const TYPE_DEVICE: &str = "device";
pub const TYPE_REVOKE: &str = "revoke";
pub const TYPE_FREEZE: &str = "freeze";
pub const TYPE_THAW: &str = "thaw";
pub const TYPE_CLAIM: &str = "claim";
pub const TYPE_RESOLVE: &str = "resolve";
pub const TYPE_SETTINGS: &str = "settings";
pub const TYPE_CHECKPOINT: &str = "checkpoint";
pub const TYPE_HUBS: &str = "hubs";
pub const TYPE_RECOVERY: &str = "recovery";
pub const TYPE_HANDOVER: &str = "handover";
/// How many devices a hubs record names.
pub const MAX_HUBS: usize = 16;

pub const POWER_ADMIT: &str = "admit";
pub const POWER_RENEW: &str = "renew";
pub const POWER_REMOVE: &str = "remove";
pub const POWER_REMOVE_ADMINS: &str = "remove-admins";
pub const POWER_FREEZE: &str = "freeze";
pub const POWER_THAW: &str = "thaw";
pub const POWER_TAKEOVER: &str = "takeover";
pub const POWER_HUB: &str = "hub";

/// Every power, sorted.
pub const POWERS: [&str; 8] =
    [POWER_ADMIT, POWER_FREEZE, POWER_HUB, POWER_REMOVE, POWER_REMOVE_ADMINS, POWER_RENEW, POWER_TAKEOVER, POWER_THAW];

/// Every command type an admin may be given, sorted.
pub const COMMANDS: [&str; 7] = ["action", "actions-off", "away-off", "hub", "mode", "paste", "paste-off"];

/// The key levels a settings record may set (docs/roadmap.md, "Key
/// levels"): only proven hardware keys, hardware keys (the default), or
/// files allowed too.
pub const KEY_LEVELS: [&str; 3] = ["proven", "hardware", "files"];

/// The values of State::stop (docs/protocol.md, section 10, "Stopping the
/// exchange"): nothing stops, no member sends a secret, or every member
/// exchanges records only.
pub const STOP_NONE: &str = "none";
pub const STOP_SECRETS: &str = "secrets";
pub const STOP_FULL: &str = "full";

const ROLES: [&str; 5] = ["full", "phone", "lite", "watch", "shortcut"];
const OSES: [&str; 8] = ["linux", "windows", "macos", "ios", "android", "watchos", "wearos", "none"];

/// A key hash (SHA-256 of a SubjectPublicKeyInfo) or a record ID (SHA-256
/// of a body). In JSON it is standard base64, and hashes sort by that
/// text, as the canonical form wants.
#[derive(Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct Hash(pub [u8; 32]);

impl Hash {
    pub fn text(&self) -> String {
        STANDARD.encode(self.0)
    }
}

impl Ord for Hash {
    fn cmp(&self, other: &Hash) -> Ordering {
        if self.0 == other.0 { Ordering::Equal } else { self.text().cmp(&other.text()) }
    }
}

impl PartialOrd for Hash {
    fn partial_cmp(&self, other: &Hash) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl core::fmt::Debug for Hash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.text())
    }
}

impl Serialize for Hash {
    fn serialize<S: Serializer>(&self, s: S) -> core::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.text())
    }
}

impl<'de> Deserialize<'de> for Hash {
    fn deserialize<D: Deserializer<'de>>(d: D) -> core::result::Result<Hash, D::Error> {
        let s = String::deserialize(d)?;
        let raw = STANDARD.decode(&s).map_err(|_| serde::de::Error::custom("a hash is not base64"))?;
        let h: [u8; 32] = raw.try_into().map_err(|_| serde::de::Error::custom("a hash is not 32 bytes"))?;
        if STANDARD.encode(h) != s {
            return Err(serde::de::Error::custom("a hash is not in its one form"));
        }
        Ok(Hash(h))
    }
}

/// The hash of a certificate's key.
pub fn key_hash_of(c: &Cert) -> Hash {
    Hash(c.key_hash())
}

/// One entry of a record's seen: the highest seq of a signer the author
/// held.
#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct Seen {
    pub key: Hash,
    pub seq: i64,
}

/// One entry of a checkpoint's heads: a signer's newest record the
/// checkpoint covers.
#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct Head {
    pub key: Hash,
    pub seq: i64,
    pub id: Hash,
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// A record's body (docs/protocol.md, section 10, "Records").
#[derive(Clone, Serialize, Deserialize, Default, Debug, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Body {
    pub v: i64,
    pub alg: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub group: String,
    pub signer: Hash,
    pub seq: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev: Option<Hash>,
    pub time_ms: i64,

    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub device: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub role: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub os: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin: Option<Hash>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub powers: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub commands: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub store: String,
    #[serde(rename = "kind", default, skip_serializing_if = "String::is_empty")]
    pub hardware: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub proof: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub holds_root: bool,
    /// The device's public key for sealed messages (`crate::seal`).
    #[serde(with = "b64", default, skip_serializing_if = "Vec::is_empty")]
    pub seal: Vec<u8>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keys: Vec<Hash>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub seen: Vec<Seen>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub records: Vec<Hash>,
    #[serde(with = "b64", default, skip_serializing_if = "Vec::is_empty")]
    pub root: Vec<u8>,
    /// The recovery key's admin CA (DER), in a recovery record.
    #[serde(with = "b64", default, skip_serializing_if = "Vec::is_empty")]
    pub cert: Vec<u8>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub takeover_delay_ms: Option<i64>,
    /// Which keys may be the group's root, an admin or a hub: one of
    /// KEY_LEVELS; absent means "hardware".
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub key_level: String,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub heads: Vec<Head>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keep: Vec<Hash>,

    /// The user's main hubs, in the order they serve.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hubs: Vec<String>,
}

const COMMON: [&str; 7] = ["v", "alg", "type", "group", "signer", "seq", "time_ms"];

/// The fields beyond those every record has that a type may carry.
fn allowed(kind: &str) -> Option<&'static [&'static str]> {
    Some(match kind {
        TYPE_DEVICE => &[
            "device",
            "name",
            "role",
            "os",
            "key",
            "admin",
            "powers",
            "commands",
            "store",
            "kind",
            "proof",
            "holds_root",
            "seal",
        ],
        TYPE_REVOKE | TYPE_FREEZE => &["keys", "seen"],
        TYPE_THAW | TYPE_RESOLVE => &["records"],
        TYPE_CLAIM => &["root", "seen"],
        TYPE_SETTINGS => &["takeover_delay_ms", "key_level"],
        TYPE_CHECKPOINT => &["heads", "keep"],
        TYPE_HUBS => &["hubs"],
        TYPE_RECOVERY => &["admin", "cert"],
        TYPE_HANDOVER => &["admin"],
        _ => return None,
    })
}

impl Body {
    /// The names of the fields b carries.
    fn present(&self) -> Vec<&'static str> {
        let mut n = Vec::new();
        let mut add = |on: bool, name: &'static str| {
            if on {
                n.push(name);
            }
        };
        add(!self.device.is_empty(), "device");
        add(!self.name.is_empty(), "name");
        add(!self.role.is_empty(), "role");
        add(!self.os.is_empty(), "os");
        add(self.key.is_some(), "key");
        add(self.admin.is_some(), "admin");
        add(!self.powers.is_empty(), "powers");
        add(!self.commands.is_empty(), "commands");
        add(!self.store.is_empty(), "store");
        add(!self.hardware.is_empty(), "kind");
        add(!self.proof.is_empty(), "proof");
        add(self.holds_root, "holds_root");
        add(!self.seal.is_empty(), "seal");
        add(!self.keys.is_empty(), "keys");
        add(!self.seen.is_empty(), "seen");
        add(!self.records.is_empty(), "records");
        add(!self.root.is_empty(), "root");
        add(!self.cert.is_empty(), "cert");
        add(self.takeover_delay_ms.is_some(), "takeover_delay_ms");
        add(!self.key_level.is_empty(), "key_level");
        add(!self.heads.is_empty(), "heads");
        add(!self.keep.is_empty(), "keep");
        add(!self.hubs.is_empty(), "hubs");
        n
    }

    /// Returns the canonical bytes of the body after checking its fields,
    /// as a signer's own code does before it signs.
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.check()?;
        let v = serde_json::to_value(self).map_err(|_| Error::msg("a record body does not encode"))?;
        let mut out = Vec::new();
        strict::write_canonical(&mut out, &v);
        // Never bytes to sign that every receiver refuses for their size.
        if out.len() > MAX_BODY {
            return Err(Error::msg(format!("a record body of {} bytes is over {MAX_BODY}", out.len())));
        }
        Ok(out)
    }

    /// Reads a record body: its size, the strict and canonical form, no
    /// field its type does not know and none empty, and each field against
    /// its row (docs/protocol.md, section 10, "Field rows").
    pub fn parse(data: &[u8]) -> Result<Body> {
        if data.len() > MAX_CHECKPOINT_BODY {
            return Err(Error::msg(format!("a record body of {} bytes is over {MAX_CHECKPOINT_BODY}", data.len())));
        }
        strict::check_canonical(data, &COMMON)?;
        let b: Body = serde_json::from_slice(data).map_err(|e| Error::msg(format!("a record body: {e}")))?;
        b.check()?;
        if data.len() > b.max_body() {
            return Err(Error::msg(format!(
                "a {} record body of {} bytes is over {}",
                b.kind,
                data.len(),
                b.max_body()
            )));
        }
        if b.encode()? != data {
            return Err(Error::msg("a record body has an empty field or a value not in its one form"));
        }
        Ok(b)
    }

    /// Puts the body's arrays in the order the canonical form wants.
    pub fn sort(&mut self) {
        self.powers.sort();
        self.commands.sort();
        self.keys.sort();
        self.records.sort();
        self.keep.sort();
        self.heads.sort_by_key(|h| h.key);
        self.seen.sort_by_key(|s| s.key);
    }

    /// The largest body of the body's type.
    pub fn max_body(&self) -> usize {
        if self.kind == TYPE_CHECKPOINT { MAX_CHECKPOINT_BODY } else { MAX_BODY }
    }

    fn check(&self) -> Result<()> {
        if self.v != 2 {
            return Err(Error::msg(format!("a record of version {}", self.v)));
        }
        if self.alg != ALG_ES256 {
            return Err(Error::msg(format!("a record signed with {:?}", self.alg)));
        }
        let allowed =
            allowed(&self.kind).ok_or_else(|| Error::msg(format!("an unknown record type {:?}", self.kind)))?;
        for n in self.present() {
            if !allowed.contains(&n) {
                return Err(Error::msg(format!("a {} record has {n}", self.kind)));
            }
        }
        if self.group.is_empty() {
            return Err(Error::msg("a record has no group"));
        }
        if self.seq < 1 || self.seq > MAX_SEQ {
            return Err(Error::msg(format!("a record's seq {} is not from 1 to {MAX_SEQ}", self.seq)));
        }
        if (self.seq == 1) != self.prev.is_none() {
            return Err(Error::msg("a record has prev exactly when its seq is above 1"));
        }
        match self.kind.as_str() {
            TYPE_DEVICE => self.check_device(),
            TYPE_REVOKE | TYPE_FREEZE => {
                if self.keys.is_empty() || self.seen.is_empty() {
                    return Err(Error::msg(format!("a {} record needs keys and seen", self.kind)));
                }
                sorted_hashes(&self.keys, "keys")?;
                check_seen(&self.seen)
            }
            TYPE_THAW | TYPE_RESOLVE => {
                if self.records.is_empty() {
                    return Err(Error::msg(format!("a {} record needs records", self.kind)));
                }
                sorted_hashes(&self.records, "records")
            }
            TYPE_CLAIM => {
                if self.root.is_empty() || self.seen.is_empty() {
                    return Err(Error::msg("a claim needs root and seen"));
                }
                check_seen(&self.seen)
            }
            TYPE_CHECKPOINT => {
                if self.heads.is_empty() {
                    return Err(Error::msg("a checkpoint needs heads"));
                }
                if let Some(h) = self.heads.iter().find(|h| h.seq < 1 || h.seq > MAX_SEQ) {
                    return Err(Error::msg(format!("a head's seq {} is not from 1 to {MAX_SEQ}", h.seq)));
                }
                if self.heads.windows(2).any(|w| matches!(w, [a, b] if a.key >= b.key)) {
                    return Err(Error::msg("heads is not sorted by key, each once"));
                }
                sorted_hashes(&self.keep, "keep")
            }
            TYPE_HUBS => check_hubs(&self.hubs),
            TYPE_RECOVERY => {
                let (Some(admin), false) = (self.admin, self.cert.is_empty()) else {
                    return Err(Error::msg("a recovery record needs admin and cert"));
                };
                match Cert::parse(&self.cert) {
                    Ok(ca) if key_hash_of(&ca) == admin => Ok(()),
                    _ => Err(Error::msg("a recovery record's cert is not the admin CA of its admin key")),
                }
            }
            TYPE_HANDOVER if self.admin.is_none() => Err(Error::msg("a handover record needs admin")),
            TYPE_HANDOVER => Ok(()),
            _ => match self.takeover_delay_ms {
                Some(d) if !(0..=MAX_DELAY).contains(&d) => {
                    Err(Error::msg(format!("a takeover delay of {d} ms is not from 0 to {MAX_DELAY}")))
                }
                _ if !self.key_level.is_empty() && !KEY_LEVELS.contains(&self.key_level.as_str()) => {
                    Err(Error::msg(format!("an unknown key level {:?}", self.key_level)))
                }
                _ => Ok(()),
            },
        }
    }

    fn check_device(&self) -> Result<()> {
        if !certs::is_id(&self.device) {
            return Err(Error::msg("a device record's device is not a device ID"));
        }
        if !valid_name(&self.name) {
            return Err(Error::msg("a device record's name is not 1 to 64 bytes without control characters"));
        }
        if !ROLES.contains(&self.role.as_str()) {
            return Err(Error::msg(format!("an unknown role {:?}", self.role)));
        }
        if !self.os.is_empty() && !OSES.contains(&self.os.as_str()) {
            return Err(Error::msg(format!("an unknown os {:?}", self.os)));
        }
        if self.key.is_none() {
            return Err(Error::msg("a device record has no key"));
        }
        if self.admin.is_none() && (!self.powers.is_empty() || !self.commands.is_empty()) {
            return Err(Error::msg("powers and commands come only with admin"));
        }
        if !self.seal.is_empty() && self.seal.len() != seal::PUBLIC_KEY_SIZE {
            return Err(Error::msg(format!(
                "a device record's seal is {} bytes, not {}",
                self.seal.len(),
                seal::PUBLIC_KEY_SIZE
            )));
        }
        sorted_of(&self.powers, &POWERS, "powers")?;
        sorted_of(&self.commands, &COMMANDS, "commands")
    }

    fn seen_of(&self, k: &Hash) -> i64 {
        self.seen.iter().find(|s| s.key == *k).map_or(0, |s| s.seq)
    }
}

/// Reports whether s is a device name: 1 to 64 bytes of UTF-8 without a
/// control character (U+0000 to U+001F, U+007F to U+009F).
pub fn valid_name(s: &str) -> bool {
    (1..=64).contains(&s.len()) && !s.chars().any(|c| c < ' ' || ('\u{7f}'..='\u{9f}').contains(&c))
}

/// Checks a hubs record's hubs: 1 to MAX_HUBS device IDs, each once, in
/// the user's order.
fn check_hubs(hubs: &[String]) -> Result<()> {
    if hubs.is_empty() || hubs.len() > MAX_HUBS {
        return Err(Error::msg(format!("a hubs record names {} devices, not 1 to {MAX_HUBS}", hubs.len())));
    }
    for (i, h) in hubs.iter().enumerate() {
        if !certs::is_id(h) || hubs.iter().take(i).any(|o| o == h) {
            return Err(Error::msg("a hubs record's hubs are not device IDs, each once"));
        }
    }
    Ok(())
}

fn sorted_hashes(hs: &[Hash], field: &str) -> Result<()> {
    if hs.windows(2).any(|w| matches!(w, [a, b] if a >= b)) {
        return Err(Error::msg(format!("{field} is not sorted, each once")));
    }
    Ok(())
}

fn check_seen(seen: &[Seen]) -> Result<()> {
    if let Some(s) = seen.iter().find(|s| !(0..=MAX_SEQ).contains(&s.seq)) {
        return Err(Error::msg(format!("a seen seq {} is not from 0 to {MAX_SEQ}", s.seq)));
    }
    if seen.windows(2).any(|w| matches!(w, [a, b] if a.key >= b.key)) {
        return Err(Error::msg("seen is not sorted by key, each once"));
    }
    Ok(())
}

fn sorted_of(vs: &[String], known: &[&str], field: &str) -> Result<()> {
    if let Some(v) = vs.iter().find(|v| !known.contains(&v.as_str())) {
        return Err(Error::msg(format!("an unknown value {v:?} in {field}")));
    }
    if vs.windows(2).any(|w| matches!(w, [a, b] if a >= b)) {
        return Err(Error::msg(format!("{field} is not sorted, each once")));
    }
    Ok(())
}

/// A signed record as it travels and is kept: its body's exact bytes, the
/// signature over them, and the signer's admin CA when an admin signed it.
#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
pub struct Record {
    #[serde(with = "b64")]
    pub body: Vec<u8>,
    #[serde(with = "b64")]
    pub sig: Vec<u8>,
    #[serde(with = "b64::list", default, skip_serializing_if = "Vec::is_empty")]
    pub chain: Vec<Vec<u8>>,
}

impl Record {
    /// The record ID: SHA-256 over the body.
    pub fn id(&self) -> Hash {
        Hash(sha256(&self.body))
    }

    /// Builds a record from a body the caller signed: the signature over
    /// body (ECDSA P-256 with SHA-256, DER) and the admin CA's DER when an
    /// admin key signed it.
    pub fn new(body: Vec<u8>, sig: Vec<u8>, admin_ca: Option<Vec<u8>>) -> Record {
        Record { body, sig, chain: admin_ca.into_iter().collect() }
    }
}

/// The most signatures a SigCache holds; when it is full it starts again.
pub const MAX_CACHE: usize = 8192;

/// Signatures already checked: an entry is a hash over the signer's key
/// hash, the body's hash and the signature, kept only for a signature that
/// verified, so that evaluating the same records again checks each
/// signature once. It is safe to share between threads and evaluations.
pub struct SigCache {
    seen: spin::Mutex<BTreeSet<[u8; 32]>>,
}

impl Default for SigCache {
    fn default() -> SigCache {
        SigCache::new()
    }
}

impl SigCache {
    pub const fn new() -> SigCache {
        SigCache { seen: spin::Mutex::new(BTreeSet::new()) }
    }

    fn entry(key: &Cert, data: &[u8], sig: &[u8]) -> [u8; 32] {
        let mut m = Vec::with_capacity(sig.len().saturating_add(16 + 32 + 32));
        m.extend_from_slice(b"cbb sig cache v1");
        m.extend_from_slice(&key_hash_of(key).0);
        m.extend_from_slice(&sha256(data));
        m.extend_from_slice(sig);
        sha256(&m)
    }

    /// Reports whether sig over data verifies with key, from the cache when
    /// it was checked before.
    pub fn verifies(&self, key: &Cert, data: &[u8], sig: &[u8]) -> bool {
        let e = SigCache::entry(key, data, sig);
        if self.seen.lock().contains(&e) {
            return true;
        }
        let ok = key.verifies(data, sig);
        if ok {
            self.add([e]);
        }
        ok
    }

    /// The entries, sorted, to save with the member's state.
    pub fn entries(&self) -> Vec<[u8; 32]> {
        self.seen.lock().iter().copied().collect()
    }

    /// Adds saved entries. Only entries from the member's own saved state,
    /// checked with its secret, may come here: an entry stands for a
    /// signature that verified.
    pub fn add(&self, entries: impl IntoIterator<Item = [u8; 32]>) {
        let mut seen = self.seen.lock();
        for e in entries {
            if seen.len() >= MAX_CACHE {
                seen.clear();
            }
            seen.insert(e);
        }
    }

    pub fn len(&self) -> usize {
        self.seen.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn verifies(sigs: Option<&SigCache>, key: &Cert, data: &[u8], sig: &[u8]) -> bool {
    match sigs {
        Some(c) => c.verifies(key, data, sig),
        None => key.verifies(data, sig),
    }
}

/// A record whose body was read and whose signature verifies with the key
/// its body names.
#[derive(Clone, Debug)]
pub struct Signed {
    pub record: Record,
    pub body: Body,
    pub id: Hash,
    /// The admin CA in the chain; None when a root's own key signed.
    pub admin_ca: Option<Cert>,
}

/// Reads r's body and checks its signature: with an admin CA in the chain,
/// the signer is that CA's key; with none, a root the group may have, which
/// root_key finds by the signer. sigs, when given, holds signatures
/// already checked.
pub fn verify<'a>(r: &Record, root_key: impl Fn(&Hash) -> Option<&'a Cert>, sigs: Option<&SigCache>) -> Result<Signed> {
    let body = Body::parse(&r.body)?;
    let (key, admin_ca) = match r.chain.as_slice() {
        [] => (
            root_key(&body.signer).ok_or_else(|| Error::msg("a record's signer is no root of the group"))?.clone(),
            None,
        ),
        [ca] => {
            let ca = Cert::parse(ca)?;
            if key_hash_of(&ca) != body.signer {
                return Err(Error::msg("a record's signer is not its admin CA's key"));
            }
            (ca.clone(), Some(ca))
        }
        _ => return Err(Error::msg("a record's chain holds more than its admin CA")),
    };
    if key_hash_of(&key) != body.signer {
        return Err(Error::msg("a record's signer is not the key it is checked with"));
    }
    if !verifies(sigs, &key, &r.body, &r.sig) {
        return Err(Error::msg("a record's signature does not verify"));
    }
    Ok(Signed { record: r.clone(), body, id: r.id(), admin_ca })
}

/// What the evaluation takes (docs/protocol.md, section 10, "The state").
pub struct Input<'a> {
    /// The group's first root; its tag is group.
    pub group_ca: &'a Cert,
    pub group: &'a str,
    pub records: &'a [Record],
    /// The member's clock, which counts sleep and does not jump, and the
    /// time on it when the member first held each claim, by record ID; a
    /// claim missing from it was first held now.
    pub now_ms: i64,
    pub first_seen: &'a BTreeMap<Hash, i64>,
    /// The member does not know how long it has held its claims: its clock
    /// started again and it kept no time. No claim then takes effect by
    /// waiting (docs/protocol.md, section 10, "Handing the group over").
    pub time_unknown: bool,
    /// Signatures already checked, when the caller keeps them.
    pub sigs: Option<&'a SigCache>,
}

/// The group's state (docs/protocol.md, section 10, "The state").
#[derive(Clone, Serialize, PartialEq, Debug, Default)]
pub struct State {
    pub roots: Vec<Hash>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub root_device: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub devices: Vec<Device>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub revoked: Vec<Hash>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<Claim>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub conflicts: Vec<Conflict>,
    pub stop: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub no_secrets_to: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub nothing_to: Vec<String>,
    /// Records of a later version: the member keeps them and tells its
    /// user to update.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub newer: Vec<Hash>,
    /// The records that do not count and why.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ignored: Vec<Ignored>,
    /// The root's checkpoint that counts: a member may drop the records it
    /// leaves out.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checkpoint: Option<Hash>,
    /// The user's main hubs from the hubs record that counts, the devices
    /// of the state with the role full or phone, in its order
    /// (docs/protocol.md, section 10, "The hubs table").
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub hubs: Vec<String>,
    /// The key level of the current root's newest settings record that
    /// counts; empty when it sets none, which means "hardware".
    #[serde(skip_serializing_if = "String::is_empty")]
    pub key_level: String,
    /// The admin key of the group's recovery key, from the newest recovery
    /// record of a root on the path, while it is neither revoked nor
    /// frozen (docs/records-v2.md, "The recovery key").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery: Option<Hash>,
}

/// A record of the set that does not count, with why: one of the WHY_
/// constants.
#[derive(Clone, Serialize, PartialEq, Debug)]
pub struct Ignored {
    pub record: Hash,
    pub why: &'static str,
}

/// How many records a state lists in ignored.
pub const MAX_IGNORED: usize = 64;

/// Its body is not a record of version 2.
pub const WHY_UNREADABLE: &str = "unreadable";
/// Its signature or chain does not check.
pub const WHY_SIGNATURE: &str = "signature";
/// It is of another group.
pub const WHY_GROUP: &str = "group";
/// Its admin CA is from no root of the group.
pub const WHY_ISSUER: &str = "issuer";
/// Its signer is no root on the path.
pub const WHY_NOT_ROOT: &str = "not_root";
/// Its prev chain is broken, on a voided branch or at a second history.
pub const WHY_HISTORY: &str = "history";
/// A root's removal, freeze or thaw cut it off, or it is past its root's cut.
pub const WHY_CUT: &str = "cut";
/// Its signer was no admin with the power it needs.
pub const WHY_POWER: &str = "power";
/// An admin's removal or freeze that counts cut it off.
pub const WHY_REMOVED: &str = "removed";
/// It is in a conflict between admins.
pub const WHY_UNDECIDED: &str = "undecided";
/// It is past a limit on the set (MAX_RECORDS, MAX_SET_BYTES, MAX_DEVICES,
/// MAX_ADMINS).
pub const WHY_LIMIT: &str = "limit";

// The limits on a record set (docs/protocol.md, section 10, "Limits"). Records over
// them count for nothing, with the reason WHY_LIMIT; the set is never
// refused, so that no admin can stop the group by filling it.

/// Records in the set, as the checkpoint prunes it.
pub const MAX_RECORDS: usize = 1024;
/// Their bodies, signatures and chains together.
pub const MAX_SET_BYTES: usize = 1 << 20;
/// Devices with a device record.
pub const MAX_DEVICES: usize = 256;
/// Admin keys a root names.
pub const MAX_ADMINS: usize = 64;
/// Roots on the path: the group CA and 15 handovers.
pub const MAX_PATH: usize = 16;

/// One device of the state.
#[derive(Clone, Serialize, PartialEq, Debug, Default)]
pub struct Device {
    pub device: String,
    pub name: String,
    pub role: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub os: String,
    pub keys: Vec<Hash>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub store: String,
    #[serde(rename = "kind", skip_serializing_if = "String::is_empty")]
    pub hardware: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub proof: String,
    #[serde(with = "b64", skip_serializing_if = "Vec::is_empty")]
    pub seal: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub admin: Option<Hash>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub powers: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub commands: Vec<String>,
    #[serde(skip_serializing_if = "is_false")]
    pub frozen: bool,
}

/// A claim of the state.
#[derive(Clone, Serialize, PartialEq, Debug)]
pub struct Claim {
    pub record: Hash,
    pub claimant: Hash,
    pub root: Hash,
    pub state: &'static str,
    #[serde(skip_serializing_if = "is_zero")]
    pub left_ms: i64,
}

fn is_zero(v: &i64) -> bool {
    *v == 0
}

/// A conflict of the state.
#[derive(Clone, Serialize, PartialEq, Debug)]
pub struct Conflict {
    pub kind: &'static str,
    pub records: Vec<Hash>,
    pub signers: Vec<Hash>,
}

impl State {
    /// The state as canonical JSON, the bytes the vectors compare.
    pub fn encode(&self) -> Vec<u8> {
        let v = serde_json::to_value(self).unwrap_or_default();
        let mut out = Vec::new();
        strict::write_canonical(&mut out, &v);
        out
    }
}

/// Turns a record set into the group's state. Records that do not verify
/// are dropped; the result depends only on the set, never on its order.
pub fn evaluate(input: &Input) -> State {
    evaluate_seqs(input).0
}

/// evaluate, and for each signer of the group the highest seq whose chain
/// is held whole down to seq 1, which a member saves to notice a record
/// set rolled back (see Evaluation::seqs).
pub fn evaluate_seqs(input: &Input) -> (State, BTreeMap<Hash, i64>) {
    let group_ca = key_hash_of(input.group_ca);
    let full = Evaluation::new(input, BTreeSet::new());
    let seqs = full.seqs(group_ca);
    // The set a root's checkpoint prunes is evaluated as if the member had
    // dropped what it leaves out; the checkpoint that counts is the newest
    // that still counts there (docs/protocol.md, section 10, "Checkpoints").
    let mut best: Option<((usize, i64, Hash), State)> = None;
    for c in full.checkpoints(group_ca) {
        let Some(r) = full.recs.get(c) else { continue };
        let (c, id) = (r.b(), r.s.id);
        let records = prune(input.records, input.group, c);
        let pruned = Input { records: &records, ..*input };
        let e = Evaluation::new(&pruned, anchors_of(c));
        let ep = e.run(&pruned);
        let Some(i) = e.recs.iter().position(|r| r.s.id == id) else { continue };
        if !ep.root_record(i) {
            continue;
        }
        let key = (ep.on_path.get(&c.signer).copied().unwrap_or(0), c.seq, id);
        let better = match &best {
            None => true,
            Some((b, _)) => key.0 > b.0 || key.0 == b.0 && (key.1 > b.1 || key.1 == b.1 && key.2 < b.2),
        };
        if better {
            let mut state = ep.finish(&pruned);
            state.checkpoint = Some(id);
            best = Some((key, state));
        }
    }
    let state = match best {
        Some((_, state)) => state,
        None => full.run(input).finish(input),
    };
    (state, seqs)
}

/// How many of a set's checkpoints the evaluation tries: those of the
/// highest seq, then the smallest ID.
pub const MAX_CHECKPOINTS: usize = 8;

/// Leaves out of a set what checkpoint c drops: each record of this group
/// whose body reads, at or below its signer's head, that is neither a head
/// nor kept, whether or not its signature checks.
fn prune(records: &[Record], group: &str, c: &Body) -> Vec<Record> {
    let heads: BTreeMap<Hash, &Head> = c.heads.iter().map(|h| (h.key, h)).collect();
    let anchors = anchors_of(c);
    records
        .iter()
        .filter(|r| match Body::parse(&r.body) {
            Ok(b) if b.group == group => {
                !matches!(heads.get(&b.signer), Some(h) if b.seq <= h.seq && !anchors.contains(&r.id()))
            }
            _ => true,
        })
        .cloned()
        .collect()
}

/// The IDs of the records of a later version for this group that a
/// current root or admin of the state signed, sorted, at most MAX_NEWER
/// (docs/protocol.md, section 10, "Records of a later version").
fn newer(input: &Input, state: &State, roots: &BTreeMap<Hash, Cert>) -> Vec<Hash> {
    let admins: BTreeSet<Hash> = state.devices.iter().filter_map(|d| d.admin).collect();
    let mut ids = BTreeSet::new();
    for r in input.records {
        if r.body.len() > MAX_BODY || crate::strict::check_canonical(&r.body, &["v", "group", "signer"]).is_err() {
            continue;
        }
        let Ok(serde_json::Value::Object(m)) = serde_json::from_slice::<serde_json::Value>(&r.body) else {
            continue;
        };
        let group = m.get("group").and_then(|g| g.as_str());
        let v = m.get("v").and_then(|v| v.as_i64());
        if group != Some(input.group) || !v.is_some_and(|v| v > 2 && v <= MAX_SEQ) {
            continue;
        }
        let Some(Ok(signer)) = m.get("signer").map(|s| serde_json::from_value::<Hash>(s.clone())) else {
            continue;
        };
        let key = match r.chain.as_slice() {
            [] if state.roots.contains(&signer) => roots.get(&signer).cloned(),
            [ca] if admins.contains(&signer) => Cert::parse(ca).ok().filter(|ca| key_hash_of(ca) == signer),
            _ => None,
        };
        if key.is_some_and(|k| verifies(input.sigs, &k, &r.body, &r.sig)) {
            ids.insert(r.id());
        }
    }
    ids.into_iter().take(MAX_NEWER).collect()
}

/// The IDs a checkpoint names: its heads and keep.
fn anchors_of(b: &Body) -> BTreeSet<Hash> {
    b.heads.iter().map(|h| h.id).chain(b.keep.iter().copied()).collect()
}

/// A verified record with the root that issued its admin CA.
struct Rec {
    s: Signed,
    issuer: Option<Hash>, // None for a root's own record
    key: LimitKey,
}

/// A record's place in the order the limits take records in: the group
/// CA's own records first, then those of the other roots of the group, then
/// those under an admin CA of the group, then the rest; within each, by
/// depth (how many of its signer's records have a lower seq), then signer
/// and ID. Each signer's records stay in seq order, so what a limit leaves
/// out is the end of its chains, never a record in the middle.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
struct LimitKey {
    rank: u8,
    depth: usize,
    signer: Hash,
    id: Hash,
}

impl Rec {
    fn b(&self) -> &Body {
        &self.s.body
    }
    fn admin(&self) -> bool {
        self.s.admin_ca.is_some()
    }
}

struct Evaluation {
    /// The heads and keep of the checkpoint it prunes by, where a prev
    /// chain may end.
    anchors: BTreeSet<Hash>,
    /// Why records were left out before the epochs, by ID.
    failed: BTreeMap<Hash, &'static str>,
    roots: BTreeMap<Hash, Cert>,
    /// Every verified record, those within the limits (the first kept)
    /// first; the epochs see only those.
    recs: Vec<Rec>,
    kept: usize,
    by_sig: BTreeMap<Hash, Vec<usize>>,
    /// by_sig with the records past the limits too, for seqs.
    all_by_sig: BTreeMap<Hash, Vec<usize>>,
    devices: BTreeMap<String, Vec<usize>>,
    /// Device records over MAX_DEVICES or MAX_ADMINS, which count for
    /// nothing; of the same length as recs.
    capped: Vec<bool>,
}

// The evaluation keeps its records in one Vec and refers to them by their
// positions, which it takes from that Vec itself (`0..recs.len()`, and maps
// filled from it), and its per-record flags are Vecs of the same length; so
// an index here is always in range.
#[allow(clippy::indexing_slicing, reason = "positions come from the records' own Vec")]
impl Evaluation {
    fn new(input: &Input, anchors: BTreeSet<Hash>) -> Evaluation {
        let mut roots = BTreeMap::new();
        roots.insert(key_hash_of(input.group_ca), input.group_ca.clone());
        // The new roots of claims are the only other roots a record may be
        // signed under; a claim itself is signed by an admin CA.
        for r in input.records {
            if r.chain.len() != 1 {
                continue;
            }
            if let Ok(b) = Body::parse(&r.body) {
                if b.kind == TYPE_CLAIM {
                    if let Ok(c) = Cert::parse(&b.root) {
                        if certs::check_root(&c).is_ok() {
                            roots.insert(key_hash_of(&c), c);
                        }
                    }
                }
            }
        }
        let mut e = Evaluation {
            anchors,
            failed: BTreeMap::new(),
            roots,
            recs: Vec::new(),
            kept: 0,
            by_sig: BTreeMap::new(),
            all_by_sig: BTreeMap::new(),
            devices: BTreeMap::new(),
            capped: Vec::new(),
        };
        // One body may come with more than one valid admin CA (an admin key
        // certified again); the smallest DER is kept, whatever the order.
        // A Vec sorted once, not a map: a set at the limits is most of the
        // memory the evaluation takes, so it is held once.
        let mut all: Vec<Rec> = Vec::with_capacity(input.records.len());
        for r in input.records {
            let s = match verify(r, |h| e.roots.get(h), input.sigs) {
                Ok(s) => s,
                Err(_) => {
                    let why = if Body::parse(&r.body).is_err() { WHY_UNREADABLE } else { WHY_SIGNATURE };
                    e.fail(r.id(), why);
                    continue;
                }
            };
            if s.body.group != input.group {
                e.fail(s.id, WHY_GROUP);
                continue;
            }
            let issuer = match &s.admin_ca {
                Some(ca) => match e.issuer_of(ca) {
                    Some(h) => Some(h),
                    None => {
                        e.fail(s.id, WHY_ISSUER);
                        continue;
                    }
                },
                None => None,
            };
            all.push(Rec { s, issuer, key: LimitKey::default() });
        }
        fn der(x: &Rec) -> Option<&[u8]> {
            x.s.admin_ca.as_ref().map(|c| c.der.as_slice())
        }
        all.sort_unstable_by(|a, b| a.s.id.cmp(&b.s.id).then_with(|| der(a).cmp(&der(b))));
        all.dedup_by(|later, first| later.s.id == first.s.id);
        let (all, kept) = e.limit(key_hash_of(input.group_ca), all);
        e.kept = kept;
        for (i, x) in all.iter().enumerate() {
            e.all_by_sig.entry(x.s.body.signer).or_default().push(i);
            if i < kept {
                e.by_sig.entry(x.s.body.signer).or_default().push(i);
                if x.s.body.kind == TYPE_DEVICE {
                    e.devices.entry(x.s.body.device.clone()).or_default().push(i);
                }
            }
        }
        e.recs = all;
        e.cap_devices();
        e
    }

    /// Sorts the records in LimitKey order and returns how many of them fit
    /// in MAX_RECORDS and MAX_SET_BYTES, up to the first that does not fit;
    /// that one and every record after it fail with WHY_LIMIT. It notes each
    /// record's key for cap_devices.
    fn limit(&mut self, group_ca: Hash, mut all: Vec<Rec>) -> (Vec<Rec>, usize) {
        // The roots of the group: the group CA and the root of each claim an
        // admin CA of one of them signed.
        let mut roots = BTreeSet::from([group_ca]);
        let mut grew = true;
        while grew {
            grew = false;
            for x in &all {
                if x.b().kind == TYPE_CLAIM && x.issuer.is_some_and(|h| roots.contains(&h)) {
                    grew |= roots.insert(claim_root(x.b()));
                }
            }
        }
        let mut rank: BTreeMap<Hash, u8> = BTreeMap::new();
        let mut seqs: BTreeMap<Hash, Vec<i64>> = BTreeMap::new();
        for x in &all {
            let k = x.b().signer;
            let r = if k == group_ca {
                0
            } else if roots.contains(&k) {
                1
            } else if x.issuer.is_some_and(|h| roots.contains(&h)) {
                2
            } else {
                3
            };
            let old = rank.entry(k).or_insert(r);
            *old = r.min(*old);
            seqs.entry(k).or_default().push(x.b().seq);
        }
        for q in seqs.values_mut() {
            q.sort_unstable();
        }
        for x in &mut all {
            let k = x.s.body.signer;
            let depth = seqs.get(&k).map_or(0, |q| q.partition_point(|&s| s < x.s.body.seq));
            x.key = LimitKey { rank: rank.get(&k).copied().unwrap_or(3), depth, signer: k, id: x.s.id };
        }
        // Keys are unique (the ID is in them), so an unstable sort is exact
        // and needs no buffer as large as the set.
        all.sort_unstable_by_key(|x| x.key);
        let mut size = 0usize;
        let mut keep = all.len();
        for (i, x) in all.iter().enumerate() {
            let r = &x.s.record;
            let n = r.chain.iter().fold(r.body.len().saturating_add(r.sig.len()), |n, c| n.saturating_add(c.len()));
            size = size.saturating_add(n);
            if i >= MAX_RECORDS || size > MAX_SET_BYTES {
                keep = i;
                break;
            }
        }
        for x in all.get(keep..).unwrap_or_default() {
            self.fail(x.s.id, WHY_LIMIT);
        }
        (all, keep)
    }

    /// Marks the device records over MAX_DEVICES and MAX_ADMINS: the
    /// devices, and the admin keys of a root's own records, are taken in
    /// the LimitKey order of their first such record, and a record naming
    /// one past the limit counts for nothing.
    fn cap_devices(&mut self) {
        let admin_of = |x: &Rec| if x.admin() { None } else { x.b().admin.map(|a| a.text()) };
        let devices = self.over(MAX_DEVICES, |x| Some(x.b().device.clone()));
        let admins = self.over(MAX_ADMINS, admin_of);
        self.capped = (0..self.recs.len())
            .map(|i| {
                let x = &self.recs[i];
                x.b().kind == TYPE_DEVICE
                    && (devices.contains(&x.b().device) || admin_of(x).is_some_and(|a| admins.contains(&a)))
            })
            .collect();
    }

    /// Takes the names the device records give (name returns None for a
    /// record that gives none) in the LimitKey order of each name's first
    /// record and returns those past the first max.
    fn over(&self, max: usize, name: impl Fn(&Rec) -> Option<String>) -> BTreeSet<String> {
        let mut best: BTreeMap<String, LimitKey> = BTreeMap::new();
        for rs in self.devices.values() {
            for &i in rs {
                let x = &self.recs[i];
                if let Some(n) = name(x) {
                    let k = best.entry(n).or_insert(x.key);
                    *k = x.key.min(*k);
                }
            }
        }
        let mut names: Vec<(LimitKey, String)> = best.into_iter().map(|(n, k)| (k, n)).collect();
        names.sort();
        names.into_iter().skip(max).map(|(_, n)| n).collect()
    }

    /// Notes why a record was left out; of two copies of one body left out
    /// for different reasons, the reason first in byte order is kept,
    /// whatever the order of the set.
    fn fail(&mut self, id: Hash, why: &'static str) {
        let old = self.failed.entry(id).or_insert(why);
        if why < *old {
            *old = why;
        }
    }

    /// The highest seq of each signer whose prev chain is held whole down
    /// to seq 1. Only the group's signers count: the group CA, the root of
    /// a claim that one of the group's admins signed, and the admins under
    /// those roots; a root named in a claim nobody of the group signed
    /// could come and go with records that never counted. A whole chain,
    /// not the highest seq held, so that a record missing from the middle
    /// of a chain lowers it.
    fn seqs(&self, group_ca: Hash) -> BTreeMap<Hash, i64> {
        let roots = self.group_roots(group_ca);
        // A root's checkpoint lets a chain end at its anchors, so that a
        // set pruned by it is not taken for a rollback.
        let anchors: BTreeSet<Hash> = self
            .recs
            .iter()
            .filter(|r| r.b().kind == TYPE_CHECKPOINT && !r.admin() && roots.contains(&r.b().signer))
            .flat_map(|r| anchors_of(r.b()))
            .collect();
        let mut seqs = BTreeMap::new();
        // Past the limits too: a set that grows past them is no rollback.
        for (signer, rs) in &self.all_by_sig {
            let by_id: BTreeMap<Hash, usize> = rs.iter().map(|&i| (self.recs[i].s.id, i)).collect();
            let wholes = self.wholes(rs, &by_id, &anchors);
            for &i in rs {
                let r = &self.recs[i];
                let ours = match r.issuer {
                    Some(h) => roots.contains(&h),
                    None => !r.admin() && roots.contains(signer),
                };
                if ours && wholes.contains(&i) {
                    let s = seqs.entry(*signer).or_insert(0);
                    *s = r.b().seq.max(*s);
                }
            }
        }
        seqs
    }

    /// The records of rs (one signer's, by_id their IDs) whose prev chain
    /// down to seq 1, or to a record whose ID is one of anchors, is held,
    /// each step one seq lower. Each record is walked once, so that a long
    /// chain costs its length, not its square.
    fn wholes(&self, rs: &[usize], by_id: &BTreeMap<Hash, usize>, anchors: &BTreeSet<Hash>) -> BTreeSet<usize> {
        let step = |i: usize| -> Result<bool, usize> {
            let Some(r) = self.recs.get(i) else { return Ok(false) };
            if r.b().seq <= 1 || anchors.contains(&r.s.id) {
                return Ok(true);
            }
            let Some(&p) = r.b().prev.as_ref().and_then(|p| by_id.get(p)) else { return Ok(false) };
            let Some(prev) = self.recs.get(p) else { return Ok(false) };
            if Some(prev.b().seq) != r.b().seq.checked_sub(1) {
                return Ok(false);
            }
            Err(p)
        };
        let mut memo = BTreeMap::new();
        rs.iter().copied().filter(|&i| walk(&mut memo, i, step)).collect()
    }

    /// Turns the evaluation into its last epoch, with the claims of the
    /// roots before the current one.
    fn run(&self, input: &Input) -> Epoch<'_> {
        let mut path = vec![key_hash_of(input.group_ca)];
        let mut cuts = BTreeMap::new();
        let mut earlier = Vec::new();
        loop {
            let mut ep = Epoch::new(self, path.clone(), cuts.clone());
            match ep.decide_claims(input.now_ms, input.first_seen, input.time_unknown) {
                Some((next, cut)) => {
                    earlier.append(&mut ep.claims);
                    cuts.insert(*path.last().unwrap_or(&Hash::default()), cut);
                    path.push(next);
                }
                None => {
                    earlier.append(&mut ep.claims);
                    ep.claims = earlier;
                    return ep;
                }
            }
        }
    }

    /// The roots of the group: the group CA, and the root of each claim an
    /// admin under one of them signed.
    fn group_roots(&self, group_ca: Hash) -> BTreeSet<Hash> {
        let mut roots = BTreeSet::from([group_ca]);
        let mut grew = true;
        while grew {
            grew = false;
            for r in &self.recs {
                if r.b().kind == TYPE_CLAIM && r.issuer.is_some_and(|h| roots.contains(&h)) {
                    grew |= roots.insert(claim_root(r.b()));
                }
            }
        }
        roots
    }

    /// The checkpoints the evaluation tries, by index: a root's own, of a
    /// root of the group, at most MAX_CHECKPOINTS. They come from every
    /// verified record, past the limits too, so that a root's checkpoint can
    /// bring a set back under them.
    fn checkpoints(&self, group_ca: Hash) -> Vec<usize> {
        let roots = self.group_roots(group_ca);
        let mut cs: Vec<usize> = (0..self.recs.len())
            .filter(|&i| {
                let r = &self.recs[i];
                !r.admin() && r.b().kind == TYPE_CHECKPOINT && roots.contains(&r.b().signer)
            })
            .collect();
        cs.sort_by(|&a, &b| {
            let (ra, rb) = (&self.recs[a], &self.recs[b]);
            rb.b().seq.cmp(&ra.b().seq).then(ra.s.id.cmp(&rb.s.id))
        });
        cs.truncate(MAX_CHECKPOINTS);
        cs
    }

    /// Finds the root that issued an admin CA.
    fn issuer_of(&self, c: &Cert) -> Option<Hash> {
        if !c.is_ca || c.path_len != Some(0) || !c.cert_sign || !c.p256 {
            return None;
        }
        self.roots.iter().find(|(_, root)| root.is_ca && c.signed_by(root)).map(|(h, _)| *h)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Label {
    Unlabelled,
    In,
    Out,
    Undecided,
}

/// The evaluation under one path of roots.
struct Epoch<'a> {
    e: &'a Evaluation,
    path: Vec<Hash>,
    on_path: BTreeMap<Hash, usize>,
    cuts: BTreeMap<Hash, i64>,
    cur: Hash,
    voided: BTreeSet<Hash>,
    counted: Vec<bool>,
    forked: BTreeMap<Hash, i64>,
    admins: BTreeMap<Hash, usize>,
    /// The recovery record that counts, if any.
    recovery: Option<usize>,
    label: Vec<Label>,
    /// Why the labelling put a record out.
    why: Vec<&'static str>,
    revoked: BTreeSet<Hash>,
    frozen: BTreeSet<Hash>,
    conflicts: Vec<Conflict>,
    claims: Vec<Claim>,
    stop_full: bool,
    pending: Option<Hash>,
}

#[allow(clippy::indexing_slicing, reason = "positions come from the records' own Vec")]
impl<'a> Epoch<'a> {
    fn new(e: &'a Evaluation, path: Vec<Hash>, cuts: BTreeMap<Hash, i64>) -> Epoch<'a> {
        let cur = *path.last().unwrap_or(&Hash::default());
        let on_path = path.iter().enumerate().map(|(i, h)| (*h, i)).collect();
        let n = e.recs.len();
        let mut ep = Epoch {
            e,
            path,
            on_path,
            cuts,
            cur,
            voided: BTreeSet::new(),
            counted: vec![false; n],
            forked: BTreeMap::new(),
            admins: BTreeMap::new(),
            recovery: None,
            label: vec![Label::Unlabelled; n],
            why: vec![""; n],
            revoked: BTreeSet::new(),
            frozen: BTreeSet::new(),
            conflicts: Vec::new(),
            claims: Vec::new(),
            stop_full: false,
            pending: None,
        };
        ep.voided = ep.voids();
        for (signer, rs) in &e.by_sig {
            ep.chain(*signer, rs);
        }
        ep.find_admins();
        ep.do_label();
        ep.collect();
        ep
    }

    fn r(&self, i: usize) -> &'a Rec {
        &self.e.recs[i]
    }

    fn all(&self) -> core::ops::Range<usize> {
        0..self.e.kept
    }

    fn of(&self, signer: &Hash) -> &'a [usize] {
        self.e.by_sig.get(signer).map_or(&[], |v| v.as_slice())
    }

    /// Reports whether record i is a root's own record that counts in this
    /// epoch: its root is on the path and it is within that root's cut.
    fn root_record(&self, i: usize) -> bool {
        let r = self.r(i);
        if r.admin() || !self.counted[i] || self.e.capped[i] || !self.on_path.contains_key(&r.b().signer) {
            return false;
        }
        !matches!(self.cuts.get(&r.b().signer), Some(cut) if r.b().seq > *cut)
    }

    /// The records the current root's resolve records name; a resolve
    /// counts here when its own chain is whole.
    fn voids(&self) -> BTreeSet<Hash> {
        let rs = self.of(&self.cur);
        let by_id: BTreeMap<Hash, usize> = rs.iter().map(|&i| (self.r(i).s.id, i)).collect();
        let wholes = self.e.wholes(rs, &by_id, &self.e.anchors);
        let mut v = BTreeSet::new();
        for &i in rs {
            let r = self.r(i);
            if r.admin() || r.b().kind != TYPE_RESOLVE || !wholes.contains(&i) {
                continue;
            }
            v.extend(r.b().records.iter().copied());
        }
        v
    }

    /// Finds which of one signer's records count: whole chains, not on a
    /// branch a resolve voided, below the lowest seq with two records.
    fn chain(&mut self, signer: Hash, rs: &[usize]) {
        let by_id: BTreeMap<Hash, usize> = rs.iter().map(|&i| (self.r(i).s.id, i)).collect();
        let mut by_seq: BTreeMap<i64, usize> = BTreeMap::new();
        for &i in rs {
            let n = by_seq.entry(self.r(i).b().seq).or_default();
            *n = n.saturating_add(1);
        }
        // A record is dead when it or a record below it is voided and has
        // a twin of its seq; only whole chains are walked.
        let dead = |i: usize| -> Result<bool, usize> {
            let r = self.r(i);
            if self.voided.contains(&r.s.id) && by_seq[&r.b().seq] > 1 {
                return Ok(true);
            }
            if r.b().seq == 1 || self.e.anchors.contains(&r.s.id) {
                return Ok(false);
            }
            match r.b().prev.as_ref().and_then(|p| by_id.get(p)) {
                Some(&p) => Err(p),
                None => Ok(false),
            }
        };
        let wholes = self.e.wholes(rs, &by_id, &self.e.anchors);
        let mut dead_memo = BTreeMap::new();
        let mut live: BTreeMap<i64, Vec<usize>> = BTreeMap::new();
        for &i in rs {
            if wholes.contains(&i) && !walk(&mut dead_memo, i, dead) {
                live.entry(self.r(i).b().seq).or_default().push(i);
            }
        }
        let fork = live.iter().find(|(_, l)| l.len() > 1).map_or(MAX_SEQ + 1, |(s, _)| *s);
        if fork <= MAX_SEQ {
            self.forked.insert(signer, fork);
        }
        for (seq, l) in live {
            for i in l {
                if seq < fork && !self.voided.contains(&self.r(i).s.id) {
                    self.counted[i] = true;
                }
            }
        }
    }

    /// Reports whether root record a is newer than b: a later root on the
    /// path, then a higher seq.
    fn newer(&self, a: usize, b: usize) -> bool {
        let (a, b) = (self.r(a).b(), self.r(b).b());
        let pa = self.on_path.get(&a.signer).copied().unwrap_or(0);
        let pb = self.on_path.get(&b.signer).copied().unwrap_or(0);
        if pa != pb {
            return pa > pb;
        }
        a.seq > b.seq
    }

    /// The admin keys: the admin of a device record a root on the path
    /// signed, with the powers of the newest such record.
    fn find_admins(&mut self) {
        for rs in self.e.devices.values() {
            for &i in rs {
                let Some(a) = self.r(i).b().admin else { continue };
                if !self.root_record(i) {
                    continue;
                }
                match self.admins.get(&a) {
                    Some(&old) if !self.newer(i, old) => {}
                    _ => {
                        self.admins.insert(a, i);
                    }
                }
            }
        }
        // The recovery key: the admin of the newest recovery record a root
        // on the path signed, with takeover only, unless a device record
        // makes that key an admin too.
        self.recovery = None;
        let roots: Vec<Hash> = self.on_path.keys().copied().collect();
        for signer in &roots {
            for &i in self.of(signer) {
                if self.r(i).b().kind == TYPE_RECOVERY
                    && self.root_record(i)
                    && Cert::parse(&self.r(i).b().cert).is_ok_and(|c| self.e.issuer_of(&c) == Some(*signer))
                    && self.recovery.is_none_or(|old| self.newer(i, old))
                {
                    self.recovery = Some(i);
                }
            }
        }
        if let Some(i) = self.recovery {
            if let Some(a) = self.r(i).b().admin {
                self.admins.entry(a).or_insert(i);
            }
        }
    }

    fn has(&self, admin: &Hash, power: &str) -> bool {
        self.admins.get(admin).is_some_and(|&i| {
            let b = self.r(i).b();
            if b.kind == TYPE_RECOVERY { power == POWER_TAKEOVER } else { b.powers.iter().any(|p| p == power) }
        })
    }

    /// Reports whether k is an admin key or the member key of a device
    /// whose newest root record names one.
    fn is_admin(&self, k: &Hash) -> bool {
        self.admins.contains_key(k) || self.admins.values().any(|&i| self.r(i).b().key.as_ref() == Some(k))
    }

    /// Reports whether k is a root key or the member key of the root's own
    /// device.
    fn is_root(&self, k: &Hash) -> bool {
        self.e.roots.contains_key(k) || self.root_device().is_some_and(|d| self.r(d).b().key.as_ref() == Some(k))
    }

    /// The current root's newest device record with holds_root.
    fn root_device(&self) -> Option<usize> {
        let mut best: Option<usize> = None;
        for &i in self.of(&self.cur) {
            let b = self.r(i).b();
            if b.kind == TYPE_DEVICE
                && b.holds_root
                && self.root_record(i)
                && best.is_none_or(|x| b.seq > self.r(x).b().seq)
            {
                best = Some(i);
            }
        }
        best
    }

    /// Reports whether an admin may sign record i.
    fn permitted(&self, i: usize) -> bool {
        let r = self.r(i);
        let a = &r.b().signer;
        if !r.issuer.is_some_and(|h| self.on_path.contains_key(&h)) || !self.admins.contains_key(a) || self.e.capped[i]
        {
            return false;
        }
        let b = r.b();
        match b.kind.as_str() {
            TYPE_DEVICE => {
                self.has(a, POWER_ADMIT) && b.admin.is_none() && !b.holds_root && b.role != "phone" && b.role != "watch"
            }
            TYPE_REVOKE => b.keys.iter().all(|k| {
                if self.is_root(k) {
                    false
                } else if self.is_admin(k) {
                    self.has(a, POWER_REMOVE_ADMINS)
                } else {
                    self.has(a, POWER_REMOVE)
                }
            }),
            TYPE_FREEZE => {
                self.has(a, POWER_FREEZE)
                    && b.keys.iter().all(|k| self.admins.contains_key(k) && !self.has(k, POWER_REMOVE_ADMINS))
            }
            TYPE_THAW => self.has(a, POWER_THAW) && self.has(a, POWER_REMOVE_ADMINS),
            TYPE_CLAIM => self.has(a, POWER_TAKEOVER) && r.issuer == Some(self.cur),
            TYPE_HUBS => self.has(a, POWER_HUB),
            _ => false,
        }
    }

    /// Reports whether a, a revoke or freeze, cuts off b: it names b's
    /// signer and saw fewer of its records than b's seq.
    fn cuts_off(&self, a: usize, b: usize) -> bool {
        let (a, b) = (self.r(a).b(), self.r(b).b());
        a.signer != b.signer
            && (a.kind == TYPE_REVOKE || a.kind == TYPE_FREEZE)
            && a.keys.contains(&b.signer)
            && a.seen_of(&b.signer) < b.seq
    }

    fn thawed_by_root(&self) -> BTreeSet<Hash> {
        let mut t = BTreeSet::new();
        for i in self.all() {
            if self.r(i).b().kind == TYPE_THAW && self.root_record(i) {
                t.extend(self.r(i).b().records.iter().copied());
            }
        }
        t
    }

    /// Gives every admin record its label: the grounded labelling of the
    /// attacks of removals, freezes and thaws.
    fn do_label(&mut self) {
        let thawed = self.thawed_by_root();
        let mut admin_recs = Vec::new();
        let mut root_acts = Vec::new();
        for i in self.all() {
            let r = self.r(i);
            if self.root_record(i) {
                if r.b().kind == TYPE_REVOKE || r.b().kind == TYPE_FREEZE && !thawed.contains(&r.s.id) {
                    root_acts.push(i);
                }
            } else if r.admin() && self.counted[i] {
                if !self.permitted(i) {
                    self.label[i] = Label::Out;
                    self.why[i] = WHY_POWER;
                }
                admin_recs.push(i);
            }
        }
        // A root's removal or freeze puts what it cuts off out for good,
        // and a root's thaw puts out the admin freezes it names.
        for &b in &admin_recs {
            if self.label[b] == Label::Out {
                continue;
            }
            if self.r(b).b().kind == TYPE_FREEZE && thawed.contains(&self.r(b).s.id)
                || root_acts.iter().any(|&a| self.cuts_off(a, b))
            {
                self.label[b] = Label::Out;
                self.why[b] = WHY_CUT;
            }
        }
        let mut attackers: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
        for &b in &admin_recs {
            for &a in &admin_recs {
                if self.label[a] == Label::Out {
                    continue;
                }
                let (ab, bb) = (self.r(a).b(), self.r(b).b());
                // An admin's removal of a claimant does not cut its claim:
                // decide_claims sees it as a dispute.
                if self.cuts_off(a, b) && bb.kind != TYPE_CLAIM
                    || ab.kind == TYPE_THAW && bb.kind == TYPE_FREEZE && ab.records.contains(&self.r(b).s.id)
                {
                    attackers.entry(b).or_default().push(a);
                }
            }
        }
        let mut changed = true;
        while changed {
            changed = false;
            for &b in &admin_recs {
                if self.label[b] != Label::Unlabelled {
                    continue;
                }
                let mut all = true;
                for &a in attackers.get(&b).map_or(&[][..], |v| v.as_slice()) {
                    if self.label[a] == Label::In {
                        self.label[b] = Label::Out;
                        self.why[b] = WHY_REMOVED;
                        changed = true;
                        break;
                    }
                    if self.label[a] != Label::Out {
                        all = false;
                    }
                }
                if self.label[b] == Label::Unlabelled && all {
                    self.label[b] = Label::In;
                    changed = true;
                }
            }
        }
        let mut undec = Vec::new();
        for &b in &admin_recs {
            if self.label[b] == Label::Unlabelled {
                self.label[b] = Label::Undecided;
                if matches!(self.r(b).b().kind.as_str(), TYPE_REVOKE | TYPE_FREEZE | TYPE_THAW) {
                    undec.push(b);
                }
            }
        }
        self.conflicts_of(&undec, &attackers);
    }

    /// Groups undecided records that attack each other into conflicts.
    fn conflicts_of(&mut self, undec: &[usize], attackers: &BTreeMap<usize, Vec<usize>>) {
        let mut parent: BTreeMap<usize, usize> = undec.iter().map(|&r| (r, r)).collect();
        fn find(parent: &BTreeMap<usize, usize>, mut r: usize) -> usize {
            while parent[&r] != r {
                r = parent[&r];
            }
            r
        }
        for &b in undec {
            for &a in attackers.get(&b).map_or(&[][..], |v| v.as_slice()) {
                if parent.contains_key(&a) {
                    let (ra, rb) = (find(&parent, a), find(&parent, b));
                    parent.insert(ra, rb);
                }
            }
        }
        let mut by_root: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
        for &r in undec {
            by_root.entry(find(&parent, r)).or_default().push(r);
        }
        for rs in by_root.values() {
            let mut c = Conflict { kind: CONFLICT_ADMINS, records: Vec::new(), signers: Vec::new() };
            for &r in rs {
                c.records.push(self.r(r).s.id);
                if !c.signers.contains(&self.r(r).b().signer) {
                    c.signers.push(self.r(r).b().signer);
                }
            }
            self.conflicts.push(c);
            self.stop_full = true;
        }
    }

    /// Lists the records of the set that do not count, with why, sorted by
    /// ID, at most MAX_IGNORED; the records of a later version are in newer
    /// instead.
    fn ignored(&self, newer: &[Hash]) -> Vec<Ignored> {
        let mut why = self.e.failed.clone();
        for i in self.all() {
            let id = self.r(i).s.id;
            why.remove(&id);
            if let Some(w) = self.why_not(i) {
                why.insert(id, w);
            }
        }
        for id in newer {
            why.remove(id);
        }
        let mut out: Vec<Ignored> = why.into_iter().map(|(record, why)| Ignored { record, why }).collect();
        out.truncate(MAX_IGNORED);
        out
    }

    /// Why record i does not count in this epoch; None when it counts.
    fn why_not(&self, i: usize) -> Option<&'static str> {
        let r = self.r(i);
        let effective = |id: Hash| self.claims.iter().any(|c| c.record == id && c.state == "effective");
        Some(if self.counts(i) || r.b().kind == TYPE_CLAIM && effective(r.s.id) {
            // A claim that took effect counted under the root before.
            return None;
        } else if self.e.capped[i] {
            WHY_LIMIT
        } else if !self.counted[i] {
            WHY_HISTORY
        } else if !r.admin() {
            if self.on_path.contains_key(&r.b().signer) { WHY_CUT } else { WHY_NOT_ROOT }
        } else if self.label[i] == Label::Undecided {
            WHY_UNDECIDED
        } else if !self.why[i].is_empty() {
            self.why[i]
        } else {
            WHY_POWER
        })
    }

    /// The state, with the records of a later version and those left out.
    fn finish(&self, input: &Input) -> State {
        let mut state = self.state();
        state.newer = newer(input, &state, &self.e.roots);
        state.ignored = self.ignored(&state.newer);
        state
    }

    /// Reports whether record i counts: a root's record in this epoch, or
    /// an admin record that is in.
    fn counts(&self, i: usize) -> bool {
        self.root_record(i) || self.r(i).admin() && self.label[i] == Label::In
    }

    /// Finds the revoked and frozen keys and the two histories.
    fn collect(&mut self) {
        let thawed = self.thawed_by_root();
        for i in self.all() {
            if !self.counts(i) {
                continue;
            }
            let b = self.r(i).b();
            match b.kind.as_str() {
                TYPE_REVOKE => self.revoked.extend(b.keys.iter().copied()),
                TYPE_FREEZE if !thawed.contains(&self.r(i).s.id) => self.frozen.extend(b.keys.iter().copied()),
                _ => {}
            }
        }
        let forked: Vec<(Hash, i64)> = self.forked.iter().map(|(k, v)| (*k, *v)).collect();
        for (signer, seq) in forked {
            let records =
                self.of(&signer).iter().filter(|&&i| self.r(i).b().seq == seq).map(|&i| self.r(i).s.id).collect();
            self.conflicts.push(Conflict { kind: CONFLICT_TWO_HISTORIES, records, signers: vec![signer] });
            if self.on_path.contains_key(&signer) {
                self.stop_full = true;
            }
        }
    }

    /// The admin removals and freezes that count and name the admin key k
    /// or the member key of its device.
    fn removals(&self, k: &Hash) -> Vec<usize> {
        let mut keys = vec![*k];
        if let Some(key) = self.admins.get(k).and_then(|&d| self.r(d).b().key) {
            keys.push(key);
        }
        self.all()
            .filter(|&i| {
                let r = self.r(i);
                r.admin()
                    && self.label[i] == Label::In
                    && (r.b().kind == TYPE_REVOKE || r.b().kind == TYPE_FREEZE)
                    && keys.iter().any(|key| r.b().keys.contains(key))
            })
            .collect()
    }

    /// Reports whether a root's freeze, not thawed by a root, names k.
    fn root_frozen(&self, k: &Hash) -> bool {
        if !self.frozen.contains(k) {
            return false;
        }
        let thawed = self.thawed_by_root();
        self.all().any(|i| {
            let r = self.r(i);
            r.b().kind == TYPE_FREEZE && self.root_record(i) && !thawed.contains(&r.s.id) && r.b().keys.contains(k)
        })
    }

    fn claim(&self, i: usize, state: &'static str) -> Claim {
        let r = self.r(i);
        Claim { record: r.s.id, claimant: r.b().signer, root: claim_root(r.b()), state, left_ms: 0 }
    }

    /// The current root's newest settings record that counts.
    fn settings(&self) -> Option<usize> {
        let mut settings: Option<usize> = None;
        for &i in self.of(&self.cur) {
            if self.r(i).b().kind == TYPE_SETTINGS
                && self.root_record(i)
                && settings.is_none_or(|s| self.r(i).b().seq > self.r(s).b().seq)
            {
                settings = Some(i);
            }
        }
        settings
    }

    /// The current root's newest handover record that counts.
    fn handover(&self) -> Option<usize> {
        let mut h: Option<usize> = None;
        for &i in self.of(&self.cur) {
            if self.r(i).b().kind == TYPE_HANDOVER
                && self.root_record(i)
                && h.is_none_or(|o| self.r(i).b().seq > self.r(o).b().seq)
            {
                h = Some(i);
            }
        }
        h
    }

    /// Looks at the claims under the current root and returns the next
    /// root and the current root's cut when one takes effect.
    fn decide_claims(&mut self, now: i64, first_seen: &BTreeMap<Hash, i64>, unknown: bool) -> Option<(Hash, i64)> {
        let mut delay = DEFAULT_DELAY;
        if let Some(d) = self.settings().and_then(|s| self.r(s).b().takeover_delay_ms) {
            delay = d;
        }
        let cancelled = |c: usize| {
            let c = self.r(c);
            self.of(&self.cur).iter().any(|&i| {
                let b = self.r(i).b();
                self.root_record(i)
                    && (b.kind == TYPE_RESOLVE && b.records.contains(&c.s.id)
                        || b.kind == TYPE_REVOKE && b.keys.contains(&c.b().signer))
            })
        };
        let mut live = Vec::new();
        let mut decided = Vec::new();
        for i in self.all() {
            let c = self.r(i);
            if c.b().kind != TYPE_CLAIM
                || !c.admin()
                || c.issuer != Some(self.cur)
                || !self.counted[i] && !self.voided.contains(&c.s.id)
            {
                continue;
            }
            let root = Cert::parse(&c.b().root).ok();
            let root_hash = root.as_ref().map(key_hash_of);
            let state = match root_hash {
                None => Some("void"),
                Some(h) if !self.e.roots.contains_key(&h) || h == self.path[0] => Some("void"),
                _ if cancelled(i) => Some("cancelled"),
                _ if self.label[i] == Label::Out => Some("void"),
                Some(h) if self.on_path.contains_key(&h) => Some("void"),
                _ => None,
            };
            match state {
                Some(s) => decided.push(self.claim(i, s)),
                None => live.push(i),
            }
        }
        self.claims.append(&mut decided);
        // An admin's removal or freeze of a claimant that the claimant had
        // seen voids its claim; one it had not seen disputes it, whatever
        // else its author had seen (a claimed root can sign before its claim
        // takes effect).
        let mut disputes: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
        let mut kept = Vec::new();
        for &c in &live {
            let cb = self.r(c).b();
            let mut void = false;
            for r in self.removals(&cb.signer) {
                let rb = self.r(r).b();
                if cb.seen_of(&rb.signer) >= rb.seq {
                    void = true;
                } else {
                    disputes.entry(c).or_default().push(r);
                }
            }
            if void {
                let cl = self.claim(c, "void");
                self.claims.push(cl);
            } else {
                kept.push(c);
            }
        }
        // One claim at a time: a claim whose author held another live claim
        // counts for nothing.
        let mut first = Vec::new();
        for &c in &kept {
            let later =
                kept.iter().any(|&o| o != c && self.r(c).b().seen_of(&self.r(o).b().signer) >= self.r(o).b().seq);
            if later {
                let cl = self.claim(c, "void");
                self.claims.push(cl);
            } else {
                first.push(c);
            }
        }
        if first.len() > 1 {
            let mut conflict = Conflict { kind: CONFLICT_CLAIMS, records: Vec::new(), signers: Vec::new() };
            for &r in &first {
                let cl = self.claim(r, "competing");
                self.claims.push(cl);
                conflict.records.push(self.r(r).s.id);
                conflict.signers.push(self.r(r).b().signer);
            }
            self.conflicts.push(conflict);
            self.stop_full = true;
            return None;
        }
        let &c = first.first()?;
        if let Some(ds) = disputes.get(&c) {
            let cl = self.claim(c, "disputed");
            self.claims.push(cl);
            let mut conflict =
                Conflict { kind: CONFLICT_CLAIMS, records: vec![self.r(c).s.id], signers: vec![self.r(c).b().signer] };
            for &r in ds {
                conflict.records.push(self.r(r).s.id);
                if !conflict.signers.contains(&self.r(r).b().signer) {
                    conflict.signers.push(self.r(r).b().signer);
                }
            }
            self.conflicts.push(conflict);
            self.stop_full = true;
            return None;
        }
        let r = self.r(c);
        let mut cl = self.claim(c, "pending");
        if let Some(h) = self.handover()
            && self.r(h).b().admin == Some(r.b().signer)
            && r.b().seen_of(&self.cur) >= self.r(h).b().seq
        {
            // The root handed the group to this admin: its claim, made after
            // it held the handover, takes effect without the delay.
            delay = 0;
        }
        let seen = first_seen.get(&r.s.id).copied().filter(|&s| s <= now).unwrap_or(now);
        let waits = unknown && delay > 0;
        // Saturating: a caller's times are any i64.
        let elapsed = now.saturating_sub(seen);
        if self.label[c] != Label::In || self.root_frozen(&r.b().signer) || waits || elapsed < delay {
            cl.left_ms = if unknown { 0 } else { delay.saturating_sub(elapsed).max(0) };
            self.claims.push(cl);
            self.pending = Some(r.b().signer);
            return None;
        }
        if self.path.len() >= MAX_PATH {
            // A handover past the limit on the path counts for nothing.
            cl.state = "void";
            self.claims.push(cl);
            return None;
        }
        cl.state = "effective";
        let next = cl.root;
        self.claims.push(cl);
        Some((next, r.b().seen_of(&self.cur)))
    }

    /// Builds the state of the last epoch.
    fn state(&self) -> State {
        let mut s = State { roots: self.path.clone(), stop: STOP_NONE.into(), ..State::default() };
        if let Some(d) = self.root_device() {
            if !self.r(d).b().key.is_some_and(|k| self.revoked.contains(&k)) {
                s.root_device = self.r(d).b().device.clone();
            }
        }
        let forked_admin = self.forked.keys().any(|k| !self.on_path.contains_key(k));
        for (id, rs) in &self.e.devices {
            if let Some(d) = self.device(id, rs) {
                s.devices.push(d);
            }
            // The devices that an admin with two histories alone admitted
            // get nothing.
            let alone = !rs.is_empty()
                && rs.iter().all(|&i| self.forked.contains_key(&self.r(i).b().signer) && self.r(i).admin());
            if alone {
                s.nothing_to.push(id.clone());
            }
            if let Some(p) = self.pending {
                if rs.iter().any(|&i| self.r(i).b().admin == Some(p) && self.root_record(i)) {
                    s.no_secrets_to.push(id.clone());
                }
            }
        }
        s.devices.sort_by(|a, b| a.device.cmp(&b.device));
        s.nothing_to.sort();
        s.no_secrets_to.sort();
        s.revoked = self.revoked.iter().copied().collect();
        s.revoked.sort();
        s.claims = self.claims.clone();
        s.claims.sort_by_key(|c| c.record);
        s.conflicts = self.conflicts.clone();
        for c in &mut s.conflicts {
            c.records.sort();
            c.signers.sort();
        }
        s.conflicts.sort_by(|a, b| a.records.first().cmp(&b.records.first()));
        s.hubs = self.hubs(&s.devices);
        if let Some(i) = self.settings() {
            s.key_level = self.r(i).b().key_level.clone();
        }
        if let Some(i) = self.recovery {
            if let Some(a) = self.r(i).b().admin {
                if self.admins.get(&a) == Some(&i) && !self.revoked.contains(&a) && !self.frozen.contains(&a) {
                    s.recovery = Some(a);
                }
            }
        }
        if self.stop_full {
            s.stop = STOP_FULL.into();
        } else if forked_admin {
            s.stop = STOP_SECRETS.into();
        }
        s
    }

    /// The main hubs of the hubs record that counts: a root's beats an
    /// admin's, a later root's an earlier one's, then the higher seq; among
    /// admins the later time_ms, then the smaller signer, then the higher
    /// seq. Only the devices it names that are among devices with the role
    /// full or phone are kept.
    fn hubs(&self, devices: &[Device]) -> Vec<String> {
        let mut best: Option<usize> = None;
        for &i in self.e.by_sig.values().flatten() {
            if self.r(i).b().kind == TYPE_HUBS && self.counts(i) && best.is_none_or(|b| self.newer_hubs(i, b)) {
                best = Some(i);
            }
        }
        let Some(best) = best else { return Vec::new() };
        self.r(best)
            .b()
            .hubs
            .iter()
            .filter(|h| devices.iter().any(|d| &d.device == *h && (d.role == "full" || d.role == "phone")))
            .cloned()
            .collect()
    }

    /// Reports whether hubs record a beats b.
    fn newer_hubs(&self, a: usize, b: usize) -> bool {
        let (ra, rb) = (!self.r(a).admin(), !self.r(b).admin());
        if ra != rb {
            return ra;
        }
        if ra {
            return self.newer(a, b);
        }
        let (ba, bb) = (self.r(a).b(), self.r(b).b());
        if ba.time_ms != bb.time_ms {
            return ba.time_ms > bb.time_ms;
        }
        if ba.signer != bb.signer {
            return ba.signer < bb.signer;
        }
        ba.seq > bb.seq
    }

    /// Builds one device of the state from its counting records.
    fn device(&self, id: &str, rs: &[usize]) -> Option<Device> {
        let mut counting: Vec<usize> = rs
            .iter()
            .copied()
            .filter(|&i| self.counts(i) && !self.r(i).b().key.is_some_and(|k| self.revoked.contains(&k)))
            .collect();
        if counting.is_empty() {
            return None;
        }
        let keys: BTreeSet<Hash> = counting.iter().filter_map(|&i| self.r(i).b().key).collect();
        // The newest record: a root's beats an admin's, a later root's an
        // earlier one's, then the higher seq; among admins the larger signer.
        counting.sort_by(|&a, &b| {
            let (ra, rb) = (!self.r(a).admin(), !self.r(b).admin());
            if ra != rb {
                return if ra { Ordering::Less } else { Ordering::Greater };
            }
            if ra {
                return if self.newer(a, b) {
                    Ordering::Less
                } else if self.newer(b, a) {
                    Ordering::Greater
                } else {
                    Ordering::Equal
                };
            }
            let (ba, bb) = (self.r(a).b(), self.r(b).b());
            bb.signer.cmp(&ba.signer).then(bb.seq.cmp(&ba.seq))
        });
        let top = counting[0];
        let n = self.r(top).b();
        let mut d = Device {
            device: String::from(id),
            name: n.name.clone(),
            role: n.role.clone(),
            os: n.os.clone(),
            keys: keys.into_iter().collect(),
            store: n.store.clone(),
            hardware: n.hardware.clone(),
            proof: n.proof.clone(),
            seal: n.seal.clone(),
            ..Device::default()
        };
        d.keys.sort();
        if let Some(a) = n.admin {
            if !self.r(top).admin() && !self.revoked.contains(&a) && self.admins.get(&a) == Some(&top) {
                d.admin = Some(a);
                d.powers = n.powers.clone();
                d.commands = n.commands.clone();
                d.frozen = self.frozen.contains(&a);
            }
        }
        Some(d)
    }
}

/// Follows a chain from i by step, which either decides a record
/// (Ok) or names the record below it (Err), and gives every record on
/// the way the answer at its end; memo keeps the answers, so that each
/// record is stepped at most once across calls.
fn walk(memo: &mut BTreeMap<usize, bool>, mut i: usize, step: impl Fn(usize) -> Result<bool, usize>) -> bool {
    let mut path = Vec::new();
    let v = loop {
        if let Some(&v) = memo.get(&i) {
            break v;
        }
        match step(i) {
            Ok(v) => {
                memo.insert(i, v);
                break v;
            }
            Err(p) => {
                path.push(i);
                i = p;
            }
        }
    };
    for j in path {
        memo.insert(j, v);
    }
    v
}

fn claim_root(b: &Body) -> Hash {
    Cert::parse(&b.root).map(|c| key_hash_of(&c)).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The cases of v2-records.json and v2-flood.json (the sets at the
    /// limit on records, apart for the size of a file) in one "cases".
    fn vectors() -> serde_json::Value {
        let mut cases = Vec::new();
        for name in ["v2-records.json", "v2-flood.json"] {
            let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/interop").join(name);
            let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            cases.extend(v["cases"].as_array().unwrap().iter().cloned());
        }
        serde_json::json!({ "cases": cases })
    }

    /// Every case of the vectors gives the state Go gives, byte for byte,
    /// in every order tried.
    #[test]
    fn v2_vectors() {
        let v = vectors();
        let cases = v["cases"].as_array().unwrap();
        assert!(cases.len() >= 19);
        for c in cases {
            let name = c["name"].as_str().unwrap();
            let ca = Cert::parse(&STANDARD.decode(c["group_ca"].as_str().unwrap()).unwrap()).unwrap();
            let records: Vec<Record> = serde_json::from_value(c["records"].clone()).unwrap();
            let mut first_seen = BTreeMap::new();
            for f in c["first_seen"].as_array().map_or(&[][..], |a| a.as_slice()) {
                let h: Hash = serde_json::from_value(f["record"].clone()).unwrap();
                first_seen.insert(h, f["ms"].as_i64().unwrap());
            }
            let want = c["state"].as_str().unwrap();
            let mut rs = records.clone();
            let cache = SigCache::new();
            for order in 0..4 {
                if order == 1 {
                    rs.reverse();
                } else if order > 1 {
                    let n = rs.len().max(1);
                    rs.rotate_left(order % n);
                }
                let input = Input {
                    group_ca: &ca,
                    group: c["group"].as_str().unwrap(),
                    records: &rs,
                    now_ms: c["now_ms"].as_i64().unwrap(),
                    first_seen: &first_seen,
                    time_unknown: c["time_unknown"].as_bool().unwrap_or(false),
                    sigs: if order % 2 == 0 { Some(&cache) } else { None },
                };
                let got = evaluate(&input).encode();
                assert_eq!(core::str::from_utf8(&got).unwrap(), want, "{name}, order {order}");
            }
        }
    }

    /// Each body in the vectors reads and writes back to the same bytes,
    /// and changed bodies are refused.
    #[test]
    fn bodies() {
        let v = vectors();
        let mut n = 0;
        for c in v["cases"].as_array().unwrap() {
            let records: Vec<Record> = serde_json::from_value(c["records"].clone()).unwrap();
            for r in records {
                // The bodies of a later version have no alg and do not read.
                let Ok(b) = Body::parse(&r.body) else {
                    assert!(!r.body.windows(5).any(|w| w == br#""alg""#), "{}", c["name"]);
                    continue;
                };
                assert_eq!(b.encode().unwrap(), r.body);
                n += 1;
            }
        }
        assert!(n > 0);
        let good = r#"{"alg":"es256","device":"0123456789abcdef0123456789abcdef","group":"g","key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","name":"Laptop","role":"full","seq":1,"signer":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","time_ms":1,"type":"device","v":2}"#;
        Body::parse(good.as_bytes()).unwrap();
        for bad in [
            good.replace(r#"{"#, r#"{"aaa":1,"#),
            good.replace(r#""alg":"es256""#, r#""alg":"es384""#),
            good.replace(r#""alg":"es256","#, ""),
            good.replace(r#""device""#, r#""commands":[],"device""#),
            good.replace(r#""key""#, r#""holds_root":false,"key""#),
            good.replace(r#""v":2"#, r#""v":1"#),
            good.replace(r#""seq":1"#, r#""seq":2"#),
            good.replace(r#""role":"full""#, r#""role":"linux""#),
            good.replace(r#""name""#, r#""keys":["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="],"name""#),
            good.replace(r#"{"#, r#"{ "#),
        ] {
            assert!(Body::parse(bad.as_bytes()).is_err(), "{bad} is taken");
        }
        let hubs = |list: &str| {
            format!(
                r#"{{"alg":"es256","group":"g","hubs":[{list}],"seq":1,"signer":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","time_ms":1,"type":"hubs","v":2}}"#
            )
        };
        let (a, b) = (r#""bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb""#, r#""aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa""#);
        Body::parse(hubs(&format!("{a},{b}")).as_bytes()).unwrap();
        let many: Vec<String> = (0..=MAX_HUBS).map(|i| format!(r#""{i:032x}""#)).collect();
        for bad in [hubs(""), hubs(&format!("{a},{a}")), hubs(r#""ABCDEF""#), hubs(&many.join(","))] {
            assert!(Body::parse(bad.as_bytes()).is_err(), "{bad} is taken");
        }
    }
}
