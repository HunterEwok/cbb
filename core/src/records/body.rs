// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The bodies of records v3 (format-0.6 section 4): their fields as Rust
//! types, the checks of each field's row, and their encoding.

use alloc::string::String;
use alloc::vec::Vec;

use super::cbor::{self, Map};
use super::key::{DeviceId, GroupId, Key, KeyCheck, KeyHash, RecordId};
use super::{MAX_SEQ, Rule};

/// Record types (section 4).
pub const TYPE_DEVICE: u64 = 1;
pub const TYPE_REVOKE: u64 = 2;
pub const TYPE_FREEZE: u64 = 3;
pub const TYPE_THAW: u64 = 4;
pub const TYPE_CLAIM: u64 = 5;
pub const TYPE_RESOLVE: u64 = 6;
pub const TYPE_SETTINGS: u64 = 7;
pub const TYPE_COPIES: u64 = 8;
pub const TYPE_CHECKPOINT: u64 = 9;
pub const TYPE_HUBS: u64 = 10;
pub const TYPE_RECOVERY: u64 = 11;
pub const TYPE_HANDOVER: u64 = 12;

/// Roles of a device record.
pub const ROLE_MEMBER: u64 = 1;
pub const ROLE_PHONE: u64 = 2;
pub const ROLE_WATCH: u64 = 3;
pub const ROLE_LEAF: u64 = 4;

/// Rights bits: copies are sealed to it, it makes copies, it is a hub, and
/// secrets are sealed to it. Bits a version does not know grant nothing.
pub const RIGHT_READ: u64 = 1;
pub const RIGHT_SEND: u64 = 2;
pub const RIGHT_HUB: u64 = 4;
pub const RIGHT_SECRETS: u64 = 8;

/// Caps bits (only with role member).
pub const CAP_ADMIN: u64 = 1;
pub const CAP_DIALS: u64 = 2;
pub const CAP_HUB: u64 = 4;

/// Powers of an admin key.
pub const POWER_ADMIT: u64 = 1;
pub const POWER_MANAGE: u64 = 2;
pub const POWER_REMOVE: u64 = 4;
pub const POWER_REMOVE_ADMINS: u64 = 8;
pub const POWER_FREEZE: u64 = 16;
pub const POWER_THAW: u64 = 32;
pub const POWER_TAKEOVER: u64 = 64;
pub const POWER_HUB: u64 = 128;
pub const POWER_PERIODS: u64 = 256;
const POWERS_ALL: u64 = 511;

/// Store kinds; `proof` only with STORE_PROVEN.
pub const STORE_FILE: u64 = 1;
pub const STORE_HARDWARE: u64 = 2;
pub const STORE_ROOTLESS: u64 = 3;
pub const STORE_PROVEN: u64 = 4;

/// Key levels of `settings`.
pub const LEVEL_PROVEN: u64 = 1;
pub const LEVEL_HARDWARE: u64 = 2;
pub const LEVEL_FILES: u64 = 3;

/// The settings' defaults.
pub const DEFAULT_DELAY_MS: u64 = 259_200_000;
pub const MAX_DELAY_MS: u64 = 604_800_000;
pub const DEFAULT_ADMIN_LIMIT: u64 = 128;
pub const MIN_INCOMING_MS: u64 = 5_000;
pub const MAX_INCOMING_MS: u64 = 3_600_000;
pub const MAX_KEYS: usize = 256;
pub const MAX_HUBS: usize = 16;
pub const MAX_SERVERS: usize = 16;

/// A record's body.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Body {
    pub group: GroupId,
    pub signer: KeyHash,
    pub seq: u64,
    /// The ID of the signer's record with seq − 1; none when seq is 1.
    pub prev: Option<RecordId>,
    /// The signer's clock, for display; 0 when not written.
    pub time_ms: u64,
    pub kind: Kind,
    /// The body has a field of the critical zone (or a second signer) this
    /// version does not know: it is kept and passed on, never applied
    /// (section 3.3). The reader sets it; the writer refuses to sign it.
    pub held: bool,
}

/// A record's type with its own fields.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Kind {
    Device(Device),
    Revoke(Removal),
    Freeze(Removal),
    Thaw(Vec<RecordId>),
    Claim {
        root: Key,
        seen: Vec<Seen>,
    },
    Resolve(Vec<RecordId>),
    Settings(Settings),
    Copies {
        incoming_ms: u64,
    },
    Checkpoint {
        heads: Vec<Head>,
        keep: Vec<RecordId>,
    },
    Hubs(Vec<DeviceId>),
    Recovery {
        admin: Key,
    },
    Handover {
        admin: KeyHash,
    },
    /// A type of a later version: held.
    Unknown(u64),
}

/// `[key hash, seq]` of a revoke, freeze or claim: how many of each
/// signer's records the author held.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Seen {
    pub key: KeyHash,
    pub seq: u64,
}

/// `[key hash, seq, record ID]` of a checkpoint.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Head {
    pub key: KeyHash,
    pub seq: u64,
    pub id: RecordId,
}

/// The fields of a revoke or a freeze.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Removal {
    pub keys: Vec<KeyHash>,
    pub seen: Vec<Seen>,
}

impl Removal {
    /// The seq the author held of signer.
    pub fn seen_of(&self, signer: &KeyHash) -> u64 {
        seen_of(&self.seen, signer)
    }

    /// The removal signed again (after a root voided its signer's two
    /// histories): the keys it names keep what the first one saw of them,
    /// or less, so that nothing they signed in between counts; the other
    /// entries are the signer's current ones.
    pub fn signed_again(&self, current: &[Seen]) -> Removal {
        let mut seen: Vec<Seen> = current
            .iter()
            .filter(|c| self.keys.binary_search(&c.key).is_err())
            .copied()
            .chain(self.keys.iter().map(|k| Seen { key: *k, seq: self.seen_of(k).min(seen_of(current, k)) }))
            .filter(|s| s.seq != 0)
            .collect();
        seen.sort_by_key(|s| s.key);
        Removal { keys: self.keys.clone(), seen }
    }
}

pub fn seen_of(seen: &[Seen], signer: &KeyHash) -> u64 {
    seen.binary_search_by(|s| s.key.cmp(signer)).ok().and_then(|i| seen.get(i)).map_or(0, |s| s.seq)
}

/// The fields of a device record (section 4.1).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Device {
    pub key: Key,
    pub name: String,
    pub role: u64,
    pub rights: u64,
    pub skip: u64,
    pub caps: u64,
    pub os: u64,
    pub store: u64,
    pub proof: u64,
    pub admin: Option<Key>,
    pub powers: u64,
    pub commands: u64,
    pub holds_root: bool,
    pub replaces: Option<KeyHash>,
    /// A guarded leaf (a lock, a door), field 25: only a root's record for
    /// it counts, and once a root set it, it stays for the device's ID (a
    /// reset leaf has a new key).
    pub guarded: bool,
}

impl Device {
    /// A member with no rights and the defaults, for building records.
    pub fn new(key: Key, name: &str, role: u64) -> Device {
        Device {
            key,
            name: String::from(name),
            role,
            rights: 0,
            skip: 0,
            caps: 0,
            os: 0,
            store: STORE_FILE,
            proof: 0,
            admin: None,
            powers: 0,
            commands: 0,
            holds_root: false,
            replaces: None,
            guarded: false,
        }
    }

    /// The device's ID: the first 16 bytes of its member key's hash.
    pub fn id(&self) -> DeviceId {
        self.key.device_id()
    }
}

/// The fields of settings (section 4.5); a field at its default is 0 here
/// and left out of the encoding.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Settings {
    pub takeover_delay_ms: Option<u64>,
    pub key_level: u64,
    pub min_rules: u64,
    pub admin_limit: u64,
    pub shared: bool,
    pub servers: Vec<Server>,
}

/// A server of the group's list.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Server {
    pub kind: u64,
    pub endpoint: String,
    pub key: Key,
}

pub const SERVER_FORWARDER: u64 = 1;
pub const SERVER_RELAY: u64 = 2;

impl Kind {
    pub fn type_number(&self) -> u64 {
        match self {
            Kind::Device(_) => TYPE_DEVICE,
            Kind::Revoke(_) => TYPE_REVOKE,
            Kind::Freeze(_) => TYPE_FREEZE,
            Kind::Thaw(_) => TYPE_THAW,
            Kind::Claim { .. } => TYPE_CLAIM,
            Kind::Resolve(_) => TYPE_RESOLVE,
            Kind::Settings(_) => TYPE_SETTINGS,
            Kind::Copies { .. } => TYPE_COPIES,
            Kind::Checkpoint { .. } => TYPE_CHECKPOINT,
            Kind::Hubs(_) => TYPE_HUBS,
            Kind::Recovery { .. } => TYPE_RECOVERY,
            Kind::Handover { .. } => TYPE_HANDOVER,
            Kind::Unknown(t) => *t,
        }
    }

    /// The types every version from 0.6 on must apply: they are written
    /// with the fields of 0.6 only (section 3.3).
    pub fn frozen_form(&self) -> bool {
        matches!(
            self,
            Kind::Revoke(_) | Kind::Freeze(_) | Kind::Claim { .. } | Kind::Resolve(_) | Kind::Handover { .. }
        )
    }
}

fn field(t: &'static str, f: &'static str) -> Rule {
    Rule::field(t, f)
}

fn type_name(t: u64) -> &'static str {
    match t {
        TYPE_DEVICE => "device",
        TYPE_REVOKE => "revoke",
        TYPE_FREEZE => "freeze",
        TYPE_THAW => "thaw",
        TYPE_CLAIM => "claim",
        TYPE_RESOLVE => "resolve",
        TYPE_SETTINGS => "settings",
        TYPE_COPIES => "copies",
        TYPE_CHECKPOINT => "checkpoint",
        TYPE_HUBS => "hubs",
        TYPE_RECOVERY => "recovery",
        TYPE_HANDOVER => "handover",
        _ => "unknown",
    }
}

/// Reports whether v is sorted strictly increasing (so each value once).
fn strictly_sorted<T: Ord>(v: &[T]) -> bool {
    v.windows(2).all(|w| matches!(w, [a, b] if a < b))
}

/// A device name or an endpoint: no control character.
fn plain_text(s: &str) -> bool {
    !s.chars().any(|c| matches!(c, '\u{0}'..='\u{1f}' | '\u{7f}'..='\u{9f}'))
}

/// Checks a key and reports whether it is of an algorithm this version
/// does not know; such a key where a signature key is wanted holds the
/// record.
fn signer_key(k: &Key, t: &'static str, f: &'static str) -> Result<bool, Rule> {
    match k.check_signer() {
        Ok(KeyCheck::Good) => Ok(false),
        Ok(KeyCheck::Unknown) => Ok(true),
        Err(_) => Err(field(t, f)),
    }
}

impl Body {
    /// Checks each field against its row (section 4) and returns whether
    /// the record is held: a key of an unknown algorithm where a signature
    /// key is wanted, besides what the reader found (`held`).
    pub fn check(&self) -> Result<bool, Rule> {
        let t = type_name(self.kind.type_number());
        if self.seq == 0 || self.seq > MAX_SEQ {
            return Err(field("common", "seq"));
        }
        if (self.seq == 1) != self.prev.is_none() {
            return Err(field("common", "prev"));
        }
        let mut held = self.held;
        match &self.kind {
            Kind::Device(d) => held |= check_device(d)?,
            Kind::Revoke(r) | Kind::Freeze(r) => {
                if r.keys.is_empty() || r.keys.len() > MAX_KEYS || !strictly_sorted(&r.keys) {
                    return Err(field(t, "keys"));
                }
                if !strictly_sorted(&r.seen) || r.seen.len() > super::MAX_SEEN || r.seen.iter().any(|s| s.seq > MAX_SEQ)
                {
                    return Err(field(t, "seen"));
                }
            }
            Kind::Thaw(ids) | Kind::Resolve(ids) => {
                if ids.is_empty() || ids.len() > MAX_KEYS || !strictly_sorted(ids) {
                    return Err(field(t, "records"));
                }
            }
            Kind::Claim { root, seen } => {
                held |= signer_key(root, t, "root")?;
                if !strictly_sorted(seen) || seen.len() > super::MAX_SEEN || seen.iter().any(|s| s.seq > MAX_SEQ) {
                    return Err(field(t, "seen"));
                }
            }
            Kind::Settings(s) => held |= check_settings(s)?,
            Kind::Copies { incoming_ms } => {
                if !(MIN_INCOMING_MS..=MAX_INCOMING_MS).contains(incoming_ms) {
                    return Err(field(t, "incoming_ms"));
                }
            }
            Kind::Checkpoint { heads, keep } => {
                let keys: Vec<KeyHash> = heads.iter().map(|h| h.key).collect();
                if heads.is_empty() || !strictly_sorted(&keys) || heads.iter().any(|h| h.seq == 0 || h.seq > MAX_SEQ) {
                    return Err(field(t, "heads"));
                }
                if !strictly_sorted(keep) {
                    return Err(field(t, "keep"));
                }
            }
            Kind::Hubs(hubs) => {
                let mut sorted = hubs.clone();
                sorted.sort();
                sorted.dedup();
                if hubs.is_empty() || hubs.len() > MAX_HUBS || sorted.len() != hubs.len() {
                    return Err(field(t, "hubs"));
                }
            }
            Kind::Recovery { admin } => held |= signer_key(admin, t, "admin")?,
            Kind::Handover { .. } => {}
            Kind::Unknown(n) => {
                if *n == 0 {
                    return Err(field("common", "type"));
                }
                held = true;
            }
        }
        Ok(held)
    }

    /// The body's bytes in the profile. A held body has a critical field
    /// this version does not write; the writer here marks it with field 250
    /// so that the tests can make one.
    pub fn encode(&self) -> Vec<u8> {
        let mut m = Map::new();
        m.put(1, cbor::uint(self.kind.type_number()));
        m.put(2, cbor::bytes(&self.group.0));
        m.put(3, cbor::bytes(&self.signer.0));
        m.put(4, cbor::uint(self.seq));
        if let Some(p) = &self.prev {
            m.put(5, cbor::bytes(&p.0));
        }
        if self.time_ms != 0 {
            m.put(6, cbor::uint(self.time_ms));
        }
        if self.held {
            m.put(250, cbor::uint(1));
        }
        let seen = |s: &[Seen]| cbor::array(s.iter().map(|s| cbor::array([cbor::bytes(&s.key.0), cbor::uint(s.seq)])));
        let ids = |v: &[RecordId]| cbor::array(v.iter().map(|i| cbor::bytes(&i.0)));
        match &self.kind {
            Kind::Device(d) => encode_device(&mut m, d),
            Kind::Revoke(r) | Kind::Freeze(r) => {
                m.put(10, cbor::array(r.keys.iter().map(|k| cbor::bytes(&k.0))));
                m.put(11, seen(&r.seen));
            }
            Kind::Thaw(v) | Kind::Resolve(v) => {
                m.put(10, ids(v));
            }
            Kind::Claim { root, seen: s } => {
                m.put(10, root.encode());
                m.put(11, seen(s));
            }
            Kind::Settings(s) => encode_settings(&mut m, s),
            Kind::Copies { incoming_ms } => {
                m.put(10, cbor::uint(*incoming_ms));
            }
            Kind::Checkpoint { heads, keep } => {
                m.put(
                    10,
                    cbor::array(
                        heads
                            .iter()
                            .map(|h| cbor::array([cbor::bytes(&h.key.0), cbor::uint(h.seq), cbor::bytes(&h.id.0)])),
                    ),
                );
                if !keep.is_empty() {
                    m.put(11, ids(keep));
                }
            }
            Kind::Hubs(h) => {
                m.put(10, cbor::array(h.iter().map(|d| cbor::bytes(&d.0))));
            }
            Kind::Recovery { admin } => {
                m.put(10, admin.encode());
            }
            Kind::Handover { admin } => {
                m.put(10, cbor::bytes(&admin.0));
            }
            Kind::Unknown(_) => {}
        }
        m.finish()
    }
}

fn check_device(d: &Device) -> Result<bool, Rule> {
    let t = "device";
    let mut held = signer_key(&d.key, t, "key")?;
    if d.name.is_empty() || d.name.len() > 64 || !plain_text(&d.name) {
        return Err(field(t, "name"));
    }
    if !(ROLE_MEMBER..=ROLE_LEAF).contains(&d.role) {
        return Err(field(t, "role"));
    }
    if d.caps != 0 && d.role != ROLE_MEMBER || d.caps > (CAP_ADMIN | CAP_DIALS | CAP_HUB) {
        return Err(field(t, "caps"));
    }
    if d.os > 10 {
        return Err(field(t, "os"));
    }
    if !(STORE_FILE..=STORE_PROVEN).contains(&d.store) {
        return Err(field(t, "store"));
    }
    if d.proof > 3 || d.proof != 0 && d.store != STORE_PROVEN {
        return Err(field(t, "proof"));
    }
    match &d.admin {
        Some(a) => {
            held |= signer_key(a, t, "admin")?;
            if d.powers > POWERS_ALL {
                return Err(field(t, "powers"));
            }
        }
        None if d.powers != 0 => return Err(field(t, "powers")),
        None if d.commands != 0 => return Err(field(t, "commands")),
        None => {}
    }
    if d.replaces == Some(d.key.hash()) {
        return Err(field(t, "replaces"));
    }
    if d.guarded && d.role != ROLE_LEAF {
        return Err(field(t, "guarded"));
    }
    Ok(held)
}

fn encode_device(m: &mut Map, d: &Device) {
    m.put(10, d.key.encode());
    m.put(11, cbor::text(&d.name));
    m.put(12, cbor::uint(d.role));
    let mut opt = |k: u16, v: u64| {
        if v != 0 {
            m.put(k, cbor::uint(v));
        }
    };
    opt(13, d.rights);
    opt(14, d.skip);
    opt(16, d.caps);
    opt(17, d.os);
    if d.store != STORE_FILE {
        m.put(18, cbor::uint(d.store));
    }
    if d.proof != 0 {
        m.put(19, cbor::uint(d.proof));
    }
    if let Some(a) = &d.admin {
        m.put(20, a.encode());
    }
    if d.powers != 0 {
        m.put(21, cbor::uint(d.powers));
    }
    if d.commands != 0 {
        m.put(22, cbor::uint(d.commands));
    }
    if d.holds_root {
        m.put(23, cbor::uint(1));
    }
    if let Some(r) = &d.replaces {
        m.put(24, cbor::bytes(&r.0));
    }
    if d.guarded {
        m.put(25, cbor::uint(1));
    }
}

fn check_settings(s: &Settings) -> Result<bool, Rule> {
    let t = "settings";
    if s.takeover_delay_ms.is_some_and(|d| d > MAX_DELAY_MS || d == DEFAULT_DELAY_MS) {
        return Err(field(t, "takeover_delay_ms"));
    }
    if s.key_level > LEVEL_FILES || s.key_level == LEVEL_HARDWARE {
        return Err(field(t, "key_level"));
    }
    if s.min_rules == 1 {
        return Err(field(t, "min_rules"));
    }
    if s.admin_limit > super::MAX_ADMIN_RECORDS as u64 || s.admin_limit == DEFAULT_ADMIN_LIMIT {
        return Err(field(t, "admin_limit"));
    }
    if s.servers.len() > MAX_SERVERS
        || s.servers.iter().any(|v| {
            !(SERVER_FORWARDER..=SERVER_RELAY).contains(&v.kind)
                || v.endpoint.is_empty()
                || v.endpoint.len() > 255
                || !plain_text(&v.endpoint)
                || !matches!(v.key.check(), Ok(KeyCheck::Good))
        })
    {
        return Err(field(t, "servers"));
    }
    Ok(false)
}

fn encode_settings(m: &mut Map, s: &Settings) {
    if let Some(d) = s.takeover_delay_ms {
        m.put(10, cbor::uint(d));
    }
    if s.key_level != 0 {
        m.put(11, cbor::uint(s.key_level));
    }
    if s.min_rules != 0 {
        m.put(12, cbor::uint(s.min_rules));
    }
    if s.admin_limit != 0 {
        m.put(13, cbor::uint(s.admin_limit));
    }
    if s.shared {
        m.put(14, cbor::uint(1));
    }
    if !s.servers.is_empty() {
        m.put(
            15,
            cbor::array(
                s.servers.iter().map(|v| cbor::array([cbor::uint(v.kind), cbor::text(&v.endpoint), v.key.encode()])),
            ),
        );
    }
}

impl Settings {
    /// The takeover delay, its default when not set.
    pub fn delay_ms(&self) -> u64 {
        self.takeover_delay_ms.unwrap_or(DEFAULT_DELAY_MS)
    }
    pub fn level(&self) -> u64 {
        if self.key_level == 0 { LEVEL_HARDWARE } else { self.key_level }
    }
    pub fn rules(&self) -> u64 {
        if self.min_rules == 0 { 1 } else { self.min_rules }
    }
    pub fn admin_records(&self) -> usize {
        if self.admin_limit == 0 { DEFAULT_ADMIN_LIMIT as usize } else { self.admin_limit as usize }
    }
}
