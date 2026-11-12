// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The bodies of records v3 (format-0.6 section 4): their fields as Rust
//! types, the checks of each field's row, and their encoding and reading
//! on the format's codec.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use super::key::{DeviceId, GroupId, Key, KeyCheck, KeyHash, RecordId};
use super::{MAX_SEQ, Rule};
use crate::format::cbor::{MAX_INT, Value};

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

/// Command types (format section 6); a device record's `commands` has bit
/// (type − 1) for each type the admin may sign.
pub const COMMAND_MODE: u64 = 1;
pub const COMMAND_HUB: u64 = 2;
pub const COMMAND_PASTE: u64 = 3;
pub const COMMAND_PASTE_OFF: u64 = 4;
pub const COMMAND_ACTION: u64 = 5;
pub const COMMAND_ACTIONS_OFF: u64 = 6;
pub const COMMAND_AWAY_OFF: u64 = 7;
pub const COMMAND_MUTE: u64 = 8;
pub const COMMAND_UNMUTE: u64 = 9;
pub const COMMAND_DEVICE: u64 = 10;

/// The `commands` bit of a command type.
pub const fn command_bit(t: u64) -> u64 {
    match 1u64.checked_shl(t.saturating_sub(1) as u32) {
        Some(b) if t != 0 => b,
        _ => 0,
    }
}

/// The kind of device a root makes an admin, which fixes its powers and
/// commands. The rules evaluate any powers and commands; the writers only
/// ever give one of these three sets, so that every client gives the same.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AdminKind {
    /// A watch: removes and freezes, turns things off, runs an action;
    /// admits nobody.
    Watch,
    /// A computer: admits, manages, removes, freezes, sets the hubs; all
    /// commands.
    Computer,
    /// A phone: all of a computer's, and removes admins, thaws and takes
    /// the group over.
    Phone,
}

impl AdminKind {
    /// The powers and the commands of a device record for this kind.
    pub const fn grants(self) -> (u64, u64) {
        const ALL_COMMANDS: u64 = (1 << COMMAND_DEVICE) - 1;
        const ADMIN: u64 = POWER_ADMIT | POWER_MANAGE | POWER_REMOVE | POWER_FREEZE | POWER_HUB;
        match self {
            AdminKind::Watch => (
                POWER_REMOVE | POWER_FREEZE,
                command_bit(COMMAND_PASTE_OFF)
                    | command_bit(COMMAND_ACTIONS_OFF)
                    | command_bit(COMMAND_AWAY_OFF)
                    | command_bit(COMMAND_ACTION),
            ),
            AdminKind::Computer => (ADMIN, ALL_COMMANDS),
            AdminKind::Phone => (ADMIN | POWER_REMOVE_ADMINS | POWER_THAW | POWER_TAKEOVER, ALL_COMMANDS),
        }
    }
}

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

/// `[key hash, seq ≥ 1, record ID]` of a revoke, freeze or claim: the
/// head of each signer's chain the author held. A record of that signer
/// at or below seq is seen only when it is on the chain ending at id; a
/// signer not listed was seen at 0.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Seen {
    pub key: KeyHash,
    pub seq: u64,
    pub id: RecordId,
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
            .chain(self.keys.iter().filter_map(|k| match (seen_entry(&self.seen, k), seen_entry(current, k)) {
                (Some(a), Some(b)) => Some(if a.seq <= b.seq { a } else { b }),
                _ => None,
            }))
            .collect();
        seen.sort_by_key(|s| s.key);
        Removal { keys: self.keys.clone(), seen }
    }
}

pub fn seen_of(seen: &[Seen], signer: &KeyHash) -> u64 {
    seen_entry(seen, signer).map_or(0, |s| s.seq)
}

/// The entry of seen for signer.
pub fn seen_entry(seen: &[Seen], signer: &KeyHash) -> Option<Seen> {
    seen.binary_search_by(|s| s.key.cmp(signer)).ok().and_then(|i| seen.get(i)).copied()
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
    /// The device's system; numbers of later versions are kept as they
    /// are.
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

/// Reports whether a `seen` list is a set: sorted by key hash, each key
/// once.
fn seen_set(seen: &[Seen]) -> bool {
    seen.windows(2).all(|w| matches!(w, [a, b] if a.key < b.key))
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
        // A key of the wrong size or off the curve is the key's own rule
        // (`keys/es256`); a key of another algorithm breaks the field's.
        Err(r) if !r.is("keys/alg") => Err(r),
        Err(_) => Err(field(t, f)),
    }
}

impl Body {
    /// Checks each field against its row (section 4) and returns whether
    /// the record is held: a key of an unknown algorithm where a signature
    /// key is wanted, besides what the reader found (`held`).
    pub fn check(&self) -> Result<bool, Rule> {
        let t = type_name(self.kind.type_number());
        if self.time_ms > MAX_INT {
            return Err(Rule::new("records/time_ms"));
        }
        let mut held = self.held;
        match &self.kind {
            Kind::Device(d) => held |= check_device(d)?,
            Kind::Revoke(r) | Kind::Freeze(r) => {
                if r.keys.is_empty() || r.keys.len() > MAX_KEYS || !strictly_sorted(&r.keys) {
                    return Err(field(t, "keys"));
                }
                if !seen_set(&r.seen)
                    || r.seen.len() > super::MAX_SEEN
                    || r.seen.iter().any(|s| s.seq == 0 || s.seq > MAX_SEQ)
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
                if !seen_set(seen) || seen.len() > super::MAX_SEEN || seen.iter().any(|s| s.seq == 0 || s.seq > MAX_SEQ)
                {
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
                    return Err(Rule::new("records/type"));
                }
                held = true;
            }
        }
        // The fields between them last: a field's own row names its fault
        // first.
        if self.seq == 0 || self.seq > MAX_SEQ {
            return Err(Rule::new("records/seq"));
        }
        if (self.seq == 1) != self.prev.is_none() {
            return Err(Rule::new("records/prev"));
        }
        Ok(held)
    }

    /// The body's bytes in the profile. A held body has a critical field
    /// this version does not write; the writer here marks it with field 250
    /// so that the tests can make one.
    pub fn encode(&self) -> Vec<u8> {
        let mut m: Vec<(u16, Value<'_>)> = vec![
            (1, Value::Uint(self.kind.type_number())),
            (2, Value::Bytes(&self.group.0)),
            (3, Value::Bytes(&self.signer.0)),
            (4, Value::Uint(self.seq)),
        ];
        if let Some(p) = &self.prev {
            m.push((5, Value::Bytes(&p.0)));
        }
        if self.time_ms != 0 {
            m.push((6, Value::Uint(self.time_ms)));
        }
        match &self.kind {
            Kind::Device(d) => encode_device(&mut m, d),
            Kind::Revoke(r) | Kind::Freeze(r) => {
                m.push((10, Value::Array(r.keys.iter().map(|k| Value::Bytes(&k.0)).collect())));
                m.push((11, seen(&r.seen)));
            }
            Kind::Thaw(v) | Kind::Resolve(v) => m.push((10, ids(v))),
            Kind::Claim { root, seen: s } => {
                m.push((10, root.to_value()));
                m.push((11, seen(s)));
            }
            Kind::Settings(s) => encode_settings(&mut m, s),
            Kind::Copies { incoming_ms } => m.push((10, Value::Uint(*incoming_ms))),
            Kind::Checkpoint { heads, keep } => {
                let heads = heads
                    .iter()
                    .map(|h| Value::Array(vec![Value::Bytes(&h.key.0), Value::Uint(h.seq), Value::Bytes(&h.id.0)]));
                m.push((10, Value::Array(heads.collect())));
                if !keep.is_empty() {
                    m.push((11, ids(keep)));
                }
            }
            Kind::Hubs(h) => m.push((10, Value::Array(h.iter().map(|d| Value::Bytes(&d.0)).collect()))),
            Kind::Recovery { admin } => m.push((10, admin.to_value())),
            Kind::Handover { admin } => m.push((10, Value::Bytes(&admin.0))),
            Kind::Unknown(_) => {}
        }
        if self.held {
            m.push((250, Value::Uint(1)));
        }
        m.sort_by_key(|(k, _)| *k);
        Value::Map(m).encode()
    }

    /// Reads a body from the map its envelope holds, field by field against
    /// the rows (sections 1, 3.2, 3.3 and 4): a field of the wrong type or
    /// out of its row's range breaks the row; a default written out breaks
    /// `form/default`; a removed field breaks `form/critical`. A critical
    /// field this version does not know, or a type it does not know, holds
    /// the record; an unknown optional field is skipped. The values' own
    /// rules (sorted sets, counts, keys) are `check`'s.
    pub fn from_value(v: &Value<'_>) -> Result<Body, Rule> {
        let map = v.as_map().ok_or(Rule::new("env/shape"))?;
        let r = Read { map };
        let type_number = r.need_uint(1, Rule::new("records/type"))?;
        let t = type_name(type_number);
        let group = r.need(2, Rule::new("records/group"))?;
        let group = group.as_bytes().and_then(DeviceId::from_slice).ok_or(Rule::new("records/group"))?;
        let signer = r.need(3, Rule::new("records/signer"))?;
        let signer = signer.as_bytes().and_then(KeyHash::from_slice).ok_or(Rule::new("records/signer"))?;
        let seq = r.need_uint(4, Rule::new("records/seq"))?;
        let prev = match r.get(5) {
            Some(p) => Some(p.as_bytes().and_then(RecordId::from_slice).ok_or(Rule::new("records/prev"))?),
            None => None,
        };
        let time_ms = r.opt_uint(6, 0, Rule::new("records/time_ms"))?;
        let f = |name: &'static str| field(t, name);
        let (kind, own, gone): (Kind, &[u16], &[u16]) = match type_number {
            TYPE_DEVICE => (Kind::Device(read_device(&r)?), DEVICE_OWN, &[15]),
            TYPE_REVOKE | TYPE_FREEZE => {
                let keys = r.need_list(10, f("keys"), |v| v.as_bytes().and_then(KeyHash::from_slice))?;
                let seen = read_seen(&r, f("seen"))?;
                let rm = Removal { keys, seen };
                (if type_number == TYPE_REVOKE { Kind::Revoke(rm) } else { Kind::Freeze(rm) }, &[10, 11], &[])
            }
            TYPE_THAW | TYPE_RESOLVE => {
                let ids = r.need_list(10, f("records"), |v| v.as_bytes().and_then(RecordId::from_slice))?;
                (if type_number == TYPE_THAW { Kind::Thaw(ids) } else { Kind::Resolve(ids) }, &[10], &[])
            }
            TYPE_CLAIM => {
                let root = Key::read(r.need(10, f("root"))?)?;
                (Kind::Claim { root, seen: read_seen(&r, f("seen"))? }, &[10, 11], &[])
            }
            TYPE_SETTINGS => (Kind::Settings(read_settings(&r)?), &[10, 11, 12, 14, 15], &[13]),
            TYPE_COPIES => (Kind::Copies { incoming_ms: r.need_uint(10, f("incoming_ms"))? }, &[10], &[]),
            TYPE_CHECKPOINT => {
                let heads = r.need_list(10, f("heads"), |v| match v.as_array() {
                    Some([Value::Bytes(k), Value::Uint(seq), Value::Bytes(id)]) => {
                        Some(Head { key: KeyHash::from_slice(k)?, seq: *seq, id: RecordId::from_slice(id)? })
                    }
                    _ => None,
                })?;
                let keep = r.opt_list(11, f("keep"), |v| v.as_bytes().and_then(RecordId::from_slice))?;
                (Kind::Checkpoint { heads, keep }, &[10, 11], &[])
            }
            TYPE_HUBS => {
                let hubs = r.need_list(10, f("hubs"), |v| v.as_bytes().and_then(DeviceId::from_slice))?;
                (Kind::Hubs(hubs), &[10], &[])
            }
            TYPE_RECOVERY => (Kind::Recovery { admin: Key::read(r.need(10, f("admin"))?)? }, &[10], &[]),
            TYPE_HANDOVER => {
                let admin = r.need(10, f("admin"))?;
                let admin = admin.as_bytes().and_then(KeyHash::from_slice).ok_or(f("admin"))?;
                (Kind::Handover { admin }, &[10], &[])
            }
            n => (Kind::Unknown(n), &[], &[]),
        };
        // The common fields of a record: type, group, signer, seq, prev,
        // time.
        const COMMON: [u16; 6] = COMMON_FIELDS;
        let mut held = false;
        for (k, _) in map {
            if COMMON.contains(k) || own.contains(k) {
                continue;
            }
            if gone.contains(k) {
                return Err(Rule::new("form/critical"));
            }
            if *k < 256 {
                held = true;
            }
        }
        Ok(Body { group, signer, seq, prev, time_ms, kind, held })
    }
}

fn seen(s: &[Seen]) -> Value<'_> {
    Value::Array(
        s.iter()
            .map(|s| Value::Array(vec![Value::Bytes(&s.key.0), Value::Uint(s.seq), Value::Bytes(&s.id.0)]))
            .collect(),
    )
}

fn ids(v: &[RecordId]) -> Value<'_> {
    Value::Array(v.iter().map(|i| Value::Bytes(&i.0)).collect())
}

/// The fields of a body's map, read against their rows.
struct Read<'v, 'a> {
    map: &'v [(u16, Value<'a>)],
}

impl<'v, 'a> Read<'v, 'a> {
    fn get(&self, k: u16) -> Option<&'v Value<'a>> {
        self.map.binary_search_by_key(&k, |(key, _)| *key).ok().and_then(|i| self.map.get(i)).map(|(_, v)| v)
    }

    fn need(&self, k: u16, rule: Rule) -> Result<&'v Value<'a>, Rule> {
        self.get(k).ok_or(rule)
    }

    fn need_uint(&self, k: u16, rule: Rule) -> Result<u64, Rule> {
        self.need(k, rule)?.as_uint().ok_or(rule)
    }

    /// An optional unsigned integer: its default when absent, refused when
    /// written as its default.
    fn opt_uint(&self, k: u16, default: u64, rule: Rule) -> Result<u64, Rule> {
        match self.get(k) {
            None => Ok(default),
            Some(v) => match v.as_uint() {
                Some(n) if n == default => Err(Rule::new("form/default")),
                Some(n) => Ok(n),
                None => Err(rule),
            },
        }
    }

    /// A flag: the integer 1, present only when set.
    fn flag(&self, k: u16, rule: Rule) -> Result<bool, Rule> {
        match self.get(k).map(|v| v.as_uint()) {
            None => Ok(false),
            Some(Some(1)) => Ok(true),
            Some(Some(0)) => Err(Rule::new("form/default")),
            Some(_) => Err(rule),
        }
    }

    fn list<T>(v: &Value<'a>, rule: Rule, item: impl Fn(&Value<'a>) -> Option<T>) -> Result<Vec<T>, Rule> {
        v.as_array().ok_or(rule)?.iter().map(|e| item(e).ok_or(rule)).collect()
    }

    fn need_list<T>(&self, k: u16, rule: Rule, item: impl Fn(&Value<'a>) -> Option<T>) -> Result<Vec<T>, Rule> {
        Self::list(self.need(k, rule)?, rule, item)
    }

    /// An optional array: empty when absent, refused when written empty.
    fn opt_list<T>(&self, k: u16, rule: Rule, item: impl Fn(&Value<'a>) -> Option<T>) -> Result<Vec<T>, Rule> {
        match self.get(k) {
            None => Ok(Vec::new()),
            Some(v) => {
                let l = Self::list(v, rule, item)?;
                if l.is_empty() {
                    return Err(Rule::new("form/default"));
                }
                Ok(l)
            }
        }
    }
}

fn read_seen(r: &Read<'_, '_>, rule: Rule) -> Result<Vec<Seen>, Rule> {
    r.need_list(11, rule, |v| match v.as_array() {
        Some([Value::Bytes(k), Value::Uint(seq), Value::Bytes(id)]) => {
            Some(Seen { key: KeyHash::from_slice(k)?, seq: *seq, id: RecordId::from_slice(id)? })
        }
        _ => None,
    })
}

fn read_device(r: &Read<'_, '_>) -> Result<Device, Rule> {
    let f = |name: &'static str| field("device", name);
    let key = Key::read(r.need(10, f("key"))?)?;
    let name = r.need(11, f("name"))?.as_text().ok_or(f("name"))?;
    let role = r.need_uint(12, f("role"))?;
    let admin = match r.get(20) {
        Some(v) => Some(Key::read(v)?),
        None => None,
    };
    let replaces = match r.get(24) {
        Some(v) => Some(v.as_bytes().and_then(KeyHash::from_slice).ok_or(f("replaces"))?),
        None => None,
    };
    Ok(Device {
        key,
        name: String::from(name),
        role,
        rights: r.opt_uint(13, 0, f("rights"))?,
        skip: r.opt_uint(14, 0, f("skip"))?,
        caps: r.opt_uint(16, 0, f("caps"))?,
        os: r.opt_uint(17, 0, f("os"))?,
        store: r.opt_uint(18, STORE_FILE, f("store"))?,
        proof: r.opt_uint(19, 0, f("proof"))?,
        admin,
        powers: r.opt_uint(21, 0, f("powers"))?,
        commands: r.opt_uint(22, 0, f("commands"))?,
        holds_root: r.flag(23, f("holds_root"))?,
        replaces,
        guarded: r.flag(25, f("guarded"))?,
    })
}

fn read_settings(r: &Read<'_, '_>) -> Result<Settings, Rule> {
    let f = |name: &'static str| field("settings", name);
    let takeover_delay_ms = match r.get(10) {
        None => None,
        Some(_) => Some(r.opt_uint(10, DEFAULT_DELAY_MS, f("takeover_delay_ms"))?),
    };
    // Absent is the default, which the type keeps as 0; a written 0 is
    // outside both rows.
    let key_level = match (r.get(11), r.opt_uint(11, LEVEL_HARDWARE, f("key_level"))?) {
        (Some(_), 0) => return Err(f("key_level")),
        (_, LEVEL_HARDWARE) => 0,
        (_, n) => n,
    };
    let min_rules = match (r.get(12), r.opt_uint(12, 1, f("min_rules"))?) {
        (Some(_), 0) => return Err(f("min_rules")),
        (_, 1) => 0,
        (_, n) => n,
    };
    let servers = r.opt_list(15, f("servers"), |v| match v.as_array() {
        Some([Value::Uint(kind), Value::Text(endpoint), key]) => {
            Some(Server { kind: *kind, endpoint: String::from(*endpoint), key: Key::read(key).ok()? })
        }
        _ => None,
    })?;
    Ok(Settings { takeover_delay_ms, key_level, min_rules, shared: r.flag(14, f("shared"))?, servers })
}

/// The fields every record has.
pub(crate) const COMMON_FIELDS: [u16; 6] = [1, 2, 3, 4, 5, 6];

/// A device record's own fields; with COMMON_FIELDS they are the format's
/// `DEVICE_FIELDS` (a test holds the two lists equal).
pub(crate) const DEVICE_OWN: &[u16] = &[10, 11, 12, 13, 14, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25];

fn check_device(d: &Device) -> Result<bool, Rule> {
    let t = "device";
    let mut held = signer_key(&d.key, t, "key")?;
    if !crate::format::name_ok(&d.name) {
        return Err(field(t, "name"));
    }
    if !(ROLE_MEMBER..=ROLE_LEAF).contains(&d.role) {
        return Err(field(t, "role"));
    }
    if d.caps != 0 && d.role != ROLE_MEMBER || d.caps > (CAP_ADMIN | CAP_DIALS | CAP_HUB) {
        return Err(field(t, "caps"));
    }
    // os: any number is taken as it is; one this version does not name
    // is shown as unknown. Every integer stays within the profile's range.
    for (v, name) in [(d.rights, "rights"), (d.skip, "skip"), (d.os, "os"), (d.commands, "commands")] {
        if v > MAX_INT {
            return Err(field(t, name));
        }
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

fn encode_device<'a>(m: &mut Vec<(u16, Value<'a>)>, d: &'a Device) {
    m.push((10, d.key.to_value()));
    m.push((11, Value::Text(&d.name)));
    m.push((12, Value::Uint(d.role)));
    let mut opt = |k: u16, v: u64, default: u64| {
        if v != default {
            m.push((k, Value::Uint(v)));
        }
    };
    opt(13, d.rights, 0);
    opt(14, d.skip, 0);
    opt(16, d.caps, 0);
    opt(17, d.os, 0);
    opt(18, d.store, STORE_FILE);
    opt(19, d.proof, 0);
    if let Some(a) = &d.admin {
        m.push((20, a.to_value()));
    }
    let mut opt = |k: u16, v: u64| {
        if v != 0 {
            m.push((k, Value::Uint(v)));
        }
    };
    opt(21, d.powers);
    opt(22, d.commands);
    opt(23, u64::from(d.holds_root));
    if let Some(r) = &d.replaces {
        m.push((24, Value::Bytes(&r.0)));
    }
    if d.guarded {
        m.push((25, Value::Uint(1)));
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

fn encode_settings<'a>(m: &mut Vec<(u16, Value<'a>)>, s: &'a Settings) {
    if let Some(d) = s.takeover_delay_ms {
        m.push((10, Value::Uint(d)));
    }
    if s.key_level != 0 {
        m.push((11, Value::Uint(s.key_level)));
    }
    if s.min_rules != 0 {
        m.push((12, Value::Uint(s.min_rules)));
    }
    if s.shared {
        m.push((14, Value::Uint(1)));
    }
    if !s.servers.is_empty() {
        let servers = s
            .servers
            .iter()
            .map(|v| Value::Array(vec![Value::Uint(v.kind), Value::Text(&v.endpoint), v.key.to_value()]));
        m.push((15, Value::Array(servers.collect())));
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
}
