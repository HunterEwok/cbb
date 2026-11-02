// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The set of a group's records of version 2 that a member keeps, as Go's
//! group.Records: it checks each record as it comes, keeps it, and asks
//! the evaluation (`crate::authority`) what the set says
//! (docs/records-v2.md). What it says depends on the records alone, never
//! on the order in which they came, and on the member's clock for the
//! claims it waits on.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::cell::RefCell;

use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::authority::{self, Body, Hash, Input, Record, Seen, SigCache, State, key_hash_of};
use crate::certs::{self, Cert, KeyHash, sha256};
use crate::command::{COMMAND_AHEAD_MS, Command, store_of};
use crate::error::{Context, Error, Result, Wrap};

/// The most records the set keeps, waiting ones included.
pub const MAX_RECORDS: usize = 4096;
/// The most records of one signer the set keeps.
pub const MAX_PER_SIGNER: usize = 1024;

/// When a member first held a claim, in Unix milliseconds: what the
/// records file keeps and a Welcome hands a new member.
#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Debug)]
pub struct ClaimTime {
    pub record: Hash,
    pub ms: i64,
}

/// The records file: the records and when this member first held each
/// claim.
#[derive(Serialize, Deserialize)]
struct File {
    v: i64,
    records: Vec<Record>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    first_seen: Vec<ClaimTime>,
}

/// An entry of the devices list.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct Device {
    pub id: String,
    pub name: String,
    /// `full`, `phone`, `lite`, `shortcut` or `watch`.
    pub role: String,
    /// Its operating system; empty when its record does not tell.
    pub os: String,
    /// The member key of its newest counting record.
    pub key: KeyHash,
    /// Where its keys live (store_of).
    pub store: String,
    /// With a checked attestation: the kind of hardware and the hex
    /// SHA-256 of the attestation's leaf; empty without one.
    pub kind: String,
    pub proof: String,
    /// Its public key for sealed messages, which commands for it are
    /// sealed to; empty when its record has none.
    pub seal: Vec<u8>,
    /// An admin now: it has an admin key and is not frozen.
    pub admin: bool,
    /// Its admin key, whether or not it is frozen.
    pub admin_key: Option<KeyHash>,
    pub powers: Vec<String>,
    pub commands: Vec<String>,
    /// Another admin froze it: it is no admin until the freeze ends, and
    /// its connections are refused.
    pub frozen: bool,
    /// Every key that a counting device record names for it and that is
    /// not revoked, key among them.
    pub keys: Vec<KeyHash>,
}

impl Device {
    /// Whether the device is an admin with the power p.
    pub fn may(&self, p: &str) -> bool {
        self.admin && self.powers.iter().any(|q| q == p)
    }
}

/// Why a chain is refused, as Records::refused returns it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The chain passes every rule but that a device record that counts
    /// names its key: the device's record has not reached this member, or
    /// this member holds no records yet. Its connection carries records
    /// only, so that the records reach the member that lacks them.
    NotListed,
    /// It is refused, for the reason given.
    Refused(&'static str),
    /// The chain passes every rule, but the state stops the exchange with
    /// its device (Records::stopped). Its connection carries records only,
    /// so that the root's decision reaches every member.
    Stopped,
}

impl Refusal {
    pub fn why(&self) -> &'static str {
        match self {
            Refusal::NotListed => "no device record that counts names the device's key",
            Refusal::Stopped => "the group's records stop the exchange until its root decides",
            Refusal::Refused(why) => why,
        }
    }
}

/// The set of a group's records. It is not safe for concurrent use.
pub struct Records {
    group_ca: Cert,
    tag: String,
    /// Each record once, by ID and signature, as all sorts them.
    recs: BTreeMap<([u8; 32], Vec<u8>), Record>,
    by_signer: BTreeMap<Hash, usize>,
    /// The keys records may be signed with without an admin CA: the group
    /// CA and the new root of every claim in the set.
    roots: BTreeMap<Hash, Cert>,
    /// When, on the clock, the set first held each claim.
    first_seen: BTreeMap<Hash, i64>,
    now: Box<dyn Fn() -> i64 + Send + Sync>,
    sigs: SigCache,
    /// The state and the time it was worked out at, since a waiting claim
    /// changes it with time.
    st: RefCell<Option<(State, i64)>>,
}

impl core::fmt::Debug for Records {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Records({})", self.len())
    }
}

/// Whether the CA parent signed c, as Go's CheckSignatureFrom.
fn from(c: &Cert, parent: &Cert) -> bool {
    parent.is_ca && c.signed_by(parent)
}

fn signed_by_any(c: &Cert, roots: &[Cert]) -> bool {
    roots.iter().any(|r| from(c, r))
}

impl Records {
    /// An empty set for the group of group_ca, the group's first root,
    /// which names the group for good. Its clock reads 0 until set_clock.
    pub fn new(group_ca: &Cert) -> Records {
        Records {
            group_ca: group_ca.clone(),
            tag: certs::tag(group_ca),
            recs: BTreeMap::new(),
            by_signer: BTreeMap::new(),
            roots: BTreeMap::from([(key_hash_of(group_ca), group_ca.clone())]),
            first_seen: BTreeMap::new(),
            now: Box::new(|| 0),
            sigs: SigCache::new(),
            st: RefCell::new(None),
        }
    }

    /// Sets the clock, in Unix milliseconds, that the set counts a claim's
    /// wait by.
    pub fn set_clock(&mut self, now: impl Fn() -> i64 + Send + Sync + 'static) {
        self.now = Box::new(now);
        self.st.replace(None);
    }

    pub fn len(&self) -> usize {
        self.recs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.recs.is_empty()
    }

    /// Whether the set holds exactly the record r.
    pub fn has(&self, r: &Record) -> bool {
        self.recs.contains_key(&(r.id().0, r.sig.clone()))
    }

    fn keep(&mut self, mut r: Record, signer: Hash) {
        r.chain.truncate(1);
        self.recs.insert((r.id().0, r.sig.clone()), r);
        let n = self.by_signer.entry(signer).or_default();
        *n = n.saturating_add(1);
        self.st.replace(None);
    }

    /// Checks a record and adds it, reporting whether it was new. A record
    /// that is not of this group, does not read, or whose signature does
    /// not verify with a root the set knows or its admin CA is an error;
    /// whether its signer may sign it is for the evaluation.
    pub fn add(&mut self, r: &Record) -> Result<bool> {
        if self.has(r) {
            return Ok(false);
        }
        let sr = match authority::verify(r, |h| self.roots.get(h), Some(&self.sigs)) {
            Ok(sr) => sr,
            Err(e) => {
                // A record of a later version is kept and passed on, never
                // applied (docs/protocol.md, section 10, "Records of a later version").
                let Some(signer) = self.later_version(r) else {
                    return Err(e);
                };
                if self.by_signer.get(&signer).copied().unwrap_or(0) >= MAX_PER_SIGNER || self.recs.len() >= MAX_RECORDS
                {
                    return Err(Error::msg("too many records"));
                }
                self.keep(r.clone(), signer);
                return Ok(true);
            }
        };
        if sr.body.group != self.tag {
            return Err(Error::msg("a record of another group"));
        }
        if let Some(ca) = &sr.admin_ca
            && !self.under_root(ca)
        {
            return Err(Error::msg("a record's admin CA is from no root of the group"));
        }
        if self.by_signer.get(&sr.body.signer).copied().unwrap_or(0) >= MAX_PER_SIGNER {
            return Err(Error::msg("too many records from one signer"));
        }
        // Past MAX_RECORDS the set still takes up to MAX_PER_SIGNER records
        // of a root's own key on the path, so that admins that fill it
        // leave room for the root to remove them.
        let n = self.recs.len();
        if n >= MAX_RECORDS
            && (n >= MAX_RECORDS.saturating_add(MAX_PER_SIGNER)
                || !r.chain.is_empty()
                || !self.on_path(&sr.body.signer))
        {
            return Err(Error::msg("too many records"));
        }
        if sr.body.kind == authority::TYPE_CLAIM {
            if let Ok(c) = Cert::parse(&sr.body.root) {
                self.roots.insert(key_hash_of(&c), c);
            }
            let now = (self.now)();
            self.first_seen.entry(sr.id).or_insert(now);
        }
        self.keep(r.clone(), sr.body.signer);
        Ok(true)
    }

    /// Whether the admin CA ca is signed by a root the set knows.
    fn under_root(&self, ca: &Cert) -> bool {
        self.roots.values().any(|root| from(ca, root))
    }

    /// The signer of r when it is a record of a later version that a
    /// member keeps, as Go's laterVersion: a canonical body of at most
    /// MAX_BODY bytes, v from 3 to MAX_SEQ, this group's tag, and a
    /// signature that verifies with a root the set knows (no chain) or with
    /// its admin CA under one.
    fn later_version(&self, r: &Record) -> Option<Hash> {
        if r.body.len() > authority::MAX_BODY
            || crate::strict::check_canonical(&r.body, &["v", "group", "signer"]).is_err()
        {
            return None;
        }
        let serde_json::Value::Object(m) = serde_json::from_slice::<serde_json::Value>(&r.body).ok()? else {
            return None;
        };
        if m.get("group").and_then(|g| g.as_str()) != Some(self.tag.as_str()) {
            return None;
        }
        let v = m.get("v").and_then(|v| v.as_i64())?;
        if v <= 2 || v > authority::MAX_SEQ {
            return None;
        }
        let signer: Hash = serde_json::from_value(m.get("signer")?.clone()).ok()?;
        let key = match r.chain.as_slice() {
            [] => self.roots.get(&signer).cloned(),
            [ca] => Cert::parse(ca).ok().filter(|ca| key_hash_of(ca) == signer && self.under_root(ca)),
            _ => None,
        }?;
        key.verifies(&r.body, &r.sig).then_some(signer)
    }

    /// Adds the valid records among rs and returns those that were new,
    /// and an error for each that is not valid. A record signed by a
    /// claim's new root is taken once the claim is in the set, so the
    /// result does not depend on the order of rs.
    pub fn add_all(&mut self, rs: &[Record]) -> (Vec<Record>, Vec<Error>) {
        let mut fresh = Vec::new();
        let mut pending: Vec<Record> = rs.to_vec();
        loop {
            let mut rest = Vec::new();
            let mut errs = Vec::new();
            let roots = self.roots.len();
            for r in pending {
                match self.add(&r) {
                    Err(e) => {
                        rest.push(r);
                        errs.push(e);
                    }
                    Ok(true) => fresh.push(r),
                    Ok(false) => {}
                }
            }
            if self.roots.len() == roots || rest.is_empty() {
                return (fresh, errs);
            }
            pending = rest;
        }
    }

    /// Every record, sorted by ID and then signature.
    pub fn all(&self) -> Vec<Record> {
        self.recs.values().cloned().collect()
    }

    /// The body of every record that reads, with its ID.
    fn bodies(&self) -> impl Iterator<Item = (Hash, Body)> + '_ {
        self.recs.values().filter_map(|r| Body::parse(&r.body).ok().map(|b| (r.id(), b)))
    }

    /// What the records say (docs/protocol.md, section 10, "The state").
    pub fn state(&self) -> State {
        let now = (self.now)();
        if let Some((st, at)) = &*self.st.borrow()
            && (st.claims.is_empty() || now.abs_diff(*at) < 1000)
        {
            return st.clone();
        }
        let records = self.all();
        let st = authority::evaluate(&Input {
            group_ca: &self.group_ca,
            group: &self.tag,
            records: &records,
            now_ms: now,
            first_seen: &self.first_seen,
            time_unknown: false,
            sigs: Some(&self.sigs),
        });
        self.st.replace(Some((st.clone(), now)));
        st
    }

    /// How far the records stop the exchange: "none", "secrets" or "full"
    /// (docs/protocol.md, section 10, "Stopping the exchange").
    pub fn stop(&self) -> String {
        self.state().stop
    }

    /// The roots on the path, the group CA first.
    fn path(&self) -> Vec<Cert> {
        let out: Vec<Cert> = self.state().roots.iter().filter_map(|h| self.roots.get(h).cloned()).collect();
        if out.is_empty() { alloc::vec![self.group_ca.clone()] } else { out }
    }

    fn on_path(&self, k: &Hash) -> bool {
        self.state().roots.contains(k)
    }

    /// The roots that took the group over from the group CA, in order; the
    /// last is the current root. Empty in a group never handed over.
    pub fn roots(&self) -> Vec<Cert> {
        self.path().split_off(1)
    }

    /// Whether a revocation that counts names the key k.
    pub fn revoked(&self, k: &KeyHash) -> bool {
        self.state().revoked.contains(&Hash(*k))
    }

    /// Whether k is a frozen admin key, or a key of the device of a frozen
    /// admin.
    pub fn frozen(&self, k: &KeyHash) -> bool {
        let k = Hash(*k);
        self.state().devices.iter().any(|d| d.frozen && (d.admin == Some(k) || d.keys.contains(&k)))
    }

    /// Whether k is a watch's admin key.
    pub fn watch(&self, k: &KeyHash) -> bool {
        let k = Hash(*k);
        self.state().devices.iter().any(|d| d.role == "watch" && d.admin == Some(k))
    }

    /// The devices list, sorted by name and then ID.
    pub fn devices(&self) -> Vec<Device> {
        let st = self.state();
        let mut newest: BTreeMap<String, Body> = BTreeMap::new();
        for (_, b) in self.bodies() {
            if b.kind != authority::TYPE_DEVICE {
                continue;
            }
            if newest.get(&b.device).is_none_or(|o| (b.time_ms, b.seq) > (o.time_ms, o.seq)) {
                newest.insert(b.device.clone(), b);
            }
        }
        let mut out: Vec<Device> = st
            .devices
            .iter()
            .map(|d| {
                let keys: Vec<KeyHash> = d.keys.iter().map(|k| k.0).collect();
                let mut key = newest
                    .get(&d.device)
                    .and_then(|b| b.key)
                    .filter(|k| d.keys.contains(k))
                    .map(|k| k.0)
                    .unwrap_or_default();
                if key == KeyHash::default()
                    && let Some(last) = keys.last()
                {
                    key = *last;
                }
                Device {
                    id: d.device.clone(),
                    name: d.name.clone(),
                    role: d.role.clone(),
                    os: d.os.clone(),
                    key,
                    store: store_of(&d.store, &d.role).to_string(),
                    kind: d.hardware.clone(),
                    proof: d.proof.clone(),
                    seal: d.seal.clone(),
                    // A frozen admin is no admin until the freeze ends.
                    admin: d.admin.is_some() && !d.frozen,
                    admin_key: d.admin.map(|a| a.0),
                    powers: d.powers.clone(),
                    commands: d.commands.clone(),
                    frozen: d.frozen,
                    keys,
                }
            })
            .collect();
        out.sort_by(|a, b| (&a.name, &a.id).cmp(&(&b.name, &b.id)));
        out
    }

    /// Whether a device of the list has the key k.
    fn listed(&self, k: &KeyHash) -> bool {
        let k = Hash(*k);
        self.state().devices.iter().any(|d| d.keys.contains(&k))
    }

    /// The device whose admin key is k.
    fn admin_device(&self, k: &KeyHash) -> Option<authority::Device> {
        let k = Hash(*k);
        self.state().devices.into_iter().find(|d| d.admin == Some(k))
    }

    /// Why a member's chain (leaf first, then the certificates it came
    /// with), already verified to a trusted root, is not taken; None when
    /// it is (docs/protocol.md, section 10, "Certificates"). See Refusal::NotListed.
    pub fn refused(&self, chain: &[Cert]) -> Option<Refusal> {
        if let Some(why) = self.refused_chain(chain) {
            return Some(Refusal::Refused(why));
        }
        if !chain.first().is_some_and(|c| self.listed(&c.key_hash())) {
            // A device no record names gets records only, unless the admin
            // that certified it was removed: so the holder of a removed
            // recovery key gets nothing.
            if self.issuer_admin(chain).is_some_and(|a| self.revoked(&a)) {
                return Some(Refusal::Refused("the admin that certified the device was removed from the group"));
            }
            return Some(Refusal::NotListed);
        }
        if chain.first().and_then(|c| certs::device_of(c).ok()).is_some_and(|d| self.stopped(d.as_str())) {
            return Some(Refusal::Stopped);
        }
        None
    }

    /// Whether the state stops the exchange with dev: the whole group stops
    /// (stop full), or dev gets nothing (docs/protocol.md, section 10,
    /// "Stopping the exchange"). A connection with it carries records only.
    pub fn stopped(&self, dev: &str) -> bool {
        let st = self.state();
        st.stop == authority::STOP_FULL || st.nothing_to.iter().any(|d| d == dev)
    }

    /// Whether this member sends dev no secret: while the state stops
    /// secrets or everything, or names dev among the devices that get no
    /// secrets or nothing. Such a device gets the mark of a secret, never
    /// its text, and no secret paste.
    pub fn no_secrets_to(&self, dev: &str) -> bool {
        let st = self.state();
        st.stop != authority::STOP_NONE || st.no_secrets_to.iter().chain(&st.nothing_to).any(|d| d == dev)
    }

    /// The key hash of the admin CA in chain that signed its leaf; None
    /// when a root on the path signed it or none did.
    fn issuer_admin(&self, chain: &[Cert]) -> Option<KeyHash> {
        let first = chain.first()?;
        if signed_by_any(first, &self.path()) {
            return None;
        }
        chain.iter().skip(1).find(|c| from(first, c)).map(|c| c.key_hash())
    }

    /// refused without the rule that a device record names the key.
    fn refused_chain(&self, chain: &[Cert]) -> Option<&'static str> {
        let Some(first) = chain.first() else {
            return Some("no certificate");
        };
        let leaf = first.key_hash();
        if self.revoked(&leaf) {
            return Some("the device was removed from the group");
        }
        if self.frozen(&leaf) {
            return Some("the device is a frozen admin; the root or an admin with thaw unfreezes or removes it");
        }
        let path = self.path();
        if signed_by_any(first, &path) {
            return None;
        }
        let Some(issuer) = chain.iter().skip(1).find(|c| from(first, c)) else {
            return Some("the certificate's issuer is not in its chain");
        };
        if !signed_by_any(issuer, &path) {
            return Some("the certificate is not from a root of the group");
        }
        let admin = issuer.key_hash();
        if self.frozen(&admin) {
            return Some("the admin that certified the device is frozen");
        }
        // An admin removed later still certified the devices whose records
        // stay; one listed must have a power to certify.
        if let Some(d) = self.admin_device(&admin)
            && !d.powers.iter().any(|p| p == authority::POWER_ADMIT || p == authority::POWER_RENEW)
        {
            return Some("the admin that certified the device certifies no devices");
        }
        None
    }

    /// Why an admin CA is not taken; None when it is: it is under a root
    /// on the path, its key is not revoked, and a device record that counts
    /// names it as an admin key.
    pub fn refused_admin_ca(&self, ca: &Cert) -> Option<Refusal> {
        let k = ca.key_hash();
        if self.revoked(&k) {
            return Some(Refusal::Refused("the admin CA's key was removed from the group"));
        }
        if !signed_by_any(ca, &self.path()) {
            return Some(Refusal::Refused("the admin CA is not from a root of the group"));
        }
        if self.admin_device(&k).is_none() {
            return Some(Refusal::NotListed);
        }
        None
    }

    /// The device that holds the group's current root and its member key:
    /// the newest device record with holds_root that the current root's
    /// own key signed for the state's root device.
    pub fn root_member(&self) -> Option<(String, KeyHash)> {
        let st = self.state();
        if st.root_device.is_empty() {
            return None;
        }
        let cur = *st.roots.last()?;
        self.bodies()
            .filter(|(_, b)| {
                b.kind == authority::TYPE_DEVICE && b.holds_root && b.signer == cur && b.device == st.root_device
            })
            .max_by_key(|(_, b)| b.seq)
            .and_then(|(_, b)| b.key.map(|k| (st.root_device.clone(), k.0)))
    }

    /// Whether the device `dev` with the verified chain (leaf first) is the
    /// group's root or an admin, as Go's adminPeer: an admin CA of its own
    /// under a root on the path that a device record that counts names and
    /// that is neither revoked nor frozen, the root's own device by its
    /// key, or an admin of the devices list by its key. Only such a device
    /// may be the group's hub (docs/protocol.md, section 11).
    pub fn admin_peer(&self, dev: &str, chain: &[Cert]) -> bool {
        let Some(leaf) = chain.first() else { return false };
        if let Some(ca) = chain.get(1)
            && ca.is_ca
            && ca.common_name.as_deref() == Some(format!("clipboardbridge admin {dev}").as_str())
        {
            let k = ca.key_hash();
            return from(leaf, ca)
                && self.path().iter().any(|root| certs::check_admin_ca(ca, root).is_ok())
                && self.refused_admin_ca(ca).is_none()
                && !self.frozen(&k);
        }
        let key = leaf.key_hash();
        if self.root_member().is_some_and(|(id, k)| id == dev && k == key) && !self.revoked(&key) {
            return true;
        }
        self.devices().iter().any(|d| d.id == dev && d.key == key && d.admin)
    }

    /// Whether the device `dev` may be the group's hub by the records
    /// alone, as Go's MayHost: the root's own device, whose key is not
    /// revoked, or an admin with the power hub.
    pub fn may_host(&self, dev: &str) -> bool {
        if self.root_member().is_some_and(|(id, k)| id == dev && !self.revoked(&k)) {
            return true;
        }
        self.devices().iter().any(|d| d.id == dev && d.may(authority::POWER_HUB))
    }

    /// The devices that may be the group's hubs, in the order in which they
    /// serve, as Go's HubOrder (docs/protocol.md, section 11, "Several
    /// hubs"): the main hubs of the hubs table first, in its order, then
    /// the others: the phones, then the rest, and in each part the root's
    /// own device first, then by device ID.
    pub fn hub_order(&self) -> Vec<String> {
        let root = self.root_member().filter(|(_, k)| !self.revoked(k)).map(|(id, _)| id);
        let mut hubs: Vec<(bool, bool, String)> = self
            .devices()
            .into_iter()
            .filter(|d| root.as_deref() == Some(d.id.as_str()) || d.may(authority::POWER_HUB))
            .map(|d| (d.role != "phone", root.as_deref() != Some(d.id.as_str()), d.id))
            .collect();
        hubs.sort();
        let order: Vec<String> = hubs.into_iter().map(|(_, _, id)| id).collect();
        let main: Vec<String> = self.state().hubs.into_iter().filter(|id| order.contains(id)).collect();
        let rest = order.into_iter().filter(|id| !main.contains(id));
        main.iter().cloned().chain(rest).collect()
    }

    /// The key that signed c, a command, and the root on the path it was
    /// signed under: a root's own key with no chain, or the admin CA of the
    /// chain, certified by that root.
    fn signer_of(&self, c: &Record) -> Result<(KeyHash, KeyHash)> {
        let path = self.path();
        match c.chain.as_slice() {
            [] => path
                .iter()
                .find(|root| root.verifies(&c.body, &c.sig))
                .map(|root| (root.key_hash(), root.key_hash()))
                .ok_or_else(|| Error::msg("the command is not signed by a root of the group")),
            [ca] => {
                let ca = Cert::parse(ca).wrap("the command's admin CA")?;
                if !ca.verifies(&c.body, &c.sig) {
                    return Err(Error::msg("the command's signature does not verify"));
                }
                path.iter()
                    .find(|root| from(&ca, root))
                    .map(|root| (ca.key_hash(), root.key_hash()))
                    .ok_or_else(|| Error::msg("the command's admin CA is not from a root of the group"))
            }
            _ => Err(Error::msg("a command's chain holds more than its admin CA")),
        }
    }

    fn signer_device(&self, signer: &KeyHash, anchor: &KeyHash) -> (Option<Device>, bool) {
        let root = signer == anchor;
        let id = if root {
            match self.root_member() {
                Some((id, _)) => Some(id),
                None => return (None, true),
            }
        } else {
            None
        };
        let d = self.devices().into_iter().find(|d| match &id {
            Some(id) => &d.id == id,
            None => d.admin_key == Some(*signer),
        });
        (d, root)
    }

    /// Checks a command for the member `me` at now_ms, as Go's
    /// VerifyCommand: its signer is the current root, or an admin key under
    /// a root on the path that is listed, neither revoked nor frozen, and
    /// whose newest root record gives it the command's type; its by is the
    /// signer's device when the records show it; it is for `me` in this
    /// group, has not expired and was not signed in the future. The caller
    /// keeps the replay cache.
    pub fn verify_command(&self, c: &Record, me: &str, now_ms: i64) -> Result<Command> {
        let body = Command::parse(&c.body)?;
        if body.group != self.tag {
            return Err(Error::msg("the command is for another group"));
        }
        if body.to != me {
            return Err(Error::msg("the command is for another device"));
        }
        let (signer, anchor) = self.signer_of(c)?;
        let path = self.path();
        if signer == anchor && path.last().map(Cert::key_hash) != Some(anchor) {
            return Err(Error::msg("the command's signer is not the group's current root"));
        }
        let (dev, _) = self.signer_device(&signer, &anchor);
        if signer != anchor {
            let Some(d) = dev.as_ref().filter(|d| d.admin && !self.revoked(&signer) && !self.frozen(&signer)) else {
                return Err(Error::msg("the command's signer is not an admin of the group"));
            };
            if !d.commands.contains(&body.kind) {
                return Err(Error::msg(format!("the command's signer may not sign {} commands", body.kind)));
            }
        }
        // by names the signer's device whenever the records show it, and
        // otherwise no device they show.
        match &dev {
            Some(d) if d.id != body.by => {
                return Err(Error::msg("a command's by is not the device of its signer"));
            }
            None if self.devices().iter().any(|d| d.id == body.by) => {
                return Err(Error::msg("a command's by names a device that does not hold its signer's key"));
            }
            _ => {}
        }
        if body.expires_ms <= now_ms {
            return Err(Error::msg("the command expired; check the clocks of both devices"));
        }
        if body.time_ms > now_ms.saturating_add(COMMAND_AHEAD_MS) {
            return Err(Error::msg("the command was signed in the future; check the clocks of both devices"));
        }
        Ok(body)
    }

    /// The device whose key signed the command c, which verify_command
    /// took, as Go's CommandSigner: the device that holds the group's root
    /// when the root's own key signed it (the bool is true), or the device
    /// whose record names the admin key that did. None when no listed
    /// device holds the key.
    pub fn command_signer(&self, c: &Record) -> (Option<Device>, bool) {
        match self.signer_of(c) {
            Ok((signer, anchor)) => self.signer_device(&signer, &anchor),
            Err(_) => (None, false),
        }
    }

    /// Whom the limits per sender and the logs count for the command c,
    /// with by, as Go's CommandSender: by, verified (true), when the
    /// records show that its device holds the signing key, and otherwise
    /// the signing key itself, as "key " and its hash in hex.
    pub fn command_sender(&self, c: &Record, by: &str) -> (String, bool) {
        let Ok((signer, anchor)) = self.signer_of(c) else { return (String::new(), false) };
        match self.signer_device(&signer, &anchor) {
            (Some(d), _) if d.id == by => (d.id, true),
            _ => (format!("key {}", certs::hex(&signer)), false),
        }
    }

    /// When the set first held each claim, sorted by record.
    pub fn claim_times(&self) -> Vec<ClaimTime> {
        let mut out: Vec<ClaimTime> = self.first_seen.iter().map(|(r, ms)| ClaimTime { record: *r, ms: *ms }).collect();
        out.sort_by_key(|t| t.record);
        out
    }

    /// Takes, for each claim the set holds, the time in ts when it is
    /// earlier than the set's own and not in the future: a new member takes
    /// the times of the member that admitted it from the Welcome
    /// (docs/protocol.md, section 10, "Handing the group over").
    pub fn take_claim_times(&mut self, ts: &[ClaimTime]) {
        let now = (self.now)();
        for t in ts {
            if let Some(ms) = self.first_seen.get_mut(&t.record)
                && t.ms < *ms
                && t.ms <= now
            {
                *ms = t.ms;
                self.st.replace(None);
            }
        }
    }

    /// SHA-256 over each record's ID and the hash of its signature, sorted
    /// as all sorts them, in base64: the value a hello carries; "" for an
    /// empty set.
    pub fn digest(&self) -> String {
        if self.recs.is_empty() {
            return String::new();
        }
        let mut data = Vec::with_capacity(self.recs.len().saturating_mul(64));
        for (id, sig) in self.recs.keys() {
            data.extend_from_slice(id);
            data.extend_from_slice(&sha256(sig));
        }
        base64::engine::general_purpose::STANDARD.encode(sha256(&data))
    }

    /// Names the set's group with tag instead of the group CA's own: for
    /// the vectors, whose groups carry tags of their own.
    pub(crate) fn set_tag(&mut self, tag: &str) {
        self.tag = tag.to_string();
        self.st.replace(None);
    }

    /// The seq and prev of the next record the key signer signs: one past
    /// the highest seq of its records in the set that is on no branch a
    /// root's resolve voided, after that record's ID; 1 and none when the
    /// set holds none. So once the root voids both histories of a key
    /// (docs/protocol.md, section 10, "Two numbers"), the key goes on from
    /// the record below the fork, and what it signs counts.
    pub fn next_for(&self, signer: &Hash) -> (i64, Option<Hash>) {
        let roots = self.state().roots;
        let mut voided: BTreeMap<Hash, ()> = BTreeMap::new();
        let mut by_id: BTreeMap<Hash, Body> = BTreeMap::new();
        let mut by_seq: BTreeMap<i64, usize> = BTreeMap::new();
        for r in self.recs.values() {
            let Ok(b) = Body::parse(&r.body) else { continue };
            if b.kind == authority::TYPE_RESOLVE && r.chain.is_empty() && roots.contains(&b.signer) {
                for id in &b.records {
                    voided.insert(*id, ());
                }
            }
            if b.signer == *signer {
                let n = by_seq.entry(b.seq).or_insert(0usize);
                *n = n.saturating_add(1);
                by_id.insert(r.id(), b);
            }
        }
        // A record is on a voided branch when its prev chain, as far as the
        // set holds it, passes through a voided record with a sibling.
        let dead = |mut id: Hash| {
            for _ in 0..=authority::MAX_SEQ {
                let Some(b) = by_id.get(&id) else { return false };
                if voided.contains_key(&id) && by_seq.get(&b.seq).copied().unwrap_or(0) > 1 {
                    return true;
                }
                match b.prev {
                    Some(p) => id = p,
                    None => return false,
                }
            }
            false
        };
        by_id
            .iter()
            .filter(|(id, _)| !dead(**id))
            // Of two records with one seq, which only a key that signed two
            // histories has, the lower ID, so that every member gives the same.
            .max_by(|(ia, a), (ib, b)| a.seq.cmp(&b.seq).then_with(|| ib.cmp(ia)))
            .map_or((1, None), |(id, b)| (b.seq.saturating_add(1), Some(*id)))
    }

    /// Whether the state names signer in a conflict of two histories: a
    /// record it signed now would count for nothing until the root resolves
    /// them.
    pub fn two_histories(&self, signer: &Hash) -> bool {
        self.state().conflicts.iter().any(|c| c.kind == authority::CONFLICT_TWO_HISTORIES && c.signers.contains(signer))
    }

    /// The group's tag, which every record of the set names.
    pub fn tag(&self) -> &str {
        &self.tag
    }

    /// For every signer of the set, the highest seq the set holds of it:
    /// what a removal, a freeze or a claim names in seen, sorted by key.
    pub fn seen(&self) -> Vec<Seen> {
        let mut top: BTreeMap<Hash, i64> = BTreeMap::new();
        for (_, b) in self.bodies() {
            let e = top.entry(b.signer).or_insert(0);
            if b.seq > *e {
                *e = b.seq;
            }
        }
        top.into_iter().map(|(key, seq)| Seen { key, seq }).collect()
    }

    /// Every device ID a device record of the set names, whether it counts
    /// or not, sorted: IDs a new device must not take.
    pub fn known(&self) -> Vec<String> {
        let mut out: Vec<String> =
            self.bodies().filter(|(_, b)| b.kind == authority::TYPE_DEVICE).map(|(_, b)| b.device).collect();
        out.sort();
        out.dedup();
        out
    }

    /// The IDs of the freezes of the admin key, which a thaw names.
    pub fn freezes_of(&self, admin: &KeyHash) -> Vec<Hash> {
        let mut out: Vec<Hash> = Vec::new();
        for (id, b) in self.bodies() {
            if b.kind == authority::TYPE_FREEZE && b.keys.iter().any(|k| k.0 == *admin) && !out.contains(&id) {
                out.push(id);
            }
        }
        out
    }

    /// Whether chain is the member certificate of a root's own device that
    /// a claim took the group over from, as Go's TakenOver: its leaf is the
    /// key of a holds_root device record of a root on the path that is no
    /// longer the current root, which certified it, and a claim to the
    /// next root took effect. It gives the claimant's device and admin
    /// key. Such a peer is refused, but its connections carry records, so
    /// that the old root, if it is still in use, can cancel the claim
    /// (docs/protocol.md, section 10, "Handing the group over").
    pub fn taken_over(&self, chain: &[Cert]) -> Option<(String, KeyHash)> {
        let first = chain.first()?;
        let st = self.state();
        let path = self.path();
        let leaf = first.key_hash();
        for (i, root) in path.iter().enumerate() {
            let Some(next) = path.get(i.saturating_add(1)) else { break };
            if !from(first, root) {
                continue;
            }
            let rk = root.key_hash();
            let own = self.bodies().any(|(_, b)| {
                b.kind == authority::TYPE_DEVICE
                    && b.holds_root
                    && b.signer.0 == rk
                    && b.key.is_some_and(|k| k.0 == leaf)
            });
            if !own {
                continue;
            }
            let nk = next.key_hash();
            if let Some(c) = st.claims.iter().find(|c| c.root.0 == nk && c.state == "effective") {
                let dev = self
                    .bodies()
                    .filter(|(_, b)| b.kind == authority::TYPE_DEVICE && b.admin == Some(c.claimant))
                    .last()
                    .map(|(_, b)| b.device)
                    .unwrap_or_default();
                return Some((dev, c.claimant.0));
            }
        }
        None
    }

    /// The certificates of the roots on the path, the group CA first.
    pub fn path_certs(&self) -> Vec<Cert> {
        self.path()
    }

    /// The records file's contents.
    pub fn to_file(&self) -> Result<Vec<u8>> {
        let f = File { v: 2, records: self.all(), first_seen: self.claim_times() };
        let mut data = serde_json::to_vec_pretty(&f).context("cannot encode the records")?;
        data.push(b'\n');
        Ok(data)
    }

    /// A set for the group of group_ca from a records file's contents;
    /// records not valid for the group are left out, and a file of
    /// version 1 is an empty set: its group is set up again.
    pub fn from_file(data: &[u8], group_ca: &Cert) -> Result<Records> {
        Records::from_file_with(data, group_ca, || 0)
    }

    /// from_file with the set's clock.
    pub fn from_file_with(
        data: &[u8],
        group_ca: &Cert,
        now: impl Fn() -> i64 + Send + Sync + 'static,
    ) -> Result<Records> {
        let mut s = Records::new(group_ca);
        s.set_clock(now);
        let Ok(f) = serde_json::from_slice::<File>(data) else {
            return Ok(s);
        };
        if f.v != 2 {
            return Ok(s);
        }
        for t in f.first_seen {
            s.first_seen.insert(t.record, t.ms);
        }
        s.add_all(&f.records);
        Ok(s)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::arithmetic_side_effects)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;

    fn cases() -> Vec<serde_json::Value> {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/interop/v2-records.json");
        let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        v["cases"].as_array().unwrap().clone()
    }

    /// A set of the case's group, which the vectors name with a tag of
    /// their own, holding records.
    fn set_of(c: &serde_json::Value, records: &[Record]) -> Records {
        let ca = Cert::parse(&STANDARD.decode(c["group_ca"].as_str().unwrap()).unwrap()).unwrap();
        let now = c["now_ms"].as_i64().unwrap();
        let mut s = Records::new(&ca);
        s.tag = c["group"].as_str().unwrap().to_string();
        s.set_clock(move || now);
        for f in c["first_seen"].as_array().map_or(&[][..], |a| a.as_slice()) {
            let t: ClaimTime = serde_json::from_value(f.clone()).unwrap();
            s.first_seen.insert(t.record, t.ms);
        }
        s.add_all(records);
        s
    }

    /// The set says what the evaluation says of the vectors' records it
    /// keeps, whatever order they come in, and a set read back from its
    /// file says the same.
    #[test]
    fn set_vectors() {
        let mut n = 0;
        for c in cases() {
            if c["time_unknown"].as_bool().unwrap_or(false) {
                continue;
            }
            let name = c["name"].as_str().unwrap();
            let mut rs: Vec<Record> = serde_json::from_value(c["records"].clone()).unwrap();
            let s = set_of(&c, &rs);
            if s.len() != rs.len() {
                continue; // records the set does not keep, which the state lists as ignored
            }
            let want = c["state"].as_str().unwrap();
            assert_eq!(core::str::from_utf8(&s.state().encode()).unwrap(), want, "{name}");
            rs.reverse();
            let r = set_of(&c, &rs);
            assert_eq!(r.digest(), s.digest(), "{name}");
            assert_eq!(r.all(), s.all(), "{name}");
            let f: File = serde_json::from_slice(&s.to_file().unwrap()).unwrap();
            assert_eq!(f.v, 2);
            assert_eq!(f.records, s.all(), "{name}");
            assert_eq!(f.first_seen, s.claim_times(), "{name}");
            n += 1;
        }
        assert!(n >= 5, "only {n} cases compared");
    }

    /// The seq and prev the set gives a key's next record, and whether the
    /// key signed two histories, as Go's TestNextVectors wrote them: once
    /// the root voids both histories, the key goes on below the fork.
    #[test]
    fn next_vectors() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/interop/v2-next.json");
        let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let cases = v["cases"].as_array().unwrap();
        assert!(cases.len() >= 4);
        for c in cases {
            let name = c["name"].as_str().unwrap();
            let rs: Vec<Record> = serde_json::from_value(c["records"].clone()).unwrap();
            let s = set_of(c, &rs);
            assert_eq!(s.len(), rs.len(), "{name}");
            let signer: Hash = serde_json::from_value(c["signer"].clone()).unwrap();
            let prev: Option<Hash> = c.get("prev").map(|p| serde_json::from_value(p.clone()).unwrap());
            assert_eq!(s.two_histories(&signer), c["two_histories"].as_bool().unwrap(), "{name}");
            assert_eq!(s.next_for(&signer), (c["seq"].as_i64().unwrap(), prev), "{name}");
        }
    }

    /// The hubs table's main hubs that may be hubs come first in the order
    /// of hubs, in the table's order, and the others follow as without it.
    #[test]
    fn hubs_table_first() {
        let mut n = 0;
        for c in cases().iter().filter(|c| c["name"].as_str().unwrap().starts_with("hubs table")) {
            let rs: Vec<Record> = serde_json::from_value(c["records"].clone()).unwrap();
            let s = set_of(c, &rs);
            let order = s.hub_order();
            let main: Vec<String> = s.state().hubs.into_iter().filter(|h| s.may_host(h)).collect();
            assert_eq!(order[..main.len()], main[..], "{}", c["name"]);
            let all = s.devices().into_iter().filter(|d| s.may_host(&d.id)).count();
            assert_eq!(order.len(), all, "{}", c["name"]);
            n += usize::from(!main.is_empty());
        }
        assert!(n >= 3, "only {n} cases with main hubs");
    }

    /// A file of version 1, a bare array, is an empty set.
    #[test]
    fn version_1_file() {
        let c = &cases()[0];
        let ca = Cert::parse(&STANDARD.decode(c["group_ca"].as_str().unwrap()).unwrap()).unwrap();
        let rs: Vec<Record> = serde_json::from_value(c["records"].clone()).unwrap();
        let s = Records::from_file(&serde_json::to_vec(&rs).unwrap(), &ca).unwrap();
        assert!(s.is_empty());
        assert_eq!(s.digest(), "");
    }

    /// A claim's time from a Welcome is taken only when it is earlier than
    /// the set's own and not in the future.
    #[test]
    fn claim_times() {
        for c in cases() {
            let rs: Vec<Record> = serde_json::from_value(c["records"].clone()).unwrap();
            let mut c = c.clone();
            c["now_ms"] = 1_000_000.into();
            c["first_seen"] = serde_json::Value::Null;
            let mut s = set_of(&c, &rs);
            let held = s.claim_times();
            let Some(first) = held.first().copied() else { continue };
            assert_eq!(first.ms, 1_000_000);
            s.take_claim_times(&[ClaimTime { record: first.record, ms: 2_000_000 }]);
            assert_eq!(s.claim_times()[0].ms, 1_000_000, "a later time is taken");
            s.take_claim_times(&[ClaimTime { record: Hash([7; 32]), ms: 5 }]);
            assert_eq!(s.claim_times(), held, "a time for a claim the set does not hold is taken");
            s.take_claim_times(&[ClaimTime { record: first.record, ms: 10 }]);
            assert_eq!(s.claim_times()[0].ms, 10);
            return;
        }
        panic!("no case holds a claim");
    }

    /// A chain from a root that no device record names is refused only as
    /// not listed, so that its connection carries records; no chain is
    /// refused outright.
    #[test]
    fn not_listed() {
        let c = &cases()[0];
        let rs: Vec<Record> = serde_json::from_value(c["records"].clone()).unwrap();
        let s = set_of(c, &rs);
        assert_eq!(s.refused(core::slice::from_ref(&s.group_ca)), Some(Refusal::NotListed));
        assert!(matches!(s.refused(&[]), Some(Refusal::Refused(_))));
        assert_eq!(s.refused_admin_ca(&s.group_ca), Some(Refusal::NotListed));
    }
}
