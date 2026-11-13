// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// Groups of records v3 of a chosen size, built from a fixed seed: a copy of
// the generator the auto-checks keep (core/src/groupgen.rs on their branch,
// feature testkit), for the tests that count what building and loading a
// set costs (tests/set_cost.rs). It goes when the generator reaches the
// core.
//
// [`build`] makes a valid group from a [`Spec`]: the root and its devices,
// phone admins that admit devices and remove some of them, settings and
// copies records that fill each key's room, root checkpoints that keep the
// live devices and leave out the removed ones and the older fill, and up to
// two changes of root by the recovery key, each written by
// `RecordSet::write_change` as a device does. [`ceilings`] is the set at
// table A's ceilings. The same spec gives the same records, byte for byte.

use std::collections::BTreeMap;

use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::hazmat::PrehashSigner as _;

use cbb_core::certs::sha256;
use cbb_core::identity::ExternalKey;
use cbb_core::records::body::*;
use cbb_core::records::eval::{Input, State, evaluate};
use cbb_core::records::pq::PqKey;
use cbb_core::records::set::RecordSet;
use cbb_core::records::{
    ADMIN_KEYS_MAX, Body, GroupId, Key, KeyHash, MAX_ADMIN_RECORDS, MAX_DEVICES, MAX_ROOT_RECORDS, Record, RecordId,
    Recovery, group_id, keep,
};

/// A key made from a name.
pub struct NamedKey {
    sk: SigningKey,
    pub key: Key,
    pub hash: KeyHash,
}

impl ExternalKey for NamedKey {
    fn public(&self) -> Vec<u8> {
        self.key.public().to_vec()
    }
    fn sign_digest(&self, digest: &[u8; 32]) -> cbb_core::error::Result<Vec<u8>> {
        let sig: p256::ecdsa::Signature =
            self.sk.sign_prehash(digest).map_err(|_| cbb_core::error::Error::msg("groupgen: sign"))?;
        Ok(sig.to_der().as_bytes().to_vec())
    }
}

/// The second half of the recovery key of the groups of seed (SLH-DSA, E-6).
pub fn pq_key(seed: u64) -> PqKey {
    let s = |part: &str| -> [u8; 16] {
        let d = sha256(format!("cbb groupgen {seed} recovery {part}").as_bytes());
        let mut out = [0u8; 16];
        out.copy_from_slice(&d[..16]);
        out
    };
    PqKey::from_seeds(&s("sk_seed"), &s("sk_prf"), &s("pk_seed"))
}

/// The key named name in the groups of seed.
pub fn key(seed: u64, name: &str) -> NamedKey {
    let mut n = 0u32;
    loop {
        // A digest that is no scalar (zero or past the order) is all but
        // impossible; the counter only keeps this total.
        let d = sha256(format!("cbb groupgen {seed} {name} {n}").as_bytes());
        if let Ok(sk) = SigningKey::from_slice(&d) {
            let key = Key::es256(sk.verifying_key().to_sec1_point(false).as_bytes().to_vec());
            let hash = key.hash();
            return NamedKey { sk, key, hash };
        }
        n = n.wrapping_add(1);
    }
}

/// What a group is made of.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Spec {
    pub seed: u64,
    /// Devices in all, the admins' phones included; at most MAX_DEVICES.
    pub devices: usize,
    /// Phone admins the root makes.
    pub admins: usize,
    /// Devices each admin admits and then removes, one revoke each.
    pub removals: usize,
    /// Settings and copies records the root signs between the others.
    pub root_fill: usize,
    /// Copies records each admin signs.
    pub admin_fill: usize,
    /// Root checkpoints, spread over the fill.
    pub checkpoints: usize,
    /// Changes of root by the recovery key, 0, 1 or 2.
    pub takeovers: usize,
}

/// A group built from a spec, with what its evaluation takes besides the
/// records.
pub struct Group {
    pub spec: Spec,
    /// The group's first root key.
    pub root: Key,
    /// The group's recovery key.
    pub recovery: Recovery,
    /// The records, each after the records that name its signer.
    pub records: Vec<Record>,
    /// The lists the changes of root carry, as their bytes.
    pub lists: Vec<Vec<u8>>,
    /// The roots the changes put on the path, in order.
    pub new_roots: Vec<KeyHash>,
    /// The devices removed.
    pub removed: Vec<KeyHash>,
}

impl Group {
    pub fn gid(&self) -> GroupId {
        group_id(&self.root, &self.recovery)
    }

    /// The bytes of the records' envelopes.
    pub fn bytes(&self) -> usize {
        self.records.iter().map(|r| r.envelope().len()).sum()
    }

    /// The units the records take before any is dropped.
    pub fn units(&self) -> u64 {
        self.records.iter().map(|r| keep::units(r.envelope().len())).sum()
    }

    /// The state of all the records at once.
    pub fn evaluate(&self) -> State {
        evaluate(&Input { root: &self.root, recovery: &self.recovery, records: &self.records, lists: &self.lists })
    }

    /// The records in a member's set, as a member that took them one by
    /// one and compacted at each change of root and checkpoint keeps them.
    pub fn set(&self) -> (RecordSet, State) {
        let mut set = RecordSet::new(self.root.clone(), self.recovery.clone());
        // A change of root gives the new root its room only once the set
        // has compacted on it (which it does by itself); then the records
        // dropped before come again.
        for _ in 0..=self.spec.takeovers + 1 {
            self.feed(&mut set);
        }
        self.feed(&mut set);
        let state = set.state();
        (set, state)
    }

    /// Records, lists, then the records again: a new root's first records
    /// wait for its head's list. A record refused then is a fault.
    fn feed(&self, set: &mut RecordSet) {
        set.insert_all(self.records.iter().cloned());
        for l in &self.lists {
            set.insert_list(l).expect("a change's list is taken");
        }
        let (_, refused) = set.insert_all(self.records.iter().cloned());
        assert!(refused.is_empty(), "groupgen: records refused: {refused:?}");
    }
}

struct Builder {
    seed: u64,
    gid: GroupId,
    heads: BTreeMap<KeyHash, (u64, RecordId)>,
    records: Vec<Record>,
    rng: u64,
    /// Each signer's units, and all of them.
    units: BTreeMap<KeyHash, u64>,
    total: u64,
}

impl Builder {
    fn rec(&mut self, by: &NamedKey, kind: Kind) -> Record {
        let (seq, prev) = match self.heads.get(&by.hash) {
            Some((s, id)) => (s.saturating_add(1), Some(*id)),
            None => (1, None),
        };
        let body = Body { group: self.gid, signer: by.hash, seq, prev, time_ms: 0, kind, held: false };
        // Signing with a named key never fails.
        #[allow(clippy::unwrap_used)]
        let r = Record::sign(body, by).unwrap();
        self.heads.insert(by.hash, (seq, r.id()));
        self.push(r.clone());
        r
    }

    /// Takes a record signed elsewhere (a change of root's), in order.
    fn push(&mut self, r: Record) {
        let b = r.body();
        self.heads.insert(b.signer, (b.seq, r.id()));
        let u = keep::units(r.envelope().len());
        *self.units.entry(b.signer).or_insert(0) += u;
        self.total += u;
        self.records.push(r);
    }

    fn seen(&self) -> Vec<Seen> {
        self.heads.iter().map(|(k, (s, id))| Seen { key: *k, seq: *s, id: *id }).collect()
    }

    /// splitmix64: the generator's own choices (names' lengths, rights).
    fn next(&mut self) -> u64 {
        self.rng = self.rng.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.rng;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn device(&mut self, by: &NamedKey, name: &str, f: impl FnOnce(&mut Device)) -> (NamedKey, Record) {
        let m = key(self.seed, name);
        // Names of 8 to 40 bytes, as people name their devices.
        let pad = (self.next() % 33) as usize;
        let shown: String = format!("{name} {}", "x".repeat(pad));
        let roles = [ROLE_MEMBER, ROLE_PHONE, ROLE_WATCH];
        let role = roles.get((self.next() % 3) as usize).copied().unwrap_or(ROLE_MEMBER);
        let mut d = Device::new(m.key.clone(), &shown, role);
        d.rights = RIGHT_READ | RIGHT_SEND;
        f(&mut d);
        let r = self.rec(by, Kind::device(d));
        (m, r)
    }

    fn fill(&mut self, by: &NamedKey, i: usize, root: bool) {
        let incoming_ms = MIN_INCOMING_MS + (self.next() % (MAX_INCOMING_MS - MIN_INCOMING_MS));
        if root && i % 4 == 3 {
            let s = Settings { shared: i % 8 == 3, ..Settings::default() };
            self.rec(by, Kind::settings(s));
        } else {
            self.rec(by, Kind::Copies { incoming_ms, seen: Vec::new() });
        }
    }
}

/// Builds the group of spec.
pub fn build(spec: Spec) -> Group {
    build_with(spec, false)
}

/// Builds the group of spec; a later change of root removes the phone
/// that held the root before only when remove_holder is set.
fn build_with(spec: Spec, remove_holder: bool) -> Group {
    let root = key(spec.seed, "root");
    let recovery = key(spec.seed, "recovery");
    let recovery2 = pq_key(spec.seed);
    let recovery_pair = Recovery { k1: recovery.key.clone(), k2: recovery2.key() };
    let gid = group_id(&root.key, &recovery_pair);
    let mut b = Builder {
        seed: spec.seed,
        gid,
        heads: BTreeMap::new(),
        records: Vec::new(),
        rng: spec.seed,
        units: BTreeMap::new(),
        total: 0,
    };
    let devices = spec.devices.min(MAX_DEVICES);
    let takeovers = spec.takeovers.min(2);
    // Devices the changes of root record: the phone that holds the new
    // root.
    let late = takeovers;
    let admins = spec.admins.min(devices.saturating_sub(late));
    let removed_count = (admins * spec.removals).min(devices.saturating_sub(late + admins));
    let by_root = devices.saturating_sub(late + admins + removed_count);

    let (powers, commands) = AdminKind::Phone.grants();
    let mut admin_keys = Vec::new();
    for i in 0..admins {
        let a = key(spec.seed, &format!("admin {i}"));
        let akey = a.key.clone();
        b.device(&root, &format!("admin phone {i}"), |d| {
            d.role = ROLE_PHONE;
            d.rights = RIGHT_READ | RIGHT_SEND | RIGHT_SECRETS;
            d.admin = Some(akey);
            d.powers = powers;
            d.commands = commands;
        });
        admin_keys.push(a);
    }

    // The root's devices, its fill and checkpoints in between.
    let mut live: Vec<RecordId> = b.records.clone().iter().map(|r| r.id()).collect();
    let steps = by_root.max(spec.root_fill).max(1);
    let every = if spec.checkpoints == 0 { usize::MAX } else { steps.div_ceil(spec.checkpoints + 1).max(1) };
    let (mut d, mut f, mut cps) = (0, 0, 0);
    // The root's fill stops short of its ceiling, with room for the
    // checkpoints still to come, so that every record of the group counts.
    let cp_units = ((by_root + admins + 4) * 40).div_ceil(keep::UNIT) as u64 + 1;
    // After a change of root the earlier roots share the reserve for cut
    // roots, a root's ceiling: the first root leaves room in it for the
    // records of the roots between it and the newest (some 50 units each).
    let cut = takeovers.saturating_sub(1) as u64 * 50;
    let root_room = |b: &Builder, cps: usize, d: usize| {
        let reserve = (spec.checkpoints.saturating_sub(cps)) as u64 * cp_units + (by_root - d) as u64 + 2;
        b.units.get(&root.hash).copied().unwrap_or(0) + 1 + reserve + cut <= MAX_ROOT_RECORDS as u64
    };
    for step in 0..steps {
        if d < by_root && d * steps <= step * by_root {
            let (_, r) = b.device(&root, &format!("device {d}"), |_| {});
            live.push(r.id());
            d += 1;
        }
        if f < spec.root_fill && f * steps <= step * spec.root_fill && root_room(&b, cps, d) {
            b.fill(&root, f, true);
            f += 1;
        }
        if step > 0 && step % every == 0 && cps < spec.checkpoints {
            checkpoint(&mut b, &root, &live);
            cps += 1;
        }
    }
    while d < by_root {
        let (_, r) = b.device(&root, &format!("device {d}"), |_| {});
        live.push(r.id());
        d += 1;
    }
    while f < spec.root_fill && root_room(&b, cps, d) {
        b.fill(&root, f, true);
        f += 1;
    }

    // The admins admit devices and remove them, and fill their room.
    let mut removed = Vec::new();
    let mut left = removed_count;
    for (i, a) in admin_keys.iter().enumerate() {
        let mine = spec.removals.min(left);
        left -= mine;
        let mut admitted = Vec::new();
        for j in 0..mine {
            let (m, _) = b.device(a, &format!("admitted {i} {j}"), |d| d.role = ROLE_MEMBER);
            admitted.push(m.hash);
        }
        for h in admitted {
            let seen = b.seen();
            b.rec(a, Kind::Revoke(Removal { keys: vec![h], seen }));
            removed.push(h);
        }
        // An admin fills up to its ceiling, all of them leaving the set room
        // for the changes of root's records (the new root's phone, a copy of
        // the settings, the writer's first checkpoint, the head with its
        // SLH-DSA signature, some 16 units), so that the set holds at most its 4096
        // units and everything counts.
        let end = takeovers as u64 * 30 + 8;
        for j in 0..spec.admin_fill {
            let mine = b.units.get(&a.hash).copied().unwrap_or(0);
            if mine + 1 > MAX_ADMIN_RECORDS as u64 || b.total + 1 + end > keep::ROOM {
                break;
            }
            b.fill(a, j, false);
        }
    }

    // The changes of root: the recovery key makes a new root, which
    // records the phone that holds it, as a device writes the change; the
    // phone that held the root before stays a device (the owner may
    // remove it: build_with).
    let mut lists: Vec<Vec<u8>> = Vec::new();
    let mut new_roots = Vec::new();
    let mut holder: Option<KeyHash> = None;
    let mut last_root: Option<NamedKey> = None;
    for t in 0..takeovers {
        let n = key(spec.seed, &format!("new root {t}"));
        let phone = key(spec.seed, &format!("new root phone {t}"));
        let mut d = Device::new(phone.key.clone(), &format!("new root phone {t}"), ROLE_PHONE);
        d.rights = RIGHT_READ | RIGHT_SEND | RIGHT_SECRETS;
        let mut set = RecordSet::new(root.key.clone(), recovery_pair.clone());
        // Records, lists, then the records again: a new root's first
        // records wait for its head's list. Nothing may be refused then.
        set.insert_all(b.records.iter().cloned());
        for l in &lists {
            set.insert_list(l).expect("a change's list is taken");
        }
        let (_, refused) = set.insert_all(b.records.iter().cloned());
        assert!(refused.is_empty(), "groupgen: records refused: {refused:?}");
        let state = set.state();
        // A change written from a valid group never fails.
        let lost: Vec<KeyHash> = holder.take().into_iter().filter(|_| remove_holder).collect();
        #[allow(clippy::unwrap_used)]
        let w = set.write_change(&state, &recovery, &recovery2, &n, d, &lost, false, 0).unwrap();
        removed.extend(lost);
        holder = Some(phone.hash);
        for r in w.first {
            b.push(r);
        }
        b.push(w.record);
        lists.push(w.list.encode().to_vec());
        new_roots.push(n.hash);
        last_root = Some(n);
    }

    // The newest root fills its own room too, up to its ceiling and inside
    // the set's room: the earlier roots' records stay in the reserve for
    // cut roots, so that a group at the ceilings fills every part of it.
    if let Some(n) = &last_root {
        let mut f = 0;
        while f < spec.root_fill {
            let mine = b.units.get(&n.hash).copied().unwrap_or(0);
            if mine + 1 > MAX_ROOT_RECORDS as u64 || b.total + 1 > keep::ROOM {
                break;
            }
            b.fill(n, f, true);
            f += 1;
        }
    }

    Group { spec, root: root.key, recovery: recovery_pair, records: b.records, lists, new_roots, removed }
}

/// A root checkpoint at the root's head that keeps the live devices'
/// records: the removed devices, the older fill and earlier checkpoints
/// are its gaps.
fn checkpoint(b: &mut Builder, root: &NamedKey, live: &[RecordId]) {
    let Some((seq, id)) = b.heads.get(&root.hash).copied() else { return };
    let mut keep: Vec<RecordId> = live.to_vec();
    keep.sort();
    keep.dedup();
    b.rec(root, Kind::Checkpoint { heads: vec![Head { key: root.hash, seq, id }], keep });
}

/// About 5, 100 and 1000 records.
pub fn sizes(seed: u64) -> [Spec; 3] {
    let base =
        Spec { seed, devices: 0, admins: 0, removals: 0, root_fill: 0, admin_fill: 0, checkpoints: 0, takeovers: 0 };
    [
        Spec { devices: 4, admins: 1, root_fill: 1, ..base },
        Spec {
            devices: 40,
            admins: 3,
            removals: 4,
            root_fill: 30,
            admin_fill: 6,
            checkpoints: 1,
            takeovers: 1,
            ..base
        },
        Spec {
            devices: 200,
            admins: 8,
            removals: 6,
            root_fill: 400,
            admin_fill: 40,
            checkpoints: 3,
            takeovers: 2,
            ..base
        },
    ]
}

/// The set at the format's ceilings: 256 devices, 12 phone admins at
/// their 256 units with many removals, the root at its 1024, two
/// changes of root and checkpoints with gaps; within a few units of the set's
/// 4096 and inside them, so that every record still counts.
pub fn ceilings(seed: u64) -> Spec {
    Spec {
        seed,
        devices: MAX_DEVICES,
        admins: ADMIN_KEYS_MAX,
        removals: 8,
        root_fill: MAX_ROOT_RECORDS,
        admin_fill: MAX_ADMIN_RECORDS,
        checkpoints: 4,
        takeovers: 2,
    }
}
