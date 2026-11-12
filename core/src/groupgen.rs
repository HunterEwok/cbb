// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Groups of records v3 of a chosen size, built from a fixed seed, for the
//! tests that measure the records at their ceilings, the board's
//! measurements and the fuzzers' seeds (feature `testkit`, never in a
//! release).
//!
//! [`build`] makes a valid group from a [`Spec`]: the root and its devices,
//! phone admins that admit devices and remove some of them, settings and
//! copies records that fill each key's room, root checkpoints that keep the
//! live devices and leave out the removed ones and the older fill (gaps in
//! what they keep), and up to two takeovers, each claim held for the full
//! delay so that it counts. [`sizes`] names the sets the tests measure:
//! about 5, 100 and 1000 records, and [`ceilings`], the set at the format's
//! ceilings (the 4096 units of room filled, 256 devices, the root at its
//! 1024 units and admins at their 256, two takeovers, checkpoints with
//! gaps). Fills stop short of each ceiling, so every record counts.
//!
//! The same spec gives the same records, byte for byte: keys come from
//! names with the seed in them, and ECDSA signs deterministically
//! (RFC 6979).
//!
//! Test code: its numbers are small and fixed (at most a few thousand
//! records), so it counts with plain arithmetic.
#![allow(clippy::arithmetic_side_effects)]

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::hazmat::PrehashSigner as _;

use crate::certs::sha256;
use crate::identity::ExternalKey;
use crate::records::body::*;
use crate::records::eval::{Input, State, evaluate};
use crate::records::set::RecordSet;
use crate::records::{
    Body, GroupId, Key, KeyHash, MAX_ADMIN_RECORDS, MAX_DEVICES, MAX_ROOT_RECORDS, Record, RecordId, keep,
};

/// A key made from a name.
pub struct NamedKey {
    sk: SigningKey,
    pub key: Key,
    pub hash: KeyHash,
}

impl ExternalKey for NamedKey {
    fn public(&self) -> Vec<u8> {
        self.key.public.clone()
    }
    fn sign_digest(&self, digest: &[u8; 32]) -> crate::error::Result<Vec<u8>> {
        let sig: p256::ecdsa::Signature =
            self.sk.sign_prehash(digest).map_err(|_| crate::error::Error::msg("groupgen: sign"))?;
        Ok(sig.to_der().as_bytes().to_vec())
    }
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
    /// Takeovers, 0, 1 or 2.
    pub takeovers: usize,
}

/// A group built from a spec, with what its evaluation takes besides the
/// records.
pub struct Group {
    pub spec: Spec,
    /// The group's first root key.
    pub root: Key,
    /// The records, each after the records that name its signer.
    pub records: Vec<Record>,
    /// How long the device has held each claim: the full delay.
    pub held_ms: BTreeMap<RecordId, u64>,
    /// The claims counted, none: the evaluation counts them from held_ms.
    pub counted: BTreeSet<RecordId>,
    /// The roots the takeovers put on the path, in order.
    pub new_roots: Vec<KeyHash>,
    /// The devices removed.
    pub removed: Vec<KeyHash>,
}

impl Group {
    pub fn gid(&self) -> GroupId {
        self.root.device_id()
    }

    /// The bytes of the records' envelopes.
    pub fn bytes(&self) -> usize {
        self.records.iter().map(|r| r.envelope().len()).sum()
    }

    /// The units the records take before any is dropped.
    pub fn units(&self) -> u64 {
        self.records.iter().map(|r| keep::units(r.envelope().len(), matches!(r.body().kind, Kind::Claim { .. }))).sum()
    }

    /// The state of all the records at once.
    pub fn evaluate(&self) -> State {
        evaluate(&Input { root: &self.root, records: &self.records, held_ms: &self.held_ms, counted: &self.counted })
    }

    /// The records in a member's set, as a member that took them one by
    /// one and compacted at each takeover and checkpoint keeps them.
    pub fn set(&self) -> (RecordSet, State) {
        let mut set = RecordSet::new(self.root.clone());
        // A takeover gives the new root its room only once the set has
        // compacted on it; then the records dropped before come again.
        for _ in 0..=self.spec.takeovers + 1 {
            set.insert_all(self.records.iter().cloned());
            let state = set.state(&self.held_ms);
            set.compact(&state);
        }
        set.insert_all(self.records.iter().cloned());
        let state = set.state(&self.held_ms);
        (set, state)
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
        let u = keep::units(r.envelope().len(), matches!(r.body().kind, Kind::Claim { .. }));
        *self.units.entry(by.hash).or_insert(0) += u;
        self.total += u;
        self.records.push(r.clone());
        r
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
        let r = self.rec(by, Kind::Device(d));
        (m, r)
    }

    fn fill(&mut self, by: &NamedKey, i: usize, root: bool) {
        let incoming_ms = MIN_INCOMING_MS + (self.next() % (MAX_INCOMING_MS - MIN_INCOMING_MS));
        if root && i % 4 == 3 {
            let s = Settings { shared: i % 8 == 3, ..Settings::default() };
            self.rec(by, Kind::Settings(s));
        } else {
            self.rec(by, Kind::Copies { incoming_ms });
        }
    }
}

/// Builds the group of spec.
pub fn build(spec: Spec) -> Group {
    let root = key(spec.seed, "root");
    let gid = root.key.device_id();
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
    // Devices the takeovers' new roots record: the phone that holds the
    // root and the next takeover's admin.
    let late = takeovers * 2;
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
    let root_room = |b: &Builder, cps: usize, d: usize| {
        let reserve = (spec.checkpoints.saturating_sub(cps)) as u64 * cp_units + (by_root - d) as u64 + 2;
        b.units.get(&root.hash).copied().unwrap_or(0) + 1 + reserve <= MAX_ROOT_RECORDS as u64
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
            b.rec(a, Kind::Revoke(Removal { keys: alloc::vec![h], seen }));
            removed.push(h);
        }
        // An admin fills up to its ceiling, the first one leaving room for
        // its claim, and all of them leaving the set room for the
        // takeovers' records, so that the set holds at most its 4096 units
        // and everything counts.
        // A claim's seen names every signer: about 80 bytes each.
        let claim_units = ((admins + 8) * 80).div_ceil(keep::UNIT) as u64 + keep::CLAIM_EXTRA;
        let claim = if i == 0 && takeovers > 0 { claim_units } else { 0 };
        let end = takeovers as u64 * (claim_units + 4) + 8;
        for j in 0..spec.admin_fill {
            let mine = b.units.get(&a.hash).copied().unwrap_or(0);
            if mine + 1 + claim > MAX_ADMIN_RECORDS as u64 || b.total + 1 + end > keep::ROOM {
                break;
            }
            b.fill(a, j, false);
        }
    }

    // The takeovers: an admin claims for a new root, the claim is held for
    // the delay, the new root records the phone that holds it and, for the
    // next takeover, an admin.
    let mut held_ms = BTreeMap::new();
    let mut new_roots = Vec::new();
    let mut claimer = (!admin_keys.is_empty()).then(|| key(spec.seed, "admin 0"));
    for t in 0..takeovers {
        let Some(a) = claimer.take() else { break };
        let n = key(spec.seed, &format!("new root {t}"));
        let seen = b.seen();
        let c = b.rec(&a, Kind::Claim { root: n.key.clone(), seen });
        held_ms.insert(c.id(), DEFAULT_DELAY_MS);
        b.device(&n, &format!("new root phone {t}"), |d| {
            d.role = ROLE_PHONE;
            d.rights = RIGHT_READ | RIGHT_SEND | RIGHT_SECRETS;
            d.holds_root = true;
        });
        let next = key(spec.seed, &format!("late admin {t}"));
        let nkey = next.key.clone();
        b.device(&n, &format!("late admin phone {t}"), |d| {
            d.role = ROLE_PHONE;
            d.rights = RIGHT_READ | RIGHT_SEND | RIGHT_SECRETS;
            d.admin = Some(nkey);
            d.powers = powers;
            d.commands = commands;
        });
        new_roots.push(n.hash);
        claimer = Some(next);
    }

    Group { spec, root: root.key, records: b.records, held_ms, counted: BTreeSet::new(), new_roots, removed }
}

/// A root checkpoint at the root's head that keeps the live devices'
/// records: the removed devices, the older fill and earlier checkpoints
/// are its gaps.
fn checkpoint(b: &mut Builder, root: &NamedKey, live: &[RecordId]) {
    let Some((seq, id)) = b.heads.get(&root.hash).copied() else { return };
    let mut keep: Vec<RecordId> = live.to_vec();
    keep.sort();
    keep.dedup();
    b.rec(root, Kind::Checkpoint { heads: alloc::vec![Head { key: root.hash, seq, id }], keep });
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
/// takeovers and checkpoints with gaps; within a few units of the set's
/// 4096 and inside them, so that every record still counts.
pub fn ceilings(seed: u64) -> Spec {
    Spec {
        seed,
        devices: MAX_DEVICES,
        admins: 12,
        removals: 8,
        root_fill: 1000,
        admin_fill: MAX_ADMIN_RECORDS,
        checkpoints: 4,
        takeovers: 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::records::eval::Stop;

    fn check(g: &Group, s: &State) {
        let spec = g.spec;
        assert_eq!(s.stop, Stop::None, "{spec:?}: {:?}", s.conflicts);
        assert_eq!(s.roots.len(), 1 + spec.takeovers, "{spec:?}");
        assert_eq!(&s.roots[1..], &g.new_roots[..]);
        assert_eq!(s.devices.len() + g.removed.len(), spec.devices.min(MAX_DEVICES), "{spec:?}");
        for h in &g.removed {
            assert!(s.revoked.contains(h), "{spec:?}");
        }
        assert!(s.ignored.is_empty(), "{spec:?}: {:?}", s.ignored);
        if spec.takeovers > 0 {
            assert!(s.root_device.is_some());
        }
    }

    #[test]
    fn the_sizes_are_valid_groups() {
        for spec in sizes(1) {
            let g = build(spec);
            check(&g, &g.evaluate());
        }
    }

    #[test]
    fn the_same_seed_gives_the_same_records() {
        let [a, ..] = sizes(7);
        let (x, y) = (build(a), build(a));
        let ids = |g: &Group| g.records.iter().map(|r| r.id()).collect::<Vec<_>>();
        assert_eq!(ids(&x), ids(&y));
        assert_ne!(ids(&x), ids(&build(Spec { seed: 8, ..a })));
    }
}
