// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! What the black-box tests of the seen line, the last root only (L with
//! B's re-issue) and the spare key (S) share: keys, an admin's own chain,
//! a group with an admin, a change of root, and syncing whole sets in
//! several orders. Written from the rules (docs and the notes), through
//! the record set's public API only.

#![allow(dead_code, reason = "each test file uses its own part")]

use std::collections::BTreeMap;

use cbb_core::identity::ExternalKey;
use cbb_core::records::body::{Device, RIGHT_READ, RIGHT_SEND, ROLE_MEMBER, ROLE_PHONE, Removal, Seen, Settings};
use cbb_core::records::pq::PqKey;
use cbb_core::records::set::Written;
use cbb_core::records::{Body, Key, KeyHash, Kind, Record, RecordId, RecordSet, Recovery, State};
use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::hazmat::PrehashSigner as _;

pub struct K {
    pub sk: SigningKey,
    pub key: Key,
    pub hash: KeyHash,
}

impl ExternalKey for K {
    fn public(&self) -> Vec<u8> {
        self.key.public().to_vec()
    }
    fn sign_digest(&self, digest: &[u8; 32]) -> cbb_core::error::Result<Vec<u8>> {
        let sig: p256::ecdsa::Signature = self.sk.sign_prehash(digest).unwrap();
        Ok(sig.to_der().as_bytes().to_vec())
    }
}

pub fn k(name: &str) -> K {
    let sk = SigningKey::from_slice(&cbb_core::certs::sha256(name.as_bytes())).unwrap();
    let key = Key::es256(sk.verifying_key().to_sec1_point(false).as_bytes().to_vec());
    let hash = key.hash();
    K { sk, key, hash }
}

pub fn rk2() -> PqKey {
    PqKey::from_seeds(&[0x31; 16], &[0x32; 16], &[0x33; 16])
}

pub fn recovery() -> Recovery {
    Recovery { k1: k("recovery").key, k2: rk2().key() }
}

/// Signs an admin's (or an old root's) records apart from the set, as its
/// own device does: the set is read only for the group.
pub struct Chain {
    pub heads: BTreeMap<KeyHash, (u64, RecordId)>,
}

impl Chain {
    pub fn new() -> Chain {
        Chain { heads: BTreeMap::new() }
    }

    /// Continues by's chain from what set holds of it (its highest seq).
    pub fn follow(&mut self, set: &RecordSet, by: &K) {
        if let Some(s) = head_of(set, &by.hash) {
            self.heads.insert(by.hash, (s.seq, s.id));
        }
    }

    /// Signs as the honest writer does (see `honest`).
    pub fn sign(&mut self, set: &RecordSet, by: &K, kind: Kind, time_ms: u64) -> Record {
        let kind = if self.heads.contains_key(&by.hash) { kind } else { Self::honest(set, kind) };
        self.sign_raw(set, by, kind, time_ms)
    }

    /// As the honest writer signs: a key's first record carries, when its
    /// own seen is empty, the current root's head the set holds, so that it
    /// sits above the seen line.
    pub fn honest(set: &RecordSet, kind: Kind) -> Kind {
        let Some(root) = set.state().roots.last().copied() else { return kind };
        let Some(head) = set
            .in_dependency_order()
            .into_iter()
            .filter(|r| r.body().signer == root)
            .max_by_key(|r| r.body().seq)
            .map(|r| cbb_core::records::body::Seen { key: root, seq: r.body().seq, id: r.id() })
        else {
            return kind;
        };
        let fill = |seen: &mut Vec<cbb_core::records::body::Seen>| {
            if seen.is_empty() {
                seen.push(head);
            }
        };
        let mut kind = kind;
        match &mut kind {
            Kind::Device(d) => fill(&mut d.seen),
            Kind::Revoke(rm) | Kind::Freeze(rm) => fill(&mut rm.seen),
            Kind::Thaw { seen, .. } | Kind::Copies { seen, .. } | Kind::Hubs { seen, .. } | Kind::Ack { seen, .. } => {
                fill(seen)
            }
            _ => {}
        }
        kind
    }

    /// Signs exactly what it is given, as a deviant device may.
    pub fn sign_raw(&mut self, set: &RecordSet, by: &K, kind: Kind, time_ms: u64) -> Record {
        let (seq, prev) = self.heads.get(&by.hash).map_or((1, None), |(s, id)| (s + 1, Some(*id)));
        let body = Body { group: set.group(), signer: by.hash, seq, prev, time_ms, kind, held: false };
        let r = Record::sign(body, by).unwrap();
        self.heads.insert(by.hash, (seq, r.id()));
        r
    }
}

/// The head (highest seq) of key's chain that set holds, as a `seen`.
pub fn head_of(set: &RecordSet, key: &KeyHash) -> Option<Seen> {
    set.in_dependency_order()
        .into_iter()
        .filter(|r| r.body().signer == *key)
        .max_by_key(|r| r.body().seq)
        .map(|r| Seen { key: *key, seq: r.body().seq, id: r.id() })
}

/// The record of key's chain at seq, as a `seen`.
pub fn seen_at(set: &RecordSet, key: &KeyHash, seq: u64) -> Seen {
    let r =
        set.in_dependency_order().into_iter().find(|r| r.body().signer == *key && r.body().seq == seq).expect("held");
    Seen { key: *key, seq, id: r.id() }
}

pub const POWERS: u64 = 0x1ff & !64;

pub fn plain(member: &K, name: &str) -> Device {
    let mut d = Device::new(member.key.clone(), name, ROLE_MEMBER);
    d.rights = RIGHT_READ | RIGHT_SEND;
    d
}

pub fn admin_device(member: &K, name: &str, admin: &K) -> Device {
    let mut d = Device::new(member.key.clone(), name, ROLE_PHONE);
    d.rights = RIGHT_READ | RIGHT_SEND;
    d.admin = Some(admin.key.clone());
    d.powers = POWERS;
    d
}

pub fn removal(keys: &[&K], seen: Vec<Seen>) -> Removal {
    let mut keys: Vec<KeyHash> = keys.iter().map(|k| k.hash).collect();
    keys.sort();
    Removal { keys, seen }
}

pub fn has(s: &State, member: &K) -> bool {
    s.device_by_key(&member.hash).is_some()
}

pub fn admin_of(s: &State, member: &K) -> Option<KeyHash> {
    s.device_by_key(&member.hash).and_then(|d| d.admin)
}

pub fn is_admin(s: &State, a: &K) -> bool {
    s.devices.iter().any(|d| d.admin == Some(a.hash))
}

pub fn frozen(s: &State, member: &K) -> bool {
    s.device_by_key(&member.hash).is_some_and(|d| d.frozen)
}

/// The group the L and S tests start from, on the root's device: the root
/// R1 admits D and E; admin key A on phone PA (admin since its
/// admission); A admits F; R1 writes settings, hubs (D) and copies. Each
/// root record is followed by nothing else; t is the clock after it.
pub struct Group {
    pub set: RecordSet,
    pub r1: K,
    pub chain: Chain,
    pub t: u64,
}

pub fn group(tag: &str) -> Group {
    let r1 = k(&format!("{tag} root 1"));
    let mut set = RecordSet::new(r1.key.clone(), recovery());
    let mut t = 1_000u64;
    let (d, e, pa, a) = (k("D"), k("E"), k("PA"), k("A"));
    for kind in [
        Kind::Copies { secret_ttl_ms: 0, ttl_ms: 60_000, seen: vec![] },
        Kind::settings(Settings { shared: true, ..Settings::default() }),
        Kind::device(plain(&d, "D")),
        Kind::device(plain(&e, "E")),
        Kind::device(admin_device(&pa, "PA", &a)),
        Kind::Hubs { hubs: vec![d.key.device_id()], seen: vec![] },
    ] {
        t += 1_000;
        let st = set.state();
        set.write_record(&st, &r1, kind, t).unwrap();
    }
    let mut chain = Chain::new();
    t += 1_000;
    let root_head = head_of(&set, &r1.hash).unwrap();
    let mut f = plain(&k("F"), "F");
    f.seen = vec![root_head];
    let r = chain.sign(&set, &a, Kind::device(f), t);
    set.insert(r).unwrap();
    let st = set.state();
    assert!(has(&st, &k("F")) && is_admin(&st, &a), "the group as built: {st:?}");
    Group { set, r1, chain, t }
}

/// A change of root on the writer's set (the device where the recovery
/// key was entered): new root `root`, its phone `phone`, the devices the
/// person leaves out.
pub fn change(set: &mut RecordSet, root: &K, phone: &K, leave_out: &[KeyHash], t: u64) -> Written {
    let st = set.state();
    let p = Device::new(phone.key.clone(), "new phone", ROLE_PHONE);
    set.write_change(&st, &k("recovery"), &rk2(), root, p, leave_out, false, t).unwrap()
}

/// Every record and list `from` holds, offered to `to` a few times over
/// (records that wait for others go in on a later pass).
pub fn sync(from: &RecordSet, to: &mut RecordSet) {
    let lists: Vec<Vec<u8>> = from.lists().map(<[u8]>::to_vec).collect();
    let records: Vec<Record> = from.in_dependency_order().into_iter().cloned().collect();
    offer(to, &lists, &records);
}

pub fn offer(to: &mut RecordSet, lists: &[Vec<u8>], records: &[Record]) {
    for _ in 0..3 {
        for l in lists {
            let _ = to.insert_list(l);
        }
        for r in records {
            let _ = to.insert(r.clone());
        }
    }
}

/// What every member must agree on: roots, devices, removed keys,
/// settings, the copies' window and the recovery chain.
pub type View = (Vec<KeyHash>, Vec<String>, Vec<KeyHash>, Settings, Option<u64>, Vec<RecordId>);

pub fn view(s: &State) -> View {
    let mut devices: Vec<String> = s
        .devices
        .iter()
        .map(|d| format!("{:?} {} admin={:?} frozen={} rights={}", d.key.hash(), d.name, d.admin, d.frozen, d.rights))
        .collect();
    devices.sort();
    let mut revoked = s.revoked.clone();
    revoked.sort();
    (s.roots.clone(), devices, revoked, s.settings.clone(), s.ttl_ms, s.chain())
}

/// The records and lists of `src` offered to fresh members in several
/// orders (as held, reversed, and three rotations interleaved): every
/// member reaches the same view as `src`.
pub fn same_in_every_order(src: &RecordSet, what: &str) {
    let lists: Vec<Vec<u8>> = src.lists().map(<[u8]>::to_vec).collect();
    let records: Vec<Record> = src.in_dependency_order().into_iter().cloned().collect();
    let want = view(&src.state());
    let n = records.len().max(1);
    let mut orders: Vec<Vec<Record>> = vec![records.clone(), records.iter().rev().cloned().collect()];
    for step in [3usize, 5, 7] {
        let mut o = Vec::with_capacity(n);
        for start in 0..step {
            o.extend(records.iter().skip(start).step_by(step).cloned());
        }
        orders.push(o);
    }
    for (i, o) in orders.iter().enumerate() {
        let mut m = RecordSet::new(src.root().clone(), src.recovery().clone());
        offer(&mut m, &lists, o);
        for _ in 0..n {
            let before = m.len();
            offer(&mut m, &lists, o);
            if m.len() == before {
                break;
            }
        }
        assert_eq!(view(&m.state()), want, "{what}: order {i}");
    }
}
