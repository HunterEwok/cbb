// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

// The records_set fuzzer's generator (core/fuzz), kept here to replay its
// slow inputs (testdata/records-cost): records signed with fixed test keys
// from an input's bytes, changes of root by the recovery key among them,
// and a member's fill in rounds of sync. `big` is the fuzzer's large
// checkpoints (FZ_NO_BIG there turns them off). Kept close to its source,
// so its style is the fuzzer's.
#![allow(
    clippy::large_enum_variant,
    clippy::manual_range_patterns,
    clippy::field_reassign_with_default,
    clippy::collapsible_if
)]

use std::collections::BTreeMap;
use std::sync::OnceLock;

use cbb_core::identity::ExternalKey;
use cbb_core::records::body::*;
use cbb_core::records::key::group_id;
use cbb_core::records::{Body, Key, KeyHash, Kind, Record, RecordId, RecordSet};
use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::hazmat::PrehashSigner as _;

struct K {
    sk: SigningKey,
    key: Key,
    hash: KeyHash,
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

fn k(name: &str) -> K {
    let sk = SigningKey::from_slice(&cbb_core::certs::sha256(name.as_bytes())).unwrap();
    let key = Key::es256(sk.verifying_key().to_sec1_point(false).as_bytes().to_vec());
    let hash = key.hash();
    K { sk, key, hash }
}

// 0 root, 1..=3 admin keys, 4..=6 their phones, 7..=8 new roots,
// 9 the recovery key, 10..=17 devices
const NAMES: [&str; 18] = [
    "root",
    "admin a",
    "admin b",
    "admin c",
    "phone a",
    "phone b",
    "phone c",
    "new root a",
    "new root b",
    "recovery",
    "dev 0",
    "dev 1",
    "dev 2",
    "dev 3",
    "dev 4",
    "dev 5",
    "dev 6",
    "dev 7",
];
const RECOVERY: usize = 9;

fn keys() -> &'static Vec<K> {
    static KS: OnceLock<Vec<K>> = OnceLock::new();
    KS.get_or_init(|| NAMES.iter().map(|n| k(n)).collect())
}

/// The recovery key's second half (E-6): SLH-DSA, slow to sign, so heads
/// are signed once per body and kept (`sign_head_cached`).
fn k2() -> &'static cbb_core::records::pq::PqKey {
    static K2: OnceLock<cbb_core::records::pq::PqKey> = OnceLock::new();
    K2.get_or_init(|| cbb_core::records::pq::PqKey::from_seeds(&[0x31; 16], &[0x32; 16], &[0x33; 16]))
}

fn recov() -> cbb_core::records::Recovery {
    cbb_core::records::Recovery { k1: keys()[RECOVERY].key.clone(), k2: k2().key() }
}

/// A head signed with both halves, kept by its body's bytes: SLH-DSA takes
/// about a third of a second a signature, so the same head across inputs
/// is signed once.
fn sign_head_cached(body: Body) -> Option<Record> {
    use std::collections::HashMap;
    use std::sync::Mutex;
    static C: OnceLock<Mutex<HashMap<Vec<u8>, Record>>> = OnceLock::new();
    let c = C.get_or_init(|| Mutex::new(HashMap::new()));
    let key = body.encode();
    if let Some(r) = c.lock().unwrap().get(&key) {
        return Some(r.clone());
    }
    let r = Record::sign_head(body, &keys()[RECOVERY], k2()).ok()?;
    let mut m = c.lock().unwrap();
    if m.len() > 20_000 {
        m.clear();
    }
    m.insert(key, r.clone());
    Some(r)
}

/// At most this many heads an input makes: each new one costs a signature.
const MAX_HEADS: usize = 4;

/// What a member is handed: a record or a list's bytes.
#[derive(Clone)]
pub enum Item {
    Rec(Record),
    List(Vec<u8>),
}

pub struct G {
    gid: cbb_core::records::GroupId,
    heads: BTreeMap<KeyHash, (u64, RecordId)>,
    pub recs: Vec<Record>,
    /// Lists that travel, and those nobody ever sends.
    lists: Vec<Vec<u8>>,
    withheld: Vec<Vec<u8>>,
}

impl G {
    fn body(&self, by: &K, kind: Kind, time: u64) -> Body {
        let (seq, prev) = match self.heads.get(&by.hash) {
            Some((s, id)) => (s + 1, Some(*id)),
            None => (1, None),
        };
        Body { group: self.gid, signer: by.hash, seq, prev, time_ms: time, kind, held: false }
    }
    fn seen(&self, mask: u8) -> Vec<Seen> {
        self.heads
            .iter()
            .enumerate()
            .filter(|(i, _)| mask == 0xff || (mask >> (i % 8)) & 1 == 1)
            .map(|(_, (k, (s, id)))| Seen { key: *k, seq: *s, id: *id })
            .collect()
    }
    /// What a writer that holds every record and list would list.
    fn listing(&self) -> Vec<RecordId> {
        let ks = keys();
        let mut set = RecordSet::new(ks[0].key.clone(), recov());
        for _ in 0..3 {
            set.insert_all(self.recs.clone());
            for l in &self.lists {
                let _ = set.insert_list(l);
            }
        }
        set.change_list(&set.state()).0
    }
}

fn heads_made(g: &G) -> usize {
    g.recs.iter().filter(|r| matches!(r.body().kind, Kind::Recovery { .. })).count()
}

fn list_bytes(ids: &[RecordId]) -> Vec<u8> {
    let mut v = ids.to_vec();
    v.sort();
    v.dedup();
    List(v).encode()
}

pub fn build(data: &[u8], big: bool) -> (G, u8) {
    let ks = keys();
    let mut g = G {
        gid: group_id(&ks[0].key, &recov()),
        heads: BTreeMap::new(),
        recs: Vec::new(),
        lists: Vec::new(),
        withheld: Vec::new(),
    };
    let cfg = data.first().copied().unwrap_or(0);
    let mut it = data.chunks_exact(4);
    let _ = it.next();
    for (n, c) in it.enumerate() {
        if n >= 48 {
            break;
        }
        let (who, op, arg, x) = (c[0], c[1], c[2], c[3]);
        let signer_idx = match who % 8 {
            0 | 1 => 0,
            2 => 1,
            3 => 2,
            4 => 3,
            5 => 7,
            6 => 8,
            _ => 10 + usize::from(x % 8),
        };
        let by = &ks[signer_idx];
        let dev = &ks[10 + usize::from(arg % 8)];
        let any_key = &ks[usize::from(arg) % ks.len()];
        let time = u64::from(n as u32) * 1000;
        let kind = match op % 16 {
            0 | 1 => {
                let role = [ROLE_MEMBER, ROLE_PHONE, ROLE_WATCH, ROLE_LEAF][usize::from(x % 4)];
                let mut d = Device::new(dev.key.clone(), "dev", role);
                d.rights = u64::from(x >> 4) & 0xf;
                d.guarded = role == ROLE_LEAF && x & 0x40 != 0;
                Kind::device(d)
            }
            2 => {
                let i = 1 + usize::from(arg % 3);
                let mut d = Device::new(ks[i + 3].key.clone(), "admin", ROLE_PHONE);
                d.rights = RIGHT_READ | RIGHT_SEND;
                d.caps = CAP_ADMIN;
                d.admin = Some(ks[i].key.clone());
                d.powers = (u64::from(x) | (u64::from(arg >> 2) << 8)) & 0x1ff & !64;
                Kind::device(d)
            }
            3 => {
                let mut v = vec![any_key.hash];
                if x & 1 == 1 {
                    v.push(dev.hash);
                }
                v.sort();
                v.dedup();
                Kind::Revoke(Removal { keys: v, seen: g.seen(x) })
            }
            4 => Kind::Freeze(Removal { keys: vec![any_key.hash], seen: g.seen(x) }),
            5 => {
                let fs: Vec<RecordId> =
                    g.recs.iter().filter(|r| matches!(r.body().kind, Kind::Freeze(_))).map(Record::id).collect();
                match fs.get(usize::from(arg) % fs.len().max(1)) {
                    Some(f) => Kind::Thaw { ids: vec![*f], seen: if x & 1 == 0 { g.seen(x) } else { vec![] } },
                    None => continue,
                }
            }
            6 => match g.recs.get(usize::from(arg) % g.recs.len().max(1)) {
                Some(r) => Kind::Resolve(vec![r.id()]),
                None => continue,
            },
            7 | 8 | 9 if heads_made(&g) < MAX_HEADS => {
                // A change of root by the recovery key, with one of the
                // lists a writer could send.
                let rec = &ks[RECOVERY];
                let new_root = match x % 8 {
                    0 => &ks[1 + usize::from(arg % 3)], // an admin key named as the root
                    1 => &ks[0],                        // the first root again
                    _ => &ks[7 + usize::from(arg % 2)],
                };
                let honest = g.listing();
                let ids: Vec<RecordId> = match (x >> 3) % 6 {
                    0 | 1 => honest,
                    2 => honest.into_iter().filter(|id| (id.0[0] ^ arg) & 1 == 0).collect(),
                    3 => {
                        // IDs nobody holds, and some of the group's.
                        let mut v: Vec<RecordId> = (0..1 + arg % 4)
                            .map(|i| RecordId(cbb_core::certs::sha256(&[i, arg, x, n as u8])))
                            .collect();
                        v.extend(g.recs.iter().filter(|r| r.id().0[1] & 1 == 1).map(Record::id));
                        v
                    }
                    4 => Vec::new(),
                    _ => g.recs.iter().map(Record::id).collect(),
                };
                let bytes = match (x >> 6) & 3 {
                    3 if arg & 1 == 1 => vec![0x9f, arg, x], // bytes that do not read
                    _ => list_bytes(&ids),
                };
                let hash = list_hash(&bytes);
                let fork = op % 16 == 9 && g.heads.contains_key(&rec.hash);
                // Where the new root's records start (field 12): 0 for a fresh
                // key, else past what the key signed, or anywhere.
                let signed = g.heads.get(&new_root.hash).map_or(0, |(s, _)| *s);
                let from = match (arg >> 4) % 4 {
                    0 if signed == 0 => 0,
                    0 | 1 => signed + 1,
                    2 => u64::from(arg % 5),
                    _ => signed,
                };
                // The new root's first checkpoint (field 13): its newest
                // checkpoint, another record, or an ID nobody holds.
                let cp = g
                    .recs
                    .iter()
                    .rev()
                    .find(|r| r.body().signer == new_root.hash && matches!(r.body().kind, Kind::Checkpoint { .. }));
                let first = match (cp, arg >> 6) {
                    (Some(c), 0..=2) => c.id(),
                    (_, 3) | (None, 0) => RecordId(cbb_core::certs::sha256(&[arg, x, n as u8, 13])),
                    _ => g.recs.get(usize::from(x) % g.recs.len().max(1)).map_or(RecordId([7; 32]), Record::id),
                };
                let mut body = g.body(
                    rec,
                    Kind::Recovery { root: new_root.key.clone(), list: hash, from, first, signer2: k2().key().hash() },
                    time,
                );
                if fork {
                    // A second head at the recovery key's last seq, its prev
                    // right or wrong.
                    body.seq -= 1;
                    body.prev = if arg & 2 == 0 {
                        g.recs
                            .iter()
                            .find(|r| r.body().signer == rec.hash && r.body().seq + 1 == body.seq)
                            .map(|r| r.id())
                    } else {
                        Some(RecordId([arg; 32]))
                    };
                }
                if let Some(r) = sign_head_cached(body) {
                    if (x >> 6) & 3 == 2 && arg & 4 != 0 {
                        g.withheld.push(bytes);
                    } else {
                        g.lists.push(bytes);
                    }
                    if !fork {
                        g.heads.insert(rec.hash, (r.body().seq, r.id()));
                    }
                    g.recs.push(r);
                }
                continue;
            }
            10 => {
                let Some(&(seq, id)) = g.heads.get(&by.hash) else { continue };
                let mut keep: Vec<RecordId> = g
                    .recs
                    .iter()
                    .filter(|r| r.body().signer == by.hash && r.body().seq < seq && (r.id().0[0] ^ x) % 2 == 0)
                    .map(Record::id)
                    .collect();
                if x & 0x80 != 0 && big {
                    // A large checkpoint (a first checkpoint over 64 KiB):
                    // IDs nobody holds, about 2100 to 2600 of them.
                    let more = 2100 + usize::from(arg) * 2;
                    keep.extend(
                        (0..more).map(|i| RecordId(cbb_core::certs::sha256(&[(i >> 8) as u8, i as u8, arg, n as u8]))),
                    );
                }
                keep.sort();
                keep.dedup();
                Kind::Checkpoint { heads: vec![Head { key: by.hash, seq, id }], keep }
            }
            11 => Kind::Copies { incoming_ms: MIN_INCOMING_MS + u64::from(x) * 1000, seen: g.seen(arg) },
            12 => {
                let mut v = vec![dev.key.device_id()];
                if x & 1 == 1 {
                    v.push(any_key.key.device_id());
                }
                v.sort();
                v.dedup();
                Kind::Hubs { hubs: v, seen: if x & 2 == 0 { g.seen(arg) } else { vec![] } }
            }
            13 => {
                // The recovery key signing something other than a head.
                let rec = &ks[RECOVERY];
                let body = g.body(rec, Kind::Copies { incoming_ms: MIN_INCOMING_MS, seen: vec![] }, time);
                if let Ok(r) = Record::sign(body, rec) {
                    g.recs.push(r);
                }
                continue;
            }
            14 => {
                // A second record at one seq by a key that is not the
                // recovery key.
                let Some(&(seq, _)) = g.heads.get(&by.hash) else { continue };
                let mut body =
                    g.body(by, Kind::Copies { incoming_ms: MIN_INCOMING_MS + u64::from(x), seen: vec![] }, time);
                body.seq = seq;
                body.prev =
                    g.recs.iter().find(|r| r.body().signer == by.hash && r.body().seq + 1 == seq).map(|r| r.id());
                if let Ok(r) = Record::sign(body, by) {
                    g.recs.push(r);
                }
                continue;
            }
            15 if x & 1 == 1 && heads_made(&g) < MAX_HEADS => {
                // An honest change of root by the core's writer: the new
                // root's first records, its first checkpoint, then the head
                // and its list.
                let ks2 = keys();
                let new_root = &ks2[7 + usize::from(arg % 2)];
                let mut set = RecordSet::new(ks2[0].key.clone(), recov());
                for _ in 0..3 {
                    set.insert_all(g.recs.clone());
                    for l in &g.lists {
                        let _ = set.insert_list(l);
                    }
                }
                let st = set.state();
                let remove: Vec<KeyHash> = if x & 2 != 0 { vec![dev.hash] } else { vec![] };
                let mut d = Device::new(ks2[4 + usize::from(arg % 3)].key.clone(), "new root phone", ROLE_PHONE);
                d.rights = RIGHT_READ | RIGHT_SEND;
                let Ok(w) = set.write_change(&st, &ks2[RECOVERY], k2(), new_root, d, &remove, x & 4 != 0, time) else {
                    continue;
                };
                for r in w.first {
                    g.heads.insert(r.body().signer, (r.body().seq, r.id()));
                    g.recs.push(r);
                }
                g.lists.push(w.list.encode());
                g.heads.insert(w.record.body().signer, (w.record.body().seq, w.record.id()));
                g.recs.push(w.record);
                continue;
            }
            _ => {
                let mut s = Settings::default();
                s.shared = x & 2 != 0;
                Kind::Settings(Box::new(s))
            }
        };
        let body = g.body(by, kind, time);
        if body.check().is_err() {
            continue;
        }
        if let Ok(r) = Record::sign(body, by) {
            g.heads.insert(r.body().signer, (r.body().seq, r.id()));
            g.recs.push(r);
        }
    }
    (g, cfg)
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

/// The records and lists in an order: as made with each list after its
/// head, or shuffled with the lists anywhere.
pub fn order(g: &G, seed: u64) -> Vec<Item> {
    let mut items: Vec<Item> = Vec::new();
    let mut li = g.lists.iter();
    for r in &g.recs {
        items.push(Item::Rec(r.clone()));
        if matches!(r.body().kind, Kind::Recovery { .. }) {
            // The lists come in the order of their heads, except withheld.
            if let Kind::Recovery { list, .. } = &r.body().kind {
                if let Some(b) = g.lists.iter().find(|b| list_hash(b) == *list) {
                    items.push(Item::List(b.clone()));
                }
            }
        }
    }
    let _ = li.next();
    if seed != 0 {
        let mut rng = Rng(seed);
        for i in (1..items.len()).rev() {
            let j = (rng.next() % (i as u64 + 1)) as usize;
            items.swap(i, j);
        }
    }
    items
}

/// Fills a set as a member does: rounds of sync until one changes nothing.
pub fn fill(items: &[Item], every: usize) -> RecordSet {
    let ks = keys();
    let mut m = RecordSet::new(ks[0].key.clone(), recov());
    let mut last = None;
    for _ in 0..12 {
        let now = (m.digest(), m.lists().count());
        if last.as_ref() == Some(&now) {
            break;
        }
        last = Some(now);
        for (i, it) in items.iter().enumerate() {
            match it {
                Item::Rec(r) => {
                    let _ = m.insert(r.clone());
                }
                Item::List(b) => {
                    let _ = m.insert_list(b);
                }
            }
            if (i + 1) % every == 0 {
                let st = m.state();
                drop(st);
            }
        }
        for _ in 0..2 {
            let st = m.state();
            drop(st);
        }
    }
    m
}
