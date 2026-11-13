// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Random record sets signed with fixed test keys, changes of root by the
//! recovery key among them (rule 33): heads with honest, partial, foreign,
//! empty, unreadable and withheld lists, second heads at one seq, the new
//! roots' records, in any order with the lists; a set filled in two orders
//! with compactions agrees with evaluate, and members converge.

#![no_main]
use std::collections::BTreeMap;
use std::sync::OnceLock;

use cbb_core::identity::ExternalKey;
use cbb_core::records::body::*;
use cbb_core::records::key::group_id;
use cbb_core::records::keep;
use cbb_core::records::{evaluate, Body, Input, Key, KeyHash, Kind, Record, RecordId, RecordSet, State};
use p256::ecdsa::signature::hazmat::PrehashSigner as _;
use p256::ecdsa::SigningKey;

/// FZ_ONLY=<text>: only the checks whose message holds text fire (to
/// minimize one family of failures without sliding into another).
fn only(msg: &str) -> bool {
    std::env::var("FZ_ONLY").map_or(true, |o| msg.contains(&o))
}

macro_rules! aeq {
    ($a:expr, $b:expr, $($f:tt)+) => {{
        let msg = format!($($f)+);
        if only(&msg) {
            assert_eq!($a, $b, "{}", msg);
        }
    }};
}

struct K {
    sk: SigningKey,
    key: Key,
    hash: KeyHash,
}

impl ExternalKey for K {
    fn public(&self) -> Vec<u8> {
        self.key.public.clone()
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
    "root", "admin a", "admin b", "admin c", "phone a", "phone b", "phone c", "new root a", "new root b", "recovery",
    "dev 0", "dev 1", "dev 2", "dev 3", "dev 4", "dev 5", "dev 6", "dev 7",
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
enum Item {
    Rec(Record),
    List(Vec<u8>),
}

struct G {
    gid: cbb_core::records::GroupId,
    heads: BTreeMap<KeyHash, (u64, RecordId)>,
    recs: Vec<Record>,
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

fn build(data: &[u8]) -> (G, u8) {
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
                    1 => &ks[0],                         // the first root again
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
                let cp = g.recs.iter().rev().find(|r| {
                    r.body().signer == new_root.hash && matches!(r.body().kind, Kind::Checkpoint { .. })
                });
                let first = match (cp, arg >> 6) {
                    (Some(c), 0..=2) => c.id(),
                    (_, 3) | (None, 0) => RecordId(cbb_core::certs::sha256(&[arg, x, n as u8, 13])),
                    _ => g.recs.get(usize::from(x) % g.recs.len().max(1)).map_or(RecordId([7; 32]), Record::id),
                };
                let mut body = g.body(rec, Kind::Recovery { root: new_root.key.clone(), list: hash, from, first, signer2: k2().key().hash() }, time);
                if fork {
                    // A second head at the recovery key's last seq, its prev
                    // right or wrong.
                    body.seq -= 1;
                    body.prev = if arg & 2 == 0 {
                        g.recs.iter().find(|r| r.body().signer == rec.hash && r.body().seq + 1 == body.seq).map(|r| r.id())
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
                if x & 0x80 != 0 {
                    // A large checkpoint (a first checkpoint over 64 KiB):
                    // IDs nobody holds, about 2100 to 2600 of them.
                    let more = 2100 + usize::from(arg) * 2;
                    keep.extend((0..more).map(|i| RecordId(cbb_core::certs::sha256(&[(i >> 8) as u8, i as u8, arg, n as u8]))));
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
                let mut body = g.body(by, Kind::Copies { incoming_ms: MIN_INCOMING_MS + u64::from(x), seen: vec![] }, time);
                body.seq = seq;
                body.prev = g.recs.iter().find(|r| r.body().signer == by.hash && r.body().seq + 1 == seq).map(|r| r.id());
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
                let Ok(w) = set.write_change(&st, &ks2[RECOVERY], k2(), new_root, d, &remove, x & 4 != 0, time) else { continue };
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


fn name(h: &KeyHash) -> &'static str {
    keys().iter().position(|k| k.hash == *h).map_or("?", |i| NAMES[i])
}

fn short(id: &RecordId) -> String {
    id.0[..3].iter().map(|b| format!("{b:02x}")).collect()
}

fn describe(r: &Record) -> String {
    let b = r.body();
    let k = match &b.kind {
        Kind::Device(d) => format!("device key={} role={} admin={:?} holds_root={}", name(&d.key.hash()), d.role, d.admin.as_ref().map(|a| name(&a.hash())), d.holds_root),
        Kind::Revoke(rm) => format!("revoke {:?} seen={}", rm.keys.iter().map(name).collect::<Vec<_>>(), rm.seen.len()),
        Kind::Freeze(rm) => format!("freeze {:?}", rm.keys.iter().map(name).collect::<Vec<_>>()),
        Kind::Recovery { root, list, from, first, .. } => format!("RECOVERY root={} list={} from={from} first={}", name(&root.hash()), list[..3].iter().map(|b| format!("{b:02x}")).collect::<String>(), short(first)),
        Kind::Checkpoint { heads, keep } => format!("checkpoint heads={:?} keep={:?}", heads.iter().map(|h| (name(&h.key), h.seq)).collect::<Vec<_>>(), keep.iter().map(short).collect::<Vec<_>>()),
        other => format!("type {}", other.type_number()),
    };
    format!("{} {}#{} prev={} {}", short(&r.id()), name(&b.signer), b.seq, b.prev.as_ref().map_or("-".into(), short), k)
}

fn trace_g(g: &G) {
    for r in &g.recs {
        eprintln!("REC {}", describe(r));
    }
    for l in &g.lists {
        let ids = List::decode(l).map(|l| l.0.iter().map(short).collect::<Vec<_>>());
        eprintln!("LIST {} {:?}", list_hash(l)[..3].iter().map(|b| format!("{b:02x}")).collect::<String>(), ids);
    }
    for l in &g.withheld {
        eprintln!("WITHHELD {}", list_hash(l)[..3].iter().map(|b| format!("{b:02x}")).collect::<String>());
    }
}

fn trace_set(m: &RecordSet, what: &str) {
    let st = m.state();
    eprintln!("SET {what}: kept {:?}", m.ids().map(short).collect::<Vec<_>>());
    eprintln!("SET {what}: roots {:?} counting {:?} stop {:?} chain {:?}", st.roots.iter().map(name).collect::<Vec<_>>(), st.counting.iter().map(short).collect::<Vec<_>>(), st.stop, st.chain().iter().map(short).collect::<Vec<_>>());
    eprintln!("SET {what}: devices {:?}", st.devices.iter().map(|d| (name(&d.key.hash()), d.role)).collect::<Vec<_>>());
}

fn trace_eval(st: &State, what: &str) {
    eprintln!("EVAL {what}: roots {:?} counting {:?} stop {:?}", st.roots.iter().map(name).collect::<Vec<_>>(), st.counting.iter().map(short).collect::<Vec<_>>(), st.stop);
    eprintln!("EVAL {what}: devices {:?}", st.devices.iter().map(|d| (name(&d.key.hash()), d.role)).collect::<Vec<_>>());
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
fn order(g: &G, seed: u64) -> Vec<Item> {
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
fn fill(items: &[Item], every: usize) -> RecordSet {
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

fn eval(recs: &[Record], lists: &[Vec<u8>]) -> State {
    let ks = keys();
    evaluate(&Input { root: &ks[0].key, recovery: &recov(), records: recs, lists })
}


/// Optional relaxations for debugging older heads, both off by default:
/// FZ_EARLY_LAX ignores a first_missing that only the set's aside explains;
/// FZ_IGNORED_LAX ignores records only a waiting head names in `ignored`.
fn mask_waiting(m: &RecordSet, got: &State, mut want: State) -> State {
    if std::env::var_os("FZ_IGNORED_LAX").is_none() {
        return want;
    }
    want.ignored.retain(|i| {
        got.ignored.contains(i)
            || m.get(&i.record).is_none_or(|r| {
                let s = r.body().signer;
                got.roots.contains(&s)
                    || !m.ids().filter_map(|id| m.get(id)).any(|h| matches!(&h.body().kind, cbb_core::records::Kind::Recovery { root, .. } if root.hash() == s))
            })
    });
    want
}

fn mask_early(got: &State, mut want: State) -> State {
    if std::env::var_os("FZ_EARLY_LAX").is_some() && got.first_missing.is_none() && want.first_missing.is_some() {
        want.first_missing = None;
    }
    want
}

fn check(m: &RecordSet, g: &G, what: &str) -> State {
    let kept: Vec<Record> = m.ids().map(|id| m.get(id).unwrap().clone()).collect();
    let held: Vec<Vec<u8>> = m.lists().map(<[u8]>::to_vec).collect();
    let st = m.state();
    let whole = eval(&g.recs, &g.lists);
    if std::env::var_os("FZ_TRACE").is_some() {
        trace_set(m, what);
        trace_eval(&eval(&kept, &held), &format!("{what} kept"));
        trace_eval(&whole, "all");
    }
    aeq!(st, mask_waiting(m, &st, mask_early(&st, eval(&kept, &held))), "{what}: set and evaluate of its records differ");
    // A saved set restored in one call is the same set.
    let ks = keys();
    let back = RecordSet::restore(ks[0].key.clone(), recov(), &kept, &held);
    aeq!(back.digest(), m.digest(), "{what}: a restored set keeps other records");
    aeq!(back.state(), st, "{what}: a restored set reads another state");
    aeq!(st.roots, whole.roots, "{what}: roots differ from evaluate of all records");
    aeq!(st.halted(), whole.halted(), "{what}: halted differs from evaluate of all records");
    // FZ_HALTED_LAX=1: in a halted group check only the halt, roots and
    // stop (a looser comparison for debugging).
    if whole.halted() && std::env::var_os("FZ_HALTED_LAX").is_some() {
        aeq!(st.stop, whole.stop, "{what}: stop differs from evaluate of all records");
        return st;
    }
    aeq!(st.devices, whole.devices, "{what}: devices differ from evaluate of all records");
    aeq!(st.revoked, whole.revoked, "{what}: revoked differ from evaluate of all records");
    aeq!(st.stop, whole.stop, "{what}: stop differs from evaluate of all records");
    aeq!(st.changes, whole.changes, "{what}: changes differ from evaluate of all records");
    st
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let (g, cfg) = build(data);
    if std::env::var_os("FZ_TRACE").is_some() {
        trace_g(&g);
    }
    if g.recs.is_empty() {
        return;
    }
    let every = 1 + usize::from(cfg & 7);
    let seed = u64::from_le_bytes(cbb_core::certs::sha256(data)[..8].try_into().unwrap()) | 1;
    let m1 = fill(&order(&g, 0), every);
    let m2 = fill(&order(&g, seed), every + 2);
    let s1 = check(&m1, &g, "m1");
    let s2 = check(&m2, &g, "m2");
    let lax = s1.halted() && std::env::var_os("FZ_HALTED_LAX").is_some();
    if !lax {
        aeq!(m1.digest(), m2.digest(), "two orders, two sets");
        aeq!(s1, s2, "two orders, two states");
    }
    // Two members that swap what they keep, by ids and by what each says
    // is missing, converge on one set, one state and one place aside.
    let (mut a, mut b) = (m1, m2);
    fn give(from: &RecordSet, to: &mut RecordSet) {
        let st = to.state();
        let mut want: Vec<RecordId> = from.ids().filter(|id| !to.contains(id)).copied().collect();
        want.extend(to.missing(&st));
        let recs: Vec<Record> = want.iter().filter_map(|id| from.get(id).cloned()).collect();
        to.insert_all(recs);
        let ls: Vec<Vec<u8>> = from.lists().map(<[u8]>::to_vec).collect();
        for l in &ls {
            let _ = to.insert_list(l);
        }
    }
    for _ in 0..6 {
        give(&a, &mut b);
        give(&b, &mut a);
    }
    let aside = |m: &RecordSet| -> Vec<RecordId> { m.aside().copied().collect() };
    let room = |m: &RecordSet| -> u64 { m.aside().filter_map(|id| m.get(id)).map(|r| keep::units(r.envelope().len())).sum() };
    for (m, w) in [(&a, "a"), (&b, "b")] {
        assert!(room(m) <= keep::ROOM, "{w}: the place aside holds more than one room");
    }
    aeq!(a.state().halted(), b.state().halted(), "two members that swapped: a halt in one is not in the other");
    if !lax {
        aeq!(a.digest(), b.digest(), "two members that swapped their records keep different sets");
        aeq!(a.state(), b.state(), "two members that swapped their records differ");
        aeq!(aside(&a), aside(&b), "two members that swapped hold different records aside");
    } else {
        aeq!(a.state().roots, b.state().roots, "halted: two members that swapped differ in roots");
    }
    // A member that takes from a ForkProof peer (insert_proof): from a set
    // holding only the proof, it stores nothing but the current root's
    // records and changes of root.
    let sa0 = a.state();
    if let Some((seq0, p, q)) = sa0.root_pair {
        let ks = keys();
        let mut pf = RecordSet::new(ks[0].key.clone(), recov());
        // What a ForkProof member first holds: the path of roots and the pair.
        let path: Vec<Record> = a.in_dependency_order().into_iter().filter(|r| matches!(r.body().kind, Kind::Recovery { .. })).cloned().collect();
        pf.insert_all(path);
        for l in a.lists().map(<[u8]>::to_vec).collect::<Vec<_>>() {
            let _ = pf.insert_list(&l);
        }
        for id in [p, q] {
            if let Some(r) = a.get(&id) {
                let _ = pf.insert(r.clone());
            }
        }
        let before = pf.state();
        let _ = &before;
        for r in &g.recs {
            let had = pf.contains(&r.id());
            let st0 = pf.state();
            // Roots a held change of root names (insert_proof's doc: the
            // records of a root a held recovery record names).
            let named = pf.in_dependency_order().iter().any(|h| {
                h.body().signer == ks[RECOVERY].hash
                    && matches!(&h.body().kind, Kind::Recovery { root, .. } if root.hash() == r.body().signer)
            });
            match pf.insert_proof(r.clone()) {
                Ok(cbb_core::records::set::Added::Stored) if !had => {
                    // The current root's records and changes of
                    // root (signed by the recovery key), nothing else.
                    let s = r.body().signer;
                    assert!(named || Some(&s) == st0.roots.last() || s == ks[RECOVERY].hash, "insert_proof stored a record of another signer");
                }
                _ => {}
            }
        }
        let _ = seq0;
    }
    for r in &g.recs {
        let again = Record::decode(&r.envelope()).expect("a signed record does not read");
        aeq!(&again, r, "a signed record reads another");
    }
    let sa = a.state();
    let _ = RecordSet::ignored(&sa);
    let _ = a.change_list(&sa);
    for kk in keys().iter().take(10) {
        let _ = a.for_peer(&sa, &kk.hash);
    }
    let _ = &g.withheld;
});
