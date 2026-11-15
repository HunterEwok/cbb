// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Full groups whose rooms are squeezed: the root and 16 admin keys fill
//! their rooms, then 0..=16 keys made admin and unmade fill theirs; then
//! records the input picks (take-backs, removals of admins by the root or
//! by an admin, new admin keys past the 16th filling their rooms, honest
//! root checkpoints, re-admissions, more wide removals, plain devices).
//! Checks (architecture's P1-P5, 2026-11-14): what a member holds is a
//! fixed point; a live set and its restart answer alike and end equal; two
//! members built in other orders or batchings, syncing what they hold, end
//! equal in bounded rounds, and so do three syncing pairwise; before sync
//! only second-tier keys' records differ; one batch in two orders is one
//! batch; one offer of everything on an empty set equals a second offer.

#![no_main]
use std::collections::{BTreeMap, HashMap};
use std::sync::{Mutex, OnceLock};

use cbb_core::identity::ExternalKey;
use cbb_core::records::body::*;
use cbb_core::records::key::group_id;
use cbb_core::records::{Body, Key, KeyHash, Kind, Record, RecordId, RecordSet};
use libfuzzer_sys::fuzz_target;
#[path = "drop_oracle.rs"]
mod drop_oracle;

/// W counters (655fcdac), FZ_STATS=1: acks written, checkpoints that let a
/// removal go (settles), of those after an ack in the same input, and
/// take-backs for Silence, for a freeze (Frozen) and by the person's choice.
mod w {
    use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
    pub static ACKS: AtomicU64 = AtomicU64::new(0);
    pub static SETTLES: AtomicU64 = AtomicU64::new(0);
    pub static SETTLES_AFTER_ACK: AtomicU64 = AtomicU64::new(0);
    pub static FROZEN: AtomicU64 = AtomicU64::new(0);
    pub static PERSON: AtomicU64 = AtomicU64::new(0);
    pub static SILENCE: AtomicU64 = AtomicU64::new(0);
    pub static CPS: AtomicU64 = AtomicU64::new(0);
    pub static RUNS: AtomicU64 = AtomicU64::new(0);
    pub fn print() {
        let r = RUNS.fetch_add(1, Relaxed) + 1;
        if std::env::var_os("FZ_STATS").is_some() && (r % 20 == 0 || std::env::var_os("FZ_TRACE").is_some()) {
            eprintln!(
                "WSTATS runs={r} checkpoints={} acks={} settles={} settles_after_ack={} takeback_silence={} takeback_frozen={} takeback_person={}",
                CPS.load(Relaxed), ACKS.load(Relaxed), SETTLES.load(Relaxed), SETTLES_AFTER_ACK.load(Relaxed), SILENCE.load(Relaxed), FROZEN.load(Relaxed), PERSON.load(Relaxed)
            );
        }
    }
    pub fn bump(c: &AtomicU64) {
        c.fetch_add(1, Relaxed);
    }
}

/// Counting removal records of a state.
fn counting_removals(m: &RecordSet) -> usize {
    let st = m.state();
    m.in_dependency_order().iter().filter(|r| matches!(r.body().kind, Kind::Revoke(_)) && st.counting.contains(&r.id())).count()
}

/// Every live admin whose ack is due writes one, honestly (write_ack).
fn ack_all(signer: &mut RecordSet, g: &mut G, names: &[String], made: &mut Vec<Record>) -> bool {
    let mut any = false;
    for name in names {
        let ak = k(&format!("{name} key"));
        let st = signer.state();
        if !signer.ack_due(&st, &ak.hash) {
            continue;
        }
        if let Ok(r) = signer.write_ack(&st, ak, g.t + 1) {
            g.heads.insert(ak.hash, (r.body().seq, r.id()));
            g.t += 1000;
            let _ = signer.insert(r.clone());
            made.push(r);
            w::bump(&w::ACKS);
            any = true;
        }
    }
    any
}

/// The honest root's checkpoint, counting a settle when it lets a removal go.
fn honest_checkpoint(signer: &mut RecordSet, g: &mut G, root: &K, acked: bool, made: &mut Vec<Record>) {
    let before = counting_removals(signer);
    let st = signer.state();
    if let Ok(cp) = signer.write_checkpoint(&st, root, g.t + 1) {
        g.heads.insert(root.hash, (cp.body().seq, cp.id()));
        g.t += 1000;
        let _ = signer.insert(cp.clone());
        w::bump(&w::CPS);
        if trace() {
            let st2 = signer.state();
            eprintln!("WCP before {before} after {} counting cp {} admins {} unack {:?}", counting_removals(signer), st2.checkpoints.contains(&cp.id()), st2.devices.iter().filter(|d| d.admin.is_some()).count(), signer.unacknowledged(&st).values().sum::<usize>());
        }
        if counting_removals(signer) < before {
            w::bump(&w::SETTLES);
            if acked {
                w::bump(&w::SETTLES_AFTER_ACK);
            }
        }
        made.push(cp);
    }
}
use p256::ecdsa::signature::hazmat::PrehashSigner as _;
use p256::ecdsa::SigningKey;

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

fn mk(name: &str) -> K {
    let sk = SigningKey::from_slice(&cbb_core::certs::sha256(name.as_bytes())).unwrap();
    let key = Key::es256(sk.verifying_key().to_sec1_point(false).as_bytes().to_vec());
    let hash = key.hash();
    K { sk, key, hash }
}

/// Keys by name, made once per process.
fn k(name: &str) -> &'static K {
    static C: OnceLock<Mutex<HashMap<String, &'static K>>> = OnceLock::new();
    let c = C.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(x) = c.lock().unwrap().get(name) {
        return x;
    }
    let x: &'static K = Box::leak(Box::new(mk(name)));
    c.lock().unwrap().insert(name.to_string(), x);
    x
}

fn recovery() -> cbb_core::records::Recovery {
    static PQ: OnceLock<Key> = OnceLock::new();
    let k2 = PQ
        .get_or_init(|| cbb_core::records::pq::PqKey::from_seeds(&[0x31; 16], &[0x32; 16], &[0x33; 16]).key())
        .clone();
    cbb_core::records::Recovery { k1: k("recovery").key.clone(), k2 }
}

#[derive(Clone)]
struct G {
    gid: cbb_core::records::GroupId,
    heads: BTreeMap<KeyHash, (u64, RecordId)>,
    t: u64,
}

impl G {
    fn sign(&mut self, by: &K, kind: Kind) -> Record {
        let (seq, prev) = self.heads.get(&by.hash).map_or((1, None), |(s, id)| (s + 1, Some(*id)));
        self.t += 1000;
        let body = Body { group: self.gid, signer: by.hash, seq, prev, time_ms: self.t, kind, held: false };
        let r = Record::sign(body, by).unwrap();
        self.heads.insert(by.hash, (seq, r.id()));
        r
    }
}

/// A removal of 256 keys nobody has: 8 KiB, 16 units.
fn wide_removal(g: &mut G, by: &K, tag: &str, n: u32) -> Record {
    let mut keys: Vec<KeyHash> = (0..256u32)
        .map(|i| KeyHash(cbb_core::certs::sha256(&[tag.as_bytes(), &n.to_le_bytes()[..], &i.to_le_bytes()[..]].concat())))
        .collect();
    keys.sort();
    g.sign(by, Kind::Revoke(Removal { keys, seen: Vec::new() }))
}

fn admin_device(name: &str, powers: u64) -> Device {
    let mut d = Device::new(k(&format!("{name} phone")).key.clone(), "admin", ROLE_PHONE);
    d.rights = RIGHT_READ | RIGHT_SEND;
    d.admin = Some(k(&format!("{name} key")).key.clone());
    d.powers = powers;
    d
}

const ALL_POWERS: u64 = 0x1ff & !64;

/// The base group for `ex` keys made and unmade, in signing order, the
/// signer's heads after it, and a set that took it in one offer.
struct Base {
    recs: Vec<Record>,
    g: G,
    set: RecordSet,
    /// Names of the admin keys it made: 16 live, then the ex-admins.
    names: Vec<String>,
}

fn base(ex: u8) -> &'static Base {
    static C: OnceLock<Mutex<HashMap<u8, &'static Base>>> = OnceLock::new();
    let c = C.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(b) = c.lock().unwrap().get(&ex) {
        return b;
    }
    let root = k("root");
    let mut g = G { gid: group_id(&root.key, &recovery()), heads: BTreeMap::new(), t: 0 };
    let mut recs = Vec::new();
    let mut names = Vec::new();
    for a in 0..16u32 {
        let name = format!("admin {a}");
        // Admin key 1 cannot remove admins; admin key 0 keeps its room
        // empty, so that it can still remove.
        let p = if a == 1 { ALL_POWERS & !POWER_REMOVE_ADMINS } else { ALL_POWERS };
        recs.push(g.sign(root, Kind::device(admin_device(&name, p))));
        names.push(name);
    }
    for a in 1..16u32 {
        let ak = k(&format!("admin {a} key"));
        for n in 0..16u32 {
            recs.push(wide_removal(&mut g, ak, &format!("w {a}"), n));
        }
    }
    for n in 0..76u32 {
        recs.push(wide_removal(&mut g, root, "w root", n));
    }
    for e in 0..ex as u32 {
        let name = format!("ex admin {e}");
        recs.push(g.sign(root, Kind::device(admin_device(&name, ALL_POWERS))));
        let ak = k(&format!("{name} key"));
        for n in 0..16u32 {
            recs.push(wide_removal(&mut g, ak, &format!("w ex {e}"), n));
        }
        let ph = k(&format!("{name} phone"));
        recs.push(g.sign(root, Kind::device(Device::new(ph.key.clone(), "was admin", ROLE_PHONE))));
        names.push(name);
    }
    let mut set = RecordSet::new(root.key.clone(), recovery());
    set.insert_all(recs.clone());
    let b: &'static Base = Box::leak(Box::new(Base { recs, g, set, names }));
    c.lock().unwrap().insert(ex, b);
    b
}

fn xs(seed: &mut u64) -> u64 {
    *seed ^= *seed << 13;
    *seed ^= *seed >> 7;
    *seed ^= *seed << 17;
    *seed
}

fn shuffle<T>(v: &mut [T], seed: &mut u64) {
    for i in (1..v.len()).rev() {
        let j = (xs(seed) % (i as u64 + 1)) as usize;
        v.swap(i, j);
    }
}

type Seen = (Vec<RecordId>, [u8; 32], cbb_core::records::State);

fn seen(s: &RecordSet) -> Seen {
    let mut ids: Vec<RecordId> = s.ids().copied().collect();
    ids.sort();
    (ids, s.digest(), s.state())
}

fn differ(what: &str, a: &Seen, b: &Seen) {
    if a == b {
        return;
    }
    let only_a = a.0.iter().filter(|x| b.0.binary_search(x).is_err()).count();
    let only_b = b.0.iter().filter(|x| a.0.binary_search(x).is_err()).count();
    panic!(
        "order: {what}: {} held against {} ({only_a} only in the first, {only_b} only in the second), digest equal {}, state equal {}",
        a.0.len(),
        b.0.len(),
        a.1 == b.1,
        a.2 == b.2
    );
}

fn trace() -> bool {
    std::env::var("FZ_TRACE").is_ok()
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 3 {
        return;
    }
    let ex = if data[0] & 0x80 != 0 { (data[0] & 0x7f) % 17 } else { 7 + data[0] % 10 };
    let flags = data[1];
    let b = base(ex);
    let root = k("root");
    let mut g = b.g.clone();
    let mut names = b.names.clone();
    // The signer's own view, for honest checkpoints.
    let mut signer = b.set.clone();
    let mut tail: Vec<Record> = Vec::new();
    let tmk = std::time::Instant::now();
    let mut fresh = 0u32;
    let mut cps = 0;
    let mut acked = false;
    // Plain devices made in this input, which a removal may name (W
    // settles only removals of plain device keys).
    let mut devs: Vec<&'static K> = Vec::new();
    for (n, op) in data[2..].chunks(3).take(12).enumerate() {
        let (o, x, y) = (op[0], *op.get(1).unwrap_or(&0), *op.get(2).unwrap_or(&0));
        let pick = |i: u8, names: &Vec<String>| names[i as usize % names.len()].clone();
        let mut made = Vec::new();
        let mut late: Vec<Record> = Vec::new();
        match if o >= 0xe0 { 7 } else { o % 10 } {
            0 => {
                // The root takes an admin key back: its phone, no admin.
                let name = pick(x, &names);
                let ph = k(&format!("{name} phone"));
                made.push(g.sign(root, Kind::device(Device::new(ph.key.clone(), "was admin", ROLE_PHONE))));
            }
            1 => {
                // A new admin key past the 16th, filling (part of) its room.
                let name = format!("new admin {fresh}");
                fresh += 1;
                made.push(g.sign(root, Kind::device(admin_device(&name, ALL_POWERS))));
                let ak = k(&format!("{name} key"));
                for i in 0..(y % 17) as u32 {
                    made.push(wide_removal(&mut g, ak, &format!("w {name}"), i));
                }
                names.push(name);
            }
            2 => {
                let name = pick(x, &names);
                let keys = vec![k(&format!("{name} key")).hash];
                made.push(g.sign(root, Kind::Revoke(Removal { keys, seen: Vec::new() })));
            }
            3 => {
                let by = pick(x, &names);
                let who = pick(y, &names);
                let keys = vec![k(&format!("{who} key")).hash];
                made.push(g.sign(k(&format!("{by} key")), Kind::Revoke(Removal { keys, seen: Vec::new() })));
            }
            4 => {
                if cps < 2 {
                    cps += 1;
                    // W: half the time every admin acks honestly first.
                    if y & 1 == 0 {
                        acked |= ack_all(&mut signer, &mut g, &names, &mut made);
                    }
                    honest_checkpoint(&mut signer, &mut g, root, acked, &mut made);
                }
            }
            5 => {
                // Made admin again, on the same phone.
                let name = pick(x, &names);
                made.push(g.sign(root, Kind::device(admin_device(&name, ALL_POWERS))));
            }
            6 => {
                let by = pick(x, &names);
                let ak = k(&format!("{by} key"));
                for i in 0..(1 + y % 4) as u32 {
                    made.push(wide_removal(&mut g, ak, &format!("more {by} {n}"), i));
                }
            }
            8 => {
                // Down to 15 live admins, then a new one: the second tier's
                // caps fall to 0.
                let name = pick(x % 16, &names);
                let ph = k(&format!("{name} phone"));
                made.push(g.sign(root, Kind::device(Device::new(ph.key.clone(), "was admin", ROLE_PHONE))));
                let nn = format!("new admin {fresh}");
                fresh += 1;
                made.push(g.sign(root, Kind::device(admin_device(&nn, ALL_POWERS))));
                let ak = k(&format!("{nn} key"));
                for i in 0..(y % 17) as u32 {
                    made.push(wide_removal(&mut g, ak, &format!("w {nn}"), i));
                }
                names.push(nn);
            }
            9 => {
                // An admin's records signed while it was one, arriving after
                // the root took it back and wrote a checkpoint.
                if cps < 2 {
                    cps += 1;
                    let name = pick(x, &names);
                    let ak = k(&format!("{name} key"));
                    for i in 0..(1 + y % 4) as u32 {
                        late.push(wide_removal(&mut g, ak, &format!("late {name} {n}"), i));
                    }
                    let ph = k(&format!("{name} phone"));
                    let tb = g.sign(root, Kind::device(Device::new(ph.key.clone(), "was admin", ROLE_PHONE)));
                    let _ = signer.insert(tb.clone());
                    tail.push(tb);
                    if y & 0x80 == 0 {
                        acked |= ack_all(&mut signer, &mut g, &names, &mut made);
                    }
                    honest_checkpoint(&mut signer, &mut g, root, acked, &mut made);
                }
            }
            _ if o & 0xf0 == 0xe0 && !devs.is_empty() => {
                // A removal of a plain device: by the root (x even) or by a
                // live admin, then (y odd) every due admin acks.
                let dk = devs[x as usize % devs.len()];
                let keys = vec![dk.hash];
                let by: &K = if x & 1 == 0 { root } else { k(&format!("{} key", pick(y, &names))) };
                let r = g.sign(by, Kind::Revoke(Removal { keys, seen: Vec::new() }));
                let _ = signer.insert(r.clone());
                made.push(r);
                if y & 1 == 1 {
                    acked |= ack_all(&mut signer, &mut g, &names, &mut made);
                }
                // One root record after the removal, so that a checkpoint's
                // root head is above it and it may settle (`under`).
                if y & 2 == 0 {
                    let st = signer.state();
                    if let Ok(rs) = signer.write_record(&st, root, Kind::Copies { incoming_ms: g.t + 1, seen: Vec::new() }, g.t + 1) {
                        for r in rs {
                            g.heads.insert(r.body().signer, (r.body().seq, r.id()));
                            made.push(r);
                        }
                        g.t += 1000;
                    }
                }
            }
            _ if o & 0xf0 == 0xf0 => {
                // W ops: 0/1 every due admin acks (x picks which half
                // never does: the laggards); 2 the root freezes an admin
                // (x picks), then takes back the lagging (Frozen), or with
                // y odd takes back that admin by the person's choice;
                // 3 after 35 days of silence (Silence).
                match o & 3 {
                    0 | 1 => {
                        let some: Vec<String> = names.iter().enumerate().filter(|(i, _)| (x >> (i % 8)) & 1 == 1).map(|(_, n)| n.clone()).collect();
                        acked |= ack_all(&mut signer, &mut g, &some, &mut made);
                    }
                    op => {
                        if op == 3 {
                            g.t += cbb_core::records::set::ADMIN_SILENCE_MS + 1;
                        }
                        honest_checkpoint(&mut signer, &mut g, root, acked, &mut made);
                        if op == 2 && !names.is_empty() {
                            let ak = k(&format!("{} key", pick(x, &names)));
                            let st = signer.state();
                            if y & 1 == 1 {
                                if let Ok(r) = signer.take_back(&st, root, &ak.hash, g.t + 1) {
                                    g.heads.insert(root.hash, (r.body().seq, r.id()));
                                    g.t += 1000;
                                    let _ = signer.insert(r.clone());
                                    w::bump(&w::PERSON);
                                    made.push(r);
                                }
                            } else if is_live_admin(&st, &ak.hash) {
                                let r = g.sign(root, Kind::Freeze(Removal { keys: vec![ak.hash], seen: Vec::new() }));
                                let _ = signer.insert(r.clone());
                                made.push(r);
                            }
                        }
                        let st = signer.state();
                        let heard = std::collections::BTreeMap::new();
                        if let Ok(v) = signer.take_back_lagging(&st, root, &heard, g.t + 1) {
                            for (why, r) in v {
                                g.heads.insert(root.hash, (r.body().seq, r.id()));
                                g.t += 1000;
                                let _ = signer.insert(r.clone());
                                // By name, so the generator builds on heads with
                                // and without the automatic Frozen take-back.
                                match format!("{why:?}").as_str() {
                                    "Silence" => w::bump(&w::SILENCE),
                                    _ => w::bump(&w::FROZEN),
                                }
                                made.push(r);
                            }
                        }
                        honest_checkpoint(&mut signer, &mut g, root, acked, &mut made);
                    }
                }
            }
            _ => {
                let dk = k(&format!("dev {n} {x}"));
                devs.push(dk);
                made.push(g.sign(root, Kind::device(Device::new(dk.key.clone(), "dev", ROLE_MEMBER))));
            }
        }
        for r in made.into_iter().chain(late) {
            let _ = signer.insert(r.clone());
            tail.push(r);
        }
    }
    if tail.is_empty() {
        return;
    }
    if trace() {
        eprintln!("  making: {} ms", tmk.elapsed().as_millis());
    }
    let mut seed = 0x9e37_79b9_7f4a_7c15u64 ^ u64::from_le_bytes(cbb_core::certs::sha256(data)[..8].try_into().unwrap());
    if trace() {
        eprintln!("ex {ex}, {} base records, {} tail records, {} admin names", b.recs.len(), tail.len(), names.len());
    }
    let t0 = std::time::Instant::now();
    let tm = |w: &str| {
        if trace() {
            eprintln!("  {w}: {} ms", t0.elapsed().as_millis())
        }
    };
    if std::env::var_os("FZ_ONLY_P5A").is_some() {
        tier_one_never_squeezed(&b.set, &tail, &names);
        return;
    }
    let every: Vec<Record> = b.recs.iter().cloned().chain(tail.iter().cloned()).collect();

    // FZ_COST: per insert in signing order before and after the first
    // checkpoint, and a second offer of what is held; then stop.
    if std::env::var_os("FZ_COST").is_some() {
        let mut m = b.set.clone();
        let (mut pre, mut post) = (Vec::new(), Vec::new());
        let mut after = false;
        for r in &tail {
            let t = std::time::Instant::now();
            let cp = matches!(r.body().kind, Kind::Checkpoint { .. });
            let _ = m.insert(r.clone());
            let ms = t.elapsed().as_secs_f64() * 1000.0;
            if cp {
                eprintln!("COST checkpoint insert {ms:.1} ms");
                after = true;
            } else if after {
                post.push(ms);
            } else {
                pre.push(ms);
            }
        }
        let avg = |v: &Vec<f64>| if v.is_empty() { 0.0 } else { v.iter().sum::<f64>() / v.len() as f64 };
        let held: Vec<Record> = m.in_dependency_order().into_iter().cloned().collect();
        let n = held.len();
        let t = std::time::Instant::now();
        m.insert_all(held);
        eprintln!(
            "COST ex {ex}: per insert {:.1} ms ({} records) before a checkpoint, {:.1} ms ({}) after; second offer of {n} held {:.0} ms",
            avg(&pre), pre.len(), avg(&post), post.len(), t.elapsed().as_secs_f64() * 1000.0
        );
        return;
    }
    // Member A: the base, then the tail in one batch, signing order.
    let mut a = b.set.clone();
    a.insert_all(tail.clone());
    fixed(&a, "a");
    // The same batch in another order is the same batch.
    let mut perm = tail.clone();
    if flags & 0x20 != 0 {
        perm.rotate_left(1);
    } else {
        shuffle(&mut perm, &mut seed);
    }
    if flags & 1 != 0 {
        perm.reverse();
    }
    // B's order respects dependencies (a record after its signer's admission
    // and after its own prev), unless 0x10 asks for the free order, which has
    // its own check below.
    let free = flags & 0x10 != 0 || std::env::var_os("FZ_FREE_ORDER").is_some();
    if !free {
        perm = dependency_order(&perm, &tail);
    }
    {
        let mut a2 = b.set.clone();
        a2.insert_all(perm.clone());
        differ("one batch in two orders", &seen(&a), &seen(&a2));
    }
    // Member B: the tail in that other order, one record at a time (or in
    // batches of three).
    let mut bm = b.set.clone();
    let mut b_unknown: Vec<KeyHash> = Vec::new();
    if flags & 2 != 0 {
        for c in perm.chunks(3) {
            let (_, refused) = bm.insert_all(c.to_vec());
            for (id, why) in &refused {
                if format!("{why:?}").contains("UnknownSigner") {
                    if let Some(r) = c.iter().find(|r| r.id() == *id) {
                        if !b_unknown.contains(&r.body().signer) {
                            b_unknown.push(r.body().signer);
                        }
                    }
                }
            }
            fixed(&bm, "b, after a batch");
        }
    } else {
        let tb = std::env::var_os("FZ_TRACE_B").is_some();
        let tail_root_seqs: Vec<u64> = tail.iter().filter(|r| r.body().signer == root.hash).map(|r| r.body().seq).collect();
        let mut root_in: Vec<u64> = Vec::new();
        let mut bm_root_max: u64 = 0;
        let mut unknown: Vec<KeyHash> = Vec::new();
        for (i, r) in perm.iter().enumerate() {
            let before = bm.state();
            let got = bm.insert(r.clone());
            noroom_oracle(&before, &bm, r, &format!("{got:?}"), &mut unknown);
            // A key B met before its admission took effect: refused as
            // unknown, or (root chain with a gap, so the admission does not
            // count yet) answered NoRoom.
            let gs = format!("{got:?}");
            let root_gap = {
                let mut seqs: Vec<u64> = tail_root_seqs.clone();
                seqs.retain(|q| *q <= bm_root_max);
                seqs.iter().any(|q| !root_in.contains(q))
            };
            if r.body().signer == root.hash {
                root_in.push(r.body().seq);
                bm_root_max = bm_root_max.max(r.body().seq);
            }
            if (gs.contains("UnknownSigner") || (root_gap && gs.contains("NoRoom"))) && !b_unknown.contains(&r.body().signer) {
                b_unknown.push(r.body().signer);
            }
            if tb {
                let sg = r.body().signer;
                let who = names.iter().find(|n| k(&format!("{n} key")).hash == sg).cloned().unwrap_or_else(|| if sg == root.hash { "root".into() } else { "?".into() });
                let what = match &r.body().kind {
                    Kind::Device(d) => format!("device admin={}", d.admin.as_ref().map(|a| names.iter().find(|n| k(&format!("{n} key")).key == *a).cloned().unwrap_or("?".into())).unwrap_or("-".into())),
                    Kind::Revoke(rm) => format!("removal of {} keys", rm.keys.len()),
                    Kind::Checkpoint { .. } => "checkpoint".into(),
                    _ => "other".into(),
                };
                eprintln!("B {i}: {who} seq {} {what}: {}", r.body().seq, short(&format!("{got:?}")));
            }
        }
    }
    fixed(&bm, "b");
    tm("members a and b");
    // P2: live equals restored, in every answer.
    let mut probes: Vec<Record> = every.iter().filter(|r| !a.contains(&r.id())).take(3).cloned().collect();
    {
        // A record nobody had: one more wide removal by a key the input picks.
        let by = names[(flags as usize >> 2) % names.len()].clone();
        let mut g2 = g.clone();
        probes.push(wide_removal(&mut g2, k(&format!("{by} key")), "probe", 0));
    }
    for (m, w) in [(&a, "a"), (&bm, "b")] {
        restored_answers(m, &probes, w);
    }
    tm("restores");
    // P5: what only one of A and B holds is of second-tier keys only.
    // P6: with the same root records one member's end may still depend on
    // the order (whole records of unequal size), and that is counted; but
    // where the key's records are all of one size, or one member holds all
    // of them (so the key never passes its cap), a difference crashes.
    {
        let roots = |m: &RecordSet| -> Vec<RecordId> {
            let mut v: Vec<RecordId> = m.ids().filter(|id| m.get(id).is_some_and(|r| r.body().signer == root.hash)).copied().collect();
            v.sort();
            v
        };
        if free {
            free_order_only_unknown(&a, &bm, &b_unknown, &names);
        } else if roots(&a) == roots(&bm) {
            p6(&a, &bm, &every, &names, "same root records, two orders");
        }
        let mut again = a.clone();
        again.insert_all(every.clone());
        if roots(&again) == roots(&a) {
            p6(&a, &again, &every, &names, "a offered everything again");
        }
    }
    // P5c: a counter of counted removals one member lacks before sync.
    let lacked = lacks_counted(&a, &bm) + lacks_counted(&bm, &a);
    second_tier_only(&a, &bm, &names);
    // P3: A and B sync what they hold until nothing moves.
    let mut ms = vec![a, bm];
    let peer = live_peer(&ms, k("admin 0 phone").hash);
    let rounds = sync_pair(&mut ms, 0, 1, &peer, 12, "a and b");
    // P3 on heads without re-offer (a63d2788 on): one round makes them equal.
    if !free && rounds > 1 && std::env::var_os("FZ_P3_ANY_ROUNDS").is_none() {
        panic!("order: P3: a and b equal only after {rounds} rounds of sync, not one");
    }
    if free && rounds > 1 && std::env::var_os("FZ_FREE_WARN").is_none() {
        panic!("order: free order: a and b healed only after {rounds} rounds, not one exchange");
    }
    if free && std::env::var_os("FZ_FREE_WHY").is_some() && seen(&ms[0]) != seen(&ms[1]) {
        let only: Vec<Record> = ms[0].in_dependency_order().into_iter().filter(|r| !ms[1].contains(&r.id())).cloned().collect();
        let held_by = |m: &RecordSet, sg: &KeyHash| m.ids().filter(|id| m.get(id).is_some_and(|r| r.body().signer == *sg)).count();
        for r in &only {
            let sg = r.body().signer;
            let who = names.iter().find(|n| k(&format!("{n} key")).hash == sg).cloned().unwrap_or("?".into());
            let prev_in_b = r.body().prev.map(|p| ms[1].contains(&p));
            let mut t = ms[1].clone();
            let got = t.insert(r.clone());
            eprintln!("WHY a-only {who} seq {} kind {} units {}: b answers {} (prev held by b {:?}; key holds a {} b {})",
                r.body().seq, match &r.body().kind { Kind::Revoke(rm) => format!("removal of {}", rm.keys.len()), Kind::Device(_) => "device".into(), Kind::Checkpoint { .. } => "checkpoint".into(), _ => "other".into() },
                r.envelope().len(), short(&format!("{got:?}")), prev_in_b, held_by(&ms[0], &sg), held_by(&ms[1], &sg));
        }
        let mut t = ms[1].clone();
        let (n, refused) = t.insert_all(only.clone());
        eprintln!("WHY batch of all {} a-only into b: {n} added, refused {:?}", only.len(), refused.iter().map(|(_, w)| short(&format!("{w:?}"))).collect::<Vec<_>>());
        eprintln!("WHY b state equal after batch {}", seen(&t) == seen(&ms[0]));
        for (i, m) in ms.iter().enumerate() {
            let st = m.state();
            let fp = m.for_peer(&st, &peer);
            eprintln!("WHY member {i}: peer removed {} peer a device {} for_peer gives {} of {} held, a-only among them {}",
                st.revoked.contains(&peer), st.device_by_key(&peer).is_some(), fp.len(), m.ids().count(),
                fp.iter().filter(|r| only.iter().any(|o| o.id() == r.id())).count());
        }
    }
    differ("a and b after sync", &seen(&ms[0]), &seen(&ms[1]));
    // P5b: each holds every counting removal, resolve and checkpoint of the other.
    holds_counted(&ms[0], &ms[1], "a after sync");
    holds_counted(&ms[1], &ms[0], "b after sync");
    note_rounds(rounds);
    for (i, m) in ms.iter().enumerate() {
        drop_oracle::drop_oracle(m, &m.state(), if i == 0 { "a" } else { "b" });
    }
    w::print();
    if lacked > 0 && (trace() || std::env::var_os("FZ_STATS").is_some()) {
        eprintln!("P5C lacked {lacked} healed in {rounds} rounds");
    }
    // P5a: signing order one at a time; no record of the root or of a live
    // admin is ever dropped, except by a counting checkpoint's pruning.
    if flags & 0x80 == 0 {
        tier_one_never_squeezed(&b.set, &tail, &names);
        tm("tier one");
    }
    tm("sync of two");
    // P4: three members, pairwise sync in an order the input picks.
    if flags & 0x40 != 0 {
        let mut c = b.set.clone();
        let mut rev = tail.clone();
        rev.reverse();
        for ch in rev.chunks(2) {
            c.insert_all(ch.to_vec());
        }
        // Members 0 and 1 are equal already; give 1 a fresh start so the
        // three differ: the base and the tail one at a time, reversed.
        let mut d = b.set.clone();
        for r in &rev {
            let _ = d.insert(r.clone());
        }
        ms[1] = d;
        ms.push(c);
        let peer = live_peer(&ms, peer);
        let mut steps = 0;
        loop {
            let mut moved = false;
            let mut pairs = [(0usize, 1usize), (1, 2), (0, 2)];
            shuffle(&mut pairs, &mut seed);
            for (i, j) in pairs {
                if sync_pair(&mut ms, i, j, &peer, 1, "three") > 0 {
                    moved = true;
                }
            }
            steps += 1;
            if !moved {
                break;
            }
            assert!(steps <= 12, "order: three members still exchange after {steps} passes");
        }
        differ("three members after sync, 0 and 1", &seen(&ms[0]), &seen(&ms[1]));
        differ("three members after sync, 0 and 2", &seen(&ms[0]), &seen(&ms[2]));
        note_rounds(steps);
        tm("sync of three");
    }
    // One offer of everything on an empty set equals a second offer of the
    // same batch.
    if flags & 0x0c == 0x0c {
        let mut v = every;
        shuffle(&mut v, &mut seed);
        let mut f = RecordSet::new(root.key.clone(), recovery());
        f.insert_all(v.clone());
        let s1 = seen(&f);
        f.insert_all(v);
        differ("one offer of everything against a second offer of it", &s1, &seen(&f));
        fixed(&f, "fresh");
        tm("fresh");
    }
});

/// P6: classifies each record only one of x and y holds by its signer.
fn p6(x: &RecordSet, y: &RecordSet, every: &[Record], names: &[String], w: &str) {
    let (sx, sy) = (seen(x), seen(y));
    if sx == sy {
        return;
    }
    let mut keys: Vec<KeyHash> = Vec::new();
    for (m, o) in [(x, y), (y, x)] {
        for id in m.ids() {
            if !o.contains(id) {
                let sg = m.get(id).unwrap().body().signer;
                if !keys.contains(&sg) {
                    keys.push(sg);
                }
            }
        }
    }
    let mut counted = 0;
    for sg in &keys {
        let mine: Vec<&Record> = every.iter().filter(|r| r.body().signer == *sg).collect();
        let one_size = mine.windows(2).all(|p| p[0].envelope().len() == p[1].envelope().len());
        let all_in = |m: &RecordSet| mine.iter().all(|r| m.contains(&r.id()));
        let fits = all_in(x) || all_in(y);
        let who = names.iter().find(|n| k(&format!("{n} key")).hash == *sg).cloned().unwrap_or_else(|| if *sg == k("root").hash { "root".into() } else { "?".into() });
        let hx = mine.iter().filter(|r| x.contains(&r.id())).count();
        let hy = mine.iter().filter(|r| y.contains(&r.id())).count();
        if one_size || fits {
            if std::env::var_os("FZ_P6_WARN_ALL").is_some() {
                eprintln!("P6 (i) {w}: {who}: {hx} against {hy} of {} (one size {one_size}, all in one {fits})", mine.len());
                continue;
            }
            panic!("order: P6 (i) {w}: {who}: {hx} against {hy} of its {} records (all of one size {one_size}, all held by one {fits})", mine.len());
        }
        counted += 1;
        if trace() || std::env::var_os("FZ_STATS").is_some() {
            eprintln!("P6 (ii) {w}: {who}: {hx} against {hy} of {}", mine.len());
        }
    }
    let _ = counted;
}

/// P1: offering a member exactly what it holds changes nothing.
fn fixed(m: &RecordSet, w: &str) {
    let mut c = m.clone();
    let held: Vec<Record> = m.in_dependency_order().into_iter().cloned().collect();
    c.insert_all(held);
    let ls: Vec<Vec<u8>> = m.lists().map(<[u8]>::to_vec).collect();
    for l in &ls {
        let _ = c.insert_list(l);
    }
    differ(&format!("{w}: offered what it holds"), &seen(m), &seen(&c));
}

/// P2: a live set and its restart give the same answers and end equal.
fn restored_answers(m: &RecordSet, probes: &[Record], w: &str) {
    let held: Vec<Record> = m.in_dependency_order().into_iter().cloned().collect();
    let ls: Vec<Vec<u8>> = m.lists().map(<[u8]>::to_vec).collect();
    let back = RecordSet::restore(m.root().clone(), m.recovery().clone(), &held, &ls);
    differ(&format!("{w}: restored against live"), &seen(m), &seen(&back));
    for (i, r) in probes.iter().enumerate() {
        let (mut l, mut rb) = (m.clone(), back.clone());
        let (x, y) = (format!("{:?}", l.insert(r.clone())), format!("{:?}", rb.insert(r.clone())));
        if x != y {
            panic!("order: {w}: probe {i}: live answers {} and restored {}", short(&x), short(&y));
        }
        differ(&format!("{w}: probe {i}: live and restored after it"), &seen(&l), &seen(&rb));
    }
}

fn short(s: &str) -> String {
    s.chars().take(80).collect()
}

fn is_live_admin(s: &cbb_core::records::State, h: &KeyHash) -> bool {
    s.devices.iter().any(|d| d.admin == Some(*h)) && !s.revoked.contains(h)
}

fn counted_kind(r: &Record) -> bool {
    matches!(r.body().kind, Kind::Revoke(_) | Kind::Resolve(_) | Kind::Checkpoint { .. })
}

/// How many of what counts in `other` (removals, resolves, checkpoints) `m` lacks.
fn lacks_counted(m: &RecordSet, other: &RecordSet) -> usize {
    let st = other.state();
    st.counting.iter().filter(|id| !m.contains(id) && other.get(id).is_some_and(counted_kind)).count()
}

fn holds_counted(m: &RecordSet, other: &RecordSet, w: &str) {
    let st = other.state();
    for id in &st.counting {
        if let Some(r) = other.get(id) {
            if counted_kind(r) && !m.contains(id) {
                panic!("order: {w}: lacks a counting record of the other, seq {} {:?}", r.body().seq, kind_name(r));
            }
        }
    }
}

fn kind_name(r: &Record) -> &'static str {
    match &r.body().kind {
        Kind::Revoke(_) => "removal",
        Kind::Resolve(_) => "resolve",
        Kind::Checkpoint { .. } => "checkpoint",
        Kind::Device(_) => "device",
        _ => "other",
    }
}

/// Whether a counting checkpoint covers the record (prunes it by design).
fn pruned_by_checkpoint(m: &RecordSet, st: &cbb_core::records::State, r: &Record) -> bool {
    st.counting.iter().filter_map(|id| m.get(id)).any(|c| match &c.body().kind {
        Kind::Checkpoint { heads, keep } => {
            heads.iter().any(|h| h.key == r.body().signer && h.seq >= r.body().seq) && !keep.contains(&r.id())
        }
        _ => false,
    })
}

/// P5a: the base, then the tail one record at a time in signing order.
/// Records of the root and of keys that are live admins when offered, and
/// taken then, stay
/// held while their signer is still root or a live admin, unless a counting
/// checkpoint prunes them. (A key taken back or removed later is second
/// tier and may be squeezed; FZ_P5A_STRICT counts that too.)
fn tier_one_never_squeezed(base: &RecordSet, tail: &[Record], names: &[String]) {
    let root = k("root").hash;
    let strict = std::env::var_os("FZ_P5A_STRICT").is_some();
    let mut m = base.clone();
    let mut unknown: Vec<KeyHash> = Vec::new();
    let mut pending: Vec<Record> = Vec::new();
    let st0 = m.state();
    let mut prot: Vec<Record> = m
        .in_dependency_order()
        .into_iter()
        .filter(|r| r.body().signer == root || is_live_admin(&st0, &r.body().signer))
        .filter(|r| st0.counting.contains(&r.id()))
        .cloned()
        .collect();
    for (i, r) in tail.iter().enumerate() {
        let st = m.state();
        let tier1 = r.body().signer == root || is_live_admin(&st, &r.body().signer);
        let got = m.insert(r.clone());
        noroom_oracle(&st, &m, r, &format!("{got:?}"), &mut unknown);
        // Refused at once (its own room full, say) is not a squeeze.
        let st = m.state();
        // Tier one is a record that counts: one stored above a gap that
        // never counted may go at a full room (architecture 01:49Z). A
        // record that counts only later joins when it does.
        if tier1 && m.contains(&r.id()) {
            pending.push(r.clone());
        }
        pending.retain(|q| {
            if st.counting.contains(&q.id()) {
                prot.push(q.clone());
                false
            } else {
                m.contains(&q.id())
            }
        });
        for p in &prot {
            if m.contains(&p.id()) {
                continue;
            }
            let sg = p.body().signer;
            if pruned_by_checkpoint(&m, &st, p) {
                continue;
            }
            if !strict && sg != root && !is_live_admin(&st, &sg) {
                continue;
            }
            let who = if sg == root {
                "root".to_string()
            } else {
                names.iter().find(|n| k(&format!("{n} key")).hash == sg).cloned().unwrap_or("?".into())
            };
            if let Some(dir) = std::env::var_os("FZ_DUMP") {
                use std::fmt::Write as _;
                let mut out = String::new();
                let hx = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
                let _ = writeln!(out, "# missing: {} seq {} {} id {}", who, p.body().seq, kind_name(p), hx(&p.id().0));
                let _ = writeln!(out, "# root {}", hx(&root.0));
                for n in names {
                    let _ = writeln!(out, "# admin {n} key {}", hx(&k(&format!("{n} key")).hash.0));
                }
                for (j, r) in base.in_dependency_order().into_iter().enumerate() {
                    let _ = writeln!(out, "base {j} {} seq {} {} {}", hx(&r.body().signer.0[..4]), r.body().seq, kind_name(r), hx(&r.envelope()));
                }
                for (j, r) in tail[..=i].iter().enumerate() {
                    let held = m.contains(&r.id());
                    let _ = writeln!(out, "tail {j} {} seq {} {} held={held} {}", hx(&r.body().signer.0[..4]), r.body().seq, kind_name(r), hx(&r.envelope()));
                }
                let _ = writeln!(out, "# state after: roots {:?}", st.roots.iter().map(|h| hx(&h.0[..4])).collect::<Vec<_>>());
                for d in &st.devices {
                    let _ = writeln!(out, "# device {:?} admin {:?} frozen {}", d.name, d.admin.map(|h| hx(&h.0[..4])), d.frozen);
                }
                let _ = writeln!(out, "# revoked {:?}", st.revoked.iter().map(|h| hx(&h.0[..4])).collect::<Vec<_>>());
                let _ = writeln!(out, "# held now {} records; counting {}", m.len(), st.counting.len());
                let _ = std::fs::write(std::path::Path::new(&dir).join("p5a-dump.txt"), out);
            }
            panic!(
                "order: tier one squeezed: after tail record {i}, {who} seq {} {} is not held (signer still root or a live admin: {})",
                p.body().seq,
                kind_name(p),
                sg == root || is_live_admin(&st, &sg)
            );
        }
    }
}

/// P5: records only one member holds are second-tier keys' records that
/// neither member counts as a removal, resolve, root record or checkpoint.
fn second_tier_only(a: &RecordSet, b: &RecordSet, names: &[String]) {
    let (sa, sb) = (a.state(), b.state());
    let root = k("root").hash;
    for (x, y, sx, w) in [(a, b, &sa, "a"), (b, a, &sb, "b")] {
        for id in x.ids() {
            if y.contains(id) {
                continue;
            }
            let r = x.get(id).unwrap();
            let bd = r.body();
            let who = if bd.signer == root {
                "root".to_string()
            } else {
                names.iter().find(|n| k(&format!("{n} key")).hash == bd.signer).cloned().unwrap_or("?".into())
            };
            let counts = sx.counting.contains(id);
            let kind = match &bd.kind {
                Kind::Revoke(_) => "removal",
                Kind::Resolve(_) => "resolve",
                Kind::Checkpoint { .. } => "checkpoint",
                Kind::Device(_) => "device",
                _ => "other",
            };
            let is_adm = |s: &cbb_core::records::State| s.devices.iter().any(|d| d.admin == Some(bd.signer)) && !s.revoked.contains(&bd.signer);
            let admin = is_adm(&sa) || is_adm(&sb);
            if bd.signer == root || admin || (counts && kind != "removal") {
                if std::env::var_os("FZ_P5_OLD").is_none() {
                    if !trace() { continue; }
                    eprintln!("P5: only {w} holds {who} seq {} {kind} (counted {counts}, signer an admin {admin})", bd.seq);
                    continue;
                }
                panic!("order: only {w} holds {who} seq {} {kind} (counted {counts}, signer an admin {admin})", bd.seq);
            }
            if counts && std::env::var_os("FZ_P5_STRICT").is_some() {
                panic!("order: only {w} holds {who} seq {} {kind}, counted", bd.seq);
            }
        }
    }
}

/// Syncs members i and j both ways, as peers do (for_peer and the lists),
/// until neither changes or `max` rounds: the rounds that moved something.
fn sync_pair(ms: &mut [RecordSet], i: usize, j: usize, peer: &KeyHash, max: u32, w: &str) -> u32 {
    let mut moved = 0;
    for round in 0.. {
        let before = (seen(&ms[i]), seen(&ms[j]));
        for (from, to) in [(i, j), (j, i)] {
            let st = ms[from].state();
            let recs: Vec<Record> = ms[from].for_peer(&st, peer).into_iter().cloned().collect();
            let ls: Vec<Vec<u8>> = ms[from].lists().map(<[u8]>::to_vec).collect();
            ms[to].insert_all(recs.clone());
            let mut new = false;
            for l in &ls {
                new |= ms[to].insert_list(l).unwrap_or(false);
            }
            if new {
                ms[to].insert_all(recs);
            }
        }
        if (seen(&ms[i]), seen(&ms[j])) == before {
            break;
        }
        moved += 1;
        if max > 1 && round + 1 >= max {
            panic!("order: {w}: still exchanging after {max} rounds of sync");
        }
        if max == 1 {
            break;
        }
    }
    moved
}

fn note_rounds(n: u32) {
    use std::sync::atomic::{AtomicU32, Ordering};
    static MAX: AtomicU32 = AtomicU32::new(0);
    if n > MAX.fetch_max(n, Ordering::Relaxed) || std::env::var_os("FZ_STATS").is_some() {
        eprintln!("ROUNDS {n} max {}", MAX.load(Ordering::Relaxed));
    }
}

/// A record of a live key (root or live admin) whose units fit its cap
/// never answers NoRoom (architecture, 2026-11-14 12:55Z). `unknown`: the
/// keys that got UnknownSigner earlier in this member's fill.
fn noroom_oracle(before: &cbb_core::records::State, m: &RecordSet, r: &Record, got: &str, unknown: &mut Vec<KeyHash>) {
    let sg = r.body().signer;
    if got.contains("UnknownSigner") {
        if !unknown.contains(&sg) {
            unknown.push(sg);
        }
        return;
    }
    if !got.contains("NoRoom") || std::env::var_os("FZ_NO_NOROOM").is_some() {
        return;
    }
    let root = before.roots.contains(&sg);
    let admin = before.devices.iter().any(|d| d.admin == Some(sg)) && !before.revoked.contains(&sg);
    if !root && !admin {
        return;
    }
    let cap: u64 = if root { 1536 } else { 256 };
    let held: u64 = m
        .ids()
        .filter_map(|id| m.get(id))
        .filter(|x| x.body().signer == sg)
        .map(|x| cbb_core::records::keep::units(x.envelope().len()))
        .sum();
    let mine = cbb_core::records::keep::units(r.envelope().len());
    if held + mine <= cap {
        let earlier = unknown.contains(&sg);
        let gap = r.body().prev.is_some_and(|p| !m.contains(&p));
        if std::env::var_os("FZ_NOROOM_STRICT").is_none() {
            if std::env::var_os("FZ_NOROOM_COUNT").is_none() && std::env::var_os("FZ_STATS").is_none() { return; }
            eprintln!("NOROOM live {} seq {} held {held} + {mine} <= {cap}, earlier UnknownSigner {earlier}, prev not held {gap}", if root { "root" } else { "admin" }, r.body().seq);
            return;
        }
        panic!("noroom: a live {}'s record (seq {}, {mine} units, key holds {held} of {cap}) answered NoRoom; earlier UnknownSigner of the key: {earlier}; its prev not held: {gap}", if root { "root" } else { "admin" }, r.body().seq);
    }
}

/// A random order of `perm` that respects dependencies: each record comes
/// after its own prev and after every tail record that admits its signer and
/// was signed before it (in `tail`, signing order). Ties go by `perm`.
fn dependency_order(perm: &[Record], tail: &[Record]) -> Vec<Record> {
    let pos = |r: &Record| tail.iter().position(|t| t.id() == r.id()).unwrap_or(usize::MAX);
    let deps: Vec<Vec<RecordId>> = perm
        .iter()
        .map(|r| {
            let b = r.body();
            let at = pos(r);
            let mut d: Vec<RecordId> = Vec::new();
            if let Some(p) = &b.prev {
                if tail.iter().any(|t| t.id() == *p) {
                    d.push(*p);
                }
            }
            for (i, t) in tail.iter().enumerate() {
                if i >= at {
                    break;
                }
                if let Kind::Device(dv) = &t.body().kind {
                    if dv.admin.as_ref().is_some_and(|a| a.hash() == b.signer) {
                        d.push(t.id());
                    }
                }
            }
            d
        })
        .collect();
    let mut placed: Vec<RecordId> = Vec::new();
    let mut out: Vec<Record> = Vec::new();
    let mut left: Vec<usize> = (0..perm.len()).collect();
    while !left.is_empty() {
        let k = left
            .iter()
            .position(|&i| deps[i].iter().all(|d| placed.contains(d)))
            .unwrap_or(0);
        let i = left.remove(k);
        placed.push(perm[i].id());
        out.push(perm[i].clone());
    }
    out
}

/// Free order: A (signing order) and B (any order) may differ only by
/// records of keys B met before their admission (UnknownSigner) and what
/// follows from them; one exchange heals it (checked at the sync).
fn free_order_only_unknown(a: &RecordSet, b: &RecordSet, unknown: &[KeyHash], names: &[String]) {
    let name = |sg: &KeyHash| names.iter().find(|n| k(&format!("{n} key")).hash == *sg).cloned().unwrap_or_else(|| if *sg == k("root").hash { "root".into() } else { "?".into() });
    // B may hold others of such a key instead (they fit where the refused did).
    let only_b: Vec<&RecordId> = b.ids().filter(|id| !a.contains(id) && !unknown.contains(&b.get(id).unwrap().body().signer)).collect();
    let bad_a: Vec<KeyHash> = a
        .ids()
        .filter(|id| !b.contains(id))
        .map(|id| a.get(id).unwrap().body().signer)
        .filter(|sg| !unknown.contains(sg))
        .collect();
    if only_b.is_empty() && bad_a.is_empty() {
        return;
    }
    let msg = format!(
        "order: free order: b holds {} records a lacks of keys never refused as unknown; a holds records b lacks of keys never refused as unknown: {:?}",
        only_b.len(),
        bad_a.iter().map(name).collect::<Vec<_>>()
    );
    if std::env::var_os("FZ_FREE_WARN").is_some() {
        eprintln!("FREE {msg}");
    } else {
        panic!("{msg}");
    }
}

/// The peer the members sync as: a device every member's state lists and
/// none has removed (a removed peer gets only the removals naming it, so a
/// sync through it would check nothing); `want` when it qualifies.
fn live_peer(ms: &[RecordSet], want: KeyHash) -> KeyHash {
    let states: Vec<_> = ms.iter().map(|m| m.state()).collect();
    let live = |h: &KeyHash| states.iter().all(|st| st.device_by_key(h).is_some() && !st.revoked.contains(h) && !st.halted());
    if live(&want) {
        return want;
    }
    let mut c: Vec<KeyHash> = states[0].devices.iter().map(|d| d.key.hash()).filter(|h| live(h)).collect();
    c.sort();
    match c.first() {
        Some(h) => {
            if trace() || std::env::var_os("FZ_STATS").is_some() {
                eprintln!("PEER the admin 0 phone is not a live device of every member; syncing as another");
            }
            *h
        }
        None => {
            eprintln!("PEER no device is live in every member; the sync checks little");
            want
        }
    }
}
