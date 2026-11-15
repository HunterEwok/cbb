// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Changes of root on the final rules (L, B, S, the seen line): a small
//! group (a root, three admins, three devices), then ops the input picks:
//! admissions and removals by the current root and by admins, acks with
//! and without spares, honest checkpoints, changes of root by the honest
//! writer with a leave-out list, records of old admins after a change, a
//! second change at the same seq (a recovery fork) and plain filler.
//! Members: one takes everything in signing order, one in a shuffled order
//! in pairs, then they sync; one takes all from an unknown peer.
//! Oracles: the two members end equal; after a change nothing signed under
//! an old root counts (only the current root, the recovery key, keys the
//! current root's counting records name, and admins' records that count
//! through them); a re-issue names only devices that counted at the
//! writer; nothing removed or left out comes back; a recovery fork leaves
//! no device named; an unknown peer brings only recovery records and the
//! records of roots they name, at most two per seq and 64 in all.

#![no_main]
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Mutex, OnceLock};

use cbb_core::identity::ExternalKey;
use cbb_core::records::body::*;
use cbb_core::records::key::group_id;
use cbb_core::records::{Key, KeyHash, Kind, Record, RecordSet, State};
use libfuzzer_sys::fuzz_target;
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

fn k(name: &str) -> &'static K {
    static C: OnceLock<Mutex<HashMap<String, &'static K>>> = OnceLock::new();
    let c = C.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(x) = c.lock().unwrap().get(name) {
        return x;
    }
    let sk = SigningKey::from_slice(&cbb_core::certs::sha256(name.as_bytes())).unwrap();
    let key = Key::es256(sk.verifying_key().to_sec1_point(false).as_bytes().to_vec());
    let hash = key.hash();
    let x: &'static K = Box::leak(Box::new(K { sk, key, hash }));
    c.lock().unwrap().insert(name.to_string(), x);
    x
}

fn pq() -> &'static cbb_core::records::pq::PqKey {
    static PQ: OnceLock<cbb_core::records::pq::PqKey> = OnceLock::new();
    PQ.get_or_init(|| cbb_core::records::pq::PqKey::from_seeds(&[0x41; 16], &[0x42; 16], &[0x43; 16]))
}

fn recovery() -> cbb_core::records::Recovery {
    cbb_core::records::Recovery { k1: k("c recovery").key.clone(), k2: pq().key() }
}

fn phone(m: &K, name: &str) -> Device {
    let mut d = Device::new(m.key.clone(), name, ROLE_PHONE);
    d.rights = RIGHT_READ | RIGHT_SEND | RIGHT_SECRETS;
    d
}

const ALL_POWERS: u64 = 0x1ff & !64;

fn trace() -> bool {
    std::env::var_os("FZ_TRACE").is_some()
}

static STATS: OnceLock<Mutex<BTreeMap<&'static str, u64>>> = OnceLock::new();
fn bump(what: &'static str) {
    *STATS.get_or_init(|| Mutex::new(BTreeMap::new())).lock().unwrap().entry(what).or_default() += 1;
}
fn print_stats() {
    static RUNS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let r = RUNS.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
    if std::env::var_os("FZ_STATS").is_some() && (r % 50 == 0 || trace()) {
        let s = STATS.get_or_init(|| Mutex::new(BTreeMap::new())).lock().unwrap().clone();
        eprintln!("CSTATS runs={r} {s:?}");
    }
}

fn live_admins(st: &State) -> Vec<KeyHash> {
    st.devices.iter().filter(|d| !d.frozen).filter_map(|d| d.admin).filter(|a| !st.revoked.contains(a)).collect()
}

fn plain_devices(st: &State, except: &[KeyHash]) -> Vec<KeyHash> {
    st.devices.iter().filter(|d| d.admin.is_none() && !except.contains(&d.key.hash())).map(|d| d.key.hash()).collect()
}

struct World {
    w: RecordSet,
    all: Vec<Record>,
    /// Every key name made, so that ops find K by hash.
    by_hash: BTreeMap<KeyHash, &'static K>,
    root: &'static K,
    t: u64,
    n: u32,
    /// Keys removed or left out: they never come back.
    gone: BTreeSet<KeyHash>,
    /// The set as it was before the last change (for a fork).
    before_change: Option<RecordSet>,
    changes: u32,
    forked: bool,
    /// A change whose re-issue the writer has not taken (it holds the head).
    pending: Option<Pending>,
    /// Re-issue records of a waiting change, sent late (or never to some).
    late: Vec<Record>,
    /// Roots of waiting changes another change was written over.
    superseded: BTreeSet<KeyHash>,
    /// Per change (its new root): records signed before it by keys other
    /// than a root or the recovery key.
    pre_change: Vec<(KeyHash, BTreeSet<cbb_core::records::RecordId>)>,
    /// Every spare key each admin published.
    spares: BTreeMap<KeyHash, Vec<KeyHash>>,
    /// Old admin keys the new root named again.
    renamed: BTreeSet<KeyHash>,
    /// Old admin keys that signed after a change.
    old_signed: BTreeSet<KeyHash>,
}

struct Pending {
    first: Vec<Record>,
    root: KeyHash,
    gone: Vec<KeyHash>,
}

impl World {
    fn key(&mut self, name: &str) -> &'static K {
        let x = k(name);
        self.by_hash.insert(x.hash, x);
        x
    }
    fn take(&mut self, r: Record) {
        let _ = self.w.insert(r.clone());
        self.all.push(r);
    }
    fn tick(&mut self) -> u64 {
        self.t += 1000;
        self.t
    }
    fn write(&mut self, by: &'static K, kind: Kind) -> Option<Record> {
        let st = self.w.state();
        let t = self.tick();
        match self.w.write_record(&st, by, kind, t) {
            Ok(rs) => {
                // Every record the writer added (an admin's first ack, then the record).
                self.all.extend(rs.iter().cloned());
                rs.last().cloned()
            }
            Err(e) => {
                if trace() {
                    eprintln!("  write refused: {e}");
                }
                None
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let root = k("c root");
    let mut world = World {
        w: RecordSet::new(root.key.clone(), recovery()),
        all: Vec::new(),
        by_hash: BTreeMap::new(),
        root,
        t: 0,
        n: 0,
        gone: BTreeSet::new(),
        before_change: None,
        changes: 0,
        forked: false,
        pending: None,
        late: Vec::new(),
        superseded: BTreeSet::new(),
        pre_change: Vec::new(),
        spares: BTreeMap::new(),
        renamed: BTreeSet::new(),
        old_signed: BTreeSet::new(),
    };
    world.by_hash.insert(root.hash, root);
    let gid = group_id(&root.key, &recovery());
    let _ = gid;
    for i in 0..3 {
        let ak = world.key(&format!("c admin {i} key"));
        let ph = world.key(&format!("c admin {i} phone"));
        let mut d = phone(ph, "admin");
        d.admin = Some(ak.key.clone());
        d.powers = ALL_POWERS;
        world.write(root, Kind::device(d));
    }
    for i in 0..3 {
        let dk = world.key(&format!("c dev {i}"));
        world.write(root, Kind::device(Device::new(dk.key.clone(), "dev", ROLE_MEMBER)));
    }
    let flags = data[0];
    for op in data[1..].chunks(3).take(16) {
        let (o, x, y) = (op[0], *op.get(1).unwrap_or(&0), *op.get(2).unwrap_or(&0));
        world.n += 1;
        let n = world.n;
        let st = world.w.state();
        let Some(cur) = st.roots.last().copied() else { break };
        let Some(cur_k) = world.by_hash.get(&cur).copied() else { break };
        if trace() {
            let gone_live: Vec<&String> = st.devices.iter().filter(|d| world.gone.contains(&d.key.hash()) && !st.revoked.contains(&d.key.hash())).map(|d| &d.name).collect();
            eprintln!("op {n}: {o:02x} {x:02x} {y:02x}; devices {} revoked {} gone-live {:?}", st.devices.len(), st.revoked.len(), gone_live);
        }
        // While the writer holds a waiting change, it only writes the next
        // change over it or takes the late re-issue.
        if world.pending.is_some() && !matches!(o % 10, 5 | 9) {
            continue;
        }
        match o % 10 {
            0 => {
                let dk = world.key(&format!("c op dev {n}"));
                world.write(cur_k, Kind::device(Device::new(dk.key.clone(), "dev", ROLE_MEMBER)));
            }
            1 => {
                let devs = plain_devices(&st, &[]);
                if devs.is_empty() {
                    continue;
                }
                let d = devs[x as usize % devs.len()];
                let t = world.tick();
                if let Ok(rs) = world.w.write_removal(&st, cur_k, &[d], t) {
                    if !world.w.state().revoked.contains(&d) {
                        panic!("change: the current root's own removal does not count at its writer");
                    }
                    world.gone.insert(d);
                    world.all.extend(rs);
                    bump("removals");
                }
            }
            2 | 8 => {
                let admins = live_admins(&st);
                if admins.is_empty() {
                    continue;
                }
                let a = admins[x as usize % admins.len()];
                let Some(ak) = world.by_hash.get(&a).copied() else { continue };
                if o % 10 == 2 {
                    let dk = world.key(&format!("c adm dev {n}"));
                    if world.write(ak, Kind::device(Device::new(dk.key.clone(), "dev", ROLE_MEMBER))).is_some() {
                        bump("admin admissions");
                    }
                } else {
                    let devs = plain_devices(&st, &[]);
                    if devs.is_empty() {
                        continue;
                    }
                    let d = devs[y as usize % devs.len()];
                    if world.write(ak, Kind::Revoke(Removal { keys: vec![d], seen: Vec::new() })).is_some() {
                        if world.w.state().revoked.contains(&d) {
                            world.gone.insert(d);
                            bump("admin removals");
                        } else {
                            bump("admin removals not counting");
                        }
                    }
                }
            }
            3 => {
                for a in live_admins(&st) {
                    let Some(ak) = world.by_hash.get(&a).copied() else { continue };
                    let st = world.w.state();
                    let t = world.tick();
                    let got = if x & 1 == 1 {
                        let sp = world.key(&format!("c spare {n} {}", a.0[0]));
                        world.spares.entry(a).or_default().push(sp.hash);
                        world.w.write_ack_spare(&st, ak, &sp.key, t)
                    } else {
                        world.w.write_ack(&st, ak, t)
                    };
                    if let Ok(r) = got {
                        world.all.push(r);
                        bump(if x & 1 == 1 { "acks with spare" } else { "acks" });
                    }
                }
            }
            4 => {
                let t = world.tick();
                if x & 1 == 1 || world.w.checkpoint_due(&st, t) {
                    if let Ok(cp) = world.w.write_checkpoint(&st, cur_k, t) {
                        world.take(cp);
                        bump("checkpoints");
                    }
                }
            }
            5 | 7 => {
                if world.changes >= 2 {
                    continue;
                }
                let fork = o % 10 == 7;
                if fork && (world.before_change.is_none() || world.forked) {
                    continue;
                }
                let over = world.pending.is_some();
                let withhold = !fork && !over && y & 0x80 != 0;
                let mut leave: Vec<KeyHash> = Vec::new();
                if x & 1 == 1 {
                    let devs = plain_devices(&st, &[]);
                    if !devs.is_empty() {
                        leave.push(devs[y as usize % devs.len()]);
                    }
                }
                if x & 2 == 2 {
                    let admins = live_admins(&st);
                    if !admins.is_empty() {
                        leave.push(admins[(y >> 2) as usize % admins.len()]);
                    }
                }
                let nr = world.key(&format!("c new root {n}"));
                let nd = world.key(&format!("c new root phone {n}"));
                let mut writer = if fork { world.before_change.clone().unwrap() } else { world.w.clone() };
                let wst = writer.state();
                let preview = writer.change_preview(&wst, &leave);
                let counted: BTreeSet<KeyHash> = wst.devices.iter().map(|d| d.key.hash()).collect();
                // Spares that must not be named: an admin whose newest
                // counting ack carries no spare has withdrawn every one.
                let mut withdrawn: BTreeSet<KeyHash> = BTreeSet::new();
                if !over {
                    for a in live_admins(&wst) {
                        let newest = wst
                            .counting
                            .iter()
                            .filter_map(|id| writer.get(id))
                            .filter(|r| r.body().signer == a && matches!(r.body().kind, Kind::Ack { .. }))
                            .max_by_key(|r| r.body().seq);
                        if let Some(r) = newest {
                            if let Kind::Ack { spare: None, .. } = &r.body().kind {
                                withdrawn.extend(world.spares.get(&a).into_iter().flatten().copied());
                            }
                        }
                    }
                }
                let rec_h = k("c recovery").hash;
                let pre: BTreeSet<cbb_core::records::RecordId> = world
                    .all
                    .iter()
                    .filter(|r| !wst.roots.contains(&r.body().signer) && r.body().signer != rec_h)
                    .map(Record::id)
                    .collect();
                let t = world.tick();
                let got = if over {
                    writer.write_change_over_waiting(&wst, k("c recovery"), pq(), nr, phone(nd, "phone"), &leave, false, t)
                } else {
                    writer.write_change(&wst, k("c recovery"), pq(), nr, phone(nd, "phone"), &leave, false, t)
                };
                let Ok(wr) = got else {
                    if trace() {
                        eprintln!("  change refused (over {over}): {:?}", got.err());
                    }
                    continue;
                };
                // Oracle: a re-issue names only devices that counted at the writer.
                for r in &wr.first {
                    if let Kind::Device(d) = &r.body().kind {
                        if !d.holds_root && !counted.contains(&d.key.hash()) {
                            panic!("change: the re-issue names device {:?} that did not count at the writer", d.name);
                        }
                        if let Some(ad) = &d.admin {
                            if over && !d.holds_root {
                                panic!("change: a change over a waiting one names a spare or an admin key");
                            }
                            if withdrawn.contains(&ad.hash()) {
                                panic!("change: a spare is named although its admin's newest counting ack withdrew it");
                            }
                        }
                    }
                }
                let mut marks: Vec<KeyHash> = leave.clone();
                for p in &preview {
                    if p.outcome == cbb_core::records::set::Outcome::Out {
                        if let Some(d) = wst.devices.iter().find(|d| d.id == p.device) {
                            marks.push(d.key.hash());
                        }
                    }
                }
                world.pre_change.push((nr.hash, pre));
                let lists = vec![wr.list.encode()];
                world.changes += 1;
                if withhold {
                    // The writer holds the head and list, not the re-issue.
                    for _ in 0..2 {
                        let _ = world.w.insert_list(&lists[0]);
                        let _ = world.w.insert(wr.record.clone());
                    }
                    world.all.push(wr.record.clone());
                    world.lists_extra(lists);
                    world.pending = Some(Pending { first: wr.first.clone(), root: nr.hash, gone: marks });
                    world.before_change = None;
                    bump("withheld changes");
                    continue;
                }
                if over {
                    let p = world.pending.take().unwrap();
                    world.superseded.insert(p.root);
                    world.late.extend(p.first);
                    bump("changes over waiting");
                }
                world.gone.extend(marks);
                let mut recs = wr.first.clone();
                recs.insert(0, wr.record.clone());
                if !fork {
                    world.before_change = if over { None } else { Some(world.w.clone()) };
                }
                for _ in 0..2 {
                    for l in &lists {
                        let _ = world.w.insert_list(l);
                    }
                    world.w.insert_all(recs.clone());
                }
                world.all.extend(recs);
                world.lists_extra(lists);
                if fork {
                    world.forked = true;
                    bump("forks");
                } else if !over {
                    bump("changes");
                }
            }
            6 => {
                // An old admin signs after a change: refused or counts for nothing.
                if world.changes == 0 {
                    continue;
                }
                let old: Vec<KeyHash> = (0..3)
                    .map(|i| k(&format!("c admin {i} key")).hash)
                    .filter(|a| !live_admins(&st).contains(a) && !world.renamed.contains(a))
                    .collect();
                if y & 1 == 1 {
                    // The new root names an old admin key again.
                    let fresh: Vec<KeyHash> = old.iter().copied().filter(|a| !world.old_signed.contains(a)).collect();
                    if fresh.is_empty() {
                        continue;
                    }
                    let a = fresh[x as usize % fresh.len()];
                    let ak = world.by_hash[&a];
                    let ph = world.key(&format!("c renamed phone {n}"));
                    let mut d = phone(ph, "admin");
                    d.admin = Some(ak.key.clone());
                    d.powers = ALL_POWERS;
                    if world.write(cur_k, Kind::device(d)).is_some() {
                        world.renamed.insert(a);
                        bump("old admin named again");
                    }
                    continue;
                }
                if old.is_empty() {
                    continue;
                }
                let a = old[x as usize % old.len()];
                world.old_signed.insert(a);
                let ak = world.by_hash[&a];
                let (seq, prev) = world
                    .all
                    .iter()
                    .filter(|r| r.body().signer == a)
                    .map(|r| (r.body().seq, r.id()))
                    .max()
                    .map_or((1, None), |(s, id)| (s + 1, Some(id)));
                let dk = world.key(&format!("c old adm dev {n}"));
                let t = world.tick();
                let body = cbb_core::records::Body {
                    group: group_id(&root.key, &recovery()),
                    signer: a,
                    seq,
                    prev,
                    time_ms: t,
                    kind: Kind::device(Device::new(dk.key.clone(), "dev", ROLE_MEMBER)),
                    held: false,
                };
                let r = Record::sign(body, ak).unwrap();
                world.take(r);
                world.gone.insert(dk.hash);
                bump("old admin records");
            }
            9 if x & 1 == 1 && (world.pending.is_some() || !world.late.is_empty()) => {
                // The re-issue reaches the writer late.
                let (recs, marks) = match world.pending.take() {
                    Some(p) => (p.first, p.gone),
                    None => (std::mem::take(&mut world.late), Vec::new()),
                };
                let mut recs = recs;
                if x & 2 == 2 {
                    recs.reverse();
                }
                for _ in 0..2 {
                    world.w.insert_all(recs.clone());
                }
                world.gone.extend(marks);
                world.all.extend(recs);
                bump("late re-issue to the writer");
            }
            _ => {
                if world.pending.is_some() {
                    continue;
                }
                world.write(cur_k, Kind::Copies { incoming_ms: world.t + 1, seen: Vec::new() });
            }
        }
        // What the writer took besides what its calls returned (an admin's
        // first record writes its ack first, the seen line): it is sent too.
        let known: BTreeSet<cbb_core::records::RecordId> = world.all.iter().map(Record::id).collect();
        let extra: Vec<Record> = world.w.in_dependency_order().into_iter().filter(|r| !known.contains(&r.id())).cloned().collect();
        if !extra.is_empty() {
            bump("records the writer took unreturned");
            world.all.extend(extra);
        }
    }
    let lists: Vec<Vec<u8>> = world.w.lists().map(<[u8]>::to_vec).chain(LISTS.with(|l| l.borrow().clone())).collect();
    LISTS.with(|l| l.borrow_mut().clear());
    // A change still waiting at the end: its re-issue goes late to the
    // members that get the late records, and its leave-out holds there.
    let mut gone_late: BTreeSet<KeyHash> = world.gone.clone();
    if let Some(p) = world.pending.take() {
        world.late.extend(p.first);
        gone_late.extend(p.gone);
    }
    let late = world.late.clone();
    let all = world.all.clone();
    let full: Vec<Record> = all.iter().chain(late.iter()).cloned().collect();
    let fill = |m: &mut RecordSet, recs: &[Record]| {
        for _ in 0..2 {
            for l in &lists {
                let _ = m.insert_list(l);
            }
            m.insert_all(recs.to_vec());
        }
    };
    let mut a = RecordSet::new(root.key.clone(), recovery());
    fill(&mut a, &all);
    {
        let mut l = late.clone();
        if flags & 8 == 8 {
            l.reverse();
        }
        for r in l {
            let _ = a.insert(r);
        }
    }
    // Member c never gets the late re-issue.
    let mut c = RecordSet::new(root.key.clone(), recovery());
    fill(&mut c, &all);
    let mut perm = if flags & 4 == 4 { all.clone() } else { full.clone() };
    let mut s = u64::from_le_bytes(cbb_core::certs::sha256(data)[..8].try_into().unwrap()) | 1;
    for i in (1..perm.len()).rev() {
        s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        perm.swap(i, (s >> 33) as usize % (i + 1));
    }
    if flags & 1 == 1 {
        perm.reverse();
    }
    let mut b = RecordSet::new(root.key.clone(), recovery());
    for c in perm.chunks(2) {
        b.insert_all(c.to_vec());
        if flags & 2 == 2 {
            for l in &lists {
                let _ = b.insert_list(l);
            }
        }
    }
    for l in &lists {
        let _ = b.insert_list(l);
    }
    // Sync both ways until nothing moves.
    for round in 0..6 {
        let ha: Vec<Record> = a.in_dependency_order().into_iter().cloned().collect();
        let hb: Vec<Record> = b.in_dependency_order().into_iter().cloned().collect();
        let la: Vec<Vec<u8>> = a.lists().map(<[u8]>::to_vec).collect();
        let lb: Vec<Vec<u8>> = b.lists().map(<[u8]>::to_vec).collect();
        let before = (a.digest(), b.digest());
        for l in &lb {
            let _ = a.insert_list(l);
        }
        a.insert_all(hb);
        for l in &la {
            let _ = b.insert_list(l);
        }
        b.insert_all(ha);
        if (a.digest(), b.digest()) == before {
            break;
        }
        if round == 5 {
            panic!("change: members still exchanging after 6 rounds");
        }
    }
    let (sa, sb) = (a.state(), b.state());
    if sa != sb {
        panic!(
            "change: members differ after sync: roots {:?} vs {:?}, devices {} vs {}, stop {:?} vs {:?}",
            sa.roots.len(), sb.roots.len(), sa.devices.len(), sb.devices.len(), sa.stop, sb.stop
        );
    }
    let st = sa;
    // Closed sets (oracle added for 30dcfafc): what each member keeps,
    // restored from its own records in three orders, is the member, and a
    // fresh member fed what it gives every device reaches its state.
    closed_check("member a", &a);
    closed_check("member b", &b);
    closed_check("writer", &world.w);
    if trace() {
        eprintln!("end: roots {} devices {} fork {:?} stop {:?} changes {} forked {}", st.roots.len(), st.devices.len(), st.fork.is_some(), st.stop, world.changes, world.forked);
    }
    if trace() {
        let ws = world.w.state();
        let gl = |s: &State| s.devices.iter().filter(|d| world.gone.contains(&d.key.hash()) && !s.revoked.contains(&d.key.hash())).count();
        eprintln!("writer: devices {} revoked {} gone-live {}; member a: devices {} revoked {} gone-live {}; writer == a {}", ws.devices.len(), ws.revoked.len(), gl(&ws), st.devices.len(), st.revoked.len(), gl(&st), ws == st);
        let wid: BTreeSet<_> = world.w.ids().copied().collect();
        let aid: BTreeSet<_> = a.ids().copied().collect();
        for id in wid.symmetric_difference(&aid) {
            let r = world.w.get(id).or_else(|| a.get(id)).unwrap();
            let mut fresh = RecordSet::new(root.key.clone(), recovery());
            let mut got = Vec::new();
            for q in &all {
                let g = fresh.insert(q.clone());
                if q.id() == *id { got.push(format!("{g:?}")); }
            }
            let signer = if r.body().signer == root.hash { "root".to_string() } else { world.by_hash.keys().position(|h| *h == r.body().signer).map_or("?".into(), |p| format!("key#{p}")) };
            let kind = format!("{:?}", r.body().kind);
            eprintln!("  differs: in writer {} in a {}: {signer} seq {} kind {} counting at writer {} at a {}; in all {}; a fresh set in signing order answers {got:?}", wid.contains(id), aid.contains(id), r.body().seq, &kind[..kind.len().min(160)], ws.counting.contains(id), st.counting.contains(id), all.iter().any(|q| q.id() == *id));
        }
    }
    // A recovery fork leaves no device named.
    let fork_seen = st.fork.is_some();
    if fork_seen {
        bump("fork halts");
        if !st.devices.is_empty() {
            panic!("change: a recovery fork halts but {} devices are still named", st.devices.len());
        }
    } else if world.forked {
        bump("fork written, not seen");
    }
    if !fork_seen {
        // After a change nothing signed under an old root counts.
        if st.roots.len() > 1 {
            let cur = *st.roots.last().unwrap();
            let rec_h = k("c recovery").hash;
            let named: BTreeSet<KeyHash> = st
                .counting
                .iter()
                .filter_map(|id| a.get(id))
                .filter(|r| r.body().signer == cur)
                .filter_map(|r| match &r.body().kind {
                    Kind::Device(d) => Some([Some(d.key.hash()), d.admin.as_ref().map(Key::hash)]),
                    _ => None,
                })
                .flatten()
                .flatten()
                .collect();
            for id in &st.counting {
                let Some(r) = a.get(id) else { continue };
                let sg = r.body().signer;
                if sg == cur || sg == rec_h || named.contains(&sg) {
                    continue;
                }
                let old_root = st.roots[..st.roots.len() - 1].contains(&sg);
                panic!(
                    "change: a record signed under an old root counts: signer {} seq {} kind {:?}",
                    if old_root { "an old root" } else { "a key the current root names nowhere" },
                    r.body().seq,
                    std::mem::discriminant(&r.body().kind)
                );
            }
        }
        // Nothing removed or left out comes back.
        for d in &st.devices {
            if gone_late.contains(&d.key.hash()) && !st.revoked.contains(&d.key.hash()) {
                panic!("change: device {:?}, removed or left out, counts again", d.name);
            }
        }
    }
    // A change written over a waiting one: the waiting change's root and
    // all it signed never count, at any member, in any order.
    let cst = c.state();
    let wst = world.w.state();
    for (who, s, m) in [("member a", &st, &a), ("member c", &cst, &c), ("the writer", &wst, &world.w)] {
        if s.fork.is_some() {
            continue;
        }
        for sr in &world.superseded {
            if s.may_command(sr) {
                panic!("change: at {who} the waiting change's root commands after the change over it");
            }
            for id in &s.counting {
                if m.get(id).is_some_and(|r| r.body().signer == *sr) {
                    panic!("change: at {who} a record of the waiting change's root counts after the change over it");
                }
            }
        }
        // Nothing signed before a change by a key other than a root or the
        // recovery key counts once that change applies (an old admin key
        // named again included).
        for (nr, pre) in &world.pre_change {
            if !s.roots.contains(nr) {
                continue;
            }
            for id in pre {
                if s.counting.contains(id) {
                    let r = m.get(id).unwrap();
                    let again = world.renamed.contains(&r.body().signer);
                    panic!(
                        "change: at {who} a record signed before a change counts after it (seq {}, key named again {again})",
                        r.body().seq
                    );
                }
            }
        }
    }
    // Member c (no late re-issue): nothing removed or left out comes back.
    if cst.fork.is_none() {
        for d in &cst.devices {
            if world.gone.contains(&d.key.hash()) && !cst.revoked.contains(&d.key.hash()) {
                panic!("change: at member c device {:?}, removed or left out, counts again", d.name);
            }
        }
    }
    // An unknown peer brings only recovery records and named roots' records.
    let mut u = RecordSet::new(root.key.clone(), recovery());
    let lrefs: Vec<&[u8]> = lists.iter().map(Vec::as_slice).collect();
    u.insert_from_unknown(&full, &lrefs);
    let us = u.state();
    let named_roots: BTreeSet<KeyHash> = u
        .ids()
        .filter_map(|id| u.get(id))
        .filter_map(|r| match &r.body().kind {
            Kind::Recovery { root, .. } => Some(root.hash()),
            _ => None,
        })
        .chain(std::iter::once(root.hash))
        .collect();
    let mut per_seq: BTreeMap<u64, usize> = BTreeMap::new();
    let mut recov = 0;
    for id in u.ids().chain(u.aside()) {
        let Some(r) = u.get(id) else { continue };
        let sg = r.body().signer;
        if sg == k("c recovery").hash {
            recov += 1;
            *per_seq.entry(r.body().seq).or_default() += 1;
        } else if !named_roots.contains(&sg) {
            panic!("change: an unknown peer brought a record of a key no recovery record names (seq {})", r.body().seq);
        }
    }
    if recov > 64 || per_seq.values().any(|n| *n > 2) {
        panic!("change: an unknown peer brought {recov} recovery records, {per_seq:?} per seq");
    }
    let _ = us;
    print_stats();
});

fn closed_check(who: &str, set: &RecordSet) {
    let st = set.state();
    let recs: Vec<Record> = set.in_dependency_order().into_iter().cloned().collect();
    let lists: Vec<Vec<u8>> = set.lists().map(<[u8]>::to_vec).collect();
    let mut rev = recs.clone();
    rev.reverse();
    let mut mixed = recs.clone();
    let n = mixed.len();
    for i in 0..n {
        let j = (i * 7 + 3) % n;
        mixed.swap(i, j);
    }
    for (how, order) in [("dependency", &recs), ("reversed", &rev), ("mixed", &mixed)] {
        let back = RecordSet::restore(set.root().clone(), set.recovery().clone(), order, &lists);
        if back.state() != st {
            bump("closed: restore differs");
            panic!("change: closed: {who} restored from its own records ({how} order) differs from live: roots {} vs {}, devices {} vs {}, counting {} vs {}",
                back.state().roots.len(), st.roots.len(), back.state().devices.len(), st.devices.len(), back.state().counting.len(), st.counting.len());
        }
    }
    for d in &st.devices {
        let peer = d.key.hash();
        let given: Vec<Record> = set.for_peer(&st, &peer).into_iter().cloned().collect();
        let gl: Vec<Vec<u8>> = set.lists_for_peer(&st, &peer).into_iter().map(<[u8]>::to_vec).collect();
        let mut grev = given.clone();
        grev.reverse();
        for (how, order) in [("in order", &given), ("reversed", &grev)] {
            let fresh = RecordSet::restore(set.root().clone(), set.recovery().clone(), order, &gl);
            if fresh.state() != st {
                bump("closed: fresh peer differs");
                panic!("change: closed: a fresh member fed what {who} gives device {:?} ({how}) differs: roots {} vs {}, devices {} vs {}, counting {} vs {}",
                    d.name, fresh.state().roots.len(), st.roots.len(), fresh.state().devices.len(), st.devices.len(), fresh.state().counting.len(), st.counting.len());
            }
        }
    }
    bump("closed: checked");
}

thread_local! {
    static LISTS: std::cell::RefCell<Vec<Vec<u8>>> = const { std::cell::RefCell::new(Vec::new()) };
}

impl World {
    fn lists_extra(&mut self, l: Vec<Vec<u8>>) {
        LISTS.with(|x| x.borrow_mut().extend(l));
    }
}
