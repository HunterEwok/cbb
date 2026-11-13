// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! A deterministic simulation of a group: 3 to 12 members in one process,
//! on a network and clocks the simulator plays, all of it drawn from one
//! seed, so that a failure replays from its seed alone (docs/testing.md,
//! "The simulation").
//!
//! The network delivers, drops, duplicates, delays and reorders messages,
//! splits the members into two sides and heals; a member crashes and
//! restarts from what it wrote; clocks move. Outside actions make copies,
//! admit, remove, freeze, thaw, make admins, checkpoint, change the root
//! by the recovery key (rule 33), write two changes at one seq, and keep a
//! member off for days. After the run the network goes quiet and the
//! checks run: the same record digest everywhere, no copy shown twice as
//! new, a last copy from a member reaches every reader, a removed member
//! opens nothing sealed after the others held its removal, a restart
//! rebuilds what was written, and every member that holds both heads of a
//! fork is halted.
//!
//! The members speak through `exchange`, which wave 5 replaces with the
//! core's own connection; the connections settling is checked then.
//! Sealing keys come from the system's randomness and decide nothing: the
//! schedule, the keys that sign and every copy's K are drawn from the seed.
//!
//! `SIM_SEEDS` sets how many seeds run (from `SIM_FIRST`, 0 by default),
//! `SIM_STEPS` the steps of each; `SIM_SEED` runs one seed.
//!
//! Records move as the protocol moves them: a session opens with the
//! digest, a peer whose digest differs answers with the IDs it gives, the
//! other asks for what it lacks, for what `missing()` names (up to its
//! rounds, across sessions) and for the list `missing_list()` waits for,
//! and the records come one by one, lost or reordered like any message.
//! `SIM_WHOLE=1` hands the whole offer at once instead, as before, so that
//! the seeds found that way replay; `SIM_TWINS=0` leaves out the root's
//! twin records. With `SIM_SMALL`, `SIM_ROOT_LOST` and `SIM_ROOT_DEVIATES`
//! see `small_seed`, `root_lost` and `deviating_checkpoint`. `SIM_CAP=1`
//! caps a small-room seed's group so that every device's records fit.

mod exchange;

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::content::Content;
use crate::copies::fresh::{Fresh, Marks, Seen as SeenCopy};
use crate::copies::{self, Ask, Kept, Made, Opened};
use crate::format::cbor;
use crate::hlc::Timestamp;
use crate::keystore::{self, KeyStore as _, MemoryStore, ReadStatement};
use crate::records::body::*;
use crate::records::eval::{ConflictKind, DeviceState, State, Stop};
use crate::records::statement::{self, Statement};
use crate::records::{Body, DeviceId, GroupId, KeyHash, Record, RecordId, RecordSet};
use crate::testkit::{K, T0, k};

use exchange::Offer;

const SECOND: u64 = 1_000;
const DAY: u64 = 86_400_000;
/// How far a member's clock moves from the world's: under the copies'
/// allowance between any two of them.
const SKEW_MS: u64 = 120_000;
/// The days a long-off member may let pass, in all.
const MAX_DAYS_OFF: u64 = 28;
const MAX_CHANGES: usize = 4;
const MAX_ADMINS: usize = 3;
const MAX_WAITING: usize = 256;
const QUIET_ROUNDS: usize = 40;

/// splitmix64: small, and the same everywhere.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 { 0 } else { (self.next() % n as u64) as usize }
    }
    fn range(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.next() % (hi - lo + 1)
    }
    fn chance(&mut self, num: u64, den: u64) -> bool {
        self.next() % den < num
    }
    fn bytes<const N: usize>(&mut self) -> [u8; N] {
        let mut b = [0u8; N];
        for c in b.chunks_mut(8) {
            let v = self.next().to_le_bytes();
            c.copy_from_slice(&v[..c.len()]);
        }
        b
    }
    fn pick<T: Copy>(&mut self, v: &[T]) -> Option<T> {
        if v.is_empty() { None } else { Some(v[self.below(v.len())]) }
    }
}

/// What a member keeps in memory; a save writes all of it.
#[derive(Clone)]
struct Mem {
    set: RecordSet,
    state: State,
    /// The head of each key this member signs with.
    heads: BTreeMap<KeyHash, (u64, RecordId)>,
    /// The names of the root and admin keys it holds.
    keys: Vec<String>,
    marks: Marks,
    /// The other members' keys statements.
    statements: Vec<Vec<u8>>,
    /// The copies it holds and passes on, by origin and ID.
    copies: BTreeMap<(DeviceId, [u8; 16]), Vec<u8>>,
    /// Copies from an origin its records do not name yet.
    waiting: Vec<Vec<u8>>,
    kept: BTreeMap<[u8; 16], Kept>,
    last: Timestamp,
}

/// What a member wrote: its records and lists as the service keeps them,
/// and the rest as it was.
struct Saved {
    mem: Mem,
    records: Vec<Vec<u8>>,
    lists: Vec<Vec<u8>>,
}

struct Member {
    key: K,
    id: DeviceId,
    /// The sealing keys: the system's keystore, which a crash keeps.
    store: MemoryStore<K>,
    on: bool,
    back_at: Option<usize>,
    offset: i64,
    live: Mem,
    saved: Saved,
}

#[derive(Clone)]
enum Says {
    /// Statements and copies; with SIM_WHOLE=1 also every record and list,
    /// the whole-set sync of the first simulator.
    Sync(Offer),
    /// The records digest the sender holds; reply: an answer to one.
    Hello { digest: [u8; 32], reply: bool },
    /// The IDs the sender would give the receiver, once the digests
    /// differ.
    Ids(Vec<RecordId>),
    /// The records and the list the receiver asks for by ID.
    Want { ids: Vec<RecordId>, list: Option<[u8; 32]> },
    /// One record envelope.
    Record(Vec<u8>),
    /// One list of a change of root.
    List(Vec<u8>),
    /// Seal copy id of origin again for asker at its epoch.
    Ask { id: [u8; 16], asker: DeviceId, epoch: u64 },
}

struct Msg {
    from: usize,
    to: usize,
    says: Says,
}

/// What taking a message did, committed once the member saved.
enum Effect {
    Shown(DeviceId, [u8; 16]),
    Opened(DeviceId, [u8; 16]),
    Send(Msg),
}

type Check = Result<(), String>;

struct World {
    seed: u64,
    rng: Rng,
    step: usize,
    time: u64,
    gid: GroupId,
    root_name: String,
    recovery_name: String,
    members: Vec<Member>,
    admitted: Vec<bool>,
    /// Member keys a removal names.
    removed: BTreeSet<KeyHash>,
    /// The times a removed key was out by every other member's saved
    /// state: from the step all held its removal to the step one counted
    /// it a device again (a change of root by the recovery key can bring
    /// it back).
    out: BTreeMap<KeyHash, Vec<(usize, Option<usize>)>>,
    /// The step each copy was sealed at, by origin and ID.
    sealed_at: BTreeMap<(DeviceId, [u8; 16]), usize>,
    /// Copies each member showed as new.
    shown: BTreeSet<(usize, DeviceId, [u8; 16])>,
    freezes: Vec<RecordId>,
    forks: Vec<(RecordId, RecordId)>,
    /// Every change of root written, by its seq.
    heads: Vec<(u64, RecordId)>,
    /// Root records signed and lost to a power cut before they were
    /// stored: they never left the device, so no member may hold one.
    lost: Vec<RecordId>,
    /// Twins of a root record made on purpose (two writers with one key).
    twins: usize,
    /// The twins made, with the root key that signed them.
    twin_pairs: Vec<(RecordId, RecordId, KeyHash)>,
    /// Every record signed in the run, to find what a set keeps aside.
    signed: BTreeSet<RecordId>,
    net: Vec<Msg>,
    side: Vec<bool>,
    changes: usize,
    admins: usize,
    days_off: u64,
    copies_made: usize,
    /// A member kept off while the root checkpoints, and how many
    /// checkpoints it still waits for (small-room seeds only).
    away: Option<(usize, u32)>,
    /// The seed runs with small rooms (`small_seed`).
    small: bool,
    /// Members that came back after the checkpoints they were away for.
    came_back: usize,
    /// Some member kept a record aside at some point of the run.
    aside_seen: bool,
    /// The root lost for good (SIM_ROOT_LOST): the member, the checkpoint
    /// that left without the record it names, and the changes of root
    /// written by then.
    gone: Option<(usize, RecordId, usize)>,
    /// The root wrote a checkpoint with a free keep (SIM_ROOT_DEVIATES).
    deviated: bool,
    /// An admin's records past its room (small-room seeds): the admin
    /// member and its key, and the stage: 1 flooded, 2 more records of that
    /// key and a fresh member after it.
    flood: Option<(usize, String, u8)>,
    /// Records their writer's own set did not keep.
    not_kept: BTreeSet<RecordId>,
    /// Each member's last admission record.
    admission: BTreeMap<usize, RecordId>,
    /// The record IDs each change of root's list names, in order.
    change_lists: Vec<Vec<RecordId>>,
    /// SIM_ADMIN_TWIN: the member an admin removed before a twin of its
    /// key, and the changes of root written by then.
    admin_twin: Option<(usize, usize)>,
    log: Vec<String>,
}

fn statement_of(env: &[u8]) -> Option<Statement> {
    match keystore::read_statement(env) {
        Ok(ReadStatement::Take(st)) => Some(st),
        _ => None,
    }
}

/// Two histories of the current root: the group stops until the recovery
/// key changes the root.
fn root_forked(st: &State) -> bool {
    st.stop == Stop::Full
        && st.conflicts.iter().any(|c| c.kind == ConflictKind::TwoHistories && st.roots.last() == c.signers.first())
}

/// Stopped: for good by two changes of root at one seq, or until a change
/// of root by two histories of the root.
fn stopped(st: &State) -> bool {
    st.halted() || root_forked(st)
}

/// What a restart does: the core's own restore from the saved records and
/// lists, in any order.
fn rebuild(
    root: &crate::records::Key,
    recovery: &crate::records::Recovery,
    records: &[Vec<u8>],
    lists: &[Vec<u8>],
) -> RecordSet {
    let records: Vec<Record> = records.iter().filter_map(|e| Record::decode(e).ok()).collect();
    RecordSet::restore(root.clone(), recovery.clone(), &records, lists)
}

/// A seed's recovery key: K1 named by the seed, K2 the tests' fixed
/// SLH-DSA key (the Group ID still differs by the root and K1).
fn recovery_pair(name: &str) -> crate::records::Recovery {
    crate::records::Recovery { k1: k(name).key, k2: crate::testkit::rk2().key() }
}

impl World {
    fn new(seed: u64) -> World {
        let mut rng = Rng(seed ^ 0x5157_0000_c0de);
        // With SIM_CAP=1 a small-room group stays within its rooms: at most
        // 6 devices, whose device records (one unit each) the root signs
        // with a checkpoint and one more record inside its ceiling of 8,
        // and with up to 3 admin keys' records inside the room of 14.
        let n = if small_seed(seed) && env("SIM_CAP") == Some(1) { 3 + rng.below(4) } else { 3 + rng.below(10) };
        let root_name = format!("sim{seed}/root");
        let recovery_name = format!("sim{seed}/recovery");
        let root = k(&root_name);
        let pair = recovery_pair(&recovery_name);
        let gid = crate::records::group_id(&root.key, &pair);
        let mut members = Vec::new();
        for i in 0..n {
            let name = format!("sim{seed}/m{i}");
            let key = k(&name);
            let id = key.key.device_id();
            let mut store = MemoryStore::new(k(&name));
            keystore::rotate(&mut store, &gid, T0, Some(T0)).unwrap();
            let set = RecordSet::new(root.key.clone(), pair.clone());
            let mem = Mem {
                state: set.state(),
                set,
                heads: BTreeMap::new(),
                keys: Vec::new(),
                marks: Marks::default(),
                statements: Vec::new(),
                copies: BTreeMap::new(),
                waiting: Vec::new(),
                kept: BTreeMap::new(),
                last: Timestamp::default(),
            };
            let saved = Saved { mem: mem.clone(), records: Vec::new(), lists: Vec::new() };
            members.push(Member { key, id, store, on: true, back_at: None, offset: 0, live: mem, saved });
        }
        let mut w = World {
            seed,
            rng,
            step: 0,
            time: T0,
            gid,
            root_name: root_name.clone(),
            recovery_name,
            admitted: alloc::vec![false; n],
            members,
            removed: BTreeSet::new(),
            out: BTreeMap::new(),
            sealed_at: BTreeMap::new(),
            shown: BTreeSet::new(),
            freezes: Vec::new(),
            forks: Vec::new(),
            heads: Vec::new(),
            lost: Vec::new(),
            twins: 0,
            twin_pairs: Vec::new(),
            signed: BTreeSet::new(),
            net: Vec::new(),
            side: alloc::vec![false; n],
            changes: 0,
            admins: 0,
            days_off: 0,
            copies_made: 0,
            away: None,
            small: small_seed(seed),
            came_back: 0,
            aside_seen: false,
            gone: None,
            deviated: false,
            flood: None,
            not_kept: BTreeSet::new(),
            admission: BTreeMap::new(),
            change_lists: Vec::new(),
            admin_twin: None,
            log: Vec::new(),
        };
        // The root's phone is member 0; it admits a first few.
        w.members[0].live.keys.push(root_name.clone());
        let mut d = Device::new(w.members[0].key.key.clone(), "m0", ROLE_PHONE);
        d.rights = RIGHT_READ | RIGHT_SEND | RIGHT_SECRETS;
        d.holds_root = true;
        w.sign(0, &root_name, Kind::device(d));
        w.admitted[0] = true;
        let first = 1 + w.rng.below(n - 1);
        for t in 1..=first {
            w.admit_by(0, &root_name, t);
        }
        w.note(format!("{n} members, {} admitted", first + 1));
        w
    }

    fn note(&mut self, s: String) {
        self.log.push(format!("{:>4} {s}", self.step));
        if self.log.len() > 40 {
            self.log.remove(0);
        }
    }

    fn now(&self, i: usize) -> u64 {
        self.time.saturating_add_signed(self.members[i].offset)
    }

    /// Recomputes a member's state after it took records (the set drops
    /// what a counting checkpoint leaves out by itself).
    fn refresh(&mut self, i: usize) {
        let m = &mut self.members[i].live;
        m.state = m.set.state();
        if !self.aside_seen {
            let set = &self.members[i].live.set;
            self.aside_seen = self.signed.iter().any(|id| set.waits_aside(id));
        }
    }

    fn save(&mut self, i: usize) {
        let m = &mut self.members[i];
        let records = m.live.set.in_dependency_order().into_iter().map(Record::envelope).collect();
        let lists = m.live.set.lists().map(<[u8]>::to_vec).collect();
        m.saved = Saved { mem: m.live.clone(), records, lists };
    }

    /// Signs a record with the key named key_name on member i, takes it
    /// and saves: an act counts once it is written. None when the core's
    /// writer refuses it (`RecordSet::write_record`): nothing was written.
    fn sign(&mut self, i: usize, key_name: &str, kind: Kind) -> Option<Record> {
        let r = self.sign_unsaved(i, key_name, kind)?;
        self.save(i);
        Some(r)
    }

    /// Signs and takes a record on member i without storing it: what is
    /// in memory between the signature and the durable store.
    fn sign_unsaved(&mut self, i: usize, key_name: &str, kind: Kind) -> Option<Record> {
        let time_ms = self.now(i);
        let kk = k(key_name);
        // An ordinary record goes through the core's writer, as a kit's
        // does; a checkpoint signed here is a deviating root's.
        if !matches!(kind, Kind::Checkpoint { .. } | Kind::Recovery { .. }) {
            let m = &mut self.members[i].live;
            let st = m.state.clone();
            let r = match m.set.write_record(&st, &kk, kind, time_ms) {
                Ok(r) => r,
                Err(e) => {
                    REFUSED.fetch_add(1, Ordering::Relaxed);
                    refused_why(&alloc::format!("{e:?}")).fetch_add(1, Ordering::Relaxed);
                    return None;
                }
            };
            m.heads.insert(kk.hash, (r.body().seq, r.id()));
            self.signed.insert(r.id());
            self.refresh(i);
            return Some(r);
        }
        let m = &mut self.members[i].live;
        let (seq, prev) = m.heads.get(&kk.hash).map_or((1, None), |(s, id)| (s + 1, Some(*id)));
        let body = Body { group: self.gid, signer: kk.hash, seq, prev, time_ms, kind, held: false };
        let r = Record::sign(body, &kk).unwrap();
        self.signed.insert(r.id());
        let m = &mut self.members[i].live;
        m.heads.insert(kk.hash, (seq, r.id()));
        let _ = m.set.insert(r.clone());
        // A record its writer's own set does not keep never leaves it.
        if !m.set.contains(&r.id()) {
            NOT_KEPT.fetch_add(1, Ordering::Relaxed);
            self.not_kept.insert(r.id());
        }
        self.refresh(i);
        Some(r)
    }

    /// The root's own device as a record, signed again unchanged: an
    /// action of the root that changes nothing else.
    fn own_device(&self, i: usize) -> Option<Kind> {
        let ds = self.members[i].live.state.device(&self.members[i].id)?.clone();
        Some(Kind::device(self.device_of(i, &ds)))
    }

    /// Every root key of the run: the first and each change's.
    fn root_keys(&self) -> BTreeSet<KeyHash> {
        let mut out = BTreeSet::new();
        out.insert(k(&self.root_name).hash);
        for c in 1..=self.changes {
            out.insert(k(&format!("sim{}/root{c}", self.seed)).hash);
        }
        out
    }

    /// The root's power is cut between its signature and the durable
    /// store: the action was shown as done, the record never left (a
    /// root record leaves only once stored), and the root comes back
    /// without it.
    fn power_loss(&mut self) {
        let Some((i, key)) = self.signer(true) else { return };
        let Some(kind) = self.own_device(i) else { return };
        let Some(r) = self.sign_unsaved(i, &key, kind) else { return };
        self.lost.push(r.id());
        self.crash(i);
        self.note(format!("m{i} loses power after signing, before storing"));
    }

    /// Two writers with one key, forced: the root signs a record, and a
    /// second process with the same key signs another at the same seq,
    /// which reaches another member. The group halts until a change of
    /// root by the recovery key.
    fn twin(&mut self) -> Check {
        let Some((i, key)) = self.signer(true) else { return Ok(()) };
        // The second reaches a member of the group that knows the root key
        // (another refuses it, and it is lost): not one a removal named.
        let rk = k(&key).hash;
        let others: Vec<usize> = self
            .on_members()
            .into_iter()
            .filter(|j| {
                let x = &self.members[*j];
                *j != i
                    && self.admitted[*j]
                    && !self.removed.contains(&x.key.hash)
                    && x.live.state.roots.last() == Some(&rk)
            })
            .collect();
        let Some(j) = self.rng.pick(&others) else { return Ok(()) };
        let Some(kind) = self.own_device(i) else { return Ok(()) };
        let kk = k(&key);
        let before = self.members[i].live.heads.get(&kk.hash).copied();
        let Some(a) = self.sign(i, &key, kind.clone()) else { return Ok(()) };
        let (seq, prev) = before.map_or((1, None), |(s, id)| (s + 1, Some(id)));
        let body =
            Body { group: self.gid, signer: kk.hash, seq, prev, time_ms: a.body().time_ms + 1, kind, held: false };
        let b = Record::sign(body, &kk).unwrap();
        self.signed.insert(b.id());
        if self.members[j].live.set.insert(b.clone()).is_err() {
            return Err(format!("m{j} refused a root record of the root it knows"));
        }
        self.refresh(j);
        self.save(j);
        self.forks.push((a.id(), b.id()));
        self.twin_pairs.push((a.id(), b.id(), kk.hash));
        self.twins += 1;
        self.note(format!("two writers with m{i}'s root key sign at seq {seq}; m{j} takes the second"));
        self.after_save(i)?;
        self.after_save(j)
    }

    /// The records member i keeps aside for a later checkpoint.
    fn aside(&self, i: usize) -> BTreeSet<RecordId> {
        let set = &self.members[i].live.set;
        self.signed.iter().filter(|id| set.waits_aside(id)).copied().collect()
    }

    /// No member holds a lost record, nor two records of a root key at
    /// one seq unless the run made a twin on purpose.
    fn no_twins(&self) -> Check {
        let roots = self.root_keys();
        for (i, m) in self.members.iter().enumerate() {
            let mut at: BTreeMap<(KeyHash, u64), RecordId> = BTreeMap::new();
            for id in m.live.set.ids() {
                if self.lost.contains(id) {
                    return Err(format!("m{i} holds a root record that was never stored"));
                }
                let b = m.live.set.get(id).unwrap().body();
                if !roots.contains(&b.signer) {
                    continue;
                }
                if let Some(other) = at.insert((b.signer, b.seq), *id)
                    && other != *id
                    && self.twins == 0
                {
                    return Err(format!("m{i} holds two records of a root key at seq {}", b.seq));
                }
            }
        }
        Ok(())
    }

    /// Each signer's newest record that member i holds.
    fn seen(&self, i: usize) -> Vec<Seen> {
        let set = &self.members[i].live.set;
        let mut heads: BTreeMap<KeyHash, (u64, RecordId)> = BTreeMap::new();
        for id in set.ids() {
            let b = set.get(id).unwrap().body();
            let e = heads.entry(b.signer).or_insert((b.seq, *id));
            if b.seq > e.0 {
                *e = (b.seq, *id);
            }
        }
        heads.into_iter().map(|(key, (seq, id))| Seen { key, seq, id }).collect()
    }

    /// The root key member i signs with, if its state has it as the root.
    fn root_key(&self, i: usize) -> Option<String> {
        let m = &self.members[i].live;
        let root = m.state.roots.last()?;
        m.keys.iter().find(|n| &k(n).hash == root).cloned()
    }

    /// An admin key member i signs with that its state counts.
    fn admin_key(&self, i: usize) -> Option<String> {
        let m = &self.members[i].live;
        m.keys
            .iter()
            .find(|n| {
                let h = k(n).hash;
                m.state.devices.iter().any(|d| d.admin == Some(h) && !d.frozen)
            })
            .cloned()
    }

    fn device_of(&self, i: usize, d: &DeviceState) -> Device {
        let mut x = Device::new(d.key.clone(), &d.name, d.role);
        x.rights = d.rights;
        x.skip = d.skip;
        x.caps = d.caps;
        x.os = d.os;
        x.store = d.store;
        x.proof = d.proof;
        x.powers = d.powers;
        x.commands = d.commands;
        x.guarded = d.guarded;
        x.admin = d.admin.and_then(|h| self.members[i].live.keys.iter().map(|n| k(n).key).find(|key| key.hash() == h));
        x
    }

    fn admit_by(&mut self, by: usize, key_name: &str, t: usize) {
        let mut d = Device::new(self.members[t].key.key.clone(), &format!("m{t}"), ROLE_PHONE);
        d.rights = RIGHT_READ | RIGHT_SEND | RIGHT_SECRETS;
        if let Some(r) = self.sign(by, key_name, Kind::device(d)) {
            self.admission.insert(t, r.id());
            self.admitted[t] = true;
        }
    }

    fn on_members(&self) -> Vec<usize> {
        (0..self.members.len()).filter(|i| self.members[*i].on).collect()
    }

    /// Members on whose own state counts them as a device.
    fn in_group(&self) -> Vec<usize> {
        self.on_members()
            .into_iter()
            .filter(|i| {
                let m = &self.members[*i];
                m.live.state.device_by_key(&m.key.hash).is_some() && !stopped(&m.live.state)
            })
            .collect()
    }

    fn statements(&self, i: usize) -> Vec<Vec<u8>> {
        let m = &self.members[i];
        let mut out: Vec<Vec<u8>> = m.store.epochs().into_iter().map(|e| e.statement).collect();
        out.extend(m.live.statements.iter().cloned());
        out
    }

    fn sealing(&self, i: usize) -> BTreeMap<DeviceId, statement::Sealing> {
        let st: Vec<Statement> = self.statements(i).iter().filter_map(|e| statement_of(e)).collect();
        statement::choose(&self.members[i].live.state, st.iter())
    }

    fn rotate(&mut self, i: usize) {
        let now = self.now(i);
        let gid = self.gid;
        keystore::rotate(&mut self.members[i].store, &gid, now, Some(now)).unwrap();
    }

    fn tick(&mut self, i: usize, wall: u64) -> Timestamp {
        let m = &mut self.members[i].live;
        let wall = wall as i64;
        m.last = if wall > m.last.wall {
            Timestamp { wall, logical: 0 }
        } else {
            Timestamp { wall: m.last.wall, logical: m.last.logical + 1 }
        };
        m.last
    }

    /// Member i seals a copy to its readers, at wall when given; returns
    /// the copy's ID and its readers.
    fn copy(&mut self, i: usize, wall: Option<u64>) -> Option<([u8; 16], Vec<DeviceId>)> {
        self.rotate(i);
        let now = self.now(i);
        let me = self.members[i].id;
        let st = &self.members[i].live.state;
        let d = st.device(&me)?;
        if st.halted() || d.frozen || d.rights & RIGHT_SEND == 0 {
            return None;
        }
        self.copies_made += 1;
        let content = Content::text(&format!("copy {} of {}", self.copies_made, self.seed), false);
        let readers = copies::readers(st, &self.sealing(i), &content, &me, &[], Some(now));
        if readers.is_empty() {
            return None;
        }
        let time = self.tick(i, wall.unwrap_or(now));
        let made = Made { id: self.rng.bytes(), time, blob: None };
        let kk: [u8; 32] = self.rng.bytes();
        let seeds: Vec<[u8; 32]> = readers.iter().map(|_| self.rng.bytes()).collect();
        let sealed = copies::seal_with(&self.members[i].key, &readers, &made, &content, &kk, &seeds).unwrap();
        let m = &mut self.members[i].live;
        m.kept.insert(made.id, Kept::new(made, content, &readers));
        m.copies.insert((me, made.id), sealed);
        self.sealed_at.insert((me, made.id), self.step);
        self.save(i);
        Some((made.id, readers.iter().map(|r| r.id).collect()))
    }

    /// Member j takes one copy: checks it, holds it, opens it if it is a
    /// reader, and judges it.
    fn receive(&mut self, j: usize, bytes: &[u8], fx: &mut Vec<Effect>) -> Check {
        let Ok(v) = cbor::decode(bytes) else { return Err(String::from("a copy does not decode")) };
        let now = self.now(j);
        let me = self.members[j].id;
        let m = &self.members[j];
        let c = match copies::check(&v, &m.live.state) {
            Ok(c) => c,
            Err(r) if r == copies::RULE_ORIGIN || r == copies::RULE_SEND => {
                let m = &mut self.members[j].live;
                if !m.waiting.iter().any(|w| w == bytes) && m.waiting.len() < MAX_WAITING {
                    m.waiting.push(bytes.to_vec());
                }
                return Ok(());
            }
            Err(r) => return Err(format!("m{j} refused a copy: {r:?}")),
        };
        let key = (c.origin, c.id);
        match m.live.copies.get(&key) {
            Some(held) if held.as_slice() == bytes => return Ok(()),
            Some(_) if !c.readers.iter().any(|(d, _)| *d == me) => return Ok(()),
            Some(_) => {}
            None => {
                self.members[j].live.copies.insert(key, bytes.to_vec());
            }
        }
        let m = &self.members[j];
        match copies::open(&c, &me, &m.store, &m.live.state) {
            Ok(Opened::Content { content, .. }) => {
                fx.push(Effect::Opened(c.origin, c.id));
                let seen = SeenCopy::of(&c, &content, DAY, DAY);
                let state = m.live.state.clone();
                let marks = &mut self.members[j].live.marks;
                match marks.judge(&seen, Some(now), &state) {
                    Fresh::New { .. } => {
                        marks.wrote(&c.origin, c.time);
                        fx.push(Effect::Shown(c.origin, c.id));
                    }
                    Fresh::Ahead => return Err(format!("m{j} took a copy for one from the future")),
                    Fresh::Behind | Fresh::SeenSecret => {}
                }
            }
            Ok(Opened::Reseal { .. }) => {
                let epoch = m.store.epochs().iter().map(|e| e.epoch).max().unwrap_or(0);
                if let Some(to) = self.members.iter().position(|x| x.id == c.origin) {
                    fx.push(Effect::Send(Msg { from: j, to, says: Says::Ask { id: c.id, asker: me, epoch } }));
                }
            }
            Ok(_) => {}
            Err(r) => return Err(format!("m{j} could not open a copy sealed to it: {r:?}")),
        }
        Ok(())
    }

    /// Member j takes a message. With crash, it goes down before it saves:
    /// what it took is lost, as nothing of it was written.
    fn deliver(&mut self, msg: Msg, crash: bool) -> Check {
        let j = msg.to;
        if !self.members[j].on {
            return Ok(());
        }
        self.rotate(j);
        let mut fx = Vec::new();
        match msg.says {
            Says::Sync(offer) => {
                // A peer that only gets the root's pair gives nothing but
                // what makes or completes one.
                let point: [u8; 65] = self.members[msg.from].key.key.public.clone().try_into().unwrap();
                let standing = crate::peer::standing(&self.members[j].live.state, &self.members[j].key.hash, &point);
                if standing == crate::peer::Standing::ForkProof {
                    exchange::take_proof(&mut self.members[j].live.set, &offer);
                } else {
                    exchange::take(&mut self.members[j].live.set, &offer);
                }
                self.refresh(j);
                let m = &mut self.members[j].live;
                for s in offer.statements {
                    if !m.statements.contains(&s) {
                        m.statements.push(s);
                    }
                }
                for c in &offer.copies {
                    self.receive(j, c, &mut fx)?;
                }
                let waiting = core::mem::take(&mut self.members[j].live.waiting);
                for c in &waiting {
                    self.receive(j, c, &mut fx)?;
                }
            }
            Says::Hello { digest, reply } => {
                let a = msg.from;
                if digest != self.members[j].live.set.digest() {
                    let ids = self.ids_for(j, a);
                    if !ids.is_empty() {
                        fx.push(Effect::Send(Msg { from: j, to: a, says: Says::Ids(ids) }));
                    }
                }
                // Equal digests say nothing of what both lack: what its
                // records name and the list it waits for, it still asks.
                let m = &mut self.members[j].live;
                let state = m.state.clone();
                let want = m.set.missing(&state);
                let list = m.set.missing_list();
                if !want.is_empty() || list.is_some() {
                    fx.push(Effect::Send(Msg { from: j, to: a, says: Says::Want { ids: want, list } }));
                }
                if !reply {
                    let digest = self.members[j].live.set.digest();
                    fx.push(Effect::Send(Msg { from: j, to: a, says: Says::Hello { digest, reply: true } }));
                }
            }
            Says::Ids(ids) => {
                // What it lacks of the peer's; what its records name and
                // the list it waits for it asked on the peer's Hello.
                let m = &self.members[j].live;
                let want: Vec<RecordId> = ids.into_iter().filter(|id| !m.set.contains(id)).collect();
                if !want.is_empty() {
                    fx.push(Effect::Send(Msg { from: j, to: msg.from, says: Says::Want { ids: want, list: None } }));
                }
            }
            Says::Want { ids, list } => {
                let a = msg.from;
                // Asked by ID, a record goes out only as for_peer_by_id
                // allows, never straight from get().
                let peer = self.members[a].key.hash;
                let m = &self.members[j].live;
                for id in &ids {
                    if let Some(r) = m.set.for_peer_by_id(&m.state, &peer, id) {
                        fx.push(Effect::Send(Msg { from: j, to: a, says: Says::Record(r.envelope()) }));
                    }
                }
                // A list goes out as lists_for_peer allows: every list to
                // a device, to a removed device or a proof-only peer the
                // lists of the recovery records it is given.
                if let Some(h) = list
                    && let Some(l) =
                        m.set.lists_for_peer(&m.state, &peer).into_iter().find(|l| List::of(l, &h).is_some())
                {
                    fx.push(Effect::Send(Msg { from: j, to: a, says: Says::List(l.to_vec()) }));
                }
            }
            Says::Record(env) => {
                if let Ok(r) = Record::decode(&env) {
                    let point: [u8; 65] = self.members[msg.from].key.key.public.clone().try_into().unwrap();
                    let standing =
                        crate::peer::standing(&self.members[j].live.state, &self.members[j].key.hash, &point);
                    let set = &mut self.members[j].live.set;
                    let _ =
                        if standing == crate::peer::Standing::ForkProof { set.insert_proof(r) } else { set.insert(r) };
                    self.refresh(j);
                }
            }
            Says::List(bytes) => {
                let _ = self.members[j].live.set.insert_list(&bytes);
                self.refresh(j);
            }
            Says::Ask { id, asker, epoch } => {
                let now = self.now(j);
                let sealing = self.sealing(j);
                let m = &mut self.members[j];
                let state = m.live.state.clone();
                if let Some(kept) = m.live.kept.get_mut(&id) {
                    let ask = Ask { asker, epoch, leaves: &[], now_ms: Some(now), group_ttl_ms: DAY };
                    if let Ok(again) = copies::reseal(&m.key, kept, &state, &sealing, &ask) {
                        let off = Offer { copies: alloc::vec![again], ..Offer::default() };
                        if let Some(to) = self.members.iter().position(|x| x.id == asker) {
                            fx.push(Effect::Send(Msg { from: j, to, says: Says::Sync(off) }));
                        }
                    }
                }
            }
        }
        if crash {
            self.crash(j);
            return Ok(());
        }
        self.save(j);
        for e in fx {
            match e {
                Effect::Shown(o, id) => {
                    if !self.shown.insert((j, o, id)) {
                        return Err(format!("m{j} showed a copy as new twice"));
                    }
                }
                Effect::Opened(o, id) => {
                    let h = self.members[j].key.hash;
                    let sealed = self.sealed_at.get(&(o, id)).copied().unwrap_or(0);
                    let out = self.out.get(&h).into_iter().flatten();
                    if let Some((from, _)) =
                        out.into_iter().find(|(from, to)| *from < sealed && to.is_none_or(|t| sealed < t))
                    {
                        return Err(format!(
                            "removed m{j} opened a copy sealed at step {sealed}, after the others held its removal at {from}"
                        ));
                    }
                }
                Effect::Send(m) => self.net.push(m),
            }
        }
        self.after_save(j)
    }

    /// The checks after member i saved: the fork, and who holds which
    /// removal.
    fn after_save(&mut self, i: usize) -> Check {
        let m = &self.members[i].live;
        for (a, b) in &self.forks {
            if m.set.contains(a) && m.set.contains(b) && !stopped(&m.state) {
                return Err(format!("m{i} holds both heads of a fork and is not halted"));
            }
        }
        let removed: Vec<KeyHash> = self.removed.iter().copied().collect();
        for h in removed {
            let open = self.out.get(&h).and_then(|v| v.last()).is_some_and(|(_, to)| to.is_none());
            let saved = |j: usize| &self.members[j].saved.mem.state;
            let inside = |j: usize| self.admitted[j] && saved(j).device_by_key(&self.members[j].key.hash).is_some();
            let others = (0..self.members.len()).filter(|j| self.members[*j].key.hash != h);
            if !open && others.clone().all(|j| !inside(j) || saved(j).revoked.contains(&h)) {
                self.out.entry(h).or_default().push((self.step, None));
            } else if open
                && others.clone().any(|j| inside(j) && saved(j).device_by_key(&h).is_some())
                && let Some(last) = self.out.get_mut(&h).and_then(|v| v.last_mut())
            {
                last.1 = Some(self.step);
            }
        }
        Ok(())
    }

    /// What a opens a session with b with: its statements and copies,
    /// and its records digest (protocol-shaped), or everything at once
    /// with SIM_WHOLE=1.
    fn session(&self, a: usize, b: usize) -> Vec<Says> {
        let mut off = self.offer(a, b);
        if whole_sync() {
            return alloc::vec![Says::Sync(off)];
        }
        off.records.clear();
        off.lists.clear();
        alloc::vec![Says::Sync(off), Says::Hello { digest: self.members[a].live.set.digest(), reply: false }]
    }

    /// The IDs member a gives member b: what for_peer hands it.
    fn ids_for(&self, a: usize, b: usize) -> Vec<RecordId> {
        let m = &self.members[a].live;
        m.set.for_peer(&m.state, &self.members[b].key.hash).into_iter().map(Record::id).collect()
    }

    fn offer(&self, a: usize, b: usize) -> Offer {
        let m = &self.members[a];
        let peer = self.members[b].key.hash;
        let copies: Vec<Vec<u8>> =
            if m.live.state.revoked.contains(&peer) { Vec::new() } else { m.live.copies.values().cloned().collect() };
        exchange::offer(&m.live.set, &m.live.state, &peer, &self.statements(a), &copies)
    }

    fn crash(&mut self, i: usize) {
        let m = &mut self.members[i];
        m.on = false;
        m.live = m.saved.mem.clone();
    }

    /// Member i comes back from what it wrote: the set built again from
    /// its records and lists must be the one it saved.
    fn restart(&mut self, i: usize) -> Check {
        if self.gone.is_some_and(|(g, _, _)| g == i) {
            return Ok(());
        }
        let (root, recovery) = (k(&self.root_name).key, recovery_pair(&self.recovery_name));
        let m = &mut self.members[i];
        let set = rebuild(&root, &recovery, &m.saved.records, &m.saved.lists);
        if set.digest() != m.saved.mem.set.digest() {
            return Err(format!("m{i} restarted with records other than it wrote"));
        }
        let state = set.state();
        if state != m.saved.mem.state {
            return Err(format!("m{i} restarted with another state than it wrote"));
        }
        m.live = m.saved.mem.clone();
        m.live.set = set;
        m.live.state = state;
        m.on = true;
        m.back_at = None;
        Ok(())
    }

    fn signer(&mut self, root_only: bool) -> Option<(usize, String)> {
        let mut cands = Vec::new();
        for i in self.in_group() {
            if let Some(n) = self.root_key(i) {
                cands.push((i, n));
            } else if !root_only && let Some(n) = self.admin_key(i) {
                cands.push((i, n));
            }
        }
        if cands.is_empty() {
            return None;
        }
        let x = self.rng.below(cands.len());
        Some(cands.swap_remove(x))
    }

    /// A device of i's state, not i and not the root's phone, not removed.
    fn target(&mut self, i: usize, f: impl Fn(&DeviceState) -> bool) -> Option<usize> {
        let st = &self.members[i].live.state;
        let me = self.members[i].id;
        let cands: Vec<usize> = (0..self.members.len())
            .filter(|t| {
                let x = &self.members[*t];
                x.id != me
                    && st.root_device != Some(x.id)
                    && !self.removed.contains(&x.key.hash)
                    && st.device(&x.id).is_some_and(&f)
            })
            .collect();
        self.rng.pick(&cands)
    }

    fn act(&mut self) -> Check {
        let roll = self.rng.below(100);
        match roll {
            0..=11 => {
                let g = self.in_group();
                if let Some(i) = self.rng.pick(&g)
                    && let Some((id, _)) = self.copy(i, None)
                {
                    self.note(format!("m{i} copies {:02x}{:02x}", id[0], id[1]));
                }
            }
            12..=15 => {
                let free: Vec<usize> = (0..self.members.len()).filter(|t| !self.admitted[*t]).collect();
                if let Some(t) = self.rng.pick(&free)
                    && let Some((by, key)) = self.signer(false)
                {
                    self.admit_by(by, &key, t);
                    self.note(format!("m{by} admits m{t}"));
                    self.after_save(by)?;
                }
            }
            16..=17 => {
                if let Some((by, key)) = self.signer(false)
                    && let Some(t) = self.target(by, |_| true)
                {
                    let h = self.members[t].key.hash;
                    let seen = self.seen(by);
                    if self.sign(by, &key, Kind::Revoke(Removal { keys: alloc::vec![h], seen })).is_some() {
                        self.removed.insert(h);
                        self.note(format!("m{by} removes m{t}"));
                        self.after_save(by)?;
                        if env("SIM_ADMIN_TWIN") == Some(1)
                            && self.root_key(by).as_deref() != Some(key.as_str())
                            && self.admin_twin.is_none()
                        {
                            self.admin_twin(by, &key, t);
                        }
                    }
                }
            }
            18..=19 => {
                if let Some((by, key)) = self.signer(false)
                    && let Some(t) = self.target(by, |d| !d.frozen)
                {
                    let h = self.members[t].key.hash;
                    let seen = self.seen(by);
                    if let Some(r) = self.sign(by, &key, Kind::Freeze(Removal { keys: alloc::vec![h], seen })) {
                        self.freezes.push(r.id());
                        self.note(format!("m{by} freezes m{t}"));
                        self.after_save(by)?;
                    }
                }
            }
            20..=21 => {
                if let Some((by, key)) = self.signer(true) {
                    let held: Vec<RecordId> =
                        self.freezes.iter().filter(|f| self.members[by].live.set.contains(f)).copied().collect();
                    if let Some(f) = self.rng.pick(&held) {
                        let seen = self.seen(by);
                        if self.sign(by, &key, Kind::Thaw { ids: alloc::vec![f], seen }).is_some() {
                            self.freezes.retain(|x| *x != f);
                            self.note(format!("m{by} thaws"));
                            self.after_save(by)?;
                        }
                    }
                }
            }
            22..=23 if self.admins < MAX_ADMINS => self.make_admin()?,
            24..=25 => self.checkpoint()?,
            26 if self.changes < MAX_CHANGES => self.change_root(false, false)?,
            27 if self.changes < MAX_CHANGES && self.rng.chance(1, 3) => self.change_root(true, false)?,
            29 => self.power_loss(),
            30 if twins_on() && self.twins == 0 && self.changes < MAX_CHANGES && self.rng.chance(1, 4) => {
                self.twin()?
            }
            // A member away over two or three checkpoints, so that it
            // comes back to a checkpoint that may not be whole for it yet.
            31 if self.small && self.away.is_none() => self.go_away(),
            43..=50 if self.small => self.flood()?,
            42 if env("SIM_ROOT_LOST") == Some(1) && self.gone.is_none() && self.rng.chance(1, 2) => {
                self.root_lost()?
            }
            32..=41 if self.away.is_some() => self.checkpoint()?,
            28 if self.days_off < MAX_DAYS_OFF => {
                let on = self.on_members();
                if on.len() > 2
                    && let Some(i) = self.rng.pick(&on)
                {
                    let days = (self.rng.range(1, 9)).min(MAX_DAYS_OFF - self.days_off);
                    self.days_off += days;
                    self.time += days * DAY;
                    self.crash(i);
                    self.members[i].back_at = Some(self.step + 50 + self.rng.below(200));
                    self.note(format!("m{i} is off; {days} days pass"));
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// The root writes a checkpoint: it keeps what counts and every other
    /// signer's record; only the root's own that no longer count go.
    fn checkpoint(&mut self) -> Check {
        let Some((by, key)) = self.signer(true) else { return Ok(()) };
        if let Some(kind) = self.deviating_checkpoint(by, &key) {
            let _ = self.sign(by, &key, kind);
            self.note(format!("m{by} checkpoints, deviating"));
        } else if self.write_checkpoint(by, &key).is_some() {
            self.note(format!("m{by} checkpoints"));
        } else {
            return Ok(());
        }
        if let Some((i, left)) = self.away
            && by != i
        {
            if left <= 1 {
                self.away = None;
                self.came_back += 1;
                self.members[i].back_at = Some(self.step + 1 + self.rng.below(20));
            } else {
                self.away = Some((i, left - 1));
            }
        }
        self.after_save(by)
    }

    /// The honest root's checkpoint on member by, through the core's
    /// writer: taken into its set like any record it signs. None when the
    /// writer refuses.
    fn write_checkpoint(&mut self, by: usize, key: &str) -> Option<Record> {
        let now = self.now(by);
        let m = &self.members[by].live;
        let r = match m.set.write_checkpoint(&m.state, &k(key), now) {
            Ok(r) => r,
            Err(_) => {
                CP_REFUSED.fetch_add(1, Ordering::Relaxed);
                return None;
            }
        };
        self.signed.insert(r.id());
        let m = &mut self.members[by].live;
        m.heads.insert(r.body().signer, (r.body().seq, r.id()));
        let _ = m.set.insert(r.clone());
        if !m.set.contains(&r.id()) {
            NOT_KEPT.fetch_add(1, Ordering::Relaxed);
        }
        self.refresh(by);
        self.save(by);
        Some(r)
    }

    /// With SIM_ROOT_DEVIATES=1, one checkpoint in three is the root's own
    /// making instead of the core writer's: half of them keep what counts
    /// and every other signer's record under the root's own head alone
    /// (past the root's ceiling when that is much), half a free choice of
    /// the held records.
    fn deviating_checkpoint(&mut self, by: usize, key: &str) -> Option<Kind> {
        if env("SIM_ROOT_DEVIATES") != Some(1) || !self.rng.chance(1, 3) {
            return None;
        }
        self.deviated = true;
        let h = k(key).hash;
        let live = &self.members[by].live;
        let mut keep: Vec<RecordId> = live
            .set
            .ids()
            .filter(|id| live.state.counting.contains(id) || live.set.get(id).is_some_and(|r| r.body().signer != h))
            .copied()
            .collect();
        if self.rng.chance(1, 2) {
            let all: Vec<RecordId> = self.members[by].live.set.ids().copied().collect();
            keep = all.into_iter().filter(|_| self.rng.chance(1, 2)).collect();
        }
        keep.sort();
        let heads = self.members[by]
            .live
            .heads
            .get(&h)
            .map(|(seq, id)| Head { key: h, seq: *seq, id: *id })
            .into_iter()
            .collect();
        Some(Kind::Checkpoint { heads, keep })
    }

    /// SIM_ADMIN_TWIN=1: after the admin key key on member by removed
    /// member t, a second record of that key at seq 1 (the key's two
    /// histories). Its removal must keep barring t at every member.
    fn admin_twin(&mut self, by: usize, key: &str, t: usize) {
        let kk = k(key);
        let set = &self.members[by].live.set;
        let Some(first) =
            set.ids().filter_map(|id| set.get(id)).find(|r| r.body().signer == kk.hash && r.body().seq == 1)
        else {
            return;
        };
        let mut body = first.body().clone();
        body.time_ms += 1;
        let Ok(twin) = Record::sign(body, &kk) else { return };
        self.signed.insert(twin.id());
        // The twin reaches one other member of the group, as if a second
        // device had the admin key, and spreads from there.
        let others: Vec<usize> = self.in_group().into_iter().filter(|j| *j != by && *j != t).collect();
        let Some(to) = self.rng.pick(&others) else { return };
        let _ = self.members[to].live.set.insert(twin);
        self.refresh(to);
        self.save(to);
        self.admin_twin = Some((t, self.changes));
        ADMIN_TWINS.fetch_add(1, Ordering::Relaxed);
        self.note(format!("a twin of m{by}'s admin key at seq 1 reaches m{to} after it removed m{t}"));
    }

    fn is_gone(&self, i: usize) -> bool {
        self.gone.is_some_and(|(g, _, _)| g == i)
    }

    /// SIM_ROOT_LOST=1: the root signs a record and a checkpoint that
    /// names it, the checkpoint alone reaches one member, and the root is
    /// lost for good before the record leaves.
    fn root_lost(&mut self) -> Check {
        let Some((by, key)) = self.signer(true) else { return Ok(()) };
        let Some(kind) = self.own_device(by) else { return Ok(()) };
        let others: Vec<usize> = self.in_group().into_iter().filter(|j| *j != by).collect();
        let Some(to) = self.rng.pick(&others) else { return Ok(()) };
        if self.sign(by, &key, kind).is_none() {
            return Ok(());
        }
        let Some(c) = self.write_checkpoint(by, &key) else { return Ok(()) };
        let _ = self.members[to].live.set.insert(c.clone());
        self.refresh(to);
        self.save(to);
        self.crash(by);
        self.members[by].back_at = None;
        self.admitted[by] = false;
        self.gone = Some((by, c.id(), self.changes));
        self.note(format!("the root m{by} is lost; its checkpoint reached m{to} without the record it names"));
        self.after_save(to)
    }

    /// With the root lost and no change of root since: every member that
    /// holds the checkpoint counts the one before, and once missing()
    /// gives up it tells the checkpoint as waiting for records nobody has.
    fn lost_root_holds(&mut self, group: &[usize]) -> Check {
        let Some((_, c, changes)) = self.gone else { return Ok(()) };
        if self.changes != changes {
            return Ok(());
        }
        for i in group {
            let m = &mut self.members[*i].live;
            if !m.set.contains(&c) {
                continue;
            }
            if m.state.counting.contains(&c) {
                return Err(format!("m{i} counts a checkpoint whose named record was lost with the root"));
            }
            let state = m.state.clone();
            for _ in 0..=crate::records::set::MISSING_ROUNDS {
                m.set.missing(&state);
            }
            if !m
                .set
                .stuck_checkpoints()
                .iter()
                .any(|(id, why)| *id == c && *why == crate::records::Stuck::NeverOffered)
            {
                return Err(format!("m{i} raised no notice for a checkpoint waiting for a record nobody has"));
            }
        }
        Ok(())
    }

    /// Whether what the waiting checkpoints of the current root keep
    /// passes one ROOM aside on member i: the stated limit N-1.
    fn past_one_room(&self, i: usize) -> bool {
        let m = &self.members[i].live;
        let Some(root) = m.state.roots.last() else { return false };
        let mut kept: BTreeSet<RecordId> = BTreeSet::new();
        for id in m.set.ids() {
            let Some(r) = m.set.get(id) else { continue };
            if r.body().signer != *root || m.state.counting.contains(id) {
                continue;
            }
            if let Kind::Checkpoint { keep, .. } = &r.body().kind {
                kept.extend(keep.iter().copied());
            }
        }
        let units: u64 = kept
            .iter()
            .filter_map(|id| self.members.iter().find_map(|x| x.live.set.get(id)))
            .map(|r| crate::records::keep::units(r.envelope().len()))
            .sum();
        units > crate::records::keep::room()
    }

    /// The root makes a device an admin.
    fn make_admin(&mut self) -> Check {
        if let Some((by, key)) = self.signer(true)
            && let Some(t) = self.target(by, |d| d.admin.is_none() && !d.frozen)
        {
            let name = format!("sim{}/admin{}", self.seed, self.admins);
            self.admins += 1;
            let ds = self.members[by].live.state.device(&self.members[t].id).unwrap().clone();
            let mut d = self.device_of(by, &ds);
            let (powers, commands) = AdminKind::Phone.grants();
            d.admin = Some(k(&name).key);
            d.powers = powers;
            d.commands = commands;
            self.members[t].live.keys.push(name);
            self.save(t);
            if self.sign(by, &key, Kind::device(d)).is_some() {
                self.note(format!("m{by} makes m{t} an admin"));
                self.after_save(by)?;
            }
        }
        Ok(())
    }

    /// The shape of a cut: an admin's own device signs past its room, so
    /// that its own set turns some of them away and nobody else ever gets
    /// them; later the same key signs again (checkpoints may come between)
    /// and a fresh member joins when one is left; quiet compares them all.
    fn flood(&mut self) -> Check {
        match self.flood.clone() {
            None => {
                let admins: Vec<(usize, String)> =
                    self.in_group().into_iter().filter_map(|i| self.admin_key(i).map(|n| (i, n))).collect();
                if admins.is_empty() {
                    // The shape needs an admin: the root makes one first.
                    if self.admins < MAX_ADMINS {
                        self.make_admin()?;
                    }
                    return Ok(());
                }
                let (by, key) = admins[self.rng.below(admins.len())].clone();
                let n = self.rng.range(6, 9);
                let signed = self.resign(by, &key, n as usize);
                if signed > 0 {
                    self.note(format!("m{by} signs {signed} records with its admin key, past its room"));
                    self.flood = Some((by, key, 1));
                    self.after_save(by)?;
                }
            }
            Some((by, key, 1)) => {
                if !self.members[by].on {
                    return Ok(());
                }
                if self.admin_key(by).as_deref() != Some(key.as_str()) {
                    self.flood = None;
                    return Ok(());
                }
                let n = self.rng.range(2, 3);
                let signed = self.resign(by, &key, n as usize);
                if signed == 0 {
                    return Ok(());
                }
                self.flood = Some((by, key, 2));
                CUT_SHAPE.fetch_add(1, Ordering::Relaxed);
                // A fresh member, when one is left, gets it all at once.
                let free: Vec<usize> = (0..self.members.len()).filter(|t| !self.admitted[*t]).collect();
                if let Some(t) = self.rng.pick(&free)
                    && let Some((root, rk)) = self.signer(true)
                {
                    self.admit_by(root, &rk, t);
                    self.note(format!("m{by} signs {signed} more with its admin key; m{root} admits m{t} fresh"));
                    self.after_save(root)?;
                } else {
                    self.note(format!("m{by} signs {signed} more with its admin key"));
                }
                self.after_save(by)?;
            }
            Some(_) => {}
        }
        Ok(())
    }

    /// Member by signs n device records again, unchanged, with key: the
    /// devices it may edit (not itself, not the root's, not an admin's).
    /// Returns how many it signed: past the room the set drops some.
    fn resign(&mut self, by: usize, key: &str, n: usize) -> usize {
        let mut took = 0;
        for _ in 0..n {
            let Some(t) = self.target(by, |d| d.admin.is_none() && !d.frozen) else { break };
            let Some(ds) = self.members[by].live.state.device(&self.members[t].id).cloned() else { break };
            let d = self.device_of(by, &ds);
            if self.sign(by, key, Kind::device(d)).is_none() {
                break;
            }
            took += 1;
        }
        took
    }

    /// An admitted member goes off until the root has checkpointed two or
    /// three times.
    fn go_away(&mut self) {
        let root = self.signer(true).map(|(by, _)| by);
        let on: Vec<usize> = self
            .on_members()
            .into_iter()
            .filter(|i| self.admitted[*i] && Some(*i) != root && self.members[*i].back_at.is_none())
            .collect();
        if on.len() < 2 {
            return;
        }
        let Some(i) = self.rng.pick(&on) else { return };
        let left = self.rng.range(2, 3) as u32;
        self.crash(i);
        // Back on its own only if the checkpoints never come.
        self.members[i].back_at = Some(self.step + 400);
        self.away = Some((i, left));
        self.note(format!("m{i} is away over {left} checkpoints"));
    }

    /// The owner enters the recovery key on a member and makes it the
    /// root; with fork, on two members from the same seq; with halted, on
    /// a halted member, which ends the halt.
    fn change_root(&mut self, fork: bool, halted: bool) -> Check {
        let g: Vec<usize> = if halted {
            self.on_members()
                .into_iter()
                .filter(|i| {
                    self.admitted[*i]
                        && !self.removed.contains(&self.members[*i].key.hash)
                        && stopped(&self.members[*i].live.state)
                })
                .collect()
        } else {
            self.in_group()
        };
        let Some(i) = self.rng.pick(&g) else { return Ok(()) };
        let tip = self.members[i].live.state.chain().len();
        let other = if fork {
            let same: Vec<usize> =
                g.iter().copied().filter(|j| *j != i && self.members[*j].live.state.chain().len() == tip).collect();
            match self.rng.pick(&same) {
                Some(j) => Some(j),
                None => return Ok(()),
            }
        } else {
            None
        };
        for w in core::iter::once(i).chain(other) {
            let st = self.members[w].live.state.clone();
            // A halted state lists no devices: the member is named anew.
            let device = match st.device(&self.members[w].id) {
                Some(ds) => self.device_of(w, &ds.clone()),
                None => {
                    let mut d = Device::new(self.members[w].key.key.clone(), &format!("m{w}"), ROLE_PHONE);
                    d.rights = RIGHT_READ | RIGHT_SEND | RIGHT_SECRETS;
                    d
                }
            };
            let mut remove = Vec::new();
            if let Some(rd) = st.root_device
                && rd != self.members[w].id
                && self.rng.chance(1, 3)
                && let Some(t) = self.members.iter().position(|x| x.id == rd)
            {
                remove.push(self.members[t].key.hash);
            }
            self.changes += 1;
            let name = format!("sim{}/root{}", self.seed, self.changes);
            let (recovery, new_root) = (k(&self.recovery_name), k(&name));
            let now = self.now(w);
            // The heads of changes the writer holds, and those its state
            // does not apply (waiting for a list, unreadable or void): an
            // honest writer refuses over those and never writes a second
            // head at a seq it holds one for.
            let set = &self.members[w].live.set;
            let chain = st.chain();
            let held: Vec<(u64, RecordId)> = set
                .ids()
                .filter_map(|id| set.get(id))
                .filter(|r| matches!(r.body().kind, Kind::Recovery { .. }))
                .map(|r| (r.body().seq, r.id()))
                .collect();
            let unapplied = held.iter().any(|(_, id)| !chain.contains(id));
            let set = &mut self.members[w].live.set;
            let written =
                match set.write_change(&st, &recovery, crate::testkit::rk2(), &new_root, device, &remove, false, now) {
                    Ok(x) => x,
                    Err(e) if halted => return Err(format!("the recovery key could not end the halt on m{w}: {e:?}")),
                    Err(_) if unapplied => {
                        self.note(format!("m{w} refuses a change over a change it does not apply"));
                        continue;
                    }
                    Err(e) => return Err(format!("m{w} could not write a change of root: {e:?}")),
                };
            self.change_lists.push(written.list.0.clone());
            if let Some((s, _)) = held.iter().find(|(s, _)| *s == written.record.body().seq) {
                return Err(format!("m{w} wrote a second change at seq {s}, where it holds one"));
            }
            if unapplied && !halted {
                return Err(format!("m{w} wrote a change over a change it does not apply"));
            }
            // Any two changes at one seq are a fork, whether written at
            // once on purpose or by members that did not know each other's.
            let (seq, id) = (written.record.body().seq, written.record.id());
            let mut forked = false;
            for (s, other) in &self.heads {
                if *s == seq {
                    self.forks.push((*other, id));
                    forked = true;
                }
            }
            if forked {
                // By which act: the recovery key used twice on purpose
                // (a change asked twice, two carriers), or by members of
                // a split network that did not know each other's change.
                let n = if fork { &FORKS_TWICE } else { &FORKS_SPLIT };
                n.fetch_add(1, Ordering::Relaxed);
            }
            self.heads.push((seq, id));
            let mut records = alloc::vec![written.record.clone()];
            records.extend(written.first.iter().cloned());
            self.signed.extend(records.iter().map(Record::id));
            let m = &mut self.members[w].live;
            m.set.insert_all(records.iter().cloned());
            let _ = m.set.insert_list(&written.list.encode());
            m.set.insert_all(records);
            let last = written.first.last().unwrap();
            m.heads.insert(new_root.hash, (last.body().seq, last.id()));
            m.keys.push(name);
            self.refresh(w);
            self.save(w);
            for h in &remove {
                self.removed.insert(*h);
            }
            self.note(format!("the recovery key makes m{w} the root{}", if fork { " (fork)" } else { "" }));
        }
        for w in core::iter::once(i).chain(other) {
            self.after_save(w)?;
        }
        Ok(())
    }

    fn fault(&mut self) -> Check {
        let n = self.members.len();
        match self.rng.below(100) {
            0..=34 => {
                let on = self.on_members();
                if let (Some(a), Some(b)) = (self.rng.pick(&on), self.rng.pick(&on))
                    && a != b
                    && self.side[a] == self.side[b]
                {
                    for says in self.session(a, b) {
                        self.net.push(Msg { from: a, to: b, says });
                    }
                }
            }
            35..=74 if !self.net.is_empty() => {
                // Any message, not the oldest: the network reorders.
                let x = self.rng.below(self.net.len());
                let msg = self.net.swap_remove(x);
                if self.rng.chance(1, 12) {
                    let again = Msg { from: msg.from, to: msg.to, says: msg.says.clone() };
                    self.net.push(again);
                }
                if self.side[msg.from] == self.side[msg.to] {
                    let crash = self.rng.chance(1, 40);
                    let to = msg.to;
                    self.deliver(msg, crash)?;
                    if crash {
                        self.note(format!("m{to} crashes while taking a message"));
                    }
                }
            }
            75..=79 if !self.net.is_empty() => {
                let x = self.rng.below(self.net.len());
                self.net.swap_remove(x);
            }
            80..=82 => {
                for s in &mut self.side {
                    *s = self.rng.chance(1, 2);
                }
                self.note(String::from("the network splits"));
            }
            83..=86 => {
                self.side = alloc::vec![false; n];
            }
            87..=89 => {
                let on = self.on_members();
                if on.len() > 2
                    && let Some(i) = self.rng.pick(&on)
                {
                    self.crash(i);
                    self.note(format!("m{i} crashes"));
                }
            }
            90..=94 => {
                let down: Vec<usize> = (0..n)
                    .filter(|i| !self.members[*i].on && self.members[*i].back_at.is_none() && !self.is_gone(*i))
                    .collect();
                if let Some(i) = self.rng.pick(&down) {
                    self.restart(i)?;
                    self.note(format!("m{i} restarts"));
                }
            }
            _ => {
                let i = self.rng.below(n);
                let skew = self.rng.range(0, 2 * SKEW_MS) as i64 - SKEW_MS as i64;
                self.members[i].offset = skew;
            }
        }
        Ok(())
    }

    fn run(&mut self, steps: usize) -> Check {
        while self.step < steps {
            self.step += 1;
            self.time += self.rng.range(SECOND, 30 * SECOND);
            for i in 0..self.members.len() {
                if self.members[i].back_at.is_some_and(|s| s <= self.step) {
                    self.restart(i)?;
                    self.note(format!("m{i} is back"));
                }
            }
            if self.rng.chance(1, 4) { self.act()? } else { self.fault()? }
        }
        Ok(())
    }

    /// Heals the network, brings everyone back with the world's clock,
    /// and syncs every pair until nothing changes.
    fn quiet(&mut self) -> Check {
        let n = self.members.len();
        self.side = alloc::vec![false; n];
        for i in 0..n {
            if !self.members[i].on {
                self.restart(i)?;
            }
            self.members[i].offset = 0;
        }
        let print = |w: &World| -> Vec<([u8; 32], usize, usize, usize, usize)> {
            w.members
                .iter()
                .map(|m| {
                    (
                        m.live.set.digest(),
                        m.live.copies.len(),
                        m.live.waiting.len(),
                        m.live.statements.len(),
                        w.shown.len(),
                    )
                })
                .collect()
        };
        for _ in 0..QUIET_ROUNDS {
            let before = print(self);
            while !self.net.is_empty() {
                let x = self.rng.below(self.net.len());
                let msg = self.net.swap_remove(x);
                self.deliver(msg, false)?;
            }
            for a in 0..n {
                for b in 0..n {
                    if a != b {
                        for says in self.session(a, b) {
                            self.deliver(Msg { from: a, to: b, says }, false)?;
                        }
                    }
                }
            }
            // A protocol-shaped session leaves its replies in the net: drain them
            // before comparing, so a quiet round ends only when nothing moves.
            while !self.net.is_empty() {
                let x = self.rng.below(self.net.len());
                let msg = self.net.swap_remove(x);
                self.deliver(msg, false)?;
            }
            if print(self) == before {
                return Ok(());
            }
        }
        Err(format!("the group did not settle in {QUIET_ROUNDS} rounds of sync"))
    }

    /// The checks once quiet: every member of the group holds the same
    /// records, and a restart of each gives back what it wrote. Returns
    /// the members of the group and its state.
    fn settled(&mut self) -> Result<(Vec<usize>, State), String> {
        for i in 0..self.members.len() {
            self.crash(i);
            self.restart(i)?;
        }
        // A fork's proof reaches every member that took one of its heads.
        let mut evidence_lost = false;
        for (i, m) in self.members.iter().enumerate() {
            for (a, b) in &self.forks {
                // Once a change of root ended them, a root's two histories
                // decide nothing and need not reach anyone.
                let ended =
                    self.twin_pairs.iter().any(|(x, y, h)| (x, y) == (a, b) && m.live.state.roots.last() != Some(h));
                let (ha, hb) = (m.live.set.contains(a), m.live.set.contains(b));
                if ha != hb && !ended && !self.is_gone(i) && m.live.state.device_by_key(&m.key.hash).is_some() {
                    // A head that only devices out of m's view hold makes no
                    // split: a removed device, or one whose removal a
                    // checkpoint pruned with its admission, is never handed
                    // the pair; nor one that only a root lost for good held. Counted, as
                    // the evidence dies there.
                    let other = if ha { b } else { a };
                    let removed_only = self.members.iter().enumerate().all(|(k, x)| {
                        !x.live.set.contains(other)
                            || m.live.state.device_by_key(&x.key.hash).is_none()
                            || self.is_gone(k)
                    });
                    if removed_only {
                        evidence_lost = true;
                        continue;
                    }
                    return Err(format!("m{i} took one head of a fork and never the other"));
                }
            }
        }
        let mut count: BTreeMap<[u8; 32], usize> = BTreeMap::new();
        // The members that count themselves in: a removed member that took
        // its removal does not.
        // A halted member lists no devices; it counts itself in all the same.
        let own = |m: &Member| m.live.state.halted() || m.live.state.device_by_key(&m.key.hash).is_some();
        // A root lost for good never comes back, even when a member that
        // never heard of the loss admits its key again.
        for i in (0..self.members.len()).filter(|i| self.admitted[*i] && !self.is_gone(*i) && own(&self.members[*i])) {
            *count.entry(self.members[i].live.set.digest()).or_default() += 1;
        }
        // The group's records: the longest chain of changes of root (a
        // member left behind by one is no reference), then those most
        // members hold, then the more records.
        let rank = |d: &[u8; 32]| {
            let m = self.members.iter().find(|m| m.live.set.digest() == *d).unwrap();
            (m.live.state.chain().len(), count[d], m.live.set.len())
        };
        if evidence_lost {
            EVIDENCE_LOST.fetch_add(1, Ordering::Relaxed);
        }
        // The reference is the root's own view: the member that holds the
        // current root key (the newest chain among those that hold theirs)
        // and whose state names at least one admitted member. Only without
        // one (the root lost for good, or a root that left nobody in) are
        // the members' sets ranked. A member the root's view names neither
        // as a device nor as removed is unknown to the group: it is checked
        // on its own (it must learn it is out), never counted toward the
        // group's records.
        let root_view = (0..self.members.len())
            .filter(|i| self.admitted[*i] && !self.is_gone(*i))
            .filter(|i| {
                let m = &self.members[*i];
                m.live.state.roots.last().is_some_and(|r| m.live.keys.iter().any(|n| k(n).hash == *r))
            })
            .filter(|i| {
                let st = &self.members[*i].live.state;
                st.halted()
                    || (0..self.members.len())
                        .any(|j| self.admitted[j] && st.device_by_key(&self.members[j].key.hash).is_some())
            })
            .max_by_key(|i| self.members[*i].live.state.chain().len())
            .map(|i| self.members[i].live.set.digest());
        if root_view.is_none() {
            RANKED.fetch_add(1, Ordering::Relaxed);
        }
        let Some(digest) = root_view.or_else(|| count.keys().max_by_key(|d| rank(d)).copied()) else {
            // A free keep that dropped the device records leaves nobody in:
            // the root key's power. Nobody may talk to anyone then, so the
            // views cannot meet; what is required is that nobody acts on
            // its own: no member seals a copy.
            if self.deviated {
                let held: Vec<usize> = (0..self.members.len()).filter(|i| self.admitted[*i]).collect();
                for i in held {
                    if self.copy(i, None).is_some() {
                        return Err(format!("m{i} sealed a copy after the root's checkpoint left nobody in"));
                    }
                }
                ROOT_POWER.fetch_add(1, Ordering::Relaxed);
                return Ok((Vec::new(), State::default()));
            }
            return Err(String::from("no member is in the group"));
        };
        let at = self.members.iter().position(|m| m.live.set.digest() == digest).unwrap();
        let state = self.members[at].live.state.clone();
        // A fork's heads go to every peer: once the group is halted, every
        // member that was ever admitted must be halted on the same fork.
        let group: Vec<usize> = (0..self.members.len())
            .filter(|i| {
                self.admitted[*i]
                    && !self.is_gone(*i)
                    && (state.halted() || state.device_by_key(&self.members[*i].key.hash).is_some())
            })
            .collect();
        for i in &group {
            let st = &self.members[*i].live.state;
            // A halted group is compared on being halted and on its fork
            // alone: each member keeps what it held below the fork.
            if state.halted() {
                if !st.halted() || st.fork != state.fork {
                    return Err(format!("m{i} is not halted on the group's fork"));
                }
            } else if self.members[*i].live.set.digest() != digest {
                return Err(format!("m{i} holds other records than the group after the network went quiet"));
            } else if self.aside(*i) != self.aside(at) {
                return Err(format!("m{i} keeps other records aside than m{at} after the network went quiet"));
            }
        }
        if !self.aside(at).is_empty() {
            ASIDE_RUNS.fetch_add(1, Ordering::Relaxed);
        }
        for (i, m) in self.members.iter().enumerate() {
            if !state.halted() && state.revoked.contains(&m.key.hash) && !m.live.state.revoked.contains(&m.key.hash) {
                return Err(format!("removed m{i} never learned its removal"));
            }
        }
        // An admin's removal keeps barring after a twin of that admin key,
        // until a change of root.
        if let Some((t, changes)) = self.admin_twin
            && changes == self.changes
        {
            let h = self.members[t].key.hash;
            for j in group.iter().filter(|j| **j != t) {
                if self.members[*j].live.state.device_by_key(&h).is_some() {
                    return Err(format!(
                        "m{j} counts m{t} again after its admin's removal and a twin of that admin key"
                    ));
                }
            }
        }
        // A member the group's view does not know (its admission dropped by
        // a checkpoint, say) and that still counts itself in.
        for (i, m) in self.members.iter().enumerate() {
            let unknown = !state.halted()
                && !group.contains(&i)
                && !state.revoked.contains(&m.key.hash)
                && !self.is_gone(i)
                && self.admitted[i]
                && m.live.state.device_by_key(&m.key.hash).is_some();
            // Its admission was signed and its writer's own set never kept
            // it (the writer class, until the core's write_record).
            let never_kept = self.admission.get(&i).is_some_and(|r| self.not_kept.contains(r));
            if unknown && never_kept {
                return Err(format!("m{i}, whose admission the group never kept, never learned it is out"));
            } else if unknown && self.removed.contains(&m.key.hash) {
                // Removed, and a checkpoint later pruned the removal with
                // its admission (the rules allow it): it is unknown, never
                // told. Counted; whether it gets a notice is wave 5's.
                UNKNOWN_PRUNED.fetch_add(1, Ordering::Relaxed);
            } else if unknown
                && self.admission.get(&i).is_some_and(|r| !self.members[at].live.set.contains(r))
                && self.heads.is_empty()
            {
                // Kept when signed, never removed, and later dropped from
                // the root's own set by its rooms filling up.
                return Err(format!("m{i}, whose admission the rooms later dropped, never learned it is out"));
            } else if unknown && !self.heads.is_empty() {
                // Kept by its writer, never removed, and a change of root
                // by the recovery key came after. Its list either left the
                // admission out (the recovery's choice, from the writer's
                // view) or named it and the view still lacks it.
                let named =
                    self.admission.get(&i).is_some_and(|r| self.change_lists.last().is_some_and(|l| l.contains(r)));
                if named {
                    return Err(format!("m{i}, named by the last change's list, is unknown to the group"));
                }
                // The recovery's choice, from the writer's view: counted
                // with the pruned removals, a notice question for wave 5.
                LEFT_OUT.fetch_add(1, Ordering::Relaxed);
            } else if unknown {
                return Err(format!("m{i}, unknown to the group, never learned it is out"));
            }
        }
        for i in 0..self.members.len() {
            self.after_save(i)?;
        }
        Ok((group, state))
    }

    /// A last copy from a member of the group, newer than any: after the
    /// network goes quiet every reader shows it.
    fn last_copy(&mut self, group: &[usize], state: &State) -> Check {
        let senders: Vec<usize> = group
            .iter()
            .copied()
            .filter(|i| state.device(&self.members[*i].id).is_some_and(|d| !d.frozen && d.rights & RIGHT_SEND != 0))
            .collect();
        let Some(i) = self.rng.pick(&senders) else { return Ok(()) };
        let newest = self.members.iter().map(|m| m.live.last.wall).max().unwrap_or(0).max(self.time as i64);
        // A root lost for good is still a device to the others: the copy
        // is sealed to it too while its keys statement lasts, and it never
        // shows it. Once that statement ages out, it is sealed to no more.
        let gone = self.gone.map(|(g, _, _)| g);
        let gone_id = gone.and_then(|g| state.device(&self.members[g].id)).map(|d| d.id);
        let expect: BTreeSet<DeviceId> = group
            .iter()
            .filter(|j| **j != i)
            .filter_map(|j| state.device(&self.members[*j].id))
            .filter(|d| !d.frozen && d.rights & RIGHT_READ != 0 && !state.nothing_to.contains(&d.id))
            .map(|d| d.id)
            .collect();
        let Some((id, readers)) = self.copy(i, Some(newest as u64 + 1)) else {
            if expect.is_empty() {
                return Ok(());
            }
            return Err(format!("m{i} could not seal its last copy"));
        };
        let mut readers: BTreeSet<DeviceId> = readers.into_iter().collect();
        if let Some(g) = gone_id {
            readers.remove(&g);
        }
        if readers != expect {
            return Err(format!("m{i} sealed its last copy to {} readers of {}", readers.len(), expect.len()));
        }
        self.quiet()?;
        let origin = self.members[i].id;
        for j in group.iter().filter(|j| expect.contains(&self.members[**j].id)) {
            if !self.shown.contains(&(*j, origin, id)) {
                return Err(format!("m{j} never showed m{i}'s last copy"));
            }
        }
        Ok(())
    }

    fn finish(&mut self) -> Check {
        self.quiet()?;
        self.no_twins()?;
        let (mut group, mut state) = self.settled()?;
        if group.is_empty() {
            return Ok(());
        }
        self.lost_root_holds(&group)?;
        let recovery_fork = state.fork.is_some_and(|(_, a, b)| {
            self.members.iter().any(|m| {
                [a, b]
                    .iter()
                    .any(|id| m.live.set.get(id).is_some_and(|r| matches!(r.body().kind, Kind::Recovery { .. })))
            })
        });
        if state.halted() && recovery_fork {
            // Two changes of root at one seq stop the group for good (rule
            // 33): every member that holds both heads is halted and seals
            // nothing, the recovery key cannot write past it, and the group
            // is made again.
            let (_, a, b) = state.fork.unwrap();
            for i in 0..self.members.len() {
                let m = &self.members[i].live;
                if m.set.contains(&a) && m.set.contains(&b) {
                    if !m.state.halted() {
                        return Err(format!("m{i} holds both changes of root at one seq and is not halted"));
                    }
                    if self.copy(i, None).is_some() {
                        return Err(format!("halted m{i} sealed a copy"));
                    }
                }
            }
            return match self.change_root(false, true) {
                Err(e) if e.starts_with("the recovery key could not end the halt") => Ok(()),
                Err(e) => Err(e),
                Ok(())
                    if self
                        .on_members()
                        .iter()
                        .all(|i| !self.admitted[*i] || !self.members[*i].live.state.halted()) =>
                {
                    Err(String::from("a change of root was written past two changes at one seq"))
                }
                Ok(()) => Ok(()),
            };
        }
        if root_forked(&state) {
            // Halted, records are still taken: every member holds the
            // same records and the same state.
            let first = &self.members[group[0]].live;
            for i in &group {
                let m = &self.members[*i].live;
                if !root_forked(&m.state) {
                    return Err(format!("m{i} is not halted with the group"));
                }
                if m.set.digest() != first.set.digest() || m.state != first.state {
                    return Err(format!("halted m{i} holds other records or another state than m{}", group[0]));
                }
            }
            // Nothing is sealed while halted; a change of root by the
            // recovery key ends it.
            for i in group.clone() {
                if self.copy(i, None).is_some() {
                    return Err(format!("halted m{i} sealed a copy"));
                }
            }
            self.change_root(false, true)?;
            self.quiet()?;
            self.no_twins()?;
            (group, state) = self.settled()?;
            if stopped(&state) {
                return Err(String::from("the group is still halted after a change of root"));
            }
        }
        for _ in 0..2 {
            self.last_copy(&group, &state)?;
        }
        Ok(())
    }
}

/// One seed's run: Ok, or what failed with the last events.
fn run(seed: u64, steps: usize) -> Result<(), String> {
    let _rooms = small_seed(seed).then(small_rooms);
    let mut w = World::new(seed);
    let r = w.run(steps).and_then(|()| w.finish());
    // A split after a deviating checkpoint is the stated limit N-1 when
    // the waiting checkpoints keep more than one ROOM aside.
    let r = r.map_err(|e| {
        if w.admin_twin.is_some() {
            return format!("admin twin (expected until the core's fix): {e}");
        }
        if !w.deviated {
            return e;
        }
        let n1 = (0..w.members.len()).any(|i| w.past_one_room(i));
        if n1 { format!("N-1: {e}") } else { format!("finding with a deviating root: {e}") }
    });
    SMALL_RUNS.fetch_add(usize::from(w.small), Ordering::Relaxed);
    CAME_BACK.fetch_add(w.came_back, Ordering::Relaxed);
    ASIDE_SEEN.fetch_add(usize::from(w.aside_seen), Ordering::Relaxed);
    r.map_err(|e| format!("{e}\n  at step {} of {steps}; last events:\n{}", w.step, w.log.join("\n")))
}

/// The fewest steps of seed's run that still fail, by halving and then
/// stepping down: a run is the prefix of a longer one.
fn shrink(seed: u64, steps: usize) -> usize {
    let mut best = steps;
    let mut n = steps / 2;
    while n > 0 && run(seed, n).is_err() {
        best = n;
        n /= 2;
    }
    let mut lo = n;
    let mut hi = best;
    while lo + 1 < hi {
        let mid = (lo + hi) / 2;
        if run(seed, mid).is_err() { hi = mid } else { lo = mid }
    }
    hi
}

/// SIM_WHOLE=1: every session hands whole sets at once, as the first
/// simulator did, so that its seeds replay.
fn whole_sync() -> bool {
    env("SIM_WHOLE") == Some(1)
}

static FORKS_TWICE: AtomicUsize = AtomicUsize::new(0);
static FORKS_SPLIT: AtomicUsize = AtomicUsize::new(0);
/// Settled runs whose sets keep records aside for a later checkpoint.
static ASIDE_RUNS: AtomicUsize = AtomicUsize::new(0);
static SMALL_RUNS: AtomicUsize = AtomicUsize::new(0);
static CAME_BACK: AtomicUsize = AtomicUsize::new(0);
static ASIDE_SEEN: AtomicUsize = AtomicUsize::new(0);
static EVIDENCE_LOST: AtomicUsize = AtomicUsize::new(0);
static ROOT_POWER: AtomicUsize = AtomicUsize::new(0);
static CUT_SHAPE: AtomicUsize = AtomicUsize::new(0);
static NOT_KEPT: AtomicUsize = AtomicUsize::new(0);
static CP_REFUSED: AtomicUsize = AtomicUsize::new(0);
/// Settled checks without a root's view to compare with (the sets ranked).
static RANKED: AtomicUsize = AtomicUsize::new(0);
/// Removed members a checkpoint later made unknown, still counting
/// themselves in.
static UNKNOWN_PRUNED: AtomicUsize = AtomicUsize::new(0);
/// Ordinary records the core's writer refused (nothing written).
static REFUSED: AtomicUsize = AtomicUsize::new(0);
/// Members a change of root's list left out that still count themselves in.
static LEFT_OUT: AtomicUsize = AtomicUsize::new(0);
/// The core writer's refusals by reason.
static REFUSED_CEILING: AtomicUsize = AtomicUsize::new(0);
static REFUSED_NO_ROOM: AtomicUsize = AtomicUsize::new(0);
static REFUSED_GROUP_FULL: AtomicUsize = AtomicUsize::new(0);
static REFUSED_STOPPED: AtomicUsize = AtomicUsize::new(0);
static REFUSED_TWO_HISTORIES: AtomicUsize = AtomicUsize::new(0);
static REFUSED_OTHER: AtomicUsize = AtomicUsize::new(0);
/// Runs with a twin of an admin key after its removal (SIM_ADMIN_TWIN).
static ADMIN_TWINS: AtomicUsize = AtomicUsize::new(0);

/// The counter of a refusal of the core's writer, by its message.
fn refused_why(e: &str) -> &'static AtomicUsize {
    if e.contains("would pass its room") {
        &REFUSED_CEILING
    } else if e.contains("has no room in the group") {
        &REFUSED_NO_ROOM
    } else if e.contains("have no room for the record") {
        &REFUSED_GROUP_FULL
    } else if e.contains("group is stopped") {
        &REFUSED_STOPPED
    } else if e.contains("two histories") {
        &REFUSED_TWO_HISTORIES
    } else {
        &REFUSED_OTHER
    }
}

const COUNTERS: [&AtomicUsize; 22] = [
    &ADMIN_TWINS,
    &REFUSED_CEILING,
    &REFUSED_NO_ROOM,
    &REFUSED_GROUP_FULL,
    &REFUSED_STOPPED,
    &REFUSED_TWO_HISTORIES,
    &REFUSED_OTHER,
    &LEFT_OUT,
    &REFUSED,
    &UNKNOWN_PRUNED,
    &RANKED,
    &NOT_KEPT,
    &CP_REFUSED,
    &FORKS_TWICE,
    &FORKS_SPLIT,
    &ASIDE_RUNS,
    &SMALL_RUNS,
    &CAME_BACK,
    &ASIDE_SEEN,
    &EVIDENCE_LOST,
    &ROOT_POWER,
    &CUT_SHAPE,
];

/// Root twins (two writers with one key) are made unless SIM_TWINS=0.
/// Every SIM_SMALL-th seed (4 by default, 0 for none) runs with small
/// rooms, SIM_ROOMS="room,root,admin" (14,8,5 by default, as the records
/// model's traces), and with a member away over checkpoints.
fn small_seed(seed: u64) -> bool {
    let k = env("SIM_SMALL").unwrap_or(4);
    k != 0 && seed % k == k - 1
}

fn small_rooms() -> crate::records::keep::small::Small {
    let v: Vec<u64> = std::env::var("SIM_ROOMS")
        .ok()
        .map(|s| s.split(',').filter_map(|x| x.trim().parse().ok()).collect())
        .unwrap_or_default();
    let (room, root, admin) = match v[..] {
        [a, b, c] => (a, b, c),
        _ => (14, 8, 5),
    };
    crate::records::keep::small::Small::new(room, root, admin)
}

fn twins_on() -> bool {
    env("SIM_TWINS") != Some(0)
}

fn env(name: &str) -> Option<u64> {
    std::env::var(name).ok().and_then(|v| v.parse().ok())
}

#[test]
fn groups_under_faults_agree() {
    let steps = env("SIM_STEPS").unwrap_or(300) as usize;
    let seeds: Vec<u64> = match env("SIM_SEED") {
        Some(s) => alloc::vec![s],
        None => {
            let first = env("SIM_FIRST").unwrap_or(0);
            (first..first + env("SIM_SEEDS").unwrap_or(16)).collect()
        }
    };
    // SIM_ALL=1 runs every seed and lists each failure, for a nightly run.
    let all = env("SIM_ALL") == Some(1);
    let mut failed = Vec::new();
    let n = seeds.len();
    for seed in seeds {
        if let Err(e) = run(seed, steps) {
            let counted = COUNTERS.map(|c| c.load(Ordering::Relaxed));
            let small = shrink(seed, steps);
            let e = run(seed, small).err().unwrap_or(e);
            for (c, v) in COUNTERS.into_iter().zip(counted) {
                c.store(v, Ordering::Relaxed);
            }
            failed.push(format!(
                "sim seed {seed} failed: {e}\nreplay: SIM_SEED={seed} SIM_STEPS={small} cargo test -p cbb-core --lib sim::"
            ));
            if !all {
                break;
            }
        }
    }
    std::eprintln!(
        "sim: {n} seeds; recovery forks: {} by the key used twice, {} by a split network; {} settled with records aside; {} with small rooms, {} members back after the checkpoints they were away for, {} runs kept a record aside on the way; {} runs where a root's twin lived only on removed devices; {} runs where a deviating root's checkpoint left nobody in; {} runs where an admin signed past its own room and later again beside a fresh member; {} records their writer's own set did not keep; {} checkpoints the core's writer refused; {} settled checks without a root's view; {} removed members a checkpoint made unknown that still count themselves in; {} ordinary records the core's writer refused; {} members a change of root's list left out that still count themselves in",
        FORKS_TWICE.load(Ordering::Relaxed),
        FORKS_SPLIT.load(Ordering::Relaxed),
        ASIDE_RUNS.load(Ordering::Relaxed),
        SMALL_RUNS.load(Ordering::Relaxed),
        CAME_BACK.load(Ordering::Relaxed),
        ASIDE_SEEN.load(Ordering::Relaxed),
        EVIDENCE_LOST.load(Ordering::Relaxed),
        ROOT_POWER.load(Ordering::Relaxed),
        CUT_SHAPE.load(Ordering::Relaxed),
        NOT_KEPT.load(Ordering::Relaxed),
        CP_REFUSED.load(Ordering::Relaxed),
        RANKED.load(Ordering::Relaxed),
        UNKNOWN_PRUNED.load(Ordering::Relaxed),
        REFUSED.load(Ordering::Relaxed),
        LEFT_OUT.load(Ordering::Relaxed)
    );
    std::eprintln!(
        "sim refusals: {} past the key's ceiling (checkpoint first), {} a key without a room, {} the group's records full, {} a stopped group, {} a key with two histories, {} other; {} runs with an admin key's twin after its removal",
        REFUSED_CEILING.load(Ordering::Relaxed),
        REFUSED_NO_ROOM.load(Ordering::Relaxed),
        REFUSED_GROUP_FULL.load(Ordering::Relaxed),
        REFUSED_STOPPED.load(Ordering::Relaxed),
        REFUSED_TWO_HISTORIES.load(Ordering::Relaxed),
        REFUSED_OTHER.load(Ordering::Relaxed),
        ADMIN_TWINS.load(Ordering::Relaxed)
    );
    assert!(failed.is_empty(), "{}", failed.join("\n\n"));
}

#[test]
fn a_seed_replays_exactly() {
    let trace = |seed| {
        let mut w = World::new(seed);
        w.run(120).unwrap();
        let digests: Vec<[u8; 32]> = w.members.iter().map(|m| m.live.set.digest()).collect();
        (w.log.clone(), digests, w.shown.clone())
    };
    assert_eq!(trace(7), trace(7));
}

#[test]
fn records_before_their_list_end_as_after() {
    // A member that gets a new root's records before the change's list
    // ends where the writer is after those two messages: no second round
    // of sync. A list that comes before its recovery record cannot be
    // known for that record's yet; the member asks for it
    // (`list_missing`) and ends there once it comes again.
    let mut w = (0u64..).map(World::new).find(|w| w.admitted.iter().filter(|a| **a).count() >= 3).unwrap();
    w.quiet().unwrap();
    w.change_root(false, false).unwrap();
    let writer = w.members.iter().position(|m| m.live.state.chain().len() == 1).unwrap();
    let mut others = w.in_group().into_iter().filter(|i| *i != writer && w.admitted[*i]);
    let (a, b) = (others.next().unwrap(), others.next().unwrap());
    let full = w.offer(writer, a);
    let records = Offer { records: full.records.clone(), ..Offer::default() };
    let lists = Offer { lists: full.lists.clone(), ..Offer::default() };
    assert!(!lists.lists.is_empty());
    let take = |w: &mut World, i: usize, o: &Offer| {
        exchange::take(&mut w.members[i].live.set, o);
        w.refresh(i);
    };
    take(&mut w, a, &records);
    take(&mut w, a, &lists);
    take(&mut w, b, &lists);
    take(&mut w, b, &records);
    assert!(w.members[b].live.state.list_missing.is_some(), "m{b} does not ask for the list");
    take(&mut w, b, &full);
    let want = &w.members[writer].live;
    for i in [a, b] {
        assert_eq!(w.members[i].live.set.digest(), want.set.digest(), "m{i}");
        assert_eq!(w.members[i].live.state, want.state, "m{i}");
    }
}
