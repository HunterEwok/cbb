// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! An independent reading of acknowledgements and take-backs (section 10),
//! through the record set's public writer only: a key a root took back is
//! never an admin again, whatever the root's checkpoints left out, and what
//! the key signed that the root never got never counts.

use std::collections::BTreeMap;

use cbb_core::identity::ExternalKey;
use cbb_core::records::body::{Device, MIN_COPY_TTL_MS, RIGHT_READ, RIGHT_SEND, ROLE_MEMBER, ROLE_PHONE};
use cbb_core::records::key::group_id;
use cbb_core::records::set::{ADMIN_KEY_TAKEN_BACK, ADMIN_SILENCE_MS};
use cbb_core::records::{Body, Key, KeyHash, Kind, Record, RecordId, RecordSet, State};
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

/// Signs an admin's records apart from the set, as its own device does.
struct Chain {
    heads: BTreeMap<KeyHash, (u64, RecordId)>,
}

impl Chain {
    /// Signs as the honest writer does (see `honest`).
    fn sign(&mut self, set: &RecordSet, by: &K, kind: Kind, time_ms: u64) -> Record {
        let kind = if self.heads.contains_key(&by.hash) { kind } else { Self::honest(set, kind) };
        self.sign_raw(set, by, kind, time_ms)
    }

    /// As the honest writer signs: a key's first record carries, when its
    /// own seen is empty, the current root's head the set holds, so that it
    /// sits above the seen line.
    fn honest(set: &RecordSet, kind: Kind) -> Kind {
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
    fn sign_raw(&mut self, set: &RecordSet, by: &K, kind: Kind, time_ms: u64) -> Record {
        let (seq, prev) = self.heads.get(&by.hash).map_or((1, None), |(s, id)| (s + 1, Some(*id)));
        let body = Body { group: set.group(), signer: by.hash, seq, prev, time_ms, kind, held: false };
        let r = Record::sign(body, by).unwrap();
        self.heads.insert(by.hash, (seq, r.id()));
        r
    }
}

const POWERS: u64 = 0x1ff & !64;

fn device(member: &K, name: &str, admin: Option<&K>) -> Kind {
    let mut d = Device::new(member.key.clone(), name, if admin.is_some() { ROLE_PHONE } else { ROLE_MEMBER });
    d.rights = RIGHT_READ | RIGHT_SEND;
    if let Some(a) = admin {
        d.admin = Some(a.key.clone());
        d.powers = POWERS;
    }
    Kind::device(d)
}

fn has(s: &State, member: &K) -> bool {
    s.device_by_key(&member.hash).is_some()
}

/// How the admin key is first named.
#[derive(Clone, Copy, Debug)]
enum Named {
    /// In the device's admission (a phone that joins as an admin).
    AtAdmission,
    /// In a later record of the device (a member made an admin later), so
    /// the device's oldest record names no admin key.
    Later,
    /// Later, then the device record is changed once more while the key is
    /// an admin, so the record that first named it is neither the oldest
    /// nor the newest.
    LaterThenChanged,
}

/// The root names admin key A for phone P, A admits x (the root gets it)
/// and d (the root never gets it), the root takes A back for silence, and
/// writes `checkpoints` checkpoints. Returns the set, the root, P, A and
/// the record of d.
fn taken_back(named: Named, checkpoints: usize) -> (RecordSet, K, K, K, Record, u64) {
    let root = k("root");
    let (p, a) = (k("phone p"), k("admin a"));
    let recovery = cbb_core::records::Recovery {
        k1: k("recovery").key,
        k2: cbb_core::records::pq::PqKey::from_seeds(&[0x31; 16], &[0x32; 16], &[0x33; 16]).key(),
    };
    assert_eq!(group_id(&root.key, &recovery), group_id(&root.key, &recovery));
    let mut set = RecordSet::new(root.key.clone(), recovery);
    let mut t = 1000;
    let w = |set: &mut RecordSet, kind: Kind, t: &mut u64| {
        *t += 1000;
        let st = set.state();
        set.write_record(&st, &root, kind, *t).unwrap_or_else(|e| panic!("{named:?}: {e:?}"));
    };
    w(&mut set, Kind::Copies { secret_ttl_ms: 0, ttl_ms: MIN_COPY_TTL_MS, seen: vec![] }, &mut t);
    match named {
        Named::AtAdmission => w(&mut set, device(&p, "phone", Some(&a)), &mut t),
        Named::Later | Named::LaterThenChanged => {
            w(&mut set, device(&p, "phone", None), &mut t);
            w(&mut set, device(&p, "phone", Some(&a)), &mut t);
        }
    }
    if matches!(named, Named::LaterThenChanged) {
        w(&mut set, device(&p, "phone renamed", Some(&a)), &mut t);
    }
    let mut chain = Chain { heads: BTreeMap::new() };
    t += 1000;
    let x = chain.sign(&set, &a, device(&k("x"), "x", None), t);
    set.insert(x).unwrap();
    t += 1000;
    let late = chain.sign(&set, &a, device(&k("d"), "d", None), t);
    assert!(has(&set.state(), &k("x")), "{named:?}: the admin's admission counts");
    t += ADMIN_SILENCE_MS + 1000;
    let st = set.state();
    let back = set.take_back_lagging(&st, &root, &BTreeMap::from([(a.hash, 0)]), t).unwrap();
    assert_eq!(back.len(), 1, "{named:?}: the silent key is taken back");
    let st = set.state();
    assert!(st.device_by_key(&p.hash).is_some_and(|d| d.admin.is_none()), "{named:?}: taken back");
    for i in 0..checkpoints {
        // Something between checkpoints, so each one has a reason.
        w(&mut set, device(&k(&format!("filler {i}")), "filler", None), &mut t);
        t += 1000;
        let st = set.state();
        let cp = set.write_checkpoint(&st, &root, t).unwrap_or_else(|e| panic!("{named:?}: {e:?}"));
        let _ = set.insert(cp.clone());
        assert_eq!(set.state().checkpoint, Some(cp.id()), "{named:?}: checkpoint {i} counts");
    }
    (set, root, p, a, late, t)
}

/// After any number of checkpoints, the root's writer refuses to name the
/// taken-back key again, and the key's admission the root never got
/// counts for nothing, at the writer and at a member restored from it.
fn never_granted_again(named: Named, checkpoints: usize) {
    let (mut set, root, p, a, late, t) = taken_back(named, checkpoints);
    let st = set.state();
    let again = set.write_record(&st, &root, device(&p, "phone", Some(&a)), t + 1000);
    match again {
        Err(e) => assert!(
            format!("{e}").contains(ADMIN_KEY_TAKEN_BACK),
            "{named:?} after {checkpoints} checkpoints: refused for another reason: {e}"
        ),
        Ok(_) => {
            // Granted: show what that costs before failing.
            let _ = set.insert(late.clone());
            let back = has(&set.state(), &k("d"));
            panic!(
                "{named:?} after {checkpoints} checkpoints: the writer named the taken-back key again; \
                 its admission the root never got counts again: {back}"
            );
        }
    }
    let _ = set.insert(late);
    assert!(!has(&set.state(), &k("d")), "{named:?}: the late admission counts for nothing");
}

#[test]
fn a_key_named_at_admission_is_never_granted_again() {
    for n in [0, 1, 3] {
        never_granted_again(Named::AtAdmission, n);
    }
}

#[test]
fn a_key_named_later_is_never_granted_again() {
    for n in [0, 1, 3] {
        never_granted_again(Named::Later, n);
    }
}

#[test]
fn a_key_named_in_a_middle_record_is_never_granted_again() {
    for n in [0, 1, 3] {
        never_granted_again(Named::LaterThenChanged, n);
    }
}

/// The same key after its device was removed and the removal settled: the
/// root takes A back, then removes P; once the checkpoints have let the
/// removal go, nothing the set holds names A. P comes back by a new
/// admission (a phone keeps its keys until it leaves the group) and asks
/// for A again, as a phone does today (its admin key under one label).
#[test]
fn a_taken_back_key_of_a_removed_device_is_never_granted_again() {
    for named in [Named::AtAdmission, Named::Later] {
        let (mut set, root, p, a, late, mut t) = taken_back(named, 1);
        let x_id = late.body().prev.unwrap();
        let x = set.get(&x_id).cloned().expect("the root holds the admin's first admission");
        t += 1000;
        let st = set.state();
        for r in set.write_removal(&st, &root, &[p.hash], t).unwrap() {
            let _ = set.insert(r);
        }
        assert!(!has(&set.state(), &p), "{named:?}: removed");
        for i in 0..3 {
            t += 1000;
            let st = set.state();
            for r in set.write_record(&st, &root, device(&k(&format!("after {i}")), "after", None), t).unwrap() {
                let _ = set.insert(r);
            }
            t += 1000;
            let st = set.state();
            let cp = set.write_checkpoint(&st, &root, t).unwrap();
            let _ = set.insert(cp);
        }
        let st = set.state();
        let removal_held = st.revoked.contains(&p.hash);
        let naming_held = set
            .in_dependency_order()
            .into_iter()
            .any(|r| matches!(&r.body().kind, Kind::Device(d) if d.admin.as_ref().map(Key::hash) == Some(a.hash)));
        eprintln!("{named:?}: removal still held: {removal_held}; a record naming A held: {naming_held}");
        t += 1000;
        let again = set.write_record(&st, &root, device(&p, "phone back", Some(&a)), t);
        match again {
            Err(e) => {
                let why = format!("{e}");
                assert!(
                    why.contains(ADMIN_KEY_TAKEN_BACK) || removal_held,
                    "{named:?}: refused for another reason: {why}"
                );
            }
            Ok(rs) => {
                for r in rs {
                    let _ = set.insert(r);
                }
                let _ = set.insert(x.clone());
                let _ = set.insert(late.clone());
                let back = has(&set.state(), &k("d"));
                panic!(
                    "{named:?}: after the removal settled, the writer named the taken-back key A again \
                     (removal held {removal_held}, naming record held {naming_held}); the admission A \
                     signed before its take-back, which the root never got, counts again: {back}"
                );
            }
        }
    }
}

/// The room trigger and a removal just written: three admins have
/// acknowledged everything; the root's room passes three quarters; the
/// root removes a device, which no admin can have seen yet. A take-back
/// right then should not take every admin back for a removal seconds old.
#[test]
fn a_fresh_removal_past_three_quarters_does_not_take_every_admin_back() {
    let root = k("root");
    let recovery = cbb_core::records::Recovery {
        k1: k("recovery").key,
        k2: cbb_core::records::pq::PqKey::from_seeds(&[0x31; 16], &[0x32; 16], &[0x33; 16]).key(),
    };
    let mut set = RecordSet::new(root.key.clone(), recovery);
    let mut t = 1000u64;
    let w = |set: &mut RecordSet, kind: Kind, t: &mut u64| {
        *t += 1000;
        let st = set.state();
        set.write_record(&st, &root, kind, *t)
    };
    w(&mut set, Kind::Copies { secret_ttl_ms: 0, ttl_ms: MIN_COPY_TTL_MS, seen: vec![] }, &mut t).unwrap();
    let admins: Vec<(K, K)> = (0..3).map(|i| (k(&format!("phone {i}")), k(&format!("admin {i}")))).collect();
    for (p, a) in &admins {
        w(&mut set, device(p, "phone", Some(a)), &mut t).unwrap();
    }
    let victim = k("victim");
    w(&mut set, device(&victim, "victim", None), &mut t).unwrap();
    // Fill the root's room with records that change nothing.
    let cap = 1536u64;
    let mut n = 0;
    loop {
        let room = set.room_of(&root.hash);
        if room.is_some_and(|r| r.used * 4 > cap * 3) {
            break;
        }
        let ms = MIN_COPY_TTL_MS + n;
        if w(&mut set, Kind::Copies { secret_ttl_ms: 0, ttl_ms: ms, seen: vec![] }, &mut t).is_err() {
            break;
        }
        n += 1;
        assert!(n < 2000, "the room never passed three quarters");
    }
    let room = set.room_of(&root.hash).unwrap();
    eprintln!("root room used {} of {} after {n} fillers", room.used, room.cap);
    // Every admin acknowledges what it holds.
    for (_, a) in &admins {
        let st = set.state();
        set.write_ack(&st, a, t).unwrap();
    }
    let st = set.state();
    assert!(set.unacknowledged(&st).values().all(|n| *n == 0));
    t += 1000;
    for r in set.write_removal(&st, &root, &[victim.hash], t).unwrap() {
        let _ = set.insert(r);
    }
    t += 1000;
    let heard: BTreeMap<KeyHash, u64> = admins.iter().map(|(_, a)| (a.hash, t)).collect();
    let st = set.state();
    let back = set.take_back_lagging(&st, &root, &heard, t).unwrap();
    assert!(
        back.is_empty(),
        "{} of 3 admins, all heard from a second ago and up to date until the removal just written, \
         are taken back by the room trigger",
        back.len()
    );
}

/// Records' limit, tried on an honest path: the root changes the device
/// many times (rights, name, the admin key set, cleared by hand, more
/// changes), with a checkpoint after each; the record that named the
/// admin key is a middle record. The checkpoints never drop it, and the
/// writer refuses the key again.
#[test]
fn a_key_named_only_in_a_middle_record_stays_known() {
    let root = k("root");
    let (p, a) = (k("phone p"), k("admin a"));
    let recovery = cbb_core::records::Recovery {
        k1: k("recovery").key,
        k2: cbb_core::records::pq::PqKey::from_seeds(&[0x31; 16], &[0x32; 16], &[0x33; 16]).key(),
    };
    let mut set = RecordSet::new(root.key.clone(), recovery);
    let mut t = 1000u64;
    let write = |set: &mut RecordSet, kind: Kind, t: &mut u64| {
        *t += 1000;
        let st = set.state();
        let r = set.write_record(&st, &root, kind, *t).unwrap().pop().unwrap();
        *t += 1000;
        let st = set.state();
        let cp = set.write_checkpoint(&st, &root, *t).unwrap();
        let _ = set.insert(cp);
        r
    };
    write(&mut set, Kind::Copies { secret_ttl_ms: 0, ttl_ms: MIN_COPY_TTL_MS, seen: vec![] }, &mut t);
    let plain = |name: &str, rights: u64| {
        let mut d = Device::new(p.key.clone(), name, ROLE_MEMBER);
        d.rights = rights;
        Kind::device(d)
    };
    write(&mut set, plain("p", RIGHT_READ), &mut t);
    write(&mut set, plain("p", RIGHT_READ | RIGHT_SEND), &mut t);
    write(&mut set, plain("p renamed", RIGHT_READ | RIGHT_SEND), &mut t);
    let naming = write(&mut set, device(&p, "p renamed", Some(&a)), &mut t);
    // Cleared by an ordinary update, as a root that takes the key back by hand.
    write(&mut set, plain("p renamed", RIGHT_READ | RIGHT_SEND), &mut t);
    write(&mut set, plain("p again", RIGHT_READ | RIGHT_SEND), &mut t);
    write(&mut set, plain("p again", RIGHT_READ), &mut t);
    write(&mut set, plain("p last", RIGHT_READ), &mut t);
    let held = set.contains(&naming.id());
    let devices_of_p = set
        .in_dependency_order()
        .into_iter()
        .filter(|r| matches!(&r.body().kind, Kind::Device(d) if d.key.hash() == p.hash))
        .count();
    eprintln!("the naming record held: {held}; records of p held: {devices_of_p}");
    let st = set.state();
    assert!(st.device_by_key(&p.hash).is_some_and(|d| d.admin.is_none()));
    let err = set
        .write_record(&st, &root, device(&p, "p", Some(&a)), t + 1000)
        .expect_err("the writer named a key the root had cleared, after checkpoints dropped the middle records");
    assert!(format!("{err}").contains(ADMIN_KEY_TAKEN_BACK), "{err}");
    assert!(held, "the record that named the admin key was dropped");
}

/// The notices on acknowledgements: a removal waits for the admin key,
/// its device owes an acknowledgement, the key is silent past the
/// threshold; after the acknowledgement nothing waits or is owed.
#[test]
fn the_notices_tell_what_waits_for_whom() {
    let root = k("root");
    let (p, a) = (k("phone p"), k("admin a"));
    let recovery = cbb_core::records::Recovery {
        k1: k("recovery").key,
        k2: cbb_core::records::pq::PqKey::from_seeds(&[0x31; 16], &[0x32; 16], &[0x33; 16]).key(),
    };
    let mut set = RecordSet::new(root.key.clone(), recovery);
    let mut t = 1000u64;
    for kind in [
        Kind::Copies { secret_ttl_ms: 0, ttl_ms: MIN_COPY_TTL_MS, seen: vec![] },
        device(&p, "phone", Some(&a)),
        device(&k("victim"), "victim", None),
    ] {
        t += 1000;
        let st = set.state();
        set.write_record(&st, &root, kind, t).unwrap();
    }
    let named = t - 1000;
    let st = set.state();
    assert!(set.removals_waiting(&st).is_empty() && set.ack_owed(&st, &a.hash, t).is_none());
    t += 1000;
    for r in set.write_removal(&st, &root, &[k("victim").hash], t).unwrap() {
        let _ = set.insert(r);
    }
    let st = set.state();
    let waiting = set.removals_waiting(&st);
    assert_eq!(waiting.len(), 1);
    assert_eq!(waiting[0].keys, vec![k("victim").hash]);
    assert_eq!(waiting[0].waits_for, vec![a.hash]);
    let owed = set.ack_owed(&st, &a.hash, t).expect("an acknowledgement is owed");
    assert_eq!((owed.removals, owed.days_left), (1, 35));
    assert!(set.root_room_waiting(&st, 1).is_none(), "one unit is under 1% of the root's room");
    assert!(set.root_room_waiting(&st, 0).is_some_and(|w| w.waiting == 1 && w.waiting_units >= 1));
    let heard = BTreeMap::new();
    let day = 86_400_000;
    assert!(set.admins_silent(&st, &heard, named + 6 * day, 7 * day).is_empty());
    let silent = set.admins_silent(&st, &heard, named + 34 * day, 7 * day);
    assert_eq!(silent.len(), 1);
    assert_eq!((silent[0].key, silent[0].since_ms, silent[0].days_left, silent[0].holds_back), (a.hash, named, 1, 1));
    let due = set.admins_silent(&st, &heard, named + ADMIN_SILENCE_MS, 7 * day);
    assert_eq!(due[0].days_left, 0, "due on the day take_back_lagging takes it");
    // Heard from yesterday: not silent for a week.
    let heard = BTreeMap::from([(a.hash, named + 33 * day)]);
    assert!(set.admins_silent(&st, &heard, named + 34 * day, 7 * day).is_empty());
    let before = set.in_dependency_order().into_iter().map(Record::id).collect::<Vec<_>>();
    t += 1000;
    set.write_ack(&st, &a, t).unwrap();
    let st = set.state();
    assert!(set.removals_waiting(&st).is_empty());
    assert!(set.ack_owed(&st, &a.hash, t).is_none());
    assert!(set.root_room_waiting(&st, 0).is_none());
    assert_eq!(set.in_dependency_order().len(), before.len() + 1, "the notices changed nothing");
}

/// A freeze is undone by a thaw; taking a key back is for good. Admin B
/// may freeze admin A but may not remove admins. While A is frozen, the
/// root removes a plain device; the writer's automatic take-back must not
/// turn B's reversible freeze into A's permanent loss of its key.
#[test]
fn a_freeze_by_an_admin_without_remove_admins_is_not_made_permanent() {
    use cbb_core::records::body::{POWER_ADMIT, POWER_FREEZE, POWER_MANAGE, POWER_REMOVE, Removal};
    let root = k("root");
    let (pa, a, pb, b) = (k("phone a"), k("admin a"), k("phone b"), k("admin b"));
    let recovery = cbb_core::records::Recovery {
        k1: k("recovery").key,
        k2: cbb_core::records::pq::PqKey::from_seeds(&[0x31; 16], &[0x32; 16], &[0x33; 16]).key(),
    };
    let mut set = RecordSet::new(root.key.clone(), recovery);
    let mut t = 1000u64;
    let computer_admin = |p: &K, a: &K| {
        let mut d = Device::new(p.key.clone(), "laptop", ROLE_MEMBER);
        d.rights = RIGHT_READ | RIGHT_SEND;
        d.admin = Some(a.key.clone());
        d.powers = POWER_ADMIT | POWER_MANAGE | POWER_REMOVE | POWER_FREEZE;
        Kind::device(d)
    };
    for kind in [
        Kind::Copies { secret_ttl_ms: 0, ttl_ms: MIN_COPY_TTL_MS, seen: vec![] },
        computer_admin(&pa, &a),
        computer_admin(&pb, &b),
        device(&k("victim"), "victim", None),
    ] {
        t += 1000;
        let st = set.state();
        set.write_record(&st, &root, kind, t).unwrap();
    }
    let mut chain = Chain { heads: BTreeMap::new() };
    t += 1000;
    let freeze = chain.sign(&set, &b, Kind::Freeze(Removal { keys: vec![a.hash], seen: Vec::new() }), t);
    set.insert(freeze).unwrap();
    let st = set.state();
    assert!(st.devices.iter().any(|d| d.admin == Some(a.hash) && d.frozen), "B froze A");
    t += 1000;
    for r in set.write_removal(&st, &root, &[k("victim").hash], t).unwrap() {
        let _ = set.insert(r);
    }
    t += 1000;
    let heard: BTreeMap<KeyHash, u64> = [(a.hash, t), (b.hash, t)].into();
    let st = set.state();
    let back = set.take_back_lagging(&st, &root, &heard, t).unwrap();
    let a_back = back.iter().any(|(_, r)| matches!(&r.body().kind, Kind::Device(d) if d.key.hash() == pa.hash));
    assert!(
        !a_back,
        "the root's writer took A's key back for good, a second after B (which may not remove admins) froze it"
    );
    // The app tells the person instead: A is frozen and holds the removal back.
    let held = set.frozen_holding(&st);
    assert_eq!(held.len(), 1, "{held:?}");
    assert_eq!((held[0].key, held[0].device, held[0].removals), (a.hash, pa.key.device_id(), 1));
    assert!(held[0].root_units > 0, "the removal is the root's own");
    let waits = set.removals_waiting(&st);
    assert_eq!(waits.len(), 1);
    assert!(waits[0].waits_for.contains(&a.hash));
}

/// An admin's removal of another admin's key, when the removal's own
/// signer is then taken back: admin 4 (which may remove admins) removes
/// admin 5's key; the root takes admin 4 back (silence, or the person's
/// choice), then writes checkpoints. The removal counts and stays, at the
/// root and at a member restored from what the root saves; admin 5's key
/// stays removed.
#[test]
fn a_removal_of_an_admin_key_stays_when_its_signer_is_taken_back() {
    use cbb_core::records::body::{POWER_ADMIT, POWER_MANAGE, POWER_REMOVE, POWER_REMOVE_ADMINS, Removal};
    for mode in 0..3 {
        let by_silence = mode == 1;
        let root = k("root");
        let (p4, a4, p5, a5) = (k("phone 4"), k("admin 4"), k("phone 5"), k("admin 5"));
        let recovery = cbb_core::records::Recovery {
            k1: k("recovery").key,
            k2: cbb_core::records::pq::PqKey::from_seeds(&[0x31; 16], &[0x32; 16], &[0x33; 16]).key(),
        };
        let mut set = RecordSet::new(root.key.clone(), recovery);
        let mut t = 1000u64;
        let admin = |p: &K, a: &K, powers: u64| {
            let mut d = Device::new(p.key.clone(), "laptop", ROLE_MEMBER);
            d.rights = RIGHT_READ | RIGHT_SEND;
            d.admin = Some(a.key.clone());
            d.powers = powers;
            Kind::device(d)
        };
        for kind in [
            Kind::Copies { secret_ttl_ms: 0, ttl_ms: MIN_COPY_TTL_MS, seen: vec![] },
            admin(&p4, &a4, POWER_ADMIT | POWER_MANAGE | POWER_REMOVE | POWER_REMOVE_ADMINS),
            admin(&p5, &a5, POWER_ADMIT | POWER_MANAGE | POWER_REMOVE),
        ] {
            t += 1000;
            let st = set.state();
            set.write_record(&st, &root, kind, t).unwrap();
        }
        let mut chain = Chain { heads: BTreeMap::new() };
        t += 1000;
        let seen = vec![];
        let rm = chain.sign(&set, &a4, Kind::Revoke(Removal { keys: vec![a5.hash], seen }), t);
        set.insert(rm.clone()).unwrap();
        let st = set.state();
        assert!(st.counting.contains(&rm.id()) && st.revoked.contains(&a5.hash), "admin 4 removed admin 5's key");
        if mode == 2 {
            // The root removes admin 4's device and key instead.
            t += 1000;
            for r in set.write_removal(&st, &root, &[p4.hash, a4.hash], t).unwrap() {
                let _ = set.insert(r);
            }
        } else if by_silence {
            t += ADMIN_SILENCE_MS + 1000;
            let back = set.take_back_lagging(&st, &root, &BTreeMap::from([(a4.hash, 0)]), t).unwrap();
            assert_eq!(back.len(), 1, "admin 4 is taken back for silence");
        } else {
            t += 1000;
            set.take_back(&st, &root, &a4.hash, t).unwrap();
        }
        let check = |set: &RecordSet, what: &str| {
            let st = set.state();
            assert!(st.device_by_key(&p4.hash).is_none_or(|d| d.admin.is_none()), "{what}: admin 4 is no admin");
            assert!(set.contains(&rm.id()), "{what}: the removal is held");
            assert!(st.counting.contains(&rm.id()), "{what}: the removal counts");
            assert!(st.revoked.contains(&a5.hash), "{what}: admin 5's key stays removed");
            assert!(st.device_by_key(&p5.hash).is_none_or(|d| d.admin != Some(a5.hash)), "{what}: admin 5 is no admin");
        };
        check(&set, &format!("mode {mode}, after the take-back"));
        for i in 0..3 {
            t += 1000;
            let st = set.state();
            set.write_record(&st, &root, device(&k(&format!("later {i}")), "later", None), t).unwrap();
            t += 1000;
            let st = set.state();
            let cp = set.write_checkpoint(&st, &root, t).unwrap();
            let _ = set.insert(cp);
            check(&set, &format!("mode {mode}, checkpoint {i}"));
        }
        // A member restored from what the root saves.
        let saved: Vec<Record> =
            set.marked(&cbb_core::certs::sha256(b"a local key")).into_iter().map(|(r, _)| r.clone()).collect();
        let lists: Vec<Vec<u8>> = set.lists().map(<[u8]>::to_vec).collect();
        let back = RecordSet::restore(set.root().clone(), set.recovery().clone(), &saved, &lists);
        check(&back, &format!("mode {mode}, restored"));
    }
}

/// The root's room at its cap under W: an admin that never acknowledges
/// holds every removal back; the root keeps admitting and removing
/// devices, with checkpoints, until its writer refuses a removal. Then
/// the take-back of the silent admin (by the person, or by the writer
/// after its silence) still goes in, and after the next checkpoint the
/// root removes again (docs/protocol.md: "its removals and take-backs
/// still go in up to its cap, and the silence frees it").
#[test]
fn a_root_at_its_cap_can_still_take_the_silent_admin_back() {
    use cbb_core::records::body::{POWER_ADMIT, POWER_MANAGE, POWER_REMOVE};
    let root = k("root");
    let recovery = cbb_core::records::Recovery {
        k1: k("recovery").key,
        k2: cbb_core::records::pq::PqKey::from_seeds(&[0x31; 16], &[0x32; 16], &[0x33; 16]).key(),
    };
    let (pa, a) = (k("cap phone a"), k("cap admin a"));
    for by_person in [true, false] {
        let mut set = RecordSet::new(root.key.clone(), recovery.clone());
        let mut t = 1_000u64;
        let mut d = Device::new(pa.key.clone(), "a", ROLE_MEMBER);
        d.rights = RIGHT_READ | RIGHT_SEND;
        d.admin = Some(a.key.clone());
        d.powers = POWER_ADMIT | POWER_MANAGE | POWER_REMOVE;
        for kind in [Kind::Copies { secret_ttl_ms: 0, ttl_ms: MIN_COPY_TTL_MS, seen: vec![] }, Kind::device(d)] {
            t += 1;
            let st = set.state();
            set.write_record(&st, &root, kind, t).unwrap();
        }
        // Spare devices admitted early, removed only once the root's
        // ordinary records are refused, so that removals fill the margin.
        let spares: Vec<K> = (0..120).map(|i| k(&format!("cap spare {i}"))).collect();
        for x in &spares {
            let st = set.state();
            t += 1;
            set.write_record(&st, &root, device(x, "s", None), t).unwrap();
        }
        let mut n = 0u32;
        let refused = loop {
            assert!(n < 5_000, "no refusal after {n} removals");
            let x = k(&format!("cap dev {n}"));
            let st = set.state();
            t += 1;
            if let Err(e) = set.write_record(&st, &root, device(&x, "d", None), t) {
                let st = set.state();
                match set.write_checkpoint(&st, &root, t) {
                    Ok(cp) => {
                        set.insert(cp).unwrap();
                        continue;
                    }
                    Err(e2) => break format!("admission: {e:?}; checkpoint: {e2:?}"),
                }
            }
            let st = set.state();
            t += 1;
            match set.write_removal(&st, &root, &[x.hash], t) {
                Ok(rs) => {
                    for r in rs {
                        set.insert(r).unwrap();
                    }
                }
                Err(e) => break format!("removal: {e:?}"),
            }
            n += 1;
        };
        let mut more = 0u32;
        let mut stop = String::new();
        for x in &spares {
            let st = set.state();
            t += 1;
            match set.write_removal(&st, &root, &[x.hash], t) {
                Ok(rs) => {
                    for r in rs {
                        set.insert(r).unwrap();
                    }
                    more += 1;
                }
                Err(e) => {
                    stop = format!("{e:?}");
                    break;
                }
            }
        }
        println!("by_person={by_person}: then {more} more removals of spares, stopped by: {stop}");
        let st = set.state();
        let room = set.root_room(&st).unwrap();
        println!(
            "by_person={by_person}: {n} removals, then refused ({refused}); root room {}/{}; waiting {}",
            room.used,
            room.cap,
            set.removals_waiting(&st).len()
        );
        t += 1;
        if by_person {
            set.take_back(&st, &root, &a.hash, t).expect("the person takes the silent admin back at the cap");
        } else {
            let heard: BTreeMap<KeyHash, u64> = [(a.hash, 0)].into();
            let back = set
                .take_back_lagging(&st, &root, &heard, t + ADMIN_SILENCE_MS)
                .expect("the writer's take-back at the cap");
            assert_eq!(back.len(), 1, "the silent admin is taken back");
            for (_, r) in back {
                let _ = set.insert(r);
            }
        }
        let st = set.state();
        assert!(st.devices.iter().all(|d| d.admin.is_none()), "taken back");
        t += ADMIN_SILENCE_MS + 1;
        let cp = set.write_checkpoint(&st, &root, t).expect("a checkpoint after the take-back");
        set.insert(cp).unwrap();
        let st = set.state();
        assert!(set.removals_waiting(&st).is_empty());
        let x = k("cap dev after");
        t += 1;
        set.write_record(&st, &root, device(&x, "d", None), t).expect("the root admits again");
        let st = set.state();
        t += 1;
        set.write_removal(&st, &root, &[x.hash], t).expect("and removes again");
    }
}

/// A group whose `n` admins never acknowledge, its root driven to its
/// cap as in `a_root_at_its_cap_can_still_take_the_silent_admin_back`:
/// ordinary records refused, then removals of devices admitted early
/// until a removal is refused. Returns the set, the admin keys, the clock.
fn at_the_cap(n: usize) -> (RecordSet, K, Vec<K>, u64) {
    use cbb_core::records::body::{POWER_ADMIT, POWER_MANAGE, POWER_REMOVE};
    let root = k("root");
    let recovery = cbb_core::records::Recovery {
        k1: k("recovery").key,
        k2: cbb_core::records::pq::PqKey::from_seeds(&[0x31; 16], &[0x32; 16], &[0x33; 16]).key(),
    };
    let mut set = RecordSet::new(root.key.clone(), recovery);
    let mut t = 1_000u64;
    let st = set.state();
    set.write_record(&st, &root, Kind::Copies { secret_ttl_ms: 0, ttl_ms: MIN_COPY_TTL_MS, seen: vec![] }, t).unwrap();
    let admins: Vec<K> = (0..n).map(|i| k(&format!("lag admin {i}"))).collect();
    for (i, a) in admins.iter().enumerate() {
        let mut d = Device::new(k(&format!("lag phone {i}")).key.clone(), "a", ROLE_MEMBER);
        d.rights = RIGHT_READ | RIGHT_SEND;
        d.admin = Some(a.key.clone());
        d.powers = POWER_ADMIT | POWER_MANAGE | POWER_REMOVE;
        t += 1;
        let st = set.state();
        set.write_record(&st, &root, Kind::device(d), t).unwrap();
    }
    let spares: Vec<K> = (0..120).map(|i| k(&format!("lag spare {i}"))).collect();
    for x in &spares {
        let st = set.state();
        t += 1;
        set.write_record(&st, &root, device(x, "s", None), t).unwrap();
    }
    let mut i = 0u32;
    loop {
        assert!(i < 5_000);
        let x = k(&format!("lag dev {i}"));
        let st = set.state();
        t += 1;
        if set.write_record(&st, &root, device(&x, "d", None), t).is_err() {
            let st = set.state();
            match set.write_checkpoint(&st, &root, t) {
                Ok(cp) => {
                    set.insert(cp).unwrap();
                    continue;
                }
                Err(_) => break,
            }
        }
        let st = set.state();
        t += 1;
        let Ok(rs) = set.write_removal(&st, &root, &[x.hash], t) else { break };
        for r in rs {
            set.insert(r).unwrap();
        }
        i += 1;
    }
    for x in &spares {
        let st = set.state();
        t += 1;
        let Ok(rs) = set.write_removal(&st, &root, &[x.hash], t) else { break };
        for r in rs {
            set.insert(r).unwrap();
        }
    }
    (set, root, admins, t)
}

/// Two admins that never acknowledge, the root at its cap: the person
/// takes the first back and the checkpoint still fits, but the settle
/// stays blocked by the second; the second take-back and its checkpoint
/// still fit, the removals settle, and the root removes again and writes
/// ordinary records again.
#[test]
fn a_root_at_its_cap_can_take_back_two_laggards_and_recover() {
    let (mut set, root, admins, mut t) = at_the_cap(2);
    let st = set.state();
    let room = set.root_room(&st).unwrap();
    println!(
        "two laggards at the cap: root room {}/{}, waiting {}",
        room.used,
        room.cap,
        set.removals_waiting(&st).len()
    );
    t += 1;
    set.take_back(&st, &root, &admins[0].hash, t).expect("the first take-back at the cap");
    let st = set.state();
    t += 1;
    let cp = set.write_checkpoint(&st, &root, t).expect("the checkpoint after the first take-back");
    set.insert(cp).unwrap();
    let st = set.state();
    let waiting = set.removals_waiting(&st);
    assert!(!waiting.is_empty(), "the second laggard still holds the removals back");
    assert!(waiting.iter().all(|w| w.waits_for == vec![admins[1].hash]));
    t += 1;
    set.take_back(&st, &root, &admins[1].hash, t).expect("the second take-back still fits");
    let st = set.state();
    t += 1;
    let cp = set.write_checkpoint(&st, &root, t).expect("and the checkpoint that settles");
    set.insert(cp).unwrap();
    let st = set.state();
    assert!(set.removals_waiting(&st).is_empty(), "settled");
    assert!(st.devices.iter().all(|d| d.admin.is_none()));
    let x = k("lag dev after");
    t += 1;
    set.write_record(&st, &root, device(&x, "d", None), t).expect("the root admits again");
    let st = set.state();
    t += 1;
    for r in set.write_removal(&st, &root, &[x.hash], t).expect("and removes again") {
        set.insert(r).unwrap();
    }
    let st = set.state();
    t += 1;
    set.write_record(&st, &root, Kind::Copies { secret_ttl_ms: 0, ttl_ms: MIN_COPY_TTL_MS + 1, seen: vec![] }, t)
        .expect("and writes ordinary records again");
}

/// From `set`, on a copy: the person takes back every live admin key that
/// holds a removal back (a checkpoint first when the writer asks), then
/// writes the checkpoint that settles. Ok when nothing waits after it.
fn way_out(set: &RecordSet, root: &K, mut t: u64) -> Result<(), String> {
    let mut s = set.clone();
    let st = s.state();
    let lagging: Vec<KeyHash> = s.unacknowledged(&st).into_iter().filter(|(_, n)| *n > 0).map(|(a, _)| a).collect();
    for a in lagging {
        t += 1;
        let st = s.state();
        if let Err(e) = s.take_back(&st, root, &a, t) {
            let cp = s.write_checkpoint(&st, root, t).map_err(|e2| format!("take-back: {e:?}; checkpoint: {e2:?}"))?;
            s.insert(cp).map_err(|e| format!("{e:?}"))?;
            t += 1;
            let st = s.state();
            s.take_back(&st, root, &a, t).map_err(|e| format!("take-back after a checkpoint: {e:?}"))?;
        }
    }
    let st = s.state();
    t += 1;
    let cp = s.write_checkpoint(&st, root, t).map_err(|e| format!("settling checkpoint: {e:?}"))?;
    s.insert(cp).map_err(|e| format!("{e:?}"))?;
    let st = s.state();
    let left = s.removals_waiting(&st).len();
    if left > 0 { Err(format!("{left} removals still wait")) } else { Ok(()) }
}

/// Sixteen admins that never acknowledge; the root writes ordinary
/// records, admissions with removals, and checkpoints in a mixed order
/// (seeded), as long as its writer takes any of them. Claim: at every
/// point the person can still take back all of them and write the
/// settling checkpoint (`way_out`). It reports where the claim first
/// breaks, and whether ordinary records alone ate the way out before any
/// removal was refused.
#[test]
#[ignore = "long: a real-size fill, the way out tried on copies; run with --ignored on a server"]
fn sixteen_laggards_a_mixed_fill_never_closes_the_way_out() {
    use cbb_core::records::body::{POWER_ADMIT, POWER_MANAGE, POWER_REMOVE};
    let root = k("root");
    let recovery = cbb_core::records::Recovery {
        k1: k("recovery").key,
        k2: cbb_core::records::pq::PqKey::from_seeds(&[0x31; 16], &[0x32; 16], &[0x33; 16]).key(),
    };
    let mut broken = Vec::new();
    for seed in [1u64, 7, 23] {
        let mut set = RecordSet::new(root.key.clone(), recovery.clone());
        let mut t = 1_000u64;
        let st = set.state();
        set.write_record(&st, &root, Kind::Copies { secret_ttl_ms: 0, ttl_ms: MIN_COPY_TTL_MS, seen: vec![] }, t)
            .unwrap();
        for i in 0..16 {
            let mut d = Device::new(k(&format!("mix phone {i}")).key.clone(), "a", ROLE_MEMBER);
            d.rights = RIGHT_READ | RIGHT_SEND;
            d.admin = Some(k(&format!("mix admin {i}")).key.clone());
            d.powers = POWER_ADMIT | POWER_MANAGE | POWER_REMOVE;
            t += 1;
            let st = set.state();
            set.write_record(&st, &root, Kind::device(d), t).unwrap();
        }
        // Devices admitted early, to be removed later past the floor.
        let mut early: Vec<K> = Vec::new();
        let mut rng = seed;
        let mut next = || {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng
        };
        let (mut removal_refused, mut first_break) = (false, None::<String>);
        let mut idle = 0u32;
        let mut step = 0u32;
        while idle < 40 && step < 6_000 {
            step += 1;
            let roll = next() % 10;
            let st = set.state();
            t += 1;
            let (what, ok) = match roll {
                0..=2 => {
                    let r = set.write_record(
                        &st,
                        &root,
                        Kind::Copies { secret_ttl_ms: 0, ttl_ms: MIN_COPY_TTL_MS + u64::from(step), seen: vec![] },
                        t,
                    );
                    ("ordinary", r.is_ok())
                }
                3 => {
                    let x = k(&format!("mix early {seed} {step}"));
                    let r = set.write_record(&st, &root, device(&x, "e", None), t);
                    if r.is_ok() {
                        early.push(x);
                    }
                    ("admission kept", r.is_ok())
                }
                4..=7 => {
                    let x = if roll == 7 && !early.is_empty() {
                        early.remove(0)
                    } else {
                        let x = k(&format!("mix dev {seed} {step}"));
                        if set.write_record(&st, &root, device(&x, "d", None), t).is_err() {
                            idle += 1;
                            continue;
                        }
                        x
                    };
                    let st = set.state();
                    t += 1;
                    match set.write_removal(&st, &root, &[x.hash], t) {
                        Ok(rs) => {
                            for r in rs {
                                set.insert(r).unwrap();
                            }
                            ("removal", true)
                        }
                        Err(_) => {
                            removal_refused = true;
                            ("removal", false)
                        }
                    }
                }
                _ => match set.write_checkpoint(&st, &root, t) {
                    Ok(cp) => ("checkpoint", set.insert(cp).is_ok()),
                    Err(_) => ("checkpoint", false),
                },
            };
            if ok {
                idle = 0;
            } else {
                idle += 1;
                continue;
            }
            let st = set.state();
            let used = set.root_room(&st).map_or(0, |r| r.used);
            let due = (used > 1_300 && step.is_multiple_of(10)) || step.is_multiple_of(100);
            if first_break.is_none()
                && due
                && let Err(e) = way_out(&set, &root, t)
            {
                first_break = Some(format!(
                    "seed {seed} step {step}: after a {what} (root room {used}, removal refused before: {removal_refused}, waiting {}): {e}",
                    set.removals_waiting(&st).len()
                ));
                break;
            }
        }
        let st = set.state();
        println!(
            "seed {seed}: {step} steps, root room {:?}, waiting {}, first break: {first_break:?}",
            set.root_room(&st).map(|r| (r.used, r.cap)),
            set.removals_waiting(&st).len()
        );
        if first_break.is_none() {
            way_out(&set, &root, t).unwrap_or_else(|e| broken.push(format!("seed {seed} at the end: {e}")));
        }
        broken.extend(first_break);
    }
    assert!(broken.is_empty(), "the way out closed: {broken:#?}");
}

/// At the cap with two laggards, the root's removal that names a lagging
/// admin's own key (its admin key, or its phone's member key) is itself
/// part of the way out: it goes in, and the other laggard's take-back and
/// the settling checkpoint still fit.
#[test]
fn at_the_cap_a_removal_naming_a_laggard_s_own_key_goes_in() {
    for by_member_key in [false, true] {
        let (mut set, root, admins, mut t) = at_the_cap(2);
        let st = set.state();
        let target = if by_member_key {
            st.devices.iter().find(|d| d.admin == Some(admins[0].hash)).map(|d| d.key.hash()).unwrap()
        } else {
            admins[0].hash
        };
        t += 1;
        for r in set
            .write_removal(&st, &root, &[target], t)
            .unwrap_or_else(|e| panic!("by_member_key={by_member_key}: the laggard's own removal at the cap: {e:?}"))
        {
            set.insert(r).unwrap();
        }
        way_out(&set, &root, t).unwrap_or_else(|e| panic!("by_member_key={by_member_key}: then the way out: {e}"));
    }
}
