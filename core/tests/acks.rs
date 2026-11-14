// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! An independent reading of acknowledgements and take-backs (section 10),
//! through the record set's public writer only: a key a root took back is
//! never an admin again, whatever the root's checkpoints left out, and what
//! the key signed that the root never got never counts.

use std::collections::BTreeMap;

use cbb_core::identity::ExternalKey;
use cbb_core::records::body::{Device, MIN_INCOMING_MS, RIGHT_READ, RIGHT_SEND, ROLE_MEMBER, ROLE_PHONE};
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
    fn sign(&mut self, set: &RecordSet, by: &K, kind: Kind, time_ms: u64) -> Record {
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
    w(&mut set, Kind::Copies { incoming_ms: MIN_INCOMING_MS, seen: vec![] }, &mut t);
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
            let r = set.write_record(&st, &root, device(&k(&format!("after {i}")), "after", None), t).unwrap();
            let _ = set.insert(r);
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
            Ok(r) => {
                let _ = set.insert(r);
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
    w(&mut set, Kind::Copies { incoming_ms: MIN_INCOMING_MS, seen: vec![] }, &mut t).unwrap();
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
        let ms = MIN_INCOMING_MS + n;
        if w(&mut set, Kind::Copies { incoming_ms: ms, seen: vec![] }, &mut t).is_err() {
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
