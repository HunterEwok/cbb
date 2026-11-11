// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Joining without certificates: who admits whom, the Welcome's checks, the
//! intro, and the invitation.

use std::collections::BTreeMap;

use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::hazmat::PrehashSigner as _;

use super::decide::{self, Checked, Choice, Signer};
use super::info::Info;
use super::intro::{self, Intro};
use super::invitation::{self, Invitation, Network, Open, Path, PathKind, Profile};
use super::welcome::{self, Welcome};
use super::*;
use crate::certs::sha256;
use crate::format::{self, Alg};
use crate::records::body::*;
use crate::records::set::RecordSet;
use crate::records::{Body, GroupId, Key, KeyHash, Kind, Record, RecordId, State};

struct K {
    sk: SigningKey,
    key: Key,
    hash: KeyHash,
}

impl ExternalKey for K {
    fn public(&self) -> Vec<u8> {
        self.key.public.clone()
    }
    fn sign_digest(&self, digest: &[u8; 32]) -> crate::error::Result<Vec<u8>> {
        let sig: p256::ecdsa::Signature = self.sk.sign_prehash(digest).unwrap();
        Ok(sig.to_der().as_bytes().to_vec())
    }
}

fn k(name: &str) -> K {
    let sk = SigningKey::from_slice(&sha256(name.as_bytes())).unwrap();
    let key = Key::es256(sk.verifying_key().to_sec1_point(false).as_bytes().to_vec());
    let hash = key.hash();
    K { sk, key, hash }
}

fn point(k: &K) -> [u8; 65] {
    k.key.public.clone().try_into().unwrap()
}

fn fhash(k: &K) -> format::KeyHash {
    format::Key::new(Alg::Es256, &k.key.public).hash()
}

/// A group: the root phone (member key "phone", root key "root"), an admin
/// laptop (member key "laptop", admin key "laptop admin").
struct G {
    root: K,
    gid: GroupId,
    heads: BTreeMap<KeyHash, (u64, RecordId)>,
    recs: Vec<Record>,
}

impl G {
    fn new() -> G {
        let root = k("root");
        let gid = root.key.device_id();
        let mut g = G { root, gid, heads: BTreeMap::new(), recs: Vec::new() };
        let phone = k("phone");
        let mut d = Device::new(phone.key.clone(), "phone", ROLE_PHONE);
        d.rights = RIGHT_READ | RIGHT_SEND | RIGHT_SECRETS;
        d.holds_root = true;
        g.rec_root(Kind::Device(d));
        let laptop = k("laptop");
        let mut d = Device::new(laptop.key.clone(), "laptop", ROLE_MEMBER);
        d.rights = RIGHT_READ | RIGHT_SEND;
        d.admin = Some(k("laptop admin").key.clone());
        let (p, c) = AdminKind::Computer.grants();
        d.powers = p;
        d.commands = c;
        g.rec_root(Kind::Device(d));
        g
    }

    fn rec(&mut self, by: &K, kind: Kind) -> Record {
        let (seq, prev) = match self.heads.get(&by.hash) {
            Some((s, id)) => (s + 1, Some(*id)),
            None => (1, None),
        };
        let body = Body { group: self.gid, signer: by.hash, seq, prev, time_ms: 0, kind, held: false };
        let r = Record::sign(body, by).unwrap();
        self.heads.insert(by.hash, (seq, r.id()));
        self.recs.push(r.clone());
        r
    }

    fn rec_root(&mut self, kind: Kind) -> Record {
        let root = k("root");
        self.rec(&root, kind)
    }

    fn set(&self) -> RecordSet {
        let mut s = RecordSet::new(self.root.key.clone());
        let (_, refused) = s.insert_all(self.recs.iter().cloned());
        assert!(refused.is_empty(), "{refused:?}");
        s
    }

    fn state(&self) -> State {
        self.set().state(&BTreeMap::new())
    }

    fn seen(&self) -> Vec<Seen> {
        self.heads.iter().map(|(k, (s, _))| Seen { key: *k, seq: *s }).collect()
    }
}

fn info(name: &str, role: u64) -> Info {
    Info::new(name, 1, role)
}

#[test]
fn the_channel_binds_both_keys() {
    let (a, b) = (k("a"), k("b"));
    let ab = channel_id(&fhash(&a), &fhash(&b));
    assert_ne!(ab, channel_id(&fhash(&b), &fhash(&a)), "the member's key comes first");
    assert_ne!(ab, channel_id(&fhash(&a), &fhash(&k("c"))));
    assert!(ab.ends_with(&fhash(&b).0));
}

#[test]
fn an_admin_key_needs_its_proof() {
    let admin = k("phone admin");
    let exporter = [7u8; 32];
    let pop = sign_admin_pop(&admin, &exporter).unwrap();
    assert!(verify_admin_pop(&admin.key, &exporter, &pop));
    assert!(!verify_admin_pop(&admin.key, &[8u8; 32], &pop), "another session's proof");
    assert!(!verify_admin_pop(&k("other").key, &exporter, &pop), "another key's proof");

    // In the Info, a key and its proof come together, from a phone or an admin member.
    let mut i = info("phone 2", ROLE_PHONE);
    i.admin = Some(admin.key.public.clone());
    assert_eq!(Info::decode(&i.encode()), Err(super::info::RULE_ADMIN));
    i.admin_pop = Some(pop.to_vec());
    assert_eq!(Info::decode(&i.encode()).unwrap(), i);
    let mut w = i.clone();
    w.role = ROLE_WATCH;
    assert_eq!(Info::decode(&w.encode()), Err(super::info::RULE_ADMIN));
    w.role = ROLE_MEMBER;
    w.caps = CAP_ADMIN;
    assert!(Info::decode(&w.encode()).is_ok());
}

#[test]
fn info_rows() {
    let mut i = info("tv", ROLE_MEMBER);
    i.os = 11; // harmonyos; and any later number is taken
    assert_eq!(Info::decode(&i.encode()).unwrap().os, 11);
    i.os = 999;
    assert_eq!(Info::decode(&i.encode()).unwrap().os, 999);
    for bad in ["", "a\u{7}b", &"x".repeat(65)] {
        assert_eq!(Info::decode(&info(bad, ROLE_MEMBER).encode()), Err(super::info::RULE_NAME), "{bad:?}");
    }
    assert_eq!(Info::decode(&info("x", 5).encode()), Err(super::info::RULE_ROLE));
    let mut c = info("x", ROLE_PHONE);
    c.caps = CAP_HUB;
    assert_eq!(Info::decode(&c.encode()), Err(super::info::RULE_CAPS), "caps only for a member");
}

#[test]
fn who_admits_whom() {
    let g = G::new();
    let st = g.state();
    let (laptop, root) = (k("laptop"), k("root"));
    let laptop_dev = st.device_by_key(&laptop.hash).cloned();
    assert!(decide::may_admit(&st, &laptop.hash, Signer::Admin, &root.hash));
    assert!(decide::may_admit(&st, &k("phone").hash, Signer::Root, &root.hash));
    assert!(!decide::may_admit(&st, &k("stranger").hash, Signer::Admin, &root.hash));

    // An admin admits with base rights only; secrets only when its own device has them.
    let tv = k("tv");
    let mut ask = info("tv", ROLE_MEMBER);
    ask.caps = CAP_HUB;
    let wide = Choice { rights: RIGHT_READ | RIGHT_SEND | RIGHT_HUB | RIGHT_SECRETS, admin: None, guarded: false };
    let d = decide::joiner_record(&st, Signer::Admin, laptop_dev.as_ref(), &point(&tv), &ask, Checked::default(), wide)
        .unwrap();
    assert_eq!(d.rights, RIGHT_READ | RIGHT_SEND);
    assert_eq!(d.store, STORE_FILE, "no evidence: a file, whatever the device says");
    assert!(d.admin.is_none());

    // An ordinary leaf: any admin; a guarded one: the root alone.
    let lamp = k("lamp");
    let leaf = info("lamp", ROLE_LEAF);
    assert!(
        decide::joiner_record(
            &st,
            Signer::Admin,
            laptop_dev.as_ref(),
            &point(&lamp),
            &leaf,
            Checked::default(),
            Choice::default()
        )
        .is_ok()
    );
    let guarded = Choice { guarded: true, ..Choice::default() };
    assert_eq!(
        decide::joiner_record(
            &st,
            Signer::Admin,
            laptop_dev.as_ref(),
            &point(&lamp),
            &leaf,
            Checked::default(),
            guarded
        ),
        Err(decide::Refusal::GuardedNeedsRoot)
    );
    assert!(
        decide::joiner_record(&st, Signer::Root, None, &point(&lamp), &leaf, Checked::default(), guarded)
            .unwrap()
            .guarded
    );

    // An admin key: only from the root, only with its proof, only as one of the three sets.
    let phone2 = k("phone 2");
    let mut ph = info("phone 2", ROLE_PHONE);
    ph.admin = Some(k("phone 2 admin").key.public.clone());
    let make = Choice { rights: RIGHT_READ | RIGHT_SEND, admin: Some(AdminKind::Phone), guarded: false };
    let none = decide::joiner_record(&st, Signer::Root, None, &point(&phone2), &ph, Checked::default(), make).unwrap();
    assert!(none.admin.is_none(), "no proof, no admin key");
    let proven = Checked { admin_pop: true, proof: Some(1) };
    let d = decide::joiner_record(&st, Signer::Root, None, &point(&phone2), &ph, proven, make).unwrap();
    assert_eq!((d.powers, d.commands), AdminKind::Phone.grants());
    assert_eq!((d.store, d.proof), (STORE_PROVEN, 1));
    let by_admin =
        decide::joiner_record(&st, Signer::Admin, laptop_dev.as_ref(), &point(&phone2), &ph, proven, make).unwrap();
    assert!(by_admin.admin.is_none(), "an admin never gives an admin key");
}

#[test]
fn a_removed_device_does_not_come_back_with_its_key() {
    let mut g = G::new();
    let tv = k("tv");
    let mut d = Device::new(tv.key.clone(), "tv", ROLE_MEMBER);
    d.rights = RIGHT_READ;
    g.rec_root(Kind::Device(d));
    let seen = g.seen();
    g.rec_root(Kind::Revoke(Removal { keys: vec![tv.hash], seen }));
    let st = g.state();
    assert!(st.device_by_key(&tv.hash).is_none());
    assert_eq!(
        decide::joiner_record(
            &st,
            Signer::Root,
            None,
            &point(&tv),
            &info("tv", ROLE_MEMBER),
            Checked::default(),
            Choice::default()
        ),
        Err(decide::Refusal::Taken)
    );
    // With a new key it is a new device.
    assert!(
        decide::joiner_record(
            &st,
            Signer::Root,
            None,
            &point(&k("tv reset")),
            &info("tv", ROLE_MEMBER),
            Checked::default(),
            Choice::default()
        )
        .is_ok()
    );
}

fn admit(g: &mut G, by_admin: bool, joiner: &K, name: &str) -> Welcome {
    let st = g.state();
    let laptop = k("laptop");
    let own = st.device_by_key(&laptop.hash).cloned();
    let signer = if by_admin { Signer::Admin } else { Signer::Root };
    let d = decide::joiner_record(
        &st,
        signer,
        own.as_ref(),
        &point(joiner),
        &info(name, ROLE_MEMBER),
        Checked::default(),
        Choice { rights: RIGHT_READ | RIGHT_SEND, ..Choice::default() },
    )
    .unwrap();
    if by_admin {
        g.rec(&k("laptop admin"), Kind::Device(d));
    } else {
        g.rec_root(Kind::Device(d));
    }
    let set = g.set();
    let st = set.state(&BTreeMap::new());
    let admitter = if by_admin { laptop.hash } else { k("phone").hash };
    Welcome::build(&set, &st, &admitter, &joiner.hash, &BTreeMap::new(), 1_793_000_000_000)
}

#[test]
fn the_joiner_checks_its_welcome() {
    let mut g = G::new();
    let tv = k("tv");
    let w = admit(&mut g, true, &tv, "tv");
    let group = format::DeviceId(g.gid.0);
    let (_, st, _) = w.check(&group, &point(&k("laptop")), &point(&tv)).unwrap();
    assert!(st.device_by_key(&tv.hash).is_some());

    // Another group.
    assert_eq!(
        w.check(&format::DeviceId([9; 16]), &point(&k("laptop")), &point(&tv)).err(),
        Some(welcome::Refusal::OtherGroup)
    );
    // Not my record.
    assert_eq!(w.check(&group, &point(&k("laptop")), &point(&k("someone"))).err(), Some(welcome::Refusal::NotAdmitted));
    // An admitter other than the one who signed: the root phone did not sign this record.
    assert_eq!(w.check(&group, &point(&k("phone")), &point(&tv)).err(), Some(welcome::Refusal::NotAdmitter));
    // A stranger in the middle.
    assert_eq!(w.check(&group, &point(&k("stranger")), &point(&tv)).err(), Some(welcome::Refusal::NotAdmitter));

    // A Welcome without the admitter's own record proves nothing.
    let mut cut = w.clone();
    cut.records.retain(|r| !matches!(&r.body().kind, Kind::Device(d) if d.key.hash() == k("laptop").hash));
    assert!(cut.check(&group, &point(&k("laptop")), &point(&tv)).is_err());

    // The root's path comes from the records: a Welcome under another root is another group.
    let mut other = w.clone();
    other.root = k("root 2").key.public.clone();
    assert_eq!(other.check(&group, &point(&k("laptop")), &point(&tv)).err(), Some(welcome::Refusal::OtherGroup));

    // By the root phone.
    let tab = k("tablet");
    let w = admit(&mut g, false, &tab, "tablet");
    assert!(w.check(&group, &point(&k("phone")), &point(&tab)).is_ok());
    assert_eq!(w.check(&group, &point(&k("laptop")), &point(&tab)).err(), Some(welcome::Refusal::NotAdmitter));

    // The encoding's parts read back.
    let (root, envs, ages, time) = Welcome::parts(&w.encode()).unwrap();
    assert_eq!(root, g.root.key.public);
    assert_eq!(envs.len(), w.records.len());
    assert!(ages.is_empty());
    assert_eq!(time, 1_793_000_000_000);
}

#[test]
fn an_intro_proves_a_new_device() {
    let mut g = G::new();
    let tv = k("tv");
    admit(&mut g, true, &tv, "tv");
    let full = g.set();
    let st = full.state(&BTreeMap::new());
    let intro = Intro::of(&full, &st, &tv.hash, None).unwrap();
    // The tv's record, the laptop's record that gave the admin key; no more.
    assert_eq!(intro.records.len(), 2);

    // A peer that knows the root phone and the laptop, but not the tv yet.
    let mut old = RecordSet::new(g.root.key.clone());
    old.insert_all(g.recs[..2].iter().cloned());
    let me = fhash(&k("phone"));
    let new = intro.check(&old, &BTreeMap::new(), &me, &point(&tv)).unwrap();
    assert_eq!(new.len(), 1);

    // Someone else's intro under the tv's key proves nothing for another key.
    assert_eq!(intro.check(&old, &BTreeMap::new(), &me, &point(&k("stranger"))), Err(intro::Refusal::NotMember));

    // A record that does not verify closes it.
    let mut bad = intro.clone();
    let r = bad.records.pop().unwrap();
    let mut sig = r.sig().to_vec();
    sig[5] ^= 1;
    bad.records.push(Record::from_parts(r.body_bytes().to_vec(), sig, None, r.body().clone()).unwrap());
    assert_eq!(bad.check(&old, &BTreeMap::new(), &me, &point(&tv)), Err(intro::Refusal::Broken));

    // Too many records.
    let mut big = intro.clone();
    while big.records.len() <= intro::MAX_RECORDS {
        big.records.push(intro.records[0].clone());
    }
    assert_eq!(big.check(&old, &BTreeMap::new(), &me, &point(&tv)), Err(intro::Refusal::TooBig));

    // A removed device's intro does not bring it back.
    let seen = g.seen();
    g.rec_root(Kind::Revoke(Removal { keys: vec![tv.hash], seen }));
    let mut now = RecordSet::new(g.root.key.clone());
    now.insert_all(g.recs.iter().cloned());
    assert_eq!(intro.check(&now, &BTreeMap::new(), &me, &point(&tv)), Err(intro::Refusal::NotMember));

    // The message's envelopes read back.
    let (envs, keys) = Intro::envelopes(&intro.message()).unwrap();
    assert_eq!(envs.len(), 2);
    assert!(keys.is_none());
}

fn invitation() -> Invitation {
    Invitation::new(
        vec![
            Path { kind: PathKind::Home, endpoints: vec![], hub_key: None, guest: None },
            Path {
                kind: PathKind::Guest,
                endpoints: vec!["192.0.2.1:51820".into()],
                hub_key: Some([1; 32]),
                guest: Some(([2; 32], [3; 32])),
            },
        ],
        Profile { role: ROLE_MEMBER, rights: RIGHT_READ | RIGHT_SEND, home_only: false, guarded: false },
    )
}

#[test]
fn one_invitation_for_home_and_away() {
    let inv = invitation();
    let text = inv.text();
    assert!(text.starts_with(invitation::PREFIX));
    assert_eq!(Invitation::parse(&text).unwrap(), inv);
    // No group ID, no root key: one-time values only.
    let b = inv.encode();
    let g = G::new();
    assert!(!b.windows(16).any(|w| w == g.gid.0));
    assert!(!b.windows(65).any(|w| w == g.root.key.public.as_slice()));

    // Rows.
    let mut home_only = inv.clone();
    home_only.profile.home_only = true;
    assert_eq!(Invitation::decode(&home_only.encode()), Err(invitation::RULE_PROFILE), "home only, with a guest path");
    let mut guarded = inv.clone();
    guarded.profile.guarded = true;
    assert_eq!(Invitation::decode(&guarded.encode()), Err(invitation::RULE_PROFILE), "guarded is for a leaf");
    let mut no_key = inv.clone();
    no_key.paths[1].hub_key = None;
    assert_eq!(Invitation::decode(&no_key.encode()), Err(invitation::RULE_PATH));
    let mut bad_ep = inv.clone();
    bad_ep.paths[1].endpoints = vec!["example.org".into()];
    assert_eq!(Invitation::decode(&bad_ep.encode()), Err(invitation::RULE_PATH));
    let small = Invitation::new(
        vec![Path { kind: PathKind::Home, endpoints: vec![], hub_key: None, guest: None }],
        Profile::small_device(),
    );
    assert_eq!(Invitation::parse(&small.text()).unwrap(), small);
}

#[test]
fn an_open_invitation() {
    let inv = invitation();
    let mut open = Open {
        invitation: inv,
        name: "kitchen tv".into(),
        created_ms: 1000,
        expires_ms: 5000,
        used: false,
        failures: 0,
        allowed_key: None,
    };
    assert_eq!(open.may_use(Network::Guest, 2000), Ok(()));
    assert_eq!(open.may_use(Network::Guest, 5000), Err(PairError::Expired), "the admitter checks the expiry");
    open.failures = invitation::MAX_FAILURES;
    assert_eq!(open.may_use(Network::Home, 2000), Err(PairError::TooMany));
    open.failures = 0;
    open.used = true;
    assert_eq!(open.may_use(Network::Home, 2000), Err(PairError::Closed), "one use");
    open.used = false;
    open.invitation.profile.home_only = true;
    assert_eq!(open.may_use(Network::Guest, 2000), Err(PairError::Refused), "home only");
    open.invitation.profile.home_only = false;

    // The device cannot ask for more than its profile.
    let mut ask = info("tv", ROLE_MEMBER);
    assert!(!open.asks_more(&ask));
    ask.caps = CAP_HUB;
    assert!(open.asks_more(&ask));
    assert!(open.asks_more(&info("tv", ROLE_PHONE)));

    // A key allowed ahead of time.
    assert_eq!(open.key_allowed(&fhash(&k("board"))), None);
    open.allowed_key = Some(fhash(&k("board")));
    assert_eq!(open.key_allowed(&fhash(&k("board"))), Some(true));
    assert_eq!(open.key_allowed(&fhash(&k("other board"))), Some(false));

    // The short code: the same on both ends of one session, another for another.
    let code = invitation::short_code(&[5; 32]);
    assert_eq!(code.len(), 6);
    assert_eq!(code, invitation::short_code(&[5; 32]));
    assert_ne!(code, invitation::short_code(&[6; 32]));

    // The decision screen.
    let g = G::new();
    let d = invitation::Decision::of(
        &g.state(),
        Some(&open),
        Network::Guest,
        &info("Laptop!", ROLE_MEMBER),
        invitation::Attestation::NotProven,
        RIGHT_READ,
        4000,
    );
    assert_eq!(d.invitation.as_deref(), Some("kitchen tv"));
    assert_eq!(d.age_ms, 3000);
    assert_eq!(d.similar.as_deref(), Some("laptop"), "a name like a device of the group");
    assert_eq!(invitation::similar_name(&g.state(), "lapton"), Some("laptop".into()));
    assert_eq!(invitation::similar_name(&g.state(), "kettle"), None);
}

#[test]
fn pair_errors_round_trip() {
    for c in 1..=8 {
        assert_eq!(PairError::of(c).unwrap().code(), c);
    }
    assert_eq!(PairError::of(9), None);
}
