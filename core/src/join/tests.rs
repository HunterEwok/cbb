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
use super::welcome::{self, Joining, Welcome};
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
    lists: Vec<Vec<u8>>,
}

impl G {
    fn new() -> G {
        let root = k("root");
        let gid = crate::records::group_id(&root.key, &crate::testkit::recovery());
        let mut g = G { root, gid, heads: BTreeMap::new(), recs: Vec::new(), lists: Vec::new() };
        let phone = k("phone");
        let mut d = Device::new(phone.key.clone(), "phone", ROLE_PHONE);
        d.rights = RIGHT_READ | RIGHT_SEND | RIGHT_SECRETS;
        d.holds_root = true;
        g.rec_root(Kind::device(d));
        let laptop = k("laptop");
        let mut d = Device::new(laptop.key.clone(), "laptop", ROLE_MEMBER);
        d.rights = RIGHT_READ | RIGHT_SEND;
        d.admin = Some(k("laptop admin").key.clone());
        let (p, c) = AdminKind::Computer.grants();
        d.powers = p;
        d.commands = c;
        g.rec_root(Kind::device(d));
        g
    }

    fn rec(&mut self, by: &K, kind: Kind) -> Record {
        let (seq, prev) = match self.heads.get(&by.hash) {
            Some((s, id)) => (s + 1, Some(*id)),
            None => (1, None),
        };
        let body = Body { group: self.gid, signer: by.hash, seq, prev, time_ms: 0, kind, held: false };
        let r = crate::testkit::sign_by(body, by);
        self.heads.insert(by.hash, (seq, r.id()));
        self.recs.push(r.clone());
        r
    }

    fn rec_root(&mut self, kind: Kind) -> Record {
        let root = k("root");
        self.rec(&root, kind)
    }

    fn empty(&self) -> RecordSet {
        RecordSet::new(self.root.key.clone(), crate::testkit::recovery())
    }

    /// The set of a member that holds every record: the heads with their
    /// lists first, as members pass them, then the rest.
    fn set(&self) -> RecordSet {
        let mut s = self.empty();
        s.insert_all(self.recs.iter().filter(|r| matches!(r.body().kind, Kind::Recovery { .. })).cloned());
        for l in &self.lists {
            s.insert_list(l).unwrap();
        }
        let (_, refused) = s.insert_all(self.recs.iter().cloned());
        assert!(refused.is_empty(), "{refused:?}");
        s
    }

    fn state(&self) -> State {
        self.set().state()
    }

    /// A change of root to new_root by the recovery key, listing every
    /// record the set would carry forward.
    fn change(&mut self, new_root: &K) -> Record {
        let set = self.set();
        let list = set.change_list(&set.state());
        self.lists.push(list.encode());
        // The new root's first checkpoint, which the head names: it keeps
        // the whole list and names the first root's head.
        let (seq, id) = self.heads[&self.root.hash];
        let first = self
            .rec(
                new_root,
                Kind::Checkpoint { heads: vec![Head { key: self.root.hash, seq, id }], keep: list.0.clone() },
            )
            .id();
        self.rec(
            &k("recovery"),
            Kind::Recovery {
                root: new_root.key.clone(),
                list: list.hash(),
                from: 0,
                first,
                signer2: crate::testkit::rk2().key().hash(),
            },
        )
    }

    fn seen(&self) -> Vec<Seen> {
        self.heads.iter().map(|(k, (s, id))| Seen { key: *k, seq: *s, id: *id }).collect()
    }
}

/// The joiner's record by an invitation whose profile allows its role and
/// every right.
fn joiner_record_any(
    st: &State,
    signer: Signer,
    own: Option<&crate::records::eval::DeviceState>,
    key: &[u8; 65],
    info: &Info,
    checked: Checked,
    choice: Choice,
) -> Result<Device, decide::Refusal> {
    let profile = Profile {
        role: info.role,
        rights: RIGHT_READ | RIGHT_SEND | RIGHT_HUB | RIGHT_SECRETS,
        home_only: false,
        guarded: false,
    };
    decide::joiner_record(st, signer, own, key, info, &profile, checked, choice)
}

fn info(name: &str, role: u64) -> Info {
    Info::new(name, 1, role)
}

#[test]
fn the_channel_binds_both_keys() {
    let (a, b) = (k("a"), k("b"));
    let id = [5u8; 16];
    let ab = channel_id(&fhash(&a), &fhash(&b), &id);
    assert_ne!(ab, channel_id(&fhash(&b), &fhash(&a), &id), "the member's key comes first");
    assert_ne!(ab, channel_id(&fhash(&a), &fhash(&k("c")), &id));
    assert!(ab.ends_with(&id));
    assert_eq!(&ab[ab.len() - 48..ab.len() - 16], &fhash(&b).0);
    // Two ends in the flows of two invitations, or one at home without
    // one, get two identifiers.
    assert_ne!(ab, channel_id(&fhash(&a), &fhash(&b), &[6u8; 16]));
    assert_ne!(ab, channel_id(&fhash(&a), &fhash(&b), &NO_INVITATION));
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
fn the_info_follows_its_table() {
    use crate::format::{Rule, Value};
    let info_of = |extra: (u16, Value<'_>)| {
        let mut m = vec![(1, Value::Text("tv")), (4, Value::Uint(ROLE_MEMBER))];
        m.push(extra);
        m.sort_by_key(|(k, _)| *k);
        Value::Map(m).encode()
    };
    // A field at its default is left out, not written.
    assert_eq!(Info::decode(&info_of((2, Value::Uint(0)))), Err(Rule::field("pair/info/os")));
    assert_eq!(Info::decode(&info_of((3, Value::Uint(0)))), Err(Rule::field("pair/info/caps")));
    // Admin keys come as a signed envelope.
    assert_eq!(Info::decode(&info_of((7, Value::Bytes(b"not an envelope")))), Err(Rule::field("pair/info/keys")));
    assert_eq!(Info::decode(&info_of((9, Value::Bytes(&[1; 8])))), Err(Rule::field("pair/info/invite")));
    // A field the table does not list is skipped.
    assert!(Info::decode(&info_of((40, Value::Uint(7)))).is_ok());
}

/// A joiner's new session, as if the person started it on a fresh joiner.
fn joiner_session() -> (invitation::JoinerAttempts, invitation::JoinerCode, [u8; 32]) {
    let mut j = invitation::JoinerAttempts::default();
    let (code, c) = j.start().unwrap();
    (j, code, c)
}

#[test]
fn the_short_code_opens_its_commitment() {
    let mut open = invitation::Open {
        invitation: Invitation::new(Vec::new(), Profile::small_device()),
        name: "kettle".into(),
        created_ms: 1,
        expires_ms: 10_000_000,
        used: false,
        failures: 0,
        allowed_key: None,
        attempt: None,
        next_attempt: 0,
    };
    let e = [9u8; 32];
    // One attempt to the end: both ends show one code, and the Welcome
    // takes back the count.
    let n = open.begin(Network::Home, 100).unwrap();
    let (mut j, joiner, c) = joiner_session();
    let nm = open.reply(n, c, 110).unwrap();
    assert_eq!(open.failures, 1, "counted once the member replied");
    let (code, nj) = j.open(joiner, &e, &nm, &open.invitation.id);
    assert_eq!(code.len(), 6);
    assert_eq!(open.short_code(n, &e, &nj, 120), Ok(code.clone()));
    open.end(n, true, 130);
    assert_eq!(open.failures, 0);

    // Each session draws new nonces at both ends.
    let n2 = open.begin(Network::Home, 200).unwrap();
    assert_ne!(n2, n);
    let (mut j2, joiner2, c2) = joiner_session();
    assert_ne!(c2, c);
    let nm2 = open.reply(n2, c2, 210).unwrap();
    assert_ne!(nm2, nm);
    // A second attempt while one is in progress: busy.
    assert_eq!(open.begin(Network::Home, 220), Err(PairError::Busy));
    // Walking away after the reply counts as a failed attempt.
    let (_, nj2) = j2.open(joiner2, &e, &nm2, &open.invitation.id);
    open.end(n2, false, 230);
    assert_eq!(open.failures, 1);
    assert_ne!(nj2, nj);

    // Another nonce than the committed one ends the attempt, counted.
    let n3 = open.begin(Network::Home, 300).unwrap();
    let (_, _, c3) = joiner_session();
    open.reply(n3, c3, 310).unwrap();
    assert_eq!(open.short_code(n3, &e, &nj, 320), Err(PairError::WrongCode));
    assert_eq!(open.failures, 2);
    assert!(open.attempt.is_none());

    // The person takes minutes to compare and answer: the attempt stays the
    // open one, and the Welcome still takes back its count.
    let kept = open.failures;
    let n5 = open.begin(Network::Home, 1_000).unwrap();
    let (mut j5, joiner5, c5) = joiner_session();
    let nm5 = open.reply(n5, c5, 1_010).unwrap();
    let (code5, nj5) = j5.open(joiner5, &e, &nm5, &open.invitation.id);
    assert_eq!(open.short_code(n5, &e, &nj5, 1_020), Ok(code5));
    let minutes = 1_020 + 5 * 60_000;
    assert_eq!(open.begin(Network::Home, minutes), Err(PairError::Busy), "still the open attempt");
    open.end(n5, true, minutes);
    assert_eq!(open.failures, kept);
    // The machine's steps alone have the short timer: a nonce opened late
    // is refused, and the attempt stays counted.
    let n6 = open.begin(Network::Home, 2_000_000).unwrap();
    let (mut j6, joiner6, c6) = joiner_session();
    let nm6 = open.reply(n6, c6, 2_000_010).unwrap();
    let (_, nj6) = j6.open(joiner6, &e, &nm6, &open.invitation.id);
    assert_eq!(open.short_code(n6, &e, &nj6, 2_000_000 + invitation::ATTEMPT_MS), Err(PairError::Closed));
    assert_eq!(open.failures, kept + 1);
    open.failures = kept;
    // An answer after the person's time takes nothing back.
    let n7 = open.begin(Network::Home, 3_000_000).unwrap();
    let (mut j7, joiner7, c7) = joiner_session();
    let nm7 = open.reply(n7, c7, 3_000_010).unwrap();
    let (_, nj7) = j7.open(joiner7, &e, &nm7, &open.invitation.id);
    assert!(open.short_code(n7, &e, &nj7, 3_000_020).is_ok());
    open.end(n7, true, 3_000_020 + invitation::ANSWER_MS);
    assert_eq!(open.failures, kept + 1);
    open.failures = kept;

    // An attempt that runs out of time frees the invitation; its count stays.
    let t = 4_000_000;
    let n8 = open.begin(Network::Home, t).unwrap();
    let (_, _, c8) = joiner_session();
    open.reply(n8, c8, t + 10).unwrap();
    assert_eq!(open.begin(Network::Home, t + invitation::ATTEMPT_MS - 1), Err(PairError::Busy));
    assert_eq!(open.begin(Network::Home, t + invitation::ATTEMPT_MS), Err(PairError::TooMany));
    assert_eq!(open.failures, invitation::MAX_FAILURES);

    // The first message commits to the nonce, the answer and the confirmation carry the nonces.
    for (t, rule) in [(64, "pair/start/commitment"), (65, "pair/reply/nonce"), (66, "pair/confirm/nonce")] {
        let table = crate::msg::tables::of(t).unwrap();
        assert!(table.fields.iter().any(|f| f.rule == rule && f.needed), "{rule}");
    }
}

#[test]
fn a_late_message_of_an_earlier_attempt_changes_nothing() {
    let mut open = invitation::Open {
        invitation: Invitation::new(Vec::new(), Profile::small_device()),
        name: "kettle".into(),
        created_ms: 1,
        expires_ms: 10_000_000,
        used: false,
        failures: 0,
        allowed_key: None,
        attempt: None,
        next_attempt: 0,
    };
    let e = [9u8; 32];
    let first = open.begin(Network::Home, 0).unwrap();
    let (mut j1, joiner1, c1) = joiner_session();
    let nm1 = open.reply(first, c1, 10).unwrap();
    let (_, nj1) = j1.open(joiner1, &e, &nm1, &open.invitation.id);
    // The first attempt's time runs out; a second begins.
    let second = open.begin(Network::Home, invitation::ATTEMPT_MS).unwrap();
    let (_, _, c2) = joiner_session();
    // The first attempt's late messages name it, and change nothing.
    assert_eq!(open.reply(first, c2, invitation::ATTEMPT_MS + 1), Err(PairError::Closed));
    open.reply(second, c2, invitation::ATTEMPT_MS + 2).unwrap();
    assert_eq!(open.short_code(first, &e, &nj1, invitation::ATTEMPT_MS + 3), Err(PairError::Closed));
    open.end(first, true, invitation::ATTEMPT_MS + 4);
    assert_eq!(open.attempt.as_ref().map(|a| a.number), Some(second), "the second attempt still runs");
    assert_eq!(open.begin(Network::Home, invitation::ATTEMPT_MS + 5), Err(PairError::Busy));
    assert_eq!(open.failures, 2);
}

#[test]
fn the_joiner_counts_its_sessions() {
    let mut j = invitation::JoinerAttempts::default();
    let e = [9u8; 32];
    // A session shows its code; until the person answers, no other starts.
    let (code, _) = j.start().unwrap();
    let (shown, _) = j.open(code, &e, &[1; 32], &[3; 16]);
    assert_eq!(shown.len(), 6);
    assert_eq!(j.start().err(), Some(PairError::Busy), "the shown code stays until the person answers");
    // The session dropped before the person answered: it counted.
    j.answered();
    for _ in 1..invitation::MAX_FAILURES {
        let (code, _) = j.start().unwrap();
        j.open(code, &e, &[2; 32], &[3; 16]);
        j.answered();
    }
    assert_eq!(j.start().err(), Some(PairError::TooMany), "three sessions per invitation");
}

/// The short code takes the ID of the invitation each end is using: a
/// joiner that uses another ID shows another code, and the member's end
/// answers as for any code; nothing tells the two apart but the codes.
#[test]
fn the_code_takes_the_invitation_id() {
    let mut open = Open {
        invitation: Invitation::new(Vec::new(), Profile::small_device()),
        name: "kettle".into(),
        created_ms: 1,
        expires_ms: 10_000_000,
        used: false,
        failures: 0,
        allowed_key: None,
        attempt: None,
        next_attempt: 0,
    };
    let e = [9u8; 32];
    let n = open.begin(Network::Home, 100).unwrap();
    let (mut j, joiner, c) = joiner_session();
    let nm = open.reply(n, c, 110).unwrap();
    let mut other = open.invitation.id;
    other[0] ^= 1;
    let (theirs, nj) = j.open(joiner, &e, &nm, &other);
    let ours = open.short_code(n, &e, &nj, 120).unwrap();
    assert_ne!(theirs, ours);
    // The same session's code with the member's ID, at home without one.
    assert_eq!(invitation::short_code(&e, &nj, &nm, &open.invitation.id), ours);
    assert_ne!(invitation::short_code(&e, &nj, &nm, &NO_INVITATION), ours);
}

/// No invitation has the ID of a pairing at home without one: a new one
/// draws again, an open one with it takes no attempt, and a reader
/// refuses it (`invite/shape`, the vector "an ID of zeros").
#[test]
fn no_invitation_has_the_id_of_none() {
    let mut draws = [[0u8; 16], [0u8; 16], [7u8; 16]].into_iter();
    assert_eq!(invitation::not_zero(|| draws.next().unwrap()), [7u8; 16]);
    let home = Path { kind: PathKind::Home, endpoints: vec![], hub_key: None, guest: None, obfuscation: None };
    let mut inv = Invitation::new(vec![home], Profile::small_device());
    assert_ne!(inv.id, NO_INVITATION);
    assert!(Invitation::decode(&inv.encode()).is_ok());
    inv.id = NO_INVITATION;
    let mut open = Open {
        invitation: inv.clone(),
        name: "kettle".into(),
        created_ms: 1,
        expires_ms: 10_000_000,
        used: false,
        failures: 0,
        allowed_key: None,
        attempt: None,
        next_attempt: 0,
    };
    assert_eq!(open.begin(Network::Home, 100), Err(PairError::Refused));
    assert_eq!(open.failures, 0);
    assert_eq!(Invitation::decode(&inv.encode()).err(), Some(invitation::RULE_SHAPE));
}

/// The short code and CPace's channel identifier against the vectors
/// (`testdata/format/messages3.json`, "codes"), which gen.py writes and
/// the Go check computes on its own.
#[test]
fn the_codes_match_their_vectors() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../testdata/format/messages3.json");
    let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let hex = |s: &serde_json::Value| -> Vec<u8> {
        let s = s.as_str().unwrap();
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    };
    let arr = |s: &serde_json::Value| -> [u8; 32] { hex(s).try_into().unwrap() };
    let id = |s: &serde_json::Value| -> [u8; 16] { hex(s).try_into().unwrap() };
    let codes = &v["codes"];
    let short = codes["short_code"].as_array().unwrap();
    assert!(short.len() >= 3);
    for c in short {
        let got = invitation::short_code(&hex(&c["exporter"]), &arr(&c["nj"]), &arr(&c["nm"]), &id(&c["invitation"]));
        assert_eq!(got, c["code"].as_str().unwrap(), "{}", c["name"]);
    }
    let channel = codes["channel_id"].as_array().unwrap();
    assert!(channel.len() >= 3);
    for c in channel {
        let ci = channel_id(&KeyHash(arr(&c["member"])), &KeyHash(arr(&c["joiner"])), &id(&c["invitation"]));
        assert_eq!(crate::certs::hex(&ci), c["ci"].as_str().unwrap(), "{}", c["name"]);
    }
}

#[test]
fn an_offered_admin_key_is_new() {
    let g = G::new();
    let st = g.state();
    let tv = k("tv");
    let with_admin = |a: &K| {
        let mut i = info("tv", ROLE_MEMBER);
        i.admin = Some(a.key.public.clone());
        i
    };
    let rec =
        |i: &Info| joiner_record_any(&st, Signer::Root, None, &point(&tv), i, Checked::default(), Choice::default());
    assert!(rec(&with_admin(&k("tv admin"))).is_ok());
    for (taken, why) in [
        (&tv, "its own member key"),
        (&k("laptop admin"), "another device's admin key"),
        (&k("laptop"), "another device's member key"),
        (&k("root"), "the root key"),
    ] {
        assert_eq!(rec(&with_admin(taken)).err(), Some(decide::Refusal::Taken), "{why}");
    }

    // A removed phone back with a new member key and its old admin key.
    let mut g = G::new();
    let mut d = Device::new(k("old phone").key.clone(), "old phone", ROLE_PHONE);
    d.rights = RIGHT_READ;
    d.admin = Some(k("old phone admin").key.clone());
    let (p, c) = AdminKind::Phone.grants();
    d.powers = p;
    d.commands = c;
    g.rec_root(Kind::device(d));
    let seen = g.seen();
    g.rec_root(Kind::Revoke(Removal { keys: vec![k("old phone").hash, k("old phone admin").hash], seen }));
    let st = g.state();
    let back = joiner_record_any(
        &st,
        Signer::Root,
        None,
        &point(&k("new phone")),
        &with_admin(&k("old phone admin")),
        Checked::default(),
        Choice::default(),
    );
    assert_eq!(back.err(), Some(decide::Refusal::Taken));
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
    let d = joiner_record_any(&st, Signer::Admin, laptop_dev.as_ref(), &point(&tv), &ask, Checked::default(), wide)
        .unwrap();
    assert_eq!(d.rights, RIGHT_READ | RIGHT_SEND);
    assert_eq!(d.store, STORE_FILE, "no evidence: a file, whatever the device says");
    assert!(d.admin.is_none());

    // An ordinary leaf: any admin; a guarded one: the root alone.
    let lamp = k("lamp");
    let leaf = info("lamp", ROLE_LEAF);
    assert!(
        joiner_record_any(
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
        joiner_record_any(&st, Signer::Admin, laptop_dev.as_ref(), &point(&lamp), &leaf, Checked::default(), guarded),
        Err(decide::Refusal::GuardedNeedsRoot)
    );
    assert!(
        joiner_record_any(&st, Signer::Root, None, &point(&lamp), &leaf, Checked::default(), guarded).unwrap().guarded
    );

    // An admin key: only from the root, only with its proof, only as one of the three sets.
    let phone2 = k("phone 2");
    let mut ph = info("phone 2", ROLE_PHONE);
    ph.admin = Some(k("phone 2 admin").key.public.clone());
    let make = Choice { rights: RIGHT_READ | RIGHT_SEND, admin: Some(AdminKind::Phone), guarded: false };
    let none = joiner_record_any(&st, Signer::Root, None, &point(&phone2), &ph, Checked::default(), make).unwrap();
    assert!(none.admin.is_none(), "no proof, no admin key");
    let proven = Checked { admin_pop: true, proof: Some(1) };
    let d = joiner_record_any(&st, Signer::Root, None, &point(&phone2), &ph, proven, make).unwrap();
    assert_eq!((d.powers, d.commands), AdminKind::Phone.grants());
    assert_eq!((d.store, d.proof), (STORE_PROVEN, 1));
    let by_admin =
        joiner_record_any(&st, Signer::Admin, laptop_dev.as_ref(), &point(&phone2), &ph, proven, make).unwrap();
    assert!(by_admin.admin.is_none(), "an admin never gives an admin key");
}

#[test]
fn a_removed_device_does_not_come_back_with_its_key() {
    let mut g = G::new();
    let tv = k("tv");
    let mut d = Device::new(tv.key.clone(), "tv", ROLE_MEMBER);
    d.rights = RIGHT_READ;
    g.rec_root(Kind::device(d));
    let seen = g.seen();
    g.rec_root(Kind::Revoke(Removal { keys: vec![tv.hash], seen }));
    let st = g.state();
    assert!(st.device_by_key(&tv.hash).is_none());
    assert_eq!(
        joiner_record_any(
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
        joiner_record_any(
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
    let d = joiner_record_any(
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
        g.rec(&k("laptop admin"), Kind::device(d));
    } else {
        g.rec_root(Kind::device(d));
    }
    let set = g.set();
    let st = set.state();
    let admitter = if by_admin { laptop.hash } else { k("phone").hash };
    Welcome::build(&set, &st, &admitter, &joiner.hash, 1_793_000_000_000).unwrap()
}

#[test]
fn the_joiner_checks_its_welcome() {
    let mut g = G::new();
    let tv = k("tv");
    let w = admit(&mut g, true, &tv, "tv");
    let group = format::DeviceId(g.gid.0);
    let (_, st) = w.check(&group, &point(&k("laptop")), &point(&tv), Joining::Ordinary).unwrap();
    assert!(st.device_by_key(&tv.hash).is_some());

    // Another group.
    assert_eq!(
        w.check(&format::DeviceId([9; 16]), &point(&k("laptop")), &point(&tv), Joining::Ordinary).err(),
        Some(welcome::Refusal::OtherGroup)
    );
    // Not my record.
    assert_eq!(
        w.check(&group, &point(&k("laptop")), &point(&k("someone")), Joining::Ordinary).err(),
        Some(welcome::Refusal::NotAdmitted)
    );
    // An admitter other than the one who signed: the root phone did not sign this record.
    assert_eq!(
        w.check(&group, &point(&k("phone")), &point(&tv), Joining::Ordinary).err(),
        Some(welcome::Refusal::NotAdmitter)
    );
    // A stranger in the middle.
    assert_eq!(
        w.check(&group, &point(&k("stranger")), &point(&tv), Joining::Ordinary).err(),
        Some(welcome::Refusal::NotAdmitter)
    );

    // A Welcome without the admitter's own record proves nothing.
    let mut cut = w.clone();
    cut.records.retain(|r| !matches!(&r.body().kind, Kind::Device(d) if d.key.hash() == k("laptop").hash));
    assert!(cut.check(&group, &point(&k("laptop")), &point(&tv), Joining::Ordinary).is_err());

    // The root's path comes from the records: a Welcome under another root is another group.
    let mut other = w.clone();
    other.root = k("root 2").key.public.clone();
    assert_eq!(
        other.check(&group, &point(&k("laptop")), &point(&tv), Joining::Ordinary).err(),
        Some(welcome::Refusal::OtherGroup)
    );

    // By the root phone.
    let tab = k("tablet");
    let w = admit(&mut g, false, &tab, "tablet");
    assert!(w.check(&group, &point(&k("phone")), &point(&tab), Joining::Ordinary).is_ok());
    // A guarded leaf takes the root's own record only, not an admin's.
    assert!(w.check(&group, &point(&k("phone")), &point(&tab), Joining::Guarded).is_ok());
    let by_admin = admit(&mut g, true, &k("lamp"), "lamp");
    assert_eq!(
        by_admin.check(&group, &point(&k("laptop")), &point(&k("lamp")), Joining::Guarded).err(),
        Some(welcome::Refusal::NotAdmitter)
    );
    assert!(by_admin.check(&group, &point(&k("laptop")), &point(&k("lamp")), Joining::Ordinary).is_ok());
    assert_eq!(
        w.check(&group, &point(&k("laptop")), &point(&tab), Joining::Ordinary).err(),
        Some(welcome::Refusal::NotAdmitter)
    );

    // The encoding reads back.
    assert_eq!(Welcome::decode(&w.encode()).unwrap(), w);
    let (root, envs, time, recovery, recovery2) = Welcome::parts(&w.encode()).unwrap();
    assert_eq!(root, g.root.key.public);
    assert_eq!(recovery, k("recovery").key.public);
    assert_eq!(recovery2, crate::testkit::rk2().public());
    assert_eq!(envs.len(), w.records.len());
    assert_eq!(time, 1_793_000_000_000);
    // A recovery key other than the group's gives another Group ID.
    let mut false_key = w.clone();
    false_key.recovery = k("not the recovery key").key.public.clone();
    let back = Welcome::decode(&false_key.encode()).unwrap();
    assert_eq!(
        back.check(&group, &point(&k("phone")), &point(&tab), Joining::Ordinary).err(),
        Some(welcome::Refusal::OtherGroup)
    );
    // The root's key as the recovery key is no Welcome.
    let mut same = w.clone();
    same.recovery = same.root.clone();
    assert_eq!(Welcome::decode(&same.encode()).err(), Some(welcome::RULE_RECOVERY));
}

/// Two changes of root: the joiner takes both heads and the newest list
/// from its Welcome, and the newest root's record of it counts.
#[test]
fn the_joiner_takes_two_changes_of_root() {
    let mut g = G::new();
    let (n1, n2) = (k("root n1"), k("root n2"));
    g.change(&n1);
    phone_admin(&mut g, &n1, &k("phone b"), &k("admin b"), true);
    g.change(&n2);
    phone_admin(&mut g, &n2, &k("phone c"), &k("admin c"), true);
    let slate = k("slate");
    let mut d = Device::new(slate.key.clone(), "slate", ROLE_MEMBER);
    d.rights = RIGHT_READ | RIGHT_SEND;
    g.rec(&n2, Kind::device(d));

    let set = g.set();
    let st = set.state();
    assert_eq!(st.roots, vec![g.root.hash, n1.hash, n2.hash]);
    assert!(st.device_by_key(&slate.hash).is_some());
    let w = Welcome::build(&set, &st, &k("phone c").hash, &slate.hash, 1_793_000_000_000).unwrap();
    let group = format::DeviceId(g.gid.0);
    let back = Welcome::decode(&w.encode()).unwrap();
    let r = back.check(&group, &point(&k("phone c")), &point(&slate), Joining::Ordinary);
    let (mine, st) = r.unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(st.roots, vec![g.root.hash, n1.hash, n2.hash]);
    assert_eq!(st.chain().len(), 2);
    assert_eq!(mine.len(), set.len(), "every record of the Welcome is kept");
    // A guarded leaf may take it too: the newest root signed it, and the
    // admitter is the newest root's device.
    assert!(back.check(&group, &point(&k("phone c")), &point(&slate), Joining::Guarded).is_ok());
    // Without the list the joiner does not apply the newest change: n1 is
    // the root there, and n2's record of it does not count.
    let mut bare = back.clone();
    bare.list = None;
    assert_eq!(
        bare.check(&group, &point(&k("phone c")), &point(&slate), Joining::Ordinary).err(),
        Some(welcome::Refusal::NotAdmitted)
    );
    // A list its heads do not name is damage.
    let mut wrong = back.clone();
    wrong.list = Some(crate::records::List(vec![RecordId([3; 32])]).encode());
    assert_eq!(
        wrong.check(&group, &point(&k("phone c")), &point(&slate), Joining::Ordinary).err(),
        Some(welcome::Refusal::Damaged)
    );
}

/// A Welcome from a group with two heads at one seq: the joiner does not
/// join a group that is stopped for good.
#[test]
fn the_joiner_sees_a_fork_in_its_welcome() {
    let mut g = G::new();
    let tv = k("tv");
    g.change(&k("root n1"));
    let twin = {
        let body = Body {
            group: g.gid,
            signer: k("recovery").hash,
            seq: 1,
            prev: None,
            time_ms: 0,
            kind: Kind::Recovery {
                root: k("root n9").key.clone(),
                list: [7; 32],
                from: 0,
                first: RecordId([0xf1; 32]),
                signer2: crate::testkit::rk2().key().hash(),
            },
            held: false,
        };
        crate::testkit::sign_by(body, &k("recovery"))
    };
    g.recs.push(twin);
    phone_admin(&mut g, &k("root n1"), &k("phone b"), &k("admin b"), true);
    let mut d = Device::new(tv.key.clone(), "tv", ROLE_MEMBER);
    d.rights = RIGHT_READ;
    g.rec(&k("root n1"), Kind::device(d));
    let set = g.set();
    let st = set.state();
    let w = Welcome::build(&set, &st, &k("phone b").hash, &tv.hash, 1_793_000_000_000).unwrap();
    assert_eq!(w.records.iter().filter(|r| matches!(r.body().kind, Kind::Recovery { .. })).count(), 2);
    let group = format::DeviceId(g.gid.0);
    assert_eq!(
        w.check(&group, &point(&k("phone b")), &point(&tv), Joining::Ordinary).err(),
        Some(welcome::Refusal::Stopped)
    );
}

/// A Welcome that carries a head this version cannot read: the joiner
/// does not join a group that is halted on it.
#[test]
fn the_joiner_does_not_join_over_a_head_it_cannot_read() {
    use crate::format::cbor::{self, Value};
    let mut g = G::new();
    let tv = k("tv");
    let w = admit(&mut g, true, &tv, "tv");
    let body = Body {
        group: g.gid,
        signer: k("recovery").hash,
        seq: 1,
        prev: None,
        time_ms: 0,
        kind: Kind::Recovery {
            root: k("root n1").key.clone(),
            list: [5; 32],
            from: 0,
            first: RecordId([0xf1; 32]),
            signer2: crate::testkit::rk2().key().hash(),
        },
        held: false,
    };
    let encoded = body.encode();
    let Ok(Value::Map(mut m)) = cbor::decode(&encoded) else { panic!("a body is a map") };
    m.push((99, Value::Uint(1)));
    let bytes = Value::Map(m).encode();
    let sig2 = crate::testkit::rk2().sign(&bytes, crate::records::pq::CONTEXT_RECORD).unwrap();
    let sig = crate::records::key::sign_es256(
        &k("recovery"),
        crate::records::LABEL_RECORD,
        &crate::records::with_sig2(&bytes, &sig2),
    )
    .unwrap();
    let later = Record::decode(&crate::format::envelope::write(&bytes, &sig, Some(&sig2))).unwrap();
    assert!(later.body().held);
    let mut w = w;
    w.records.insert(0, later);
    let group = format::DeviceId(g.gid.0);
    assert_eq!(
        w.check(&group, &point(&k("laptop")), &point(&tv), Joining::Ordinary).err(),
        Some(welcome::Refusal::Stopped)
    );
}

/// A phone admin's device in the group, with the phone's admin grants.
fn phone_admin(g: &mut G, by: &K, member: &K, admin: &K, holds_root: bool) {
    let mut d = Device::new(member.key.clone(), "phone", ROLE_PHONE);
    d.rights = RIGHT_READ | RIGHT_SEND;
    d.admin = Some(admin.key.clone());
    let (p, c) = AdminKind::Phone.grants();
    d.powers = p;
    d.commands = c;
    d.holds_root = holds_root;
    g.rec(by, Kind::device(d));
}

/// A guarded leaf's record by `root`.
fn guarded_leaf(g: &mut G, root: &K, leaf: &K) {
    let mut d = Device::new(leaf.key.clone(), "lock", ROLE_LEAF);
    d.guarded = true;
    d.rights = RIGHT_READ;
    g.rec(root, Kind::device(d));
}

/// A guarded leaf joins after a change of root only by the newest root's
/// device: not by the old root's, nor by an admin.
#[test]
fn a_guarded_leaf_joins_by_the_newest_root_only() {
    let mut g = G::new();
    let (n1, lock) = (k("root n1"), k("lock"));
    g.change(&n1);
    phone_admin(&mut g, &n1, &k("phone a"), &k("admin a"), true);
    guarded_leaf(&mut g, &n1, &lock);
    let group = format::DeviceId(g.gid.0);
    let set = g.set();
    let st = set.state();
    let w = Welcome::build(&set, &st, &k("phone a").hash, &lock.hash, 1_793_000_000_000).unwrap();
    let (_, st) = w.check(&group, &point(&k("phone a")), &point(&lock), Joining::Guarded).unwrap();
    assert_eq!(st.roots, vec![g.root.hash, n1.hash]);
    // The old root's phone is no admitter of it.
    let w = Welcome::build(&set, &st, &k("phone").hash, &lock.hash, 1_793_000_000_000).unwrap();
    assert_eq!(
        w.check(&group, &point(&k("phone")), &point(&lock), Joining::Guarded).err(),
        Some(welcome::Refusal::NotAdmitter)
    );
}

#[test]
fn an_intro_proves_a_new_device() {
    let mut g = G::new();
    let tv = k("tv");
    admit(&mut g, true, &tv, "tv");
    let full = g.set();
    let st = full.state();
    let intro = Intro::of(&full, &st, &tv.hash, None).unwrap();
    // The tv's record, the laptop's record that gave the admin key; no more.
    assert_eq!(intro.records.len(), 2);

    // A peer that knows the root phone and the laptop, but not the tv yet.
    let mut old = g.empty();
    old.insert_all(g.recs[..2].iter().cloned());
    let me = fhash(&k("phone"));
    let new = intro.check(&old, &me, &point(&tv)).unwrap();
    assert_eq!(new.len(), 1);

    // Someone else's intro under the tv's key proves nothing for another key.
    assert_eq!(intro.check(&old, &me, &point(&k("stranger"))), Err(intro::Refusal::NotMember));

    // A record that does not verify closes it.
    let mut bad = intro.clone();
    let r = bad.records.pop().unwrap();
    let mut sig = r.sig().to_vec();
    sig[5] ^= 1;
    bad.records.push(Record::from_parts(r.body_bytes().to_vec(), sig, None, r.body().clone()).unwrap());
    assert_eq!(bad.check(&old, &me, &point(&tv)), Err(intro::Refusal::Broken));

    // Too many records.
    let mut big = intro.clone();
    while big.records.len() <= intro::MAX_RECORDS {
        big.records.push(intro.records[0].clone());
    }
    assert_eq!(big.check(&old, &me, &point(&tv)), Err(intro::Refusal::TooBig));

    // A removed device's intro does not bring it back.
    let seen = g.seen();
    g.rec_root(Kind::Revoke(Removal { keys: vec![tv.hash], seen }));
    let mut now = g.empty();
    now.insert_all(g.recs.iter().cloned());
    assert_eq!(intro.check(&now, &me, &point(&tv)), Err(intro::Refusal::NotMember));

    // The message reads back.
    assert_eq!(Intro::read(&intro.message()).unwrap(), intro);
    // The message's envelopes read back.
    let (envs, keys) = Intro::envelopes(&intro.message()).unwrap();
    assert_eq!(envs.len(), 2);
    assert!(keys.is_none());
}

/// AmneziaWG settings: jc, jmin, jmax, the four sizes, the four header
/// ranges.
fn obfuscation_with(jc: u64, jmin: u64, jmax: u64) -> Vec<u8> {
    use crate::format::Value::{Array, Map, Uint};
    let h = |a: u64| Array(vec![Uint(a), Uint(a + 100)]);
    Map(vec![
        (1, Uint(jc)),
        (2, Uint(jmin)),
        (3, Uint(jmax)),
        (4, Array(vec![Uint(15), Uint(20), Uint(0), Uint(0)])),
        (5, Array(vec![h(1000), h(2000), h(3000), h(4000)])),
    ])
    .encode()
}

fn obfuscation() -> crate::msg::Obfuscation {
    crate::msg::Obfuscation::decode(&obfuscation_with(4, 40, 70), "x").unwrap()
}

fn invitation() -> Invitation {
    Invitation::new(
        vec![
            Path { kind: PathKind::Home, endpoints: vec![], hub_key: None, guest: None, obfuscation: None },
            Path {
                kind: PathKind::Guest,
                endpoints: vec!["192.0.2.1:51820".into()],
                hub_key: Some([1; 32]),
                guest: Some(([2; 32], [3; 32])),
                obfuscation: None,
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
    let mut twice = inv.clone();
    twice.paths[1].endpoints = vec!["192.0.2.1:51820".into(); 2];
    assert_eq!(Invitation::decode(&twice.encode()), Err(invitation::RULE_PATH), "an endpoint twice");

    // A group with AmneziaWG gives its settings on the guest path; never on
    // the home path, and only in their shape.
    let mut awg = inv.clone();
    awg.paths[1].obfuscation = Some(obfuscation());
    assert_eq!(Invitation::parse(&awg.text()).unwrap(), awg);
    let mut home = inv.clone();
    home.paths[0].obfuscation = Some(obfuscation());
    assert_eq!(Invitation::decode(&home.encode()), Err(invitation::RULE_OBFUSCATION));
    assert!(crate::msg::Obfuscation::decode(&obfuscation_with(300, 1, 2), "x").is_err(), "jc above 128");
    assert!(crate::msg::Obfuscation::decode(&obfuscation_with(4, 9, 2), "x").is_err(), "jmin above jmax");
    let small = Invitation::new(
        vec![Path { kind: PathKind::Home, endpoints: vec![], hub_key: None, guest: None, obfuscation: None }],
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
        attempt: None,
        next_attempt: 0,
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

#[test]
fn a_request_waits_for_an_admin() {
    use super::waiting::{self, Held};
    let mut g = G::new();
    let hub = k("hub");
    let mut d = Device::new(hub.key.clone(), "hub", ROLE_MEMBER);
    d.rights = RIGHT_READ | RIGHT_SEND | RIGHT_HUB;
    d.caps = CAP_HUB;
    g.rec_root(Kind::device(d));
    let tv = k("tv");
    let mut d = Device::new(tv.key.clone(), "tv", ROLE_MEMBER);
    d.rights = RIGHT_READ | RIGHT_SEND;
    g.rec_root(Kind::device(d));
    let st = g.state();
    let id = |x: &K| st.device_by_key(&x.hash).unwrap().id;

    // Who holds for whom.
    assert!(waiting::holder_may_send(&st, &id(&k("phone"))), "the root's device");
    assert!(waiting::holder_may_send(&st, &id(&k("laptop"))), "an admin with admit");
    assert!(!waiting::holder_may_send(&st, &id(&tv)), "a member that may not admit");
    assert!(!waiting::holder_may_send(&st, &format::DeviceId([9; 16])), "a stranger");
    assert!(waiting::admin_may_take(&st, &id(&hub)), "a hub");
    assert!(!waiting::admin_may_take(&st, &id(&tv)), "a device that may not be a hub");
    assert!(waiting::holder_takes_dismiss(&st, &id(&k("phone"))), "dismissed by the root's device");
    assert!(!waiting::holder_takes_dismiss(&st, &id(&tv)), "not by a member that may not admit");

    // The holder keeps one request per invitation and key.
    let inv = [5u8; 16];
    let joiner = k("joiner");
    let mut ask = info("kitchen tablet", ROLE_MEMBER);
    ask.invite = Some(inv);
    let mut held = Held::default();
    let (t0, day) = (1_000_000u64, waiting::MAX_WAIT_MS);
    assert!(held.knock(&point(&joiner), ask.clone(), Network::Guest, waiting::Came::Path(inv), t0, t0 + 3 * day));
    assert!(held.knock(
        &point(&joiner),
        ask.clone(),
        Network::Guest,
        waiting::Came::Path(inv),
        t0 + 60_000,
        t0 + 3 * day
    ));
    assert_eq!(held.requests.len(), 1);
    assert_eq!(held.requests[0].attempts, 2);
    assert!(
        !held.knock(
            &point(&joiner),
            info("no invite", ROLE_MEMBER),
            Network::Guest,
            waiting::Came::Path(inv),
            t0,
            t0 + day
        ),
        "no invitation named"
    );
    assert!(
        !Held::default().knock(
            &point(&k("late")),
            ask.clone(),
            Network::Guest,
            waiting::Came::Path(inv),
            t0 + day,
            t0 + day
        ),
        "past the guest path's expiry"
    );

    // The admin reads what waited and for how long.
    let msg = held.message(t0 + 120_000).unwrap();
    assert_eq!(crate::msg::check(&msg), Ok(crate::msg::tables::T_WAITING));
    let seen = waiting::read(&msg).unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!((seen[0].waited_ms, seen[0].attempts, seen[0].network), (120_000, 2, Network::Guest));
    assert_eq!(seen[0].info, ask);
    assert_eq!(seen[0].key, point(&joiner).to_vec());

    // At most a day, even when the guest path is good for longer.
    assert!(held.message(t0 + day).is_none(), "dropped after a day");
    // And not past the guest path.
    assert!(held.knock(&point(&joiner), ask.clone(), Network::Guest, waiting::Came::Path(inv), t0, t0 + 1000));
    assert!(held.message(t0 + 1000).is_none());

    // At most 16.
    for i in 0..20u8 {
        let mut a = ask.clone();
        a.invite = Some([i; 16]);
        let kept = held.knock(&point(&joiner), a, Network::Bypass, waiting::Came::Path([i; 16]), t0, t0 + day);
        assert_eq!(kept, usize::from(i) < waiting::MAX_REQUESTS);
    }

    // The admin dismisses one key's request, then a whole invitation's.
    let other = k("other");
    let mut a = ask.clone();
    a.invite = Some([1; 16]);
    held.requests.retain(|r| r.invite != [1; 16] && r.invite != [2; 16]);
    assert!(held.knock(&point(&joiner), a.clone(), Network::Guest, waiting::Came::Path([1; 16]), t0, t0 + day));
    assert!(held.knock(&point(&other), a, Network::Guest, waiting::Came::Path([1; 16]), t0, t0 + day));
    let (i, key) = waiting::read_dismiss(&waiting::dismiss_message(&[1; 16], Some(&fhash(&other)))).unwrap();
    held.dismiss(&i, key.as_ref());
    assert_eq!(held.requests.iter().filter(|r| r.invite == [1; 16]).count(), 1);
    let (i, key) = waiting::read_dismiss(&waiting::dismiss_message(&[1; 16], None)).unwrap();
    held.dismiss(&i, key.as_ref());
    assert_eq!(held.requests.iter().filter(|r| r.invite == [1; 16]).count(), 0);

    // A request whose Info names another invitation than its own is refused.
    let mut h2 = Held::default();
    assert!(h2.knock(&point(&joiner), ask.clone(), Network::Guest, waiting::Came::Path(inv), t0, t0 + day));
    h2.requests[0].invite = [6; 16];
    assert_eq!(waiting::read(&h2.message(t0).unwrap()), Err(waiting::RULE_WAITING));
}

#[test]
fn an_intro_is_checked_only_when_it_ends_in_its_sender() {
    let mut g = G::new();
    for i in 0..200 {
        let mut d = Device::new(k(&format!("device {i}")).key.clone(), "d", ROLE_MEMBER);
        d.rights = RIGHT_READ;
        g.rec_root(Kind::device(d));
    }
    let set = g.set();
    let me = fhash(&k("phone"));
    let stranger = k("stranger");
    // An intro that does not end in the sender's record is refused before
    // any work on the set: it costs far less than checking the set's records.
    let empty = Intro::default();
    let t = std::time::Instant::now();
    for _ in 0..5 {
        assert_eq!(empty.check(&set, &me, &point(&stranger)), Err(intro::Refusal::NotMember));
    }
    let per_intro = t.elapsed() / 5;
    let t = std::time::Instant::now();
    for _ in 0..20 {
        let mut s = g.empty();
        let _ = s.insert(g.recs[1].clone());
    }
    let per_record = t.elapsed() / 20;
    assert!(per_intro < per_record * 20, "{per_intro:?} for an intro, {per_record:?} for one record");
    // Another device's record at the end: refused too.
    let other = Intro { records: vec![g.recs[1].clone()], keys: None };
    assert_eq!(other.check(&set, &me, &point(&stranger)), Err(intro::Refusal::NotMember));

    // At most a few intros per network in a window.
    use core::net::IpAddr;
    let ip = |t: &str| t.parse::<IpAddr>().unwrap();
    let mut lim = intro::Limiter::default();
    for _ in 0..intro::MAX_PER_WINDOW {
        assert!(lim.allow(ip("192.0.2.1"), 0));
    }
    assert!(!lim.allow(ip("192.0.2.1"), 1));
    assert!(lim.allow(ip("192.0.2.2"), 1), "another address");
    assert!(lim.allow(ip("192.0.2.1"), intro::WINDOW_MS), "the next window");
}

#[test]
fn one_host_cannot_keep_intros_out() {
    use core::net::IpAddr;
    let ip = |t: &str| t.parse::<IpAddr>().unwrap();
    let mut lim = intro::Limiter::default();
    // One host spends its own share, not its home's.
    for _ in 0..intro::MAX_PER_WINDOW {
        assert!(lim.allow(ip("192.168.1.7"), 0));
        assert!(lim.allow(ip("2001:db8:0:1::7"), 0));
    }
    assert!(!lim.allow(ip("192.168.1.7"), 0));
    assert!(lim.allow(ip("192.168.1.8"), 0), "another device of the same home");
    assert!(lim.allow(ip("2001:db8:0:1::8"), 0), "the same over IPv6");
    // A host with a few addresses spends their shares, not the network's.
    let mut lim = intro::Limiter::default();
    for i in 0..8u32 {
        for _ in 0..intro::MAX_PER_WINDOW {
            assert!(lim.allow(ip(&alloc::format!("2001:db8:0:1::{:x}", 0x100 + i)), 0));
        }
    }
    assert!(lim.allow(ip("2001:db8:0:1::8"), 0), "another device of the same /64");
    // A host with a whole /64 spends the network's higher share, no more.
    let mut lim = intro::Limiter::default();
    let taken = (0..600u32).filter(|i| lim.allow(ip(&alloc::format!("2001:db8:0:1::{i:x}")), 0)).count();
    assert_eq!(taken, usize::try_from(intro::MAX_PER_NETWORK).unwrap());
    // A full table gives way to a newcomer.
    for i in 0..intro::MAX_ADDRESSES {
        assert!(lim.allow(ip(&alloc::format!("2001:db8:{i:x}::1")), 1));
    }
    assert!(lim.allow(ip("2001:db9::5"), 2), "a new device's intro still checked");
}

#[test]
fn the_record_follows_the_invitation_profile() {
    let g = G::new();
    let st = g.state();
    let laptop = st.device_by_key(&k("laptop").hash).cloned();
    let phone = st.device_by_key(&k("phone").hash).cloned();
    let kettle = info("kettle", ROLE_LEAF);
    // A small device's invitation: a leaf with no rights, whoever admits.
    let small = Profile::small_device();
    let wide = Choice { rights: RIGHT_READ | RIGHT_SEND | RIGHT_SECRETS, admin: None, guarded: false };
    for (signer, own) in [(Signer::Admin, laptop.as_ref()), (Signer::Root, phone.as_ref())] {
        let d =
            decide::joiner_record(&st, signer, own, &point(&k("kettle")), &kettle, &small, Checked::default(), wide)
                .unwrap();
        assert_eq!(d.rights, 0, "{signer:?}");
    }
    // A guarded profile: a guarded leaf, which an admin may not admit.
    let lock = Profile { guarded: true, ..small };
    let li = info("lock", ROLE_LEAF);
    assert_eq!(
        decide::joiner_record(
            &st,
            Signer::Admin,
            laptop.as_ref(),
            &point(&k("lock")),
            &li,
            &lock,
            Checked::default(),
            Choice::default()
        ),
        Err(decide::Refusal::GuardedNeedsRoot)
    );
    let d = decide::joiner_record(
        &st,
        Signer::Root,
        phone.as_ref(),
        &point(&k("lock")),
        &li,
        &lock,
        Checked::default(),
        Choice::default(),
    )
    .unwrap();
    assert!(d.guarded);
    // Another role than the profile's, or a hub it does not give.
    assert_eq!(
        decide::joiner_record(
            &st,
            Signer::Admin,
            laptop.as_ref(),
            &point(&k("tv")),
            &info("tv", ROLE_MEMBER),
            &small,
            Checked::default(),
            Choice::default()
        ),
        Err(decide::Refusal::AsksMore)
    );
    let mut hub = info("tv", ROLE_MEMBER);
    hub.caps = CAP_HUB;
    let member = Profile { role: ROLE_MEMBER, rights: RIGHT_READ | RIGHT_SEND, home_only: false, guarded: false };
    assert_eq!(
        decide::joiner_record(
            &st,
            Signer::Admin,
            laptop.as_ref(),
            &point(&k("tv")),
            &hub,
            &member,
            Checked::default(),
            Choice::default()
        ),
        Err(decide::Refusal::AsksMore)
    );
    // The admission checks the admitter itself: a device without admit.
    assert_eq!(
        decide::joiner_record(
            &st,
            Signer::Admin,
            None,
            &point(&k("tv")),
            &info("tv", ROLE_MEMBER),
            &member,
            Checked::default(),
            Choice::default()
        ),
        Err(decide::Refusal::NotAdmitter)
    );
}

#[test]
fn one_invitation_takes_few_waiting_places() {
    use super::waiting::{self, Held};
    let mut held = Held::default();
    let (t0, exp) = (1_000_000u64, 1_000_000u64 + waiting::MAX_WAIT_MS);
    for i in 0..waiting::MAX_REQUESTS {
        let mut a = info("x", ROLE_MEMBER);
        a.invite = Some([5; 16]);
        let kept =
            held.knock(&point(&k(&format!("fresh {i}"))), a, Network::Guest, waiting::Came::Path([5; 16]), t0, exp);
        assert_eq!(kept, i < waiting::MAX_PER_INVITATION);
    }
    let mut real = info("kitchen tablet", ROLE_MEMBER);
    real.invite = Some([6; 16]);
    // The invitation is the guest path's, as the holder knows it: an Info
    // that names another is refused, so made-up names take no place.
    for i in 0..waiting::MAX_REQUESTS {
        let mut a = info("x", ROLE_MEMBER);
        a.invite = Some([u8::try_from(i).unwrap().wrapping_add(100); 16]);
        assert!(!held.knock(
            &point(&k(&format!("named {i}"))),
            a,
            Network::Guest,
            waiting::Came::Path([5; 16]),
            t0,
            exp
        ));
    }
    // From home, where no guest path tells the invitation: one place per
    // source address, a few in all, the oldest giving way.
    let at = |n: u8| waiting::Came::Home(core::net::IpAddr::from([192, 168, 1, n]));
    for i in 0..4u8 {
        let mut a = info("x", ROLE_MEMBER);
        a.invite = Some([i.wrapping_add(100); 16]);
        assert!(held.knock(&point(&k(&format!("home {i}"))), a, Network::Home, at(7), t0 + u64::from(i), exp));
    }
    let home = |h: &Held| h.requests.iter().filter(|r| matches!(r.came, waiting::Came::Home(_))).count();
    assert_eq!(home(&held), 1, "one host at home holds one place");
    for n in 0..40u8 {
        let mut a = info("x", ROLE_MEMBER);
        a.invite = Some([n.wrapping_add(150); 16]);
        assert!(held.knock(
            &point(&k(&format!("host {n}"))),
            a,
            Network::Home,
            at(20 + n),
            t0 + 10 + u64::from(n),
            exp
        ));
    }
    assert_eq!(home(&held), waiting::MAX_HOME);
    let mut late = info("kitchen speaker", ROLE_MEMBER);
    late.invite = Some([7; 16]);
    assert!(held.knock(&point(&k("speaker")), late, Network::Home, at(99), t0 + 100, exp), "the newest gets a place");
    assert!(held.requests.iter().any(|r| r.key == point(&k("speaker")).to_vec()));
    assert!(
        held.knock(&point(&k("real tablet")), real, Network::Guest, waiting::Came::Path([6; 16]), t0 + 1, exp),
        "another invitation still has room"
    );
}

/// Under its budget a Welcome carries the recovery records and the list,
/// the new root's first checkpoint, the removals that count and the two
/// devices' records before anything else; when even those do not fit, no
/// Welcome is built, nothing of them is cut.
#[test]
fn a_welcome_carries_what_it_must_first() {
    let mut g = G::new();
    let (n1, tv, slate) = (k("root n1"), k("tv"), k("slate"));
    g.change(&n1);
    phone_admin(&mut g, &n1, &k("phone b"), &k("admin b"), true);
    let mut d = Device::new(tv.key.clone(), "tv", ROLE_MEMBER);
    d.rights = RIGHT_READ;
    g.rec(&n1, Kind::device(d));
    let seen = g.seen();
    let removal = g.rec(&n1, Kind::Revoke(Removal { keys: vec![tv.hash], seen }));
    let mut d = Device::new(slate.key.clone(), "slate", ROLE_MEMBER);
    d.rights = RIGHT_READ | RIGHT_SEND;
    let own = g.rec(&n1, Kind::device(d));
    let mut filler = Vec::new();
    for i in 0..40u64 {
        filler.push(g.rec(&n1, Kind::Copies { incoming_ms: 5_000 + i, seen: vec![] }).id());
    }
    let set = g.set();
    let st = set.state();
    assert!(st.revoked.contains(&tv.hash));
    let admitter = k("phone b").hash;
    let all = Welcome::build(&set, &st, &admitter, &slate.hash, 1).unwrap();
    let full: usize = all.records.iter().map(Record::size).sum::<usize>() + all.list.as_ref().map_or(0, Vec::len);
    let some = full - 30 * set.get(&filler[0]).unwrap().size();
    let w = Welcome::build_within(&set, &st, &admitter, &slate.hash, 1, some).unwrap();
    let has = |id: &RecordId| w.records.iter().any(|r| r.id() == *id);
    let heads: Vec<RecordId> =
        g.recs.iter().filter(|r| matches!(r.body().kind, Kind::Recovery { .. })).map(Record::id).collect();
    assert!(heads.iter().all(has) && w.list.is_some());
    assert!(set.firsts().keys().all(has));
    assert!(has(&removal.id()) && has(&own.id()));
    assert!(filler.iter().filter(|id| has(id)).count() <= 10);
    let group = format::DeviceId(g.gid.0);
    let (_, back) = Welcome::decode(&w.encode())
        .unwrap()
        .check(&group, &point(&k("phone b")), &point(&slate), Joining::Ordinary)
        .unwrap();
    assert_eq!(back.roots, st.roots);
    assert!(back.revoked.contains(&tv.hash));
    // Too small for what it must carry: no Welcome.
    assert_eq!(Welcome::build_within(&set, &st, &admitter, &slate.hash, 1, 600), Err(welcome::TooLarge));
}

/// The joiner's record comes with its signer's chain below it: a budget
/// that cannot hold that chain gives no Welcome, not one the joiner would
/// refuse.
#[test]
fn a_welcome_carries_the_chain_of_the_joiners_record() {
    let mut g = G::new();
    let slate = k("slate");
    for i in 0..20u64 {
        g.rec_root(Kind::Copies { incoming_ms: 5_000 + i, seen: vec![] });
    }
    let mut d = Device::new(slate.key.clone(), "slate", ROLE_MEMBER);
    d.rights = RIGHT_READ | RIGHT_SEND;
    g.rec_root(Kind::device(d));
    let set = g.set();
    let st = set.state();
    let admitter = k("phone").hash;
    let all = Welcome::build(&set, &st, &admitter, &slate.hash, 1).unwrap();
    let full: usize = all.records.iter().map(Record::size).sum::<usize>() + all.list.as_ref().map_or(0, Vec::len);
    let group = format::DeviceId(g.gid.0);
    assert!(all.check(&group, &point(&k("phone")), &point(&slate), Joining::Ordinary).is_ok());
    assert_eq!(Welcome::build_within(&set, &st, &admitter, &slate.hash, 1, full - 1), Err(welcome::TooLarge));
}

/// Every gate on admitting asks one predicate (`State::stopped`): two
/// histories of the current root stop it as a recovery record this version
/// cannot read does. Sync goes on in the root fork only, so that the pair
/// reaches every member.
#[test]
fn every_gate_asks_whether_the_group_is_stopped() {
    use super::waiting;
    let mut g = G::new();
    let hub = k("hub");
    let mut d = Device::new(hub.key.clone(), "hub", ROLE_MEMBER);
    d.rights = RIGHT_READ | RIGHT_SEND | RIGHT_HUB;
    d.caps = CAP_HUB;
    let last = g.rec_root(Kind::device(d));
    let open = g.state();
    let hub_id = open.device_by_key(&hub.hash).unwrap().id;
    let root = k("root");
    assert!(!open.stopped());
    assert!(decide::may_admit(&open, &k("laptop").hash, Signer::Admin, &root.hash));
    assert!(waiting::admin_may_take(&open, &hub_id));
    // A second record of the root at the seq of its newest one.
    let b = last.body();
    let twin = Body {
        group: g.gid,
        signer: b.signer,
        seq: b.seq,
        prev: b.prev,
        time_ms: 0,
        kind: Kind::device(Device::new(k("other").key.clone(), "other", ROLE_MEMBER)),
        held: false,
    };
    let twin = Record::sign(twin, &root).unwrap();
    let mut set = g.set();
    set.insert(twin.clone()).unwrap();
    let forked = set.state();
    assert!(forked.stopped() && !forked.halted());
    let mut halted = open.clone();
    halted.update_needed = true;
    for (name, st) in [("root fork", &forked), ("halted", &halted)] {
        assert!(st.stopped(), "{name}");
        assert!(!decide::may_admit(st, &k("laptop").hash, Signer::Admin, &root.hash), "{name}");
        assert!(!decide::may_admit(st, &k("phone").hash, Signer::Root, &root.hash), "{name}");
        assert!(!waiting::admin_may_take(st, &hub_id), "{name}");
        assert!(!st.may_command(&k("laptop admin").hash) && !st.may_command(&root.hash), "{name}");
    }
    assert!(set.write_checkpoint(&forked, &root, 0).is_err());
    let laptop_id = open.device_by_key(&k("laptop").hash).unwrap().id;
    assert_eq!(
        crate::peer::standing(&forked, &k("phone").hash, &point(&k("laptop"))),
        crate::peer::Standing::Member(laptop_id)
    );
    assert_eq!(crate::peer::standing(&halted, &k("phone").hash, &point(&k("laptop"))), crate::peer::Standing::Halted);
    // A joiner handed the pair does not join.
    let tv = k("tv");
    let mut w = admit(&mut g, true, &tv, "tv");
    w.records.push(twin);
    let group = format::DeviceId(g.gid.0);
    assert_eq!(
        w.check(&group, &point(&k("laptop")), &point(&tv), Joining::Ordinary).err(),
        Some(welcome::Refusal::Stopped)
    );
}
