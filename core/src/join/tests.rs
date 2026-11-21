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
use super::welcome::{self, Joining, Way, Welcome};
use super::*;
use crate::certs::sha256;
use crate::format::{self, Alg};
use crate::records::body::*;
use crate::records::set::RecordSet;
use crate::records::{Body, GroupId, Key, KeyHash, Kind, Record, RecordId, State};

mod session;

struct K {
    sk: SigningKey,
    key: Key,
    hash: KeyHash,
}

impl ExternalKey for K {
    fn public(&self) -> Vec<u8> {
        self.key.public().to_vec()
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
    k.key.public().to_vec().try_into().unwrap()
}

fn fhash(k: &K) -> format::KeyHash {
    format::Key::new(Alg::Es256, k.key.public()).hash()
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

    fn rec(&mut self, by: &K, mut kind: Kind) -> Record {
        let (seq, prev) = match self.heads.get(&by.hash) {
            Some((s, id)) => (s + 1, Some(*id)),
            None => (1, None),
        };
        // As an honest admin's device: a key's first record names the
        // root's head, so what it signs stands on its grant line.
        let root = k("root").hash;
        if by.hash != root
            && seq == 1
            && let Some(&(rs, rid)) = self.heads.get(&root)
            && let Kind::Device(d) = &mut kind
            && !d.seen.iter().any(|x| x.key == root)
        {
            d.seen.push(crate::records::body::Seen { key: root, seq: rs, id: rid });
            d.seen.sort_by_key(|x| x.key);
        }
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
        // L: after a change of root the admin keys of the roots before it
        // are no keys of the set, and their records are refused as such;
        // nothing else is refused.
        let st = s.state();
        let old_admin = |id: &crate::records::RecordId| {
            self.recs.iter().find(|r| r.id() == *id).is_some_and(|r| {
                st.roots.len() > 1 && !st.roots.contains(&r.body().signer) && !st.may_command(&r.body().signer)
            })
        };
        assert!(
            refused.iter().all(|(id, why)| *why == crate::records::set::Refused::UnknownSigner && old_admin(id)),
            "{refused:?}"
        );
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
    assert_ne!(ab, channel_id(&fhash(&a), &fhash(&b), &[0; 16]));
}

#[test]
fn an_admin_key_needs_its_proof() {
    let admin = k("phone admin");
    let exporter = PairExporter::for_tests([7u8; 32]);
    let pop = sign_admin_pop(&admin, &exporter).unwrap();
    assert!(verify_admin_pop(&admin.key, &exporter, &pop));
    assert!(!verify_admin_pop(&admin.key, &PairExporter::for_tests([8u8; 32]), &pop), "another session's proof");
    assert!(!verify_admin_pop(&k("other").key, &exporter, &pop), "another key's proof");

    // In the Info, a key and its proof come together, from a phone or an admin member.
    let mut i = info("phone 2", ROLE_PHONE);
    i.admin = Some(admin.key.public().to_vec());
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
    // Capabilities are bits: those this version does not know are ignored
    // and grant nothing, so none left reads as no capability.
    assert_eq!(Info::decode(&info_of((3, Value::Uint(0)))).unwrap().caps, 0);
    assert_eq!(Info::decode(&info_of((3, Value::Uint(8)))).unwrap().caps, 0);
    assert_eq!(Info::decode(&info_of((3, Value::Uint(8 | CAP_HUB)))).unwrap().caps, CAP_HUB);
    // Admin keys come as a signed envelope.
    assert_eq!(Info::decode(&info_of((7, Value::Bytes(b"not an envelope")))), Err(Rule::field("pair/info/keys")));
    assert_eq!(Info::decode(&info_of((9, Value::Bytes(&[1; 8])))), Err(Rule::field("pair/info/invite")));
    // A field the table does not list is skipped.
    assert!(Info::decode(&info_of((40, Value::Uint(7)))).is_ok());
}

fn kettle() -> Open {
    Open {
        invitation: Invitation::new(Vec::new(), Profile::small_device()),
        name: "kettle".into(),
        created_ms: 1,
        expires_ms: 10_000_000,
        used: false,
        failures: 0,
        allowed_key: None,
        attempt: None,
        next_attempt: 0,
    }
}

/// An open invitation counts an attempt as failed from its start, until
/// it ends in a Welcome, which takes the count back and closes it; one
/// attempt at a time; one that runs out of time frees it and stays
/// counted, and the third failure closes it (A-49).
#[test]
fn an_attempt_counts_until_its_welcome() {
    let mut open = kettle();
    let n = open.begin(Network::Home, 100).unwrap();
    assert_eq!(open.failures, 1, "counted from the start");
    assert_eq!(open.begin(Network::Home, 110), Err(PairError::Busy));
    // Walking away counts.
    open.end(n, false, 120);
    assert_eq!(open.failures, 1);
    assert!(open.attempt.is_none() && !open.used);
    // A Welcome takes its count back and closes the invitation.
    let n2 = open.begin(Network::Home, 200).unwrap();
    assert_ne!(n2, n);
    open.end(n2, true, 210);
    assert_eq!(open.failures, 1);
    assert!(open.used);
    assert_eq!(open.begin(Network::Home, 300), Err(PairError::Closed));

    // An attempt that runs out of time frees the invitation; its count
    // stays, and the third failure closes it.
    let mut open = kettle();
    let t = 4_000_000;
    for i in 0..invitation::MAX_FAILURES {
        let at = t + u64::from(i) * invitation::ATTEMPT_MS;
        open.begin(Network::Home, at).unwrap();
        assert_eq!(open.begin(Network::Home, at + invitation::ATTEMPT_MS - 1), Err(PairError::Busy));
    }
    let after = t + u64::from(invitation::MAX_FAILURES) * invitation::ATTEMPT_MS;
    assert_eq!(open.begin(Network::Home, after), Err(PairError::TooMany));
    assert_eq!(open.failures, invitation::MAX_FAILURES);

    // The messages carry CPace alone: the short code's fields are retired,
    // and a message with one is refused.
    for (t, n, rule) in [(64, 4, "pair/start/retired"), (65, 4, "pair/reply/retired"), (66, 3, "pair/confirm/retired")]
    {
        let table = crate::msg::tables::of(t).unwrap();
        assert!(table.fields.iter().all(|f| f.n != n), "{rule}");
        let mut m: Vec<(u16, format::cbor::Value<'_>)> =
            table.fields.iter().map(|f| (f.n, format::cbor::Value::Bytes(&[1; 32]))).collect();
        m.insert(0, (0, format::cbor::Value::Uint(t)));
        m.push((n, format::cbor::Value::Bytes(&[2; 32])));
        let enc = format::cbor::Value::Map(m).encode();
        assert_eq!(crate::msg::check(&enc).err(), Some(format::Rule::field(rule)));
    }
}

#[test]
fn a_late_message_of_an_earlier_attempt_changes_nothing() {
    let mut open = kettle();
    let first = open.begin(Network::Home, 0).unwrap();
    // The first attempt's time runs out; a second begins.
    let second = open.begin(Network::Home, invitation::ATTEMPT_MS).unwrap();
    // The first attempt's late end names it, and changes nothing but the
    // close: its joiner was welcomed.
    open.end(first, false, invitation::ATTEMPT_MS + 4);
    assert_eq!(open.attempt.as_ref().map(|a| a.number), Some(second), "the second attempt still runs");
    assert_eq!(open.begin(Network::Home, invitation::ATTEMPT_MS + 5), Err(PairError::Busy));
    assert_eq!(open.failures, 2);
    open.end(first, true, invitation::ATTEMPT_MS + 6);
    assert_eq!(open.failures, 2, "a late Welcome takes no count back");
    assert!(open.used, "but one success closes the invitation");
}

#[test]
fn the_joiner_counts_its_sessions() {
    let mut j = invitation::JoinerAttempts::default();
    for _ in 0..invitation::MAX_FAILURES {
        j.start().unwrap();
    }
    assert_eq!(j.start().err(), Some(PairError::TooMany), "three sessions per invitation");
}

/// A home window: a new ID, never zero, and six new digits, from which
/// its secret comes; the joiner derives the same invitation from the ID
/// and the digits, and nothing else gives one.
#[test]
fn a_home_window_has_six_digits() {
    let (window, digits) = Invitation::home();
    assert_eq!(digits.len(), invitation::HOME_DIGITS);
    assert!(digits.bytes().all(|b| b.is_ascii_digit()));
    assert_ne!(window.id, [0; 16]);
    assert_eq!(Some(window.secret), invitation::home_secret(&digits));
    assert_eq!(window.profile, Profile::home());
    assert!(window.profile.home_only && window.paths.iter().all(|p| p.kind == PathKind::Home));
    // A home window is never written as an invitation's text: its role
    // admits any but a leaf's, which no text carries.
    assert_eq!(Invitation::decode(&window.encode()).err(), Some(invitation::RULE_PROFILE));
    assert_eq!(Invitation::typed(window.id, &digits).unwrap(), window);
    // Two windows: two IDs.
    assert_ne!(Invitation::home().0.id, window.id);
    // Not six digits, or an ID of zeros: no window.
    for bad in ["12345", "1234567", "12345a", "12 345", "１２３４５６", ""] {
        assert!(invitation::home_secret(bad).is_none(), "{bad:?}");
        assert!(Invitation::typed(window.id, bad).is_none(), "{bad:?}");
    }
    assert!(Invitation::typed([0; 16], &digits).is_none());
    // Another digit, another secret.
    let other = if digits == "000000" { "000001" } else { "000000" };
    assert_ne!(invitation::home_secret(other), Some(window.secret));
}

/// No invitation has an ID or a secret of zero bytes: a new one draws
/// again, and a reader refuses one (`invite/shape`, the vector "an ID of
/// zeros").
#[test]
fn no_invitation_has_an_id_of_zeros() {
    let mut draws = [[0u8; 16], [0u8; 16], [7u8; 16]].into_iter();
    assert_eq!(invitation::not_zero(|| draws.next().unwrap()), [7u8; 16]);
    let mut draws = [[0u8; 32], [5u8; 32]].into_iter();
    assert_eq!(invitation::not_zero(|| draws.next().unwrap()), [5u8; 32]);
    let home = Path { kind: PathKind::Home, endpoints: vec![], hub_key: None, guest: None, obfuscation: None };
    let mut inv = Invitation::new(vec![home], Profile::small_device());
    assert_ne!(inv.id, [0; 16]);
    assert!(Invitation::decode(&inv.encode()).is_ok());
    let mut zero = inv.clone();
    zero.secret = [0; invitation::SECRET];
    assert_eq!(Invitation::decode(&zero.encode()).err(), Some(invitation::RULE_SHAPE));
    inv.id = [0; 16];
    assert_eq!(Invitation::decode(&inv.encode()).err(), Some(invitation::RULE_SHAPE));
}

/// A home window's secret and CPace's channel identifier against the
/// vectors (`testdata/format/messages3.json`, "codes"), which gen.py
/// writes and the Go check computes on its own.
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
    assert_eq!(codes["home_code_label"].as_str().map(str::as_bytes), invitation::HOME_CODE_LABEL.strip_suffix(b"\0"));
    let home = codes["home_secret"].as_array().unwrap();
    assert!(home.len() >= 4);
    for c in home {
        let got = invitation::home_secret(c["digits"].as_str().unwrap());
        match c.get("secret") {
            Some(s) => assert_eq!(got, Some(arr(s)), "{}", c["name"]),
            None => assert_eq!(got, None, "{}", c["name"]),
        }
    }
    let channel = codes["channel_id"].as_array().unwrap();
    assert!(channel.len() >= 3);
    for c in channel {
        let ci = channel_id(&KeyHash(arr(&c["member"])), &KeyHash(arr(&c["joiner"])), &id(&c["invitation"]));
        assert_eq!(crate::certs::hex(&ci), c["ci"].as_str().unwrap(), "{}", c["name"]);
    }
}

/// The Welcome's digest and tag against the vectors
/// (`testdata/format/messages3.json`, "welcome_parts"), which gen.py writes
/// and the Go check computes on its own.
#[test]
fn the_welcome_digest_and_tag_match_their_vectors() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../testdata/format/messages3.json");
    let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let hex = |s: &serde_json::Value| -> Vec<u8> {
        let s = s.as_str().unwrap();
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    };
    let w = &v["welcome_parts"];
    assert_eq!(w["digest_label"], welcome::LABEL_DIGEST);
    assert_eq!(w["tag_key_label"], welcome::LABEL_TAG_KEY);
    assert_eq!(w["tag_label"], welcome::LABEL_TAG);
    let digests = w["digest"].as_array().unwrap();
    assert!(digests.len() >= 3);
    for c in digests {
        let set: [u8; 32] = hex(&c["set_digest"]).try_into().unwrap();
        let lists: Vec<Vec<u8>> = c["lists"].as_array().unwrap().iter().map(hex).collect();
        let got = welcome::digest_from(&set, lists.iter().map(Vec::as_slice));
        assert_eq!(crate::certs::hex(&got), c["digest"].as_str().unwrap(), "{}", c["name"]);
    }
    let tags = w["tag"].as_array().unwrap();
    assert!(tags.len() >= 6);
    for c in tags {
        let (isk, body) = (hex(&c["isk"]), hex(&c["message"]));
        let got = welcome::open(&body, &isk);
        match c.get("rule") {
            Some(rule) => assert_eq!(got.err().map(|r| r.name()), rule.as_str(), "{}", c["name"]),
            None => assert_eq!(got.map(<[u8]>::to_vec), Ok(hex(&c["welcome"])), "{}", c["name"]),
        }
    }
}

#[test]
fn an_offered_admin_key_is_new() {
    let g = G::new();
    let st = g.state();
    let tv = k("tv");
    let with_admin = |a: &K| {
        let mut i = info("tv", ROLE_MEMBER);
        i.admin = Some(a.key.public().to_vec());
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
    ph.admin = Some(k("phone 2 admin").key.public().to_vec());
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
    built(&set, &st, &admitter, &joiner.hash)
}

#[test]
fn the_joiner_checks_its_welcome() {
    let mut g = G::new();
    let tv = k("tv");
    let w = admit(&mut g, true, &tv, "tv");
    let group = format::DeviceId(g.gid.0);
    let (_, st) =
        w.check(&group, &point(&k("laptop")), &point(&tv), Joining::Ordinary, Way::Invited(&invitation())).unwrap();
    assert!(st.device_by_key(&tv.hash).is_some());

    // Another group.
    assert_eq!(
        w.check(
            &format::DeviceId([9; 16]),
            &point(&k("laptop")),
            &point(&tv),
            Joining::Ordinary,
            Way::Invited(&invitation())
        )
        .err(),
        Some(welcome::Refusal::OtherGroup)
    );
    // Not my record.
    assert_eq!(
        w.check(&group, &point(&k("laptop")), &point(&k("someone")), Joining::Ordinary, Way::Invited(&invitation()))
            .err(),
        Some(welcome::Refusal::NotAdmitted)
    );
    // An admitter other than the one who signed: the root phone did not sign this record.
    assert_eq!(
        w.check(&group, &point(&k("phone")), &point(&tv), Joining::Ordinary, Way::Invited(&invitation())).err(),
        Some(welcome::Refusal::NotAdmitter)
    );
    // A stranger in the middle.
    assert_eq!(
        w.check(&group, &point(&k("stranger")), &point(&tv), Joining::Ordinary, Way::Invited(&invitation())).err(),
        Some(welcome::Refusal::NotAdmitter)
    );

    // A Welcome without the admitter's own record proves nothing.
    let mut cut = w.clone();
    cut.records.retain(|r| !matches!(&r.body().kind, Kind::Device(d) if d.key.hash() == k("laptop").hash));
    assert!(
        cut.check(&group, &point(&k("laptop")), &point(&tv), Joining::Ordinary, Way::Invited(&invitation())).is_err()
    );

    // The root's path comes from the records: a Welcome under another root is another group.
    let mut other = w.clone();
    other.root = k("root 2").key.public().to_vec();
    assert_eq!(
        other.check(&group, &point(&k("laptop")), &point(&tv), Joining::Ordinary, Way::Invited(&invitation())).err(),
        Some(welcome::Refusal::OtherGroup)
    );

    // By the root phone.
    let tab = k("tablet");
    let w = admit(&mut g, false, &tab, "tablet");
    assert!(w.check(&group, &point(&k("phone")), &point(&tab), Joining::Ordinary, Way::Invited(&invitation())).is_ok());
    // A guarded leaf takes the root's own record only, not an admin's.
    assert!(w.check(&group, &point(&k("phone")), &point(&tab), Joining::Guarded, Way::Invited(&invitation())).is_ok());
    let by_admin = admit(&mut g, true, &k("lamp"), "lamp");
    assert_eq!(
        by_admin
            .check(&group, &point(&k("laptop")), &point(&k("lamp")), Joining::Guarded, Way::Invited(&invitation()))
            .err(),
        Some(welcome::Refusal::NotAdmitter)
    );
    assert!(
        by_admin
            .check(&group, &point(&k("laptop")), &point(&k("lamp")), Joining::Ordinary, Way::Invited(&invitation()))
            .is_ok()
    );
    assert_eq!(
        w.check(&group, &point(&k("laptop")), &point(&tab), Joining::Ordinary, Way::Invited(&invitation())).err(),
        Some(welcome::Refusal::NotAdmitter)
    );

    // The encoding reads back.
    assert_eq!(Welcome::decode(&w.encode()).unwrap(), w);
    let (root, envs, time, recovery, recovery2) = Welcome::parts(&w.encode()).unwrap();
    assert_eq!(root, g.root.key.public());
    assert_eq!(recovery, k("recovery").key.public());
    assert_eq!(recovery2, crate::testkit::rk2().public());
    assert_eq!(envs.len(), w.records.len());
    assert_eq!(time, 1_793_000_000_000);
    // Up to 8192 records, past the old profile's 4096 items; not one more.
    let mut wide = w.clone();
    wide.records = vec![w.records[0].clone(); 8192];
    assert_eq!(Welcome::parts(&wide.encode()).map(|p| p.1.len()), Ok(8192));
    wide.records.push(w.records[0].clone());
    assert_eq!(Welcome::parts(&wide.encode()).err().map(|r| r.name()), Some("welcome/records"));
    // A recovery key other than the group's gives another Group ID.
    let mut false_key = w.clone();
    false_key.recovery = k("not the recovery key").key.public().to_vec();
    let back = Welcome::decode(&false_key.encode()).unwrap();
    assert_eq!(
        back.check(&group, &point(&k("phone")), &point(&tab), Joining::Ordinary, Way::Invited(&invitation())).err(),
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
    let w = built(&set, &st, &k("phone c").hash, &slate.hash);
    let group = format::DeviceId(g.gid.0);
    // L: both changes name the empty list, one list for both, so a set
    // this small rides in the Welcome itself.
    assert_eq!(w.parts, 0);
    let back = w.clone();
    let r = back.check(&group, &point(&k("phone c")), &point(&slate), Joining::Ordinary, Way::Invited(&invitation()));
    let (mine, st) = r.unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(st.roots, vec![g.root.hash, n1.hash, n2.hash]);
    assert_eq!(st.chain().len(), 2);
    assert_eq!(mine.len(), set.len(), "every record of the Welcome is kept");
    // A guarded leaf may take it too: the newest root signed it, and the
    // admitter is the newest root's device.
    assert!(
        back.check(&group, &point(&k("phone c")), &point(&slate), Joining::Guarded, Way::Invited(&invitation()))
            .is_ok()
    );
    // Without the list the joiner does not apply the newest change: n1 is
    // the root there, and n2's record of it does not count. Left out by the
    // way, the digest is not the Welcome's; left out by the admitter, whose
    // digest says so, the joiner is not admitted.
    let newest = back
        .records
        .iter()
        .find_map(|r| match &r.body().kind {
            Kind::Recovery { root, list, .. } if root.hash() == n2.hash => Some(*list),
            _ => None,
        })
        .unwrap();
    let mut bare = back.clone();
    bare.lists.retain(|l| crate::records::body::list_hash(l) != newest);
    // Inline, the list rides in field `list`.
    if bare.list.as_ref().is_some_and(|l| crate::records::body::list_hash(l) == newest) {
        bare.list = None;
    }
    let ordinary = |w: &Welcome| {
        w.check(&group, &point(&k("phone c")), &point(&slate), Joining::Ordinary, Way::Invited(&invitation())).err()
    };
    assert_eq!(ordinary(&bare), Some(welcome::Refusal::Digest));
    redigest(&mut bare, g.empty().root(), g.empty().recovery());
    assert_eq!(ordinary(&bare), Some(welcome::Refusal::NotAdmitted));
    // A list its heads do not name is not held: the set is not the one sent.
    let mut wrong = back.clone();
    wrong.lists.push(crate::records::List(vec![RecordId([3; 32])]).encode());
    assert_eq!(ordinary(&wrong), Some(welcome::Refusal::Digest));
    redigest(&mut wrong, g.empty().root(), g.empty().recovery());
    assert_eq!(ordinary(&wrong), Some(welcome::Refusal::Digest));
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
    let w = built(&set, &st, &k("phone b").hash, &tv.hash);
    assert_eq!(w.records.iter().filter(|r| matches!(r.body().kind, Kind::Recovery { .. })).count(), 2);
    let group = format::DeviceId(g.gid.0);
    assert_eq!(
        w.check(&group, &point(&k("phone b")), &point(&tv), Joining::Ordinary, Way::Invited(&invitation())).err(),
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
    redigest(&mut w, g.empty().root(), g.empty().recovery());
    let group = format::DeviceId(g.gid.0);
    assert_eq!(
        w.check(&group, &point(&k("laptop")), &point(&tv), Joining::Ordinary, Way::Invited(&invitation())).err(),
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
    let w = built(&set, &st, &k("phone a").hash, &lock.hash);
    let (_, st) =
        w.check(&group, &point(&k("phone a")), &point(&lock), Joining::Guarded, Way::Invited(&invitation())).unwrap();
    assert_eq!(st.roots, vec![g.root.hash, n1.hash]);
    // The old root's phone is no admitter of it.
    let w = built(&set, &st, &k("phone").hash, &lock.hash);
    assert_eq!(
        w.check(&group, &point(&k("phone")), &point(&lock), Joining::Guarded, Way::Invited(&invitation())).err(),
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

/// At the most changes of root a group may have, the Welcome still carries
/// every head (each near 8 KiB with the recovery key's second signature)
/// with the newest root's list and first checkpoint under its budget, and
/// the joiner takes it; the intro of a device admitted after them fits too.
#[test]
fn the_joiner_takes_the_most_changes_of_root() {
    let mut g = G::new();
    let max = crate::records::body::MAX_RECOVERY;
    let mut last = k("root");
    for i in 1..=max {
        last = k(&format!("root n{i}"));
        g.change(&last);
    }
    let (pa, slate) = (k("phone a"), k("slate"));
    phone_admin(&mut g, &last, &pa, &k("admin a"), true);
    let mut d = Device::new(slate.key.clone(), "slate", ROLE_MEMBER);
    d.rights = RIGHT_READ | RIGHT_SEND;
    g.rec(&last, Kind::device(d));
    let set = g.set();
    let st = set.state();
    assert_eq!(st.roots.len() as u64, max + 1);
    let w = built(&set, &st, &pa.hash, &slate.hash);
    let heads = w.records.iter().filter(|r| matches!(r.body().kind, Kind::Recovery { .. })).count();
    assert_eq!(heads as u64, max);
    let (sent, parts) = Welcome::build(&set, &st, &pa.hash, &slate.hash, 1_793_000_000_000).unwrap();
    let bytes = sent.encode().len() + parts.iter().map(|p| welcome::part_message(p).len()).sum::<usize>();
    assert!(
        bytes <= crate::format::frame::LIMIT_PAIRING,
        "a realistic Welcome and its parts stay under 1 MiB: {bytes}"
    );
    let back = w;
    let group = format::DeviceId(g.gid.0);
    let (mine, st2) = back
        .check(&group, &point(&pa), &point(&slate), Joining::Ordinary, Way::Invited(&invitation()))
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(st2.roots, st.roots);
    assert_eq!(mine.len(), set.len());
    let intro = Intro::of(&set, &st, &slate.hash, None).unwrap();
    assert!(intro::fits(&intro.records));
    assert!(intro.message().len() <= crate::format::frame::LIMIT_MEMBER);
}

/// The recovery heads ride beside the intro's 32 records and 16 KiB, at
/// most MAX_HEADS of them: three changes of root pass 16 KiB in their heads'
/// envelopes alone, and the device admitted after them still proves
/// itself. Sender and reader count alike, by the envelopes' bytes.
#[test]
fn an_intro_counts_the_recovery_heads_apart() {
    let mut g = G::new();
    let (n1, n2, n3, pa) = (k("root n1"), k("root n2"), k("root n3"), k("phone a"));
    g.change(&n1);
    g.change(&n2);
    g.change(&n3);
    phone_admin(&mut g, &n3, &pa, &k("admin a"), true);
    let full = g.set();
    let st = full.state();
    let intro = Intro::of(&full, &st, &pa.hash, None).unwrap();
    let heads: Vec<&Record> = intro.records.iter().filter(|r| matches!(r.body().kind, Kind::Recovery { .. })).collect();
    assert_eq!(heads.len(), 3);
    assert!(heads.iter().map(|r| r.envelope().len()).sum::<usize>() > intro::MAX_BYTES);
    assert!(intro::fits(&intro.records));

    // A peer that holds everything but the phone's record takes it.
    let mut old = g.empty();
    old.insert_all(g.recs.iter().filter(|r| matches!(r.body().kind, Kind::Recovery { .. })).cloned());
    for l in &g.lists {
        old.insert_list(l).unwrap();
    }
    old.insert_all(g.recs[..g.recs.len() - 1].iter().cloned());
    let me = fhash(&k("phone"));
    let new = intro.check(&old, &me, &point(&pa)).unwrap();
    assert_eq!(new.len(), 1);

    // The reader counts as the sender did.
    let back = Intro::read(&intro.message()).unwrap();
    assert_eq!(back, intro);
    assert_eq!(back.check(&old, &me, &point(&pa)).unwrap().len(), 1);

    // Up to MAX_HEADS heads pass; one more does not, on either side.
    let mut many = intro.clone();
    while many.records.iter().filter(|r| matches!(r.body().kind, Kind::Recovery { .. })).count() < intro::MAX_HEADS {
        many.records.insert(0, heads[0].clone());
    }
    assert!(intro::fits(&many.records));
    assert_eq!(Intro::read(&many.message()).map(|i| i.records.len()), Ok(many.records.len()));
    many.records.insert(0, heads[0].clone());
    assert!(!intro::fits(&many.records));
    assert_eq!(many.check(&old, &me, &point(&pa)), Err(intro::Refusal::TooBig));
    assert_eq!(Intro::read(&many.message()), Err(intro::RULE_SIZE));

    // The others still at most 32 records and 16 KiB, by their envelopes.
    let mut wide = intro.clone();
    let own = wide.records.last().unwrap().clone();
    while wide.records.len() - 3 <= intro::MAX_RECORDS {
        wide.records.insert(3, own.clone());
    }
    assert_eq!(wide.check(&old, &me, &point(&pa)), Err(intro::Refusal::TooBig));
    assert_eq!(Intro::read(&wide.message()), Err(intro::RULE_SIZE));
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
    assert!(!b.windows(65).any(|w| w == g.root.key.public()));

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

/// The Welcome a joiner ends with: built, and carried with its parts when
/// it has any.
fn built(set: &RecordSet, st: &State, admitter: &KeyHash, joiner: &KeyHash) -> Welcome {
    let (w, parts) = Welcome::build(set, st, admitter, joiner, 1_793_000_000_000).unwrap();
    if parts.is_empty() { w } else { carried(&w, &parts) }
}

/// A Welcome whose records were changed after it was built, with the
/// digest of the set they make: what an admitter that sends them would
/// have sent.
fn redigest(w: &mut Welcome, root: &Key, recovery: &crate::records::Recovery) {
    let mut set = RecordSet::new(root.clone(), recovery.clone());
    let lists: Vec<&[u8]> = w.list.iter().chain(&w.lists).map(Vec::as_slice).collect();
    set.take_part(&w.records, &lists);
    set.take_part(&w.records, &lists);
    w.digest = Some(welcome::digest_of(&set));
}

/// A Welcome and its parts as they travel and as the joiner takes them:
/// message 67 sealed with the session's ISK and opened, each part as a
/// `records` message into the assembly, the whole Welcome back.
fn carried(w: &Welcome, parts: &[crate::records::sync::Part<'_>]) -> Welcome {
    let isk = [0x15u8; 64];
    let frame = welcome::frame(&[0x7b; 64], &w.encode(), &isk).unwrap();
    let opened = welcome::open(&frame[4..], &isk).unwrap();
    let mut a = welcome::Assembly::new(Welcome::decode(opened).unwrap(), 1_000).unwrap();
    assert_eq!(a.due(), parts.len() as u64);
    for (i, p) in parts.iter().enumerate() {
        a.take(&welcome::part_message(p), 1_000 + i as u64).unwrap();
    }
    a.finish().unwrap()
}

/// A Welcome whose set passes its budget sends it whole in parts: the
/// recovery records and their lists, the new root's first checkpoint, the
/// removals that count, the two devices' records and everything else;
/// nothing is cut, and the joiner ends in the admitter's state. A set that
/// fits rides in the Welcome with no part.
#[test]
fn a_welcome_too_wide_for_its_budget_comes_whole_in_parts() {
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
    let (all, none) = Welcome::build(&set, &st, &admitter, &slate.hash, 1).unwrap();
    assert!(none.is_empty() && all.parts == 0 && all.digest == Some(welcome::digest_of(&set)));
    let full: usize =
        all.records.iter().map(|r| r.envelope().len()).sum::<usize>() + all.list.as_ref().map_or(0, Vec::len);
    let group = format::DeviceId(g.gid.0);
    for budget in [full - 30 * set.get(&filler[0]).unwrap().envelope().len(), 600] {
        let (w, parts) = Welcome::build_within(&set, &st, &admitter, &slate.hash, 1, budget).unwrap();
        assert!(!parts.is_empty() && w.parts == parts.len() as u64);
        assert!(w.records.is_empty() && w.list.is_none() && w.digest == all.digest);
        let whole = carried(&w, &parts);
        let has = |id: &RecordId| whole.records.iter().any(|r| r.id() == *id);
        let heads: Vec<RecordId> =
            g.recs.iter().filter(|r| matches!(r.body().kind, Kind::Recovery { .. })).map(Record::id).collect();
        assert!(heads.iter().all(has) && !whole.lists.is_empty());
        assert!(has(&removal.id()) && has(&own.id()) && filler.iter().all(has));
        let (mine, back) = whole
            .check(&group, &point(&k("phone b")), &point(&slate), Joining::Ordinary, Way::Invited(&invitation()))
            .unwrap();
        assert_eq!(back, st);
        assert_eq!(mine.digest(), set.digest());
    }
}

/// A map's fields, as a test edits them.
type Fields<'a> = Vec<(u16, crate::format::cbor::Value<'a>)>;

/// Message 67's tag binds every byte of the Welcome to the session:
/// a flipped byte, field 13 removed, field 12 changed, no tag, or a tag
/// from another session's ISK, and the Welcome is not opened.
#[test]
fn the_welcome_tag_binds_every_byte() {
    use crate::format::cbor::{self, Value};
    let mut g = G::new();
    let (n1, n2, slate) = (k("root n1"), k("root n2"), k("slate"));
    g.change(&n1);
    phone_admin(&mut g, &n1, &k("phone b"), &k("admin b"), true);
    g.change(&n2);
    phone_admin(&mut g, &n2, &k("phone c"), &k("admin c"), true);
    let mut d = Device::new(slate.key.clone(), "slate", ROLE_MEMBER);
    d.rights = RIGHT_READ | RIGHT_SEND;
    g.rec(&n2, Kind::device(d));
    let set = g.set();
    let st = set.state();
    // A small budget, so that the set comes in parts and field 13 is there.
    let (w, parts) = Welcome::build_within(&set, &st, &k("phone c").hash, &slate.hash, 1, 1024).unwrap();
    assert!(w.parts >= 1);
    let (isk, other) = ([0x15u8; 64], [0x16u8; 64]);
    let bytes = w.encode();
    let good = welcome::frame(&[0x7b; 64], &bytes, &isk).unwrap();
    assert_eq!(welcome::open(&good[4..], &isk), Ok(&bytes[..]));
    assert_eq!(welcome::open(&good[4..], &other), Err(welcome::RULE_TAG));
    // The same tag over other bytes.
    let tw = welcome::tag(&isk, &bytes).unwrap();
    let with = |welcome: &[u8], tw: Option<&[u8]>| {
        let mut m =
            vec![(0, Value::Uint(T_WELCOME)), (2, Value::Bytes(&[0x7b; 64])), (3, cbor::decode(welcome).unwrap())];
        if let Some(t) = tw {
            m.push((4, Value::Bytes(t)));
        }
        crate::format::frame::write(&Value::Map(m))
    };
    let edited = |f: &dyn Fn(&mut Fields<'_>)| {
        let v = cbor::decode(&bytes).unwrap();
        let mut m = v.as_map().unwrap().to_vec();
        f(&mut m);
        Value::Map(m).encode()
    };
    let no_parts = edited(&|m| m.retain(|(k, _)| *k != 13));
    let other_digest = edited(&|m| {
        for (k, v) in m.iter_mut() {
            if *k == 12 {
                *v = Value::Bytes(&[9; 32]);
            }
        }
    });
    let mut flipped = bytes.clone();
    let last = flipped.len() - 1;
    flipped[last] ^= 1;
    for (name, f) in [
        ("field 13 removed", with(&no_parts, Some(&tw))),
        ("field 12 changed", with(&other_digest, Some(&tw))),
        ("no tag", with(&bytes, None)),
    ] {
        assert_eq!(welcome::open(&f[4..], &isk).err(), Some(welcome::RULE_TAG), "{name}");
    }
    if cbor::decode(&flipped).is_ok() {
        assert_eq!(welcome::open(&with(&flipped, Some(&tw))[4..], &isk).err(), Some(welcome::RULE_TAG));
    }
    // The assembly: a part after the last, another message while parts are
    // due, and parts that come late.
    let decoded = Welcome::decode(&bytes).unwrap();
    let first = welcome::part_message(&parts[0]);
    let mut a = welcome::Assembly::new(decoded.clone(), 0).unwrap();
    for (i, p) in parts.iter().enumerate() {
        a.take(&welcome::part_message(p), i as u64).unwrap();
    }
    assert_eq!(a.take(&first, 10), Err(welcome::RULE_PARTS));
    let mut a = welcome::Assembly::new(decoded.clone(), 0).unwrap();
    let ping = crate::format::frame::write(&Value::Map(vec![(0, Value::Uint(3))]));
    assert_eq!(a.take(&ping, 1), Err(welcome::RULE_PARTS));
    let a = welcome::Assembly::new(decoded.clone(), 0).unwrap();
    assert!(!a.late(welcome::PART_MS) && a.late(welcome::PART_MS + 1));
    let mut a = welcome::Assembly::new(decoded.clone(), 0).unwrap();
    assert_eq!(a.take(&first, welcome::PART_MS + 1), Err(welcome::RULE_LATE));
    // Every part in time, all of them not: PARTS_MS after message 67 the
    // parts still due are late, however close each came to the one before.
    let mut many = decoded.clone();
    many.parts = welcome::MAX_PARTS;
    let mut a = welcome::Assembly::new(many, 0).unwrap();
    let step = welcome::PART_MS;
    let mut t = 0;
    while t + step <= welcome::PARTS_MS {
        t += step;
        a.take(&first, t).unwrap();
    }
    assert!(!a.late(welcome::PARTS_MS));
    assert!(a.late(welcome::PARTS_MS + 1));
    assert_eq!(a.take(&first, welcome::PARTS_MS + 1), Err(welcome::RULE_LATE));
    assert_eq!(welcome::Assembly::new(decoded, 0).unwrap().finish().err(), Some(welcome::RULE_PARTS));
}

/// A part whose recovery record carries another second signature: its ID
/// and the digest stay the same, but its first signature does not cover
/// it, so the set does not hold it and the joiner does not join.
#[test]
fn a_part_with_a_swapped_second_signature_is_refused() {
    let mut g = G::new();
    let (n1, n2, slate) = (k("root n1"), k("root n2"), k("slate"));
    g.change(&n1);
    phone_admin(&mut g, &n1, &k("phone b"), &k("admin b"), true);
    g.change(&n2);
    phone_admin(&mut g, &n2, &k("phone c"), &k("admin c"), true);
    let mut d = Device::new(slate.key.clone(), "slate", ROLE_MEMBER);
    d.rights = RIGHT_READ | RIGHT_SEND;
    g.rec(&n2, Kind::device(d));
    let set = g.set();
    let st = set.state();
    let group = format::DeviceId(g.gid.0);
    let mut w = built(&set, &st, &k("phone c").hash, &slate.hash);
    let heads: Vec<usize> = (0..w.records.len()).filter(|i| w.records[*i].sig2().is_some()).collect();
    assert!(heads.len() >= 2);
    let (a, b) = (&w.records[heads[0]], &w.records[heads[1]]);
    let swapped = Record::decode(&crate::format::envelope::write(a.body_bytes(), a.sig(), b.sig2())).unwrap();
    assert_eq!(swapped.id(), a.id());
    w.records[heads[0]] = swapped;
    assert_eq!(
        w.check(&group, &point(&k("phone c")), &point(&slate), Joining::Ordinary, Way::Invited(&invitation())).err(),
        Some(welcome::Refusal::Digest)
    );
}

/// The rules between a Welcome's fields.
#[test]
fn a_welcome_keeps_its_fields_together() {
    use crate::format::cbor::{self, Value};
    let mut g = G::new();
    let slate = k("slate");
    let mut d = Device::new(slate.key.clone(), "slate", ROLE_MEMBER);
    d.rights = RIGHT_READ | RIGHT_SEND;
    g.rec_root(Kind::device(d));
    let set = g.set();
    let st = set.state();
    let (w, _) = Welcome::build(&set, &st, &k("phone").hash, &slate.hash, 1).unwrap();
    let bytes = w.encode();
    let v = cbor::decode(&bytes).unwrap();
    let edit = |f: &dyn Fn(&mut Fields<'_>)| {
        let mut m = v.as_map().unwrap().to_vec();
        f(&mut m);
        m.sort_by_key(|(k, _)| *k);
        Welcome::decode(&Value::Map(m).encode()).err()
    };
    assert_eq!(edit(&|_| {}), None);
    assert_eq!(edit(&|m| m.push((13, Value::Uint(2)))), Some(welcome::RULE_PARTS), "parts beside the records");
    assert_eq!(edit(&|m| m.retain(|(k, _)| *k != 2)), Some(welcome::RULE_SHAPE), "neither records nor parts");
    assert_eq!(edit(&|m| m.retain(|(k, _)| *k != 12)), Some(welcome::RULE_DIGEST), "no digest");
    let parts = |n: u64| {
        edit(&|m| {
            m.retain(|(k, _)| *k != 2 && *k != 10);
            m.push((13, Value::Uint(n)));
        })
    };
    assert_eq!(parts(64), None);
    assert_eq!(parts(65).map(|r| r.name()), Some("welcome/parts"));
}

/// A Welcome in parts leaves nothing to sync: one sync of everything the
/// admitter holds adds nothing and changes nothing.
#[test]
fn a_welcome_in_parts_leaves_nothing_to_sync() {
    let mut g = G::new();
    let (n1, slate) = (k("root n1"), k("slate"));
    g.change(&n1);
    phone_admin(&mut g, &n1, &k("phone b"), &k("admin b"), true);
    let mut d = Device::new(slate.key.clone(), "slate", ROLE_MEMBER);
    d.rights = RIGHT_READ | RIGHT_SEND;
    g.rec(&n1, Kind::device(d));
    for i in 0..40u64 {
        g.rec(&n1, Kind::Copies { incoming_ms: 5_000 + i, seen: vec![] });
    }
    let set = g.set();
    let st = set.state();
    let admitter = k("phone b").hash;
    let (w, parts) = Welcome::build_within(&set, &st, &admitter, &slate.hash, 1, 20 * 200).unwrap();
    assert!(!parts.is_empty());
    let group = format::DeviceId(g.gid.0);
    let (mut mine, _) = carried(&w, &parts)
        .check(&group, &point(&k("phone b")), &point(&slate), Joining::Ordinary, Way::Invited(&invitation()))
        .unwrap();
    assert_eq!(mine.len(), set.len());
    // One sync: the admitter sends what it holds.
    let (stored, refused) = mine.insert_all(set.in_dependency_order().into_iter().cloned());
    assert!(refused.is_empty(), "{refused:?}");
    assert_eq!(stored, 0);
    assert_eq!(mine.state(), st);
}

/// Pairing frames: before the confirm every message takes the pairing
/// limit and a Welcome is refused; after it the Welcome alone takes the
/// member limit.
#[test]
fn only_a_confirmed_welcome_takes_the_member_frame() {
    use crate::format::frame::{self, LIMIT_MEMBER, LIMIT_PAIRING};
    let big = |t: u64, size: usize| {
        let filler = vec![7u8; size];
        frame::write(&crate::format::Value::Map(vec![
            (0, crate::format::Value::Uint(t)),
            (2, crate::format::Value::Bytes(&filler)),
        ]))
    };
    let large_welcome = big(T_WELCOME, 2 * LIMIT_PAIRING);
    let small_welcome = big(T_WELCOME, 100);
    let large_other = big(T_CONFIRM, 2 * LIMIT_PAIRING);
    let too_large = big(T_WELCOME, LIMIT_MEMBER);
    assert!(large_welcome.len() - 4 > LIMIT_PAIRING && large_welcome.len() - 4 <= LIMIT_MEMBER);
    assert_eq!(read_pairing(&large_welcome, true).map(|m| m.t), Ok(T_WELCOME));
    assert_eq!(read_pairing(&large_welcome, false).map(|m| m.t), Err(crate::format::Rule::FRAME_GRID));
    assert_eq!(read_pairing(&small_welcome, false).map(|m| m.t), Err(RULE_EARLY_WELCOME));
    assert_eq!(read_pairing(&small_welcome, true).map(|m| m.t), Ok(T_WELCOME));
    assert_eq!(read_pairing(&large_other, true).map(|m| m.t), Err(crate::format::Rule::FRAME_GRID));
    assert_eq!(read_pairing(&large_other, false).map(|m| m.t), Err(crate::format::Rule::FRAME_GRID));
    assert_eq!(read_pairing(&too_large, true).map(|m| m.t), Err(crate::format::Rule::FRAME_GRID));
    let head = |f: &[u8]| <[u8; 4]>::try_from(&f[..4]).unwrap();
    assert_eq!(pairing_length(head(&large_welcome), true), Ok(large_welcome.len() - 4));
    assert!(pairing_length(head(&large_welcome), false).is_err());
    assert!(pairing_length(head(&too_large), true).is_err());
}

/// The joiner's record comes with its signer's chain below it: a budget
/// that cannot hold the set sends it in parts, which the joiner takes,
/// never a Welcome it would refuse.
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
    let (all, _) = Welcome::build(&set, &st, &admitter, &slate.hash, 1).unwrap();
    let full: usize =
        all.records.iter().map(|r| r.envelope().len()).sum::<usize>() + all.list.as_ref().map_or(0, Vec::len);
    let group = format::DeviceId(g.gid.0);
    let check = |w: &Welcome| {
        w.check(&group, &point(&k("phone")), &point(&slate), Joining::Ordinary, Way::Invited(&invitation())).map(|_| ())
    };
    assert!(check(&all).is_ok());
    let (w, parts) = Welcome::build_within(&set, &st, &admitter, &slate.hash, 1, full - 1).unwrap();
    assert!(!parts.is_empty());
    assert!(check(&carried(&w, &parts)).is_ok());
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
    redigest(&mut w, g.empty().root(), g.empty().recovery());
    let group = format::DeviceId(g.gid.0);
    assert_eq!(
        w.check(&group, &point(&k("laptop")), &point(&tv), Joining::Ordinary, Way::Invited(&invitation())).err(),
        Some(welcome::Refusal::Stopped)
    );
}

/// An invitation at its bounds (the registry, `bounds.rs`): MAX_PATHS paths
/// of MAX_ENDPOINTS endpoints read; one path or one endpoint more does not.
#[test]
fn an_invitation_at_its_bounds() {
    let path = |n: usize| Path {
        kind: PathKind::Guest,
        endpoints: (0..n).map(|i| alloc::format!("203.0.113.{}:51820", i + 1)).collect(),
        hub_key: Some([5; 32]),
        guest: Some(([6; 32], [7; 32])),
        obfuscation: None,
    };
    let away = Profile { role: ROLE_MEMBER, rights: RIGHT_READ | RIGHT_SEND, home_only: false, guarded: false };
    let read = |paths: Vec<Path>| Invitation::decode(&Invitation::new(paths, away).encode());
    let full: Vec<Path> = (0..invitation::MAX_PATHS).map(|_| path(invitation::MAX_ENDPOINTS)).collect();
    assert!(read(full.clone()).is_ok(), "{:?}", read(full.clone()).err());
    let mut more = full.clone();
    more.push(path(1));
    assert_eq!(read(more).err(), Some(invitation::RULE_PATH));
    let mut wider = full;
    wider[0] = path(invitation::MAX_ENDPOINTS + 1);
    assert_eq!(read(wider).err(), Some(invitation::RULE_PATH));
}

/// A join in parts after two changes of root and a later checkpoint that
/// prunes a record of the last root (a removed device's admission): the
/// joiner takes the Welcome and its
/// parts and ends with the admitter's set and state, and one sync of
/// everything the admitter holds adds nothing.
#[test]
fn a_join_in_parts_after_two_changes_and_a_pruning_checkpoint_ends_equal() {
    let mut g = G::new();
    let (n1, n2, tv, slate) = (k("root n1"), k("root n2"), k("tv"), k("slate"));
    g.change(&n1);
    phone_admin(&mut g, &n1, &k("phone b"), &k("admin b"), true);
    g.change(&n2);
    phone_admin(&mut g, &n2, &k("phone c"), &k("admin c"), true);
    let mut d = Device::new(tv.key.clone(), "tv", ROLE_MEMBER);
    d.rights = RIGHT_READ;
    let tv_admission = g.rec(&n2, Kind::device(d));
    for i in 0..30u64 {
        g.rec(&n2, Kind::Copies { incoming_ms: 5_000 + i, seen: vec![] });
    }
    let seen = g.seen();
    g.rec(&n2, Kind::Revoke(Removal { keys: vec![tv.hash], seen }));
    // The removal is not the root's head when it checkpoints.
    g.rec(&n2, Kind::Copies { incoming_ms: 9_000, seen: vec![] });
    // Every live admin acknowledges the removal, so a checkpoint may let
    // it go.
    for a in [k("laptop admin"), k("admin b"), k("admin c")] {
        let seen: Vec<_> = g.seen().into_iter().filter(|s| s.key != a.hash).collect();
        g.rec(&a, Kind::Ack { seen, spare: None });
    }
    // The current root's later checkpoint, as a member writes it.
    let before = g.set();
    assert!(before.contains(&tv_admission.id()));
    let cp = before.write_checkpoint(&before.state(), &n2, 0).unwrap();
    let crate::records::Kind::Checkpoint { heads: _, keep } = &cp.body().kind else { panic!("not a checkpoint") };
    assert!(!keep.contains(&tv_admission.id()), "the checkpoint keeps the removed device's admission");
    g.heads.insert(n2.hash, (cp.body().seq, cp.id()));
    g.recs.push(cp.clone());
    let mut d = Device::new(slate.key.clone(), "slate", ROLE_MEMBER);
    d.rights = RIGHT_READ | RIGHT_SEND;
    g.rec(&n2, Kind::device(d));

    let set = g.set();
    let st = set.state();
    assert_eq!(st.roots, vec![g.root.hash, n1.hash, n2.hash]);
    assert_eq!(st.checkpoint, Some(cp.id()));
    assert!(!set.contains(&tv_admission.id()), "the later checkpoint pruned the removed device's admission");
    let admitter = k("phone c").hash;
    let (w, parts) = Welcome::build_within(&set, &st, &admitter, &slate.hash, 1, 20 * 200).unwrap();
    // The set rides in a part, not in the Welcome.
    assert!(!parts.is_empty() && w.records.len() < set.len());
    let group = format::DeviceId(g.gid.0);
    let (mut mine, theirs) = carried(&w, &parts)
        .check(&group, &point(&k("phone c")), &point(&slate), Joining::Ordinary, Way::Invited(&invitation()))
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(theirs, st);
    assert_eq!(mine.len(), set.len());
    assert_eq!(mine.digest(), set.digest());
    assert_eq!(mine.state(), st);
    let (stored, refused) = mine.insert_all(g.recs.iter().cloned());
    assert_eq!(stored, 0, "refused: {refused:?}");
    assert_eq!(mine.digest(), set.digest());
}

/// Intros at their bounds against the vectors (`testdata/format/messages3.json`,
/// "intros"), whose verdicts gen.py computes on its own: the records and the
/// recovery heads counted apart, the records' bytes, and too many envelopes
/// refused before any is read.
#[test]
fn intros_match_their_vectors() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../testdata/format/messages3.json");
    let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let hex = |s: &str| -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    };
    let cases = v["intros"].as_array().unwrap();
    assert!(cases.len() >= 6);
    for c in cases {
        let mut envs = Vec::new();
        for run in c["runs"].as_array().unwrap() {
            let env = hex(run[0].as_str().unwrap());
            for _ in 0..run[1].as_u64().unwrap() {
                envs.push(env.clone());
            }
        }
        // {0: 8, 2: [envelopes]}, each envelope already one CBOR item.
        let mut msg = vec![0xa2, 0x00, 0x08, 0x02];
        let n = envs.len();
        if n < 24 {
            msg.push(0x80 | n as u8);
        } else {
            msg.extend([0x98, u8::try_from(n).unwrap()]);
        }
        msg.extend(envs.concat());
        let got = Intro::read(&msg).map(|i| i.records.len());
        match c.get("rule") {
            Some(rule) => assert_eq!(got.err().map(|r| r.name()), rule.as_str(), "{}", c["name"]),
            None => assert_eq!(got, Ok(n), "{}", c["name"]),
        }
    }
}

/// A pairing session's CPace between the member "laptop" and the joiner
/// "tv" over `exporter`: the member answers by `member_inv`, the joiner
/// uses `joiner_secret` and `joiner_id`. Returns the member's exchange,
/// the joiner's `Ta` and the joiner's ISK.
fn session(
    member_inv: &Invitation,
    joiner_secret: &[u8],
    joiner_id: &[u8; 16],
    exporter: &PairExporter,
) -> Result<(super::approve::MemberExchange, Vec<u8>, Vec<u8>), PairError> {
    use crate::third_party::cpace;
    let (member, joiner) = (k("laptop"), k("tv"));
    let ci = channel_id(&fhash(&member), &fhash(&joiner), joiner_id);
    let (mut js, ya) = cpace::start(&cpace::Config {
        role: cpace::Role::Initiator,
        password: joiner_secret,
        channel_id: &ci,
        session_id: exporter.bytes(),
        ad: b"ada",
    })
    .unwrap();
    let (ex, yb) = super::approve::MemberExchange::respond(
        member_inv,
        &fhash(&member),
        &point(&joiner),
        exporter,
        b"adb",
        &ya,
        b"ada",
    )?;
    let isk = js.finish(&yb, b"adb").unwrap().to_vec();
    Ok((ex, js.tag().unwrap(), isk))
}

/// The member makes message 67 only from an approval of that session and
/// that joiner: the joiner's Ta under the invitation's secret (a QR code's
/// or a home window's). An approval of another session, or a Ta under
/// another secret, makes no message; one approval makes one.
#[test]
fn the_member_sends_a_welcome_only_when_approved() {
    let mut g = G::new();
    let tv = k("tv");
    let welcome = admit(&mut g, true, &tv, "tv").encode();
    let e = PairExporter::for_tests([9u8; 32]);
    let opens = |frame: &[u8], isk: &[u8]| welcome::open(&frame[4..], isk).map(<[u8]>::to_vec);

    for inv in [invitation(), Invitation::home().0] {
        // The verified Ta approves.
        let (mut ex, ta, isk) = session(&inv, &inv.secret, &inv.id, &e).unwrap();
        let approved = ex.confirm(&ta).unwrap();
        let frame = welcome::message(ex, approved, &welcome).unwrap();
        assert_eq!(opens(&frame, &isk), Ok(welcome.clone()));

        // A Ta under another secret is a wrong code, and a Ta is taken once.
        let mut other = invitation();
        other.id = inv.id;
        let (mut ex, ta, _) = session(&inv, &other.secret, &inv.id, &e).unwrap();
        assert_eq!(ex.confirm(&ta).err(), Some(PairError::WrongCode));
        let (mut ex, ta, _) = session(&inv, &inv.secret, &inv.id, &e).unwrap();
        assert!(ex.confirm(&ta).is_ok());
        assert_eq!(ex.confirm(&ta).err(), Some(PairError::WrongCode));
        // Another invitation ID at the joiner: another channel, a wrong code.
        let mut id = inv.id;
        id[0] ^= 1;
        let (mut ex, ta, _) = session(&inv, &inv.secret, &id, &e).unwrap();
        assert_eq!(ex.confirm(&ta).err(), Some(PairError::WrongCode));

        // An approval of one session serves no other.
        let (mut a, ta_a, _) = session(&inv, &inv.secret, &inv.id, &e).unwrap();
        let from_a = a.confirm(&ta_a).unwrap();
        let (mut b, ta_b, _) = session(&inv, &inv.secret, &inv.id, &PairExporter::for_tests([8; 32])).unwrap();
        b.confirm(&ta_b).unwrap();
        assert_eq!(welcome::message(b, from_a, &welcome).err(), Some(PairError::Refused));
        // Nor one before this session's Ta verified.
        let (mut a, ta_a, _) = session(&inv, &inv.secret, &inv.id, &e).unwrap();
        let early = a.confirm(&ta_a).unwrap();
        let (c, _, _) = session(&inv, &inv.secret, &inv.id, &e).unwrap();
        assert_eq!(welcome::message(c, early, &welcome).err(), Some(PairError::Refused));
    }

    // An invitation with a zero secret, or a zero ID, is no invitation.
    let mut zero = invitation();
    zero.secret = [0; invitation::SECRET];
    assert_eq!(session(&zero, &zero.secret.clone(), &zero.id, &e).err(), Some(PairError::Refused));
    let mut zero = invitation();
    zero.id = [0; 16];
    assert_eq!(session(&zero, &zero.secret.clone(), &[0; 16], &e).err(), Some(PairError::Refused));
}

/// A home window's QR code text: written and read back the same; the
/// digits are never shown by its Debug; anything but one key hash, one
/// ID that is not zero and six digits, with one to four addresses, is no
/// window's.
#[test]
fn a_window_link_reads_back() {
    let (window, digits) = Invitation::home();
    let link = invitation::WindowLink {
        addrs: vec!["192.168.1.20:7000".into(), "[fe80::1%en0]:7000".into()],
        fp: fhash(&k("laptop")),
        id: window.id,
        digits: digits.clone(),
    };
    let text = link.text();
    assert!(text.starts_with("cbb://pair?addr=192.168.1.20:7000&addr=[fe80::1%25en0]:7000&fp="));
    assert!(text.ends_with(&alloc::format!("&i={}&c={digits}", crate::certs::hex(&window.id))));
    let back = invitation::WindowLink::parse(&text).unwrap();
    assert_eq!(back, link);
    assert_eq!(back.invitation().unwrap(), window);
    assert!(!alloc::format!("{link:?}").contains(&digits));
    let fp = crate::certs::hex(&link.fp.0);
    let id = crate::certs::hex(&window.id);
    for bad in [
        alloc::format!("cbb://pair?fp={fp}&i={id}&c={digits}"),
        alloc::format!("cbb://pair?addr=a:1&i={id}&c={digits}"),
        alloc::format!("cbb://pair?addr=a:1&fp={fp}&c={digits}"),
        alloc::format!("cbb://pair?addr=a:1&fp={fp}&i={id}"),
        alloc::format!("cbb://pair?addr=a:1&fp={fp}&i={id}&c=12345"),
        alloc::format!("cbb://pair?addr=a:1&fp={fp}&i={}&c={digits}", "00".repeat(16)),
        alloc::format!("cbb://pair?addr=a:1&fp={fp}&i={}&c={digits}", id.to_uppercase()),
        alloc::format!("cbb://pair?addr=a:1&fp={fp}&i={id}&c={digits}&c={digits}"),
        alloc::format!("cbb://pair?addr=a:1&addr=b:1&addr=c:1&addr=d:1&addr=e:1&fp={fp}&i={id}&c={digits}"),
        alloc::format!("cbb://pair?addr=%zz&fp={fp}&i={id}&c={digits}"),
        alloc::format!("cbb://join?addr=a:1&fp={fp}&i={id}&c={digits}"),
        alloc::format!("cbb://pair?addr=a:1&fp={fp}&i={id}&c={digits}&x={}", "y".repeat(512)),
    ] {
        assert!(invitation::WindowLink::parse(&bad).is_none(), "{bad}");
    }
    // A key this version does not know is skipped.
    assert!(invitation::WindowLink::parse(&alloc::format!("{text}&v=2")).is_some());
}
