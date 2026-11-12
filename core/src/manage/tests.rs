// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! An admin phone's changes and commands, signed with software keys the
//! core treats as keys it does not hold.

use std::sync::Arc;

use p256::ecdsa::signature::hazmat::PrehashSigner as _;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};

use super::*;
use crate::certs::DeviceId;
use crate::issue;

struct SoftKey(SigningKey);

impl ExternalKey for SoftKey {
    fn public(&self) -> Vec<u8> {
        VerifyingKey::from(&self.0).to_sec1_point(false).as_bytes().to_vec()
    }

    fn sign_digest(&self, digest: &[u8; 32]) -> Result<Vec<u8>> {
        let s: Signature = self.0.sign_prehash(digest).map_err(|_| Error::msg("cannot sign"))?;
        Ok(s.to_der().as_bytes().to_vec())
    }
}

fn soft() -> Arc<dyn ExternalKey> {
    Arc::new(SoftKey(SigningKey::from_bytes(&certs::random_bytes::<32>().into()).unwrap()))
}

fn now_ms() -> i64 {
    i64::try_from(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis()).unwrap()
}

/// A group: the root's phone, an admin phone and a computer.
struct Group {
    rs: Records,
    root: Cert,
    root_key: Arc<dyn ExternalKey>,
    root_phone: String,
    admin_ca: Cert,
    admin_key: Arc<dyn ExternalKey>,
    admin_phone: String,
    laptop: String,
    laptop_seal: [u8; 32],
}

/// Signs a device record with the root's key.
fn add_device(g: &mut Records, root: &Cert, key: &dyn ExternalKey, b: Body) {
    let body = g.next_body(Body { signer: Hash(root.key_hash()), ..b }).unwrap();
    let sig = identity::sign_external(key, &body).unwrap();
    assert!(g.add(&Record::new(body, sig, None)).unwrap());
}

fn group() -> Group {
    let now = now_ms() / 1000;
    let root_key = soft();
    let root =
        Cert::parse(&issue::root_ca(&root_key.public(), now, &mut |b| identity::sign_external(&*root_key, b)).unwrap())
            .unwrap();
    let ms = now_ms();
    let mut rs = Records::new(&root);
    rs.set_clock(move || ms);
    let base = || Body {
        v: 2,
        alg: authority::ALG_ES256.into(),
        kind: authority::TYPE_DEVICE.into(),
        time_ms: ms,
        ..Default::default()
    };
    let root_phone = DeviceId::random().to_string();
    add_device(
        &mut rs,
        &root,
        &*root_key,
        Body {
            device: root_phone.clone(),
            name: "iPhone".into(),
            role: "phone".into(),
            key: Some(Hash(certs::random_bytes())),
            store: "hardware".into(),
            holds_root: true,
            ..base()
        },
    );
    let admin_phone = DeviceId::random();
    let admin_key = soft();
    let admin_ca = Cert::parse(
        &issue::admin_ca(&admin_phone, &admin_key.public(), &root, now, &mut |b| {
            identity::sign_external(&*root_key, b)
        })
        .unwrap(),
    )
    .unwrap();
    add_device(
        &mut rs,
        &root,
        &*root_key,
        Body {
            device: admin_phone.to_string(),
            name: "R570E".into(),
            role: "phone".into(),
            os: "aurora".into(),
            key: Some(Hash(certs::random_bytes())),
            admin: Some(Hash(admin_ca.key_hash())),
            powers: authority::POWERS.iter().map(|p| (*p).into()).collect(),
            commands: authority::COMMANDS.iter().map(|c| (*c).into()).collect(),
            store: "hardware".into(),
            ..base()
        },
    );
    let laptop = DeviceId::random().to_string();
    let laptop_seal = crate::seal::generate_secret().unwrap();
    add_device(
        &mut rs,
        &root,
        &*root_key,
        Body {
            device: laptop.clone(),
            name: "laptop".into(),
            role: "member".into(),
            caps: authority::CAPS.iter().map(|c| (*c).into()).collect(),
            os: "linux".into(),
            key: Some(Hash(certs::random_bytes())),
            seal: crate::seal::public_key(&laptop_seal).unwrap(),
            ..base()
        },
    );
    Group {
        rs,
        root,
        root_key,
        root_phone,
        admin_ca,
        admin_key,
        admin_phone: admin_phone.to_string(),
        laptop,
        laptop_seal,
    }
}

/// Signs a change and adds it to the records.
fn apply(rs: &mut Records, s: &Signer, device: &str, c: &Change, now_ms: i64) -> Result<Record> {
    let r = change(rs, s, device, c, now_ms)?;
    assert!(rs.add(&r).unwrap());
    Ok(r)
}

fn name_of(rs: &Records, id: &str) -> Option<String> {
    rs.devices().into_iter().find(|d| d.id == id).map(|d| d.name)
}

#[test]
fn the_root_renames_and_removes() {
    let mut g = group();
    let s = Signer { ca: &g.root, key: &*g.root_key, me: &g.root_phone };
    let r = apply(&mut g.rs, &s, &g.laptop, &Change::Rename("  desk  "), now_ms()).unwrap();
    assert!(r.chain.is_empty());
    assert_eq!(name_of(&g.rs, &g.laptop).as_deref(), Some("desk"));
    // Its own phone keeps the root under a new name.
    apply(&mut g.rs, &s, &g.root_phone, &Change::Rename("Mine"), now_ms()).unwrap();
    assert_eq!(g.rs.root_member().map(|(d, _)| d), Some(g.root_phone.clone()));
    assert_eq!(name_of(&g.rs, &g.root_phone).as_deref(), Some("Mine"));

    apply(&mut g.rs, &s, &g.laptop, &Change::Remove, now_ms()).unwrap();
    assert!(name_of(&g.rs, &g.laptop).is_none());
    // The admin phone, with its admin key.
    let a = g.rs.devices().into_iter().find(|d| d.id == g.admin_phone).unwrap().admin_key.unwrap();
    apply(&mut g.rs, &s, &g.admin_phone, &Change::Remove, now_ms()).unwrap();
    assert!(g.rs.revoked(&a));

    assert!(apply(&mut g.rs, &s, &g.root_phone, &Change::Remove, now_ms()).is_err());
    assert!(apply(&mut g.rs, &s, "nobody", &Change::Rename("x"), now_ms()).is_err());
}

#[test]
fn an_admin_phone_signs_with_its_admin_ca() {
    let mut g = group();
    let s = Signer { ca: &g.admin_ca, key: &*g.admin_key, me: &g.admin_phone };
    let e = apply(&mut g.rs, &s, &g.laptop, &Change::Rename("desk"), now_ms()).unwrap_err();
    assert!(e.message().contains("only the root renames it"));
    // A device it admitted itself it renames.
    let tv = DeviceId::random().to_string();
    let body =
        g.rs.next_body(Body {
            v: 2,
            alg: authority::ALG_ES256.into(),
            kind: authority::TYPE_DEVICE.into(),
            signer: Hash(g.admin_ca.key_hash()),
            time_ms: now_ms(),
            device: tv.clone(),
            name: "tv".into(),
            role: "member".into(),
            key: Some(Hash(certs::random_bytes())),
            ..Default::default()
        })
        .unwrap();
    let sig = identity::sign_external(&*g.admin_key, &body).unwrap();
    assert!(g.rs.add(&Record::new(body, sig, Some(g.admin_ca.der.clone()))).unwrap());
    let r = apply(&mut g.rs, &s, &tv, &Change::Rename("kitchen"), now_ms()).unwrap();
    assert_eq!(r.chain.len(), 1);
    assert_eq!(name_of(&g.rs, &tv).as_deref(), Some("kitchen"));

    let e = apply(&mut g.rs, &s, &g.root_phone, &Change::Remove, now_ms()).unwrap_err();
    assert!(e.message().contains("taking the group over"));
    let e = apply(&mut g.rs, &s, &g.admin_phone, &Change::Remove, now_ms()).unwrap_err();
    assert!(e.message().contains("itself"));
    assert!(apply(&mut g.rs, &s, &g.laptop, &Change::Rename("\u{7}"), now_ms()).is_err());
    assert!(apply(&mut g.rs, &s, &g.laptop, &Change::Thaw, now_ms()).unwrap_err().message().contains("not frozen"));
    apply(&mut g.rs, &s, &g.laptop, &Change::Remove, now_ms()).unwrap();
    assert!(name_of(&g.rs, &g.laptop).is_none());

    // A key that is no admin's signs nothing.
    let other = soft();
    let s = Signer { ca: &g.root, key: &*other, me: &g.admin_phone };
    let not = Cert::parse(
        &issue::admin_ca(&DeviceId::random(), &other.public(), &g.root, now_ms() / 1000, &mut |b| {
            identity::sign_external(&*g.root_key, b)
        })
        .unwrap(),
    )
    .unwrap();
    let s = Signer { ca: &not, ..s };
    assert!(
        apply(&mut g.rs, &s, &g.root_phone, &Change::Rename("x"), now_ms()).unwrap_err().message().contains("no admin")
    );
}

#[test]
fn mute_and_unmute_are_sealed_to_the_receiver() {
    let g = group();
    for (s, chain) in [
        (Signer { ca: &g.root, key: &*g.root_key, me: &g.root_phone }, 0),
        (Signer { ca: &g.admin_ca, key: &*g.admin_key, me: &g.admin_phone }, 1),
    ] {
        let r = order(&g.rs, &s, &g.laptop, &Order::Mute(60_000), now_ms()).unwrap();
        assert_eq!(r.chain.len(), chain);
        let mut c = g.rs.verify_command(&r, &g.laptop, now_ms()).unwrap();
        assert!(c.sealed());
        c.open(&g.laptop_seal).unwrap();
        assert_eq!((c.kind.as_str(), c.for_ms, c.by.as_str()), ("mute", 60_000, s.me));

        let r = order(&g.rs, &s, &g.laptop, &Order::Unmute, now_ms()).unwrap();
        let mut c = g.rs.verify_command(&r, &g.laptop, now_ms()).unwrap();
        c.open(&g.laptop_seal).unwrap();
        assert_eq!(c.kind, "unmute");
    }
    let s = Signer { ca: &g.root, key: &*g.root_key, me: &g.root_phone };
    // Without a key for sealed messages, the orders go in the open.
    let r = order(&g.rs, &s, &g.admin_phone, &Order::Mute(0), now_ms()).unwrap();
    let c = g.rs.verify_command(&r, &g.admin_phone, now_ms()).unwrap();
    assert!(!c.sealed() && c.for_ms == 0 && c.kind == "mute");
    assert!(order(&g.rs, &s, &g.laptop, &Order::Mute(-1), now_ms()).is_err());
    assert!(order(&g.rs, &s, &g.root_phone, &Order::Unmute, now_ms()).is_err());
}

#[test]
fn pastes_and_actions_are_sealed_to_the_receiver() {
    let g = group();
    let s = Signer { ca: &g.admin_ca, key: &*g.admin_key, me: &g.admin_phone };
    let paste = Order::Paste { mode: "type".into(), kind: "secret".into(), text: "hello".into(), enter: true };
    let r = order(&g.rs, &s, &g.laptop, &paste, now_ms()).unwrap();
    let mut c = g.rs.verify_command(&r, &g.laptop, now_ms()).unwrap();
    assert!(c.sealed() && c.text.is_empty());
    c.open(&g.laptop_seal).unwrap();
    assert_eq!(
        (c.kind.as_str(), c.mode.as_str(), c.paste_kind.as_str(), c.text.as_str(), c.enter),
        ("paste", "type", "secret", "hello", true)
    );
    let r = order(&g.rs, &s, &g.laptop, &Order::Action("lock".into()), now_ms()).unwrap();
    let mut c = g.rs.verify_command(&r, &g.laptop, now_ms()).unwrap();
    c.open(&g.laptop_seal).unwrap();
    assert_eq!((c.kind.as_str(), c.action.as_str()), ("action", "lock"));
    for (o, kind) in [(Order::PasteOff, "paste-off"), (Order::ActionsOff, "actions-off")] {
        let r = order(&g.rs, &s, &g.laptop, &o, now_ms()).unwrap();
        assert_eq!(g.rs.verify_command(&r, &g.laptop, now_ms()).unwrap().kind, kind);
    }
    assert!(order(&g.rs, &s, &g.laptop, &Order::Action("Not a name".into()), now_ms()).is_err());
}

#[test]
fn the_root_makes_a_computer_an_admin() {
    let mut g = group();
    let key = soft();
    let spki = certs::p256_spki_of(&key.public());
    let root = Signer { ca: &g.root, key: &*g.root_key, me: &g.root_phone };
    let e = make_admin(&g.rs, &root, &g.laptop, &spki, "file", true, now_ms()).err().unwrap();
    assert!(e.message().contains("in a file"));
    assert!(make_admin(&g.rs, &root, &g.laptop, &spki, "rootless", false, now_ms()).is_err());
    assert!(make_admin(&g.rs, &root, &g.admin_phone, &spki, "hardware", false, now_ms()).is_err());
    assert!(make_admin(&g.rs, &root, &g.laptop, &[1, 2, 3], "hardware", false, now_ms()).is_err());
    let admin = Signer { ca: &g.admin_ca, key: &*g.admin_key, me: &g.admin_phone };
    let e = make_admin(&g.rs, &admin, &g.laptop, &spki, "hardware", false, now_ms()).err().unwrap();
    assert!(e.message().contains("only the group's root"));

    let made = make_admin(&g.rs, &root, &g.laptop, &spki, "hardware", false, now_ms()).unwrap();
    let ca = Cert::parse(&made.admin_ca).unwrap();
    certs::check_admin_ca(&ca, &g.root).unwrap();
    assert_eq!(ca.public_key(), key.public().as_slice());
    assert!(g.rs.add(&made.record).unwrap());
    let d = g.rs.devices().into_iter().find(|d| d.id == g.laptop).unwrap();
    assert!(d.admin && d.admin_key == Some(ca.key_hash()));
    assert_eq!((d.store.as_str(), d.name.as_str()), ("hardware", "laptop"));
    assert!(make_admin(&g.rs, &root, &g.laptop, &spki, "hardware", false, now_ms()).is_err());
}

#[test]
fn a_due_certificate_is_renewed() {
    let g = group();
    let now = now_ms() / 1000;
    let dev = DeviceId::random();
    let key = soft();
    let sign = |b: &[u8]| identity::sign_external(&*g.root_key, b);
    let cert = Cert::parse(&issue::member(&dev, &key.public(), &g.root, now, &mut |b| sign(b)).unwrap()).unwrap();
    let roots = [g.root.clone()];
    let admin = Signer { ca: &g.admin_ca, key: &*g.admin_key, me: &g.admin_phone };
    assert!(renewal(std::slice::from_ref(&cert), &roots, &admin, now).unwrap().is_none());
    // 100 days before it ends, the admin renews it from its admin CA.
    let later = cert.not_after - 100 * 24 * 3600;
    let new = Cert::parse(&renewal(std::slice::from_ref(&cert), &roots, &admin, later).unwrap().unwrap()).unwrap();
    assert_eq!(new.public_key(), cert.public_key());
    assert!(new.not_after > cert.not_after);
    let chain = [new, g.admin_ca.clone()];
    assert_eq!(certs::verify_member(&chain, &roots, later, certs::Usage::Client).unwrap(), dev);
    // A chain from another group is refused.
    let other_key = soft();
    let other = Cert::parse(
        &issue::root_ca(&other_key.public(), now, &mut |b| identity::sign_external(&*other_key, b)).unwrap(),
    )
    .unwrap();
    let stranger = Cert::parse(
        &issue::member(&dev, &key.public(), &other, now, &mut |b| identity::sign_external(&*other_key, b)).unwrap(),
    )
    .unwrap();
    assert!(renewal(&[stranger], &roots, &admin, later).is_err());
}

#[test]
fn the_root_ends_two_histories_from_the_card() {
    let mut g = group();
    assert!(alerts(&g.rs).is_empty());
    // The admin key signs two records with one seq: two histories.
    let mut sign_twice = Vec::new();
    for name in ["tv", "radio"] {
        let body =
            g.rs.next_body(Body {
                v: 2,
                alg: authority::ALG_ES256.into(),
                kind: authority::TYPE_DEVICE.into(),
                signer: Hash(g.admin_ca.key_hash()),
                time_ms: now_ms(),
                device: DeviceId::random().to_string(),
                name: name.into(),
                role: "member".into(),
                key: Some(Hash(certs::random_bytes())),
                ..Default::default()
            })
            .unwrap();
        let sig = identity::sign_external(&*g.admin_key, &body).unwrap();
        sign_twice.push(Record::new(body, sig, Some(g.admin_ca.der.clone())));
    }
    for r in &sign_twice {
        g.rs.add(r).unwrap();
    }
    let a = alerts(&g.rs);
    let two = a.iter().find(|a| a.kind == "two_histories").expect("an alert of two histories");
    assert_eq!(two.names, ["R570E"]);
    assert_eq!(two.devices, [g.admin_phone.clone()]);
    assert_eq!(two.records.len(), 2);

    // Only the root decides.
    let admin = Signer { ca: &g.admin_ca, key: &*g.admin_key, me: &g.admin_phone };
    let e = change(&g.rs, &admin, "", &Change::Resolve(two.records.clone()), now_ms()).err().unwrap();
    assert!(e.message().contains("only the group's root"));
    let root = Signer { ca: &g.root, key: &*g.root_key, me: &g.root_phone };
    let records = two.records.clone();
    apply(&mut g.rs, &root, "", &Change::Resolve(records), now_ms()).unwrap();
    assert!(alerts(&g.rs).iter().all(|a| a.kind != "two_histories"), "{:?}", alerts(&g.rs));
}

/// A member counts as an admin through its chain only with an admin CA that
/// issued its certificate and that a root of the group certified, not with
/// a CA named after it from another root (Go's TestAdminPeerNeedsARealAdminCA).
#[test]
fn an_admin_peer_needs_a_real_admin_ca() {
    let g = group();
    let now = now_ms() / 1000;
    let dev = DeviceId::parse(&g.admin_phone).unwrap();
    let member_key = soft();
    // A CA the member made itself under a root of its own, named as its
    // admin CA would be.
    let own = soft();
    let own_root =
        Cert::parse(&issue::root_ca(&own.public(), now, &mut |b| identity::sign_external(&*own, b)).unwrap()).unwrap();
    let fake_key = soft();
    let fake = Cert::parse(
        &issue::admin_ca(&dev, &fake_key.public(), &own_root, now, &mut |b| identity::sign_external(&*own, b)).unwrap(),
    )
    .unwrap();
    let leaf = |ca: &Cert, key: &dyn ExternalKey| {
        Cert::parse(
            &issue::member(&dev, &member_key.public(), ca, now, &mut |b| identity::sign_external(key, b)).unwrap(),
        )
        .unwrap()
    };
    assert!(!g.rs.admin_peer(dev.as_str(), &[leaf(&fake, &*fake_key), fake.clone()]));
    // The real admin CA, but a leaf it did not issue.
    assert!(!g.rs.admin_peer(dev.as_str(), &[leaf(&fake, &*fake_key), g.admin_ca.clone()]));
    // The real thing: the admin CA from the root, which issued the leaf.
    assert!(g.rs.admin_peer(dev.as_str(), &[leaf(&g.admin_ca, &*g.admin_key), g.admin_ca.clone()]));
}

/// The root records what an attestation showed once, takes a revoked one
/// back to "hardware", and an admin records none.
#[test]
fn the_root_records_what_an_attestation_shows() {
    let mut g = group();
    let s = Signer { ca: &g.root, key: &*g.root_key, me: &g.root_phone };
    let key = g.rs.devices().into_iter().find(|d| d.id == g.admin_phone).unwrap().key;
    let device = |rs: &Records, id: &str| rs.devices().into_iter().find(|d| d.id == id).unwrap();
    let proven = Attested { store: "proven", kind: "android-tee", proof: "ab" };
    // Another key than the record's: nothing yet.
    assert!(evidence(&g.rs, &s, &g.admin_phone, &certs::random_bytes(), &proven, now_ms()).unwrap().is_none());
    let r = evidence(&g.rs, &s, &g.admin_phone, &key, &proven, now_ms()).unwrap().unwrap();
    assert!(g.rs.add(&r).unwrap());
    let d = device(&g.rs, &g.admin_phone);
    assert_eq!((d.store.as_str(), d.kind.as_str(), d.proof.as_str()), ("proven", "android-tee", "ab"));
    assert!(d.admin_key.is_some() && !d.powers.is_empty(), "the admin keeps its powers");
    assert!(evidence(&g.rs, &s, &g.admin_phone, &key, &proven, now_ms()).unwrap().is_none(), "said already");

    // Revoked: back to hardware with the kind it had.
    let revoked = Attested { store: "hardware", kind: "", proof: "" };
    let r = evidence(&g.rs, &s, &g.admin_phone, &key, &revoked, now_ms()).unwrap().unwrap();
    assert!(g.rs.add(&r).unwrap());
    let d = device(&g.rs, &g.admin_phone);
    assert_eq!((d.store.as_str(), d.kind.as_str()), ("hardware", "android-tee"));
    assert!(evidence(&g.rs, &s, &g.admin_phone, &key, &revoked, now_ms()).unwrap().is_none(), "proven no more");

    let a = Signer { ca: &g.admin_ca, key: &*g.admin_key, me: &g.admin_phone };
    let laptop_key = device(&g.rs, &g.laptop).key;
    assert!(evidence(&g.rs, &a, &g.laptop, &laptop_key, &proven, now_ms()).is_err());
}

/// A key whose holder sees what it signs, as a watch's does.
struct SeeingKey(SoftKey, std::sync::Mutex<Vec<Vec<u8>>>);

impl ExternalKey for SeeingKey {
    fn public(&self) -> Vec<u8> {
        self.0.public()
    }

    fn sign_digest(&self, _: &[u8; 32]) -> Result<Vec<u8>> {
        Err(Error::msg("the watch signs only what it sees"))
    }

    fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.1.lock().unwrap().push(data.to_vec());
        self.0.sign_digest(&certs::sha256(data))
    }
}

#[test]
fn a_watch_freezes_and_removes_from_the_wrist() {
    let mut g = group();
    let root = Signer { ca: &g.root, key: &*g.root_key, me: &g.root_phone };
    let watch = DeviceId::random().to_string();
    let key =
        SeeingKey(SoftKey(SigningKey::from_bytes(&certs::random_bytes::<32>().into()).unwrap()), Default::default());
    let admin = Signer { ca: &g.admin_ca, key: &*g.admin_key, me: &g.admin_phone };
    assert!(add_watch(&g.rs, &admin, &watch, "Watch", "harmonyos", &key.public(), now_ms()).is_err());
    assert!(add_watch(&g.rs, &root, &watch, "Watch", "linux", &key.public(), now_ms()).is_err());
    assert!(add_watch(&g.rs, &root, &g.laptop, "Watch", "harmonyos", &key.public(), now_ms()).is_err());
    let made = add_watch(&g.rs, &root, &watch, "Watch", "harmonyos", &key.public(), now_ms()).unwrap();
    assert!(g.rs.add(&made.record).unwrap());
    let w = g.rs.devices().into_iter().find(|d| d.id == watch).unwrap();
    assert!(w.admin && w.role == "watch");
    let ca = Cert::parse(&made.admin_ca).unwrap();

    // Nothing to the root's phone, a phone or the watch; the laptop, no
    // admin, is removed but not frozen.
    assert!(watch_actions(&g.rs, &g.root_phone).is_empty());
    assert!(watch_actions(&g.rs, &g.admin_phone).is_empty());
    assert_eq!(watch_actions(&g.rs, &g.laptop), ["remove", "paste-off", "actions-off", "away-off", "action"]);

    let s = Signer { ca: &ca, key: &key, me: &watch };
    let off = order(&g.rs, &s, &g.laptop, &Order::PasteOff, now_ms()).unwrap();
    assert!(!off.body.is_empty());
    let seen = key.1.lock().unwrap().last().cloned().unwrap();
    assert!(!seen.is_empty(), "the watch saw the command it signed");

    // The laptop made a full admin is neither frozen nor removed from the
    // wrist: only the root takes back an admin that removes admins.
    let lkey = soft();
    let spki = certs::p256_spki_of(&lkey.public());
    let made = make_admin(&g.rs, &root, &g.laptop, &spki, "hardware", false, now_ms()).unwrap();
    assert!(g.rs.add(&made.record).unwrap());
    assert!(!watch_actions(&g.rs, &g.laptop).contains(&"freeze"));
    assert!(!watch_actions(&g.rs, &g.laptop).contains(&"remove"));
    assert!(change(&g.rs, &s, &g.laptop, &Change::Freeze, now_ms()).is_err());

    // A second watch, lost, is frozen by the first.
    let lost = DeviceId::random().to_string();
    let made = add_watch(&g.rs, &root, &lost, "Old watch", "wearos", &soft().public(), now_ms()).unwrap();
    assert!(g.rs.add(&made.record).unwrap());
    assert_eq!(watch_actions(&g.rs, &lost), ["freeze"]);
    apply(&mut g.rs, &s, &lost, &Change::Freeze, now_ms()).unwrap();
    let body = Body::parse(key.1.lock().unwrap().last().unwrap()).unwrap();
    assert_eq!((body.kind.as_str(), body.signer), ("freeze", Hash(ca.key_hash())));
    assert!(g.rs.devices().into_iter().find(|d| d.id == lost).unwrap().frozen);
    assert!(watch_actions(&g.rs, &lost).is_empty());
}
