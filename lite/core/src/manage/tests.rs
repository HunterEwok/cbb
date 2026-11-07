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
            role: "full".into(),
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
            role: "lite".into(),
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
