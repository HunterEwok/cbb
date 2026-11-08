// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Taking a phone's group over, with software keys the core treats as keys
//! it does not hold.

use std::sync::Arc;

use p256::ecdsa::signature::hazmat::PrehashSigner as _;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};

use super::*;
use crate::identity::ExternalKey;

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

const HOUR: i64 = 3600 * 1000;

/// A group: the root's phone, an admin phone and an admin computer.
struct Group {
    rs: Records,
    ms: i64,
    root: Cert,
    root_key: Arc<dyn ExternalKey>,
    root_phone: String,
    admin_ca: Cert,
    admin_key: Arc<dyn ExternalKey>,
    admin_phone: String,
    admin_member: Arc<dyn ExternalKey>,
    laptop: String,
    laptop_key: Arc<dyn ExternalKey>,
}

fn sign_root(g: &mut Records, root: &Cert, key: &dyn ExternalKey, b: Body) {
    let body = g.next_body(Body { signer: Hash(root.key_hash()), ..b }).unwrap();
    let sig = identity::sign_external(key, &body).unwrap();
    assert!(g.add(&Record::new(body, sig, None)).unwrap());
}

fn base(kind: &str, ms: i64) -> Body {
    Body { v: 2, alg: authority::ALG_ES256.into(), kind: kind.into(), time_ms: ms, ..Default::default() }
}

fn make_admin_ca(device: &str, key: &dyn ExternalKey, root: &Cert, root_key: &dyn ExternalKey, now: i64) -> Cert {
    let id = DeviceId::parse(device).unwrap();
    Cert::parse(&issue::admin_ca(&id, &key.public(), root, now, &mut |b| identity::sign_external(root_key, b)).unwrap())
        .unwrap()
}

fn group(settings: Option<Body>) -> Group {
    let ms = now_ms();
    let now = ms / 1000;
    let root_key = soft();
    let root =
        Cert::parse(&issue::root_ca(&root_key.public(), now, &mut |b| identity::sign_external(&*root_key, b)).unwrap())
            .unwrap();
    let mut rs = Records::new(&root);
    rs.set_clock(move || ms);
    let root_phone = DeviceId::random().to_string();
    sign_root(
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
            ..base(authority::TYPE_DEVICE, ms)
        },
    );
    let admin_phone = DeviceId::random().to_string();
    let admin_key = soft();
    let admin_member = soft();
    let admin_ca = make_admin_ca(&admin_phone, &*admin_key, &root, &*root_key, now);
    sign_root(
        &mut rs,
        &root,
        &*root_key,
        Body {
            device: admin_phone.clone(),
            name: "R570E".into(),
            role: "phone".into(),
            os: "aurora".into(),
            key: Some(Hash(certs::sha256(&certs::p256_spki_of(&admin_member.public())))),
            admin: Some(Hash(admin_ca.key_hash())),
            powers: authority::POWERS.iter().map(|p| (*p).into()).collect(),
            commands: authority::COMMANDS.iter().map(|c| (*c).into()).collect(),
            store: "hardware".into(),
            ..base(authority::TYPE_DEVICE, ms)
        },
    );
    let laptop = DeviceId::random().to_string();
    let laptop_key = soft();
    let laptop_ca = make_admin_ca(&laptop, &*laptop_key, &root, &*root_key, now);
    sign_root(
        &mut rs,
        &root,
        &*root_key,
        Body {
            device: laptop.clone(),
            name: "laptop".into(),
            role: "full".into(),
            os: "linux".into(),
            key: Some(Hash(certs::random_bytes())),
            admin: Some(Hash(laptop_ca.key_hash())),
            powers: authority::POWERS.iter().map(|p| (*p).into()).collect(),
            commands: authority::COMMANDS.iter().map(|c| (*c).into()).collect(),
            store: "hardware".into(),
            ..base(authority::TYPE_DEVICE, ms)
        },
    );
    if let Some(b) = settings {
        sign_root(&mut rs, &root, &*root_key, Body { time_ms: ms, ..b });
    }
    Group { rs, ms, root, root_key, root_phone, admin_ca, admin_key, admin_phone, admin_member, laptop, laptop_key }
}

/// A new root for a new key of the claimant; on the Aurora phone the admin
/// key itself.
fn new_root(key: &dyn ExternalKey, ms: i64) -> Vec<u8> {
    issue::root_ca(&key.public(), ms / 1000, &mut |b| identity::sign_external(key, b)).unwrap()
}

fn add(rs: &mut Records, r: &Record) {
    assert!(rs.add(r).unwrap(), "the set refused a record");
}

#[test]
fn an_admin_takes_the_group_from_its_lost_root() {
    let mut settings = base(authority::TYPE_SETTINGS, 0);
    settings.takeover_delay_ms = Some(HOUR);
    settings.key_level = "files".into();
    let mut g = group(Some(settings));
    let s = Signer { ca: &g.admin_ca, key: &*g.admin_key, me: &g.admin_phone };
    let root_der = new_root(&*g.admin_key, g.ms);

    // Only the root's device, and only an admin.
    assert!(claim(&g.rs, &s, How::From(&g.laptop), &root_der, g.ms).is_err());
    let r = Signer { ca: &g.root, key: &*g.root_key, me: &g.root_phone };
    assert!(claim(&g.rs, &r, How::From(&g.root_phone), &root_der, g.ms).is_err());

    let c = claim(&g.rs, &s, How::From(&g.root_phone), &root_der, g.ms).unwrap();
    assert_eq!(c.chain.len(), 1);
    add(&mut g.rs, &c);
    let st = claim_state(&g.rs, &root_der).unwrap();
    assert_eq!(st.state, "pending");
    assert!(st.left_ms > 0 && st.left_ms <= HOUR);
    // A second claim waits for the first.
    assert!(claim(&g.rs, &s, How::From(&g.root_phone), &new_root(&*soft(), g.ms), g.ms).is_err());

    let root = Cert::parse(&root_der).unwrap();
    let nr = Signer { ca: &root, key: &*g.admin_key, me: &g.admin_phone };
    let own = Own { name: "Aurora", role: "phone", os: "aurora", store: "hardware", seal: &[] };
    let point = g.admin_member.public();
    assert!(finish(&g.rs, &nr, &point, &own, g.ms).is_err());

    let later = g.ms + 2 * HOUR;
    g.rs.set_clock(move || later);
    assert_eq!(claim_state(&g.rs, &root_der).unwrap().state, "effective");
    let f = finish(&g.rs, &nr, &point, &own, later).unwrap();
    let cert = Cert::parse(&f.cert).unwrap();
    assert!(cert.signed_by(&root));
    assert_eq!(cert.public_key(), point.as_slice());
    // It replaces the admin's certificate even when both are of one second.
    let id = DeviceId::parse(&g.admin_phone).unwrap();
    let old = issue::member(&id, &point, &g.admin_ca, later / 1000, &mut |b| identity::sign_external(&*g.admin_key, b))
        .unwrap();
    let ident = identity::Identity {
        id,
        key: Vec::new(),
        external: Some(g.admin_member.clone()),
        cert: Cert::parse(&old).unwrap(),
        issuer: Some(g.admin_ca.clone()),
        group_ca: g.root.clone(),
        roots: vec![root.clone()],
    };
    assert_eq!(ident.cert.not_after, cert.not_after);
    let next = ident.with_cert_from(&f.cert, None).unwrap();
    assert!(next.issuer.is_none());
    for r in &f.records {
        assert!(r.chain.is_empty());
        add(&mut g.rs, r);
    }
    let st = g.rs.state();
    assert_eq!(st.root_device, g.admin_phone);
    assert_eq!(g.rs.root_member().map(|(d, _)| d), Some(g.admin_phone.clone()));
    let devs = g.rs.devices();
    assert!(!devs.iter().any(|d| d.id == g.root_phone), "the lost root's device stays");
    let me = devs.iter().find(|d| d.id == g.admin_phone).unwrap();
    assert_eq!((me.name.as_str(), me.os.as_str()), ("R570E", "aurora"));
    assert!(devs.iter().any(|d| d.id == g.laptop && d.admin), "the admin computer goes");
    // The old root's settings go on under the new one.
    assert_eq!(st.key_level, "files");

    // The admin computer's CA is from the old root: the new root renews it,
    // and has its record already.
    let nr = Signer { ca: &root, key: &*g.admin_key, me: &g.admin_phone };
    let ren = renew_admin_ca(&g.rs, &nr, &g.laptop, &g.laptop_key.public(), later).unwrap();
    assert!(Cert::parse(&ren.admin_ca).unwrap().signed_by(&root));
    assert!(ren.record.is_none());
    assert!(renew_admin_ca(&g.rs, &nr, &g.laptop, &soft().public(), later).is_err());
    assert!(renew_admin_ca(&g.rs, &s, &g.laptop, &g.laptop_key.public(), later).is_err());
    assert!(claim(&g.rs, &nr, How::From(&g.root_phone), &new_root(&*soft(), later), later).is_err());
}

#[test]
fn a_root_that_handed_the_group_over_keeps_its_device() {
    let mut g = group(None);
    let mut h = base(authority::TYPE_HANDOVER, g.ms);
    h.admin = Some(Hash(g.admin_ca.key_hash()));
    let (root, root_key) = (g.root.clone(), g.root_key.clone());
    sign_root(&mut g.rs, &root, &*root_key, h);
    let s = Signer { ca: &g.admin_ca, key: &*g.admin_key, me: &g.admin_phone };
    let key = soft();
    let root_der = new_root(&*key, g.ms);
    let c = claim(&g.rs, &s, How::HandedOver, &root_der, g.ms).unwrap();
    add(&mut g.rs, &c);
    assert_eq!(claim_state(&g.rs, &root_der).unwrap().state, "effective");

    let root = Cert::parse(&root_der).unwrap();
    let nr = Signer { ca: &root, key: &*key, me: &g.admin_phone };
    let own = Own { name: "Aurora", role: "phone", os: "aurora", store: "hardware", seal: &[] };
    let f = finish(&g.rs, &nr, &g.admin_member.public(), &own, g.ms).unwrap();
    for r in &f.records {
        add(&mut g.rs, r);
    }
    assert_eq!(g.rs.state().root_device, g.admin_phone);
    assert!(g.rs.devices().iter().any(|d| d.id == g.root_phone));
}

#[test]
fn a_claim_needs_a_handover_or_the_recovery_key() {
    let mut g = group(None);
    let s = Signer { ca: &g.admin_ca, key: &*g.admin_key, me: &g.admin_phone };
    assert!(claim(&g.rs, &s, How::HandedOver, &new_root(&*soft(), g.ms), g.ms).is_err());
    assert!(claim(&g.rs, &s, How::Recovery, &new_root(&*soft(), g.ms), g.ms).is_err());

    // The root phone made a recovery key: its admin CA claims.
    let phone = DeviceId::random().to_string();
    let rkey = soft();
    let rca = make_admin_ca(&phone, &*rkey, &g.root, &*g.root_key, g.ms / 1000);
    let mut b = base(authority::TYPE_RECOVERY, g.ms);
    b.admin = Some(Hash(rca.key_hash()));
    b.cert = rca.der.clone();
    let (root, root_key) = (g.root.clone(), g.root_key.clone());
    sign_root(&mut g.rs, &root, &*root_key, b);
    let rs = Signer { ca: &rca, key: &*rkey, me: &phone };
    let root_der = new_root(&*soft(), g.ms);
    let c = claim(&g.rs, &rs, How::Recovery, &root_der, g.ms).unwrap();
    add(&mut g.rs, &c);
    assert_eq!(claim_state(&g.rs, &root_der).unwrap().state, "pending");
    assert!(claim_state(&g.rs, &new_root(&*soft(), g.ms)).is_none());
    // Not a root CA.
    assert!(claim(&g.rs, &s, How::From(&g.root_phone), &rca.der, g.ms).is_err());
}
