// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The root's own records, with software keys the core treats as keys it
//! does not hold.

use std::sync::Arc;

use p256::ecdsa::signature::hazmat::PrehashSigner as _;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};

use super::*;
use crate::identity::ExternalKey;
use crate::takeover::{self, How};

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

fn soft_of(scalar: [u8; 32]) -> Arc<dyn ExternalKey> {
    Arc::new(SoftKey(SigningKey::from_bytes(&scalar.into()).unwrap()))
}

fn soft() -> Arc<dyn ExternalKey> {
    soft_of(certs::random_bytes::<32>())
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
}

fn base(ms: i64) -> Body {
    Body {
        v: 2,
        alg: authority::ALG_ES256.into(),
        kind: authority::TYPE_DEVICE.into(),
        time_ms: ms,
        ..Default::default()
    }
}

fn group() -> Group {
    let ms = now_ms();
    let now = ms / 1000;
    let root_key = soft();
    let root =
        Cert::parse(&issue::root_ca(&root_key.public(), now, &mut |b| identity::sign_external(&*root_key, b)).unwrap())
            .unwrap();
    let mut rs = Records::new(&root);
    rs.set_clock(move || ms);
    let add = |rs: &mut Records, b: Body| {
        let body = rs.next_body(Body { signer: Hash(root.key_hash()), ..b }).unwrap();
        let sig = identity::sign_external(&*root_key, &body).unwrap();
        assert!(rs.add(&Record::new(body, sig, None)).unwrap());
    };
    let root_phone = DeviceId::random().to_string();
    add(
        &mut rs,
        Body {
            device: root_phone.clone(),
            name: "R570E".into(),
            role: "phone".into(),
            os: "aurora".into(),
            key: Some(Hash(certs::random_bytes())),
            store: "hardware".into(),
            holds_root: true,
            ..base(ms)
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
    add(
        &mut rs,
        Body {
            device: admin_phone.to_string(),
            name: "iPhone".into(),
            role: "phone".into(),
            key: Some(Hash(certs::random_bytes())),
            admin: Some(Hash(admin_ca.key_hash())),
            powers: authority::POWERS.iter().map(|p| (*p).into()).collect(),
            commands: authority::COMMANDS.iter().map(|c| (*c).into()).collect(),
            store: "file".into(),
            ..base(ms)
        },
    );
    let laptop = DeviceId::random().to_string();
    add(
        &mut rs,
        Body {
            device: laptop.clone(),
            name: "laptop".into(),
            role: "member".into(),
            os: "linux".into(),
            key: Some(Hash(certs::random_bytes())),
            ..base(ms)
        },
    );
    Group { rs, root, root_key, root_phone, admin_ca, admin_key, admin_phone: admin_phone.to_string(), laptop }
}

impl Group {
    fn root_signer(&self) -> Signer<'_> {
        Signer { ca: &self.root, key: &*self.root_key, me: &self.root_phone }
    }

    fn admin_signer(&self) -> Signer<'_> {
        Signer { ca: &self.admin_ca, key: &*self.admin_key, me: &self.admin_phone }
    }
}

fn add(rs: &mut Records, r: &Record) {
    assert!(rs.add(r).unwrap(), "the set refused a record");
}

#[test]
fn a_settings_record_keeps_what_it_does_not_change() {
    let mut g = group();
    let v = view(&g.rs);
    assert_eq!((v.delay_ms, v.key_level.as_str(), v.recovery), (authority::DEFAULT_DELAY, "hardware", false));
    let r = settings(&g.rs, &g.root_signer(), &Setting::KeyLevel("files"), now_ms()).unwrap();
    add(&mut g.rs, &r);
    let r = settings(&g.rs, &g.root_signer(), &Setting::Delay(3_600_000), now_ms()).unwrap();
    add(&mut g.rs, &r);
    assert_eq!(settings_of(&g.rs, &Hash(g.root.key_hash())), (Some(3_600_000), "files".to_string()));
    assert_eq!(g.rs.state().key_level, "files");
    assert_eq!(view(&g.rs).delay_ms, 3_600_000);
    let r = settings(&g.rs, &g.root_signer(), &Setting::KeyLevel("hardware"), now_ms()).unwrap();
    add(&mut g.rs, &r);
    assert_eq!(settings_of(&g.rs, &Hash(g.root.key_hash())), (Some(3_600_000), "hardware".to_string()));
    // The admin phone keeps its key in a file, below the level now.
    assert_eq!(below_level(&g.rs, &g.root_phone, "hardware"), vec![g.admin_phone.clone()]);
}

#[test]
fn only_the_root_signs_settings_within_bounds() {
    let g = group();
    assert!(settings(&g.rs, &g.admin_signer(), &Setting::Delay(0), now_ms()).is_err());
    assert!(settings(&g.rs, &g.root_signer(), &Setting::Delay(-1), now_ms()).is_err());
    assert!(settings(&g.rs, &g.root_signer(), &Setting::Delay(authority::MAX_DELAY + 1), now_ms()).is_err());
    assert!(settings(&g.rs, &g.root_signer(), &Setting::KeyLevel("any"), now_ms()).is_err());
    // The root's own phone keeps hardware keys, not proven ones.
    assert!(settings(&g.rs, &g.root_signer(), &Setting::KeyLevel("proven"), now_ms()).is_err());
}

#[test]
fn the_root_hands_the_group_to_an_admin() {
    let mut g = group();
    assert!(hand_over(&g.rs, &g.root_signer(), &g.laptop, now_ms()).is_err());
    assert!(hand_over(&g.rs, &g.root_signer(), &g.root_phone, now_ms()).is_err());
    assert!(hand_over(&g.rs, &g.admin_signer(), &g.admin_phone, now_ms()).is_err());
    assert_eq!(view(&g.rs).handed_to, None);
    let r = hand_over(&g.rs, &g.root_signer(), &g.admin_phone, now_ms()).unwrap();
    add(&mut g.rs, &r);
    assert_eq!(g.rs.handed_to(), Some(g.admin_ca.key_hash()));
    assert_eq!(view(&g.rs).handed_to, Some(g.admin_phone.clone()));
}

#[test]
fn a_recovery_key_from_its_sheet_claims_the_group() {
    let mut g = group();
    assert!(remove_recovery(&g.rs, &g.root_signer(), now_ms()).is_err());
    assert!(make_recovery(&g.rs, &g.admin_signer(), now_ms()).is_err());
    let made = make_recovery(&g.rs, &g.root_signer(), now_ms()).unwrap();
    add(&mut g.rs, &made.record);
    let sheet = recovery::read(&made.qr).unwrap();
    assert_eq!(sheet.group.as_deref(), Some(g.rs.tag()));
    assert_eq!(g.rs.state().recovery, Some(Hash(sheet.admin().unwrap())));
    assert!(view(&g.rs).recovery);
    assert_eq!(recovery::read(&made.text).unwrap().scalar(), sheet.scalar());

    // The key from the sheet signs a claim with its admin CA.
    let key = soft_of(sheet.scalar());
    let ca = Cert::parse(sheet.cert.as_deref().unwrap()).unwrap();
    let me = DeviceId::random().to_string();
    let new_key = soft();
    let new_root =
        issue::root_ca(&new_key.public(), now_ms() / 1000, &mut |b| identity::sign_external(&*new_key, b)).unwrap();
    let s = Signer { ca: &ca, key: &*key, me: &me };
    let claim = takeover::claim(&g.rs, &s, How::Recovery, &new_root, now_ms()).unwrap();
    add(&mut g.rs, &claim);

    // A new one replaces it, and the removal leaves none.
    let again = make_recovery(&g.rs, &g.root_signer(), now_ms()).unwrap();
    add(&mut g.rs, &again.record);
    assert_ne!(g.rs.state().recovery, Some(Hash(sheet.admin().unwrap())));
    let r = remove_recovery(&g.rs, &g.root_signer(), now_ms()).unwrap();
    add(&mut g.rs, &r);
    assert_eq!(g.rs.state().recovery, None);
}
