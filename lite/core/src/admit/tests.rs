// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The admitting side against the core's own listening joiner
//! (pair_session), both in memory.

use std::sync::Arc;

use p256::ecdsa::signature::hazmat::PrehashSigner as _;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use rustls::pki_types::UnixTime;
use rustls::time_provider::TimeProvider;

use super::*;
use crate::pair::Joiner;
use crate::pair_session::{Attempt, Outcome as JoinOutcome};

#[derive(Debug)]
struct SystemClock;

impl TimeProvider for SystemClock {
    fn current_time(&self) -> Option<UnixTime> {
        Some(UnixTime::now())
    }
}

fn clock() -> Clock {
    Arc::new(SystemClock)
}

fn now_ms() -> i64 {
    UnixTime::now().as_secs() as i64 * 1000
}

/// A software key that the core treats as one it does not hold.
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

fn sign_with(k: &Arc<dyn ExternalKey>) -> impl FnMut(&[u8]) -> Result<Vec<u8>> + '_ {
    move |b| identity::sign_external(&**k, b)
}

/// A group whose root this member holds: the root's key, its admitter and
/// the group's records.
fn root_group() -> (Admitter, Records) {
    let now = now_ms() / 1000;
    let root_key = soft();
    let root = Cert::parse(&issue::root_ca(&root_key.public(), now, &mut sign_with(&root_key)).unwrap()).unwrap();
    let dev_key = soft();
    let id = DeviceId::random();
    let cert =
        Cert::parse(&issue::member(&id, &dev_key.public(), &root, now, &mut sign_with(&root_key)).unwrap()).unwrap();
    let identity = Identity {
        id,
        key: Vec::new(),
        external: Some(dev_key),
        cert,
        issuer: None,
        group_ca: root.clone(),
        roots: Vec::new(),
    };
    let ms = now_ms();
    let mut rs = Records::new(&root);
    rs.set_clock(move || ms);
    (Admitter { identity, ca: root, ca_key: root_key, make_admins: false }, rs)
}

/// Runs an admission against a listening joiner and returns the two ends'
/// last outcomes and what the member admitted.
fn run(
    adm: &mut Admission,
    joining: &mut Attempt,
) -> (Option<Admitted>, Option<crate::pair_session::Joined>, Option<Error>, Option<Error>, bool) {
    let (mut admitted, mut joined, mut member_err, mut joiner_err, mut confirmed) = (None, None, None, None, false);
    let mut to_joiner = adm.feed(&[], now_ms()).send;
    for _ in 0..32 {
        let step = joining.feed(&to_joiner, now_ms());
        let mut to_member = step.send;
        match step.outcome {
            JoinOutcome::Joined(j) => {
                to_member.extend(joining.finish(true));
                joined = Some(*j);
            }
            JoinOutcome::Failed { error, .. } => joiner_err = Some(error),
            JoinOutcome::Pending => {}
        }
        let step = adm.feed(&to_member, now_ms());
        to_joiner = step.send;
        match step.outcome {
            Outcome::Admitted(a) => admitted = Some(*a),
            Outcome::Done { confirmed: c } => {
                confirmed = c;
                break;
            }
            Outcome::Failed { error, .. } => {
                member_err = Some(error);
                if let JoinOutcome::Failed { error, .. } = joining.feed(&to_joiner, now_ms()).outcome {
                    joiner_err = Some(error);
                }
                break;
            }
            Outcome::Pending => {}
        }
        if to_joiner.is_empty() && to_member.is_empty() && joiner_err.is_some() {
            break;
        }
    }
    (admitted, joined, member_err, joiner_err, confirmed)
}

/// An error's message and its causes.
fn text(e: Option<Error>) -> String {
    let e = e.expect("an error");
    format!("{}\n{}", e.message(), e.details())
}

#[test]
fn the_root_admits_a_lite_member() {
    let (admitter, mut rs) = root_group();
    let joiner = Joiner::new("router").unwrap();
    let code = pair::new_code();
    let mut joining = Attempt::listening(&joiner, &code, &clock()).unwrap();
    let mut adm =
        Admission::dial(admitter.clone(), GroupView::of(&rs), &code, &joiner.fingerprint(), &clock()).unwrap();
    let (admitted, joined, member_err, joiner_err, confirmed) = run(&mut adm, &mut joining);
    assert!(member_err.is_none() && joiner_err.is_none(), "{member_err:?} {joiner_err:?}");
    let (a, j) = (admitted.unwrap(), joined.unwrap());
    assert!(confirmed);
    assert_eq!(a.device, joiner.id);
    assert_eq!(j.identity.id, joiner.id);
    assert_eq!(j.identity.cert.der, a.cert);
    assert!(j.identity.issuer.is_none() && a.admin_ca.is_none());

    // Its device record counts in the group.
    let r = device_record(&rs, &admitter, &a, now_ms()).unwrap();
    assert!(rs.add(&r).unwrap());
    let d = rs.devices().into_iter().find(|d| d.id == joiner.id.as_str()).unwrap();
    assert_eq!((d.role.as_str(), d.name.as_str(), d.admin), ("lite", "router", false));
}

#[test]
fn the_root_makes_a_phone_an_admin() {
    let (mut admitter, mut rs) = root_group();
    admitter.make_admins = true;
    let admin_key = soft();
    let joiner = Joiner::with_key("phone", "aurora", soft()).unwrap().offering_admin_key(admin_key.clone()).unwrap();
    let code = pair::new_code();
    let mut joining = Attempt::listening(&joiner, &code, &clock()).unwrap();
    let mut adm =
        Admission::dial(admitter.clone(), GroupView::of(&rs), &code, &joiner.fingerprint(), &clock()).unwrap();
    let (admitted, joined, member_err, joiner_err, _) = run(&mut adm, &mut joining);
    assert!(member_err.is_none() && joiner_err.is_none(), "{member_err:?} {joiner_err:?}");
    let (a, j) = (admitted.unwrap(), joined.unwrap());
    let ca = Cert::parse(&j.admin_ca.unwrap()).unwrap();
    assert_eq!(ca.public_key(), admin_key.public().as_slice());
    assert_eq!(Some(ca.der.clone()), a.admin_ca);

    let r = device_record(&rs, &admitter, &a, now_ms()).unwrap();
    assert!(rs.add(&r).unwrap());
    let d = rs.devices().into_iter().find(|d| d.id == joiner.id.as_str()).unwrap();
    assert_eq!((d.role.as_str(), d.os.as_str(), d.admin), ("phone", "aurora", true));
    assert!(d.powers.iter().any(|p| p == authority::POWER_ADMIT));

    // The same admin key on another phone is refused.
    let again = Joiner::with_key("phone 2", "aurora", soft()).unwrap().offering_admin_key(admin_key).unwrap();
    let mut joining = Attempt::listening(&again, &code, &clock()).unwrap();
    let mut adm = Admission::dial(admitter, GroupView::of(&rs), &code, &again.fingerprint(), &clock()).unwrap();
    let (admitted, joined, member_err, _, _) = run(&mut adm, &mut joining);
    assert!(admitted.is_none() && joined.is_none());
    assert!(text(member_err).contains("another device"));
}

#[test]
fn an_admin_admits_with_its_admin_ca() {
    let (root_admitter, _) = root_group();
    let now = now_ms() / 1000;
    let admin_key = soft();
    let root = root_admitter.ca.clone();
    let id = root_admitter.identity.id.clone();
    let ca = issue::admin_ca(&id, &admin_key.public(), &root, now, &mut root_admitter.sign()).unwrap();
    let mut admitter = root_admitter.clone();
    admitter.ca = Cert::parse(&ca).unwrap();
    admitter.ca_key = admin_key;
    assert!(!admitter.is_root());

    let joiner = Joiner::new("router").unwrap();
    let code = pair::new_code();
    let mut joining = Attempt::listening(&joiner, &code, &clock()).unwrap();
    let mut adm = Admission::dial(admitter, GroupView::default(), &code, &joiner.fingerprint(), &clock()).unwrap();
    let (admitted, joined, member_err, joiner_err, _) = run(&mut adm, &mut joining);
    assert!(member_err.is_none() && joiner_err.is_none(), "{member_err:?} {joiner_err:?}");
    let j = joined.unwrap();
    assert_eq!(j.identity.issuer.map(|c| c.der), Some(ca));
    assert!(admitted.is_some());
}

#[test]
fn refusals() {
    // A wrong code: the joiner learns nothing, and the member hears why.
    let (admitter, rs) = root_group();
    let joiner = Joiner::new("router").unwrap();
    let mut joining = Attempt::listening(&joiner, "111111", &clock()).unwrap();
    let mut adm =
        Admission::dial(admitter.clone(), GroupView::of(&rs), "222222", &joiner.fingerprint(), &clock()).unwrap();
    let (admitted, joined, member_err, joiner_err, _) = run(&mut adm, &mut joining);
    assert!(admitted.is_none() && joined.is_none() && joiner_err.is_some());
    assert!(text(member_err).contains(Refusal::WrongCode.message()));

    // Another device than the QR code's.
    let mut joining = Attempt::listening(&joiner, "111111", &clock()).unwrap();
    let other = Joiner::new("other").unwrap();
    let mut adm =
        Admission::dial(admitter.clone(), GroupView::of(&rs), "111111", &other.fingerprint(), &clock()).unwrap();
    let (admitted, _, member_err, _, _) = run(&mut adm, &mut joining);
    assert!(admitted.is_none());
    assert!(text(member_err).contains("not the one in the QR code"));

    // A device ID in the group already.
    let mut view = GroupView::of(&rs);
    view.devices.insert(joiner.id.to_string());
    let mut joining = Attempt::listening(&joiner, "111111", &clock()).unwrap();
    let mut adm = Admission::dial(admitter.clone(), view, "111111", &joiner.fingerprint(), &clock()).unwrap();
    let (admitted, _, member_err, joiner_err, _) = run(&mut adm, &mut joining);
    assert!(admitted.is_none());
    assert!(text(member_err).contains(Refusal::Taken.message()));
    assert!(text(joiner_err).contains(Refusal::Taken.message()));

    // A phone that asks to be an admin in a window that makes none.
    let phone = Joiner::with_key("phone", "aurora", soft()).unwrap().offering_admin_key(soft()).unwrap();
    let mut joining = Attempt::listening(&phone, "111111", &clock()).unwrap();
    let mut adm = Admission::dial(admitter, GroupView::of(&rs), "111111", &phone.fingerprint(), &clock()).unwrap();
    let (admitted, joined, member_err, _, _) = run(&mut adm, &mut joining);
    assert!(admitted.is_none() && joined.is_none());
    assert!(text(member_err).contains("add it as an admin"));
}

#[test]
fn a_wrong_code_tells_the_admin() {
    // The joiner checks the code with the tag the admin sends first, and its
    // refusal says the code was wrong: the admin's side says so too.
    let (admitter, rs) = root_group();
    let joiner = Joiner::new("router").unwrap();
    let mut joining = Attempt::listening(&joiner, "111111", &clock()).unwrap();
    let mut adm = Admission::dial(admitter, GroupView::of(&rs), "222222", &joiner.fingerprint(), &clock()).unwrap();
    let mut to_joiner = adm.feed(&[], now_ms()).send;
    for _ in 0..32 {
        let to_member = joining.feed(&to_joiner, now_ms()).send;
        let step = adm.feed(&to_member, now_ms());
        to_joiner = step.send;
        if let Outcome::Failed { error, wrong_code } = step.outcome {
            assert!(wrong_code, "{error:?}");
            return;
        }
    }
    panic!("the admission did not end");
}

#[test]
fn a_phone_makes_its_group_and_admits() {
    let root_key = soft();
    let member_key = soft();
    let own = OwnDevice {
        name: "phone",
        os: "aurora",
        member_point: &member_key.public(),
        store: "hardware",
        seal: Vec::new(),
    };
    let g = new_group(&*root_key, &own, now_ms()).unwrap();
    let id = certs::verify_member(
        std::slice::from_ref(&g.cert),
        std::slice::from_ref(&g.root),
        now_ms() / 1000,
        certs::Usage::Client,
    )
    .unwrap();
    assert_eq!(id, g.device);
    let d = g.records.devices().into_iter().find(|d| d.id == g.device.as_str()).unwrap();
    assert_eq!((d.role.as_str(), d.os.as_str(), d.name.as_str()), ("phone", "aurora", "phone"));
    assert_eq!(g.records.root_member().map(|(id, _)| id), Some(g.device.to_string()));

    // The phone admits a device as the group's root.
    let identity = Identity {
        id: g.device.clone(),
        key: Vec::new(),
        external: Some(member_key),
        cert: g.cert.clone(),
        issuer: None,
        group_ca: g.root.clone(),
        roots: Vec::new(),
    };
    let admitter = Admitter { identity, ca: g.root.clone(), ca_key: root_key, make_admins: false };
    assert!(admitter.is_root());
    let mut rs = g.records;
    let joiner = Joiner::new("router").unwrap();
    let code = pair::new_code();
    let mut joining = Attempt::listening(&joiner, &code, &clock()).unwrap();
    let mut adm =
        Admission::dial(admitter.clone(), GroupView::of(&rs), &code, &joiner.fingerprint(), &clock()).unwrap();
    let (admitted, joined, member_err, joiner_err, _) = run(&mut adm, &mut joining);
    assert!(member_err.is_none() && joiner_err.is_none(), "{member_err:?} {joiner_err:?}");
    assert!(joined.is_some());
    let r = device_record(&rs, &admitter, &admitted.unwrap(), now_ms()).unwrap();
    assert!(rs.add(&r).unwrap());
    assert_eq!(rs.devices().len(), 2);
}
