// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Whole pairing sessions of 0.6, both ends driven by `join::session`:
//! at home with both persons' answers, by an invitation, and the ways a
//! session ends early.

use super::*;
use crate::join::session::{Adb, Joined, JoinerSession, MemberSession, error_frame};

const NOW: u64 = 1_793_000_000_000;

fn exporter(name: &str) -> PairExporter {
    PairExporter::for_tests(sha256(name.as_bytes()))
}

/// The admin laptop of G, as message 65 names it.
fn adb(g: &G) -> Adb {
    Adb { group: format::DeviceId(g.gid.0), device: fhash(&k("laptop")).id(), name: "laptop".into() }
}

type Ends = (invitation::JoinerAttempts, JoinerSession, MemberSession, Vec<u8>);

/// Both ends of one session, the joiner `tv` and the laptop, and message 64.
fn begin(g: &G, invitation: Option<Invitation>) -> Ends {
    let mut attempts = invitation::JoinerAttempts::default();
    let (j, m64) = JoinerSession::start(
        &mut attempts,
        info("tv", ROLE_MEMBER),
        invitation,
        Joining::Ordinary,
        point(&k("tv")),
        point(&k("laptop")),
        exporter("session"),
    )
    .unwrap();
    let m = MemberSession::new(point(&k("laptop")), point(&k("tv")), adb(g), exporter("session"));
    (attempts, j, m, m64)
}

/// A session at home up to message 66 taken: both ends show their code.
fn shown(g: &G) -> Ends {
    let (mut attempts, mut j, mut m, m64) = begin(g, None);
    let m65 = m.start_home(&m64).unwrap();
    let r = j.reply(&mut attempts, &m65).unwrap();
    let c = m.confirm(&r.send, None, NOW).unwrap();
    assert_eq!(c.code, r.code);
    (attempts, j, m, r.send)
}

/// The laptop's admin key admits tv: the Welcome and its set.
fn admitted(g: &mut G) -> (Welcome, RecordSet) {
    let st = g.state();
    let own = st.device_by_key(&k("laptop").hash).cloned();
    let d = joiner_record_any(
        &st,
        Signer::Admin,
        own.as_ref(),
        &point(&k("tv")),
        &info("tv", ROLE_MEMBER),
        Checked::default(),
        Choice { rights: RIGHT_READ | RIGHT_SEND, ..Choice::default() },
    )
    .unwrap();
    g.rec(&k("laptop admin"), Kind::device(d));
    let set = g.set();
    let (w, parts) = Welcome::build(&set, &set.state(), &k("laptop").hash, &k("tv").hash, NOW).unwrap();
    assert!(parts.is_empty());
    (w, set)
}

fn open(inv: &Invitation) -> Open {
    Open {
        invitation: inv.clone(),
        name: "tv".into(),
        created_ms: NOW - 1000,
        expires_ms: NOW + 600_000,
        used: false,
        failures: 0,
        allowed_key: None,
        attempt: None,
        next_attempt: 0,
    }
}

#[test]
fn a_pairing_at_home_takes_both_answers() {
    let mut g = G::new();
    let (mut attempts, mut j, mut m, m64) = begin(&g, None);
    let m65 = m.start_home(&m64).unwrap();
    assert_eq!(m.info().map(|i| i.name.as_str()), Some("tv"));
    let r = j.reply(&mut attempts, &m65).unwrap();
    assert_eq!(r.adb, adb(&g));
    let c = m.confirm(&r.send, None, NOW).unwrap();
    // Both ends show the same code, and both ask.
    assert!(r.code.is_some());
    assert_eq!(c.code, r.code);
    assert!(j.asks() && !m.approved());

    let (w, set) = admitted(&mut g);
    // No message 67 before the member's person answered.
    assert_eq!(m.welcome(&w, &[]).err(), Some(PairError::Refused));

    let (mut attempts, mut j, mut m, _) = shown(&g);
    m.answered(true).unwrap();
    assert!(m.approved());
    let frames = m.welcome(&w, &[]).unwrap();
    assert_eq!(frames.len(), 1);

    // The joiner takes no Welcome before its own person answered.
    let (_, mut early, mut em, _) = shown(&g);
    em.answered(true).unwrap();
    let f = em.welcome(&w, &[]).unwrap();
    assert_eq!(early.take(&f[0], NOW).err(), Some(PairError::Refused));

    j.answered(&mut attempts, true).unwrap();
    assert!(!j.asks());
    let Joined::Done(a) = j.take(&frames[0], NOW).unwrap() else { panic!("one message, no parts") };
    let (mine, state, send) = (a.set, a.state, a.send);
    assert_eq!(mine.digest(), set.digest());
    assert!(state.device_by_key(&k("tv").hash).is_some());
    m.done(&send, None, NOW).unwrap();
    assert_eq!(m.done(&send, None, NOW).err(), Some(PairError::Refused), "one end, once");
}

#[test]
fn either_person_can_decline_at_home() {
    let mut g = G::new();
    let (w, _) = admitted(&mut g);

    // The joiner's person: "they do not match".
    let (mut attempts, mut j, mut m, _) = shown(&g);
    assert_eq!(j.answered(&mut attempts, false), Err(PairError::Declined));
    m.answered(true).unwrap();
    let f = m.welcome(&w, &[]).unwrap();
    assert_eq!(j.take(&f[0], NOW).err(), Some(PairError::Refused), "the session is over");
    // The joiner may start again: its code is no longer showing.
    assert!(attempts.start().is_ok());

    // The member's person: message 69 tells the joiner why.
    let (mut attempts, mut j, mut m, _) = shown(&g);
    assert_eq!(m.answered(false), Err(PairError::Declined));
    assert_eq!(m.welcome(&w, &[]).err(), Some(PairError::Refused));
    j.answered(&mut attempts, true).unwrap();
    assert_eq!(j.take(&error_frame(PairError::Declined), NOW).err(), Some(PairError::Declined));
}

#[test]
fn a_pairing_by_an_invitation_needs_no_answer() {
    let mut g = G::new();
    let inv = invitation();
    let mut o = open(&inv);
    let (mut attempts, mut j, mut m, m64) = begin(&g, Some(inv.clone()));
    let m65 = m.start_invited(&mut o, Network::Guest, &m64, NOW).unwrap();
    let r = j.reply(&mut attempts, &m65).unwrap();
    assert!(r.code.is_none() && !j.asks());
    let c = m.confirm(&r.send, Some(&mut o), NOW).unwrap();
    assert!(c.code.is_none() && m.approved());
    assert_eq!(o.failures, 1, "an attempt counts until it ends welcomed");

    let (w, set) = admitted(&mut g);
    let frames = m.welcome(&w, &[]).unwrap();
    let Joined::Done(a) = j.take(&frames[0], NOW).unwrap() else { panic!("no parts") };
    let (mine, send) = (a.set, a.send);
    assert_eq!(mine.digest(), set.digest());
    m.done(&send, Some(&mut o), NOW).unwrap();
    assert!(o.used);
    assert_eq!(o.failures, 0);
    // One use.
    let (_, _, mut m, m64) = begin(&g, Some(inv));
    assert_eq!(m.start_invited(&mut o, Network::Guest, &m64, NOW).err(), Some(PairError::Closed));
}

#[test]
fn a_wrong_secret_ends_the_attempt() {
    let g = G::new();
    let inv = invitation();
    let mut o = open(&inv);
    let mut wrong = inv.clone();
    wrong.secret = [7; 32];
    let (mut attempts, mut j, mut m, m64) = begin(&g, Some(wrong));
    let m65 = m.start_invited(&mut o, Network::Guest, &m64, NOW).unwrap();
    let r = j.reply(&mut attempts, &m65).unwrap();
    assert_eq!(m.confirm(&r.send, Some(&mut o), NOW).err(), Some(PairError::WrongCode));
    assert!(!m.approved());
    assert!(o.attempt.is_none() && o.failures == 1, "the attempt ended and counts");
}

#[test]
fn a_session_refuses_what_does_not_fit() {
    let g = G::new();
    let inv = invitation();
    let mut o = open(&inv);
    // An invitation the member does not hold.
    let (_, _, mut m, m64) = begin(&g, Some(invitation()));
    assert_eq!(m.start_invited(&mut o, Network::Guest, &m64, NOW).err(), Some(PairError::Refused));
    // At home a joiner that names an invitation is refused.
    let (_, _, mut m, m64) = begin(&g, Some(inv.clone()));
    assert_eq!(m.start_home(&m64).err(), Some(PairError::Refused));
    // An invitation with the ID of none is no invitation.
    let mut none = inv.clone();
    none.id = NO_INVITATION;
    let mut attempts = invitation::JoinerAttempts::default();
    assert!(
        JoinerSession::start(
            &mut attempts,
            info("tv", ROLE_MEMBER),
            Some(none),
            Joining::Ordinary,
            point(&k("tv")),
            point(&k("laptop")),
            exporter("session"),
        )
        .is_err()
    );
    // Messages out of order, or of another type.
    let (mut attempts, mut j, mut m, m64) = begin(&g, None);
    assert_eq!(m.confirm(&m64, None, NOW).err(), Some(PairError::Refused));
    let (_, _, mut m, m64) = begin(&g, None);
    assert_eq!(j.reply(&mut attempts, &m64).err(), Some(PairError::Refused));
    m.start_home(&m64).unwrap();
    assert_eq!(m.start_home(&m64).err(), Some(PairError::Refused), "message 64 once");
    // Another session's exporter: the tags do not verify.
    let mut attempts = invitation::JoinerAttempts::default();
    let (mut j, m64) = JoinerSession::start(
        &mut attempts,
        info("tv", ROLE_MEMBER),
        None,
        Joining::Ordinary,
        point(&k("tv")),
        point(&k("laptop")),
        exporter("one session"),
    )
    .unwrap();
    let mut m = MemberSession::new(point(&k("laptop")), point(&k("tv")), adb(&g), exporter("another session"));
    let m65 = m.start_home(&m64).unwrap();
    let r = j.reply(&mut attempts, &m65).unwrap();
    assert_eq!(m.confirm(&r.send, None, NOW).err(), Some(PairError::WrongCode));
}

/// The member's end checks the admin key the joiner offers over its own
/// session's exporter: a proof over another session, or none, does not
/// hold.
#[test]
fn the_member_checks_an_offered_admin_key() {
    let g = G::new();
    let admin = k("tv admin");
    for (pop_over, holds) in [(Some("session"), true), (Some("another"), false), (None, false)] {
        let mut i = info("tv", ROLE_MEMBER);
        i.caps = CAP_ADMIN;
        if let Some(name) = pop_over {
            i.admin = Some(admin.key.public().to_vec());
            i.admin_pop = Some(sign_admin_pop(&admin, &exporter(name)).unwrap().to_vec());
        }
        let mut attempts = invitation::JoinerAttempts::default();
        let (_, m64) = JoinerSession::start(
            &mut attempts,
            i,
            None,
            Joining::Ordinary,
            point(&k("tv")),
            point(&k("laptop")),
            exporter("session"),
        )
        .unwrap();
        let mut m = MemberSession::new(point(&k("laptop")), point(&k("tv")), adb(&g), exporter("session"));
        assert!(!m.admin_pop_holds(), "before the Info comes");
        m.start_home(&m64).unwrap();
        assert_eq!(m.admin_pop_holds(), holds, "{pop_over:?}");
    }
}
