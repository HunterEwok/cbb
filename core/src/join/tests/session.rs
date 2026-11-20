// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Whole pairing sessions of 0.6, both ends driven by `join::session`: at
//! a home window by its six digits, by a QR code's invitation, and the
//! ways a session ends early.

use super::*;
use crate::format::grant::Kept;
use crate::join::invitation::Proven;
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

/// Both ends of one session over `ex`, the joiner `tv` by `invitation` and
/// the laptop, and message 64.
fn begin_over(g: &G, invitation: Invitation, ex: &str) -> Ends {
    let mut attempts = invitation::JoinerAttempts::default();
    let (j, m64) = JoinerSession::start(
        &mut attempts,
        info("tv", ROLE_MEMBER),
        invitation,
        Joining::Ordinary,
        point(&k("tv")),
        point(&k("laptop")),
        exporter(ex),
    )
    .unwrap();
    let m = MemberSession::new(point(&k("laptop")), point(&k("tv")), adb(g), exporter(ex));
    (attempts, j, m, m64)
}

fn begin(g: &G, invitation: Invitation) -> Ends {
    begin_over(g, invitation, "session")
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

/// One whole session by `joiner_inv` against the window `o`, over the
/// exporter `ex`, with the Welcome `w`: the joiner's end once it took the
/// Welcome, or the step's error.
fn pair(g: &G, o: &mut Open, joiner_inv: Invitation, ex: &str, w: &Welcome) -> Result<JoinerSession, PairError> {
    let (_, mut j, mut m, m64) = begin_over(g, joiner_inv, ex);
    let m65 = m.start_invited(o, Network::Home, &m64, NOW)?;
    let r = j.reply(&m65)?;
    m.confirm(&r.send, o, NOW)?;
    let frames = m.welcome(w, &[])?;
    let Joined::Done(a) = j.take(&frames[0], NOW)? else { panic!("no parts") };
    m.done(&a.send, o, NOW)?;
    Ok(j)
}

/// A home window: the joiner types its six digits (or scans its QR code,
/// which carries them with the ID), both ends hold one secret, and the
/// session runs as by any invitation, with no question to either person.
/// The window closes after one success.
#[test]
fn a_home_window_pairs_by_its_six_digits() {
    let mut g = G::new();
    let (window, digits) = Invitation::home();
    assert!(window.profile.home_only);
    let typed = Invitation::typed(window.id, &digits).unwrap();
    assert_eq!(typed, window, "the joiner's invitation is the window's");
    let mut o = open(&window);
    let (_, mut j, mut m, m64) = begin(&g, typed.clone());
    let m65 = m.start_invited(&mut o, Network::Home, &m64, NOW).unwrap();
    assert_eq!(m.info().and_then(|i| i.invite), Some(window.id));
    let r = j.reply(&m65).unwrap();
    assert_eq!(r.adb, adb(&g));
    assert!(!m.approved());
    m.confirm(&r.send, &mut o, NOW).unwrap();
    assert!(m.approved(), "the joiner's Ta under the window's secret approves");
    assert_eq!(o.failures, 1, "an attempt counts until it ends welcomed");
    assert!(j.proven().is_none(), "nothing proven before the member's Tb");

    let (w, set) = admitted(&mut g);
    let frames = m.welcome(&w, &[]).unwrap();
    assert_eq!(frames.len(), 1);
    let Joined::Done(a) = j.take(&frames[0], NOW).unwrap() else { panic!("one message, no parts") };
    let (mine, state, send) = (a.set, a.state, a.send);
    assert_eq!(mine.digest(), set.digest());
    assert!(state.device_by_key(&k("tv").hash).is_some());
    m.done(&send, &mut o, NOW).unwrap();
    assert_eq!(m.done(&send, &mut o, NOW).err(), Some(PairError::Refused), "one end, once");
    assert!(o.used && o.failures == 0);
    // The window is closed: even its own digits start nothing more.
    assert_eq!(pair(&g, &mut o, typed, "again", &w).err(), Some(PairError::Closed));
}

/// Wrong digits: the member's end finds the joiner's Ta wrong, sends no
/// Welcome and writes nothing, and the attempt counts. The third failure
/// closes the window, even to the right digits.
#[test]
fn wrong_digits_count_and_the_third_closes_the_window() {
    let mut g = G::new();
    let (w, _) = admitted(&mut g);
    let (window, digits) = Invitation::home();
    let wrong = if digits == "000000" { "000001" } else { "000000" };
    let mut o = open(&window);
    for n in 1..=invitation::MAX_FAILURES {
        let (_, mut j, mut m, m64) = begin(&g, Invitation::typed(window.id, wrong).unwrap());
        let m65 = m.start_invited(&mut o, Network::Home, &m64, NOW).unwrap();
        let r = j.reply(&m65).unwrap();
        assert_eq!(m.confirm(&r.send, &mut o, NOW).err(), Some(PairError::WrongCode));
        assert!(!m.approved());
        assert_eq!(m.welcome(&w, &[]).err(), Some(PairError::Refused), "no Welcome, nothing written");
        assert!(o.attempt.is_none(), "the attempt ended");
        assert_eq!(o.failures, n);
    }
    let right = Invitation::typed(window.id, &digits).unwrap();
    assert_eq!(pair(&g, &mut o, right, "late", &w).err(), Some(PairError::TooMany));
}

/// One attempt at a time: while one runs, another joiner is busy; a joiner
/// that walks away mid-session spends a failure once its time is over.
#[test]
fn a_window_takes_one_attempt_at_a_time() {
    let g = G::new();
    let (window, digits) = Invitation::home();
    let mut o = open(&window);
    let typed = || Invitation::typed(window.id, &digits).unwrap();
    let (_, _, mut first, m64) = begin(&g, typed());
    first.start_invited(&mut o, Network::Home, &m64, NOW).unwrap();
    let (_, _, mut second, m64) = begin_over(&g, typed(), "second");
    assert_eq!(second.start_invited(&mut o, Network::Home, &m64, NOW + 1).err(), Some(PairError::Busy));
    // The first joiner went away: after its time another may start, and
    // the first one's attempt stays counted.
    let (_, _, mut third, m64) = begin_over(&g, typed(), "third");
    third.start_invited(&mut o, Network::Home, &m64, NOW + invitation::ATTEMPT_MS).unwrap();
    assert_eq!(o.failures, 2);
    // A home window takes no joiner from a guest path.
    let mut o = open(&window);
    let (_, _, mut m, m64) = begin(&g, typed());
    assert_eq!(m.start_invited(&mut o, Network::Guest, &m64, NOW).err(), Some(PairError::Refused));
}

/// A QR code's invitation away from home: the same session, and no proof
/// of the member for a guarded leaf, which only a home window gives.
#[test]
fn a_pairing_by_a_qr_invitation_proves_nothing_for_a_leaf() {
    let mut g = G::new();
    let inv = invitation();
    assert!(!inv.profile.home_only);
    let mut o = open(&inv);
    let (_, mut j, mut m, m64) = begin(&g, inv.clone());
    let m65 = m.start_invited(&mut o, Network::Guest, &m64, NOW).unwrap();
    let r = j.reply(&m65).unwrap();
    m.confirm(&r.send, &mut o, NOW).unwrap();
    let (w, set) = admitted(&mut g);
    let frames = m.welcome(&w, &[]).unwrap();
    let Joined::Done(a) = j.take(&frames[0], NOW).unwrap() else { panic!("no parts") };
    assert_eq!(a.set.digest(), set.digest());
    assert!(j.proven().is_none(), "a Proven comes only from a home window");
    m.done(&a.send, &mut o, NOW).unwrap();
    assert!(o.used);
}

/// A home window's session proves the member to the joiner once its Tb
/// verified, for that session and that member alone: a guarded leaf's
/// binding comes from it in that session only (`grant::read_bound` checks
/// the session the grant arrives on), once, and none for a leaf that
/// waits for nothing.
#[test]
fn only_a_home_windows_own_session_proves_the_member() {
    let mut g = G::new();
    let (w, _) = admitted(&mut g);
    let (window, digits) = Invitation::home();
    let typed = || Invitation::typed(window.id, &digits).unwrap();
    let proven = |ex: &str| -> Proven {
        let mut o = open(&window);
        let mut j = pair(&g, &mut o, typed(), ex, &w).unwrap();
        let p = j.proven().expect("a home window's session proves the member");
        assert!(j.proven().is_none(), "given once");
        p
    };
    let p = proven("session a");
    assert!(p.to(&point(&k("laptop"))) && !p.to(&point(&k("phone"))));
    let lock = k("tv").key.device_id();
    let waiting = Kept { guarded: true, ..Kept::default() }.changed(k("new root").hash, 1);
    // In its own session: the binding the leaf's own state names.
    let b = proven("session a").binding(&waiting, None, &exporter("session a")).unwrap();
    assert_eq!(
        b,
        crate::format::grant::Binding::matched(
            &waiting,
            None,
            lock,
            format::grant::session_mark(exporter("session a").bytes())
        )
        .unwrap()
    );
    // From session a, offered in session b: nothing.
    assert!(proven("session a").binding(&waiting, None, &exporter("session b")).is_none());
    // A leaf that waits for no binding gets none.
    assert!(p.binding(&Kept::default(), None, &exporter("session a")).is_none());
}

#[test]
fn a_session_refuses_what_does_not_fit() {
    let g = G::new();
    let inv = invitation();
    let mut o = open(&inv);
    // An invitation the member does not hold.
    let (_, _, mut m, m64) = begin(&g, invitation());
    assert_eq!(m.start_invited(&mut o, Network::Guest, &m64, NOW).err(), Some(PairError::Refused));
    assert_eq!(o.failures, 0, "a joiner of another invitation spends nothing");
    // An invitation with an ID of zero bytes is no invitation.
    let mut none = inv.clone();
    none.id = [0; 16];
    let mut attempts = invitation::JoinerAttempts::default();
    assert!(
        JoinerSession::start(
            &mut attempts,
            info("tv", ROLE_MEMBER),
            none,
            Joining::Ordinary,
            point(&k("tv")),
            point(&k("laptop")),
            exporter("session"),
        )
        .is_err()
    );
    // Messages out of order, or of another type.
    let (_, mut j, mut m, m64) = begin(&g, inv.clone());
    assert_eq!(m.confirm(&m64, &mut o, NOW).err(), Some(PairError::Refused));
    let (_, _, mut m, m64) = begin(&g, inv.clone());
    assert_eq!(j.reply(&m64).err(), Some(PairError::Refused));
    m.start_invited(&mut o, Network::Guest, &m64, NOW).unwrap();
    assert_eq!(m.start_invited(&mut o, Network::Guest, &m64, NOW).err(), Some(PairError::Refused), "message 64 once");
    // Message 69 tells the joiner why the member ended the session.
    let (_, mut j, mut m, m64) = begin(&g, inv.clone());
    let mut o = open(&inv);
    let m65 = m.start_invited(&mut o, Network::Guest, &m64, NOW).unwrap();
    j.reply(&m65).unwrap();
    assert_eq!(j.take(&error_frame(PairError::TooMany), NOW).err(), Some(PairError::TooMany));
    // Another session's exporter: the tags do not verify.
    let mut attempts = invitation::JoinerAttempts::default();
    let (mut j, m64) = JoinerSession::start(
        &mut attempts,
        info("tv", ROLE_MEMBER),
        inv.clone(),
        Joining::Ordinary,
        point(&k("tv")),
        point(&k("laptop")),
        exporter("one session"),
    )
    .unwrap();
    let mut o = open(&inv);
    let mut m = MemberSession::new(point(&k("laptop")), point(&k("tv")), adb(&g), exporter("another session"));
    let m65 = m.start_invited(&mut o, Network::Guest, &m64, NOW).unwrap();
    let r = j.reply(&m65).unwrap();
    assert_eq!(m.confirm(&r.send, &mut o, NOW).err(), Some(PairError::WrongCode));
}

/// The member's end checks the admin key the joiner offers over its own
/// session's exporter: a proof over another session, or none, does not
/// hold.
#[test]
fn the_member_checks_an_offered_admin_key() {
    let g = G::new();
    let admin = k("tv admin");
    let inv = invitation();
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
            inv.clone(),
            Joining::Ordinary,
            point(&k("tv")),
            point(&k("laptop")),
            exporter("session"),
        )
        .unwrap();
        let mut m = MemberSession::new(point(&k("laptop")), point(&k("tv")), adb(&g), exporter("session"));
        assert!(!m.admin_pop_holds(), "before the Info comes");
        let mut o = open(&inv);
        m.start_invited(&mut o, Network::Guest, &m64, NOW).unwrap();
        assert_eq!(m.admin_pop_holds(), holds, "{pop_over:?}");
    }
}
