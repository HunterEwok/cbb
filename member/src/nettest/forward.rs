// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! A hub's registration of 0.6 (`cbb-forward/3`) against a forwarder in
//! the same process (nettest::forwarder), with the credentials of a group
//! of 0.6 made in memory (nettest::blind): the registration, the hellos it
//! sends, where the forwarder saw it, the refusals, and the ways over
//! VLESS when the forwarder's port does not answer.

use std::net::{Ipv4Addr, TcpListener};

use super::*;
use crate::nettest::blind::Blind;
use crate::nettest::forwarder::{self as fake, Answer, Forwarder, MASK};
use crate::nettest::wait_for;
use v3::Register;

type Sent = Arc<Mutex<Vec<(SocketAddr, Vec<u8>)>>>;
type Logs = Arc<Mutex<Vec<String>>>;

/// The hub's credential, fixed.
fn fixed(c: HubCredential) -> Option<CredentialFn> {
    Some(Arc::new(move || Some(c.clone())))
}

/// A hub of a group of one device, listed in its hubs' credential.
fn config(endpoint: SocketAddr, pins: Vec<certs::KeyHash>) -> (Config, Sent) {
    let g = Blind::new(1);
    let sent: Sent = Arc::new(Mutex::new(Vec::new()));
    let s = sent.clone();
    let cfg = Config {
        endpoint,
        pins,
        wg_key: crate::tunnel::new_key().unwrap().try_into().unwrap(),
        obfuscation: None,
        vless_id: None,
        send: Arc::new(move |to, b| s.lock().unwrap().push((to, b.to_vec()))),
        credential: fixed(g.hub_credential(0, 1, &[0])),
        ways: Arc::new(Mutex::new(Ways::default())),
        learned: Arc::new(Mutex::new(None)),
    };
    (cfg, sent)
}

type Log = Arc<dyn Fn(&str) + Send + Sync>;

fn logger() -> (Logs, Log) {
    let logs: Logs = Arc::new(Mutex::new(Vec::new()));
    let l = logs.clone();
    (logs, Arc::new(move |s: &str| l.lock().unwrap().push(s.to_string())))
}

/// Opens a hello as the forwarder does: the registration's ID and counter,
/// and the MAC under its hello key.
fn open_hello(p: &[u8], key: &[u8; 32]) -> (u64, u64) {
    let mut h = p[NONCE..NONCE + HELLO].to_vec();
    let nonce: &[u8; NONCE] = p[..NONCE].try_into().unwrap();
    ChaCha20::new((&MASK).into(), nonce.into()).apply_keystream(&mut h);
    assert_eq!(h[..4], [MSG_HELLO, 0, 0, 0]);
    let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(key).unwrap();
    m.update(&h[..20]);
    assert_eq!(h[20..], m.finalize().into_bytes()[..16], "the hello's MAC");
    (u64::from_be_bytes(h[4..12].try_into().unwrap()), u64::from_be_bytes(h[12..20].try_into().unwrap()))
}

/// The hub registers with the certificate of its server key alone and
/// the face's period and hubs' credentials, proves its WireGuard key,
/// sends hellos for its registration that the forwarder opens, and
/// reports where the forwarder saw it.
#[test]
fn registers_and_says_hello() {
    let f = Forwarder::start(fake::welcome(), Some("203.0.113.9:51820"));
    let (cfg, sent) = config(f.addr, vec![f.pin]);
    let shown = cfg.credential.as_ref().unwrap()().unwrap();
    let wg_public = *PublicKey::from(&StaticSecret::from(cfg.wg_key)).as_bytes();
    let report = Arc::new(Mutex::new(Report::default()));
    let (logs, log) = logger();
    let r = Registration::start(cfg, report.clone(), log);
    assert!(
        wait_for(Duration::from_secs(20), || report.lock().unwrap().seen.as_deref() == Some("203.0.113.9:51820")),
        "{:?} {:?}",
        report.lock().unwrap(),
        logs.lock().unwrap()
    );
    assert!(report.lock().unwrap().registered);
    let claim = &f.claims()[0];
    assert_eq!(claim.certs, vec![shown.cert.clone()], "the server key's certificate alone");
    assert_eq!(claim.register.key, wg_public);
    assert_eq!(claim.register.credentials, shown.credentials);
    assert!(claim.register.vless.is_none() && claim.register.obfuscation.is_none());
    assert!(wait_for(Duration::from_secs(5), || !sent.lock().unwrap().is_empty()));
    let key = f.hello_keys.lock().unwrap()[0];
    let (to, p) = sent.lock().unwrap()[0].clone();
    assert_eq!(to, f.addr);
    let (id, counter) = open_hello(&p, &key);
    assert_eq!(id, 7);
    assert!(counter > 0);
    drop(r);
    let logs = logs.lock().unwrap();
    assert!(logs.iter().all(|l| l.contains("registered with the forwarder")), "{logs:?}");
}

/// A registration that ends: the forwarder refuses it, answers without a
/// mask, or has another key; the hub's server key is not on the hubs'
/// credential it shows; the hub has no credential for the forwarder's face
/// yet, and waits without dialing. Each is reported and logged. A
/// forwarder without VLESS registers a hub that asked for UDP alone.
#[test]
fn refusals() {
    use cbb_core::format::cbor::Value as V;
    let no_mask = cbb_core::format::frame::write(&V::Map(vec![
        (cbb_core::format::frame::FIELD_T, V::Uint(cbb_core::msg::tables::T_FWD_REGISTERED)),
        (2, V::Uint(1)),
    ]));
    let cases: Vec<(fake::AnswerFn, bool, &str)> = vec![
        (Arc::new(|_: &Register| Answer::Refused("not today".into())), true, "refused the registration: not today"),
        (Arc::new(move |_: &Register| Answer::Raw(no_mask.clone())), true, "the forwarder's message breaks"),
        (fake::welcome(), false, "does not list this hub"),
    ];
    for (answer, listed, want) in cases {
        let f = Forwarder::start(answer, None);
        let (mut cfg, _) = config(f.addr, vec![f.pin]);
        if !listed {
            cfg.credential = fixed(Blind::new(2).hub_credential(0, 1, &[1]));
        }
        let report = Arc::new(Mutex::new(Report { seen: Some("kept".into()), ..Report::default() }));
        let (logs, log) = logger();
        let r = Registration::start(cfg, report.clone(), log);
        assert!(
            wait_for(Duration::from_secs(20), || report
                .lock()
                .unwrap()
                .error
                .as_deref()
                .is_some_and(|e| e.contains(want))),
            "{want}: {:?}",
            report.lock().unwrap()
        );
        assert_eq!(report.lock().unwrap().seen.as_deref(), Some("kept"), "a failure keeps where it was seen");
        assert!(logs.lock().unwrap().iter().any(|l| l.contains(want)));
        drop(r);
    }
    let f = Forwarder::start(fake::welcome(), None);
    let (mut cfg, _) = config(f.addr, vec![f.pin]);
    cfg.credential = None;
    let report = Arc::new(Mutex::new(Report::default()));
    let r = Registration::start(cfg, report.clone(), Arc::new(|_| {}));
    assert!(wait_for(Duration::from_secs(20), || report
        .lock()
        .unwrap()
        .error
        .as_deref()
        .is_some_and(|e| e.contains(NOT_LISTED))));
    assert!(f.claims().is_empty() && f.hello_keys.lock().unwrap().is_empty(), "no credential, no dial");
    drop(r);
    let f = Forwarder::start(Arc::new(|_: &Register| Answer::Registered(fake_registered(None))), None);
    let (mut cfg, _) = config(f.addr, vec![f.pin]);
    cfg.vless_id = Some("6f1c2b9e-3d4a-4f5b-8c7d-0e1f2a3b4c5d".into());
    let report = Arc::new(Mutex::new(Report::default()));
    let r = Registration::start(cfg, report.clone(), Arc::new(|_| {}));
    assert!(wait_for(Duration::from_secs(20), || report.lock().unwrap().registered), "{:?}", report.lock().unwrap());
    let rep = report.lock().unwrap().clone();
    assert!(rep.vless.is_none() && rep.error.is_none(), "UDP alone: {rep:?}");
    drop(r);
    let f = Forwarder::start(fake::welcome(), None);
    let (cfg, _) = config(f.addr, vec![[1; 32]]);
    let report = Arc::new(Mutex::new(Report::default()));
    let _r = Registration::start(cfg, report.clone(), Arc::new(|_| {}));
    assert!(wait_for(Duration::from_secs(20), || report.lock().unwrap().error.is_some()));
}

fn fake_registered(vless: Option<v3::Way>) -> v3::Registered {
    v3::Registered { id: 1, mask: MASK, vless }
}

/// A hub with a VLESS user ID claims it and learns the forwarder's VLESS
/// settings, which its report carries as an offer does.
#[test]
fn learns_the_vless_settings() {
    let f = Forwarder::start(fake::welcome(), Some("203.0.113.9:51820"));
    let (mut cfg, _) = config(f.addr, vec![f.pin]);
    let id = "6f1c2b9e-3d4a-4f5b-8c7d-0e1f2a3b4c5d";
    cfg.vless_id = Some(id.into());
    cfg.obfuscation = Some(crate::awg::Obfuscation::random().unwrap().to_value());
    let learned = cfg.learned.clone();
    let report = Arc::new(Mutex::new(Report::default()));
    let _r = Registration::start(cfg, report.clone(), Arc::new(|_| {}));
    assert!(wait_for(Duration::from_secs(20), || report.lock().unwrap().seen.is_some()));
    let v = report.lock().unwrap().vless.clone().unwrap();
    assert_eq!(v["endpoint"], "127.0.0.1:8443");
    assert_eq!(v["id"], id);
    assert_eq!(v["transport"], "xhttp");
    assert_eq!(learned.lock().unwrap().as_ref(), Some(&v));
    let claim = &f.claims()[0];
    assert_eq!(claim.register.vless, Some(cbb_core::vless::parse_id(id).unwrap()));
    assert!(claim.register.obfuscation.is_some());
}

/// The forwarder's port does not answer: without a VLESS user ID or a way
/// in, that is the error; with them, each way over VLESS is tried and the
/// errors of all are said.
#[test]
fn the_ways_over_vless_when_the_port_is_closed() {
    let ln = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let closed = ln.local_addr().unwrap();
    drop(ln);
    let (cfg, _) = config(closed, vec![[0; 32]]);
    let report = Arc::new(Mutex::new(Report::default()));
    let r = Registration::start(cfg, report.clone(), Arc::new(|_| {}));
    assert!(wait_for(Duration::from_secs(10), || report
        .lock()
        .unwrap()
        .error
        .as_deref()
        .is_some_and(|e| e.contains("reaching the forwarder"))));
    drop(r);

    let (mut cfg, _) = config(closed, vec![[0; 32]]);
    cfg.vless_id = Some("6f1c2b9e-3d4a-4f5b-8c7d-0e1f2a3b4c5d".into());
    let r = Registration::start(cfg, report.clone(), Arc::new(|_| {}));
    std::thread::sleep(Duration::from_millis(300));
    drop(r);

    let site = crate::nettest::xhttp::Site::start(crate::nettest::xhttp::Knobs::default());
    let (mut cfg, _) = config(closed, vec![[0; 32]]);
    cfg.vless_id = Some("6f1c2b9e-3d4a-4f5b-8c7d-0e1f2a3b4c5d".into());
    *cfg.learned.lock().unwrap() = Some(site.offer("6f1c2b9e-3d4a-4f5b-8c7d-0e1f2a3b4c5d"));
    let report = Arc::new(Mutex::new(Report::default()));
    let _r = Registration::start(cfg, report.clone(), Arc::new(|_| {}));
    assert!(
        wait_for(Duration::from_secs(30), || report
            .lock()
            .unwrap()
            .error
            .as_deref()
            .is_some_and(|e| e.contains("over VLESS"))),
        "{:?}",
        report.lock().unwrap()
    );
}

/// The offer from a forwarder's VLESS answer: XHTTP at the forwarder's
/// address on the answer's port (443 when it names none), the server name
/// and the ID, with the path only when the answer gives one.
#[test]
fn offers_from_answers() {
    let at: SocketAddr = "192.0.2.7:4242".parse().unwrap();
    let v = vless_offer(at, "id", v3::Way { user: [0; 16], port: None, host: "s".into(), path: String::new() });
    assert_eq!(v["endpoint"], "192.0.2.7:443");
    assert_eq!(v["server_name"], "s");
    assert_eq!(v["id"], "id");
    assert_eq!(v["transport"], "xhttp");
    assert!(v.get("path").is_none());
    let v = vless_offer(at, "id", v3::Way { user: [0; 16], port: Some(8443), host: "s".into(), path: "/p".into() });
    assert_eq!(v["endpoint"], "192.0.2.7:8443");
    assert_eq!(v["path"], "/p");
    assert!(prove(&[1; 32], &[0; 32], &[0; 32]).is_none(), "a low-order point");
    assert!(prove(&[1; 32], &[0; 3], &[0; 32]).is_none());
}

/// A hub registers with the credential it has at each registration, and
/// registers again when a newer hubs' credential comes.
#[test]
fn registers_with_a_credential() {
    let g = Blind::new(1);
    let now = Arc::new(Mutex::new(g.hub_credential(0, 1, &[0])));
    let f = Forwarder::start(fake::welcome(), None);
    let (mut cfg, _) = config(f.addr, vec![f.pin]);
    let n = now.clone();
    cfg.credential = Some(Arc::new(move || Some(n.lock().unwrap().clone())));
    let report = Arc::new(Mutex::new(Report::default()));
    let (logs, log) = logger();
    let _r = Registration::start(cfg, report.clone(), log);
    assert!(wait_for(Duration::from_secs(20), || report.lock().unwrap().registered), "{:?}", report.lock().unwrap());
    assert_eq!(f.claims()[0].register.credentials, now.lock().unwrap().credentials);
    assert!(logs.lock().unwrap().iter().any(|l| l.contains("hubs' credential")));
    let second = g.hub_credential(0, 2, &[0]);
    *now.lock().unwrap() = second.clone();
    assert!(wait_for(Duration::from_secs(20), || f.claims().len() >= 2), "no second registration");
    assert_eq!(f.claims()[1].register.credentials, second.credentials);
}
