// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! A hub's registration against a forwarder in the same process
//! (nettest::forwarder): the claim, the hellos it sends, where the
//! forwarder saw it, the refusals, and the ways over VLESS when the
//! forwarder's port does not answer.

use std::net::{Ipv4Addr, TcpListener};

use super::*;
use crate::nettest::forwarder::{self as fake, Forwarder, MASK};
use crate::nettest::{Group, wait_for};

type Sent = Arc<Mutex<Vec<(SocketAddr, Vec<u8>)>>>;
type Logs = Arc<Mutex<Vec<String>>>;

fn config(g: &Group, endpoint: SocketAddr, pins: Vec<certs::KeyHash>) -> (Config, Sent) {
    let sent: Sent = Arc::new(Mutex::new(Vec::new()));
    let s = sent.clone();
    let cfg = Config {
        endpoint,
        pins,
        chain: g.chain(0),
        key: g.key(0),
        wg_key: crate::tunnel::new_key().unwrap().try_into().unwrap(),
        obfuscation: None,
        vless_id: None,
        records: Arc::new(Mutex::new(g.records_json())),
        send: Arc::new(move |to, b| s.lock().unwrap().push((to, b.to_vec()))),
        credential: None,
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

/// The hub registers with its member certificate and the records, proves
/// its WireGuard key, sends hellos for its registration that the
/// forwarder opens, and reports where the forwarder saw it.
#[test]
fn registers_and_says_hello() {
    let g = Group::new(1);
    let f = Forwarder::start(fake::welcome(), Some("203.0.113.9:51820"));
    let (cfg, sent) = config(&g, f.addr, vec![f.pin]);
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
    use base64::Engine;
    assert_eq!(claim["key"], base64::engine::general_purpose::STANDARD.encode(wg_public));
    assert_eq!(claim["records"].as_array().unwrap().len(), g.records.all().len());
    assert!(claim.get("vless").is_none() && claim.get("credentials").is_none());
    assert!(wait_for(Duration::from_secs(5), || !sent.lock().unwrap().is_empty()));
    let key = f.hello_keys.lock().unwrap()[0];
    let (to, p) = sent.lock().unwrap()[0].clone();
    assert_eq!(to, f.addr);
    let (id, counter) = open_hello(&p, &key);
    assert_eq!(id, 7);
    assert!(counter > 0);
    drop(r);
    assert!(logs.lock().unwrap().is_empty(), "{:?}", logs.lock().unwrap());
}

/// A forwarder's answers that end the registration: a refusal, no mask,
/// no VLESS settings for a hub that asked; and a forwarder of another
/// key. Each is reported and logged.
#[test]
fn refusals() {
    use base64::Engine;
    let mask = base64::engine::general_purpose::STANDARD.encode(MASK);
    let cases: Vec<(fake::AnswerFn, bool, &str)> = vec![
        (Arc::new(|_: &Value| serde_json::json!({"error": "not today"})), false, "refused the registration: not today"),
        (Arc::new(|_: &Value| serde_json::json!({"id": 1})), false, "no key for the hellos' mask"),
        (Arc::new(move |_: &Value| serde_json::json!({"id": 1, "mask": mask})), true, "it gave no VLESS settings"),
    ];
    for (answer, vless, want) in cases {
        let g = Group::new(1);
        let f = Forwarder::start(answer, None);
        let (mut cfg, _) = config(&g, f.addr, vec![f.pin]);
        if vless {
            cfg.vless_id = Some("6f1c2b9e-3d4a-4f5b-8c7d-0e1f2a3b4c5d".into());
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
    let g = Group::new(1);
    let f = Forwarder::start(fake::welcome(), None);
    let (cfg, _) = config(&g, f.addr, vec![[1; 32]]);
    let report = Arc::new(Mutex::new(Report::default()));
    let _r = Registration::start(cfg, report.clone(), Arc::new(|_| {}));
    assert!(wait_for(Duration::from_secs(20), || report.lock().unwrap().error.is_some()));
}

/// A hub with a VLESS user ID claims it and learns the forwarder's VLESS
/// settings, which its report carries as an offer does.
#[test]
fn learns_the_vless_settings() {
    let g = Group::new(1);
    let f = Forwarder::start(fake::welcome(), Some("203.0.113.9:51820"));
    let (mut cfg, _) = config(&g, f.addr, vec![f.pin]);
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
    assert_eq!(claim["vless"], id);
    assert!(claim["obfuscation"].is_object());
}

/// The forwarder's port does not answer: without a VLESS user ID or a way
/// in, that is the error; with them, each way over VLESS is tried and the
/// errors of all are said.
#[test]
fn the_ways_over_vless_when_the_port_is_closed() {
    let g = Group::new(1);
    let ln = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let closed = ln.local_addr().unwrap();
    drop(ln);
    let (cfg, _) = config(&g, closed, vec![[0; 32]]);
    let report = Arc::new(Mutex::new(Report::default()));
    let r = Registration::start(cfg, report.clone(), Arc::new(|_| {}));
    assert!(wait_for(Duration::from_secs(10), || report
        .lock()
        .unwrap()
        .error
        .as_deref()
        .is_some_and(|e| e.contains("reaching the forwarder"))));
    drop(r);

    let (mut cfg, _) = config(&g, closed, vec![[0; 32]]);
    cfg.vless_id = Some("6f1c2b9e-3d4a-4f5b-8c7d-0e1f2a3b4c5d".into());
    let r = Registration::start(cfg, report.clone(), Arc::new(|_| {}));
    std::thread::sleep(Duration::from_millis(300));
    drop(r);

    let site = crate::nettest::xhttp::Site::start(crate::nettest::xhttp::Knobs::default());
    let (mut cfg, _) = config(&g, closed, vec![[0; 32]]);
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

/// The offer from a forwarder's VLESS answer: the endpoint at the answer's
/// port, the server name and the ID, with the transport and the path only
/// when the answer gives them.
#[test]
fn offers_from_answers() {
    let at: SocketAddr = "192.0.2.7:4242".parse().unwrap();
    let v = vless_offer(
        at,
        "id",
        VlessAnswer { transport: String::new(), port: 443, server_name: "s".into(), path: String::new() },
    );
    assert_eq!(v["endpoint"], "192.0.2.7:443");
    assert_eq!(v["server_name"], "s");
    assert_eq!(v["id"], "id");
    assert!(v.get("transport").is_none() && v.get("path").is_none());
    let v = vless_offer(
        at,
        "id",
        VlessAnswer { transport: "xhttp".into(), port: 443, server_name: "s".into(), path: "/p".into() },
    );
    assert_eq!(v["transport"], "xhttp");
    assert_eq!(v["path"], "/p");
    assert!(prove(&[1; 32], &[0; 32], &[0; 32]).is_none(), "a low-order point");
    assert!(prove(&[1; 32], &[0; 3], &[0; 32]).is_none());
}

/// A hub with the period's hubs' credential registers with it and the
/// certificate of its server key, without its member certificate or the
/// records, and registers again when a newer credential comes.
#[test]
fn registers_with_a_credential() {
    let g = Group::new(1);
    let server = crate::nettest::new_key();
    let cert = certs::server_cert_by(&crate::identity::ExternalKey::public(&*server), &mut |tbs| {
        crate::identity::sign_external(&*server, tbs)
    })
    .unwrap();
    let first = g.period(std::slice::from_ref(&server), 1);
    let now: Arc<Mutex<Vec<cbb_core::credential::Credential>>> = Arc::new(Mutex::new(vec![first[1].clone()]));
    let f = Forwarder::start(fake::welcome(), None);
    let (mut cfg, _) = config(&g, f.addr, vec![f.pin]);
    let (n, key) = (now.clone(), server.clone());
    cfg.credential = Some(Arc::new(move || {
        Some(HubCredential { credentials: n.lock().unwrap().clone(), cert: cert.clone(), key: key.clone() })
    }));
    let report = Arc::new(Mutex::new(Report::default()));
    let (logs, log) = logger();
    let _r = Registration::start(cfg, report.clone(), log);
    assert!(wait_for(Duration::from_secs(20), || report.lock().unwrap().registered), "{:?}", report.lock().unwrap());
    let claim = &f.claims()[0];
    assert!(claim.get("records").is_none());
    assert_eq!(claim["credentials"].as_array().unwrap().len(), 1);
    assert!(logs.lock().unwrap().iter().any(|l| l.contains("hubs' credential")));
    *now.lock().unwrap() = vec![g.period(&[server], 2)[1].clone()];
    assert!(wait_for(Duration::from_secs(20), || f.claims().len() >= 2), "no second registration");
}
