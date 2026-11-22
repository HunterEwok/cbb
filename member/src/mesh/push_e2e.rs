// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The push sender wired to the mesh, end to end (`crate::pusher`, "Required
//! test"): real members of a group of 0.6, the group's face toward a push
//! service that keys.json names, and that service (`crate::pushd`) with a
//! platform that keeps what it is handed. The device that registers is a
//! member of its own here; the phones' app registers the same message once
//! the phones run on the records of 0.6 (D-122), when the test with
//! `phone-on-linux` follows.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use super::push;
use cbb_core::identity::ExternalKey as _;
use cbb_core::push::{self as core_push, Body, Registration};
use cbb_core::records::body::{self, Device};
use cbb_core::records::{Kind, Recovery, key::ALG_SLH_DSA, pq};
use cbb_core::release::testing::TestKey;
use p256::ecdsa::SigningKey;

use super::tests::{own, root};
use super::*;
use crate::pushd::{Budgets, Config, Delivery, Outcome, Platform, Service};

/// A platform that keeps each body it is handed.
#[derive(Default)]
struct Kept(Mutex<Vec<Vec<u8>>>);

impl Platform for Kept {
    fn send(&self, d: &Delivery<'_>) -> Outcome {
        if let Some(b) = d.body {
            self.0.lock().unwrap().push(b.to_vec());
        }
        Outcome::Sent
    }
}

impl Kept {
    fn len(&self) -> usize {
        self.0.lock().unwrap().len()
    }

    fn get(&self, i: usize) -> Vec<u8> {
        self.0.lock().unwrap()[i].clone()
    }
}

fn temp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("cbb-push-e2e-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// The group: a, its hub (the root's hubs record names it), b, the device
/// that registers, and c, a member that is no hub. All may read copies.
fn group() -> [PathBuf; 3] {
    let dirs = [temp("a"), temp("b"), temp("c")];
    let owns: Vec<Own> = dirs.iter().map(|d| own(d)).collect();
    let root = root();
    let (k1, k2) = pq::recovery_keys(&[1; 32]).unwrap();
    let k1 = SigningKey::from(&k1).verifying_key().to_sec1_point(false).as_bytes().to_vec();
    let mut set = RecordSet::new(
        Key::es256(root.public()),
        Recovery::new(Key::es256(k1), Key::new(ALG_SLH_DSA, k2.public())).unwrap(),
    );
    let now = crate::uptime::wall_ms() as u64;
    for (o, name) in owns.iter().zip(["a", "b", "c"]) {
        let mut d = Device::new(o.member_key(), name, body::ROLE_MEMBER);
        d.rights = body::RIGHT_READ | body::RIGHT_SEND | body::RIGHT_SECRETS;
        if name == "a" {
            d.rights |= body::RIGHT_HUB;
        }
        let st = set.state();
        set.write_record(&st, &root, Kind::device(d), now - 1000).unwrap();
    }
    crate::writers::set_hubs(&mut set, &root, &["a".to_string()], now - 900).unwrap();
    for d in &dirs {
        let local = crate::set::local_key(d).unwrap();
        crate::set::save(d, &set, &local).unwrap();
    }
    dirs
}

/// Connects b to a over loopback, as the mesh's tests do.
fn connect(a: &Arc<Mesh>, b: &Arc<Mesh>) {
    let ln = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = ln.local_addr().unwrap();
    let a2 = a.clone();
    std::thread::spawn(move || {
        let (sock, _) = ln.accept().unwrap();
        let _ = a2.accept(sock);
    });
    let (b2, ad) = (b.clone(), a.device());
    std::thread::spawn(move || {
        let _ = b2.dial(addr, Some(ad));
    });
}

fn until(what: &str, secs: u64, f: impl Fn() -> bool) {
    let end = Instant::now() + Duration::from_secs(secs);
    while !f() {
        assert!(Instant::now() < end, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// keys.json naming the push service by its certificate's key, and an
/// entries.json, signed under the test root `root`, as message `entries`
/// carries them.
fn entry_points(root: &TestKey, release: &TestKey, spki: &[u8]) -> Box<serde_json::value::RawValue> {
    let at = crate::uptime::wall_ms() - 1000;
    let mut keys = release.keys("release key", "");
    keys.push(cbb_core::release::Key {
        alg: cbb_core::release::ALG_ES256,
        key: spki.to_vec(),
        name: crate::pusher::SERVICE.into(),
        usage: "push".into(),
    });
    let sign =
        |k: &TestKey, v: serde_json::Value| serde_json::to_string(&k.sign(&serde_json::to_vec(&v).unwrap())).unwrap();
    let keys = sign(
        root,
        serde_json::json!({"v": 1, "type": "keys", "seq": 1, "time_ms": at, "expires_ms": at + 86_400_000, "keys": keys}),
    );
    let entries = sign(
        release,
        serde_json::json!({"v": 1, "type": "entries", "seq": 1, "time_ms": at, "expires_ms": at + 86_400_000, "forwarders": []}),
    );
    serde_json::value::RawValue::from_string(format!(r#"{{"keys":{keys},"entries":{entries}}}"#)).unwrap()
}

/// b's registration for copies and events under the face `face`, sealed
/// to `key`, with its send key.
fn registration(seq: u64, face: [u8; 16], key: [u8; 32]) -> Vec<u8> {
    let token = vec![5; 32];
    let slot = [3; 16];
    let send = crate::push::ServerKey::from_scalar(&[11; 32]).unwrap();
    let s =
        core_push::Signed { env: core_push::ENV_APNS, token: &token, slot: &slot, face: &face, seq, challenge: None };
    let sig = core_push::sign_send(&send, &s).unwrap();
    Registration {
        seq,
        kinds: core_push::KIND_COPIES | core_push::KIND_EVENTS,
        on: Some(core_push::On {
            token,
            env: core_push::ENV_APNS,
            key: cbb_core::secret::Zeroizing::new(key),
            send_key: Key::es256(cbb_core::identity::ExternalKey::public(&send)),
            send_sig: sig.to_vec(),
            slot,
            face,
            challenge: None,
        }),
    }
    .write()
    .unwrap()
}

/// A phone that registered over its member connection and went away gets
/// one body for a copy and one for a removal, from the copy's origin or a
/// hub and never while it is connected; each opens under its registration,
/// and a send under the registration it replaced is answered stale.
#[test]
fn a_registered_device_gets_its_copies_and_events_by_push() {
    // The push service, with its certificate's key in keys.json.
    let keys = crate::relayd::keys::Keys::new().unwrap();
    let cert = cbb_core::certs::Cert::parse(&keys.cert).unwrap();
    let spki = cbb_core::certs::p256_spki_of(cert.public_key());
    let platform = Arc::new(Kept::default());
    let mut platforms: HashMap<u64, Arc<dyn Platform>> = HashMap::new();
    platforms.insert(core_push::ENV_APNS, platform.clone());
    let service = Service::start(Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        cert: keys.cert.clone(),
        key: keys.key.clone(),
        platforms,
        budgets: Budgets::default(),
        new_state: false,
        state: None,
        log: Arc::new(|_| {}),
    })
    .unwrap();
    let at: SocketAddr = service.addr();
    *push::TEST_SERVICE.lock().unwrap() = Some(at);

    let [da, db, dc] = group();
    let log: Arc<dyn Fn(&str) + Send + Sync> = Arc::new(|_| {});
    let mut oa = own(&da);
    oa.root = Some(Arc::new(root()));
    let (release_root, release) = (TestKey::new(1), TestKey::new(2));
    let roots = release_root.root("root-1");
    let now = crate::uptime::wall_ms();
    let open = |dir: &Path, o: Own| {
        let m = Mesh::open(dir, o, log.clone()).unwrap();
        m.with_signed(
            Arc::new(crate::releases::Releases::open(dir, roots.clone(), now, &|_| {})),
            Arc::new(crate::entries::Entries::open(dir, roots.clone(), now, &|_| {})),
        );
        m.rotate().unwrap();
        m
    };
    let (a, b, c) = (open(&da, oa), open(&db, own(&db)), open(&dc, own(&dc)));
    assert!(a.put_entries(&entry_points(&release_root, &release, &spki)).unwrap());
    a.refresh_faces(&a.state());
    connect(&a, &b);
    connect(&a, &c);
    connect(&c, &b);
    let pin = cbb_core::certs::sha256(&spki);
    let face = |m: &Mesh| m.faces().kept(&pin).tag();
    until("a face toward the push service on every member", 20, || {
        face(&a).is_some() && face(&b) == face(&a) && face(&c) == face(&a)
    });
    let face = face(&a).unwrap();

    // b registers with a and c over its connections to them, as a phone's
    // app does: its own registration, with the face b reads itself. b
    // reads it once a's entry points reach it too, which can come after
    // the faces.
    until("b's own face toward the push service", 20, || b.push_face() == Some(face));
    let key = [8; 32];
    let first = registration(1, face, key);
    assert!(b.set_own_push(Some(b"not a frame".to_vec())).is_err(), "a registration members refuse");
    b.set_own_push(Some(first)).unwrap();
    until("the registrations", 10, || a.push.held() == 1 && c.push.held() == 1);

    // While b is connected, a copy goes to it directly.
    assert!(a.copy(&Content::text("near", false)).unwrap());
    assert_eq!(a.push.waiting(), 0, "a body for a device that is connected");

    // b goes away; a's copy wakes it once, sealed under its registration.
    b.close();
    until("a and c see b gone", 10, || !a.connected().contains(&b.device()) && !c.connected().contains(&b.device()));
    assert!(a.copy(&Content::text("far", false)).unwrap());
    until("the copy's body", 20, || platform.len() == 1);
    match core_push::open(&key, 1, &platform.get(0)) {
        Ok(Body::Copy(_)) => {}
        other => panic!("the first body opened as {other:?}"),
    }

    // b comes back with a new registration set before it connects, which
    // a gets on the connection; then b goes.
    let b = open(&db, own(&db));
    b.set_own_push(Some(registration(2, face, key))).unwrap();
    connect(&a, &b);
    until("b back at a", 10, || a.connected().contains(&b.device()));
    until("the new registration at a", 10, || push::saved_seq(&da, &b.device()) == Some(2));
    b.close();
    until("a sees b gone again", 10, || !a.connected().contains(&b.device()));

    // c's copy: c sends under the old registration, which the service now
    // answers stale, and a, the hub, under the new one.
    assert!(c.copy(&Content::text("from c", false)).unwrap());
    until("the hub's body", 20, || platform.len() == 2);
    match core_push::open(&key, 2, &platform.get(1)) {
        Ok(Body::Copy(_)) => {}
        other => panic!("the hub's body opened as {other:?}"),
    }
    // c holds a renewal for b, which b takes when it connects to c.
    until("c asks b to register again", 20, || c.push.renewal_pending(&b.device()));
    let b = open(&db, own(&db));
    connect(&c, &b);
    until("b takes c's push-renew", 10, || b.take_renewals().iter().any(|(slot, _)| *slot == [3; 16]));
    b.close();
    until("c sees b gone", 10, || !c.connected().contains(&b.device()));

    // A removal: the hub tells b of it.
    a.write(|set, k| crate::writers::remove(set, k, "c", crate::uptime::wall_ms() as u64).map(|_| ())).unwrap();
    until("the event's body", 20, || platform.len() == 3);
    match core_push::open(&key, 2, &platform.get(2)) {
        Ok(Body::Event { event, .. }) => assert_eq!(event, core_push::EVENT_REMOVED),
        other => panic!("the event's body opened as {other:?}"),
    }
    until("nothing more to send", 20, || a.push.waiting() == 0 && c.push.waiting() == 0);
    assert_eq!(platform.len(), 3, "a body twice");

    *push::TEST_SERVICE.lock().unwrap() = None;
    for m in [&a, &c] {
        m.close();
    }
}
