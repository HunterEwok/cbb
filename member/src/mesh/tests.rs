// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

use std::net::TcpListener;
use std::sync::mpsc;
use std::time::Instant;

use cbb_core::identity::ExternalKey;
use cbb_core::records::body::{self, Device};
use cbb_core::records::{Kind, Recovery, key::ALG_SLH_DSA, pq};
use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::hazmat::PrehashSigner as _;
use p256::pkcs8::EncodePrivateKey as _;

use super::*;
use crate::content::Source;
use cbb_core::media::Part;

struct K(SigningKey);

impl ExternalKey for K {
    fn public(&self) -> Vec<u8> {
        self.0.verifying_key().to_sec1_point(false).as_bytes().to_vec()
    }
    fn sign_digest(&self, digest: &[u8; 32]) -> cbb_core::error::Result<Vec<u8>> {
        let sig: p256::ecdsa::Signature = self.0.sign_prehash(digest).unwrap();
        Ok(sig.to_der().as_bytes().to_vec())
    }
}

fn root() -> K {
    K(SigningKey::from_slice(&[1; 32]).unwrap())
}

fn temp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("cbb-mesh-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

pub(crate) fn own(dir: &Path) -> Own {
    Own::load_with(dir, &|_| Err(Error::msg("no hardware")), &|| None).unwrap()
}

/// Two devices of one group, each with its own state directory; a has the
/// group's records first, b only the root's first records (a device that
/// joined and missed some).
fn two(name: &str) -> (Arc<Mesh>, Arc<Mesh>) {
    let (da, db) = two_dirs(name);
    let log: Arc<dyn Fn(&str) + Send + Sync> = Arc::new(|_| {});
    let a = Mesh::open(&da, own(&da), log.clone()).unwrap();
    let b = Mesh::open(&db, own(&db), log).unwrap();
    a.rotate().unwrap();
    b.rotate().unwrap();
    (a, b)
}

/// The state directories of `two`'s devices, a's and b's.
pub(crate) fn two_dirs(name: &str) -> (PathBuf, PathBuf) {
    let (da, db) = (temp(&format!("{name}-a")), temp(&format!("{name}-b")));
    let (oa, ob) = (own(&da), own(&db));
    let root = root();
    let (k1, k2) = pq::recovery_keys(&[1; 32]).unwrap();
    let k1 = SigningKey::from(&k1).verifying_key().to_sec1_point(false).as_bytes().to_vec();
    let mut set = RecordSet::new(
        Key::es256(root.public()),
        Recovery::new(Key::es256(k1), Key::new(ALG_SLH_DSA, k2.public())).unwrap(),
    );
    let now = crate::uptime::wall_ms() as u64;
    for (o, name) in [(&oa, "a"), (&ob, "b")] {
        let mut d = Device::new(o.member_key(), name, body::ROLE_MEMBER);
        d.rights = body::RIGHT_READ | body::RIGHT_SEND | body::RIGHT_SECRETS;
        let st = set.state();
        set.write_record(&st, &root, Kind::device(d), now - 1000).unwrap();
    }
    let b_set = set.clone();
    let mut d = Device::new(Key::es256(K(SigningKey::from_slice(&[7; 32]).unwrap()).public()), "c", body::ROLE_MEMBER);
    d.rights = body::RIGHT_READ;
    let st = set.state();
    set.write_record(&st, &root, Kind::device(d), now - 500).unwrap();
    for (dir, s) in [(&da, &set), (&db, &b_set)] {
        let local = crate::set::local_key(dir).unwrap();
        crate::set::save(dir, s, &local).unwrap();
    }
    (da, db)
}

/// Connects b to a over loopback; the connection runs in the background.
fn connect(a: &Arc<Mesh>, b: &Arc<Mesh>) {
    let ln = TcpListener::bind("127.0.0.1:0").unwrap();
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

fn until(what: &str, f: impl Fn() -> bool) {
    let end = Instant::now() + Duration::from_secs(10);
    while !f() {
        assert!(Instant::now() < end, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn two_members_sync_their_records_and_statements() {
    let (a, b) = two("sync");
    assert_ne!(a.set().lock().unwrap().digest(), b.set().lock().unwrap().digest());
    connect(&a, &b);
    until("the sets to settle", || a.set().lock().unwrap().digest() == b.set().lock().unwrap().digest());
    // Each has the other's statement: each can seal to the other.
    until("the statements", || {
        let st = b.state();
        b.statements.lock().unwrap().sealing(&st).contains_key(&a.device())
            && a.statements.lock().unwrap().sealing(&a.state()).contains_key(&b.device())
    });
    // b kept what it learned.
    let local = crate::set::local_key(&b.dir).unwrap();
    assert_eq!(crate::set::load(&b.dir, &local).unwrap().unwrap().digest(), a.set().lock().unwrap().digest());
    a.close();
    b.close();
}

#[test]
fn a_copy_reaches_the_other_member() {
    let (a, b) = two("copy");
    let (tx, rx) = mpsc::channel();
    let tx = Mutex::new(tx);
    a.on_copy(Box::new(move |c| {
        let _ = tx.lock().unwrap().send((c.content.clone(), c.origin));
    }));
    connect(&a, &b);
    until("the statements", || b.statements.lock().unwrap().sealing(&b.state()).contains_key(&a.device()));
    let content = Content::text("from b", false);
    assert!(b.copy(&content).unwrap());
    let (got, origin) = rx.recv_timeout(Duration::from_secs(10)).unwrap();
    assert_eq!(got, content);
    assert_eq!(origin, b.device());
    a.close();
    b.close();
}

#[test]
fn a_copy_with_images_brings_its_blob_and_it_opens() {
    use cbb_core::content::TYPE_MEDIA;
    let (a, b) = two("media");
    let (tx, rx) = mpsc::channel();
    let tx = Mutex::new(tx);
    a.on_copy(Box::new(move |c| {
        let _ = tx.lock().unwrap().send(c.clone());
    }));
    connect(&a, &b);
    until("the statements", || b.statements.lock().unwrap().sealing(&b.state()).contains_key(&a.device()));
    // Over a megabyte: more than one get, several chunks and segments.
    let png: Vec<u8> = (0..(1 << 20) + 70_000).map(|i| (i % 253) as u8).collect();
    let content = Content { kind: TYPE_MEDIA, text: Some("a picture".into()), ..Content::default() };
    let parts = vec![(Part { kind: "image/png".into(), ..Part::default() }, Source::Bytes(png.clone()))];
    assert!(b.copy_media(&content, parts).unwrap());
    let got = rx.recv_timeout(Duration::from_secs(10)).unwrap();
    assert_eq!((got.origin, got.from), (b.device(), b.device()));
    let blob = got.blob.expect("a blob");
    let manifest = got.content.manifest.clone().unwrap();
    assert_eq!(manifest.size, png.len() as i64);
    // Over the limit, it is not fetched.
    assert!(a.fetch(&blob, &got.from, 1000).is_err());
    a.fetch(&blob, &got.from, 100 << 20).unwrap();
    assert_eq!(a.content.held(&blob.sha256), Some(blob.size));
    let out = a.dir.join("opened");
    let placed = a.open_media(Some(&blob), &manifest, &out).unwrap();
    assert_eq!(std::fs::read(&placed[0].1).unwrap(), png);
    // A blob nobody holds is missing.
    let gone = sealed::Blob { sha256: [9; 32], ..blob };
    let err = a.fetch(&gone, &got.from, 100 << 20).unwrap_err();
    assert!(err.to_string().contains("does not hold"), "{err}");
    a.close();
    b.close();
}

#[test]
fn the_root_commands_a_member_and_gets_its_result() {
    let (a, b) = two("command");
    let (tx, rx) = mpsc::channel();
    let tx = Mutex::new(tx);
    b.on_command(Box::new(move |t| {
        let _ = tx.lock().unwrap().send(t.kind);
        Ok(())
    }));
    connect(&a, &b);
    until("the connection", || a.connected().contains(&b.device()));
    let r = a.command(&root(), b.device(), cbb_core::commands::COMMAND_UNMUTE, None).unwrap();
    assert_eq!(r.status, 1);
    assert_eq!(r.by, b.device());
    assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), cbb_core::commands::COMMAND_UNMUTE);
    a.close();
    b.close();
}

#[test]
fn the_signed_files_travel_as_published() {
    let text = r#"{"keys":{"body":"AAE=", "sig":"AgM=","key":"BAU="},"channel":{"body":"Bg==","sig":"Bw==","key":"CA=="},"release":{"body":"CQ==","sig":"Cg==","key":"Cw=="}}"#;
    let v = serde_json::value::RawValue::from_string(text.into()).unwrap();
    let f = files_frame(m::T_RELEASE, RELEASE_FILES, &v).unwrap();
    assert_eq!(cbb_core::msg::check(&f[4..]), Ok(m::T_RELEASE));
    // Each file's bytes as published, its spacing too.
    assert_eq!(files_value(&f[4..], RELEASE_FILES).unwrap().get(), text);
    // A set without one of its files is no message.
    assert!(files_frame(m::T_ENTRIES, ENTRIES_FILES, &v).is_none());
}

#[test]
fn other_messages_go_to_the_service_and_hub_offers_only_from_hubs() {
    let (a, b) = two("other");
    let (tx, rx) = mpsc::channel();
    let tx = Mutex::new(tx);
    a.on_other(Box::new(move |from, t, _| {
        let _ = tx.lock().unwrap().send((*from, t));
    }));
    connect(&a, &b);
    until("the connection", || b.connected().contains(&a.device()));
    let reach = frame::write(&Value::Map(vec![
        (frame::FIELD_T, Value::Uint(m::T_REACH)),
        (2, Value::Array(vec![Value::Bytes(&[3; 16])])),
    ]));
    // b holds no admin key and no hubs record names it: its tunnel offer is
    // dropped, its reach goes on.
    let tunnel = frame::write(&Value::Map(vec![
        (frame::FIELD_T, Value::Uint(cbb_core::msg::tables::T_TUNNEL)),
        (2, cbb_core::format::Key::new(cbb_core::format::Alg::X25519, &[4; 32]).to_value()),
        (3, Value::Bytes(&[5; 32])),
    ]));
    assert_eq!(cbb_core::msg::check(&tunnel[4..]), Ok(cbb_core::msg::tables::T_TUNNEL));
    assert!(!a.may_be_hub(&b.device()));
    assert!(b.send(&a.device(), tunnel));
    assert!(b.send(&a.device(), reach));
    assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), (b.device(), m::T_REACH));
    assert!(rx.recv_timeout(Duration::from_millis(300)).is_err());
    a.close();
    b.close();
}

#[test]
fn the_member_port_takes_members_and_pairings() {
    let (a, b) = two("port");
    let ln = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = ln.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();
    let tx = Mutex::new(tx);
    a.on_pair(Some(Box::new(move |_sock, _s, _x| {
        let _ = tx.lock().unwrap().send(());
    })));
    let a2 = a.clone();
    std::thread::spawn(move || {
        for sock in ln.incoming().flatten() {
            let a3 = a2.clone();
            std::thread::spawn(move || {
                let _ = a3.accept_port(sock);
            });
        }
    });
    // A member connects and syncs.
    let (b2, ad) = (b.clone(), a.device());
    std::thread::spawn(move || {
        let _ = b2.dial(addr, Some(ad));
    });
    until("the sets to settle", || a.set().lock().unwrap().digest() == b.set().lock().unwrap().digest());
    // A device that pairs reaches the window.
    let stranger = K(SigningKey::from_slice(&[9; 32]).unwrap());
    let der = cbb_core::secret::Zeroizing::new(stranger.0.to_pkcs8_der().unwrap().as_bytes().to_vec());
    let ccfg = bykey::client(
        &bykey::OwnKey::pkcs8(&der).unwrap(),
        None,
        bykey::any_key(),
        cbb_core::alpn::PAIR,
        &tls::clock(),
    )
    .unwrap();
    let sock = TcpStream::connect(addr).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut s = tls::Session::client(Arc::new(ccfg), bykey::unsent_name()).unwrap();
    tls::handshake(&mut s, &sock, "the handshake").unwrap();
    rx.recv_timeout(Duration::from_secs(10)).expect("the pairing reached the window");
    // A stranger on the member protocol is refused.
    let ccfg = bykey::client(
        &bykey::OwnKey::pkcs8(&der).unwrap(),
        None,
        bykey::any_key(),
        cbb_core::alpn::MEMBER,
        &tls::clock(),
    )
    .unwrap();
    let sock = TcpStream::connect(addr).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut s = tls::Session::client(Arc::new(ccfg), bykey::unsent_name()).unwrap();
    let _ = tls::handshake(&mut s, &sock, "the handshake");
    let mut buf = [0u8; 16];
    let mut r = tls::Stream::new(s, sock);
    assert!(matches!(std::io::Read::read(&mut r, &mut buf), Ok(0) | Err(_)), "the stranger got nothing");
    a.close();
    b.close();
}

/// The two devices of `two`, with every line each logs kept.
fn two_logged(name: &str) -> (Arc<Mesh>, Arc<Mesh>, Arc<Mutex<Vec<String>>>) {
    let (da, db) = two_dirs(name);
    let lines = Arc::new(Mutex::new(Vec::new()));
    let l = lines.clone();
    let log: Arc<dyn Fn(&str) + Send + Sync> = Arc::new(move |s: &str| l.lock().unwrap().push(s.to_string()));
    let a = Mesh::open(&da, own(&da), log.clone()).unwrap();
    let b = Mesh::open(&db, own(&db), log).unwrap();
    (a, b, lines)
}

/// The root writes a device record on a: a's set changes while it is
/// connected, and a says so in a hello.
fn write_on(a: &Mesh, name: &str) {
    {
        let shared = a.set();
        let mut set = shared.lock().unwrap();
        let st = set.state();
        let key = Key::es256(K(SigningKey::from_slice(&[9; 32]).unwrap()).public());
        let mut d = Device::new(key, name, body::ROLE_MEMBER);
        d.rights = body::RIGHT_READ;
        set.write_record(&st, &root(), Kind::device(d), crate::uptime::wall_ms() as u64).unwrap();
    }
    a.changed().unwrap();
}

#[test]
fn a_record_written_while_connected_reaches_the_peer_without_a_reconnect() {
    let (a, b, lines) = two_logged("written");
    connect(&a, &b);
    until("the sets to settle", || a.set().lock().unwrap().digest() == b.set().lock().unwrap().digest());
    // Only a sends a new hello; b answers with its have, and a with its own.
    write_on(&a, "d");
    until("the record to reach b", || b.state().devices.iter().any(|d| d.name == "d"));
    assert_eq!(a.set().lock().unwrap().digest(), b.set().lock().unwrap().digest());
    let ended: Vec<String> = lines.lock().unwrap().iter().filter(|l| l.contains("ended")).cloned().collect();
    assert!(ended.is_empty(), "the connection ended: {ended:?}");
    a.close();
    b.close();
}

#[test]
fn two_members_that_dial_each_other_at_once_keep_one_connection() {
    let (a, b, _) = two_logged("double");
    for _ in 0..5 {
        // Each listens and dials the other at the same moment.
        let (la, lb) = (TcpListener::bind("127.0.0.1:0").unwrap(), TcpListener::bind("127.0.0.1:0").unwrap());
        let (aa, ab) = (la.local_addr().unwrap(), lb.local_addr().unwrap());
        for (m, ln) in [(a.clone(), la), (b.clone(), lb)] {
            std::thread::spawn(move || {
                let (sock, _) = ln.accept().unwrap();
                let _ = m.accept(sock);
            });
        }
        let go = Arc::new(std::sync::Barrier::new(2));
        for (m, to, id) in [(a.clone(), ab, b.device()), (b.clone(), aa, a.device())] {
            let go = go.clone();
            std::thread::spawn(move || {
                go.wait();
                let _ = m.dial(to, Some(id));
            });
        }
        until("both to be connected", || a.connected() == [b.device()] && b.connected() == [a.device()]);
        // The one kept carries the records both ways.
        until("the sets to settle", || a.set().lock().unwrap().digest() == b.set().lock().unwrap().digest());
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(a.connected(), [b.device()], "a lost its connection");
        assert_eq!(b.connected(), [a.device()], "b lost its connection");
        a.close_connections();
        until("both to be apart", || a.connected().is_empty() && b.connected().is_empty());
    }
    a.close();
    b.close();
}
