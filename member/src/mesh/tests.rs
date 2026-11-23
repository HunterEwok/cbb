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

pub(crate) struct K(SigningKey);

impl ExternalKey for K {
    fn public(&self) -> Vec<u8> {
        self.0.verifying_key().to_sec1_point(false).as_bytes().to_vec()
    }
    fn sign_digest(&self, digest: &[u8; 32]) -> cbb_core::error::Result<Vec<u8>> {
        let sig: p256::ecdsa::Signature = self.0.sign_prehash(digest).unwrap();
        Ok(sig.to_der().as_bytes().to_vec())
    }
}

impl K {
    /// The key made from the 32 bytes b.
    pub(crate) fn of(b: &[u8; 32]) -> K {
        K(SigningKey::from_slice(b).unwrap())
    }
}

pub(crate) fn root() -> K {
    K(SigningKey::from_slice(&[1; 32]).unwrap())
}

/// The public point of another fixed key, made from the byte b.
#[cfg(feature = "tunnel")]
pub(crate) fn root_like(b: u8) -> Vec<u8> {
    K(SigningKey::from_slice(&[b; 32]).unwrap()).public()
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
    dirs(name, &[])
}

/// two_dirs, with b one of the group's hubs by the root's hubs record.
#[cfg(feature = "tunnel")]
pub(crate) fn two_dirs_b_hub(name: &str) -> (PathBuf, PathBuf) {
    dirs(name, &["b"])
}

/// Two members that are both hubs, b above a in the hubs record.
#[cfg(feature = "tunnel")]
pub(crate) fn two_dirs_both_hubs(name: &str) -> (PathBuf, PathBuf) {
    dirs(name, &["b", "a"])
}

fn dirs(name: &str, hubs: &[&str]) -> (PathBuf, PathBuf) {
    dirs_with(name, hubs, body::ROLE_MEMBER, false)
}

/// dirs, with b's role b_role, and b frozen in a's records when frozen.
fn dirs_with(name: &str, hubs: &[&str], b_role: u64, frozen: bool) -> (PathBuf, PathBuf) {
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
        let mut d = Device::new(o.member_key(), name, if name == "b" { b_role } else { body::ROLE_MEMBER });
        d.rights = body::RIGHT_READ | body::RIGHT_SEND | body::RIGHT_SECRETS;
        if hubs.contains(&name) {
            d.rights |= body::RIGHT_HUB;
        }
        let st = set.state();
        set.write_record(&st, &root, Kind::device(d), now - 1000).unwrap();
    }
    if !hubs.is_empty() {
        let hubs: Vec<String> = hubs.iter().map(ToString::to_string).collect();
        crate::writers::set_hubs(&mut set, &root, &hubs, now - 900).unwrap();
    }
    let b_set = set.clone();
    if frozen {
        crate::writers::freeze(&mut set, &root, "b", true, now - 800).unwrap();
    }
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
        b.statements.lock().unwrap().sealing(&st).contains_key(&a.device()) && {
            let sa = a.state();
            a.statements.lock().unwrap().sealing(&sa).contains_key(&b.device())
        }
    });
    // b kept what it learned.
    let local = crate::set::local_key(&b.dir).unwrap();
    assert_eq!(crate::set::load(&b.dir, &local).unwrap().unwrap().digest(), a.set().lock().unwrap().digest());
    a.close();
    b.close();
}

// Each member keeps the release archive a peer's hello names, for the
// hub's cbb update, after the connection ends too; a name not made as
// packaging/archive.sh makes them is not kept.
#[test]
fn a_member_keeps_the_archives_its_peers_update_from() {
    let (a, b) = two("archives");
    let device = |archive: &str| crate::hello::Device { archive: archive.into(), ..Default::default() };
    a.set_hello(crate::hello::Hello { device: device("cbb-linux-arm64.tar.gz"), ..Default::default() });
    b.set_hello(crate::hello::Hello { device: device("cbb-linux-arm64.tar.gz/.."), ..Default::default() });
    connect(&a, &b);
    until("the hellos", || b.hellos().contains_key(&a.device()) && a.hellos().contains_key(&b.device()));
    assert_eq!(b.archives(), vec!["cbb-linux-arm64.tar.gz".to_string()]);
    assert!(a.archives().is_empty(), "a name packaging/archive.sh does not make");
    a.close();
    until("the connection gone", || b.connected().is_empty());
    assert_eq!(b.archives(), vec!["cbb-linux-arm64.tar.gz".to_string()]);
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
    until("the statements", || {
        // The state first: holding the statements while taking the set would invert mesh's lock order.
        let st = b.state();
        b.statements.lock().unwrap().sealing(&st).contains_key(&a.device())
    });
    let content = Content::text("from b", false);
    assert!(b.copy(&content).unwrap());
    let (got, origin) = rx.recv_timeout(Duration::from_secs(10)).unwrap();
    assert_eq!(got, content);
    assert_eq!(origin, b.device());
    a.close();
    b.close();
}

// A copy made while the member holds no other reader's keys, as just
// after it joined, goes out once a reader's statement arrives, with the
// time it was copied.
#[test]
fn a_copy_made_before_a_reader_was_known_goes_out_later() {
    let (a, b) = two("unsent");
    let (tx, rx) = mpsc::channel();
    let tx = Mutex::new(tx);
    a.on_copy(Box::new(move |c| {
        let _ = tx.lock().unwrap().send((c.content.clone(), c.origin));
    }));
    let content = Content::text("before a reader", false);
    assert!(!b.copy(&content).unwrap(), "no reader yet");
    connect(&a, &b);
    let (got, origin) = rx.recv_timeout(Duration::from_secs(10)).unwrap();
    assert_eq!((got, origin), (content, b.device()));
    assert!(b.unsent.lock().unwrap().is_none());
    a.close();
    b.close();
}

// A copy made while no peer was connected reaches a reader once they meet
// again: each side sends its current copy as the connection opens.
#[test]
fn the_current_copy_reaches_a_peer_that_connects_later() {
    let (a, b) = two("current");
    let (tx, rx) = mpsc::channel();
    let tx = Mutex::new(tx);
    a.on_copy(Box::new(move |c| {
        let _ = tx.lock().unwrap().send(c.content.clone());
    }));
    connect(&a, &b);
    until("the statements", || {
        let st = b.state();
        b.statements.lock().unwrap().sealing(&st).contains_key(&a.device())
    });
    b.close_connections();
    until("the connection gone", || a.connected().is_empty() && b.connected().is_empty());
    let content = Content::text("while apart", false);
    assert!(b.copy(&content).unwrap(), "sealed to a, which is not connected");
    assert!(rx.try_recv().is_err());
    connect(&a, &b);
    assert_eq!(rx.recv_timeout(Duration::from_secs(10)).unwrap(), content);
    // Once seen, the same copy is not taken again on the next connection.
    b.close_connections();
    until("the connection gone", || a.connected().is_empty() && b.connected().is_empty());
    connect(&a, &b);
    until("connected again", || !a.connected().is_empty());
    assert!(rx.recv_timeout(Duration::from_millis(500)).is_err());
    a.close();
    b.close();
}

#[test]
fn a_current_copy_older_than_one_the_peer_holds_is_dropped() {
    let (a, b) = two("current-old");
    let (tx, rx) = mpsc::channel();
    let tx = Mutex::new(tx);
    a.on_copy(Box::new(move |c| {
        let _ = tx.lock().unwrap().send(c.content.clone());
    }));
    let earlier = b.clock.now();
    connect(&a, &b);
    until("the statements", || {
        let st = b.state();
        b.statements.lock().unwrap().sealing(&st).contains_key(&a.device())
    });
    let newer = Content::text("newer", false);
    assert!(b.copy(&newer).unwrap());
    assert_eq!(rx.recv_timeout(Duration::from_secs(10)).unwrap(), newer);
    b.close_connections();
    until("the connection gone", || a.connected().is_empty() && b.connected().is_empty());
    // b's current copy becomes one signed before the copy a holds, as
    // after a restart that lost the newer one: a has not seen it, and
    // drops it as older.
    *b.current.lock().unwrap() = None;
    assert!(b.copy_at(&Content::text("older", false), earlier).unwrap());
    connect(&a, &b);
    until("connected again", || !a.connected().is_empty());
    assert!(rx.recv_timeout(Duration::from_millis(500)).is_err(), "the older copy was taken");
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
    until("the statements", || {
        // The state first: holding the statements while taking the set would invert mesh's lock order.
        let st = b.state();
        b.statements.lock().unwrap().sealing(&st).contains_key(&a.device())
    });
    // Over a megabyte: more than one get, several chunks and segments.
    let png: Vec<u8> = (0..(1 << 20) + 70_000).map(|i| (i % 253) as u8).collect();
    let content = Content { kind: TYPE_MEDIA, text: Some("a picture".into()), ..Content::default() };
    let parts = vec![(Part { kind: "image/png".into(), ..Part::default() }, Source::Bytes(png.clone()))];
    assert!(b.copy_media(&content, parts, true).unwrap().sent);
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
fn a_results_reason_comes_cleaned() {
    let (a, b) = two("reason");
    b.on_command(Box::new(|_| Err(Error::msg("no\u{1b}[2Jway\u{7}\u{9b}here"))));
    connect(&a, &b);
    until("the connection", || a.connected().contains(&b.device()));
    let r = a.command(&root(), b.device(), cbb_core::commands::COMMAND_UNMUTE, None).unwrap();
    assert_eq!(r.status, 3);
    // Each control character, escape and C1 too, is a space.
    assert_eq!(r.reason, "no [2Jway  here");
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
fn other_messages_go_to_the_service_and_hub_shares_only_from_hubs() {
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
    // b holds no admin key and no hubs record names it: what it would
    // tell the hubs is dropped; its key toward a as a hub, as a member of
    // the group, goes on.
    let hubs = frame::write(&Value::Map(vec![
        (frame::FIELD_T, Value::Uint(cbb_core::msg::tables::T_HUBS)),
        (3, Value::Uint(1)),
    ]));
    assert_eq!(cbb_core::msg::check(&hubs[4..]), Ok(cbb_core::msg::tables::T_HUBS));
    let tunnel = frame::write(&Value::Map(vec![
        (frame::FIELD_T, Value::Uint(cbb_core::msg::tables::T_TUNNEL)),
        (2, cbb_core::format::Key::new(cbb_core::format::Alg::X25519, &[4; 32]).to_value()),
        (3, Value::Bytes(&[5; 32])),
    ]));
    assert_eq!(cbb_core::msg::check(&tunnel[4..]), Ok(cbb_core::msg::tables::T_TUNNEL));
    assert!(!a.may_be_hub(&b.device()));
    assert!(b.send(&a.device(), hubs));
    assert!(b.send(&a.device(), tunnel));
    assert!(b.send(&a.device(), reach));
    assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), (b.device(), cbb_core::msg::tables::T_TUNNEL));
    // The member keeps a reach itself (`reach`), the device no record of
    // the group names left out.
    assert!(rx.recv_timeout(Duration::from_millis(300)).is_err());
    assert!(a.reach_of(&b.device()).is_empty());
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

/// The root's device starts the servers' period; the other member takes it,
/// adds its server key, and the root lists it in the members' credential.
#[test]
fn server_credentials_go_round_the_group() {
    let (da, db) = two_dirs("faces");
    let log: Arc<dyn Fn(&str) + Send + Sync> = Arc::new(|_| {});
    let mut oa = own(&da);
    oa.root = Some(Arc::new(root()));
    let a = Mesh::open(&da, oa, log.clone()).unwrap();
    let b = Mesh::open(&db, own(&db), log).unwrap();
    a.refresh_faces(&a.state());
    // A face for each of the project's servers, by the pins built in.
    let mut servers = crate::faces::project_servers(None, 0);
    servers.sort();
    assert_eq!(servers.len(), 2, "the relay and the forwarder; push has no pin built in");
    assert_eq!(a.faces().servers(), servers);
    let pin = servers[0].pin;
    let tag = a.faces().kept(&pin).tag();
    assert!(tag.is_some(), "the root started a period");
    assert_ne!(a.faces().kept(&servers[1].pin).tag(), tag, "another face for the other server");
    assert!(b.faces().kept(&pin).tag().is_none());
    connect(&a, &b);
    until("b takes the period", || b.faces().kept(&pin).tag() == tag);
    let bk = b.own().hash();
    until("the root lists b on both faces", || {
        servers.iter().all(|s| {
            let k = a.faces().kept(&s.pin);
            k.envelopes().len() == 5 && k.lists_member(&bk)
        })
    });
    until("b holds the new members' credentials", || servers.iter().all(|s| b.faces().kept(&s.pin).lists_member(&bk)));
    a.close();
    b.close();
}

/// Message `push` from a peer over its own connection is its registration:
/// the member keeps it, in push.cbor, and takes it again after a restart.
#[test]
#[cfg(feature = "tunnel")]
fn a_peer_registers_for_push_and_the_member_keeps_it() {
    let (da, db) = two_dirs("push");
    let log: Arc<dyn Fn(&str) + Send + Sync> = Arc::new(|_| {});
    let a = Mesh::open(&da, own(&da), log.clone()).unwrap();
    let b = Mesh::open(&db, own(&db), log.clone()).unwrap();
    connect(&a, &b);
    until("the connection", || b.connected().contains(&a.device()));
    let token = vec![5; 32];
    let send_key = Key::es256(K(SigningKey::from_slice(&[9; 32]).unwrap()).public());
    let reg = cbb_core::push::Registration {
        seq: 1,
        kinds: cbb_core::push::KIND_COPIES,
        on: Some(cbb_core::push::On {
            token,
            env: cbb_core::push::ENV_APNS,
            key: cbb_core::secret::Zeroizing::new([8; 32]),
            send_key,
            send_sig: vec![1; 64],
            slot: [3; 16],
            face: [4; 16],
            challenge: None,
        }),
    };
    assert!(b.send(&a.device(), reg.write().unwrap()));
    until("the registration", || a.push.held() == 1);
    assert!(da.join(super::push::FILE).exists());
    // A copy a makes while b is connected goes to b directly, not by push.
    a.copy(&Content::text("near", false)).unwrap();
    assert_eq!(a.push.waiting(), 0);
    a.close();
    b.close();
    let a = Mesh::open(&da, own(&da), log).unwrap();
    assert_eq!(a.push.held(), 1, "kept across a restart");
    a.close();
}

/// A member connection gives the tunnel's pre-shared keys (A-22): the
/// hub's and its client's ends export the same key and tag, the two
/// directions differ, and a new connection gives a new key.
#[test]
fn a_connection_gives_both_ends_the_tunnels_key() {
    let (da, db) = two_dirs("tunnel-psk");
    let log: Arc<dyn Fn(&str) + Send + Sync> = Arc::new(|_| {});
    let a = Mesh::open(&da, own(&da), log.clone()).unwrap();
    let b = Mesh::open(&db, own(&db), log).unwrap();
    connect(&a, &b);
    until("the connection", || a.connected().contains(&b.device()) && b.connected().contains(&a.device()));
    let a_hub = a.tunnel_psk(&b.device(), true).expect("the hybrid exchange gives a key");
    assert_eq!(b.tunnel_psk(&a.device(), false), Some(a_hub), "the hub's and the client's ends agree");
    let b_hub = b.tunnel_psk(&a.device(), true).unwrap();
    assert_eq!(a.tunnel_psk(&b.device(), false), Some(b_hub));
    assert_ne!(a_hub, b_hub, "each direction its own");
    a.close();
    b.close();
}

/// Reach (docs/protocol.md, section 4): a computer tells a phone connected
/// to it the other members it reaches, and a member keeps what a peer told
/// it, the IDs the records name and not its own, until the connection ends.
#[test]
fn a_computer_tells_a_phone_what_it_reaches() {
    let (da, db) = dirs_with("reach", &[], body::ROLE_PHONE, false);
    let log: Arc<dyn Fn(&str) + Send + Sync> = Arc::new(|_| {});
    let (a, b) = (Mesh::open(&da, own(&da), log.clone()).unwrap(), Mesh::open(&db, own(&db), log).unwrap());
    connect(&a, &b);
    until("the connection", || b.connected().contains(&a.device()));
    // a, a computer, reaches nobody else: it tells the phone so.
    until("the phone's reach from the computer", || b.reach_in.lock().unwrap().contains_key(&a.device()));
    assert!(b.reach_of(&a.device()).is_empty());
    assert!(!a.reach_in.lock().unwrap().contains_key(&b.device()), "a phone tells no reach");

    let c = a.state().devices.iter().find(|d| d.name == "c").unwrap().id;
    let a_id = a.device();
    // A set goes sorted (docs/protocol.md, section 2).
    let mut ids = [c.0, [3; 16], a_id.0];
    ids.sort();
    let reach = frame::write(&Value::Map(vec![
        (frame::FIELD_T, Value::Uint(m::T_REACH)),
        (2, Value::Array(ids.iter().map(|i| Value::Bytes(i)).collect())),
    ]));
    assert!(b.send(&a.device(), reach));
    until("the computer keeps the reach", || a.reach_of(&b.device()) == vec![c]);
    b.close();
    until("the reach goes with the connection", || a.reach_of(&b.device()).is_empty());
    a.close();
}

/// A phone the records refuse (frozen) learns nothing of whom the computer
/// reaches: no reach goes to it.
#[test]
fn a_refused_phone_gets_no_reach() {
    let (da, db) = dirs_with("reach-frozen", &[], body::ROLE_PHONE, true);
    let log: Arc<dyn Fn(&str) + Send + Sync> = Arc::new(|_| {});
    let (a, b) = (Mesh::open(&da, own(&da), log.clone()).unwrap(), Mesh::open(&db, own(&db), log).unwrap());
    assert!(a.state().device(&b.device()).is_some_and(|d| d.frozen));
    connect(&a, &b);
    std::thread::sleep(Duration::from_secs(2));
    assert!(!b.reach_in.lock().unwrap().contains_key(&a.device()), "a frozen phone got a reach");
    a.close();
    b.close();
}

/// Only the group's current root key renews the server credentials.
#[test]
fn only_the_root_key_renews_the_credentials() {
    let (a, b) = two("renew");
    let other = K(SigningKey::from_slice(&[9; 32]).unwrap());
    let e = a.refresh_faces_by(&other).unwrap_err();
    assert!(e.message().contains("not the group's current root key"), "{e:?}");
    assert!(a.refresh_faces_by(&root()).is_ok());
    a.close();
    b.close();
}

/// Two devices of one group where b joined first and a later, through
/// another device (a phone root, which b never meets): a holds both
/// records, b only its own and the root's. Gives a's and b's meshes, with
/// one log for both.
fn joined_later(name: &str) -> (Arc<Mesh>, Arc<Mesh>, Arc<Mutex<Vec<String>>>) {
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
    let write = |set: &mut RecordSet, o: &Own, name: &str, at: u64| {
        let mut d = Device::new(o.member_key(), name, body::ROLE_MEMBER);
        d.rights = body::RIGHT_READ | body::RIGHT_SEND | body::RIGHT_SECRETS;
        let st = set.state();
        set.write_record(&st, &root, Kind::device(d), at).unwrap();
    };
    write(&mut set, &ob, "b", now - 1000);
    let b_set = set.clone();
    write(&mut set, &oa, "a", now - 500);
    for (dir, s) in [(&da, &set), (&db, &b_set)] {
        let local = crate::set::local_key(dir).unwrap();
        crate::set::save(dir, s, &local).unwrap();
    }
    let lines = Arc::new(Mutex::new(Vec::new()));
    let l = lines.clone();
    let log: Arc<dyn Fn(&str) + Send + Sync> = Arc::new(move |s: &str| l.lock().unwrap().push(s.to_string()));
    let a = Mesh::open(&da, own(&da), log.clone()).unwrap();
    let b = Mesh::open(&db, own(&db), log).unwrap();
    a.rotate().unwrap();
    b.rotate().unwrap();
    (a, b, lines)
}

// b does not know a's key yet; a's intro, its first message, brings b the
// record that admits it, whichever side dials (docs/protocol.md, section
// 6, "The intro").
#[test]
fn a_device_admitted_later_gets_through_by_its_intro() {
    for b_dials in [true, false] {
        let (a, b, lines) = joined_later(if b_dials { "intro-b-dials" } else { "intro-a-dials" });
        assert!(b.state().device(&a.device()).is_none(), "b knows a before the intro");
        if b_dials {
            connect(&a, &b);
        } else {
            connect(&b, &a);
        }
        until("b to take a's intro", || b.state().device(&a.device()).is_some());
        until("the sets to settle", || a.set().lock().unwrap().digest() == b.set().lock().unwrap().digest());
        until("the statements", || {
            let st = b.state();
            b.statements.lock().unwrap().sealing(&st).contains_key(&a.device())
        });
        // b kept the record.
        let local = crate::set::local_key(&b.dir).unwrap();
        assert!(crate::set::load(&b.dir, &local).unwrap().unwrap().state().device(&a.device()).is_some());
        assert!(lines.lock().unwrap().iter().any(|l| l.contains("took the intro of")), "{:?}", lines.lock().unwrap());
        a.close();
        b.close();
    }
}

// A key no record admits gets nothing: its intro proves nothing, and the
// connection closes before any hello.
#[test]
fn a_stranger_gets_nothing_by_an_intro() {
    let (a, _b, lines) = joined_later("intro-stranger");
    let ds = temp("intro-stranger-s");
    // The stranger keeps a group of its own, with the same root's key but
    // no record of a.
    let root = root();
    let (k1, k2) = pq::recovery_keys(&[2; 32]).unwrap();
    let k1 = SigningKey::from(&k1).verifying_key().to_sec1_point(false).as_bytes().to_vec();
    let mut set = RecordSet::new(
        Key::es256(root.public()),
        Recovery::new(Key::es256(k1), Key::new(ALG_SLH_DSA, k2.public())).unwrap(),
    );
    let os = own(&ds);
    let mut d = Device::new(os.member_key(), "s", body::ROLE_MEMBER);
    d.rights = body::RIGHT_READ;
    let st = set.state();
    set.write_record(
        &st,
        &K(SigningKey::from_slice(&[3; 32]).unwrap()),
        Kind::device(d),
        crate::uptime::wall_ms() as u64,
    )
    .ok();
    let local = crate::set::local_key(&ds).unwrap();
    crate::set::save(&ds, &set, &local).unwrap();
    let log: Arc<dyn Fn(&str) + Send + Sync> = Arc::new(|_| {});
    let s = Mesh::open(&ds, own(&ds), log).unwrap();
    let before = a.set().lock().unwrap().digest();
    let ln = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = ln.local_addr().unwrap();
    let a2 = a.clone();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let (sock, _) = ln.accept().unwrap();
        let _ = tx.send(a2.accept(sock).map_err(|e| e.details()));
    });
    let _ = s.dial(addr, Some(a.device()));
    let got = rx.recv_timeout(Duration::from_secs(20)).unwrap();
    assert!(got.is_err(), "a took a stranger: {got:?}");
    assert_eq!(a.set().lock().unwrap().digest(), before, "a kept something of a stranger's intro");
    assert!(!lines.lock().unwrap().iter().any(|l| l.contains("took the intro of")));
    a.close();
    s.close();
}
