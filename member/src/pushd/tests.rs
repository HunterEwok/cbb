// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The push service against a fake platform: a member with its face's
//! credentials gets its bodies through once each, within the budgets; a
//! member the credentials leave out, an older credential or another period
//! key is refused. And the HTTP/2 client against a fake server.

use std::sync::Mutex;

use cbb_core::blind::alias;
use cbb_core::blind::credential::{self, TYPE_HUBS, TYPE_MEMBERS};
use cbb_core::format::sig::LABEL_CREDENTIAL;
use p256::ecdsa::SigningKey;

use super::*;
use crate::push::{Client, ServerKey};
use crate::relayd::keys::Keys;

/// A platform that keeps what it was given.
#[derive(Default)]
struct Fake {
    got: Mutex<Vec<(u64, Vec<u8>, usize)>>,
    answer: Mutex<Option<Outcome>>,
}

impl Platform for Fake {
    fn send(&self, env: u64, token: &[u8], body: &[u8], _expires: u64) -> Outcome {
        self.got.lock().unwrap().push((env, token.to_vec(), body.len()));
        self.answer.lock().unwrap().clone().unwrap_or(Outcome::Sent)
    }
}

fn period(name: &str) -> SigningKey {
    SigningKey::from_slice(&cbb_core::certs::sha256(name.as_bytes())).unwrap()
}

fn point(k: &SigningKey) -> Vec<u8> {
    k.verifying_key().to_sec1_point(false).as_bytes().to_vec()
}

fn cred(by: &SigningKey, kind: u64, tag: [u8; 16], version: u64, list: &[[u8; 32]]) -> Vec<u8> {
    use cbb_core::format::Value;
    let pk = point(by);
    let expires = now_ms() + 3_600_000;
    let mut m = vec![
        (1, Value::Uint(kind)),
        (2, Value::Bytes(&tag)),
        (3, Value::Array(vec![Value::Uint(1), Value::Bytes(&pk)])),
        (4, Value::Uint(version)),
        (7, Value::Uint(expires)),
    ];
    let hubs = credential::pad(list, credential::LENGTHS_HUBS).unwrap();
    let admins = credential::pad(&[], credential::LENGTHS_ADMINS).unwrap();
    let members = credential::pad(list, credential::LENGTHS_MEMBERS).unwrap();
    if kind == TYPE_HUBS {
        m.push((12, Value::Array(hubs.iter().map(|h| Value::Bytes(h)).collect())));
        m.push((13, Value::Array(admins.iter().map(|h| Value::Bytes(h)).collect())));
    } else {
        m.push((14, Value::Array(members.iter().map(|h| Value::Bytes(h)).collect())));
    }
    let body = Value::Map(m).encode();
    cbb_core::format::envelope::sign(by, LABEL_CREDENTIAL, &body)
}

struct World {
    service: Service,
    fake: Arc<Fake>,
    pin: [u8; 32],
}

fn world(budgets: Budgets) -> World {
    let keys = Keys::new().unwrap();
    let pin = cbb_core::certs::Cert::parse(&keys.cert).unwrap().key_hash();
    let fake = Arc::new(Fake::default());
    let mut platforms: HashMap<u64, Arc<dyn Platform>> = HashMap::new();
    platforms.insert(push::ENV_APNS, fake.clone());
    let service = Service::start(Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        cert: keys.cert.clone(),
        key: keys.key.clone(),
        platforms,
        budgets,
        log: Arc::new(|_| {}),
    })
    .unwrap();
    World { service, fake, pin }
}

/// A member of a group's face: its server key and the credentials.
fn member(tag: [u8; 16], secret: u8, period_name: &str, version: u64, listed: bool) -> (Arc<ServerKey>, Vec<Vec<u8>>) {
    let (d, p) = alias::server_key(&[secret; 32], &tag);
    let key = Arc::new(ServerKey::from_scalar(&d).unwrap());
    let hash = Key::new(Alg::Es256, &p).hash().0;
    let other = Key::new(Alg::Es256, &alias::server_key(&[99; 32], &tag).1).hash().0;
    let pk = period(period_name);
    let list = if listed { vec![hash] } else { vec![other] };
    (key, vec![cred(&pk, TYPE_HUBS, tag, version, &list), cred(&pk, TYPE_MEMBERS, tag, version, &list)])
}

fn refs(c: &[Vec<u8>]) -> Vec<&[u8]> {
    c.iter().map(Vec::as_slice).collect()
}

#[test]
fn a_listed_member_gets_each_copy_through_once() {
    let w = world(Budgets::default());
    let (key, creds) = member([1; 16], 1, "period", 5, true);
    let mut c = Client::connect(w.service.addr(), w.pin, key, &refs(&creds)).unwrap();
    assert!(c.left > 0);
    let body = vec![0u8; push::MAX_BODY];
    let token = [7u8; 32];
    let once = push::once(&[3; 32], &[4; 16]);
    assert_eq!(c.send(&token, push::ENV_APNS, once, &body, None).unwrap().status, push::SENT);
    // A second member of the group sends the same copy: a repeat.
    let (key2, creds2) = member([1; 16], 2, "period", 5, true);
    let mut c2 = Client::connect(w.service.addr(), w.pin, key2, &refs(&creds2)).unwrap();
    assert_eq!(c2.send(&token, push::ENV_APNS, once, &body, None).unwrap().status, push::SENT_REPEAT);
    assert_eq!(w.fake.got.lock().unwrap().len(), 1);
    // A body not of its env's size, and an env the service has no way to.
    assert_eq!(c.send(&token, push::ENV_APNS, [9; 16], &body[..100], None).unwrap().status, push::SENT_FAILED);
    assert_eq!(c.send(&token, push::ENV_FCM, [9; 16], &body, None).unwrap().status, push::SENT_FAILED);
    // A dead token is said so.
    *w.fake.answer.lock().unwrap() = Some(Outcome::Gone);
    assert_eq!(c.send(&token, push::ENV_APNS, [10; 16], &body, None).unwrap().status, push::SENT_GONE);
    // A platform that says later: not counted as sent, so another may try.
    *w.fake.answer.lock().unwrap() = Some(Outcome::Later(Duration::from_secs(30)));
    let r = c.send(&token, push::ENV_APNS, [11; 16], &body, None).unwrap();
    assert_eq!((r.status, r.retry_ms), (push::SENT_FAILED, Some(30_000)));
    *w.fake.answer.lock().unwrap() = None;
    assert_eq!(c2.send(&token, push::ENV_APNS, [11; 16], &body, None).unwrap().status, push::SENT);
    let (tags, tokens, sent) = w.service.stats();
    assert_eq!((tags, tokens, sent), (1, 1, 2));
    w.service.stop();
}

#[test]
fn a_member_the_credentials_leave_out_or_an_old_or_other_period_is_refused() {
    let w = world(Budgets::default());
    let (key, creds) = member([2; 16], 1, "period", 5, false);
    let e = Client::connect(w.service.addr(), w.pin, key, &refs(&creds)).err().unwrap();
    assert!(e.to_string().contains("does not list this device"), "{e}");
    let (key, creds) = member([2; 16], 1, "period", 5, true);
    assert!(Client::connect(w.service.addr(), w.pin, key, &refs(&creds)).is_ok());
    let (key, creds) = member([2; 16], 1, "period", 4, true);
    let e = Client::connect(w.service.addr(), w.pin, key, &refs(&creds)).err().unwrap();
    assert!(e.to_string().contains("older"), "{e}");
    let (key, creds) = member([2; 16], 1, "another period", 6, true);
    let e = Client::connect(w.service.addr(), w.pin, key, &refs(&creds)).err().unwrap();
    assert!(e.to_string().contains("another period key"), "{e}");
    // Only the hubs' credential: refused.
    let (key, creds) = member([3; 16], 1, "period", 1, true);
    let e = Client::connect(w.service.addr(), w.pin, key, &refs(&creds[..1])).err().unwrap();
    assert!(e.to_string().contains("needed"), "{e}");
    // A wrong pin: the TLS fails.
    let (key, creds) = member([3; 16], 1, "period", 1, true);
    assert!(Client::connect(w.service.addr(), [0; 32], key, &refs(&creds)).is_err());
    w.service.stop();
}

#[test]
fn the_budgets_hold_per_token_and_per_tag() {
    let w = world(Budgets { per_token: (3600.0, 2.0), per_tag: (3600.0, 4.0), ..Budgets::default() });
    let (key, creds) = member([4; 16], 1, "period", 1, true);
    let mut c = Client::connect(w.service.addr(), w.pin, key, &refs(&creds)).unwrap();
    let body = vec![0u8; push::MAX_BODY];
    let status =
        |c: &mut Client, token: u8, once: u8| c.send(&[token; 32], push::ENV_APNS, [once; 16], &body, None).unwrap();
    assert_eq!(status(&mut c, 1, 1).status, push::SENT);
    assert_eq!(status(&mut c, 1, 2).status, push::SENT);
    let r = status(&mut c, 1, 3);
    assert_eq!(r.status, push::SENT_BUDGET);
    assert!(r.retry_ms.is_some());
    assert_eq!(status(&mut c, 2, 4).status, push::SENT);
    // The tag's burst of 4 is spent (the refused send took one).
    assert_eq!(status(&mut c, 3, 5).status, push::SENT_BUDGET);
    w.service.stop();
}

#[test]
fn one_address_brings_a_bounded_number_of_new_groups() {
    let w = world(Budgets::default());
    for i in 0..16u8 {
        let (key, creds) = member([100 + i; 16], 1, &format!("period {i}"), 1, true);
        Client::connect(w.service.addr(), w.pin, key, &refs(&creds)).unwrap();
    }
    let (key, creds) = member([200; 16], 1, "period x", 1, true);
    let e = Client::connect(w.service.addr(), w.pin, key, &refs(&creds)).err().unwrap();
    assert!(e.to_string().contains("too many groups"), "{e}");
    // A group already seen still says hello.
    let (key, creds) = member([100; 16], 1, "period 0", 1, true);
    assert!(Client::connect(w.service.addr(), w.pin, key, &refs(&creds)).is_ok());
    assert_eq!(w.service.stats().0, 16);
    w.service.stop();
}

/// A fake HTTP/2 server for one request: reads the preface, the settings,
/// a request, and answers with `status` (indexed when 200, else a literal)
/// and the body.
fn fake_h2(status: u16, body: &'static [u8]) -> (SocketAddr, std::thread::JoinHandle<Vec<u8>>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let t = std::thread::spawn(move || {
        let (mut s, _) = l.accept().unwrap();
        let mut pre = [0u8; 24];
        s.read_exact(&mut pre).unwrap();
        // Our settings first, then read theirs and the request.
        s.write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 0]).unwrap();
        let mut got = Vec::new();
        loop {
            let mut h = [0u8; 9];
            s.read_exact(&mut h).unwrap();
            let len = u32::from_be_bytes([0, h[0], h[1], h[2]]) as usize;
            let mut p = vec![0u8; len];
            s.read_exact(&mut p).unwrap();
            if h[3] == 1 {
                got.extend_from_slice(&p);
            }
            if h[3] == 0 && h[4] & 1 != 0 {
                break;
            }
        }
        let block: Vec<u8> = if status == 200 {
            vec![0x88]
        } else {
            let mut b = vec![0x08, 3];
            b.extend_from_slice(status.to_string().as_bytes());
            b
        };
        let end = if body.is_empty() { 0x5 } else { 0x4 };
        let mut out = vec![0, 0, block.len() as u8, 1, end, 0, 0, 0, 1];
        out.extend_from_slice(&block);
        if !body.is_empty() {
            out.extend_from_slice(&[0, 0, body.len() as u8, 0, 1, 0, 0, 0, 1]);
            out.extend_from_slice(body);
        }
        s.write_all(&out).unwrap();
        // Keep the socket open until the client reads the answer.
        let mut rest = [0u8; 64];
        let _ = s.read(&mut rest);
        got
    });
    (addr, t)
}

#[test]
fn the_http2_client_posts_and_reads_the_status_and_the_body() {
    for (status, body) in [(200u16, &b""[..]), (410, &br#"{"reason":"Unregistered"}"#[..])] {
        let (addr, t) = fake_h2(status, body);
        let s = TcpStream::connect(addr).unwrap();
        let mut c = h2::Conn::start(s).unwrap();
        let a = c.post("api.push.apple.com", "/3/device/00ff", &[("apns-topic", "tools.cbb")], b"{}").unwrap();
        assert_eq!(a.status, Some(status));
        assert_eq!(a.body, body);
        let block = t.join().unwrap();
        assert_eq!(block, h2::header_block("api.push.apple.com", "/3/device/00ff", &[("apns-topic", "tools.cbb")]));
        assert_eq!(apns::outcome(&a), if status == 200 { Outcome::Sent } else { Outcome::Gone });
    }
}

/// Against Apple's sandbox, without a provider token: Apple answers 403
/// with its reason, which shows the HTTP/2 client, its TLS and the
/// reading of an answer on the real server. Run by hand:
/// `CBB_PUSH_LIVE_ROOTS=/etc/ssl/certs/ca-certificates.crt cargo test -p cbb-member pushd::tests::live -- --ignored`.
#[test]
#[ignore = "reaches Apple's sandbox"]
fn live_apple_sandbox_answers_without_a_token() {
    use rustls::pki_types::pem::PemObject;
    let roots = std::env::var("CBB_PUSH_LIVE_ROOTS").unwrap_or("/etc/ssl/certs/ca-certificates.crt".into());
    let mut store = rustls::RootCertStore::empty();
    store.add_parsable_certificates(
        rustls::pki_types::CertificateDer::pem_file_iter(roots).unwrap().filter_map(|c| c.ok()),
    );
    let mut cfg = rustls::ClientConfig::builder_with_provider(Arc::new(cbb_core::tls::web::provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(store)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    let host = apns::SANDBOX;
    let tcp = std::net::ToSocketAddrs::to_socket_addrs(&(host, 443))
        .unwrap()
        .next()
        .map(TcpStream::connect)
        .unwrap()
        .unwrap();
    let conn =
        rustls::ClientConnection::new(Arc::new(cfg), rustls::pki_types::ServerName::try_from(host).unwrap()).unwrap();
    let mut tls = StreamOwned::new(conn, tcp);
    while tls.conn.is_handshaking() {
        tls.conn.complete_io(&mut tls.sock).unwrap();
    }
    assert_eq!(tls.conn.alpn_protocol(), Some(&b"h2"[..]));
    let mut c = h2::Conn::start(tls).unwrap();
    let path = format!("/3/device/{}", "00".repeat(32));
    let a = c
        .post(
            host,
            &path,
            &[("apns-topic", apns::TOPIC), ("apns-push-type", "alert")],
            apns::payload(&[0; 16]).as_bytes(),
        )
        .unwrap();
    std::eprintln!("status {:?} body {}", a.status, String::from_utf8_lossy(&a.body));
    assert!(String::from_utf8_lossy(&a.body).contains("reason"));
    // A second request on the same connection.
    let a = c.post(host, &path, &[("apns-topic", apns::TOPIC)], b"{}").unwrap();
    assert!(String::from_utf8_lossy(&a.body).contains("reason"));
}

// ------------------------------------------------------------ the sender

use crate::pusher::{self, Face, Faces, Role, Saved};
use cbb_core::records::key::{DeviceId, GroupId};

struct OneFace {
    addr: SocketAddr,
    pin: [u8; 32],
    tag: [u8; 16],
}

impl Faces for OneFace {
    fn face(&self, _: &GroupId) -> Option<Face> {
        let (key, credentials) = member(self.tag, 1, "period", 1, true);
        Some(Face { addr: self.addr, pin: self.pin, key, credentials })
    }
}

#[derive(Default)]
struct Kept(Mutex<Vec<(DeviceId, bool)>>);

impl Saved for Kept {
    fn save(&self, _: &GroupId, d: &DeviceId, r: Option<&push::Registration>) {
        self.0.lock().unwrap().push((*d, r.is_some()));
    }
}

fn registration(seq: u64, kinds: u64, key: [u8; 32]) -> Vec<u8> {
    push::Registration {
        seq,
        kinds,
        on: (kinds != 0).then(|| push::On {
            token: vec![5; 32],
            env: push::ENV_APNS,
            key: zeroize::Zeroizing::new(key),
        }),
    }
    .write()
}

fn wait_for(what: impl Fn() -> bool) -> bool {
    let until = Instant::now() + Duration::from_secs(10);
    while Instant::now() < until {
        if what() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

#[test]
fn the_sender_wakes_a_phone_once_and_never_one_that_is_connected() {
    let w = world(Budgets::default());
    let kept = Arc::new(Kept::default());
    let faces = Arc::new(OneFace { addr: w.service.addr(), pin: w.pin, tag: [50; 16] });
    let s = pusher::Sender::start(faces, kept.clone(), Vec::new(), Arc::new(|_| {}));
    let (g, phone, laptop) = (DeviceId([1; 16]), DeviceId([2; 16]), DeviceId([3; 16]));
    let pk = [8u8; 32];
    let f = registration(1, push::KIND_COPIES | push::KIND_EVENTS, pk);
    let m = frame::read(&f, 64 * 1024).unwrap();
    s.registration(&g, &phone, &m.map);
    assert_eq!(s.held(), 1);
    assert_eq!(kept.0.lock().unwrap().as_slice(), &[(phone, true)]);
    // A copy this laptop made: the phone gets the hint that it waits; the
    // laptop, a reader without a registration, nothing.
    let id = [9u8; 16];
    s.copy(&g, &id, Role::Origin, &[phone, laptop], None, &|_| push::Body::Waits { id, origin: [3; 16] });
    assert!(wait_for(|| w.fake.got.lock().unwrap().len() == 1), "nothing sent");
    let (env, token, len) = w.fake.got.lock().unwrap()[0].clone();
    assert_eq!((env, token, len), (push::ENV_APNS, vec![5; 32], push::MAX_BODY));
    // A hub received the same copy: the service drops the repeat.
    s.copy(&g, &id, Role::Hub, &[phone], None, &|_| push::Body::Waits { id, origin: [3; 16] });
    assert!(wait_for(|| s.waiting() == 0));
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(w.fake.got.lock().unwrap().len(), 1);
    // The phone's app is open: nothing goes, and a body queued before it
    // connected is dropped.
    s.copy(&g, &[10; 16], Role::Origin, &[phone], None, &|_| push::Body::Unknown(9));
    s.connected(&phone);
    assert_eq!(s.waiting(), 0);
    s.copy(&g, &[11; 16], Role::Origin, &[phone], None, &|_| push::Body::Unknown(9));
    assert_eq!(s.waiting(), 0);
    s.left(&phone);
    // Neither origin nor hub: nothing.
    s.copy(&g, &[12; 16], Role::Neither, &[phone], None, &|_| push::Body::Unknown(9));
    assert_eq!(s.waiting(), 0);
    // An event: the phone hears of a removal.
    s.event(&g, &[13; 16], push::EVENT_REMOVED, Some(laptop), true, 1);
    assert!(wait_for(|| w.fake.got.lock().unwrap().len() == 2));
    // An older registration changes nothing; push off drops it.
    s.registration(&g, &phone, &frame::read(&registration(1, 0, pk), 1 << 16).unwrap().map);
    assert_eq!(s.held(), 1);
    s.registration(&g, &phone, &frame::read(&registration(2, 0, pk), 1 << 16).unwrap().map);
    assert_eq!(s.held(), 0);
    s.stop();
    w.service.stop();
}

#[test]
fn the_sender_drops_a_token_the_platform_says_is_gone() {
    let w = world(Budgets::default());
    *w.fake.answer.lock().unwrap() = Some(Outcome::Gone);
    let kept = Arc::new(Kept::default());
    let faces = Arc::new(OneFace { addr: w.service.addr(), pin: w.pin, tag: [51; 16] });
    let (g, phone) = (DeviceId([1; 16]), DeviceId([2; 16]));
    let loaded = push::Registration::read(&frame::read(&registration(4, 1, [7; 32]), 1 << 16).unwrap().map).unwrap();
    let s = pusher::Sender::start(faces, kept.clone(), vec![(g, phone, loaded)], Arc::new(|_| {}));
    assert_eq!(s.held(), 1, "the saved registration is back after a restart");
    s.copy(&g, &[1; 16], Role::Origin, &[phone], Some(1), &|_| push::Body::Unknown(9));
    assert!(wait_for(|| s.held() == 0), "the gone token is still held");
    assert_eq!(kept.0.lock().unwrap().last(), Some(&(phone, false)));
    s.stop();
    w.service.stop();
}
