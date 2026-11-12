// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The push service against a fake platform: a member with its face's
//! credentials gets its bodies through once each, within the budgets, and
//! only with the token's send key and a seq no lower than the highest seen,
//! across a restart too; a member the credentials leave out, an older
//! credential or another period key is refused. And the HTTP/2 client
//! against a fake server.

use std::sync::Mutex;

use cbb_core::blind::alias;
use cbb_core::blind::credential::{self, TYPE_HUBS, TYPE_MEMBERS};
use cbb_core::format::sig::LABEL_CREDENTIAL;
use p256::ecdsa::SigningKey;

use super::*;
use crate::push::{Client, ServerKey};
use crate::relayd::keys::Keys;
use cbb_core::format::Value;

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
    world_at(budgets, None)
}

fn world_at(budgets: Budgets, state: Option<PathBuf>) -> World {
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
        state,
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

/// A phone's send key, from a byte.
fn send_key(b: u8) -> ServerKey {
    ServerKey::from_scalar(&[b; 32]).unwrap()
}

/// The send key's half of a registration: the key and its signature over
/// (env, token, seq).
fn signed(k: &ServerKey, env: u64, token: &[u8], seq: u64) -> (cbb_core::records::key::Key, Vec<u8>) {
    let sig = push::sign_send(k, env, token, seq).unwrap();
    (cbb_core::records::key::Key::es256(cbb_core::identity::ExternalKey::public(k)), sig.to_vec())
}

/// Sends body to token of env under the phone's send key `k` and seq.
fn send(c: &mut Client, k: &ServerKey, env: u64, token: &[u8], seq: u64, body: &[u8]) -> push::Sent {
    let (key, sig) = signed(k, env, token, seq);
    c.send(push::Send { n: 0, token, env, body, ttl: None, key, sig: &sig, seq }).unwrap()
}

/// A body of the platform's size, its bytes from b.
fn body(b: u8) -> Vec<u8> {
    vec![b; push::MAX_BODY]
}

#[test]
fn a_listed_member_gets_each_copy_through_once() {
    let w = world(Budgets::default());
    let (key, creds) = member([1; 16], 1, "period", 5, true);
    let mut c = Client::connect(w.service.addr(), w.pin, key, &refs(&creds)).unwrap();
    assert!(c.left > 0);
    let phone = send_key(3);
    let token = [7u8; 32];
    assert_eq!(send(&mut c, &phone, push::ENV_APNS, &token, 1, &body(0)).status, push::SENT);
    // A second member of the group sends the same body: a repeat.
    let (key2, creds2) = member([1; 16], 2, "period", 5, true);
    let mut c2 = Client::connect(w.service.addr(), w.pin, key2, &refs(&creds2)).unwrap();
    assert_eq!(send(&mut c2, &phone, push::ENV_APNS, &token, 1, &body(0)).status, push::SENT_REPEAT);
    assert_eq!(w.fake.got.lock().unwrap().len(), 1);
    // The same body to another token is no repeat.
    assert_eq!(send(&mut c2, &send_key(4), push::ENV_APNS, &[8; 32], 1, &body(0)).status, push::SENT);
    // A body not of its env's size, and an env the service has no way to.
    assert_eq!(send(&mut c, &phone, push::ENV_APNS, &token, 1, &body(9)[..100]).status, push::SENT_FAILED);
    assert_eq!(send(&mut c, &phone, push::ENV_FCM, &token, 1, &body(9)).status, push::SENT_FAILED);
    // A dead token is said so.
    *w.fake.answer.lock().unwrap() = Some(Outcome::Gone);
    assert_eq!(send(&mut c, &phone, push::ENV_APNS, &token, 1, &body(10)).status, push::SENT_GONE);
    // A platform that says later: not counted as sent, so another may try.
    *w.fake.answer.lock().unwrap() = Some(Outcome::Later(Duration::from_secs(30)));
    let r = send(&mut c, &phone, push::ENV_APNS, &token, 1, &body(11));
    assert_eq!((r.status, r.retry_ms), (push::SENT_FAILED, Some(30_000)));
    *w.fake.answer.lock().unwrap() = None;
    assert_eq!(send(&mut c2, &phone, push::ENV_APNS, &token, 1, &body(11)).status, push::SENT);
    let (tags, tokens, sent) = w.service.stats();
    assert_eq!((tags, tokens, sent), (1, 2, 3));
    w.service.stop();
}

#[test]
fn a_send_needs_the_tokens_send_key_and_a_seq_no_lower_than_seen() {
    let w = world(Budgets::default());
    let (key, creds) = member([5; 16], 1, "period", 1, true);
    let mut c = Client::connect(w.service.addr(), w.pin, key, &refs(&creds)).unwrap();
    let (phone, other) = (send_key(3), send_key(4));
    let token = [7u8; 32];
    assert_eq!(send(&mut c, &phone, push::ENV_APNS, &token, 10, &body(1)).status, push::SENT);
    assert_eq!(w.service.bindings(), 1);
    // Another key for the bound token: stale, whatever its seq.
    assert_eq!(send(&mut c, &other, push::ENV_APNS, &token, 11, &body(2)).status, push::SENT_STALE);
    // The phone registered again with seq 12: the old seq passes until the
    // first send under the new one, then never again.
    assert_eq!(send(&mut c, &phone, push::ENV_APNS, &token, 10, &body(3)).status, push::SENT);
    assert_eq!(send(&mut c, &phone, push::ENV_APNS, &token, 12, &body(4)).status, push::SENT);
    assert_eq!(send(&mut c, &phone, push::ENV_APNS, &token, 10, &body(5)).status, push::SENT_STALE);
    assert_eq!(send(&mut c, &phone, push::ENV_APNS, &token, 12, &body(6)).status, push::SENT);
    // A signature over another seq, token or env than the send's.
    let (k, sig) = signed(&phone, push::ENV_APNS, &token, 13);
    let r = c.send(push::Send {
        n: 0,
        token: &token,
        env: push::ENV_APNS,
        body: &body(7),
        ttl: None,
        key: k,
        sig: &sig,
        seq: 14,
    });
    assert_eq!(r.unwrap().status, push::SENT_STALE);
    let (k, sig) = signed(&phone, push::ENV_APNS_SANDBOX, &token, 13);
    let r = c.send(push::Send {
        n: 0,
        token: &token,
        env: push::ENV_APNS,
        body: &body(7),
        ttl: None,
        key: k,
        sig: &sig,
        seq: 13,
    });
    assert_eq!(r.unwrap().status, push::SENT_STALE);
    // A send key of an algorithm the service does not take.
    let unknown = cbb_core::records::key::Key { alg: 77, public: vec![1; 40] };
    let r = c.send(push::Send {
        n: 0,
        token: &[9; 32],
        env: push::ENV_APNS,
        body: &body(8),
        ttl: None,
        key: unknown,
        sig: &[2; 64],
        seq: 1,
    });
    assert_eq!(r.unwrap().status, push::SENT_KEY);
    assert_eq!(w.fake.got.lock().unwrap().len(), 4);
    w.service.stop();
}

#[test]
fn the_bindings_outlive_a_restart() {
    let dir = std::env::temp_dir().join(format!("cbb-push-state-{}", cbb_core::certs::random_id()));
    std::fs::create_dir_all(&dir).unwrap();
    let state = dir.join("push.state");
    let phone = send_key(3);
    let token = [7u8; 32];
    {
        let w = world_at(Budgets::default(), Some(state.clone()));
        let (key, creds) = member([6; 16], 1, "period", 1, true);
        let mut c = Client::connect(w.service.addr(), w.pin, key, &refs(&creds)).unwrap();
        assert_eq!(send(&mut c, &phone, push::ENV_APNS, &token, 20, &body(1)).status, push::SENT);
        w.service.stop();
    }
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(std::fs::metadata(&state).unwrap().permissions().mode() & 0o777, 0o600);
    let w = world_at(Budgets::default(), Some(state.clone()));
    assert_eq!(w.service.bindings(), 1);
    let (key, creds) = member([6; 16], 1, "period", 1, true);
    let mut c = Client::connect(w.service.addr(), w.pin, key, &refs(&creds)).unwrap();
    assert_eq!(send(&mut c, &phone, push::ENV_APNS, &token, 19, &body(2)).status, push::SENT_STALE);
    assert_eq!(send(&mut c, &send_key(4), push::ENV_APNS, &token, 30, &body(3)).status, push::SENT_STALE);
    assert_eq!(send(&mut c, &phone, push::ENV_APNS, &token, 20, &body(4)).status, push::SENT);
    w.service.stop();
    // A state file that does not read stops the service from starting.
    std::fs::write(&state, b"something else").unwrap();
    let keys = Keys::new().unwrap();
    let e = Service::start(Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        cert: keys.cert.clone(),
        key: keys.key.clone(),
        platforms: HashMap::new(),
        budgets: Budgets::default(),
        state: Some(state.clone()),
        log: Arc::new(|_| {}),
    });
    assert!(e.is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_binding_ends_thirty_days_after_its_last_send() {
    let day = 24 * 3600 * 1000;
    let b = bind(None, [1; 32], 5, 1000).unwrap();
    assert_eq!(b, Binding { key: [1; 32], seq: 5, used_ms: 1000 });
    assert_eq!(bind(Some(&b), [1; 32], 4, 2000), None);
    assert_eq!(bind(Some(&b), [2; 32], 9, 2000), None);
    assert_eq!(bind(Some(&b), [1; 32], 5, 2000), Some(Binding { key: [1; 32], seq: 5, used_ms: 2000 }));
    assert_eq!(bind(Some(&b), [2; 32], 1, 1000 + 30 * day - 1), None);
    assert_eq!(
        bind(Some(&b), [2; 32], 1, 1000 + 30 * day),
        Some(Binding { key: [2; 32], seq: 1, used_ms: 1000 + 30 * day })
    );
    // A clock that went back keeps the later time.
    assert_eq!(bind(Some(&b), [1; 32], 6, 10).map(|b| b.used_ms), Some(1000));
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
    let phone = send_key(3);
    let status = |c: &mut Client, token: u8, b: u8| send(c, &phone, push::ENV_APNS, &[token; 32], 1, &body(b));
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

/// The test tool for a real phone (never in a release): it says hello to
/// a running cbb-push as a group of its own, seals an event or a "copy
/// waits" body to the phone's registration and sends it, so APNs, the
/// notification extension and `push_open` are tried on the device before
/// the member's sync sends real ones. The registration is the frame the
/// app's test row copies (Settings, with the launch argument
/// `-PushTestTools YES`). Run by hand:
/// `CBB_PUSH_LIVE_ADDR=host:8767 CBB_PUSH_LIVE_PIN=<base64> CBB_PUSH_LIVE_REG=<base64 frame>
/// [CBB_PUSH_LIVE_KIND=event|waits] cargo test -p cbb-member pushd::tests::live_push -- --ignored --nocapture`.
#[test]
#[ignore = "sends to a real phone through a running cbb-push"]
fn live_push_to_a_phone() {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    let env = |k: &str| std::env::var(k).unwrap_or_else(|_| panic!("set {k}"));
    let addr = std::net::ToSocketAddrs::to_socket_addrs(&env("CBB_PUSH_LIVE_ADDR")).unwrap().next().unwrap();
    let pin: [u8; 32] = STANDARD.decode(env("CBB_PUSH_LIVE_PIN")).unwrap().try_into().unwrap();
    let frame = STANDARD.decode(env("CBB_PUSH_LIVE_REG")).unwrap();
    let r = push::Registration::read(&frame::read(&frame, 1 << 16).unwrap().map).unwrap();
    let on = r.on.as_ref().expect("the registration has push off");
    let id: [u8; 16] = cbb_core::certs::random_bytes();
    let body = match std::env::var("CBB_PUSH_LIVE_KIND").as_deref() {
        Ok("waits") => push::Body::Waits { id, origin: [1; 16] },
        _ => push::Body::Event { id, event: push::EVENT_JOINED, device: None, time_ms: Some(now_ms()) },
    };
    let sealed = push::seal(&on.key, r.seq, on.env, &body).unwrap();
    let tag: [u8; 16] = cbb_core::certs::random_bytes();
    let (key, creds) = member(tag, 1, &format!("live {}", STANDARD.encode(tag)), 1, true);
    let mut c = Client::connect(addr, pin, key, &refs(&creds)).unwrap();
    let sent = c
        .send(push::Send {
            n: 0,
            token: &on.token,
            env: on.env,
            body: &sealed,
            ttl: Some(2),
            key: on.send_key.clone(),
            sig: &on.send_sig,
            seq: r.seq,
        })
        .unwrap();
    std::eprintln!("status {} retry {:?}", sent.status, sent.retry_ms);
    assert_eq!(sent.status, push::SENT);
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

/// The phone's registration frame, signed with its send key `send_key(1)`.
fn registration(seq: u64, kinds: u64, key: [u8; 32]) -> Vec<u8> {
    let token = vec![5; 32];
    let (send_key, send_sig) = signed(&send_key(1), push::ENV_APNS, &token, seq);
    push::Registration {
        seq,
        kinds,
        on: (kinds != 0).then(|| push::On {
            token,
            env: push::ENV_APNS,
            key: zeroize::Zeroizing::new(key),
            send_key,
            send_sig,
        }),
    }
    .write()
    .unwrap()
}

fn read_reg(f: &[u8]) -> Value<'_> {
    frame::read(f, 1 << 16).unwrap().map
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

fn sender(w: &World, tag: u8) -> (pusher::Sender, Arc<Kept>) {
    let kept = Arc::new(Kept::default());
    let faces = Arc::new(OneFace { addr: w.service.addr(), pin: w.pin, tag: [tag; 16] });
    (pusher::Sender::start(faces, kept.clone(), Vec::new(), Arc::new(|_| {})), kept)
}

const PHONE: u64 = cbb_core::records::body::ROLE_PHONE;

#[test]
fn the_sender_wakes_a_phone_once_and_never_one_that_is_connected() {
    let w = world(Budgets::default());
    let (s, kept) = sender(&w, 50);
    let (g, phone, laptop) = (DeviceId([1; 16]), DeviceId([2; 16]), DeviceId([3; 16]));
    let pk = [8u8; 32];
    let f = registration(1, push::KIND_COPIES | push::KIND_EVENTS, pk);
    s.registration(&g, &phone, PHONE, &read_reg(&f));
    assert_eq!(s.held(), 1);
    assert_eq!(kept.0.lock().unwrap().as_slice(), &[(phone, true)]);
    // A copy this laptop made: the phone gets the hint that it waits; the
    // laptop, a reader without a registration, nothing.
    let id = [9u8; 16];
    let waits = |_: &DeviceId| Some(push::Body::Waits { id, origin: [3; 16] });
    s.copy(&g, Role::Origin, &[phone, laptop], None, &waits);
    assert!(wait_for(|| w.fake.got.lock().unwrap().len() == 1), "nothing sent");
    let (env, token, len) = w.fake.got.lock().unwrap()[0].clone();
    assert_eq!((env, token, len), (push::ENV_APNS, vec![5; 32], push::MAX_BODY));
    // A hub received the same copy and made the same body: the service
    // drops the repeat.
    s.copy(&g, Role::Hub, &[phone], None, &waits);
    assert!(wait_for(|| s.waiting() == 0));
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(w.fake.got.lock().unwrap().len(), 1);
    // The phone's app is open: nothing goes, and a body queued before it
    // connected is dropped.
    s.copy(&g, Role::Origin, &[phone], None, &|_| Some(push::Body::Unknown(9)));
    s.connected(&phone);
    assert_eq!(s.waiting(), 0);
    s.copy(&g, Role::Origin, &[phone], None, &|_| Some(push::Body::Unknown(9)));
    assert_eq!(s.waiting(), 0);
    s.left(&phone);
    // Neither origin nor hub: nothing. A copy not sealed to the phone:
    // nothing either.
    s.copy(&g, Role::Neither, &[phone], None, &|_| Some(push::Body::Unknown(9)));
    s.copy(&g, Role::Origin, &[phone], None, &|_| None);
    assert_eq!(s.waiting(), 0);
    // An event: the phone hears of a removal.
    s.event(&g, &[13; 16], push::EVENT_REMOVED, Some(laptop), true, Some(1));
    assert!(wait_for(|| w.fake.got.lock().unwrap().len() == 2));
    // A device that does not send events sends none.
    s.event(&g, &[14; 16], push::EVENT_REMOVED, Some(laptop), false, Some(1));
    assert_eq!(s.waiting(), 0);
    // An older registration changes nothing; push off drops it.
    s.registration(&g, &phone, PHONE, &read_reg(&registration(1, 0, pk)));
    assert_eq!(s.held(), 1);
    s.registration(&g, &phone, PHONE, &read_reg(&registration(2, 0, pk)));
    assert_eq!(s.held(), 0);
    assert_eq!(kept.0.lock().unwrap().last(), Some(&(phone, false)));
    s.stop();
    w.service.stop();
}

#[test]
fn only_a_phone_or_a_computer_registers_and_only_for_the_kinds_it_asks() {
    use cbb_core::records::body::{ROLE_LEAF, ROLE_MEMBER, ROLE_WATCH};
    let w = world(Budgets::default());
    let (s, _) = sender(&w, 52);
    let (g, phone) = (DeviceId([1; 16]), DeviceId([2; 16]));
    let f = registration(1, push::KIND_EVENTS, [8; 32]);
    for role in [ROLE_LEAF, ROLE_WATCH, 0, 99] {
        s.registration(&g, &phone, role, &read_reg(&f));
        assert_eq!(s.held(), 0, "role {role} registered");
    }
    s.registration(&g, &phone, ROLE_MEMBER, &read_reg(&f));
    assert_eq!(s.held(), 1);
    // It asked for events only: a copy wakes nothing, an event does.
    s.copy(&g, Role::Origin, &[phone], None, &|_| Some(push::Body::Unknown(9)));
    assert_eq!(s.waiting(), 0);
    s.event(&g, &[1; 16], push::EVENT_JOINED, None, true, Some(5));
    assert_eq!(s.waiting(), 1);
    // A newer registration drops what waited under the older one.
    s.registration(&g, &phone, ROLE_MEMBER, &read_reg(&registration(2, push::KIND_COPIES, [9; 32])));
    assert_eq!(s.waiting(), 0);
    s.event(&g, &[2; 16], push::EVENT_JOINED, None, true, Some(5));
    assert_eq!(s.waiting(), 0);
    // A message that is not a registration changes nothing.
    s.registration(&g, &phone, ROLE_MEMBER, &Value::Map(vec![]));
    assert_eq!(s.held(), 1);
    s.stop();
    w.service.stop();
}

#[test]
fn a_removed_or_frozen_device_is_forgotten() {
    let w = world(Budgets::default());
    let (s, kept) = sender(&w, 53);
    let (g, other, phone) = (DeviceId([1; 16]), DeviceId([9; 16]), DeviceId([2; 16]));
    s.registration(&g, &phone, PHONE, &read_reg(&registration(1, push::KIND_COPIES, [8; 32])));
    s.registration(&other, &phone, PHONE, &read_reg(&registration(1, push::KIND_COPIES, [8; 32])));
    s.copy(&g, Role::Origin, &[phone], None, &|_| Some(push::Body::Unknown(9)));
    assert_eq!((s.held(), s.waiting()), (2, 1));
    s.forget(&g, &phone);
    assert_eq!((s.held(), s.waiting()), (1, 0), "only the group's registration goes");
    assert_eq!(kept.0.lock().unwrap().last(), Some(&(phone, false)));
    s.stop();
    w.service.stop();
}

#[test]
fn the_sender_drops_a_send_the_service_finds_stale() {
    let w = world(Budgets::default());
    let (s, _) = sender(&w, 54);
    let (g, phone) = (DeviceId([1; 16]), DeviceId([2; 16]));
    // A registration whose signature is over another seq than its own.
    let token = vec![5; 32];
    let (send_key, send_sig) = signed(&send_key(1), push::ENV_APNS, &token, 2);
    let r = push::Registration {
        seq: 3,
        kinds: push::KIND_COPIES,
        on: Some(push::On { token, env: push::ENV_APNS, key: zeroize::Zeroizing::new([8; 32]), send_key, send_sig }),
    };
    s.registration(&g, &phone, PHONE, &read_reg(&r.write().unwrap()));
    s.copy(&g, Role::Origin, &[phone], None, &|_| Some(push::Body::Unknown(9)));
    assert_eq!(s.waiting(), 1);
    // The service answered (its tag is held) and the job did not come back.
    assert!(wait_for(|| w.service.stats().0 == 1 && s.waiting() == 0));
    std::thread::sleep(Duration::from_secs(1));
    assert_eq!(s.waiting(), 0);
    assert!(w.fake.got.lock().unwrap().is_empty());
    assert_eq!(s.held(), 1, "the registration is kept");
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
    let loaded = push::Registration::read(&read_reg(&registration(4, 1, [7; 32]))).unwrap();
    let s = pusher::Sender::start(faces, kept.clone(), vec![(g, phone, loaded)], Arc::new(|_| {}));
    assert_eq!(s.held(), 1, "the saved registration is back after a restart");
    s.copy(&g, Role::Origin, &[phone], Some(1), &|_| Some(push::Body::Unknown(9)));
    assert!(wait_for(|| s.held() == 0), "the gone token is still held");
    assert_eq!(kept.0.lock().unwrap().last(), Some(&(phone, false)));
    s.stop();
    w.service.stop();
}
