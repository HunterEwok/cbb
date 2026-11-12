// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The push service against a fake platform: a member with its face's
//! credentials gets its bodies through once each, within the budgets; a
//! token's key is confirmed by the challenge the platform carried, and then
//! only that key sends, with a seq per slot no lower than the highest seen,
//! across a restart too; a member the credentials leave out, an older
//! credential or another period key is refused; a body on its way is never
//! made a repeat. And the HTTP/2 client against a fake server.

use std::sync::Mutex;

use cbb_core::blind::alias;
use cbb_core::blind::credential::{self, TYPE_HUBS, TYPE_MEMBERS};
use cbb_core::format::sig::LABEL_CREDENTIAL;
use p256::ecdsa::SigningKey;

use super::*;
use crate::push::{Client, ServerKey};
use crate::relayd::keys::Keys;
use cbb_core::format::Value;

/// What the fake platform was handed.
#[derive(Clone, Debug)]
struct Got {
    env: u64,
    token: Vec<u8>,
    /// The body's length; None for a challenge alone.
    body: Option<usize>,
    challenge: Option<Challenge>,
    expires_s: u64,
}

/// A platform that keeps what it was given.
#[derive(Default)]
struct Fake {
    got: Mutex<Vec<Got>>,
    answer: Mutex<Option<Outcome>>,
    /// How long it takes to answer.
    delay: Mutex<Duration>,
}

impl Platform for Fake {
    fn send(&self, d: &Delivery<'_>) -> Outcome {
        let delay = *self.delay.lock().unwrap();
        std::thread::sleep(delay);
        self.got.lock().unwrap().push(Got {
            env: d.env,
            token: d.token.to_vec(),
            body: d.body.map(<[u8]>::len),
            challenge: d.challenge,
            expires_s: d.expires_s,
        });
        self.answer.lock().unwrap().clone().unwrap_or(Outcome::Sent)
    }
}

impl Fake {
    /// The bodies it was handed (challenges alone left out).
    fn bodies(&self) -> usize {
        self.got.lock().unwrap().iter().filter(|g| g.body.is_some()).count()
    }

    /// The last challenge it carried to token.
    fn challenge(&self, token: &[u8]) -> Option<[u8; 16]> {
        self.got.lock().unwrap().iter().rev().find(|g| g.token == token).and_then(|g| g.challenge).map(|c| c.value)
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
        new_state: state.as_ref().is_some_and(|p| !p.exists()),
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

/// The slot of the phone's registration in the tests' group.
const SLOT: [u8; 16] = [1; 16];

/// The send key's half of a registration: the key and its signature over
/// (env, token, slot, seq[, challenge]).
fn signed_by(
    k: &ServerKey,
    env: u64,
    token: &[u8],
    slot: [u8; 16],
    seq: u64,
    challenge: Option<[u8; 16]>,
) -> (cbb_core::records::key::Key, Vec<u8>) {
    let s = push::Signed { env, token, slot: &slot, seq, challenge: challenge.as_ref() };
    let sig = push::sign_send(k, &s).unwrap();
    (cbb_core::records::key::Key::es256(cbb_core::identity::ExternalKey::public(k)), sig.to_vec())
}

fn signed(k: &ServerKey, env: u64, token: &[u8], seq: u64) -> (cbb_core::records::key::Key, Vec<u8>) {
    signed_by(k, env, token, SLOT, seq, None)
}

/// One send as a member makes it from a registration.
struct S<'a> {
    k: &'a ServerKey,
    env: u64,
    token: &'a [u8],
    slot: [u8; 16],
    seq: u64,
    challenge: Option<[u8; 16]>,
    ttl: Option<u64>,
}

impl S<'_> {
    fn send(&self, c: &mut Client, body: &[u8]) -> push::Sent {
        let (key, sig) = signed_by(self.k, self.env, self.token, self.slot, self.seq, self.challenge);
        c.send(push::Send {
            n: 0,
            token: self.token,
            env: self.env,
            body,
            ttl: self.ttl,
            key,
            sig: &sig,
            seq: self.seq,
            slot: self.slot,
            challenge: self.challenge,
        })
        .unwrap()
    }
}

fn s<'a>(k: &'a ServerKey, env: u64, token: &'a [u8], seq: u64) -> S<'a> {
    S { k, env, token, slot: SLOT, seq, challenge: None, ttl: None }
}

/// Sends body to token of env under the phone's send key `k` and seq.
fn send(c: &mut Client, k: &ServerKey, env: u64, token: &[u8], seq: u64, body: &[u8]) -> push::Sent {
    s(k, env, token, seq).send(c, body)
}

/// The phone confirms its key for token: it sends over the challenge the
/// platform carried with its last body.
fn confirm(w: &World, c: &mut Client, k: &ServerKey, token: &[u8], seq: u64, b: u8) -> push::Sent {
    let ch = w.fake.challenge(token).expect("no challenge reached the token");
    S { challenge: Some(ch), ..s(k, push::ENV_APNS, token, seq) }.send(c, &body(b))
}

/// seq as a clock, as the phone numbers its registrations.
fn now_seq(plus: u64) -> u64 {
    now_ms() + plus
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
    assert_eq!(w.fake.bodies(), 1);
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
fn a_key_is_confirmed_by_its_challenge_and_then_only_it_sends() {
    let w = world(Budgets::default());
    let (key, creds) = member([5; 16], 1, "period", 1, true);
    let mut c = Client::connect(w.service.addr(), w.pin, key, &refs(&creds)).unwrap();
    let (phone, stranger) = (send_key(3), send_key(4));
    let token = [7u8; 32];
    let t0 = now_seq(0);
    // A stranger who knows the token sends first, under its own key: it
    // passes (nothing is confirmed), with a challenge for its key, which
    // only the token's holder sees.
    assert_eq!(send(&mut c, &stranger, push::ENV_APNS, &token, t0, &body(1)).status, push::SENT);
    let for_stranger = w.fake.challenge(&token).unwrap();
    // The phone's own key is never refused before it confirms.
    assert_eq!(send(&mut c, &phone, push::ENV_APNS, &token, t0, &body(2)).status, push::SENT);
    let for_phone = w.fake.challenge(&token).unwrap();
    assert_ne!(for_stranger, for_phone);
    // The stranger's challenge confirms nothing for the phone's key, nor
    // a made-up one.
    let wrong = S { challenge: Some(for_stranger), ..s(&phone, push::ENV_APNS, &token, t0) };
    assert_eq!(wrong.send(&mut c, &body(3)).status, push::SENT);
    assert_eq!(
        w.service
            .inner
            .lock()
            .bindings
            .get(&w.service.inner.keyed(b"token", &push::ENV_APNS.to_be_bytes(), &token))
            .map(Binding::confirmed),
        Some(false)
    );
    // The phone registers again over its challenge: confirmed.
    assert_eq!(confirm(&w, &mut c, &phone, &token, t0 + 1, 4).status, push::SENT);
    // From now the stranger is refused, whatever its seq, and the platform
    // carries a challenge for its key alone (no body); the phone's sends
    // pass.
    let bodies = w.fake.bodies();
    assert_eq!(send(&mut c, &stranger, push::ENV_APNS, &token, t0 + 2, &body(5)).status, push::SENT_STALE);
    assert_eq!(w.fake.bodies(), bodies);
    assert!(w.fake.got.lock().unwrap().last().is_some_and(|g| g.body.is_none() && g.challenge.is_some()));
    assert_eq!(send(&mut c, &phone, push::ENV_APNS, &token, t0 + 1, &body(6)).status, push::SENT);
    // seq per slot: the phone registered again with a higher seq; the old
    // one is stale after that, never before.
    assert_eq!(send(&mut c, &phone, push::ENV_APNS, &token, t0 + 5, &body(7)).status, push::SENT);
    assert_eq!(send(&mut c, &phone, push::ENV_APNS, &token, t0 + 1, &body(8)).status, push::SENT_STALE);
    // A seq more than a day ahead of the service's clock: refused.
    let ahead = t0 + push::MAX_SEQ_AHEAD_MS + 60_000;
    assert_eq!(send(&mut c, &phone, push::ENV_APNS, &token, ahead, &body(9)).status, push::SENT_STALE);
    w.service.stop();
}

#[test]
fn a_phone_in_two_groups_gets_push_from_both() {
    let w = world(Budgets::default());
    let (ka, ca) = member([20; 16], 1, "period a", 1, true);
    let (kb, cb) = member([21; 16], 1, "period b", 1, true);
    let mut a = Client::connect(w.service.addr(), w.pin, ka, &refs(&ca)).unwrap();
    let mut b = Client::connect(w.service.addr(), w.pin, kb, &refs(&cb)).unwrap();
    let phone = send_key(3);
    let token = [7u8; 32];
    let (slot_a, slot_b) = ([1u8; 16], [2u8; 16]);
    let t0 = now_seq(0);
    let in_a = |seq, ch| S { slot: slot_a, challenge: ch, ..s(&phone, push::ENV_APNS, &token, seq) };
    let in_b = |seq| S { slot: slot_b, ..s(&phone, push::ENV_APNS, &token, seq) };
    assert_eq!(in_a(t0, None).send(&mut a, &body(1)).status, push::SENT);
    let ch = w.fake.challenge(&token);
    assert_eq!(in_a(t0 + 1, ch).send(&mut a, &body(2)).status, push::SENT);
    // Group B's registration is five minutes newer; A's sends still pass,
    // as many times as they come.
    assert_eq!(in_b(t0 + 300_000).send(&mut b, &body(3)).status, push::SENT);
    for i in 0..3 {
        assert_eq!(in_a(t0 + 1, ch).send(&mut a, &body(10 + i)).status, push::SENT, "A's copy {i}");
        assert_eq!(in_b(t0 + 300_000).send(&mut b, &body(20 + i)).status, push::SENT, "B's copy {i}");
    }
    // A registers again: A's old registration is stale, B untouched.
    assert_eq!(in_a(t0 + 600_000, None).send(&mut a, &body(30)).status, push::SENT);
    assert_eq!(in_a(t0 + 1, ch).send(&mut a, &body(31)).status, push::SENT_STALE);
    assert_eq!(in_b(t0 + 300_000).send(&mut b, &body(32)).status, push::SENT);
    w.service.stop();
}

#[test]
fn a_send_that_does_not_hold_is_refused_and_too_many_close_the_connection() {
    let w = world(Budgets::default());
    let (key, creds) = member([5; 16], 1, "period", 1, true);
    let mut c = Client::connect(w.service.addr(), w.pin, key, &refs(&creds)).unwrap();
    let phone = send_key(3);
    let token = [7u8; 32];
    // A signature over another seq, slot, token or env than the send's.
    let t0 = now_seq(0);
    for (env, slot, seq) in
        [(push::ENV_APNS, SLOT, t0 + 1), (push::ENV_APNS, [9; 16], t0), (push::ENV_APNS_SANDBOX, SLOT, t0)]
    {
        let (k, sig) = signed_by(&phone, env, &token, slot, seq, None);
        let r = c.send(push::Send {
            n: 0,
            token: &token,
            env: push::ENV_APNS,
            body: &body(7),
            ttl: None,
            key: k,
            sig: &sig,
            seq: t0,
            slot: SLOT,
            challenge: None,
        });
        assert_eq!(r.unwrap().status, push::SENT_STALE);
    }
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
        slot: SLOT,
        challenge: None,
    });
    assert_eq!(r.unwrap().status, push::SENT_KEY);
    assert_eq!(w.fake.bodies(), 0);
    // The eighth refusal is answered, and then the service closes the
    // connection.
    for _ in 0..4 {
        assert_eq!(send(&mut c, &phone, push::ENV_APNS, &token, t0, &body(9)[..100]).status, push::SENT_FAILED);
    }
    let (k, sig) = signed(&phone, push::ENV_APNS, &token, 1);
    let r = c.send(push::Send {
        n: 0,
        token: &token,
        env: push::ENV_APNS,
        body: &body(1),
        ttl: None,
        key: k,
        sig: &sig,
        seq: 2,
        slot: SLOT,
        challenge: None,
    });
    assert!(r.is_err(), "the connection stayed open: {r:?}");
    w.service.stop();
}

#[test]
fn a_body_on_its_way_is_never_made_a_repeat() {
    let w = world(Budgets::default());
    *w.fake.delay.lock().unwrap() = Duration::from_millis(1500);
    let phone = send_key(3);
    let token = [7u8; 32];
    let t0 = now_seq(0);
    let (k1, c1) = member([5; 16], 1, "period", 1, true);
    let (k2, c2) = member([5; 16], 2, "period", 1, true);
    let addr = w.service.addr();
    let pin = w.pin;
    let first = std::thread::spawn(move || {
        let mut c = Client::connect(addr, pin, k1, &refs(&c1)).unwrap();
        send(&mut c, &send_key(3), push::ENV_APNS, &[7u8; 32], t0, &body(1))
    });
    std::thread::sleep(Duration::from_millis(500));
    let mut c = Client::connect(addr, pin, k2, &refs(&c2)).unwrap();
    // While the first is with the platform: try again shortly.
    let r = send(&mut c, &phone, push::ENV_APNS, &token, t0, &body(1));
    assert_eq!((r.status, r.retry_ms), (push::SENT_FAILED, Some(IN_FLIGHT_WAIT_MS)));
    assert_eq!(first.join().unwrap().status, push::SENT);
    // Taken: now it is a repeat.
    assert_eq!(send(&mut c, &phone, push::ENV_APNS, &token, t0, &body(1)).status, push::SENT_REPEAT);
    // A platform that said later: the next try is sent, not a repeat.
    *w.fake.delay.lock().unwrap() = Duration::ZERO;
    *w.fake.answer.lock().unwrap() = Some(Outcome::Later(Duration::from_secs(1)));
    assert_eq!(send(&mut c, &phone, push::ENV_APNS, &token, t0, &body(2)).status, push::SENT_FAILED);
    *w.fake.answer.lock().unwrap() = None;
    assert_eq!(send(&mut c, &phone, push::ENV_APNS, &token, t0, &body(2)).status, push::SENT);
    // A later expiry passes once; then it is a repeat.
    let short = S { ttl: Some(1), ..s(&phone, push::ENV_APNS, &token, t0) };
    let long = S { ttl: Some(4), ..s(&phone, push::ENV_APNS, &token, t0) };
    assert_eq!(short.send(&mut c, &body(3)).status, push::SENT);
    assert_eq!(long.send(&mut c, &body(3)).status, push::SENT);
    assert_eq!(long.send(&mut c, &body(3)).status, push::SENT_REPEAT);
    assert_eq!(short.send(&mut c, &body(3)).status, push::SENT_REPEAT);
    let got = w.fake.got.lock().unwrap();
    let last = got.iter().rev().take(2).map(|g| g.expires_s).collect::<Vec<_>>();
    assert!(last[0] > last[1] + 80_000, "{last:?}");
    drop(got);
    w.service.stop();
}

#[test]
fn a_gone_token_leaves_nothing_behind() {
    let w = world(Budgets::default());
    *w.fake.answer.lock().unwrap() = Some(Outcome::Gone);
    let (key, creds) = member([5; 16], 1, "period", 1, true);
    let mut c = Client::connect(w.service.addr(), w.pin, key, &refs(&creds)).unwrap();
    for i in 0..20u8 {
        assert_eq!(send(&mut c, &send_key(3), push::ENV_APNS, &[i; 32], now_seq(0), &body(i)).status, push::SENT_GONE);
    }
    let st = w.service.inner.lock();
    assert_eq!((st.bindings.len(), st.repeats.len()), (0, 0));
    drop(st);
    w.service.stop();
}

#[test]
fn an_ipv4_client_pays_as_its_own_address() {
    let a: IpAddr = "::ffff:198.51.100.7".parse().unwrap();
    let b: IpAddr = "::ffff:203.0.113.9".parse().unwrap();
    assert_eq!(payer_addr(a), "198.51.100.7".parse::<IpAddr>().unwrap());
    assert_ne!(payer_addr(a), payer_addr(b));
    assert_eq!(payer_addr("2001:db8:1:2:3:4:5:6".parse().unwrap()), "2001:db8:1:2::".parse::<IpAddr>().unwrap());
    // On a dual-stack listener the kernel hands an IPv4 client over as
    // ::ffff:a.b.c.d; its payer is the IPv4 address. Where the machine has
    // no IPv6 socket, there is nothing to check.
    let Ok(l) = TcpListener::bind("[::]:0") else { return };
    let port = l.local_addr().unwrap().port();
    let Ok(_c) = TcpStream::connect(("127.0.0.1", port)) else { return };
    let (_, from) = l.accept().unwrap();
    assert_eq!(payer_addr(from.ip()), "127.0.0.1".parse::<IpAddr>().unwrap(), "seen as {from}");
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
        let t0 = now_seq(0);
        assert_eq!(send(&mut c, &phone, push::ENV_APNS, &token, t0, &body(1)).status, push::SENT);
        assert_eq!(confirm(&w, &mut c, &phone, &token, t0 + 20, 2).status, push::SENT);
        // Journaled before it was answered: the files read it back now,
        // without a stop (a crash right after the answer keeps it).
        let l = saved::load(&state, false).unwrap();
        let b = &l.bindings.values().next().unwrap().0;
        assert!(b.confirmed() && b.slots[0].seq == t0 + 20, "{b:?}");
        w.service.stop();
    }
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(std::fs::metadata(&state).unwrap().permissions().mode() & 0o777, 0o600);
    let w = world_at(Budgets::default(), Some(state.clone()));
    assert_eq!(w.service.bindings(), 1);
    let (key, creds) = member([6; 16], 1, "period", 1, true);
    let mut c = Client::connect(w.service.addr(), w.pin, key, &refs(&creds)).unwrap();
    let seq = saved::load(&state, false).unwrap().bindings.values().next().unwrap().0.slots[0].seq;
    assert_eq!(send(&mut c, &phone, push::ENV_APNS, &token, seq - 1, &body(3)).status, push::SENT_STALE);
    assert_eq!(send(&mut c, &send_key(4), push::ENV_APNS, &token, seq + 10, &body(4)).status, push::SENT_STALE);
    assert_eq!(send(&mut c, &phone, push::ENV_APNS, &token, seq, &body(5)).status, push::SENT);
    w.service.stop();
    let start = |state: &PathBuf, new_state: bool| {
        let keys = Keys::new().unwrap();
        Service::start(Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            cert: keys.cert.clone(),
            key: keys.key.clone(),
            platforms: HashMap::new(),
            budgets: Budgets::default(),
            state: Some(state.clone()),
            new_state,
            log: Arc::new(|_| {}),
        })
    };
    // A state file that does not read stops the service from starting.
    std::fs::write(&state, b"something else").unwrap();
    assert!(start(&state, false).is_err());
    // A missing one too, unless this is the first start.
    std::fs::remove_file(&state).unwrap();
    let e = start(&state, false).err().unwrap();
    assert!(e.to_string().contains("-new-state"), "{e}");
    let _ = std::fs::remove_dir_all(&dir);
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
    let t0 = now_seq(0);
    let status = |c: &mut Client, token: u8, b: u8| send(c, &phone, push::ENV_APNS, &[token; 32], t0, &body(b));
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
            apns::payload(&[0; 16], None).as_bytes(),
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
            slot: on.slot,
            challenge: on.challenge,
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
    registration_in(SLOT, seq, kinds, key)
}

fn registration_in(slot: [u8; 16], seq: u64, kinds: u64, key: [u8; 32]) -> Vec<u8> {
    let token = vec![5; 32];
    let (send_key, send_sig) = signed_by(&send_key(1), push::ENV_APNS, &token, slot, seq, None);
    push::Registration {
        seq,
        kinds,
        on: (kinds != 0).then(|| push::On {
            token,
            env: push::ENV_APNS,
            key: zeroize::Zeroizing::new(key),
            send_key,
            send_sig,
            slot,
            challenge: None,
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
    let t0 = now_seq(0);
    let f = registration(t0, push::KIND_COPIES | push::KIND_EVENTS, pk);
    s.registration(&g, &phone, PHONE, &read_reg(&f));
    assert_eq!(s.held(), 1);
    assert_eq!(kept.0.lock().unwrap().as_slice(), &[(phone, true)]);
    // A copy this laptop made: the phone gets the hint that it waits; the
    // laptop, a reader without a registration, nothing.
    let id = [9u8; 16];
    let waits = |_: &DeviceId| Some(push::Body::Waits { id, origin: [3; 16] });
    s.copy(&g, Role::Origin, &[phone, laptop], None, &waits);
    assert!(wait_for(|| w.fake.bodies() == 1), "nothing sent");
    let g0 = w.fake.got.lock().unwrap()[0].clone();
    assert_eq!((g0.env, g0.token, g0.body), (push::ENV_APNS, vec![5; 32], Some(push::MAX_BODY)));
    // A hub received the same copy and made the same body: the service
    // drops the repeat.
    s.copy(&g, Role::Hub, &[phone], None, &waits);
    assert!(wait_for(|| s.waiting() == 0));
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(w.fake.bodies(), 1);
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
    assert!(wait_for(|| w.fake.bodies() == 2));
    // A device that does not send events sends none.
    s.event(&g, &[14; 16], push::EVENT_REMOVED, Some(laptop), false, Some(1));
    assert_eq!(s.waiting(), 0);
    // An older registration changes nothing; push off drops it.
    s.registration(&g, &phone, PHONE, &read_reg(&registration(t0, 0, pk)));
    assert_eq!(s.held(), 1);
    s.registration(&g, &phone, PHONE, &read_reg(&registration(t0 + 1, 0, pk)));
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
        on: Some(push::On {
            token,
            env: push::ENV_APNS,
            key: zeroize::Zeroizing::new([8; 32]),
            send_key,
            send_sig,
            slot: SLOT,
            challenge: None,
        }),
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
    // The phone is asked to register again, once, when it next connects.
    let renew = s.renewals(&phone);
    assert_eq!(renew.len(), 1);
    assert_eq!(renew[0].0, g);
    let m = frame::read(&renew[0].1, 1 << 16).unwrap();
    assert_eq!(push::read_renew(&m.map), Ok(SLOT));
    assert!(s.renewals(&phone).is_empty());
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
    let loaded = push::Registration::read(&read_reg(&registration(now_seq(0), 1, [7; 32]))).unwrap();
    let s = pusher::Sender::start(faces, kept.clone(), vec![(g, phone, loaded)], Arc::new(|_| {}));
    assert_eq!(s.held(), 1, "the saved registration is back after a restart");
    s.copy(&g, Role::Origin, &[phone], Some(1), &|_| Some(push::Body::Unknown(9)));
    assert!(wait_for(|| s.held() == 0), "the gone token is still held");
    assert_eq!(kept.0.lock().unwrap().last(), Some(&(phone, false)));
    s.stop();
    w.service.stop();
}
