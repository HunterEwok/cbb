// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Push: the registration and its send key, the sealed body of one size,
//! the service's messages, and a copy carried to a phone and opened there.

use alloc::string::String;
use alloc::vec;

use super::*;
use crate::content::Content;
use crate::copies::{self, Made, Opened};
use crate::hlc::Timestamp;
use crate::records::body::{RIGHT_READ, RIGHT_SECRETS, RIGHT_SEND, ROLE_LEAF, ROLE_MEMBER, ROLE_PHONE, ROLE_WATCH};
use crate::testkit::{G, T0, k, sealing, store};

const PK: [u8; 32] = [7; 32];

fn on_with(env: u64, seq: u64, token: &[u8]) -> Registration {
    let send = k("send key");
    let sig = sign_send(&send, env, token, seq).unwrap();
    Registration {
        seq,
        kinds: KIND_COPIES | KIND_EVENTS,
        on: Some(On {
            token: token.to_vec(),
            env,
            key: Zeroizing::new(PK),
            send_key: send.key.clone(),
            send_sig: sig.to_vec(),
        }),
    }
}

fn on(env: u64) -> Registration {
    on_with(env, 3, &[1; 32])
}

fn read_frame(f: &[u8]) -> Value<'_> {
    let m = frame::read(f, frame::LIMIT_MEMBER).unwrap();
    assert!(frame::on_grid(f.len() - 4), "{} bytes off the grid", f.len() - 4);
    m.map
}

#[test]
fn a_registration_round_trips_and_push_off_carries_nothing() {
    let r = on(ENV_APNS);
    let f = r.write().unwrap();
    let back = Registration::read(&read_frame(&f)).unwrap();
    assert_eq!(back, r);
    assert!(back.wants(KIND_COPIES) && back.wants(KIND_EVENTS));
    let off = Registration { seq: 4, kinds: 0, on: None };
    let back = Registration::read(&read_frame(&off.write().unwrap())).unwrap();
    assert!(!back.wants(KIND_COPIES));
    assert!(r.replaced_by(&back) && !back.replaced_by(&r));
    // The push key is never printed.
    let printed = alloc::format!("{r:?}");
    assert!(!printed.contains("7, 7"), "{printed}");
    // The writer writes nothing its reader refuses: push on without what it
    // carries, a key of zeros.
    assert_eq!(Registration { kinds: 0, ..on(ENV_APNS) }.write(), None);
    assert_eq!(Registration { kinds: 1, on: None, seq: 4 }.write(), None);
    let mut zero = on(ENV_APNS);
    if let Some(o) = zero.on.as_mut() {
        o.key = Zeroizing::new([0; 32]);
    }
    assert_eq!(zero.write(), None);
}

#[test]
fn a_registration_is_on_with_all_it_carries_or_off_with_none() {
    let r = on(ENV_APNS);
    let o = r.on.as_ref().unwrap();
    let kv = o.send_key.to_value();
    let m = |kinds: u64, have: [bool; 5]| {
        let mut v = vec![(0, Value::Uint(T_PUSH))];
        let fields: [(u16, Value<'_>); 5] = [
            (2, Value::Bytes(&o.token)),
            (3, Value::Uint(1)),
            (4, Value::Bytes(&o.key[..])),
            (7, kv.clone()),
            (8, Value::Bytes(&o.send_sig)),
        ];
        for (i, (n, x)) in fields.into_iter().enumerate() {
            if have[i] && n < 5 {
                v.push((n, x));
            }
        }
        v.push((5, Value::Uint(1)));
        v.push((6, Value::Uint(kinds)));
        for (i, n) in [(3usize, 7u16), (4, 8)] {
            if have[i] {
                v.push((n, if n == 7 { kv.clone() } else { Value::Bytes(&o.send_sig) }));
            }
        }
        Value::Map(v)
    };
    assert!(Registration::read(&m(1, [true; 5])).is_ok());
    assert!(Registration::read(&m(0, [false; 5])).is_ok());
    for i in 0..5 {
        let mut have = [true; 5];
        have[i] = false;
        assert_eq!(Registration::read(&m(1, have)).err(), Some(RULE_PUSH_SHAPE), "without field {i}");
        let mut only = [false; 5];
        only[i] = true;
        assert_eq!(Registration::read(&m(0, only)).err(), Some(RULE_PUSH_SHAPE), "off with field {i}");
    }
}

#[test]
fn the_send_key_signs_the_token_and_the_number_and_a_later_algorithm_is_held() {
    let r = on(ENV_APNS);
    let o = r.on.as_ref().unwrap();
    assert_eq!(check_send(&o.send_key, &o.send_sig, ENV_APNS, &o.token, 3), Ok(SendCheck::Good));
    // Another number, token or platform: the signature does not hold.
    assert_eq!(check_send(&o.send_key, &o.send_sig, ENV_APNS, &o.token, 4), Err(RULE_SEND_SIG));
    assert_eq!(check_send(&o.send_key, &o.send_sig, ENV_APNS, &[2; 32], 3), Err(RULE_SEND_SIG));
    assert_eq!(check_send(&o.send_key, &o.send_sig, ENV_FCM, &o.token, 3), Err(RULE_SEND_SIG));
    // A key exchange's algorithm is refused where a send key is wanted; an
    // algorithm this version does not know is held.
    let later = Key { alg: 9, public: vec![1; 2000] };
    assert_eq!(check_send(&later, &[1; 3000], ENV_APNS, &o.token, 3), Ok(SendCheck::Unknown));
    let kem = Key { alg: crate::records::key::ALG_X25519, public: vec![1; 32] };
    assert_eq!(check_send(&kem, &o.send_sig, ENV_APNS, &o.token, 3), Err(RULE_SEND_SIG));
    let mut held = on(ENV_APNS);
    if let Some(x) = held.on.as_mut() {
        x.send_key = later.clone();
        x.send_sig = vec![1; 3000];
    }
    let back = Registration::read(&read_frame(&held.write().unwrap())).unwrap();
    assert_eq!(back.on.unwrap().send_key, later);
}

#[test]
fn a_phone_restored_from_a_backup_still_moves_forward() {
    // The phone saved 9 before the backup and 12 after; restored, it holds
    // 9 again, and its clock has moved on: its next number passes 12.
    let before = next_seq(Some(8), 1_000);
    assert_eq!(before, 1_000);
    let later = next_seq(Some(before), 5_000);
    assert!(later > before);
    let restored = next_seq(Some(before), 6_000);
    assert!(restored > later, "{restored} after {later}");
    // Without a clock that moved, one more than the saved one.
    assert_eq!(next_seq(Some(41), 0), 42);
    assert_eq!(next_seq(None, 0), 1);
    assert!(next_seq(Some(1 << 53), 0) <= 1 << 53);
}

#[test]
fn only_a_phone_or_a_computer_registers() {
    assert!(may_register(ROLE_PHONE) && may_register(ROLE_MEMBER));
    assert!(!may_register(ROLE_LEAF) && !may_register(ROLE_WATCH) && !may_register(77));
}

#[test]
fn unknown_values_are_held_not_refused() {
    // An env a later version numbers is kept and handed on as it is.
    let r = on(200);
    let back = Registration::read(&read_frame(&r.write().unwrap())).unwrap();
    assert_eq!(back.on.as_ref().map(|o| o.env), Some(200));
    assert_eq!(body_len(200), None);
    // Unknown kinds bits ask for nothing this version sends, up to bit 31.
    for kinds in [64, 1 << 31] {
        let r = Registration { kinds, ..on(ENV_APNS) };
        let back = Registration::read(&read_frame(&r.write().unwrap())).unwrap();
        assert!(!back.wants(KIND_COPIES) && !back.wants(KIND_EVENTS));
    }
    // An unknown status is "failed, try later".
    assert_eq!(status(77), SENT_FAILED);
    assert_eq!(status(SENT_GONE), SENT_GONE);
    assert_eq!(status(SENT_STALE), SENT_STALE);
}

#[test]
fn every_body_is_one_size_and_opens_only_under_its_key_and_number() {
    let bodies = [
        Body::Waits { id: [1; 16], origin: [2; 16] },
        Body::Event { id: [3; 16], event: EVENT_REMOVED, device: Some([4; 16]), time_ms: Some(T0) },
        Body::Event { id: [3; 16], event: EVENT_STOPPED, device: None, time_ms: None },
        Body::Unknown(9),
        Body::Copy(vec![0xa0]),
    ];
    for b in &bodies {
        let sealed = seal(&PK, 3, ENV_APNS, b).unwrap();
        assert_eq!(sealed.len(), MAX_BODY);
        assert_eq!(&open(&PK, 3, &sealed).unwrap(), b);
        assert_eq!(open(&[8; 32], 3, &sealed).err(), Some(RULE_BODY_OPEN));
        assert_eq!(open(&PK, 4, &sealed).err(), Some(RULE_BODY_OPEN));
        let mut bent = sealed.clone();
        bent[100] ^= 1;
        assert_eq!(open(&PK, 3, &bent).err(), Some(RULE_BODY_OPEN));
        // Every honest sender of one body makes the same bytes.
        assert_eq!(seal(&PK, 3, ENV_APNS, b).unwrap(), sealed);
    }
    // Two plaintexts never share a nonce.
    let a = seal(&PK, 3, ENV_APNS, &bodies[0]).unwrap();
    let b = seal(&PK, 3, ENV_APNS, &bodies[1]).unwrap();
    assert_ne!(a[..NONCE_LEN], b[..NONCE_LEN]);
    // The fits-every-service arithmetic: base64 in APNs' wrapper.
    let b64 = MAX_BODY.div_ceil(3) * 4;
    let apns = r#"{"aps":{"alert":{"loc-key":"push.new"},"mutable-content":1},"c":""}"#.len() + b64;
    assert!(apns <= 4096, "{apns}");
    // An env this version does not know gets no body; only the registry's
    // size opens.
    assert_eq!(seal(&PK, 3, 200, &bodies[0]), None);
    assert_eq!(open(&PK, 3, &[0; 27]).err(), Some(RULE_BODY_SIZE));
    assert_eq!(open(&PK, 3, &a[..88]).err(), Some(RULE_BODY_SIZE));
}

#[test]
fn hints_are_hints_and_unknown_kinds_and_fields_are_neutral() {
    assert!(Body::Waits { id: [0; 16], origin: [0; 16] }.is_hint());
    assert!(Body::Unknown(4).is_hint());
    assert!(!Body::Copy(vec![]).is_hint());
    // A later version's kind: the neutral hint, whatever its fields 2 to 7
    // hold; a later field 8 beside a known kind is skipped.
    let future = |kind: u64, field: u16, id: &[u8]| {
        let x = [5u8; 40];
        let entries =
            vec![(0, Value::Uint(kind)), (3, Value::Bytes(id)), (5, Value::Text("x")), (field, Value::Bytes(&x))];
        let base = Value::Map(entries.clone()).encode();
        let plen = pad_for(base.len(), entries.len(), PLAIN_LEN).unwrap();
        let zeros = vec![0u8; plen];
        let mut all = entries;
        all.insert(1, (1, Value::Bytes(&zeros)));
        Value::Map(all).encode()
    };
    assert_eq!(Body::read(&future(4, 9, &[1; 32])).unwrap(), Body::Unknown(4));
    assert_eq!(Body::read(&future(BODY_EVENT, 8, &[1; 16])).err(), Some(Rule::field("pushbody/event")));
    // An event this version does not number is still an event, which the
    // app shows as the neutral hint.
    let b = Body::Event { id: [1; 16], event: 99, device: None, time_ms: None };
    assert_eq!(Body::read(&b.plaintext().unwrap()).unwrap(), b);
    // The writer writes nothing its reader refuses or reads otherwise.
    assert_eq!(Body::Copy(vec![]).plaintext(), None);
    for k in [BODY_COPY, BODY_WAITS, BODY_EVENT] {
        assert_eq!(Body::Unknown(k).plaintext(), None);
    }
}

#[test]
fn a_body_has_one_padding() {
    let b = Body::Waits { id: [1; 16], origin: [2; 16] };
    let p = b.plaintext().unwrap();
    assert_eq!(p.len(), PLAIN_LEN);
    assert_eq!(Body::read(&p).unwrap(), b);
    // A nonzero pad byte.
    let mut bent = p.clone();
    // The pad follows field 0, so byte 20 is one of its zeros.
    bent[20] = 1;
    assert_eq!(Body::read(&bent).err(), Some(RULE_BODY_PAD));
}

/// A point of P-256, uncompressed: the generator's.
fn point() -> [u8; 65] {
    use p256::elliptic_curve::sec1::ToSec1Point as _;
    let p = p256::ProjectivePoint::GENERATOR.to_affine().to_sec1_point(false);
    p.as_bytes().try_into().unwrap()
}

#[test]
fn a_unifiedpush_token_holds_the_endpoint_and_the_keys_within_its_bound() {
    let url = String::from("https://up.example.org/") + &"a".repeat(MAX_UP_URL - 23);
    let p256dh = point();
    let auth = [6u8; 16];
    let t = UnifiedPush { url: &url, p256dh: &p256dh, auth: &auth };
    let token = t.write();
    assert!(token.len() <= MAX_TOKEN, "{}", token.len());
    assert_eq!(UnifiedPush::read(&token).unwrap(), t);
    let longer = String::from("https://up.example.org/") + &"a".repeat(MAX_UP_URL - 22);
    assert!(UnifiedPush::read(&UnifiedPush { url: &longer, ..t.clone() }.write()).is_err());
    // The endpoint: https to a host name, port 443, no user.
    for good in [
        "https://ntfy.example.net/upAbc123",
        "https://up.example.org:443/x?t=1",
        "https://a-b.example.org:443",
        "https://x.io",
    ] {
        assert!(up_url(good), "{good}");
    }
    for bad in [
        "http://up.example.org/x",
        "https://",
        "https://localhost/x",
        "https://10.0.0.1/x",
        "https://192.168.1.2:443/x",
        "https://[::1]/x",
        "https://up.example.org:8080/x",
        "https://up.example.org:8443/x",
        "https://up.example.org./x",
        "https://up.example.org:/x",
        "https://user@up.example.org/x",
        "https://up.example.org/x#frag",
        "https://up.example.org/a b",
        "https://-up.example.org/x",
        "https://up..example.org/x",
        "https://up.example.org\\@evil.example/x",
    ] {
        assert!(!up_url(bad), "{bad}");
        let w = UnifiedPush { url: bad, ..t.clone() }.write();
        assert_eq!(UnifiedPush::read(&w).err(), Some(RULE_UP_URL), "{bad}");
    }
    // p256dh must be a point of P-256, uncompressed.
    let mut off = point();
    off[64] ^= 1;
    assert_eq!(UnifiedPush::read(&UnifiedPush { p256dh: &off, ..t.clone() }.write()).err(), Some(RULE_UP_KEY));
    assert_eq!(UnifiedPush::read(&UnifiedPush { p256dh: &[4; 65], ..t.clone() }.write()).err(), Some(RULE_UP_KEY));
    // A send with an APNs token stays on the 4096 step; the longest token
    // takes it to the 16384 step.
    let body = vec![0u8; MAX_BODY];
    let apns = [1u8; 32];
    let r = on(ENV_APNS);
    let o = r.on.as_ref().unwrap();
    let s = Send {
        n: u32::MAX as u64,
        token: &apns,
        env: ENV_APNS,
        body: &body,
        ttl: Some(4),
        key: o.send_key.clone(),
        sig: &o.send_sig,
        seq: 1 << 53,
    };
    assert_eq!(s.write().unwrap().len() - 4, 4096);
    // The longest token, send key and signature still fit one frame.
    let longest = vec![1u8; MAX_TOKEN];
    let big_sig = vec![1u8; MAX_SEND_SIG];
    let big_key = Key { alg: 9, public: vec![1; MAX_SEND_KEY] };
    let s = Send { token: &longest, env: ENV_UNIFIEDPUSH, key: big_key, sig: &big_sig, ..s.clone() };
    let f = s.write().unwrap();
    assert_eq!(f.len() - 4, 16384);
    assert!(f.len() - 4 <= MAX_SERVICE_FRAME);
    let v = read_frame(&f);
    let back = Send::read(&v).unwrap();
    assert_eq!(back, s);
    assert!(back.sized());
    assert!(!Send { body: &body[..100], ..s.clone() }.sized());
}

#[test]
fn the_services_messages_follow_their_tables() {
    for (f, t) in [
        (ready(10), T_READY),
        (sent(1, SENT_REPEAT, None), T_SENT),
        (sent(2, SENT_BUDGET, Some(60_000)), T_SENT),
        (error("over budget"), T_ERROR),
    ] {
        let v = read_frame(&f);
        check_map(of(t).unwrap(), &v).unwrap();
    }
    assert!(of(T_PUSH).is_some() && of(29).is_none());
}

/// A group of a phone and `others` computers, each with its statement.
fn world(
    others: usize,
) -> (
    G,
    Vec<String>,
    alloc::collections::BTreeMap<String, crate::keystore::MemoryStore<crate::testkit::K>>,
    Vec<crate::records::statement::Statement>,
) {
    let mut g = G::new();
    let mut names = vec![String::from("phone")];
    g.device("phone", ROLE_PHONE, RIGHT_READ | RIGHT_SEND | RIGHT_SECRETS, |_| {});
    for i in 0..others {
        let n = alloc::format!("computer{i}");
        g.device(&n, ROLE_MEMBER, RIGHT_READ | RIGHT_SEND | RIGHT_SECRETS, |_| {});
        names.push(n);
    }
    let mut stores = alloc::collections::BTreeMap::new();
    let mut statements = Vec::new();
    for n in &names {
        let (s, st) = store(n, &g.gid);
        stores.insert(n.clone(), s);
        statements.push(st);
    }
    (g, names, stores, statements)
}

#[test]
fn a_copy_reaches_the_phone_whole_and_opens_there() {
    let (g, _, stores, statements) = world(3);
    let state = g.state();
    let refs: Vec<&_> = statements.iter().collect();
    let sealing = sealing(&state, &refs);
    let phone = k("phone").key.device_id();
    let origin = k("computer0");
    let text = Content::text("the code is 4711", false);
    let rs = copies::readers(&state, &sealing, &text, &origin.key.device_id(), &[], None);
    let made = Made { id: [5; 16], time: Timestamp { wall: (T0 + 5) as i64, logical: 0 }, blob: None };
    let copy = copies::seal(&origin, &rs, &made, &text).unwrap();
    let v = cbor::decode(&copy).unwrap();
    let c = copies::check(&v, &state).unwrap();
    let body = copy_body(&c.copy, &c.readers, &phone, made.id, origin.key.device_id().0).unwrap();
    let Body::Copy(_) = body else { panic!("a short copy among four readers fits: {body:?}") };
    // A hub that passed the copy on, its age grown, makes the same body.
    let mut aged = c.copy.clone();
    aged.age_ms = 1234;
    assert_eq!(copy_body(&aged, &c.readers, &phone, made.id, origin.key.device_id().0).unwrap(), body);
    // The member seals it; the phone opens it, checks the origin from the
    // reduced copy alone and opens its own wrap.
    let sealed = seal(&PK, 3, ENV_APNS, &body).unwrap();
    let Body::Copy(reduced) = open(&PK, 3, &sealed).unwrap() else { panic!() };
    let rv = cbor::decode(&reduced).unwrap();
    let rc = copies::check(&rv, &state).unwrap();
    match copies::open(&rc, &phone, &stores["phone"], &state).unwrap() {
        Opened::Content { content, .. } => assert_eq!(content.text.as_deref(), Some("the code is 4711")),
        other => panic!("{other:?}"),
    }
    // Not a reader: no body at all, not even a hint that names the copy.
    let stranger = k("stranger").key.device_id();
    assert_eq!(copy_body(&c.copy, &c.readers, &stranger, made.id, [0; 16]), None);
}

#[test]
fn a_copy_too_large_or_with_too_many_readers_is_a_hint_that_it_waits() {
    // How many readers still fit with a short text: the rows say about 10.
    let mut fits = 0;
    for others in [4usize, 7, 9, 12, 20] {
        let (g, _, _, statements) = world(others);
        let state = g.state();
        let refs: Vec<&_> = statements.iter().collect();
        let sealing = sealing(&state, &refs);
        let origin = k("computer0");
        let text = Content::text("hi", false);
        let rs = copies::readers(&state, &sealing, &text, &origin.key.device_id(), &[], None);
        let made = Made { id: [6; 16], time: Timestamp { wall: (T0 + 6) as i64, logical: 0 }, blob: None };
        let copy = copies::seal(&origin, &rs, &made, &text).unwrap();
        let v = cbor::decode(&copy).unwrap();
        let c = copies::check(&v, &state).unwrap();
        let b = copy_body(&c.copy, &c.readers, &k("phone").key.device_id(), made.id, [0; 16]).unwrap();
        if !b.is_hint() {
            fits = fits.max(others + 1);
        }
    }
    assert!(fits >= 8, "only {fits} readers fit");
    // A text over the 1 KiB step: it waits.
    let (g, _, _, statements) = world(2);
    let state = g.state();
    let refs: Vec<&_> = statements.iter().collect();
    let sealing = sealing(&state, &refs);
    let origin = k("computer0");
    let text = Content::text(&"x".repeat(2000), false);
    let rs = copies::readers(&state, &sealing, &text, &origin.key.device_id(), &[], None);
    let made = Made { id: [7; 16], time: Timestamp { wall: (T0 + 7) as i64, logical: 0 }, blob: None };
    let copy = copies::seal(&origin, &rs, &made, &text).unwrap();
    let v = cbor::decode(&copy).unwrap();
    let c = copies::check(&v, &state).unwrap();
    assert_eq!(
        copy_body(&c.copy, &c.readers, &k("phone").key.device_id(), made.id, [9; 16]),
        Some(Body::Waits { id: [7; 16], origin: [9; 16] })
    );
}

fn unhex(v: &serde_json::Value) -> Vec<u8> {
    let s = v.as_str().unwrap();
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn verdict<T>(r: Result<T, Rule>, take: impl FnOnce(T) -> String) -> String {
    match r {
        Ok(x) => take(x),
        Err(e) => e.name().into(),
    }
}

#[test]
fn the_vectors_are_what_the_readers_say() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../testdata/format/push.json");
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    // The tables are the vectors'.
    let theirs = v["tables"].as_object().unwrap();
    assert_eq!(theirs.len(), ALL.len());
    for t in ALL {
        let ours: Vec<serde_json::Value> = t
            .fields
            .iter()
            .map(|f| serde_json::json!({"n": f.n, "rule": f.rule, "type": f.ty.describe(), "needed": f.needed}))
            .collect();
        assert_eq!(theirs[t.name()].as_array().unwrap(), &ours, "{}", t.name());
    }
    for (t, name) in v["types"].as_object().unwrap() {
        let n: u64 = t.parse().unwrap();
        assert_eq!(of(n).map(Table::name), name.as_str(), "type {t}");
        assert!(crate::msg::tables::of(n).is_none() && crate::msg::wave4::of(n).is_none(), "type {t} named twice");
    }
    for (e, row) in v["envs"].as_object().unwrap() {
        assert_eq!(body_len(e.parse().unwrap()), row["body"].as_u64().map(|b| b as usize), "env {e}");
    }
    assert_eq!(v["labels"]["body"], LABEL_BODY);
    assert_eq!(v["labels"]["nonce"], LABEL_NONCE);
    assert_eq!(v["labels"]["send"], LABEL_SEND);
    let name = |x: &serde_json::Value| x["name"].as_str().unwrap().to_owned();
    let want = |x: &serde_json::Value| x["verdict"].as_str().unwrap().to_owned();
    for r in v["registrations"].as_array().unwrap() {
        let f = unhex(&r["frame"]);
        let m = frame::read(&f, frame::LIMIT_MEMBER).unwrap();
        assert_eq!(m.t, T_PUSH);
        let got = verdict(Registration::read(&m.map), |r| if r.on.is_some() { "on".into() } else { "off".into() });
        assert_eq!(got, want(r), "registration {}", name(r));
    }
    for b in v["bodies"].as_array().unwrap() {
        let key: [u8; 32] = unhex(&b["key"]).try_into().unwrap();
        let sealed = unhex(&b["sealed"]);
        let got = verdict(open(&key, b["seq"].as_u64().unwrap(), &sealed), |b| {
            match b {
                Body::Copy(_) => "copy",
                Body::Waits { .. } => "waits",
                Body::Event { .. } => "event",
                Body::Unknown(_) => "neutral",
            }
            .into()
        });
        assert_eq!(got, want(b), "body {}", name(b));
        // Ours seals the same bytes from the same plaintext.
        if let (Some(p), Ok(body)) = (b.get("plaintext"), open(&key, 3, &sealed))
            && !matches!(body, Body::Unknown(_))
            && !name(b).contains("later")
        {
            assert_eq!(body.plaintext().unwrap(), unhex(p), "plaintext {}", name(b));
            assert_eq!(seal(&key, 3, b["env"].as_u64().unwrap(), &body).unwrap(), sealed, "sealed {}", name(b));
        }
    }
    for r in v["sends"].as_array().unwrap() {
        let key = Key::read(&cbor::decode(&unhex(&r["key"])).unwrap()).unwrap();
        let got = verdict(
            check_send(
                &key,
                &unhex(&r["sig"]),
                r["env"].as_u64().unwrap(),
                &unhex(&r["token"]),
                r["seq"].as_u64().unwrap(),
            ),
            |c| if c == SendCheck::Good { "good".into() } else { "held".into() },
        );
        assert_eq!(got, want(r), "send key {}", name(r));
    }
    for u in v["unifiedpush"].as_array().unwrap() {
        let t = unhex(&u["token"]);
        let got = verdict(UnifiedPush::read(&t), |_| "take".into());
        assert_eq!(got, want(u), "unifiedpush {}", name(u));
        assert!(t.len() <= MAX_TOKEN);
    }
    for m in v["messages"].as_array().unwrap() {
        let f = unhex(&m["frame"]);
        let msg = frame::read(&f, frame::LIMIT_MEMBER).unwrap();
        let got = verdict(check_map(of(msg.t).unwrap(), &msg.map), |()| "take".into());
        // msg::check reads the same tables.
        assert_eq!(
            crate::msg::check(&f[4..]).map(|_| "take".to_string()).unwrap_or_else(|r| r.name().to_string()),
            got
        );
        assert_eq!(got, want(m), "message {}", name(m));
        if let Some(sized) = m.get("sized").and_then(serde_json::Value::as_bool) {
            assert_eq!(Send::read(&msg.map).unwrap().sized(), sized, "sized {}", name(m));
        }
    }
}

fn call(op: &str, args: serde_json::Value) -> serde_json::Value {
    let req = serde_json::json!({ "abi": crate::api::ABI, "op": op, "args": args });
    serde_json::from_slice(&crate::api::call(&serde_json::to_vec(&req).unwrap())).unwrap()
}

fn b64(b: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(b)
}

/// The phone's calls: a push key, the registration's frame, the limits,
/// and a body opened as a notification extension opens it, with only the
/// push keys, its copy-opening secrets and the origins the app saved.
#[test]
fn the_phone_registers_and_opens_a_body_through_the_core_api() {
    let key = call("push_key", serde_json::Value::Null);
    let pk_b64 = key["ok"]["key"].as_str().unwrap().to_string();
    assert_eq!(pk_b64.len(), 44);
    let send_key = key["ok"]["send_key"].as_str().unwrap().to_string();
    let limits = call("push_limits", serde_json::json!({ "env": ENV_APNS }));
    assert_eq!(limits["ok"]["body"], MAX_BODY);
    assert_eq!(limits["ok"]["token"], MAX_TOKEN);
    assert_eq!(call("push_limits", serde_json::json!({ "env": 77 }))["ok"]["known"], false);

    let reg = call(
        "push_registration",
        serde_json::json!({ "saved_seq": 1, "now_ms": 0, "kinds": 3, "env": ENV_APNS, "token": b64(&[5; 32]),
            "key": b64(&PK), "send_key": send_key }),
    );
    let frame = {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.decode(reg["ok"]["frame"].as_str().unwrap()).unwrap()
    };
    assert_eq!(reg["ok"]["seq"], 2);
    let r = Registration::read(&read_frame(&frame)).unwrap();
    let o = r.on.as_ref().unwrap();
    assert_eq!((r.seq, r.kinds, o.env), (2, 3, ENV_APNS));
    // The service can check the send key's signature.
    assert_eq!(check_send(&o.send_key, &o.send_sig, ENV_APNS, &[5; 32], 2), Ok(SendCheck::Good));
    // A restored phone whose saved number went back still moves forward.
    let restored = call("push_registration", serde_json::json!({ "saved_seq": 1, "now_ms": T0, "kinds": 0 }));
    assert_eq!(restored["ok"]["seq"], T0);
    let up = call(
        "push_registration",
        serde_json::json!({ "now_ms": 0, "kinds": 1, "env": ENV_UNIFIEDPUSH,
            "unifiedpush": { "url": "http://up.example/x", "p256dh": b64(&point()), "auth": b64(&[1; 16]) },
            "key": b64(&PK), "send_key": send_key }),
    );
    assert_eq!(up["error"]["name"], "push", "a plain-HTTP endpoint is refused: {up}");
    let bad = call("push_registration", serde_json::json!({ "now_ms": 0, "kinds": 1, "env": 1, "token": b64(&[1]) }));
    assert_eq!(bad["error"]["code"], 18);

    // A copy from computer0, sealed into a body by a member.
    let (g, _, stores, statements) = world(3);
    let state = g.state();
    let refs: Vec<&_> = statements.iter().collect();
    let sealing = sealing(&state, &refs);
    let phone = k("phone").key.device_id();
    let origin = k("computer0");
    let text = Content::text("the code is 4711", false);
    let rs = copies::readers(&state, &sealing, &text, &origin.key.device_id(), &[], None);
    let made = Made { id: [5; 16], time: Timestamp { wall: (T0 + 5) as i64, logical: 0 }, blob: None };
    let copy = copies::seal(&origin, &rs, &made, &text).unwrap();
    let v = cbor::decode(&copy).unwrap();
    let c = copies::check(&v, &state).unwrap();
    let body = copy_body(&c.copy, &c.readers, &phone, made.id, origin.key.device_id().0).unwrap();
    let sealed = seal(&PK, 2, ENV_APNS, &body).unwrap();
    let epoch = c.readers.iter().find(|(d, _)| *d == phone).unwrap().1;
    let secret = crate::keystore::KeyStore::sealing(&stores["phone"], epoch).unwrap();
    let od = state.device(&origin.key.device_id()).unwrap();
    let origins = serde_json::json!([{ "key": b64(&od.key.encode()), "rights": od.rights }]);
    let args = |origins: &serde_json::Value, keys: serde_json::Value| {
        serde_json::json!({ "keys": keys, "body": b64(&sealed), "me": b64(&phone.0), "origins": origins,
            "sealing": [{ "epoch": epoch, "secret": b64(&secret) }] })
    };
    let old = serde_json::json!({ "key": b64(&[1; 32]), "seq": 1 });
    let current = serde_json::json!({ "key": b64(&PK), "seq": 2 });
    let got = call("push_open", args(&origins, serde_json::json!([old, current])));
    let ok = &got["ok"];
    assert_eq!(ok["kind"], "copy", "{got}");
    assert_eq!(ok["text"], "the code is 4711");
    assert_eq!(
        (ok["type"].as_str(), ok["secret"].as_bool(), ok["key_index"].as_u64()),
        (Some("text"), Some(false), Some(1))
    );
    // Without the origin in the saved records the text never shows.
    let got = call("push_open", args(&serde_json::json!([]), serde_json::json!([current])));
    assert_eq!(got["ok"]["kind"], "hint", "{got}");
    assert!(got["ok"].get("text").is_none());
    // A halted group opens nothing: a hint that the copy waits.
    let mut halted = args(&origins, serde_json::json!([current]));
    halted["halted"] = true.into();
    let got = call("push_open", halted);
    assert_eq!(got["ok"]["kind"], "waits", "{got}");
    // After a membership change, or past the group's window: a hint.
    let mut changed = args(&origins, serde_json::json!([current]));
    changed["hints_only"] = true.into();
    assert_eq!(call("push_open", changed)["ok"]["kind"], "waits");
    let mut late = args(&origins, serde_json::json!([current]));
    late["now_ms"] = (T0 + 5 + 120_001).into();
    late["window_ms"] = 120_000.into();
    assert_eq!(call("push_open", late.clone())["ok"]["kind"], "waits");
    late["now_ms"] = (T0 + 5 + 1_000).into();
    assert_eq!(call("push_open", late)["ok"]["kind"], "copy");
    // No key opens it: code 18.
    let got = call("push_open", args(&origins, serde_json::json!([old])));
    assert_eq!(got["error"]["name"], "push", "{got}");
    // An event is a hint with its number.
    let ev = Body::Event { id: [8; 16], event: EVENT_ROOT, device: None, time_ms: Some(T0) };
    let sealed_ev = seal(&PK, 2, ENV_APNS, &ev).unwrap();
    let got = call("push_open", serde_json::json!({ "keys": [current], "body": b64(&sealed_ev), "me": b64(&phone.0) }));
    assert_eq!((got["ok"]["kind"].as_str(), got["ok"]["event"].as_u64()), (Some("event"), Some(EVENT_ROOT)), "{got}");
    // An event older than a day is the neutral hint.
    let got = call(
        "push_open",
        serde_json::json!({ "keys": [current], "body": b64(&sealed_ev), "me": b64(&phone.0), "now_ms": T0 + 86_400_001 }),
    );
    assert_eq!(got["ok"]["kind"], "hint", "{got}");
}
