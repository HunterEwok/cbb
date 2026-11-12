// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Push: the registration, the sealed body of one size, `once`, the
//! service's messages, and a copy carried to a phone and opened there.

use alloc::string::String;
use alloc::vec;

use super::*;
use crate::content::Content;
use crate::copies::{self, Made, Opened};
use crate::hlc::Timestamp;
use crate::records::body::{RIGHT_READ, RIGHT_SECRETS, RIGHT_SEND, ROLE_MEMBER, ROLE_PHONE};
use crate::testkit::{G, T0, k, sealing, store};

const PK: [u8; 32] = [7; 32];
const NONCE: [u8; 12] = [9; 12];

fn on(env: u64) -> Registration {
    Registration {
        seq: 3,
        kinds: KIND_COPIES | KIND_EVENTS,
        on: Some(On { token: vec![1; 32], env, key: Zeroizing::new(PK) }),
    }
}

fn read_frame(f: &[u8]) -> Value<'_> {
    let m = frame::read(f, frame::LIMIT_MEMBER).unwrap();
    assert!(frame::on_grid(f.len() - 4), "{} bytes off the grid", f.len() - 4);
    m.map
}

#[test]
fn a_registration_round_trips_and_push_off_carries_nothing() {
    let r = on(ENV_APNS);
    let f = r.write();
    let back = Registration::read(&read_frame(&f)).unwrap();
    assert_eq!(back, r);
    assert!(back.wants(KIND_COPIES) && back.wants(KIND_EVENTS));
    let off = Registration { seq: 4, kinds: 0, on: None };
    let back = Registration::read(&read_frame(&off.write())).unwrap();
    assert!(!back.wants(KIND_COPIES));
    assert!(r.replaced_by(&back) && !back.replaced_by(&r));
    // The push key is never printed.
    let printed = alloc::format!("{r:?}");
    assert!(!printed.contains("7, 7"), "{printed}");
}

#[test]
fn a_registration_is_on_with_all_three_or_off_with_none() {
    let token = [1u8; 32];
    let key = [2u8; 32];
    let m = |kinds: u64, t: bool, e: bool, k: bool| {
        let mut v = vec![(0, Value::Uint(T_PUSH))];
        if t {
            v.push((2, Value::Bytes(&token)));
        }
        if e {
            v.push((3, Value::Uint(1)));
        }
        if k {
            v.push((4, Value::Bytes(&key)));
        }
        v.push((5, Value::Uint(1)));
        v.push((6, Value::Uint(kinds)));
        Value::Map(v)
    };
    assert!(Registration::read(&m(1, true, true, true)).is_ok());
    assert!(Registration::read(&m(0, false, false, false)).is_ok());
    for (kinds, t, e, k) in [
        (0, true, true, true),
        (1, false, true, true),
        (1, true, false, true),
        (1, true, true, false),
        (0, true, false, false),
    ] {
        assert_eq!(Registration::read(&m(kinds, t, e, k)).err(), Some(RULE_PUSH_SHAPE), "{kinds} {t} {e} {k}");
    }
}

#[test]
fn unknown_values_are_held_not_refused() {
    // An env a later version numbers is kept and handed on as it is.
    let r = on(200);
    let back = Registration::read(&read_frame(&r.write())).unwrap();
    assert_eq!(back.on.as_ref().map(|o| o.env), Some(200));
    assert_eq!(body_len(200), None);
    // Unknown kinds bits ask for nothing this version sends.
    let r = Registration { kinds: 64, ..on(ENV_APNS) };
    let back = Registration::read(&read_frame(&r.write())).unwrap();
    assert!(!back.wants(KIND_COPIES) && !back.wants(KIND_EVENTS));
    // An unknown status is "failed, try later".
    assert_eq!(status(77), SENT_FAILED);
    assert_eq!(status(SENT_GONE), SENT_GONE);
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
        let sealed = seal(&PK, 3, ENV_APNS, b, &NONCE).unwrap();
        assert_eq!(sealed.len(), MAX_BODY);
        assert_eq!(&open(&PK, 3, &sealed).unwrap(), b);
        assert_eq!(open(&[8; 32], 3, &sealed).err(), Some(RULE_BODY_OPEN));
        assert_eq!(open(&PK, 4, &sealed).err(), Some(RULE_BODY_OPEN));
        let mut bent = sealed.clone();
        bent[100] ^= 1;
        assert_eq!(open(&PK, 3, &bent).err(), Some(RULE_BODY_OPEN));
    }
    // The fits-every-service arithmetic: base64 in APNs' wrapper.
    let b64 = MAX_BODY.div_ceil(3) * 4;
    let apns = r#"{"aps":{"alert":{"loc-key":"push.new"},"mutable-content":1},"c":""}"#.len() + b64;
    assert!(apns <= 4096, "{apns}");
    // An env this version does not know gets no body.
    assert_eq!(seal(&PK, 3, 200, &bodies[0], &NONCE), None);
    assert_eq!(open(&PK, 3, &[0; 27]).err(), Some(RULE_BODY_SIZE));
}

#[test]
fn hints_are_hints_and_unknown_kinds_and_fields_are_neutral() {
    assert!(Body::Waits { id: [0; 16], origin: [0; 16] }.is_hint());
    assert!(Body::Unknown(4).is_hint());
    assert!(!Body::Copy(vec![]).is_hint());
    // A later version's kind 4 with a field 9 of its own: read as the
    // neutral hint; a later field 8 beside a known kind is skipped.
    let future = |kind: u64, field: u16| {
        let x = [5u8; 40];
        let entries =
            vec![(0, Value::Uint(kind)), (3, Value::Bytes(&[1u8; 16])), (5, Value::Uint(1)), (field, Value::Bytes(&x))];
        let base = Value::Map(entries.clone()).encode();
        let plen = pad_for(base.len(), entries.len(), PLAIN_LEN).unwrap();
        let zeros = vec![0u8; plen];
        let mut all = entries;
        all.insert(1, (1, Value::Bytes(&zeros)));
        Value::Map(all).encode()
    };
    assert_eq!(Body::read(&future(4, 9)).unwrap(), Body::Unknown(4));
    assert_eq!(
        Body::read(&future(BODY_EVENT, 8)).unwrap(),
        Body::Event { id: [1; 16], event: 1, device: None, time_ms: None }
    );
    // An event this version does not number is still an event, which the
    // app shows as the neutral hint.
    let b = Body::Event { id: [1; 16], event: 99, device: None, time_ms: None };
    assert_eq!(Body::read(&b.plaintext().unwrap()).unwrap(), b);
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
    // A body padded short of its size cannot claim another: rebuild it with
    // one byte less of padding inside a longer frame.
    let entries = vec![(0, Value::Uint(BODY_WAITS)), (3, Value::Bytes(&[1u8; 16])), (4, Value::Bytes(&[2u8; 16]))];
    let short = vec![0u8; 10];
    let mut all = entries.clone();
    all.insert(1, (1, Value::Bytes(&short)));
    let small = Value::Map(all).encode();
    assert_eq!(Body::read(&small).err(), None, "any size may be read: the AEAD decides");
    // A known kind without its needed field.
    let missing = Body::Unknown(BODY_WAITS).plaintext().unwrap();
    assert_eq!(Body::read(&missing).err(), Some(Rule::field("pushbody/id")));
}

#[test]
fn once_is_the_same_for_every_sender_and_differs_between_keys_and_copies() {
    let a = once(&PK, &[1; 16]);
    assert_eq!(a, once(&PK, &[1; 16]));
    assert_ne!(a, once(&PK, &[2; 16]));
    assert_ne!(a, once(&[8; 32], &[1; 16]));
    assert_ne!(&a[..], &[1u8; 16][..]);
}

#[test]
fn a_unifiedpush_token_holds_the_endpoint_and_the_keys_within_its_bound() {
    let url = String::from("https://up.example.org/") + &"a".repeat(870);
    let p256dh = [4u8; 65];
    let auth = [6u8; 16];
    let t = UnifiedPush { url: &url, p256dh: &p256dh, auth: &auth };
    let token = t.write();
    assert!(token.len() <= MAX_TOKEN, "{}", token.len());
    assert_eq!(UnifiedPush::read(&token).unwrap(), t);
    let plain = UnifiedPush { url: "http://up.example.org/x", ..t.clone() }.write();
    assert_eq!(UnifiedPush::read(&plain).err(), Some(RULE_UP_URL));
    let bare = UnifiedPush { url: "https://", ..t.clone() }.write();
    assert_eq!(UnifiedPush::read(&bare).err(), Some(RULE_UP_URL));
    // The longest send stays on the 4096 step.
    let body = vec![0u8; MAX_BODY];
    let longest = vec![1u8; MAX_TOKEN];
    let s =
        Send { n: u32::MAX as u64, token: &longest, env: ENV_UNIFIEDPUSH, once: [3; 16], body: &body, ttl: Some(4) };
    let f = s.write();
    assert_eq!(f.len() - 4, 4096);
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
    let body = copy_body(&c.copy, &c.readers, &phone, made.id, origin.key.device_id().0);
    let Body::Copy(_) = body else { panic!("a short copy among four readers fits: {body:?}") };
    // The member seals it; the phone opens it, checks the origin from the
    // reduced copy alone and opens its own wrap.
    let sealed = seal(&PK, 3, ENV_APNS, &body, &NONCE).unwrap();
    let Body::Copy(reduced) = open(&PK, 3, &sealed).unwrap() else { panic!() };
    let rv = cbor::decode(&reduced).unwrap();
    let rc = copies::check(&rv, &state).unwrap();
    match copies::open(&rc, &phone, &stores["phone"], &state).unwrap() {
        Opened::Content { content, .. } => assert_eq!(content.text.as_deref(), Some("the code is 4711")),
        other => panic!("{other:?}"),
    }
    // Not a reader: a hint at most.
    let stranger = k("stranger").key.device_id();
    assert!(copy_body(&c.copy, &c.readers, &stranger, made.id, [0; 16]).is_hint());
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
        let b = copy_body(&c.copy, &c.readers, &k("phone").key.device_id(), made.id, [0; 16]);
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
        Body::Waits { id: [7; 16], origin: [9; 16] }
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
    assert_eq!(v["labels"]["once"], LABEL_ONCE);
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
            let nonce: [u8; 12] = sealed[..12].try_into().unwrap();
            assert_eq!(seal(&key, 3, b["env"].as_u64().unwrap(), &body, &nonce).unwrap(), sealed, "sealed {}", name(b));
        }
    }
    for o in v["once"].as_array().unwrap() {
        let key: [u8; 32] = unhex(&o["key"]).try_into().unwrap();
        let id: [u8; 16] = unhex(&o["id"]).try_into().unwrap();
        assert_eq!(once(&key, &id).to_vec(), unhex(&o["once"]));
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
        assert_eq!(got, want(m), "message {}", name(m));
        if let Some(sized) = m.get("sized").and_then(serde_json::Value::as_bool) {
            assert_eq!(Send::read(&msg.map).unwrap().sized(), sized, "sized {}", name(m));
        }
    }
}
