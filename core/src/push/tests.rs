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
const SLOT: [u8; 16] = [9; 16];

fn on_with(env: u64, seq: u64, token: &[u8]) -> Registration {
    let send = k("send key");
    let sig = sign_send(&send, &Signed { env, token, slot: &SLOT, seq, challenge: None }).unwrap();
    Registration {
        seq,
        kinds: KIND_COPIES | KIND_EVENTS,
        on: Some(On {
            token: token.to_vec(),
            env,
            key: Zeroizing::new(PK),
            send_key: send.key.clone(),
            send_sig: sig.to_vec(),
            slot: SLOT,
            challenge: None,
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
    assert!(r.replaced_by(&back, 0) && !back.replaced_by(&r, 0));
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
    // The fields push on needs, in key order around seq (5) and kinds (6).
    let m = |kinds: u64, have: [bool; 6], challenge: bool| {
        let fields: [(u16, Value<'_>); 6] = [
            (2, Value::Bytes(&o.token)),
            (3, Value::Uint(1)),
            (4, Value::Bytes(&o.key[..])),
            (7, kv.clone()),
            (8, Value::Bytes(&o.send_sig)),
            (9, Value::Bytes(&SLOT)),
        ];
        let mut v = vec![(0, Value::Uint(T_PUSH))];
        let mut late = vec![];
        for (i, (n, x)) in fields.into_iter().enumerate() {
            if have[i] {
                if n < 5 { v.push((n, x)) } else { late.push((n, x)) }
            }
        }
        v.push((5, Value::Uint(1)));
        v.push((6, Value::Uint(kinds)));
        v.extend(late);
        if challenge {
            v.push((10, Value::Bytes(&[3; 16])));
        }
        Value::Map(v)
    };
    assert!(Registration::read(&m(1, [true; 6], false)).is_ok());
    assert!(Registration::read(&m(1, [true; 6], true)).is_ok());
    assert!(Registration::read(&m(0, [false; 6], false)).is_ok());
    // A challenge belongs to push on only.
    assert_eq!(Registration::read(&m(0, [false; 6], true)).err(), Some(RULE_PUSH_SHAPE));
    for i in 0..6 {
        let mut have = [true; 6];
        have[i] = false;
        assert_eq!(Registration::read(&m(1, have, false)).err(), Some(RULE_PUSH_SHAPE), "without field {i}");
        let mut only = [false; 6];
        only[i] = true;
        assert_eq!(Registration::read(&m(0, only, false)).err(), Some(RULE_PUSH_SHAPE), "off with field {i}");
    }
}

#[test]
fn the_send_key_signs_the_token_and_the_number_and_a_later_algorithm_is_held() {
    let r = on(ENV_APNS);
    let o = r.on.as_ref().unwrap();
    assert_eq!(
        check_send(
            &o.send_key,
            &o.send_sig,
            &Signed { env: ENV_APNS, token: &o.token, slot: &SLOT, seq: 3, challenge: None }
        ),
        Ok(SendCheck::Good)
    );
    // Another number, token or platform: the signature does not hold.
    assert_eq!(
        check_send(
            &o.send_key,
            &o.send_sig,
            &Signed { env: ENV_APNS, token: &o.token, slot: &SLOT, seq: 4, challenge: None }
        ),
        Err(RULE_SEND_SIG)
    );
    assert_eq!(
        check_send(
            &o.send_key,
            &o.send_sig,
            &Signed { env: ENV_APNS, token: &[2; 32], slot: &SLOT, seq: 3, challenge: None }
        ),
        Err(RULE_SEND_SIG)
    );
    assert_eq!(
        check_send(
            &o.send_key,
            &o.send_sig,
            &Signed { env: ENV_FCM, token: &o.token, slot: &SLOT, seq: 3, challenge: None }
        ),
        Err(RULE_SEND_SIG)
    );
    // A key exchange's algorithm is refused where a send key is wanted; an
    // algorithm this version does not know is held.
    let later = Key { alg: 9, public: vec![1; 2000] };
    assert_eq!(
        check_send(
            &later,
            &[1; 3000],
            &Signed { env: ENV_APNS, token: &o.token, slot: &SLOT, seq: 3, challenge: None }
        ),
        Ok(SendCheck::Unknown)
    );
    let kem = Key { alg: crate::records::key::ALG_X25519, public: vec![1; 32] };
    assert_eq!(
        check_send(&kem, &o.send_sig, &Signed { env: ENV_APNS, token: &o.token, slot: &SLOT, seq: 3, challenge: None }),
        Err(RULE_SEND_SIG)
    );
    let mut held = on(ENV_APNS);
    if let Some(x) = held.on.as_mut() {
        x.send_key = later.clone();
        x.send_sig = vec![1; 3000];
    }
    let back = Registration::read(&read_frame(&held.write().unwrap())).unwrap();
    assert_eq!(back.on.unwrap().send_key, later);
}

/// A number saved while the phone's clock was ahead, then the clock set
/// right: max(saved + 1, now) would stay ahead, and the service would
/// refuse every registration until the clock caught up less a day. The
/// next number is the clock instead, and the service takes it.
#[test]
fn a_number_saved_while_the_clock_was_ahead_starts_again_at_the_clock() {
    let now = 1_800_000_000_000u64;
    for days in [2u64, 30, 365] {
        let saved = now + days * 86_400_000;
        assert!(seq_was_ahead(saved, now));
        let next = next_seq(Some(saved), now);
        assert_eq!(next, now, "{days} days");
        assert!(seq_in_time(next, now));
        // From there on, one more each time.
        assert_eq!(next_seq(Some(next), now), now + 1);
    }
    // Ahead by less than a day: the service took it; one more than it.
    let saved = now + MAX_SEQ_AHEAD_MS;
    assert!(!seq_was_ahead(saved, now));
    assert_eq!(next_seq(Some(saved), now), saved + 1);
}

/// A member takes a lower number only when the one it holds is more than a
/// day ahead of its clock and the newer one is within a day of it.
#[test]
fn a_lower_number_replaces_only_one_out_of_time() {
    let reg = |seq| Registration { seq, kinds: 0, on: None };
    let day = MAX_SEQ_AHEAD_MS;
    let now = 1_800_000_000_000u64;
    // A member with a right clock: the sender's clock jumped 30 days ahead
    // and back. The member held the ahead one; the phone's next, at the
    // clock, replaces it; one two days old does not.
    let ahead = reg(now + 30 * day);
    assert!(ahead.replaced_by(&reg(now), now));
    assert!(ahead.replaced_by(&reg(now - day), now));
    assert!(!ahead.replaced_by(&reg(now - 2 * day), now));
    assert!(!ahead.replaced_by(&reg(now + 2 * day), now));
    // Within a day ahead: a higher number only, as always.
    let near = reg(now + day);
    assert!(!near.replaced_by(&reg(now), now));
    assert!(near.replaced_by(&reg(now + day + 1), now));

    // A member whose own clock is a year behind: the phone's current
    // registration (true time T) is "ahead" by that clock. An old
    // registration from a year ago, replayed, is within a day of the
    // member's clock, so the member takes it; it lasts only until the
    // phone's true registration is seen again, which is higher and so
    // replaces it. A replay of anything older is not taken.
    let t = now;
    let behind = t - 365 * day;
    let current = reg(t);
    let replayed = reg(behind + 1000);
    assert!(current.replaced_by(&replayed, behind));
    assert!(replayed.replaced_by(&current, behind));
    assert!(replayed.replaced_by(&reg(t + 1), behind));
    assert!(!current.replaced_by(&reg(behind - 2 * day), behind));
    // The member's normal case, its clock behind: the phone's next number
    // is higher, and taken.
    assert!(current.replaced_by(&reg(t + 1), behind));
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
        slot: SLOT,
        challenge: Some([3; 16]),
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
    assert!(of(T_PUSH).is_some() && of(T_RENEW).is_some() && of(30).is_none());
    // Renew names the registration's slot, and nothing else.
    let r = renew(&SLOT);
    assert_eq!(read_renew(&read_frame(&r)), Ok(SLOT));
    let short = frame::write(&Value::Map(vec![(0, Value::Uint(T_RENEW)), (2, Value::Bytes(&[1; 15]))]));
    assert!(read_renew(&read_frame(&short)).is_err());
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
        let token = unhex(&r["token"]);
        let slot: [u8; 16] = unhex(&r["slot"]).try_into().unwrap();
        let challenge: Option<[u8; 16]> = r.get("challenge").map(|c| unhex(c).try_into().unwrap());
        let signed = Signed {
            env: r["env"].as_u64().unwrap(),
            token: &token,
            slot: &slot,
            seq: r["seq"].as_u64().unwrap(),
            challenge: challenge.as_ref(),
        };
        let got = verdict(check_send(&key, &unhex(&r["sig"]), &signed), |c| {
            if c == SendCheck::Good { "good".into() } else { "held".into() }
        });
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
    let slot_b64 = key["ok"]["slot"].as_str().unwrap().to_string();
    let slot: [u8; 16] = {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.decode(&slot_b64).unwrap().try_into().unwrap()
    };
    // Each call draws a new slot.
    assert_ne!(call("push_key", serde_json::Value::Null)["ok"]["slot"].as_str().unwrap(), slot_b64);
    let limits = call("push_limits", serde_json::json!({ "env": ENV_APNS }));
    assert_eq!(limits["ok"]["body"], MAX_BODY);
    assert_eq!(limits["ok"]["token"], MAX_TOKEN);
    assert_eq!(call("push_limits", serde_json::json!({ "env": 77 }))["ok"]["known"], false);

    let reg = call(
        "push_registration",
        serde_json::json!({ "saved_seq": 1, "now_ms": 0, "kinds": 3, "env": ENV_APNS, "token": b64(&[5; 32]),
            "key": b64(&PK), "send_key": send_key, "slot": slot_b64 }),
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
    assert_eq!(o.slot, slot);
    assert_eq!(check_send(&o.send_key, &o.send_sig, &o.signed(2)), Ok(SendCheck::Good));
    // The hint the service puts beside a challenge: the send key's hash.
    assert_eq!(reg["ok"]["key_hint"].as_str().unwrap(), b64(&o.send_key.hash().0[..8]));
    assert_eq!(
        check_send(
            &o.send_key,
            &o.send_sig,
            &Signed { env: ENV_APNS, token: &[5; 32], slot: &slot, seq: 2, challenge: None }
        ),
        Ok(SendCheck::Good)
    );
    // Another slot: the signature does not hold.
    assert_eq!(
        check_send(
            &o.send_key,
            &o.send_sig,
            &Signed { env: ENV_APNS, token: &[5; 32], slot: &SLOT, seq: 2, challenge: None }
        ),
        Err(RULE_SEND_SIG)
    );
    // The challenge the service sent is in the registration and under its
    // signature; without it the signature does not hold.
    let ch = call(
        "push_registration",
        serde_json::json!({ "saved_seq": 2, "now_ms": 0, "kinds": 3, "env": ENV_APNS, "token": b64(&[5; 32]),
            "key": b64(&PK), "send_key": send_key, "slot": slot_b64, "challenge": b64(&[4; 16]) }),
    );
    let chf = {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.decode(ch["ok"]["frame"].as_str().unwrap()).unwrap()
    };
    let cr = Registration::read(&read_frame(&chf)).unwrap();
    let co = cr.on.as_ref().unwrap();
    assert_eq!(co.challenge, Some([4; 16]));
    assert_eq!(check_send(&co.send_key, &co.send_sig, &co.signed(3)), Ok(SendCheck::Good));
    assert_eq!(check_send(&co.send_key, &co.send_sig, &Signed { challenge: None, ..co.signed(3) }), Err(RULE_SEND_SIG));
    // Push on without a slot is refused.
    let noslot = call(
        "push_registration",
        serde_json::json!({ "now_ms": 0, "kinds": 3, "env": ENV_APNS, "token": b64(&[5; 32]),
            "key": b64(&PK), "send_key": send_key }),
    );
    assert_eq!(noslot["error"]["code"], 18, "{noslot}");
    // A restored phone whose saved number went back still moves forward.
    let restored = call("push_registration", serde_json::json!({ "saved_seq": 1, "now_ms": T0, "kinds": 0 }));
    assert!(restored["ok"].get("key_hint").is_none(), "push off carries no hint");
    assert_eq!(restored["ok"]["seq"], T0);
    assert!(restored["ok"].get("ahead").is_none());
    // A number saved while the clock was 30 days ahead: the next one is the
    // clock, and the answer says so.
    let month = 30 * 86_400_000u64;
    let back = call("push_registration", serde_json::json!({ "saved_seq": T0 + month, "now_ms": T0, "kinds": 0 }));
    assert_eq!((back["ok"]["seq"].as_u64(), back["ok"]["ahead"].as_bool()), (Some(T0), Some(true)), "{back}");
    let up = call(
        "push_registration",
        serde_json::json!({ "now_ms": 0, "kinds": 1, "env": ENV_UNIFIEDPUSH,
            "unifiedpush": { "url": "http://up.example/x", "p256dh": b64(&point()), "auth": b64(&[1; 16]) },
            "key": b64(&PK), "send_key": send_key, "slot": slot_b64 }),
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
            "sealing": [{ "epoch": epoch, "secret": b64(&secret) }], "now_ms": T0 + 5, "window_ms": 120_000,
            "halted": false, "hints_only": false })
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
    // Any input the rules need left out: the neutral hint.
    for missing in ["now_ms", "window_ms", "halted", "hints_only"] {
        let mut a = args(&origins, serde_json::json!([current]));
        a.as_object_mut().unwrap().remove(missing);
        let got = call("push_open", a);
        assert_eq!(got["ok"]["kind"], "hint", "without {missing}: {got}");
        assert!(got["ok"].get("text").is_none());
    }
    // A halted group opens nothing: the neutral hint.
    let mut halted = args(&origins, serde_json::json!([current]));
    halted["halted"] = true.into();
    let got = call("push_open", halted);
    assert_eq!(got["ok"]["kind"], "hint", "{got}");
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
    let event_at = |body: &[u8], now: u64| {
        call(
            "push_open",
            serde_json::json!({ "keys": [current], "body": b64(body), "me": b64(&phone.0), "now_ms": now,
                "window_ms": 120_000, "halted": false, "hints_only": false }),
        )
    };
    let got = event_at(&sealed_ev, T0 + 10);
    assert_eq!((got["ok"]["kind"].as_str(), got["ok"]["event"].as_u64()), (Some("event"), Some(EVENT_ROOT)), "{got}");
    // An event older than a day, or more than five minutes ahead of the
    // phone's clock, is the neutral hint; so is one with no time.
    assert_eq!(event_at(&sealed_ev, T0 + 86_400_001)["ok"]["kind"], "hint");
    assert_eq!(event_at(&sealed_ev, T0 - 300_000)["ok"]["kind"], "event");
    assert_eq!(event_at(&sealed_ev, T0 - 300_001)["ok"]["kind"], "hint");
    let timeless = Body::Event { id: [8; 16], event: EVENT_ROOT, device: None, time_ms: None };
    assert_eq!(event_at(&seal(&PK, 2, ENV_APNS, &timeless).unwrap(), T0)["ok"]["kind"], "hint");
}

#[test]
fn a_body_whose_nonce_is_not_its_own_is_refused() {
    let body = Body::Waits { id: [1; 16], origin: [2; 16] };
    let sealed = seal(&PK, 5, ENV_APNS, &body).unwrap();
    assert_eq!(open(&PK, 5, &sealed), Ok(body.clone()));
    // The same plaintext under a nonce of the sender's choosing: the AEAD
    // holds, the nonce does not.
    let plain = body.plaintext().unwrap();
    let ad = associated(5);
    let k = derive(&PK, LABEL_BODY);
    let aead = ChaCha20Poly1305::new_from_slice(&k[..]).unwrap();
    let nonce = [0x5a; NONCE_LEN];
    let ct = aead.encrypt(&Nonce::from(nonce), Payload { msg: &plain, aad: &ad }).unwrap();
    let mut other = nonce.to_vec();
    other.extend_from_slice(&ct);
    assert_eq!(other.len(), MAX_BODY);
    assert_eq!(open(&PK, 5, &other), Err(RULE_BODY_NONCE));
}

#[test]
fn a_copy_in_a_body_carries_no_age() {
    let with_age = Value::Map(vec![(crate::format::copy::FIELD_AGE, Value::Uint(1))]).encode();
    let plain = Value::Map(vec![(0, Value::Uint(BODY_COPY)), (2, Value::Bytes(&with_age))]).encode();
    assert_eq!(Body::read(&plain), Err(RULE_BODY_AGE));
}

#[test]
fn the_clock_is_bounded_both_ways() {
    // A phone clock past 2100 (a unit mistake) numbers as 2100, so seq
    // keeps room to move forward.
    assert_eq!(next_seq(None, u64::MAX / 2), MAX_CLOCK_MS);
    assert_eq!(next_seq(Some(MAX_CLOCK_MS), u64::MAX), MAX_CLOCK_MS + 1);
    // The service takes a seq up to a day ahead of its clock, no more.
    assert!(seq_in_time(T0 + MAX_SEQ_AHEAD_MS, T0));
    assert!(!seq_in_time(T0 + MAX_SEQ_AHEAD_MS + 1, T0));
    assert!(seq_in_time(1, T0));
}

#[test]
fn a_host_whose_last_label_starts_with_a_digit_is_refused() {
    for bad in ["https://up.0x7f/x", "https://up.1/x", "https://example.0177/x", "https://a.9example/x"] {
        assert!(!up_url(bad), "{bad}");
    }
    for good in ["https://up.example.org/x", "https://1up.example.org/x", "https://up.example.o1/x"] {
        assert!(up_url(good), "{good}");
    }
}

/// One copy from computer0 to the phone, sealed to the phone's epoch of the
/// statements given, in a body under PK and seq 2.
fn copy_in_a_body(
    g: &G,
    statements: &[crate::records::statement::Statement],
    id: u8,
    wall: u64,
    text: &str,
) -> (Vec<u8>, u64) {
    let state = g.state();
    let refs: Vec<&_> = statements.iter().collect();
    let sealing = sealing(&state, &refs);
    let phone = k("phone").key.device_id();
    let origin = k("computer0");
    let content = Content::text(text, false);
    let rs = copies::readers(&state, &sealing, &content, &origin.key.device_id(), &[], None);
    let made = Made { id: [id; 16], time: Timestamp { wall: wall as i64, logical: 0 }, blob: None };
    let copy = copies::seal(&origin, &rs, &made, &content).unwrap();
    let c = copies::check(&cbor::decode(&copy).unwrap(), &state).unwrap();
    let epoch = c.readers.iter().find(|(d, _)| *d == phone).unwrap().1;
    let body = copy_body(&c.copy, &c.readers, &phone, made.id, origin.key.device_id().0).unwrap();
    (seal(&PK, 2, ENV_APNS, &body).unwrap(), epoch)
}

fn interop() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../testdata/interop/push-open.json")
}

/// What the phone's notification extension is handed across a rotation of
/// its sealing key: a copy sealed to the first epoch, then one sealed to the
/// second, and which epochs' secrets the app leaves it at each step.
fn push_open_vectors() -> serde_json::Value {
    let (g, _, mut stores, mut statements) = world(1);
    let phone_store = stores.get_mut("phone").unwrap();
    let secret = |s: &crate::keystore::MemoryStore<crate::testkit::K>, e: u64| {
        b64(&crate::keystore::KeyStore::sealing(s, e).unwrap())
    };
    let (first, e1) = copy_in_a_body(&g, &statements, 5, T0 + 5, "the code is 4711");
    let s1 = secret(phone_store, e1);
    // A week on: a new epoch, the previous kept a week more.
    let week = crate::keystore::WEEK_MS;
    let made = crate::keystore::rotate(phone_store, &g.gid, T0 + week, Some(T0 + week)).unwrap().made.unwrap();
    statements[0] = crate::testkit::statement_of(&made);
    let (second, e2) = copy_in_a_body(&g, &statements, 6, T0 + week + 5, "the new code is 1234");
    assert_ne!(e1, e2);
    let s2 = secret(phone_store, e2);
    // Two weeks on: the first epoch has left the window and is erased.
    let erased = crate::keystore::rotate(phone_store, &g.gid, T0 + 2 * week, Some(T0 + 2 * week)).unwrap().erased;
    assert!(erased.contains(&e1), "{erased:?}");
    let state = g.state();
    let od = state.device(&k("computer0").key.device_id()).unwrap();
    serde_json::json!({
        "comment": "Written by the Rust core's push tests with CBB_UPDATE_VECTORS=1. The kits' notification extensions open each body with the secrets the app leaves at each step: a copy sealed to an epoch the extension holds shows its text, one sealed to an epoch that left the window does not.",
        "key": b64(&PK), "seq": 2, "me": b64(&k("phone").key.device_id().0), "window_ms": 120_000,
        "origins": [{ "key": b64(&od.key.encode()), "rights": od.rights }],
        "bodies": {
            "first": { "body": b64(&first), "now_ms": T0 + 1_000, "text": "the code is 4711" },
            "second": { "body": b64(&second), "now_ms": T0 + week + 1_000, "text": "the new code is 1234" },
        },
        "steps": [
            { "name": "before the rotation", "sealing": [{ "epoch": e1, "secret": s1 }], "opens": ["first"] },
            { "name": "a week on, both epochs in the window",
              "sealing": [{ "epoch": e2, "secret": s2 }, { "epoch": e1, "secret": s1 }], "opens": ["first", "second"] },
            { "name": "two weeks on, the first epoch out of the window",
              "sealing": [{ "epoch": e2, "secret": s2 }], "opens": ["second"] },
        ],
    })
}

/// testdata/interop/push-open.json, which this writes with
/// CBB_UPDATE_VECTORS=1: at each step a body opens to its text exactly
/// when the extension holds its epoch's secret, and else waits.
#[test]
fn the_extension_opens_what_its_epochs_open_across_a_rotation() {
    if std::env::var("CBB_UPDATE_VECTORS").as_deref() == Ok("1") {
        let mut s = serde_json::to_string_pretty(&push_open_vectors()).unwrap();
        s.push('\n');
        std::fs::write(interop(), s).unwrap();
    }
    let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(interop()).unwrap()).unwrap();
    let steps = v["steps"].as_array().unwrap();
    assert_eq!(steps.len(), 3);
    for step in steps {
        let opens: Vec<&str> = step["opens"].as_array().unwrap().iter().map(|o| o.as_str().unwrap()).collect();
        for (name, b) in v["bodies"].as_object().unwrap() {
            let got = call(
                "push_open",
                serde_json::json!({ "keys": [{ "key": v["key"], "seq": v["seq"] }], "body": b["body"], "me": v["me"],
                    "origins": v["origins"], "sealing": step["sealing"], "now_ms": b["now_ms"],
                    "window_ms": v["window_ms"], "halted": false, "hints_only": false }),
            );
            let what = format!("{} {name}: {got}", step["name"]);
            if opens.contains(&name.as_str()) {
                assert_eq!((&got["ok"]["kind"], &got["ok"]["text"]), (&"copy".into(), &b["text"]), "{what}");
            } else {
                assert_eq!(got["ok"]["kind"], "waits", "{what}");
                assert!(got["ok"].get("text").is_none(), "{what}");
            }
        }
    }
}
