// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Commands: their form, who a member obeys, who a leaf obeys, the guarded
//! leaf's one-time number, counters, sealed orders, and the vectors.

use alloc::string::String;
use alloc::vec;

use serde_json::Value as Json;

use super::*;
use crate::format::grant::Kept;
use crate::keystore::MemoryStore;
use crate::records::body::*;
use crate::records::{Body, Record};
use crate::testkit::{G, K, T0, k, store};

fn orders(entries: Vec<(u16, Value<'_>)>) -> Vec<u8> {
    Value::Map(entries).encode()
}

struct World {
    g: G,
    laptop: K,
    laptop_store: MemoryStore<K>,
    seal: (u64, Vec<u8>),
}

impl World {
    fn new() -> World {
        let mut g = G::new();
        g.device("phone", ROLE_PHONE, RIGHT_READ | RIGHT_SEND, |_| {});
        let laptop = g.device("laptop", ROLE_MEMBER, RIGHT_READ | RIGHT_SEND, |_| {});
        g.admin("desk", "desk admin", AdminKind::Computer);
        g.admin("watch", "watch admin", AdminKind::Watch);
        let (laptop_store, st) = store("laptop", &g.gid);
        let seal = (st.body().epoch, st.body().seal.public.clone());
        World { g, laptop, laptop_store, seal }
    }

    fn draft<'a>(&'a self, kind: u64, n: u64, o: Option<&'a [u8]>) -> Draft<'a> {
        Draft {
            kind,
            group: self.g.gid,
            to: self.laptop.key.device_id(),
            n,
            time_ms: T0,
            nonce: None,
            orders: o,
            seal_to: Some((self.seal.0, &self.seal.1)),
        }
    }

    fn take(&self, env: &[u8], counters: &mut Counters, now: Option<u64>) -> Result<Option<Vec<u8>>, Rule> {
        let c = Command::read(env)?;
        self.accept(&c, counters, now).map_err(|r| r.rule)
    }

    fn accept(&self, c: &Command<'_>, counters: &mut Counters, now: Option<u64>) -> Result<Option<Vec<u8>>, Refusal> {
        let state = self.g.state();
        let at = Member { me: self.laptop.key.device_id(), state: &state, set: &self.g.set, now_ms: now };
        accept_member(c, &at, counters, &self.laptop_store)
    }
}

#[test]
fn a_member_obeys_the_root_and_its_admins_by_their_commands() {
    let w = World::new();
    let mut ctr = Counters::default();
    let paste = orders(vec![(10, Value::Uint(1)), (12, Value::Uint(1)), (13, Value::Text("hi"))]);
    let env = make(&w.draft(COMMAND_PASTE, 1, Some(&paste)), &k("root")).unwrap();
    assert_eq!(w.take(&env, &mut ctr, Some(T0)).unwrap(), Some(paste.clone()));
    // The same counter again: refused, also after a restart.
    let again = make(&w.draft(COMMAND_PASTE, 1, Some(&paste)), &k("root")).unwrap();
    let mut back = Counters::decode(&ctr.encode()).unwrap();
    assert_eq!(back, ctr);
    assert_eq!(w.take(&again, &mut back, Some(T0)), Err(RULE_COUNTER));
    // An admin of a computer: all types.
    let env = make(&w.draft(COMMAND_PASTE_OFF, 5, None), &k("desk admin")).unwrap();
    assert_eq!(w.take(&env, &mut ctr, Some(T0)), Ok(None));
    // A watch's admin may not paste.
    let env = make(&w.draft(COMMAND_PASTE, 6, Some(&paste)), &k("watch admin")).unwrap();
    assert_eq!(w.take(&env, &mut ctr, Some(T0)), Err(RULE_RIGHT));
    // A member key commands nothing; nor does a stranger.
    for who in ["phone", "stranger", "desk"] {
        let env = make(&w.draft(COMMAND_PASTE_OFF, 7, None), &k(who)).unwrap();
        assert_eq!(w.take(&env, &mut ctr, Some(T0)), Err(RULE_SIGNER), "{who}");
    }
    // Another receiver, another group.
    let mut d = w.draft(COMMAND_PASTE_OFF, 8, None);
    d.to = k("phone").key.device_id();
    assert_eq!(w.take(&make(&d, &k("root")).unwrap(), &mut ctr, Some(T0)), Err(RULE_TO));
    let mut d = w.draft(COMMAND_PASTE_OFF, 9, None);
    d.group = k("other root").key.device_id();
    assert_eq!(w.take(&make(&d, &k("root")).unwrap(), &mut ctr, Some(T0)), Err(RULE_GROUP));
    // Expired on a receiver with a clock; a leaf without one decides by n.
    let env = make(&w.draft(COMMAND_PASTE_OFF, 10, None), &k("root")).unwrap();
    assert_eq!(w.take(&env, &mut ctr.clone(), Some(T0 + LIFETIME_MS + SKEW_MS + 1)), Err(RULE_LATE));
    assert_eq!(w.take(&env, &mut ctr.clone(), Some(T0 - SKEW_MS - 1)), Err(RULE_LATE));
    assert_eq!(w.take(&env, &mut ctr, None), Ok(None));
}

/// A member without a trusted clock is a stated case: it judges no time
/// and decides by the signer's counter alone, so a command is taken once
/// however old it is, and never twice.
#[test]
fn a_receiver_without_a_trusted_clock_decides_by_the_counter() {
    let w = World::new();
    let mut ctr = Counters::default();
    let mut old = w.draft(COMMAND_PASTE_OFF, 3, None);
    old.time_ms = T0 - 365 * 86_400_000;
    let env = make(&old, &k("root")).unwrap();
    assert_eq!(w.take(&env, &mut ctr.clone(), Some(T0)), Err(RULE_LATE), "with a clock: late");
    assert_eq!(w.take(&env, &mut ctr, None), Ok(None), "without one: by n");
    assert_eq!(w.take(&env, &mut ctr, None), Err(RULE_COUNTER));
    let lower = make(&w.draft(COMMAND_PASTE_OFF, 2, None), &k("root")).unwrap();
    assert_eq!(w.take(&lower, &mut ctr, None), Err(RULE_COUNTER));
}

/// A late command is refused back to its sender with the rule's name, so
/// the sender's app can say that a clock is off.
#[test]
fn a_late_command_is_refused_back_with_its_rule() {
    let w = World::new();
    let env = make(&w.draft(COMMAND_PASTE_OFF, 1, None), &k("root")).unwrap();
    let c = Command::read(&env).unwrap();
    let r = w.accept(&c, &mut Counters::default(), Some(T0 + LIFETIME_MS + SKEW_MS + 1)).unwrap_err();
    assert_eq!(r, Refusal { rule: RULE_LATE, answer: true });
    let me = w.laptop.key.device_id();
    let r = refusal(&c.id, &me, r).unwrap();
    let m = frame::read(&r, frame::LIMIT_LEAF).unwrap();
    assert_eq!(m.t, crate::msg::tables::T_RESULT);
    assert_eq!(crate::msg::check(&m.map.encode()), Ok(crate::msg::tables::T_RESULT));
    assert_eq!(m.get(2).and_then(Value::as_bytes), Some(&c.id[..]));
    assert_eq!(m.get(3).and_then(Value::as_bytes), Some(&me.0[..]));
    assert_eq!(m.get(4), Some(&Value::Uint(STATUS_REFUSED)));
    assert_eq!(m.get(5), Some(&Value::Text("commands/late")));
}

/// The counters are saved before the command's effect. A restart from the
/// state one step old (saved before this command) means its effect did
/// not happen yet: the command is taken once more, and then never again.
#[test]
fn counters_survive_a_restart_from_a_state_one_step_old() {
    let w = World::new();
    let mut ctr = Counters::default();
    let first = make(&w.draft(COMMAND_PASTE_OFF, 1, None), &k("root")).unwrap();
    w.take(&first, &mut ctr, Some(T0)).unwrap();
    let one_step_old = ctr.encode();
    let next = make(&w.draft(COMMAND_PASTE_OFF, 2, None), &k("root")).unwrap();
    w.take(&next, &mut ctr, Some(T0)).unwrap();
    // Saved, then the device stops before the effect: back at the old state.
    let mut back = Counters::decode(&one_step_old).unwrap();
    assert_eq!(w.take(&first, &mut back, Some(T0)), Err(RULE_COUNTER), "the step before stays done");
    assert_eq!(w.take(&next, &mut back, Some(T0)), Ok(None), "this one runs once");
    let saved = back.encode();
    assert_eq!(w.take(&next, &mut Counters::decode(&saved).unwrap(), Some(T0)), Err(RULE_COUNTER));
}

#[test]
fn a_removed_frozen_or_forked_key_commands_nothing() {
    let paste_off = |w: &World, by: &str, n| make(&w.draft(COMMAND_PASTE_OFF, n, None), &k(by)).unwrap();
    // Frozen.
    let mut w = World::new();
    w.g.freeze(&[k("desk").hash]);
    assert_eq!(w.take(&paste_off(&w, "desk admin", 1), &mut Counters::default(), Some(T0)), Err(RULE_SIGNER));
    // Removed.
    let mut w = World::new();
    w.g.revoke(&[k("desk").hash]);
    assert_eq!(w.take(&paste_off(&w, "desk admin", 1), &mut Counters::default(), Some(T0)), Err(RULE_SIGNER));
    // Two histories: the admin key signs two records with one seq.
    let mut w = World::new();
    let admin = k("desk admin");
    for ms in [10_000, 20_000] {
        let body = Body {
            group: w.g.gid,
            signer: admin.hash,
            seq: 1,
            prev: None,
            time_ms: 0,
            kind: Kind::Copies { incoming_ms: ms },
            held: false,
        };
        let _ = w.g.set.insert(Record::sign(body, &admin).unwrap());
    }
    let state = w.g.state();
    assert!(state.two_histories(&admin.hash), "{:?}", state.conflicts);
    assert_eq!(w.take(&paste_off(&w, "desk admin", 1), &mut Counters::default(), Some(T0)), Err(RULE_SIGNER));
    // The root still commands.
    assert_eq!(w.take(&paste_off(&w, "root", 1), &mut Counters::default(), Some(T0)), Ok(None));
}

#[test]
fn orders_are_sealed_to_the_receiver_only() {
    let w = World::new();
    let mode = orders(vec![(10, Value::Uint(2))]);
    let env = make(&w.draft(COMMAND_MODE, 1, Some(&mode)), &k("root")).unwrap();
    let c = Command::read(&env).unwrap();
    assert!(c.sealed.is_some() && c.epoch == Some(w.seal.0));
    // The phone cannot open them.
    let (phone_store, _) = store("phone", &w.g.gid);
    assert_eq!(c.open(&phone_store), Err(RULE_SEALED));
    // An epoch the receiver no longer holds.
    let mut d = w.draft(COMMAND_MODE, 2, Some(&mode));
    let old = d.seal_to.unwrap().1;
    d.seal_to = Some((9, old));
    assert_eq!(w.take(&make(&d, &k("root")).unwrap(), &mut Counters::default(), Some(T0)), Err(RULE_EPOCH));
    // Orders in the open: the form reads (a later receiver refuses), this
    // receiver refuses.
    let body = Value::Map(vec![
        (1, Value::Uint(COMMAND_MODE)),
        (2, Value::Bytes(&w.g.gid.0)),
        (3, Value::Bytes(&k("root").hash.0)),
        (4, Value::Uint(3)),
        (6, Value::Uint(T0)),
        (7, Value::Uint(T0 + 1000)),
        (10, Value::Bytes(&w.laptop.key.device_id().0)),
        (11, Value::Bytes(&[1; 16])),
    ])
    .encode();
    let open = envelope::sign(&k("root").sk, sig::LABEL_COMMAND, &body);
    assert_eq!(w.take(&open, &mut Counters::default(), Some(T0)), Err(RULE_SEALED));
    // A writer never makes orders that break their rows.
    let bad = orders(vec![(10, Value::Uint(3))]);
    assert!(make(&w.draft(COMMAND_MODE, 4, Some(&bad)), &k("root")).is_err());
    assert!(make(&w.draft(COMMAND_PASTE_OFF, 4, Some(&mode)), &k("root")).is_err());
}

fn body(fields: Vec<(u16, Value<'_>)>) -> Vec<u8> {
    envelope::sign(&k("root").sk, sig::LABEL_COMMAND, &Value::Map(fields).encode())
}

#[test]
fn the_form_and_its_rules_between_fields() {
    let g = [1u8; 16];
    let s = k("root").hash.0;
    let to = [2u8; 16];
    let id = [3u8; 16];
    let sealed = vec![0u8; crate::seal::OVERHEAD + 3];
    let base = |t: u64| -> Vec<(u16, Value<'static>)> {
        vec![(1, Value::Uint(t)), (4, Value::Uint(1)), (6, Value::Uint(T0)), (7, Value::Uint(T0 + 30_000))]
    };
    let full = |t: u64, extra: Vec<(u16, Value<'_>)>| {
        // The extra fields first: they replace the base's.
        let mut f = extra;
        f.extend(base(t));
        f.push((2, Value::Bytes(&g)));
        f.push((3, Value::Bytes(&s)));
        f.push((10, Value::Bytes(&to)));
        f.push((11, Value::Bytes(&id)));
        f.sort_by_key(|(n, _)| *n);
        f.dedup_by_key(|(n, _)| *n);
        body(f)
    };
    assert!(Command::read(&full(COMMAND_PASTE_OFF, vec![])).is_ok());
    assert!(Command::read(&full(COMMAND_MODE, vec![(14, Value::Uint(1)), (15, Value::Bytes(&sealed))])).is_ok());
    let cases: Vec<(&str, Vec<u8>, Rule)> = vec![
        ("type 0", full(0, vec![]), RULE_TYPE),
        ("type 11", full(11, vec![]), RULE_TYPE),
        ("lifetime 30 s and 1 ms", full(4, vec![(7, Value::Uint(T0 + 30_001))]), RULE_EXPIRES),
        ("expires at time", full(4, vec![(7, Value::Uint(T0))]), RULE_EXPIRES),
        ("n 0", full(4, vec![(4, Value::Uint(0))]), RULE_N),
        ("nonce of 15 bytes", full(4, vec![(13, Value::Bytes(&[0; 15]))]), RULE_NONCE),
        ("epoch without sealed", full(1, vec![(14, Value::Uint(1))]), RULE_EPOCH),
        ("sealed without epoch", full(1, vec![(15, Value::Bytes(&sealed))]), RULE_EPOCH),
        (
            "sealed on a type without orders",
            full(4, vec![(14, Value::Uint(1)), (15, Value::Bytes(&sealed))]),
            RULE_SEALED,
        ),
        ("sealed shorter than a seal", full(1, vec![(14, Value::Uint(1)), (15, Value::Bytes(&[0; 10]))]), RULE_SEALED),
        ("epoch 0 written", full(1, vec![(14, Value::Uint(0)), (15, Value::Bytes(&sealed))]), Rule::FORM_DEFAULT),
        ("class, gone", full(4, vec![(12, Value::Uint(4))]), Rule::FORM_CRITICAL),
        ("signer2", full(4, vec![(8, Value::Bytes(&s))]), Rule::ENV_SHAPE),
        ("a later critical field", full(4, vec![(99, Value::Uint(1))]), Rule::FORM_CRITICAL),
        ("to of 15 bytes", full(4, vec![(10, Value::Bytes(&[0; 15]))]), RULE_TO),
    ];
    for (name, env, rule) in cases {
        assert_eq!(Command::read(&env).err(), Some(rule), "{name}");
    }
    // An optional field of a later version is skipped.
    assert!(Command::read(&full(4, vec![(300, Value::Uint(1))])).is_ok());
}

#[test]
fn orders_of_each_type() {
    let ok: Vec<(u64, Vec<u8>)> = vec![
        (COMMAND_MODE, orders(vec![(10, Value::Uint(1))])),
        (
            COMMAND_PASTE,
            orders(vec![(10, Value::Uint(2)), (11, Value::Uint(1)), (12, Value::Uint(2)), (13, Value::Text("pw\n"))]),
        ),
        (COMMAND_PASTE, orders(vec![(10, Value::Uint(1)), (12, Value::Uint(3)), (14, Value::Bytes(&[1; 16]))])),
        (COMMAND_ACTION, orders(vec![(10, Value::Text("lock-screen"))])),
        (COMMAND_MUTE, orders(vec![])),
        (COMMAND_MUTE, orders(vec![(10, Value::Uint(60_000))])),
        (COMMAND_DEVICE, orders(vec![(10, Value::Text("heat")), (11, Value::Bytes(&[0xa1, 0x01, 0x18, 0x5a]))])),
        (COMMAND_HUB, orders(vec![(13, Value::Uint(1))])),
        (COMMAND_HUB, orders(vec![(11, Value::Array(vec![Value::Text("[2001:db8::1]:443")]))])),
    ];
    for (t, o) in ok {
        assert_eq!(orders::check(t, &o), Ok(()), "{t}");
    }
    let typed = "x".repeat(orders::MAX_TYPED_TEXT + 1);
    let bad: Vec<(u64, Vec<u8>, Rule)> = vec![
        (COMMAND_MODE, orders(vec![]), orders::RULE_MODE),
        (COMMAND_MODE, orders(vec![(10, Value::Uint(1)), (11, Value::Uint(1))]), Rule::FORM_CRITICAL),
        (COMMAND_PASTE, orders(vec![(10, Value::Uint(1)), (12, Value::Uint(1))]), orders::RULE_PASTE),
        (
            COMMAND_PASTE,
            orders(vec![(10, Value::Uint(2)), (12, Value::Uint(1)), (13, Value::Text(&typed))]),
            orders::RULE_PASTE,
        ),
        (
            COMMAND_PASTE,
            orders(vec![(10, Value::Uint(1)), (12, Value::Uint(3)), (13, Value::Text("x"))]),
            orders::RULE_PASTE,
        ),
        (
            COMMAND_PASTE,
            orders(vec![(10, Value::Uint(1)), (11, Value::Uint(2)), (12, Value::Uint(1)), (13, Value::Text("x"))]),
            orders::RULE_PASTE,
        ),
        (COMMAND_ACTION, orders(vec![(10, Value::Text("Reboot"))]), orders::RULE_ACTION),
        (COMMAND_ACTION, orders(vec![(10, Value::Text("1st"))]), orders::RULE_ACTION),
        (COMMAND_MUTE, orders(vec![(10, Value::Uint(orders::MAX_MUTE_MS + 1))]), orders::RULE_MUTE),
        (COMMAND_DEVICE, orders(vec![(10, Value::Text("he\u{202e}at"))]), orders::RULE_DEVICE),
        (COMMAND_DEVICE, orders(vec![(10, Value::Text("heat")), (11, Value::Bytes(&[0x82]))]), orders::RULE_DEVICE),
        (
            COMMAND_HUB,
            orders(vec![(13, Value::Uint(1)), (11, Value::Array(vec![Value::Text("a:1")]))]),
            orders::RULE_HUB,
        ),
        (COMMAND_HUB, orders(vec![]), orders::RULE_HUB),
    ];
    for (t, o, rule) in bad {
        assert_eq!(orders::check(t, &o), Err(rule), "{t} {o:02x?}");
    }
}

/// A leaf and the grant it keeps: an ordinary kettle obeys its
/// commanders; a guarded lock wants a one-time number on every command and
/// obeys nobody with a stale grant.
#[test]
fn a_leaf_obeys_its_grant() {
    let g = G::new();
    let (kettle_store, kst) = store("kettle", &g.gid);
    let kettle = k("kettle").key.device_id();
    let phone = k("phone");
    let point = |x: &K| -> [u8; 65] { x.key.public.clone().try_into().unwrap() };
    let mut kept = Kept { commanders: vec![(phone.hash, point(&phone))], ..Kept::default() };
    let heat = orders(vec![(10, Value::Text("heat"))]);
    let draft = |n, nonce| Draft {
        kind: COMMAND_DEVICE,
        group: g.gid,
        to: kettle,
        n,
        time_ms: T0,
        nonce,
        orders: Some(&heat),
        seal_to: Some((kst.body().epoch, &kst.body().seal.public)),
    };
    let take = |env: &[u8], kept: &Kept, stale: bool, ctr: &mut Counters, nonces: &mut Nonces| {
        let c = Command::read(env)?;
        let at = Leaf { me: kettle, group: g.gid, kept, stale, now_ms: None };
        accept_leaf(&c, &at, ctr, nonces, &kettle_store).map_err(|r| r.rule)
    };
    let (mut ctr, mut nonces) = (Counters::default(), Nonces::default());
    let env = make(&draft(1, None), &phone).unwrap();
    assert_eq!(take(&env, &kept, false, &mut ctr, &mut nonces), Ok(Some(heat.clone())));
    assert_eq!(take(&env, &kept, false, &mut ctr, &mut nonces), Err(RULE_COUNTER));
    // The root is no commander of this kettle.
    let env = make(&draft(2, None), &k("root")).unwrap();
    assert_eq!(take(&env, &kept, false, &mut ctr, &mut nonces), Err(RULE_SIGNER));
    // Guarded: each command with the number the lock gave out, once.
    kept.guarded = true;
    let env = make(&draft(3, None), &phone).unwrap();
    assert_eq!(take(&env, &kept, false, &mut ctr, &mut nonces), Err(RULE_NONCE));
    let n = nonces.issue(&phone.hash).unwrap();
    let wrong = make(&draft(4, Some([0; 16])), &phone).unwrap();
    assert_eq!(take(&wrong, &kept, false, &mut ctr, &mut nonces), Err(RULE_NONCE));
    let n2 = nonces.issue(&phone.hash).unwrap();
    assert_ne!(n, n2);
    let stale_n = make(&draft(5, Some(n)), &phone).unwrap();
    assert_eq!(take(&stale_n, &kept, false, &mut ctr, &mut nonces), Err(RULE_NONCE), "a number replaced is gone");
    let n3 = nonces.issue(&phone.hash).unwrap();
    let good = make(&draft(6, Some(n3)), &phone).unwrap();
    assert_eq!(take(&good, &kept, false, &mut ctr, &mut nonces), Ok(Some(heat.clone())));
    let replay = make(&draft(7, Some(n3)), &phone).unwrap();
    assert_eq!(take(&replay, &kept, false, &mut ctr, &mut nonces), Err(RULE_NONCE), "a number is used once");
    // A forged command does not use up the number.
    let n4 = nonces.issue(&phone.hash).unwrap();
    let forged = make(&Draft { to: kettle, ..draft(8, Some(n4)) }, &k("stranger")).unwrap();
    assert_eq!(take(&forged, &kept, false, &mut ctr, &mut nonces), Err(RULE_SIGNER));
    let after = make(&draft(9, Some(n4)), &phone).unwrap();
    assert_eq!(take(&after, &kept, false, &mut ctr, &mut nonces), Ok(Some(heat.clone())));
    // A stale grant: nothing runs.
    let n5 = nonces.issue(&phone.hash).unwrap();
    let env = make(&draft(10, Some(n5)), &phone).unwrap();
    assert!(stale(true, None, DEFAULT_LIFE_MS));
    assert!(!stale(true, None, DEFAULT_LIFE_MS - 1));
    assert!(!stale(false, None, u64::MAX));
    assert_eq!(take(&env, &kept, true, &mut ctr, &mut nonces), Err(RULE_STALE));
    // Message nonce: from the leaf with a number, to it without.
    let nm = nonce_message(Some(&n5));
    let m = frame::read(&nm, frame::LIMIT_LEAF).unwrap();
    assert_eq!((m.t, m.get(2).and_then(Value::as_bytes)), (T_NONCE, Some(&n5[..])));
    assert_eq!(frame::read(&nonce_message(None), frame::LIMIT_LEAF).unwrap().get(2), None);
    // A command message fits the leaf's frame.
    assert!(message(&good).unwrap().len() <= frame::LIMIT_LEAF);
}

/// A guarded lock's number is used up only by a signed command that shows
/// it after its counter passed: an old command sent again leaves it.
#[test]
fn an_old_command_sent_again_leaves_the_number() {
    let g = G::new();
    let (lock_store, lst) = store("lock", &g.gid);
    let lock = k("lock").key.device_id();
    let phone = k("phone");
    let point: [u8; 65] = phone.key.public.clone().try_into().unwrap();
    let kept = Kept { commanders: vec![(phone.hash, point)], guarded: true, ..Kept::default() };
    let open = orders(vec![(10, Value::Text("open"))]);
    let draft = |n, nonce| Draft {
        kind: COMMAND_DEVICE,
        group: g.gid,
        to: lock,
        n,
        time_ms: T0,
        nonce,
        orders: Some(&open),
        seal_to: Some((lst.body().epoch, &lst.body().seal.public)),
    };
    let take = |env: &[u8], ctr: &mut Counters, nonces: &mut Nonces| {
        let c = Command::read(env).unwrap();
        let at = Leaf { me: lock, group: g.gid, kept: &kept, stale: false, now_ms: None };
        accept_leaf(&c, &at, ctr, nonces, &lock_store)
    };
    let (mut ctr, mut nonces) = (Counters::default(), Nonces::default());
    let n1 = nonces.issue(&phone.hash).unwrap();
    let first = make(&draft(1, Some(n1)), &phone).unwrap();
    assert_eq!(take(&first, &mut ctr, &mut nonces), Ok(Some(open.clone())));
    // The person confirms the next command: the lock gives n2. The old
    // command is sent again on the way: refused by its counter, n2 stays.
    let n2 = nonces.issue(&phone.hash).unwrap();
    assert_eq!(take(&first, &mut ctr, &mut nonces), Err(Refusal { rule: RULE_COUNTER, answer: true }));
    // A signed command with another number leaves n2 too.
    let wrong = make(&draft(2, Some([7; 16])), &phone).unwrap();
    assert_eq!(take(&wrong, &mut ctr, &mut nonces), Err(Refusal { rule: RULE_NONCE, answer: true }));
    let confirmed = make(&draft(3, Some(n2)), &phone).unwrap();
    assert_eq!(take(&confirmed, &mut ctr, &mut nonces), Ok(Some(open.clone())));
}

/// A forged command gets no answer and the same refusal whatever it
/// claims: the signature is checked before the signer's rights.
#[test]
fn a_forged_command_gets_no_answer() {
    let w = World::new();
    let paste = orders(vec![(10, Value::Uint(1)), (12, Value::Uint(1)), (13, Value::Text("hi"))]);
    // A stranger's command in the watch admin's name: it may not paste,
    // but nobody learns that from a forgery.
    let mut forged = make(&w.draft(COMMAND_PASTE, 1, Some(&paste)), &k("stranger")).unwrap();
    let c = Command::read(&forged).unwrap();
    assert_eq!(w.accept(&c, &mut Counters::default(), Some(T0)), Err(Refusal::SILENT));
    let real = make(&w.draft(COMMAND_PASTE, 1, Some(&paste)), &k("watch admin")).unwrap();
    let rc = Command::read(&real).unwrap();
    let body = rc.envelope.body.to_vec();
    forged = crate::format::envelope::write(&body, &[1; 64], None);
    let fc = Command::read(&forged).unwrap();
    assert_eq!(w.accept(&fc, &mut Counters::default(), Some(T0)), Err(Refusal::SILENT));
    assert_eq!(refusal(&fc.id, &w.laptop.key.device_id(), Refusal::SILENT), None);
    // The watch admin's own command: refused with its rule, answered.
    assert_eq!(w.accept(&rc, &mut Counters::default(), Some(T0)), Err(Refusal { rule: RULE_RIGHT, answer: true }));
}

fn load(name: &str) -> Json {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../testdata/format").join(name);
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

/// commands.json: the form level of each vector. A guarded lock's command
/// without a number reads; the lock refuses it (`a_leaf_obeys_its_grant`).
#[test]
fn command_vectors() {
    let v = load("commands.json");
    for t in v["take"].as_array().unwrap() {
        let env = unhex(t["envelope"].as_str().unwrap());
        assert!(Command::read(&env).is_ok(), "{}: {:?}", t["name"], Command::read(&env).err());
    }
    for r in v["refuse"].as_array().unwrap() {
        let env = unhex(r["envelope"].as_str().unwrap());
        let rule: String = r["rule"].as_str().unwrap().into();
        match Command::read(&env) {
            Err(e) => assert_eq!(e.name(), rule, "{}", r["name"]),
            Ok(c) => {
                assert_eq!(rule, "commands/nonce", "{}", r["name"]);
                assert!(c.nonce.is_none());
            }
        }
    }
}
