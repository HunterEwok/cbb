// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Power cut in the middle of a save, at every byte: a member's saved
//! state (its records with the lists of the changes of root, its command
//! counters and its copies' freshness marks) goes through the
//! two-slot store (`crate::store`) of a device with only flash, and each
//! save is cut after each of its bytes, the rest of the slot left erased
//! or left as it was. After every cut the member starts again from what
//! the flash holds and is sent again what it was handling, then the rest.
//!
//! Checked at each cut: the state reads; it is the state before the save
//! or the state after it, never a mix; the member ends where one that was
//! never cut ends; no command runs twice and none is lost, no copy is
//! written twice and a secret never again, nothing accepted is lost, and a
//! change of root it reported stays.
//!
//! A member acts on a command or writes a copy only after the save that
//! records it is complete; a cut before that leaves it undone, and the
//! command or copy, sent again, is taken then.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use crate::commands::Counters;
use crate::copies::fresh::{Fresh, Marks, Seen};
use crate::hlc::Timestamp;
use crate::records::body::*;
use crate::records::set::RecordSet;
use crate::records::{Key, KeyHash, Record};
use crate::store::{self, Fields};
use crate::testkit::{G, k, recovery, rk2};

const SLOT: usize = 32 << 10;

const TAG_RECORDS: u8 = 1;
const TAG_LISTS: u8 = 2;
const TAG_COUNTERS: u8 = 4;
const TAG_MARKS: u8 = 5;

/// How the rest of a slot looks after a cut: erased before the write, as
/// flash is, or with the bytes of the copy that was there.
#[derive(Clone, Copy, Debug)]
enum Tear {
    Erased,
    Stale,
}

struct Flash {
    slots: [Vec<u8>; 2],
}

impl Flash {
    fn new() -> Flash {
        Flash { slots: [alloc::vec![0xff; SLOT], alloc::vec![0xff; SLOT]] }
    }

    fn load(&self) -> Option<Fields> {
        let n = store::newest(&self.slots[0], &self.slots[1])?;
        Fields::decode(n.payload)
    }

    fn newest(&self) -> Option<(usize, u32)> {
        store::newest(&self.slots[0], &self.slots[1]).map(|n| (n.slot, n.seq))
    }

    /// Saves fields; cut: Some((n, tear)) stops after n bytes of the frame.
    /// Returns the frame's length, and whether it was written whole.
    fn save(&mut self, f: &Fields, cut: Option<(usize, Tear)>) -> (usize, bool) {
        let (slot, seq) = store::next(self.newest());
        let frame = store::frame(seq, &f.encode());
        assert!(frame.len() <= SLOT);
        let s = &mut self.slots[slot];
        match cut {
            Some((n, _)) if n >= frame.len() => {
                s[..frame.len()].copy_from_slice(&frame);
                (frame.len(), true)
            }
            Some((n, tear)) => {
                if let Tear::Erased = tear {
                    s.fill(0xff);
                }
                s[..n].copy_from_slice(&frame[..n]);
                (frame.len(), false)
            }
            None => {
                s.fill(0xff);
                s[..frame.len()].copy_from_slice(&frame);
                (frame.len(), true)
            }
        }
    }
}

/// What reaches the member, in order.
#[derive(Clone, Debug)]
enum Event {
    Record(alloc::boxed::Box<Record>),
    /// A command from a signer with its counter.
    Command(KeyHash, u64),
    /// A copy with its ID and signed time, and whether it is a secret.
    Copy([u8; 16], Timestamp, bool),
    /// The list a change of root carries.
    List(Vec<u8>),
}

/// The member's state, and what it did (outside the state: the world sees
/// it).
#[derive(Clone)]
struct Member {
    set: RecordSet,
    counters: Counters,
    marks: Marks,
}

/// What a member does once its save is whole.
type Act = alloc::boxed::Box<dyn FnOnce(&mut Done)>;

#[derive(Clone, Default, PartialEq, Eq, Debug)]
struct Done {
    commands: Vec<(KeyHash, u64)>,
    written: Vec<[u8; 16]>,
    reported_roots: BTreeSet<KeyHash>,
}

impl Member {
    fn new(root: &Key) -> Member {
        Member { set: RecordSet::new(root.clone(), recovery()), counters: Counters::default(), marks: Marks::default() }
    }

    fn fields(&self) -> Fields {
        let mut f = Fields::default();
        let mut recs = Vec::new();
        for r in self.set.in_dependency_order() {
            let e = r.envelope();
            recs.extend_from_slice(&(e.len() as u32).to_le_bytes());
            recs.extend_from_slice(&e);
        }
        f.set(TAG_RECORDS, recs);
        let mut lists = Vec::new();
        for l in self.set.lists() {
            lists.extend_from_slice(&(l.len() as u32).to_le_bytes());
            lists.extend_from_slice(l);
        }
        f.set(TAG_LISTS, lists);
        f.set(TAG_COUNTERS, self.counters.encode());
        f.set(TAG_MARKS, self.marks.encode());
        f
    }

    /// The member as it starts from saved fields (None: nothing saved).
    fn from_fields(root: &Key, f: Option<&Fields>) -> Member {
        let mut m = Member::new(root);
        let Some(f) = f else { return m };
        let mut saved = Vec::new();
        let mut recs = f.get(TAG_RECORDS).unwrap();
        while !recs.is_empty() {
            let n = u32::from_le_bytes(recs[..4].try_into().unwrap()) as usize;
            saved.push(Record::decode(&recs[4..4 + n]).expect("a saved record reads back"));
            recs = &recs[4 + n..];
        }
        let (_, refused) = m.set.insert_all(saved);
        assert!(refused.is_empty(), "a saved record is refused: {refused:?}");
        let mut lists = f.get(TAG_LISTS).unwrap();
        while !lists.is_empty() {
            let n = u32::from_le_bytes(lists[..4].try_into().unwrap()) as usize;
            m.set.insert_list(&lists[4..4 + n]).expect("a saved list is taken again");
            lists = &lists[4 + n..];
        }
        m.counters = Counters::decode(f.get(TAG_COUNTERS).unwrap()).expect("the counters read back");
        m.marks = Marks::decode(f.get(TAG_MARKS).unwrap()).expect("the marks read back");
        m
    }

    /// Once saved, the member tells its user the roots after the first.
    fn report_roots(&self) -> Option<Act> {
        let roots: BTreeSet<KeyHash> = self.set.state().roots.into_iter().skip(1).collect();
        (!roots.is_empty())
            .then(|| -> Act { alloc::boxed::Box::new(move |d: &mut Done| d.reported_roots.extend(roots)) })
    }

    /// Handles an event: changes the state, saves it (cut as given), and
    /// only once the save is whole acts on it. Returns whether the save was
    /// whole, and the frame's length.
    fn handle(&mut self, e: &Event, flash: &mut Flash, cut: Option<(usize, Tear)>, done: &mut Done) -> (usize, bool) {
        let mut act: Option<Act> = None;
        match e {
            Event::Record(r) => {
                self.set.insert((**r).clone()).expect("the test's records are taken");
                act = self.report_roots();
            }
            Event::List(l) => {
                self.set.insert_list(l).expect("the test's list is taken");
                act = self.report_roots();
            }
            Event::Command(signer, n) => {
                if self.counters.0.get(signer).is_none_or(|last| n > last) {
                    self.counters.0.insert(*signer, *n);
                    let (s, n) = (*signer, *n);
                    act = Some(alloc::boxed::Box::new(move |d: &mut Done| d.commands.push((s, n))));
                }
            }
            Event::Copy(id, ts, secret) => {
                // The copies come from the laptop.
                let origin = k("laptop").key.device_id();
                let seen = Seen { origin, id: *id, signed: *ts, age_ms: 0, secret: *secret, ttl_ms: None };
                if let Fresh::New { .. } = self.marks.judge(&seen, None, &self.set.state()) {
                    self.marks.wrote(&origin, *ts);
                    let id = *id;
                    act = Some(alloc::boxed::Box::new(move |d: &mut Done| d.written.push(id)));
                }
            }
        }
        let (len, whole) = flash.save(&self.fields(), cut);
        if whole && let Some(a) = act {
            a(done);
        }
        (len, whole)
    }
}

/// The events of a member's life: records of a group with an admin, a
/// laptop and a removal; commands, some sent twice; copies, a secret sent
/// twice and an older copy after a newer one; a change of root by the
/// recovery key, its head first, then the new root's records and the list.
fn life() -> (Key, Vec<Event>) {
    let mut g = G::new();
    g.admin("phone a", "admin a", AdminKind::Phone);
    g.device("laptop", ROLE_MEMBER, RIGHT_READ | RIGHT_SEND, |_| {});
    g.device("old", ROLE_MEMBER, RIGHT_READ | RIGHT_SEND, |_| {});
    g.revoke(&[k("old").hash]);
    let root = g.set.root().clone();
    let mut d = Device::new(k("new phone").key.clone(), "new phone", ROLE_PHONE);
    d.rights = RIGHT_READ | RIGHT_SEND | RIGHT_SECRETS;
    let w = g.set.write_change(&g.state(), &k("recovery"), rk2(), &k("new root"), d, &[], false, 0).unwrap();
    let ts = |w: i64| Timestamp { wall: w, logical: 0 };
    let (r, adm) = (k("root").hash, k("admin a").hash);
    let mut ev: Vec<Event> = g.records().into_iter().map(|r| Event::Record(alloc::boxed::Box::new(r))).collect();
    ev.extend([
        Event::Command(r, 1),
        Event::Command(adm, 1),
        Event::Command(r, 1),
        Event::Command(r, 2),
        Event::Copy([1; 16], ts(1000), false),
        Event::Copy([2; 16], ts(2000), true),
        Event::Copy([2; 16], ts(2000), true),
        Event::Copy([3; 16], ts(1500), false),
        Event::Record(alloc::boxed::Box::new(w.record)),
    ]);
    ev.extend(w.first.into_iter().map(|r| Event::Record(alloc::boxed::Box::new(r))));
    ev.extend([Event::List(w.list.encode().to_vec()), Event::Command(adm, 2), Event::Copy([4; 16], ts(3000), false)]);
    (root, ev)
}

/// Runs events from i on, without cuts.
fn finish(m: &mut Member, flash: &mut Flash, events: &[Event], done: &mut Done) {
    for e in events {
        m.handle(e, flash, None, done);
    }
}

#[test]
fn a_power_cut_at_every_byte_of_every_save() {
    let (root, events) = life();
    // The life without a cut.
    let mut flash = Flash::new();
    let mut m = Member::new(&root);
    let mut want = Done::default();
    finish(&mut m, &mut flash, &events, &mut want);
    let want_fields = m.fields();
    assert_eq!(want.commands.len(), 4, "{:?}", want.commands);
    assert_eq!(want.written, alloc::vec![[1; 16], [2; 16], [4; 16]]);
    assert_eq!(want.reported_roots, BTreeSet::from([k("new root").hash]), "the change of root counts");

    let mut cuts = 0usize;
    // The state before event i, and the flash and what was done then.
    let mut before = Member::new(&root);
    let mut before_flash = Flash::new();
    let mut before_done = Done::default();
    for (i, e) in events.iter().enumerate() {
        let saved_before = before_flash.load();
        let mut after = before.clone();
        let mut after_flash = Flash { slots: before_flash.slots.clone() };
        let mut after_done = before_done.clone();
        let (len, _) = after.handle(e, &mut after_flash, None, &mut after_done);
        let saved_after = after_flash.load();
        // Restarting from either state, sent this event again and the rest,
        // ends as the life without a cut; each is played once and compared
        // by its fields.
        for (which, saved) in [(0, &saved_before), (1, &saved_after)] {
            let mut flash =
                Flash { slots: if which == 0 { before_flash.slots.clone() } else { after_flash.slots.clone() } };
            let mut m = Member::from_fields(&root, saved.as_ref());
            let mut done = if which == 0 { before_done.clone() } else { after_done.clone() };
            // A change of root the member reported before the cut stays.
            let roots = m.set.state().roots;
            for h in &done.reported_roots {
                assert!(roots.contains(h), "event {i}: a reported change of root forgotten");
            }
            // Messages are sent again.
            finish(&mut m, &mut flash, &events[i..], &mut done);
            assert_eq!(m.fields(), want_fields, "event {i}, restart from the state {}", ["before", "after"][which]);
            assert_eq!(done, want, "event {i}: done twice or lost");
        }
        for n in 0..=len {
            for tear in [Tear::Erased, Tear::Stale] {
                let mut flash = Flash { slots: before_flash.slots.clone() };
                let mut m = before.clone();
                let mut done = before_done.clone();
                let (_, whole) = m.handle(e, &mut flash, Some((n, tear)), &mut done);
                assert_eq!(whole, n == len);
                let loaded = flash.load();
                // Whole: the state before or after the save, never a mix.
                let which = if loaded == saved_after && n == len {
                    1
                } else if loaded == saved_before {
                    0
                } else {
                    panic!("event {i}, cut at byte {n} of {len} ({tear:?}): the flash holds neither state");
                };
                assert_eq!(
                    done,
                    if which == 1 { after_done.clone() } else { before_done.clone() },
                    "event {i}, byte {n}"
                );
                cuts += 1;
            }
        }
        before = after;
        before_flash = after_flash;
        before_done = after_done;
    }
    assert!(cuts > 10_000, "{cuts} cuts");
}
