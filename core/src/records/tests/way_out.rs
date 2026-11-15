// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The person's way out of a full root room: whatever removals the honest
//! root's writer lets pass, the person can still take back every live
//! admin key that holds removals back and write the checkpoint that then
//! settles them; a removal that would close that way is refused with its
//! own text, and after the take-backs and the settle the root removes
//! again. Small rooms, so that the room fills in a few dozen rounds.

use super::*;
use crate::records::keep::small::Small;
use crate::records::set::TAKE_BACK_FIRST;

struct Writer {
    set: RecordSet,
    root: K,
    t: u64,
    /// Every record the writer made, in order, for a receiver.
    made: Vec<Record>,
}

impl Writer {
    fn new() -> Writer {
        let root = k("root");
        Writer { set: set_of(&root.key), root, t: 1_000, made: Vec::new() }
    }

    fn keep_new(&mut self) {
        let have: alloc::collections::BTreeSet<RecordId> = self.made.iter().map(Record::id).collect();
        for r in self.set.in_dependency_order() {
            if !have.contains(&r.id()) {
                self.made.push(r.clone());
            }
        }
    }

    fn checkpoint(&mut self) -> Result<(), String> {
        self.t += 1_000;
        let st = self.set.state();
        let cp = self.set.write_checkpoint(&st, &self.root, self.t).map_err(|e| format!("checkpoint: {e}"))?;
        let id = cp.id();
        self.set.insert(cp).map_err(|e| format!("{e:?}"))?;
        assert!(self.set.state().counting.contains(&id), "the writer's checkpoint counts");
        self.keep_new();
        Ok(())
    }

    /// An action, with a checkpoint first when the root's room asks for one.
    fn act(&mut self, f: &dyn Fn(&mut RecordSet, &State, &K, u64) -> crate::error::Result<()>) -> Result<(), String> {
        self.t += 1_000;
        let st = self.set.state();
        let first = f(&mut self.set, &st, &self.root, self.t);
        let out = match first {
            Err(e) if e.to_string().contains("checkpoint first") => {
                self.checkpoint()?;
                self.t += 1_000;
                let st = self.set.state();
                f(&mut self.set, &st, &self.root, self.t).map_err(|e| e.to_string())
            }
            other => other.map_err(|e| e.to_string()),
        };
        self.keep_new();
        out
    }

    fn admit(&mut self, name: &str) -> Result<(), String> {
        let key = k(name).key.clone();
        self.act(&|set, st, root, t| {
            set.write_record(st, root, Kind::device(Device::new(key.clone(), "device", ROLE_MEMBER)), t).map(|_| ())
        })
    }

    fn remove(&mut self, name: &str) -> Result<(), String> {
        let h = k(name).hash;
        self.act(&|set, st, root, t| set.write_removal(st, root, &[h], t).map(|_| ()))
    }

    fn take_back(&mut self, admin: &K) -> Result<(), String> {
        let a = admin.hash;
        self.act(&|set, st, root, t| set.take_back(st, root, &a, t).map(|_| ()))
    }

    fn ack(&mut self, admin: &K) {
        self.t += 1_000;
        let st = self.set.state();
        // An admin's room full of its acknowledgements: the root's
        // checkpoint lets the older ones go.
        if self.set.write_ack(&st, admin, self.t).is_err() && self.checkpoint().is_ok() {
            self.t += 1_000;
            let st = self.set.state();
            let _ = self.set.write_ack(&st, admin, self.t);
        }
        self.keep_new();
    }
}

/// Fills the root's room with removals that `laggards` never acknowledge
/// (one other admin acks each round), until the writer refuses a removal
/// with its own text. It returns the writer and the devices still in.
fn at_the_way_out(laggards: usize) -> (Writer, Vec<K>, Vec<String>) {
    let mut w = Writer::new();
    let admins: Vec<K> = (0..=laggards).map(|i| k(&format!("way admin {i}"))).collect();
    for (i, a) in admins.iter().enumerate() {
        let phone = k(&format!("way phone {i}"));
        let key = a.key.clone();
        w.act(&|set, st, root, t| {
            let mut d = Device::new(phone.key.clone(), "phone", ROLE_PHONE);
            d.admin = Some(key.clone());
            d.powers = POWER_ADMIT | POWER_REMOVE;
            set.write_record(st, root, Kind::device(d), t).map(|_| ())
        })
        .unwrap();
    }
    for a in &admins {
        w.ack(a);
    }
    let mut live: alloc::collections::VecDeque<String> = (0..6).map(|i| alloc::format!("way dev {i}")).collect();
    for name in live.clone() {
        w.admit(&name).unwrap();
    }
    let acker = admins.last().unwrap().clone();
    for (round, next) in (0..400).zip(6..) {
        let gone = live.pop_front().unwrap();
        match w.remove(&gone) {
            Ok(()) => {}
            Err(e) => {
                assert!(e.contains(TAKE_BACK_FIRST), "round {round}: the refusal names the way out: {e}");
                live.push_front(gone);
                w.ack(&acker);
                return (w, admins, live.into_iter().collect());
            }
        }
        let name = alloc::format!("way dev {next}");
        if w.admit(&name).is_ok() {
            live.push_back(name);
        }
        w.ack(&acker);
    }
    panic!("the room never filled");
}

fn the_person_takes_the_laggards_back_and_the_root_removes_again(laggards: usize) {
    let _small = Small::new(4_096, 48, 16);
    let (mut w, admins, live) = at_the_way_out(laggards);
    let st = w.set.state();
    let holders: Vec<KeyHash> = w.set.unacknowledged(&st).into_iter().filter(|(_, n)| *n > 0).map(|(a, _)| a).collect();
    assert_eq!(holders.len(), laggards, "the laggards hold removals back");
    for a in admins.iter().take(laggards) {
        w.take_back(a).unwrap_or_else(|e| panic!("the person takes {} back: {e}", laggards));
    }
    w.checkpoint().expect("the checkpoint that settles");
    let st = w.set.state();
    assert!(w.set.unacknowledged(&st).values().all(|n| *n == 0), "nothing waits");
    w.remove(&live[0]).expect("the root removes again");
    assert!(w.set.state().device_by_key(&k(&live[0]).hash).is_none());
    // A receiver that takes each record as it was made keeps every root
    // record that counts at the writer.
    let mut m = set_of(&w.root.key);
    for r in &w.made {
        let _ = m.insert(r.clone());
    }
    let (ws, ms) = (w.set.state(), m.state());
    assert_eq!(ms.revoked, ws.revoked);
    assert_eq!(
        ms.devices.iter().map(|d| d.key.hash()).collect::<Vec<_>>(),
        ws.devices.iter().map(|d| d.key.hash()).collect::<Vec<_>>()
    );
}

#[test]
fn a_root_whose_room_fills_can_still_take_one_laggard_back() {
    the_person_takes_the_laggards_back_and_the_root_removes_again(1);
}

#[test]
fn a_root_whose_room_fills_can_still_take_two_laggards_back() {
    the_person_takes_the_laggards_back_and_the_root_removes_again(2);
}
