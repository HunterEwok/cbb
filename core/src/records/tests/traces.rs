// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The records model's traces (plans: model replays), run as they are:
//! small rooms (14 units, a root's ceiling 8, an admin's 5), each record
//! the units the model gave it, each member offered what the model offered
//! it, in that order. Whatever order its records came in, a member is in
//! the state a member that took the same records at once is in: the same
//! records kept, the same state, and compacting changes neither.

use super::*;
use crate::records::keep::small::Small;
use alloc::collections::BTreeSet;
use alloc::string::String;

/// The members of the model.
const MEMBERS: [&str; 5] = ["r", "a", "c", "k", "m"];

/// The key of a signer or target the model names.
fn key(name: &str) -> K {
    match name {
        "R" => k("root"),
        "K" => k("recovery"),
        "dA" => k("phone A"),
        other => k(&format!("key {other}")),
    }
}

/// The device of an admin the model names.
fn device_of(admin: &str) -> K {
    match admin {
        "A" => k("phone A"),
        other => k(&format!("device {other}")),
    }
}

/// The numbers in "[1, 2, 3]".
fn ids(s: &str) -> Vec<u32> {
    s.trim_matches(|c| c == '[' || c == ']').split(',').filter_map(|x| x.trim().parse().ok()).collect()
}

/// The text between `open` and its closing `close` at the start of s,
/// and what follows.
fn bracket(s: &str, close: char) -> (&str, &str) {
    let end = s.find(close).unwrap();
    (&s[..=end], &s[end + 1..])
}

/// A run of one trace.
struct Run {
    g: G,
    small: Small,
    by_n: BTreeMap<u32, Record>,
    sets: BTreeMap<&'static str, RecordSet>,
    got: BTreeMap<&'static str, Vec<u32>>,
}

impl Run {
    fn new() -> Run {
        let g = G::new();
        let sets = MEMBERS.iter().map(|m| (*m, set_of(&g.root.key))).collect();
        let got = MEMBERS.iter().map(|m| (*m, Vec::new())).collect();
        Run { g, small: Small::new(14, 8, 5), by_n: BTreeMap::new(), sets, got }
    }

    fn id(&self, n: u32) -> RecordId {
        self.by_n.get(&n).map_or(RecordId([n as u8; 32]), Record::id)
    }

    /// Makes the records of one step: "#5 K seq 1 prev - recover ...; #6 ...".
    /// A recovery head's first checkpoint is signed before the head, which
    /// names it.
    fn make(&mut self, specs: &str) -> Vec<u32> {
        let mut specs: Vec<&str> = specs.split(';').map(str::trim).collect();
        // Sign what a head names before the head.
        specs.sort_by_key(|s| s.contains(" recover "));
        let mut made = Vec::new();
        for spec in specs {
            let words: Vec<&str> = spec.split_whitespace().collect();
            let n: u32 = words[0].trim_start_matches('#').parse().unwrap();
            let by = key(words[1]);
            let seq: u64 = words[3].parse().unwrap();
            let rest = spec.splitn(7, ' ').nth(6).unwrap();
            let (kind_text, units) = rest.rsplit_once(" units ").unwrap();
            let units: u64 = units.parse().unwrap();
            let mut kw = kind_text.split_whitespace();
            let kind = match kw.next().unwrap() {
                "admin" => {
                    let t = kind_text.split_whitespace().nth(2).unwrap();
                    let all =
                        POWER_ADMIT | POWER_MANAGE | POWER_REMOVE | POWER_REMOVE_ADMINS | POWER_FREEZE | POWER_THAW;
                    let mut d = Device::new(device_of(t).key.clone(), "admin", ROLE_MEMBER);
                    d.rights = RIGHT_READ | RIGHT_SEND;
                    d.admin = Some(key(t).key.clone());
                    d.powers = all;
                    Kind::device(d)
                }
                "copies" => Kind::Copies { incoming_ms: MIN_INCOMING_MS + u64::from(n), seen: vec![] },
                "revoke" => Kind::Revoke(removal(&[key(kind_text.split_whitespace().nth(2).unwrap()).hash], vec![])),
                "freeze" => Kind::Freeze(removal(&[key(kind_text.split_whitespace().nth(2).unwrap()).hash], vec![])),
                "thaw" => {
                    let t: u32 = kind_text.split_whitespace().nth(2).unwrap().parse().unwrap();
                    Kind::Thaw { ids: vec![self.id(t)], seen: vec![] }
                }
                "checkpoint" => {
                    let (heads_text, after) = bracket(kind_text.trim_start_matches("checkpoint heads "), '}');
                    let mut heads: Vec<Head> = heads_text
                        .trim_matches(|c| c == '{' || c == '}')
                        .split(',')
                        .filter(|x| !x.trim().is_empty())
                        .map(|x| {
                            let (who, last) = x.split_once(':').unwrap();
                            let r = &self.by_n[&last.trim().parse::<u32>().unwrap()];
                            Head { key: key(who.trim().trim_matches('\'')).hash, seq: r.body().seq, id: r.id() }
                        })
                        .collect();
                    let named = ids(after.trim().trim_start_matches("keep "));
                    // The core wants a head: a checkpoint the model writes
                    // with none names the newest record it keeps as one.
                    if heads.is_empty()
                        && let Some(r) = named.iter().max().and_then(|n| self.by_n.get(n))
                    {
                        heads.push(Head { key: r.body().signer, seq: r.body().seq, id: r.id() });
                    }
                    heads.sort_by_key(|h| h.key);
                    let mut keep: Vec<RecordId> = named.into_iter().map(|i| self.id(i)).collect();
                    keep.sort();
                    Kind::Checkpoint { heads, keep }
                }
                "recover" => {
                    let w: Vec<&str> = kind_text.split_whitespace().collect();
                    let root = key(w[2]);
                    let (list_text, after) = bracket(kind_text.split_once(" list ").unwrap().1, ']');
                    let mut list: Vec<RecordId> = ids(list_text).into_iter().map(|i| self.id(i)).collect();
                    list.sort();
                    list.dedup();
                    let list = List(list);
                    self.g.lists.push(list.encode());
                    let a: Vec<&str> = after.split_whitespace().collect();
                    let from: u64 = a[1].parse().unwrap();
                    let first = self.id(a[3].parse().unwrap());
                    Kind::Recovery { root: root.key.clone(), list: list.hash(), from, first }
                }
                other => panic!("kind {other}"),
            };
            let body = self.g.body(&by, kind);
            assert_eq!(body.seq, seq, "#{n}");
            let r = Record::sign(body, &by).unwrap_or_else(|e| panic!("#{n}: {e}"));
            self.small.units(r.id(), units);
            self.g.push(r.clone());
            self.by_n.insert(n, r);
            made.push(n);
        }
        made.sort();
        made
    }

    /// Offers member m record n, with every list (a member takes a head's
    /// list with it).
    fn offer(&mut self, m: &str, n: u32) {
        let (name, set) = self.sets.iter_mut().find(|(k, _)| **k == m).unwrap();
        let _ = set.insert(self.by_n[&n].clone());
        for l in &self.g.lists {
            let _ = set.insert_list(l);
        }
        self.got.get_mut(name).unwrap().push(n);
    }

    fn compact(&mut self, m: &str) {
        let set = self.sets.get_mut(m).unwrap();
        let st = set.state();
        set.compact(&st);
    }

    /// Runs the steps of a trace.
    fn steps(&mut self, trace: &str) {
        for line in trace.lines().filter(|l| !l.trim().is_empty()) {
            self.step(line);
        }
    }

    fn step(&mut self, line: &str) {
        {
            let (_, step) = line.split_once(". ").unwrap();
            let (action, got) = match step.split_once("  | got: ") {
                Some((a, g)) => (a, Some(g)),
                None => (step, None),
            };
            let made = match action.split_once(": #") {
                Some((_, specs)) => self.make(&format!("#{specs}")),
                None => vec![],
            };
            if action.starts_with("init") {
                for m in MEMBERS {
                    for &n in &made {
                        self.offer(m, n);
                    }
                }
            }
            if let Some(m) = action.strip_prefix("compact (m=") {
                self.compact(m.trim_end_matches(')'));
            }
            if let Some(got) = got {
                let mut rest = got;

                while let Some((m, after)) = rest.split_once("+[") {
                    let (list, after) = after.split_once(']').unwrap();
                    let m = m.trim().trim_start_matches(',').trim();
                    for n in ids(list) {
                        self.offer(m, n);
                    }
                    rest = after;
                }
            }
        }
    }

    /// Each member syncs with peers that hold what it was offered: it asks
    /// for what it misses and is sent again every record it was offered,
    /// in rounds until one changes nothing.
    fn settle(&mut self) {
        for m in MEMBERS {
            let got: BTreeSet<u32> = self.got[m].iter().copied().collect();
            for _ in 0..8 {
                let set = self.sets.get_mut(m).unwrap();
                let before = set.digest();
                let st = set.state();
                let asked = set.missing(&st);
                let back: Vec<Record> = got
                    .iter()
                    .map(|n| self.by_n[n].clone())
                    .filter(|r| asked.contains(&r.id()) || !set.contains(&r.id()))
                    .collect();
                set.insert_all(back);
                if set.digest() == before {
                    break;
                }
            }
        }
    }

    /// The model numbers of what member m holds.
    fn held(&self, m: &str) -> Vec<u32> {
        let set = &self.sets[m];
        self.by_n.iter().filter(|(_, r)| set.contains(&r.id())).map(|(n, _)| *n).collect()
    }

    /// Checks every member: compacting changes nothing, and a member that
    /// takes the same records at once, in rounds until nothing changes, keeps
    /// the same records and is in the same state; members offered the same
    /// records agree.
    fn check(&self, name: &str) -> BTreeMap<&'static str, Vec<u32>> {
        let mut by_got: BTreeMap<BTreeSet<u32>, (&str, [u8; 32], State)> = BTreeMap::new();
        let mut out = BTreeMap::new();
        for m in MEMBERS {
            let set = &self.sets[m];
            let mut again = set.clone();
            let st = again.state();
            again.compact(&st);
            assert_eq!(again.digest(), set.digest(), "{name} {m}: compacting dropped records");
            assert_eq!(again.state(), st, "{name} {m}: compacting changed the state");
            let got: BTreeSet<u32> = self.got[m].iter().copied().collect();
            let mut once = set_of(&self.g.root.key);
            for _ in 0..8 {
                let before = once.digest();
                once.insert_all(got.iter().map(|n| self.by_n[n].clone()));
                for l in &self.g.lists {
                    let _ = once.insert_list(l);
                }
                if once.digest() == before {
                    break;
                }
            }
            assert_eq!(
                self.held(m),
                {
                    let held: Vec<u32> =
                        self.by_n.iter().filter(|(_, r)| once.contains(&r.id())).map(|(n, _)| *n).collect();
                    held
                },
                "{name} {m}: the records kept"
            );
            assert_eq!(set.state(), once.state(), "{name} {m}: the state");
            let digest = set.digest();
            if let Some((other, d, s)) = by_got.get(&got) {
                assert_eq!((&digest, &st), (d, s), "{name}: {m} and {other} took the same records");
            } else {
                by_got.insert(got, (m, digest, st));
            }
            out.insert(m, self.held(m));
        }
        out
    }
}

/// The model's final records of each member.
fn model_end(end: &str) -> BTreeMap<String, Vec<u32>> {
    end.lines()
        .filter_map(|l| l.strip_prefix("- "))
        .map(|l| {
            let (m, rest) = l.split_once(": recs ").unwrap();
            let (list, _) = bracket(rest, ']');
            (String::from(m), ids(list))
        })
        .collect()
}

/// Runs a trace and checks it; gives what each member holds next to what
/// the model's member holds.
fn run(name: &str, trace: &str, end: &str) -> Vec<(String, Vec<u32>, Vec<u32>)> {
    let mut r = Run::new();
    r.steps(trace);
    r.settle();
    let held = r.check(name);
    let model = model_end(end);
    held.into_iter().map(|(m, h)| (String::from(m), h, model[m].clone())).collect()
}

/// Replay 801: its steps.
const T_801: &str = r#"
0. init: #1 R seq 1 prev - admin target A units 1; #2 R seq 2 prev 1 admin target C units 1; #3 R seq 3 prev 2 admin target W units 1
1. broadcastNewest
2. compact (m=a)
3. signCheckpointNaming: #4 R seq 4 prev 3 checkpoint heads {'R': 3} keep [1, 2, 3] units 2  | got: r+[4]
4. signChange: #5 K seq 1 prev - recover target NK targetRec 1 list [1, 2, 3] from 1 first 6 units 0; #6 NK seq 1 prev - checkpoint heads {} keep [1, 2, 3] units 2  | got: k+[5, 6]
5. signRecover: #7 K seq 2 prev 5 recover target R targetRec 5 list [1, 2, 3] from 5 first 99 units 0  | got: k+[7]
6. broadcastNewest  | got: a+[7], c+[7], m+[7], r+[7]
7. signCopies: #8 C seq 1 prev - copies units 1  | got: c+[8]
8. broadcastNewest  | got: a+[8], k+[8], m+[8], r+[8]
9. broadcastNewest
10. sign: #9 R seq 5 prev 4 revoke target K units 1  | got: r+[9]
11. broadcastNewest  | got: a+[9], c+[9], k+[9], m+[9]
12. rootRemovesPhone: #10 R seq 6 prev 9 revoke target A units 1  | got: r+[10]
13. sign: #11 A seq 1 prev - freeze target W units 1  | got: a+[11]
14. signNewRoot: #12 NK seq 2 prev 6 copies units 2  | got: k+[12]
15. signThaw: #13 A seq 2 prev 11 thaw targetRec 11 units 1  | got: a+[13]
16. signNewRoot: #14 NK seq 3 prev 12 copies units 1  | got: k+[14]
17. sign: #15 A seq 3 prev 13 copies units 2  | got: a+[15]
18. broadcast (i=13)  | got: c+[13], k+[13], m+[13], r+[13]
19. signCopies: #16 C seq 2 prev 8 copies units 1  | got: c+[16]
20. sign: #17 A seq 4 prev 15 copies units 2  | got: a+[17]
21. signNewRoot: #18 NK seq 4 prev 14 copies units 1  | got: k+[18]
22. broadcastNewest  | got: a+[18], c+[18], m+[18], r+[18]
23. signCheckpointNaming: #19 NK seq 5 prev 18 checkpoint heads {'A': 13, 'C': 8, 'NK': 18, 'R': 3} keep [1, 2, 3, 8, 12, 14, 18] units 2  | got: k+[19]
24. signNewRoot: #20 NK seq 6 prev 19 copies units 1  | got: k+[20]
25. compact (m=m)
26. deliver (m=a, i=6)  | got: a+[6]
27. broadcastNewest  | got: a+[20], c+[20], m+[20], r+[20]
28. broadcastNewest
29. compact (m=c)
30. syncAll  | got: a+[4, 5, 10, 12, 14, 16, 19], c+[4, 5, 6, 10, 11, 12, 14, 15, 19], k+[4, 10, 11, 15, 16], m+[4, 5, 6, 10, 11, 12, 14, 15, 16, 19], r+[5, 6, 11, 12, 14, 15, 16, 19]
"#;

/// Replay 801: each member's final records in the model.
const T_801_END: &str = r#"
- a: recs [1, 2, 3, 8, 11, 12, 13, 14, 15, 16, 19], checkpoint 0, view checkpoint 0, counting [1, 2, 3, 6, 8, 12, 13, 14, 15, 16], got [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]
- c: recs [1, 2, 3, 8, 11, 12, 13, 14, 15, 16, 19], checkpoint 0, view checkpoint 0, counting [1, 2, 3, 6, 8, 12, 13, 14, 15, 16], got [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 19, 20]
- k: recs [1, 2, 3, 8, 12, 13, 14, 15, 16, 18, 19], checkpoint 19, view checkpoint 19, counting [1, 2, 3, 8, 12, 13, 14, 15, 16, 18, 19], got [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 19, 20]
- m: recs [1, 2, 3, 8, 11, 12, 13, 14, 15, 16, 19], checkpoint 0, view checkpoint 0, counting [1, 2, 3, 6, 8, 12, 13, 14, 15, 16], got [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 19, 20]
- r: recs [1, 2, 3, 8, 11, 12, 13, 14, 15, 16, 19], checkpoint 0, view checkpoint 0, counting [1, 2, 3, 6, 8, 12, 13, 14, 15, 16], got [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 19, 20]
"#;

/// Replay 0x302d: its steps.
const T_X302D: &str = r#"
0. init: #1 R seq 1 prev - admin target A units 1; #2 R seq 2 prev 1 admin target C units 1; #3 R seq 3 prev 2 admin target W units 1
1. signCheckpointNaming: #4 R seq 4 prev 3 checkpoint heads {'R': 3} keep [1, 2, 3] units 2  | got: r+[4]
2. broadcast (i=2)
3. broadcastNewest  | got: a+[4], c+[4], k+[4], m+[4]
4. broadcastNewest
5. broadcastNewest
6. broadcastNewest
7. signRecover: #5 K seq 1 prev - recover target R targetRec 1 list [1, 2, 3] from 1 first 6 units 0; #6 R seq 5 prev 4 checkpoint heads {'R': 3} keep [1, 2, 3] units 2  | got: k+[5, 6]
8. broadcastNewest  | got: a+[6], c+[6], m+[6], r+[6]
9. broadcastNewest
10. broadcastNewest
11. signHidden: #7 NA seq 1 prev - admin target A units 1
12. signCopies: #8 R seq 6 prev 6 copies units 2  | got: r+[8]
13. broadcastNewest  | got: a+[8], c+[8], k+[8], m+[8]
14. signCheckpoint: #9 NA seq 2 prev 7 checkpoint heads {'NA': 7, 'R': 6} keep [1, 2, 3] units 2  | got: a+[9]
15. rootRemovesPhone: #10 R seq 7 prev 8 revoke target A units 1  | got: r+[10]
16. welcomeNewcomer (x=c)
17. rootRemovesPhone: #11 R seq 8 prev 10 revoke target A units 1  | got: r+[11]
18. welcomeNewcomer (x=k)  | got: m+[5]
19. syncAll  | got: a+[5, 10, 11], c+[5, 10, 11], k+[10, 11], m+[10, 11], r+[5]
20. welcomeNewcomer (x=r)
21. broadcastNewest
22. sign: #12 A seq 1 prev - thaw targetRec 8 units 1  | got: a+[12]
23. rootRemovesPhone: #13 R seq 9 prev 11 revoke target A units 1  | got: r+[13]
24. syncAll  | got: a+[13], c+[12, 13], k+[12, 13], m+[12, 13], r+[12]
25. broadcastNewest
26. signCheckpointNaming: #14 R seq 10 prev 13 checkpoint heads {'A': 12, 'R': 13} keep [1, 3, 10, 11, 13] units 2  | got: r+[14]
"#;

/// Replay 0x302d: each member's final records in the model.
const T_X302D_END: &str = r#"
- a: recs [1, 4, 6, 10, 11, 12, 13], checkpoint 0, view checkpoint 0, counting [1, 10, 11, 13], got [1, 2, 3, 4, 5, 6, 8, 9, 10, 11, 12, 13]
- c: recs [1, 4, 6, 10, 11, 12, 13], checkpoint 0, view checkpoint 0, counting [1, 10, 11, 13], got [1, 2, 3, 4, 5, 6, 8, 10, 11, 12, 13]
- k: recs [1, 4, 6, 10, 11, 12, 13], checkpoint 0, view checkpoint 0, counting [1, 10, 11, 13], got [1, 2, 3, 4, 5, 6, 8, 10, 11, 12, 13]
- m: recs [1, 4, 6, 10, 11, 12, 13], checkpoint 0, view checkpoint 0, counting [1, 10, 11, 13], got [1, 2, 4, 5, 6, 10, 11, 12, 13]
- r: recs [6, 10, 11, 12, 13, 14], checkpoint 0, view checkpoint 0, counting [10, 11, 13], got [1, 2, 3, 4, 5, 6, 8, 10, 11, 12, 13, 14]
"#;

/// Replay 0x9107: its steps.
const T_X9107: &str = r#"
0. init: #1 R seq 1 prev - admin target A units 1; #2 R seq 2 prev 1 admin target C units 1; #3 R seq 3 prev 2 admin target W units 1
1. broadcast (i=1)
2. signRevoke: #4 A seq 1 prev - revoke target X units 1  | got: a+[4]
3. signCopies: #5 C seq 1 prev - copies units 1  | got: c+[5]
4. broadcastNewest  | got: a+[5], k+[5], m+[5], r+[5]
5. compact (m=r)
6. compact (m=r)
7. signRecover: #6 K seq 1 prev - recover target R targetRec 4 list [] from 4 first 7 units 0; #7 R seq 4 prev 3 checkpoint heads {} keep [1, 2, 3, 5] units 2  | got: k+[6, 7]
8. signCheckpointNaming: #8 R seq 5 prev 7 checkpoint heads {'C': 5, 'R': 7} keep [1, 2, 3, 5] units 2  | got: r+[8]
9. welcomeNewcomer (x=k)  | got: m+[6, 7]
10. welcomeNewcomer (x=k)
11. broadcastNewest  | got: a+[8], c+[8], k+[8], m+[8]
12. compact (m=k)
13. signCopies: #9 C seq 2 prev 5 copies units 1  | got: c+[9]
14. welcomeNewcomer (x=c)  | got: m+[9]
15. signCopies: #10 NA seq 1 prev - copies units 1  | got: a+[10]
16. signCopies: #11 W seq 1 prev - copies units 1  | got: c+[11]
17. rootRemovesPhone: #12 R seq 6 prev 8 revoke target A units 1  | got: r+[12]
18. deliver (m=k, i=11)  | got: k+[11]
19. sign: #13 A seq 2 prev 4 revoke target C units 1  | got: a+[13]
20. broadcastNewest  | got: c+[13], k+[13], m+[13], r+[13]
21. broadcastNewest
22. signHidden: #14 NK seq 1 prev - revoke target C units 1
23. compact (m=m)
24. signCheckpointNaming: #15 NK seq 2 prev 14 checkpoint heads {'A': 13, 'C': 5, 'NK': 14, 'R': 8, 'W': 11} keep [1, 2, 3, 5, 11, 14] units 2  | got: k+[15]
25. signCheckpoint: #16 R seq 7 prev 12 checkpoint heads {'A': 13, 'C': 5, 'R': 12} keep [1, 2, 3, 5, 12] units 2  | got: r+[16]
26. broadcastNewest  | got: a+[16], c+[16], k+[16], m+[16]
27. broadcastNewest
28. sign: #17 A seq 3 prev 13 revoke target C units 1  | got: a+[17]
29. deliver (m=k, i=15)
30. welcomeNewcomer (x=a)  | got: m+[4, 17]
31. deliver (m=r, i=9)  | got: r+[9]
32. welcomeNewcomer (x=a)
33. broadcastNewest  | got: c+[17], k+[17], r+[17]
34. broadcastNewest
35. compact (m=a)
36. sign: #18 A seq 4 prev 17 revoke target dA units 1  | got: a+[18]
37. sign: #19 A seq 5 prev 18 copies units 2  | got: a+[19]
38. syncAll  | got: a+[6, 7, 9, 11, 12], c+[4, 6, 7, 12, 18], k+[4, 9, 12, 18], m+[6, 7, 9, 11, 12, 18], r+[4, 6, 7, 11, 18]
"#;

/// Replay 0x9107: each member's final records in the model.
const T_X9107_END: &str = r#"
- a: recs [4, 5, 8, 9, 11, 12, 13, 16, 17, 18], checkpoint 0, view checkpoint 0, counting [12], got [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 16, 17, 18, 19]
- c: recs [4, 5, 7, 8, 9, 11, 12, 13, 16, 17, 18], checkpoint 0, view checkpoint 0, counting [12], got [1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13, 16, 17, 18]
- k: recs [4, 5, 7, 8, 9, 11, 12, 13, 16, 17, 18], checkpoint 0, view checkpoint 0, counting [12], got [1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13, 15, 16, 17, 18]
- m: recs [4, 5, 7, 8, 9, 11, 12, 13, 16, 17, 18], checkpoint 0, view checkpoint 0, counting [12], got [1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13, 16, 17, 18]
- r: recs [1, 2, 3, 5, 9, 11, 12, 13, 16, 17, 18], checkpoint 16, view checkpoint 16, counting [1, 2, 3, 5, 9, 11, 12, 16], got [1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13, 16, 17, 18]
"#;

/// Replay 0x3262c: its steps.
const T_X3262C: &str = r#"
0. init: #1 R seq 1 prev - admin target A units 1; #2 R seq 2 prev 1 admin target C units 1; #3 R seq 3 prev 2 admin target W units 1
1. broadcast (i=2)
2. broadcastNewest
3. broadcastNewest
4. signHidden: #4 NA seq 1 prev - revoke target C units 1
5. compact (m=r)
6. broadcastNewest  | got: a+[4], c+[4], k+[4], m+[4], r+[4]
7. syncAll
8. rootRemovesPhone: #5 R seq 4 prev 3 revoke target A units 1  | got: r+[5]
9. broadcast (i=3)
10. broadcastNewest  | got: a+[5], c+[5], k+[5], m+[5]
11. signCheckpoint: #6 NA seq 2 prev 4 checkpoint heads {'NA': 4, 'R': 5} keep [1, 2, 3, 5] units 2  | got: a+[6]
12. compact (m=m)
13. rootRemovesPhone: #7 R seq 5 prev 5 revoke target A units 1  | got: r+[7]
14. signCheckpoint: #8 NK seq 1 prev - checkpoint heads {'R': 5} keep [1, 2, 3, 5] units 2  | got: k+[8]
15. sign: #9 A seq 1 prev - thaw targetRec 7 units 1  | got: a+[9]
16. signCheckpointNaming: #10 R seq 6 prev 7 checkpoint heads {'R': 7} keep [1, 2, 3, 5, 7] units 2  | got: r+[10]
17. signCheckpointNaming: #11 NA seq 3 prev 6 checkpoint heads {'A': 9, 'NA': 6, 'R': 5} keep [1, 2, 3, 4, 5] units 2  | got: a+[11]
18. signRevoke: #12 NK seq 2 prev 8 revoke target W units 1  | got: k+[12]
19. broadcastNewest  | got: a+[12], c+[12], m+[12], r+[12]
20. sign: #13 A seq 2 prev 9 thaw targetRec 7 units 1  | got: a+[13]
21. broadcast (i=6)  | got: c+[6], k+[6], m+[6], r+[6]
22. broadcastNewest  | got: c+[13], k+[13], m+[13], r+[13]
23. broadcastNewest
24. syncAll  | got: a+[7, 10], c+[7, 9, 10], k+[7, 9, 10], m+[7, 9, 10], r+[9]
25. signCheckpointNaming: #14 NA seq 4 prev 11 checkpoint heads {'A': 13, 'NA': 11, 'R': 10} keep [1, 2, 3, 4, 5, 7] units 2  | got: a+[14]
26. broadcastNewest  | got: c+[14], k+[14], m+[14], r+[14]
27. sign: #15 A seq 3 prev 13 copies units 2  | got: a+[15]
28. signCheckpointNaming: #16 NK seq 3 prev 12 checkpoint heads {'A': 13, 'NK': 12, 'R': 10} keep [1, 2, 3, 5, 7, 12] units 2  | got: k+[16]
29. broadcastNewest  | got: a+[16], c+[16], m+[16], r+[16]
30. rootRemovesPhone: #17 R seq 7 prev 10 revoke target A units 1  | got: r+[17]
31. signCheckpoint: #18 R seq 8 prev 17 checkpoint heads {'A': 13, 'R': 17} keep [1, 2, 3, 5, 7, 17] units 2  | got: r+[18]
32. compact (m=k)
33. compact (m=m)
34. broadcastNewest  | got: a+[18], c+[18], k+[18], m+[18]
35. broadcastNewest
36. syncAll  | got: a+[17], c+[15, 17], k+[15, 17], m+[15, 17], r+[15]
"#;

/// Replay 0x3262c: each member's final records in the model.
const T_X3262C_END: &str = r#"
- a: recs [1, 5, 7, 9, 10, 13, 15, 17, 18], checkpoint 0, view checkpoint 0, counting [1, 5, 7, 17], got [1, 2, 3, 4, 5, 6, 7, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18]
- c: recs [1, 5, 7, 9, 10, 13, 15, 17, 18], checkpoint 0, view checkpoint 0, counting [1, 5, 7, 17], got [1, 2, 3, 4, 5, 6, 7, 9, 10, 12, 13, 14, 15, 16, 17, 18]
- k: recs [1, 5, 7, 9, 10, 13, 15, 17, 18], checkpoint 0, view checkpoint 0, counting [1, 5, 7, 17], got [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 13, 14, 15, 16, 17, 18]
- m: recs [1, 5, 7, 9, 10, 13, 15, 17, 18], checkpoint 0, view checkpoint 0, counting [1, 5, 7, 17], got [1, 2, 3, 4, 5, 6, 7, 9, 10, 12, 13, 14, 15, 16, 17, 18]
- r: recs [1, 2, 3, 5, 7, 13, 15, 17, 18], checkpoint 18, view checkpoint 18, counting [1, 2, 3, 5, 7, 17, 18], got [1, 2, 3, 4, 5, 6, 7, 9, 10, 12, 13, 14, 15, 16, 17, 18]
"#;

/// Each trace: every member ends as a member that took the same records at
/// once, and compacting changes nothing.
#[test]
fn the_models_traces_end_alike_in_any_order() {
    for (name, trace, end) in [
        ("801", T_801, T_801_END),
        ("0x302d", T_X302D, T_X302D_END),
        ("0x9107", T_X9107, T_X9107_END),
        ("0x3262c", T_X3262C, T_X3262C_END),
    ] {
        for (m, held, model) in run(name, trace, end) {
            std::eprintln!("{name} {m}: holds {held:?}, the model's {model:?}");
        }
    }
}
