// Long fuzzing of the 0.6 readers (not for the repository as is): valid
// groups from groupgen (vendored from PR #531's core/src/groupgen.rs), taken
// by members in fuzzed orders, with fuzzed gaps, compactions and list orders (rule 33).
#![no_main]
#![allow(dead_code, clippy::all)]
use std::sync::OnceLock;

#[path = "groupgen_vendored.rs"]
mod groupgen;

use cbb_core::records::{evaluate, Input, Kind, Record, RecordSet, State};

fn groups() -> &'static Vec<groupgen::Group> {
    static G: OnceLock<Vec<groupgen::Group>> = OnceLock::new();
    G.get_or_init(|| {
        let mut v = Vec::new();
        for s in [1u64, 2] {
            for spec in groupgen::sizes(s) {
                v.push(groupgen::build(spec));
            }
        }
        v.push(groupgen::build(groupgen::ceilings(1)));
        v
    })
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

fn shuffle(recs: &mut [Record], rng: &mut Rng) {
    for i in (1..recs.len()).rev() {
        let j = (rng.next() % (i as u64 + 1)) as usize;
        recs.swap(i, j);
    }
}

/// A member that takes the records and lists over some syncs: in each, the
/// items in its order, one by one, a compaction every `every` items and at
/// the sync's end, until nothing changes.
fn member(g: &groupgen::Group, items: &[Item], every: usize) -> RecordSet {
    let mut m = RecordSet::new(g.root.clone(), g.recovery.clone());
    let mut last = None;
    for _ in 0..(g.spec.takeovers + 3).max(12) {
        let now = (m.digest(), m.lists().count());
        if last.as_ref() == Some(&now) {
            break;
        }
        last = Some(now);
        for (i, it) in items.iter().enumerate() {
            match it {
                Item::Rec(r) => {
                    let _ = m.insert(r.clone());
                }
                Item::List(b) => {
                    let _ = m.insert_list(b);
                }
            }
            if every > 0 && (i + 1) % every == 0 {
                let st = m.state();
                drop(st);
            }
        }
        for _ in 0..2 {
            let st = m.state();
            drop(st);
        }
    }
    m
}

#[derive(Clone)]
enum Item {
    Rec(Record),
    List(Vec<u8>),
}


/// Optional relaxations for debugging older heads, both off by default:
/// FZ_EARLY_LAX ignores a first_missing that only the set's aside explains;
/// FZ_IGNORED_LAX ignores records only a waiting head names in `ignored`.
fn mask_waiting(m: &RecordSet, got: &State, mut want: State) -> State {
    if std::env::var_os("FZ_IGNORED_LAX").is_none() {
        return want;
    }
    want.ignored.retain(|i| {
        got.ignored.contains(i)
            || m.get(&i.record).is_none_or(|r| {
                let s = r.body().signer;
                got.roots.contains(&s)
                    || !m.ids().filter_map(|id| m.get(id)).any(|h| matches!(&h.body().kind, cbb_core::records::Kind::Recovery { root, .. } if root.hash() == s))
            })
    });
    want
}

fn mask_early(got: &State, mut want: State) -> State {
    if std::env::var_os("FZ_EARLY_LAX").is_some() && got.first_missing.is_none() && want.first_missing.is_some() {
        want.first_missing = None;
    }
    want
}

fn agrees(g: &groupgen::Group, m: &RecordSet, all: &[Record], lists: &[Vec<u8>], what: &str) -> State {
    let (root, recovery) = (&g.root, &g.recovery);
    let kept: Vec<Record> = m.ids().map(|id| m.get(id).unwrap().clone()).collect();
    let held: Vec<Vec<u8>> = m.lists().map(<[u8]>::to_vec).collect();
    let want = evaluate(&Input { root, recovery, records: &kept, lists: &held });
    let got = m.state();
    let want = mask_waiting(m, &got, mask_early(&got, want));
    assert_eq!(got, want, "{what}: set and evaluate of its records differ");
    let whole = evaluate(&Input { root, recovery, records: all, lists });
    assert_eq!(got.roots, whole.roots, "{what}: roots differ from evaluate of what it got");
    assert_eq!(got.devices, whole.devices, "{what}: devices differ from evaluate of what it got");
    assert_eq!(got.revoked, whole.revoked, "{what}: revoked differ from evaluate of what it got");
    assert_eq!(got.changes, whole.changes, "{what}: changes differ from evaluate of what it got");
    assert_eq!(got.stop, whole.stop, "{what}: stop differs from evaluate of what it got");
    got
}

/// The items in a shuffled order; lists placed by `how`: 0 shuffled with the
/// records, 1 first, 2 last, 3 withheld.
fn items(recs: &[Record], lists: &[Vec<u8>], how: u8, rng: &mut Rng) -> (Vec<Item>, Vec<Vec<u8>>) {
    let mut r: Vec<Record> = recs.to_vec();
    shuffle(&mut r, rng);
    let mut out: Vec<Item> = r.into_iter().map(Item::Rec).collect();
    let ls: Vec<Item> = lists.iter().cloned().map(Item::List).collect();
    let given = match how & 3 {
        0 => {
            for l in ls {
                let at = (rng.next() % (out.len() as u64 + 1)) as usize;
                out.insert(at, l);
            }
            lists.to_vec()
        }
        1 => {
            let mut v = ls;
            v.extend(out);
            out = v;
            lists.to_vec()
        }
        2 => {
            out.extend(ls);
            lists.to_vec()
        }
        _ => Vec::new(),
    };
    (out, given)
}

/// FZ_BENCH=1: time the parts of one input natively for a group and the
/// same group with its dominant parts doubled, then exit.
fn bench() {
    use std::time::Instant;
    let base = groupgen::sizes(1)[2].clone();
    let scale: Vec<(String, groupgen::Spec)> = [50usize, 100, 200, 400, 800]
        .iter()
        .map(|&f| (format!("root_fill {f}"), groupgen::Spec { root_fill: f, checkpoints: 0, takeovers: 0, ..base.clone() }))
        .collect();
    let specs_v: Vec<(String, groupgen::Spec)> = if std::env::var("FZ_BENCH").as_deref() == Ok("2") { scale } else { [
        ("sizes(1)[2]", base.clone()),
        ("2x root_fill", groupgen::Spec { root_fill: base.root_fill * 2, ..base.clone() }),
        ("2x admin_fill", groupgen::Spec { admin_fill: base.admin_fill * 2, ..base.clone() }),
        ("2x devices (cap)", groupgen::Spec { devices: (base.devices * 2).min(256), ..base.clone() }),
        ("ceilings(1)", groupgen::ceilings(1)),
    ].into_iter().map(|(n, s)| (n.to_string(), s)).collect() };
    for (name, spec) in specs_v {
        let t = Instant::now();
        let g = groupgen::build(spec);
        let tb = t.elapsed();
        let items: Vec<Item> = g.records.iter().cloned().map(Item::Rec).chain(g.lists.iter().cloned().map(Item::List)).collect();
        let t = Instant::now();
        let m = member(&g, &items, 0);
        let tf = t.elapsed();
        let t = Instant::now();
        let st = m.state();
        let ts = t.elapsed();
        let t = Instant::now();
        let _ = g.evaluate();
        let te = t.elapsed();
        let t = Instant::now();
        let m7 = member(&g, &items, 7);
        let tf7 = t.elapsed();
        let t = Instant::now();
        let mut one = RecordSet::new(g.root.clone(), g.recovery.clone());
        for r in &g.records {
            let _ = one.insert(r.clone());
        }
        for l in &g.lists {
            let _ = one.insert_list(l);
        }
        let ti = t.elapsed();
        let kinds = |k: fn(&Kind) -> bool| g.records.iter().filter(|r| k(&r.body().kind)).count();
        println!(
            "{name}: {} records ({} devices, {} copies, {} settings, {} checkpoints, {} revokes, {} heads), {} kept; build {:?}; one pass of inserts {:?}; member fill {:?}; fill with state() every 7 {:?}; state {:?}; evaluate all {:?}; roots {}",
            g.records.len(),
            kinds(|k| matches!(k, Kind::Device(_))),
            kinds(|k| matches!(k, Kind::Copies { .. })),
            kinds(|k| matches!(k, Kind::Settings(_))),
            kinds(|k| matches!(k, Kind::Checkpoint { .. })),
            kinds(|k| matches!(k, Kind::Revoke(_))),
            kinds(|k| matches!(k, Kind::Recovery { .. })),
            m.ids().count(), tb, ti, tf, tf7, ts, te, st.roots.len()
        );
        let _ = m7;
    }
    std::process::exit(0);
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    if std::env::var_os("FZ_BENCH").is_some() {
        bench();
    }
    if data.len() < 8 {
        return;
    }
    let small;
    let g: &groupgen::Group = if data[0] < 200 {
        let gs = groups();
        // The ceilings' group is slow: rarely.
        let i = usize::from(data[0]) % gs.len();
        if i == gs.len() - 1 && data[1] & 7 != 0 {
            &gs[usize::from(data[0]) % (gs.len() - 1)]
        } else {
            &gs[i]
        }
    } else {
        let spec = groupgen::Spec {
            seed: u64::from(data[1]),
            devices: 2 + usize::from(data[2] % 14),
            admins: usize::from(data[3] % 4),
            removals: usize::from(data[4] % 3),
            root_fill: usize::from(data[5] % 12),
            admin_fill: usize::from(data[6] % 6),
            checkpoints: usize::from(data[7] % 3),
            takeovers: usize::from((data[2] >> 4) % 3),
        };
        small = groupgen::build(spec);
        &small
    };
    let mut rng = Rng(u64::from_le_bytes(cbb_core::certs::sha256(data)[..8].try_into().unwrap()));
    let cfg = data.get(8).copied().unwrap_or(0);
    // Gaps: a member that never got some records.
    let gaps = data.get(9).copied().unwrap_or(0);
    let mut part: Vec<Record> = g.records.clone();
    if gaps & 1 == 1 {
        let n = (gaps >> 1) as u64 + 1;
        part.retain(|_| rng.next() % 64 >= n.min(63));
    }
    let (a_items, a_lists) = items(&part, &g.lists, cfg & 3, &mut rng);
    let every_a = usize::from((cfg >> 2) & 7) * 7;
    let a = member(g, &a_items, every_a);
    let sa = agrees(g, &a, &part, &a_lists, "a");
    if gaps & 1 == 0 && cfg & 3 != 3 {
        // Two members with everything, in two orders, keep one set.
        let (b_items, b_lists) = items(&g.records, &g.lists, (cfg >> 6) % 3, &mut rng);
        let every_b = usize::from((cfg >> 5) & 1) * 13;
        let b = member(g, &b_items, every_b);
        let sb = agrees(g, &b, &g.records, &b_lists, "b");
        assert_eq!(sa.roots, sb.roots, "two orders, two roots");
        assert_eq!(a.digest(), b.digest(), "two orders, two sets");
        // The group's own evaluation, with every record at once.
        let all = g.evaluate();
        assert_eq!(all.roots, sb.roots, "a member's roots and the group's");
    }
    let _ = Kind::Unknown(0);
});
