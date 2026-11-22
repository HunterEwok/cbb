// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The wave 4 vectors mutated field by field, with the Rust readers'
//! verdicts, written to `testdata/format/wave4-mutants.json`. The Go check
//! applies the same mutations to the same vectors and judges them by its
//! own rules; any disagreement fails there, and this test fails when the
//! file no longer matches what the readers say. `CBB_WRITE_MUTANTS=1`
//! writes the file again.

use alloc::vec::Vec;

use serde_json::{Value as Json, json};

use crate::format::Rule;
use crate::format::cbor::{self, Value};

/// The values a field is set to, as CBOR.
fn alts() -> Vec<Vec<u8>> {
    let items: Vec<Value<'static>> = alloc::vec![
        Value::Uint(0),
        Value::Uint(1),
        Value::Uint(5),
        Value::Uint((1 << 62) + 1),
        Value::Text(""),
        Value::Text("a\u{202e}b"),
        Value::Text("../x"),
        Value::Bytes(&[0; 16]),
        Value::Bytes(&[0; 32]),
        Value::Array(Vec::new()),
        Value::Map(Vec::new()),
    ];
    items.iter().map(Value::encode).collect()
}

/// A mutation: where (map keys and array indices from the top), and what:
/// drop it, set it to an alternative, or add key `add` with alternative 1.
#[derive(Clone, Debug)]
enum Op {
    Drop,
    Set(usize),
    Add(u16),
}

fn apply<'a>(v: &Value<'a>, path: &[u64], op: &Op, alts: &[Value<'a>]) -> Option<Value<'a>> {
    match (v, path) {
        (Value::Map(m), []) => match op {
            Op::Add(k) if !m.iter().any(|(x, _)| x == k) => {
                let mut m = m.clone();
                m.push((*k, alts.get(1)?.clone()));
                m.sort_by_key(|(x, _)| *x);
                Some(Value::Map(m))
            }
            _ => None,
        },
        (Value::Map(m), [k, rest @ ..]) => {
            let k = u16::try_from(*k).ok()?;
            let i = m.iter().position(|(x, _)| *x == k)?;
            let mut m = m.clone();
            if rest.is_empty() {
                match op {
                    Op::Drop => {
                        m.remove(i);
                    }
                    Op::Set(a) => m.get_mut(i)?.1 = alts.get(*a)?.clone(),
                    Op::Add(_) => return None,
                }
            } else {
                let inner = apply(&m.get(i)?.1, rest, op, alts)?;
                m.get_mut(i)?.1 = inner;
            }
            Some(Value::Map(m))
        }
        (Value::Array(a), [i, rest @ ..]) => {
            let i = usize::try_from(*i).ok()?;
            let mut a = a.clone();
            if rest.is_empty() {
                match op {
                    Op::Drop => {
                        a.get(i)?;
                        a.remove(i);
                    }
                    Op::Set(x) => *a.get_mut(i)? = alts.get(*x)?.clone(),
                    Op::Add(_) => return None,
                }
            } else {
                let inner = apply(a.get(i)?, rest, op, alts)?;
                *a.get_mut(i)? = inner;
            }
            Some(Value::Array(a))
        }
        _ => None,
    }
}

/// Every path to a map entry or array element, three deep at most, and
/// every map's own path (for adding a key).
fn paths(v: &Value<'_>, at: &mut Vec<u64>, out: &mut Vec<(Vec<u64>, bool)>, depth: usize) {
    match v {
        Value::Map(m) => {
            out.push((at.clone(), true));
            for (k, x) in m {
                at.push(u64::from(*k));
                out.push((at.clone(), false));
                if depth > 1 {
                    paths(x, at, out, depth - 1);
                }
                at.pop();
            }
        }
        Value::Array(a) => {
            for (i, x) in a.iter().enumerate().take(4) {
                at.push(i as u64);
                out.push((at.clone(), false));
                if depth > 1 {
                    paths(x, at, out, depth - 1);
                }
                at.pop();
            }
        }
        _ => {}
    }
}

fn hex(b: &[u8]) -> alloc::string::String {
    b.iter().map(|x| alloc::format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn verdict<T>(r: Result<T, Rule>, take: impl FnOnce(T) -> &'static str) -> alloc::string::String {
    match r {
        Ok(x) => take(x).into(),
        Err(e) => e.name().into(),
    }
}

/// What the Rust readers say of a family's mutated input: for a content
/// the map unpadded (padded here), for orders the map, for the rest the
/// envelope with the vector's own signature.
fn judge(
    family: &str,
    t: u64,
    top: &Value<'_>,
    env: Option<&crate::format::envelope::Envelope<'_>>,
) -> Option<alloc::string::String> {
    use crate::keystore::{ReadStatement, read_statement};
    let body = top.encode();
    Some(match family {
        "contents" => {
            let padded = crate::format::copy::write_content(top)?;
            verdict(crate::content::Content::read(&padded), |c| if c.unknown { "keep" } else { "take" })
        }
        "orders" => verdict(crate::commands::orders::check(t, &body), |()| "take"),
        _ => {
            let e = env?;
            let wire = crate::format::envelope::write(&body, e.sig, e.sig2);
            match family {
                "commands" => verdict(crate::commands::Command::read(&wire), |_| "take"),
                "beacons" => verdict(crate::beacon::read(&wire), |_| "take"),
                "statements" => verdict(read_statement(&wire), |r| match r {
                    ReadStatement::Held { .. } => "hold",
                    ReadStatement::Take(_) => "take",
                }),
                _ => return None,
            }
        }
    })
}

fn mutants() -> Json {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../testdata/format/wave4.json");
    let v: Json = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let alt_bytes = alts();
    let alt_values: Vec<Value<'_>> = alt_bytes.iter().map(|b| cbor::decode(b).unwrap()).collect();
    let mut cases = Vec::new();
    for (family, field) in [
        ("contents", "content"),
        ("commands", "envelope"),
        ("orders", "orders"),
        ("statements", "envelope"),
        ("beacons", "envelope"),
    ] {
        for (index, vec) in v[family].as_array().unwrap().iter().enumerate() {
            let want = vec["verdict"].as_str().unwrap();
            if !matches!(want, "take" | "keep" | "hold") {
                continue;
            }
            let raw = unhex(vec[field].as_str().unwrap());
            let t = vec["type"].as_u64().unwrap_or(0);
            let env = match field {
                "envelope" => Some(crate::format::envelope::Envelope::parse(&raw).unwrap()),
                _ => None,
            };
            let top = match (&env, family) {
                (Some(e), _) => e.map.clone(),
                (None, "contents") => {
                    let c = cbor::decode(&raw).unwrap();
                    Value::Map(c.as_map().unwrap().iter().filter(|(k, _)| *k != 1).cloned().collect())
                }
                (None, _) => cbor::decode(&raw).unwrap(),
            };
            let mut ps = Vec::new();
            paths(&top, &mut Vec::new(), &mut ps, 3);
            for (p, is_map) in ps {
                let mut ops = Vec::new();
                if is_map {
                    ops.extend([Op::Add(8), Op::Add(99), Op::Add(300)]);
                } else {
                    ops.push(Op::Drop);
                    ops.extend((0..alt_values.len()).map(Op::Set));
                }
                for op in ops {
                    let Some(m) = apply(&top, &p, &op, &alt_values) else { continue };
                    let Some(got) = judge(family, t, &m, env.as_ref()) else { continue };
                    let (name, arg) = match op {
                        Op::Drop => ("drop", 0u64),
                        Op::Set(a) => ("set", a as u64),
                        Op::Add(k) => ("add", u64::from(k)),
                    };
                    cases.push(
                        json!({"family": family, "index": index, "path": p, "op": name, "arg": arg, "verdict": got}),
                    );
                }
            }
        }
    }
    json!({"alts": alt_bytes.iter().map(|b| hex(b)).collect::<Vec<_>>(), "add_value": 1, "cases": cases})
}

#[test]
fn the_mutants_are_what_the_readers_say() {
    let got = mutants();
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../testdata/format/wave4-mutants.json");
    if std::env::var_os("CBB_WRITE_MUTANTS").is_some() {
        let mut text = serde_json::to_string(&got).unwrap();
        text.push('\n');
        std::fs::write(path, text).unwrap();
    }
    let file: Json = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert!(got["cases"].as_array().unwrap().len() > 1000);
    assert_eq!(file, got, "wave4-mutants.json is not what the readers say: CBB_WRITE_MUTANTS=1 writes it again");
}
