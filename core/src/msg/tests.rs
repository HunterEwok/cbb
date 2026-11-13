// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

use serde_json::Value as Json;

use super::{check, check_map, tables, wave4};
use crate::blind::card::Card;
use crate::format::{Rule, cbor};
use crate::join::invitation::Invitation;

fn load() -> Json {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../testdata/format/messages3.json");
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn unhex(v: &Json) -> Vec<u8> {
    let s = v.as_str().unwrap();
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn table(name: &str) -> &'static super::Table {
    tables::ALL.iter().find(|t| t.name() == name).unwrap_or_else(|| panic!("no table {name}"))
}

#[test]
fn the_tables_are_the_vectors() {
    let v = load();
    let theirs = v["tables"].as_object().unwrap();
    assert_eq!(theirs.len(), tables::ALL.len());
    for t in tables::ALL {
        let rows = theirs[t.name()].as_array().unwrap_or_else(|| panic!("{} missing", t.name()));
        let ours: Vec<Json> = t
            .fields
            .iter()
            .map(|f| serde_json::json!({"n": f.n, "rule": f.rule, "type": f.ty.describe(), "needed": f.needed}))
            .collect();
        assert_eq!(rows, &ours, "{}", t.name());
    }
    for (t, name) in v["types"].as_object().unwrap() {
        let n: u64 = t.parse().unwrap();
        assert_eq!(tables::of(n).map(super::Table::name), name.as_str(), "type {t}");
    }
}

#[test]
fn messages_of_the_vectors() {
    let v = load();
    for t in v["take"].as_array().unwrap() {
        assert_eq!(check(&unhex(&t["message"])), Ok(t["t"].as_u64().unwrap()), "{}", t["name"]);
    }
    for r in v["refuse"].as_array().unwrap() {
        let rule = r["rule"].as_str().unwrap();
        assert_eq!(check(&unhex(&r["message"])).err().map(|e| e.name()), Some(rule), "{}", r["name"]);
    }
    for m in v["maps"].as_array().unwrap() {
        let b = unhex(&m["value"]);
        let got = check_map(table(m["table"].as_str().unwrap()), &cbor::decode(&b).unwrap());
        assert_eq!(got.err().map(Rule::name), m["rule"].as_str(), "{}", m["name"]);
    }
}

#[test]
fn invitations_of_the_vectors() {
    let v = &load()["invitations"];
    for t in v["take"].as_array().unwrap() {
        let b = unhex(&t["invitation"]);
        let inv = Invitation::decode(&b).unwrap_or_else(|e| panic!("{}: {e}", t["name"]));
        assert_eq!(inv.encode(), b, "{}", t["name"]);
        assert_eq!(Invitation::parse(t["text"].as_str().unwrap()).unwrap(), inv);
        assert!(check_map(&tables::INVITE, &cbor::decode(&b).unwrap()).is_ok());
    }
    for r in v["refuse"].as_array().unwrap() {
        let got = Invitation::decode(&unhex(&r["invitation"]));
        match (r["reader_paths"].as_u64(), r["reader_rights"].as_u64()) {
            // A reader of this version skips the path it cannot read.
            (Some(n), _) => assert_eq!(got.map(|i| i.paths.len() as u64), Ok(n), "{}", r["name"]),
            // And ignores the rights bits it does not know.
            (_, Some(n)) => assert_eq!(got.map(|i| i.profile.rights), Ok(n), "{}", r["name"]),
            _ => assert_eq!(got.err().map(|e| e.name()), r["rule"].as_str(), "{}", r["name"]),
        }
    }
}

#[test]
fn cards_of_the_vectors() {
    let v = &load()["cards"];
    for t in v["take"].as_array().unwrap() {
        assert!(Card::read(&unhex(&t["envelope"])).is_ok(), "{}", t["name"]);
    }
    for r in v["refuse"].as_array().unwrap() {
        let got = Card::read(&unhex(&r["envelope"])).err().map(|e| e.name());
        assert_eq!(got, r["rule"].as_str(), "{}", r["name"]);
    }
}

#[test]
#[ignore = "prints the tables in gen.py's form"]
fn print_tables() {
    for t in tables::ALL {
        println!("    \"{}\": [", t.name());
        for f in t.fields {
            println!(
                "        ({}, \"{}\", \"{}\", {}),",
                f.n,
                f.rule,
                f.ty.describe(),
                if f.needed { "True" } else { "False" }
            );
        }
        println!("    ],");
    }
}

#[test]
fn one_address_one_spelling() {
    for t in ["192.0.2.1:443", "[2001:db8::1]:443", "[2001:db8:0:1:1:1:1:1]:443", "[::102:304]:1"] {
        assert!(super::valid_addr(t), "{t}");
    }
    for t in [
        "[2001:DB8::1]:443",
        "[2001:db8:0:0:0:0:0:1]:443",
        "[2001:0db8::0001]:443",
        "[2001:db8::0.0.0.1]:443",
        "[2001:db8:0::1]:443",
        "[2001:db8::1:1:1:1:1]:443",
        "192.0.2.1:0",
        "0.0.0.0:443",
        "[::]:443",
    ] {
        assert!(!super::valid_addr(t), "{t}");
    }
}

fn load4() -> Json {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../testdata/format/wave4.json");
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn verdict<T>(r: Result<T, Rule>, take: impl FnOnce(T) -> &'static str) -> String {
    match r {
        Ok(x) => take(x).into(),
        Err(e) => e.name().into(),
    }
}

#[test]
fn the_wave4_tables_are_the_vectors() {
    let v = load4();
    let theirs = v["tables"].as_object().unwrap();
    assert_eq!(theirs.len(), wave4::ALL.len());
    for t in wave4::ALL {
        let rows = theirs[t.name()].as_array().unwrap_or_else(|| panic!("{} missing", t.name()));
        let ours: Vec<Json> = t
            .fields
            .iter()
            .map(|f| serde_json::json!({"n": f.n, "rule": f.rule, "type": f.ty.describe(), "needed": f.needed}))
            .collect();
        assert_eq!(rows, &ours, "{}", t.name());
        assert!(tables::ALL.iter().all(|o| o.name() != t.name()), "{} named twice", t.name());
    }
    for (t, name) in v["types"].as_object().unwrap() {
        let n: u64 = t.parse().unwrap();
        assert_eq!(wave4::of(n).map(super::Table::name), name.as_str(), "type {t}");
        assert!(tables::of(n).is_none(), "type {t} named twice");
    }
    let labels = &v["labels"];
    assert_eq!(labels["command"], crate::format::sig::LABEL_COMMAND);
    assert_eq!(labels["beacon"], crate::format::sig::LABEL_BEACON);
}

#[test]
fn the_wave4_vectors_are_what_the_readers_say() {
    use crate::content::Content;
    use crate::keystore::{ReadStatement, read_statement};
    let v = load4();
    let name = |x: &Json| x["name"].as_str().unwrap().to_owned();
    let want = |x: &Json| x["verdict"].as_str().unwrap().to_owned();
    for c in v["contents"].as_array().unwrap() {
        let got = verdict(Content::read(&unhex(&c["content"])), |c| if c.unknown { "keep" } else { "take" });
        assert_eq!(got, want(c), "contents {}", name(c));
    }
    for c in v["commands"].as_array().unwrap() {
        let got = verdict(crate::commands::Command::read(&unhex(&c["envelope"])), |_| "take");
        assert_eq!(got, want(c), "commands {}", name(c));
    }
    for o in v["orders"].as_array().unwrap() {
        let got =
            verdict(crate::commands::orders::check(o["type"].as_u64().unwrap(), &unhex(&o["orders"])), |()| "take");
        assert_eq!(got, want(o), "orders {}", name(o));
    }
    for h in v["statements"].as_array().unwrap() {
        let got = verdict(read_statement(&unhex(&h["envelope"])), |r| match r {
            ReadStatement::Held { .. } => "hold",
            ReadStatement::Take(_) => "take",
        });
        assert_eq!(got, want(h), "statements {}", name(h));
    }
    for b in v["beacons"].as_array().unwrap() {
        let got = verdict(crate::beacon::read(&unhex(&b["envelope"])), |_| "take");
        assert_eq!(got, want(b), "beacons {}", name(b));
    }
    for m in v["messages"].as_array().unwrap() {
        let msg = unhex(&m["message"]);
        let got = verdict(check(&msg), |_| "take");
        assert_eq!(got, want(m), "messages {}", name(m));
        let fb = unhex(&m["frame"]);
        let f = crate::format::frame::read(&fb, crate::format::frame::LIMIT_MEMBER).unwrap();
        assert_eq!(f.t, m["t"].as_u64().unwrap(), "messages {}", name(m));
    }
}

#[test]
fn an_offer_names_its_endpoint_keys() {
    use crate::format::Value;
    let key = |k: &'static [u8; 32]| Value::Array(vec![Value::Uint(3), Value::Bytes(k)]);
    static HUB: [u8; 32] = [3; 32];
    static FACE: [u8; 32] = [4; 32];
    let offer = |keys: Vec<(&'static str, &'static [u8; 32])>| {
        let mut m = vec![
            (1, key(&HUB)),
            (2, Value::Array(vec![Value::Text("203.0.113.5:51820"), Value::Text("[2001:db8::5]:51820")])),
        ];
        if !keys.is_empty() {
            m.push((
                9,
                Value::Array(
                    keys.into_iter().map(|(e, k)| Value::Map(vec![(1, Value::Text(e)), (2, key(k))])).collect(),
                ),
            ));
        }
        Value::Map(m)
    };
    assert_eq!(check_map(&tables::OFFER, &offer(vec![])), Ok(()));
    // One endpoint on a forwarder with the hub's key for that face.
    assert_eq!(check_map(&tables::OFFER, &offer(vec![("203.0.113.5:51820", &FACE)])), Ok(()));
    let bad = Err(Rule::field("offer/endpoint-keys"));
    assert_eq!(check_map(&tables::OFFER, &offer(vec![("198.51.100.1:1", &FACE)])), bad, "not its endpoint");
    assert_eq!(
        check_map(&tables::OFFER, &offer(vec![("203.0.113.5:51820", &FACE), ("203.0.113.5:51820", &HUB)])),
        bad,
        "two keys for one endpoint"
    );
}

mod reading {
    use super::super::{Field, Later, Table, Ty, check_map, later, read_map, read_map_by, tables, wave4};
    use crate::format::{Rule, Value};

    const fn f(n: u16, rule: &'static str, ty: Ty, needed: bool) -> Field {
        Field { n, rule, ty, needed }
    }
    static T: Table = Table {
        shape: "t/shape",
        fields: &[
            f(2, "t/kind", Ty::Uint { min: 1, max: 3 }, true),
            f(3, "t/count", Ty::Uint { min: 1, max: 9 }, false),
            f(4, "t/name", Ty::Text(8), false),
            f(5, "t/key", Ty::Bytes(32), false),
            f(6, "t/list", Ty::Array { of: &Ty::Uint { min: 1, max: 9 }, max: 4 }, false),
            f(7, "t/obfuscation", Ty::Map(&tables::OBFUSCATION), false),
            f(8, "t/flag", Ty::Flag, false),
            f(9, "t/bits", Ty::Uint { min: 1, max: 7 }, false),
            f(10, "t/refused", Ty::Uint { min: 1, max: 9 }, false),
            f(11, "t/id", Ty::Id(16), false),
        ],
    };

    fn m<'a>(entries: Vec<(u16, Value<'a>)>) -> Value<'a> {
        Value::Map(entries)
    }

    /// The rows of the test table: 3, 4, 6 and 8 read as absent, 7 is a
    /// transport, 9 bits, 10 and 11 refuse (the default).
    fn rows(t: &Table, n: u16) -> Later {
        if !core::ptr::eq(t, &T) {
            return later::of(t, n);
        }
        match n {
            3 | 4 | 6 | 8 => Later::Absent,
            7 => Later::Unusable,
            9 => Later::Bits(7),
            _ => Later::Refuse,
        }
    }

    fn read(v: &Value<'static>) -> Result<Value<'static>, Rule> {
        read_map_by(&T, v, rows)
    }

    /// A value from a later version, by the field's row: out of range it
    /// reads as absent where absent is neutral, a list keeps what it
    /// understands, bits keep the ones this version knows, a transport's
    /// table is made unusable, and everything else refuses; the shape
    /// always refuses.
    #[test]
    fn a_value_from_a_later_version_reads_by_its_row() {
        let base = vec![(0, Value::Uint(9)), (2, Value::Uint(1))];
        let with = |extra: Vec<(u16, Value<'static>)>| {
            let mut e = base.clone();
            e.extend(extra);
            e.sort_by_key(|(k, _)| *k);
            m(e)
        };
        // In range: the same map.
        let good = with(vec![(3, Value::Uint(4)), (4, Value::Text("lamp")), (6, Value::Array(vec![Value::Uint(2)]))]);
        assert_eq!(read(&good), Ok(good.clone()));
        // Optional fields whose row reads as absent, out of range: gone.
        for (k, v) in [
            (3, Value::Uint(10)),
            (4, Value::Text("a name far too long")),
            (4, Value::Text("a\nb")),
            (8, Value::Uint(2)),
            (6, Value::Array(vec![Value::Uint(1); 5])),
        ] {
            assert_eq!(read(&with(vec![(k, v.clone())])), Ok(with(vec![])), "{k}: {v:?}");
        }
        // A list skips the element it does not understand, and reads as
        // absent when nothing is left.
        let list = with(vec![(6, Value::Array(vec![Value::Uint(2), Value::Uint(20), Value::Uint(3)]))]);
        assert_eq!(read(&list), Ok(with(vec![(6, Value::Array(vec![Value::Uint(2), Value::Uint(3)]))])));
        assert_eq!(read(&with(vec![(6, Value::Array(vec![Value::Uint(20)]))])), Ok(with(vec![])));
        // Bits: the unknown ones are cleared, none left reads as absent.
        assert_eq!(read(&with(vec![(9, Value::Uint(0b1101))])), Ok(with(vec![(9, Value::Uint(0b101))])));
        assert_eq!(read(&with(vec![(9, Value::Uint(0b1000))])), Ok(with(vec![])));
        // A transport's table out of range, or with a field it does not
        // name, is the empty map: unusable, and its strict reader refuses it.
        let settings = |extra: Vec<(u16, Value<'static>)>| {
            let mut e = vec![
                (1, Value::Uint(4)),
                (2, Value::Uint(40)),
                (3, Value::Uint(70)),
                (4, Value::Array(vec![Value::Uint(0); 4])),
                (5, Value::Array(vec![Value::Array(vec![Value::Uint(5)]); 4])),
            ];
            e.extend(extra);
            m(e)
        };
        assert!(check_map(&tables::OBFUSCATION, &settings(vec![])).is_ok());
        assert_eq!(read(&with(vec![(7, settings(vec![]))])), Ok(with(vec![(7, settings(vec![]))])));
        for broken in [m(vec![(1, Value::Uint(0))]), settings(vec![(7, Value::Uint(1))])] {
            let got = read(&with(vec![(7, broken)])).unwrap();
            assert!(later::unusable(got.get(7).unwrap()));
            assert!(crate::msg::Obfuscation::read(got.get(7).unwrap(), "t/obfuscation").is_err());
        }
        // Refused by their row (the default), out of range.
        assert_eq!(read(&with(vec![(10, Value::Uint(10))])), Err(Rule::field("t/refused")));
        assert_eq!(read(&with(vec![(11, Value::Bytes(&[0; 16]))])), Err(Rule::field("t/id")));
        // A field this table does not name is kept for its reader.
        let later = with(vec![(300, Value::Text("later"))]);
        assert_eq!(read(&later), Ok(later.clone()));
        // The shape refuses: a CBOR type, a fixed length, a needed field.
        assert_eq!(read(&with(vec![(3, Value::Text("4"))])), Err(Rule::field("t/count")));
        assert_eq!(read(&with(vec![(5, Value::Bytes(&[1; 31]))])), Err(Rule::field("t/key")));
        assert_eq!(read(&with(vec![(6, Value::Array(vec![Value::Text("x")]))])), Err(Rule::field("t/list")));
        assert_eq!(read(&with(vec![(7, Value::Uint(1))])), Err(Rule::field("t/obfuscation")));
        assert_eq!(read(&m(vec![(0, Value::Uint(9)), (2, Value::Uint(7))])), Err(Rule::field("t/kind")));
        assert_eq!(read(&m(vec![(0, Value::Uint(9))])), Err(Rule::field("t/kind")));
        assert_eq!(read(&Value::Uint(1)), Err(Rule::field("t/shape")));
    }

    /// Every table's optional fields, each in [`later::OPTIONAL`] exactly
    /// once, with a row that fits it; no row names a needed field or one
    /// that does not exist.
    #[test]
    fn every_optional_field_has_one_row() {
        let all: Vec<&'static Table> = tables::ALL.iter().chain(wave4::ALL.iter()).copied().collect();
        let mut seen = 0;
        for t in &all {
            for f in t.fields.iter().filter(|f| !f.needed) {
                let n = later::OPTIONAL.iter().filter(|r| core::ptr::eq(r.table, *t) && r.n == f.n).count();
                assert_eq!(n, 1, "{} field {}: {n} rows", t.name(), f.n);
                seen += 1;
            }
        }
        assert_eq!(seen, later::OPTIONAL.len());
        for r in later::OPTIONAL {
            assert!(all.iter().any(|t| core::ptr::eq(*t, r.table)), "{} is no message table", r.table.name());
            assert!(later::fits(r), "{} field {}: {:?}", r.table.name(), r.n, r.later);
            assert!(!r.why.is_empty());
        }
    }

    /// The rows the product reads by: on the real tables, a value out of
    /// range refuses unless its row says otherwise.
    #[test]
    fn the_real_tables_read_by_their_rows() {
        // An offer's `moved` flag of a later version refuses: absent would
        // change what the device does.
        let key = Value::Array(vec![Value::Uint(crate::format::Alg::X25519.number()), Value::Bytes(&[9; 32])]);
        let offer = |extra: Vec<(u16, Value<'static>)>| {
            let mut e = vec![(1, key.clone())];
            e.extend(extra);
            m(e)
        };
        assert!(read_map(&tables::OFFER, &offer(vec![])).is_ok());
        assert_eq!(read_map(&tables::OFFER, &offer(vec![(6, Value::Uint(2))])), Err(Rule::field("offer/moved")));
        // Its settings of a later version make it unusable, not refused.
        let got = read_map(&tables::OFFER, &offer(vec![(3, m(vec![(1, Value::Uint(0))]))])).unwrap();
        assert!(later::unusable(got.get(3).unwrap()));
        // A Welcome with more keys statements than this version takes reads
        // without them: they also come by sync, and none grants nothing.
        let v = super::load();
        let w = v["maps"].as_array().unwrap().iter().find(|m| m["name"] == "a Welcome").unwrap();
        let b = super::unhex(&w["value"]);
        let welcome = crate::format::cbor::decode(&b).unwrap();
        let env = welcome.get(2).and_then(Value::as_array).unwrap()[0].clone();
        let with_keys = |n: usize| {
            let mut e: Vec<(u16, Value<'_>)> =
                welcome.as_map().unwrap().iter().filter(|(k, _)| *k != 4).cloned().collect();
            e.push((4, Value::Array(vec![env.clone(); n])));
            e.sort_by_key(|(k, _)| *k);
            m(e)
        };
        assert_eq!(
            read_map(&tables::WELCOME, &with_keys(256)).unwrap().get(4).and_then(Value::as_array).map(<[_]>::len),
            Some(256)
        );
        assert_eq!(read_map(&tables::WELCOME, &with_keys(257)).unwrap().get(4), None);
        assert_eq!(check_map(&tables::WELCOME, &with_keys(257)), Err(Rule::field("welcome/keys")));
        // A reason this version cannot read reads as none, and the reader
        // says it dropped one, so a log tells it from "no reason sent".
        let long = "x".repeat(257);
        let result = |reason: Option<&str>| {
            let mut e = vec![
                (0, Value::Uint(tables::T_RESULT)),
                (2, Value::Bytes(&[1; 16])),
                (3, Value::Bytes(&[2; 16])),
                (4, Value::Uint(2)),
            ];
            if let Some(r) = reason {
                e.push((5, Value::Text(r)));
            }
            m(e).encode()
        };
        let sent = result(Some(&long));
        let (_, read, dropped) = super::super::read_noted(&sent).unwrap();
        assert_eq!(read.get(5), None);
        assert_eq!(dropped, vec![super::super::Dropped { rule: "result/reason", n: 5, bytes: 260 }]);
        let none = result(None);
        assert_eq!(super::super::read_noted(&none).unwrap().2, vec![]);
        // The zero invitation ID refuses, as a dismiss without its key would
        // reach every request.
        let dismiss = m(vec![(0, Value::Uint(tables::T_DISMISS)), (2, Value::Bytes(&[0; 16]))]);
        assert_eq!(read_map(&tables::DISMISS, &dismiss), Err(Rule::field("dismiss/invite")));
    }

    /// A registry number this version does not know never reads as one it
    /// knows: the field's row refuses it (each is needed), and the
    /// readers that turn it into a kind refuse it too.
    #[test]
    fn an_unknown_registry_number_matches_no_known_one() {
        let v = super::load();
        let sample = |table: &Table| -> Value<'static> {
            let hex = v["take"]
                .as_array()
                .unwrap()
                .iter()
                .find(|t| tables::of(t["t"].as_u64().unwrap()).is_some_and(|x| core::ptr::eq(x, table)))
                .map(|t| &t["message"])
                .or_else(|| {
                    v["maps"].as_array().unwrap().iter().find(|m| m["table"] == table.name()).map(|m| &m["value"])
                })
                .unwrap_or_else(|| panic!("no sample of {}", table.name()));
            let b: &'static [u8] = Box::leak(super::unhex(hex).into_boxed_slice());
            crate::format::cbor::decode(b).unwrap()
        };
        let set = |val: &Value<'static>, n: u16, to: u64| -> Value<'static> {
            m(val
                .as_map()
                .unwrap()
                .iter()
                .map(|(k, x)| (*k, if *k == n { Value::Uint(to) } else { x.clone() }))
                .collect())
        };
        for (table, n) in [
            (&tables::GUEST, 2),
            (&tables::RESULT, 4),
            (&tables::PAIR_ERROR, 2),
            (&tables::REQUEST, 4),
            (&tables::INFO, 4),
            (&tables::PATH, 1),
            (&tables::PROFILE, 1),
        ] {
            let f = table.fields.iter().find(|f| f.n == n).unwrap();
            let Ty::Uint { max, .. } = f.ty else { panic!("{} {n} is no number", table.name()) };
            assert!(f.needed, "{} {n}", table.name());
            if let Some(val) =
                (!core::ptr::eq(table, &tables::PATH) && !core::ptr::eq(table, &tables::PROFILE)).then(|| sample(table))
            {
                assert!(read_map(table, &val).is_ok(), "{}", table.name());
                assert_eq!(read_map(table, &set(&val, n, max + 1)), Err(Rule::field(f.rule)), "{} {n}", table.name());
            }
        }
        // The kinds: a role, a path, a profile's role, a network.
        let role = crate::join::info::Info::decode(&m(vec![(1, Value::Text("tv")), (4, Value::Uint(5))]).encode());
        assert!(role.is_err());
        let inv = v["invitations"]["take"].as_array().unwrap()[0]["invitation"].clone();
        let inv: &'static [u8] = Box::leak(super::unhex(&inv).into_boxed_slice());
        let inv = crate::format::cbor::decode(inv).unwrap();
        let paths = inv.get(3).and_then(Value::as_array).unwrap();
        let bad_path = m(inv
            .as_map()
            .unwrap()
            .iter()
            .map(|(k, x)| (*k, if *k == 3 { Value::Array(vec![set(&paths[0], 1, 4)]) } else { x.clone() }))
            .collect());
        assert!(crate::join::invitation::Invitation::decode(&bad_path.encode()).is_err());
        let bad_role = m(inv
            .as_map()
            .unwrap()
            .iter()
            .map(|(k, x)| (*k, if *k == 4 { set(x, 1, 5) } else { x.clone() }))
            .collect());
        assert!(crate::join::invitation::Invitation::decode(&bad_role.encode()).is_err());
        // A message type this version does not number is passed on as it
        // is, never read by another type's table.
        let unknown = m(vec![(0, Value::Uint(200)), (2, Value::Uint(1))]).encode();
        assert_eq!(super::super::read(&unknown).map(|(t, _)| t), Ok(200));
        assert!(tables::of(200).is_none() && wave4::of(200).is_none());
    }

    /// future.json: the rows are ours, and each case reads as it says.
    #[test]
    fn the_future_vectors_are_what_the_reader_says() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../testdata/format/future.json");
        let v: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let all: Vec<&'static Table> = tables::ALL.iter().chain(wave4::ALL.iter()).copied().collect();
        let by_name = |n: &str| *all.iter().find(|t| t.name() == n).unwrap_or_else(|| panic!("no table {n}"));
        let word = |l: Later| match l {
            Later::Refuse => "refuse".into(),
            Later::Absent => "absent".into(),
            Later::Bits(m) => format!("bits {m}"),
            Later::Unusable => "unusable".into(),
        };
        let rows = v["rows"].as_array().unwrap();
        assert_eq!(rows.len(), later::OPTIONAL.len());
        for r in rows {
            let t = by_name(r["table"].as_str().unwrap());
            let n = u16::try_from(r["n"].as_u64().unwrap()).unwrap();
            assert_eq!(word(later::of(t, n)), r["later"].as_str().unwrap(), "{} {n}", t.name());
        }
        for c in v["cases"].as_array().unwrap() {
            let b = super::unhex(&c["value"]);
            let got = read_map(by_name(c["table"].as_str().unwrap()), &crate::format::cbor::decode(&b).unwrap());
            match c["rule"].as_str() {
                Some(rule) => assert_eq!(got.err().map(Rule::name), Some(rule), "{}", c["name"]),
                None => assert_eq!(got.map(|x| x.encode()), Ok(super::unhex(&c["read"])), "{}", c["name"]),
            }
        }
    }

    /// Everything the vectors take reads back unchanged.
    #[test]
    fn what_the_writer_check_takes_reads_unchanged() {
        let v = super::load();
        for t in v["take"].as_array().unwrap() {
            let msg = super::unhex(&t["message"]);
            let val = crate::format::cbor::decode(&msg).unwrap();
            let ty = val.get(0).and_then(Value::as_uint).unwrap();
            if let Some(table) = tables::of(ty).or_else(|| super::super::wave4::of(ty)) {
                assert_eq!(read_map(table, &val).as_ref(), Ok(&val), "{}", t["name"]);
            }
        }
    }
}
