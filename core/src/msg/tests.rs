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
        let got = Invitation::decode(&unhex(&r["invitation"])).err().map(|e| e.name());
        assert_eq!(got, r["rule"].as_str(), "{}", r["name"]);
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
    for h in v["statements_held"].as_array().unwrap() {
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
