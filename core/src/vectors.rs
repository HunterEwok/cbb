// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The cross-implementation test vectors in testdata/interop, which the Go
//! tests write and the phone kit reads too: a lite member must decode,
//! encode and decide what they say as the Go member does.

use std::path::PathBuf;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::Value;

use crate::authority::Record;
use crate::certs::{self, Cert, KeyHash};
use crate::clip::Event;
use crate::group::Records;
use crate::hlc::Timestamp;
use crate::identity::Identity;
use crate::wire::{self, Message};

fn vectors(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../testdata/interop").join(name);
    serde_json::from_slice(&std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))).unwrap()
}

fn bytes(v: &Value) -> Vec<u8> {
    STANDARD.decode(v.as_str().unwrap()).unwrap()
}

fn cert(v: &Value) -> Cert {
    Cert::parse(&bytes(v)).unwrap()
}

fn records(v: &Value) -> Vec<Record> {
    serde_json::from_value(v.clone()).unwrap()
}

/// The member protocol's frames, timestamps, events and their order
/// (member.json).
#[test]
fn member_frames() {
    let v = vectors("member.json");
    for f in v["frames"].as_array().unwrap() {
        let m: Message = serde_json::from_value(f.clone()).unwrap();
        // Encoding again gives the same JSON.
        assert_eq!(serde_json::to_value(&m).unwrap(), *f, "frame {f}");
        match m.kind.as_str() {
            "hello" => {
                assert!(wire::known_role(&m.role));
                let (h, body) = wire::decode_hello(m.hello.as_ref()).unwrap();
                let want = &f["hello"];
                assert_eq!(h.wall, want["wall_ms"].as_i64().unwrap_or(0));
                assert_eq!(body.name, want["name"].as_str().unwrap_or(""));
                let device = wire::DeviceInfo::of(&body);
                assert_eq!(device.is_empty(), want.get("device").is_none());
                if let Some(d) = want.get("device") {
                    assert_eq!(serde_json::to_value(&device).unwrap(), *d);
                }
                // The current copy is sealed: its header, unread here.
                if let Some(c) = h.current {
                    assert!(c.unread);
                    let s = c.sealed.unwrap();
                    s.validate().unwrap();
                    assert_eq!(serde_json::to_value(&s).unwrap(), want["current"]);
                }
            }
            "event" => {
                let s: crate::copy::Sealed = serde_json::from_value(m.event.clone().unwrap()).unwrap();
                s.validate().unwrap();
                assert_eq!(serde_json::to_value(&s).unwrap(), f["event"]);
            }
            "records" => assert!(!m.records.is_empty()),
            _ => {}
        }
    }
    for t in v["timestamps"].as_array().unwrap() {
        let text = t["text"].as_str().unwrap();
        let got = Timestamp::parse(text);
        assert_eq!(got.is_some(), t["ok"].as_bool().unwrap(), "timestamp {text:?}");
        // Leading zeros parse; what is written again parses the same.
        if let Some(ts) = got {
            assert_eq!(Timestamp::parse(&ts.to_string()), Some(ts));
        }
    }
    for e in v["events"].as_array().unwrap() {
        let valid = serde_json::from_value::<Event>(e["json"].clone()).ok().is_some_and(|ev| ev.validate().is_ok());
        assert_eq!(valid, e["valid"].as_bool().unwrap(), "event {}", e["json"]);
    }
    for o in v["order"].as_array().unwrap() {
        let a: Event = serde_json::from_value(o["a"].clone()).unwrap();
        let b: Event = serde_json::from_value(o["b"].clone()).unwrap();
        assert_eq!(a.later(&b), o["later"].as_bool().unwrap(), "order {o}");
    }
    let bodies = v["bodies"].as_array().unwrap();
    assert!(bodies.len() >= 14);
    for b in bodies {
        let text = b["text"].as_str().unwrap();
        assert_eq!(wire::decode(text.as_bytes()).is_ok(), b["ok"].as_bool().unwrap(), "body {text}");
    }
}

/// Which member certificates a peer accepts at which time
/// (member-certs.json).
#[test]
fn member_certs() {
    let v = vectors("member-certs.json");
    let ca = cert(&v["group_ca"]);
    for c in v["cases"].as_array().unwrap() {
        let leaf = cert(&c["cert"]);
        let t = (c["now_ms"].as_i64().unwrap() / 1000).max(ca.not_before);
        let got = certs::verify_member(&[leaf], std::slice::from_ref(&ca), t, certs::Usage::Server)
            .map(|d| d.to_string())
            .unwrap_or_default();
        assert_eq!(got, c["device"].as_str().unwrap(), "{}", c["name"]);
    }
}

/// The pairing's channel identifier, the QR fingerprint and the frames
/// (pairing.json).
#[test]
fn pairing() {
    let v = vectors("pairing.json");
    let (member, joiner) = (bytes(&v["member_cert"]), bytes(&v["joiner_cert"]));
    assert_eq!(certs::hex(&crate::pair::channel_id(&member, &joiner)), v["channel_id"].as_str().unwrap());
    assert_eq!(certs::fingerprint(&joiner), v["fingerprint"].as_str().unwrap());
    let frames = v["frames"].as_array().unwrap();
    // The joiner's first frame, as a lite member writes it, differs only in
    // its role; the member's frames decode.
    crate::pair::check_frames_for_tests(frames);
}

/// The devices list, the revocations and the digest of records the phone
/// kit signed (swift-records.json).
#[test]
fn swift_records() {
    let v = vectors("swift-records.json");
    let mut s = crate::group::Records::new(&cert(&v["group_ca"]));
    let (fresh, errs) = s.add_all(&records(&v["records"]));
    assert!(errs.is_empty(), "{errs:?}");
    assert_eq!(fresh.len(), v["records"].as_array().unwrap().len());
    let ids: Vec<String> = s.devices().into_iter().map(|d| d.id).collect();
    let want: Vec<String> = serde_json::from_value(v["devices"].clone()).unwrap();
    assert_eq!(ids, want);
    for k in v["revoked"].as_array().unwrap() {
        assert!(s.revoked(&bytes(k).try_into().unwrap()));
    }
    assert_eq!(s.digest(), v["digest"].as_str().unwrap());
}

/// Records and a member certificate from an admin CA under the phone's
/// root (swift-admin.json).
#[test]
fn swift_admin() {
    let v = vectors("swift-admin.json");
    let ca = cert(&v["group_ca"]);
    let admin = cert(&v["admin_ca"]);
    let mut s = crate::group::Records::new(&ca);
    let (_, errs) = s.add_all(&records(&v["records"]));
    assert!(errs.is_empty(), "{errs:?}");
    let mut ids: Vec<String> = s.devices().into_iter().map(|d| d.id).collect();
    let mut want: Vec<String> = serde_json::from_value(v["devices"].clone()).unwrap();
    ids.sort();
    want.sort();
    assert_eq!(ids, want);
    assert_eq!(s.digest(), v["digest"].as_str().unwrap());

    let leaf = cert(&v["cert"]);
    let chain = [leaf.clone(), admin.clone()];
    let t = leaf.not_before + 48 * 3600;
    assert_eq!(
        certs::verify_member(&chain, std::slice::from_ref(&ca), t, certs::Usage::Client).unwrap().as_str(),
        v["device"].as_str().unwrap()
    );
    assert!(s.refused(&chain).is_none());
    // Without its admin CA the certificate does not verify.
    assert!(certs::verify_member(&chain[..1], std::slice::from_ref(&ca), t, certs::Usage::Server).is_err());
    // The identity of the device it names holds together, with the key.
    if let Ok(key) = STANDARD.decode(v["key"].as_str().unwrap()) {
        if crate::identity::public_key(&key).is_ok() {
            let id = Identity {
                id: certs::DeviceId::parse(v["device"].as_str().unwrap()).unwrap(),
                key,
                external: None,
                cert: leaf,
                issuer: Some(admin),
                group_ca: ca,
                roots: vec![],
            };
            id.check().unwrap();
        }
    }
}

/// A group handed over to a new root by a claim that took effect: the
/// cases of v2-records.json about it, as Go's TestGoRootVectors runs them.
#[test]
fn go_root() {
    v2_cases(&["claim waits and takes effect", "chain of claims", "settings delay"]);
}

/// A legacy group that cbb upgrade gave a root wrote records of version 1,
/// which no member takes: there is no migration (docs/records-v2.md).
#[test]
fn go_upgrade() {
    let group = "0123456789abcdef";
    for body in [
        format!(
            r#"{{"by":"{0}","device":"{0}","group":"{group}","key":"{1}","name":"pi","role":"full","time_ms":1,"type":"device","v":1}}"#,
            "a".repeat(32),
            STANDARD.encode([0u8; 32])
        ),
        format!(r#"{{"group":"{group}","root":"{}","time_ms":3,"type":"root","v":1}}"#, STANDARD.encode([1u8; 8])),
    ] {
        assert!(crate::authority::Body::parse(body.as_bytes()).is_err(), "{body}");
    }
}

/// Runs the cases of v2-records.json whose names start with one of the
/// prefixes through the record set of the core's entry point (group_add,
/// group_claim_times, group_view), as Go's checkV2Cases and the phone
/// kits do: each gives the case's state. Answers how many cases ran.
fn v2_cases(prefixes: &[&str]) -> usize {
    let call = |op: &str, args: Value| -> Value {
        let req = serde_json::json!({"abi": crate::api::ABI, "op": op, "args": args});
        let out: Value = serde_json::from_slice(&crate::api::call(&serde_json::to_vec(&req).unwrap())).unwrap();
        assert!(out.get("error").is_none(), "{op}: {out}");
        out["ok"].clone()
    };
    let v = vectors("v2-records.json");
    let mut n = 0;
    for case in v["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        if case["time_unknown"].as_bool().unwrap_or(false) || !prefixes.iter().any(|p| name.starts_with(p)) {
            continue;
        }
        let mut set =
            serde_json::json!({"group_ca": case["group_ca"], "group": case["group"], "now_ms": case["now_ms"]});
        let mut args = set.clone();
        args["records"] = case["records"].clone();
        set["file"] = call("group_add", args)["file"].clone();
        if let Some(times) = case.get("first_seen") {
            let mut args = set.clone();
            args["claim_times"] = times.clone();
            set["file"] = call("group_claim_times", args)["file"].clone();
        }
        let mut got = call("group_view", set)["state"].clone();
        let mut want: Value = serde_json::from_str(case["state"].as_str().unwrap()).unwrap();
        // The set does not keep the records it refuses, which the
        // evaluation of all of them lists as ignored.
        let ignored = |v: &mut Value| {
            v.as_object_mut().unwrap().remove("ignored").map_or_else(Vec::new, |i| i.as_array().unwrap().clone())
        };
        let (kept, all) = (ignored(&mut got), ignored(&mut want));
        assert!(kept.iter().all(|i| all.contains(i)), "{name}");
        assert_eq!(got, want, "{name}");
        n += 1;
    }
    assert!(n > 0, "no case of {prefixes:?}");
    n
}

/// The order of the group's hubs (docs/protocol.md section 11, "Several
/// hubs"), as Go's TestGoHubVectors writes it (v2-hubs.json).
#[test]
fn go_hubs() {
    let v = vectors("v2-hubs.json");
    let mut s = Records::new(&cert(&v["group_ca"]));
    let mut rs = records(&v["records"]);
    rs.reverse();
    let (_, errs) = s.add_all(&rs);
    assert!(errs.is_empty(), "{errs:?}");
    let want: Vec<String> =
        v["hub_order"].as_array().unwrap().iter().map(|d| d.as_str().unwrap().to_string()).collect();
    assert_eq!(want.len(), 4);
    assert_eq!(s.hub_order(), want);
}

/// What a computer's admin CA may do in a phone's group: the cases of
/// v2-records.json about powers, as Go's TestGoAdminVectors runs them.
#[test]
fn go_admins() {
    v2_cases(&["powers", "one record under two admin CAs", "two histories of an admin"]);
}

/// One body under two signers, and two histories of one signer: the
/// cases of v2-records.json about them.
#[test]
fn go_envelopes() {
    v2_cases(&["one record under two admin CAs", "two histories", "times at the ends"]);
}

/// Where a device's keys live, as Go's StoreOf reads a record's store.
#[test]
fn stores() {
    use crate::command::store_of;
    for (store, role, want) in [
        ("file", "full", "file"),
        ("hardware", "full", "hardware"),
        ("proven", "phone", "proven"),
        ("rootless", "full", "rootless"),
        ("", "phone", "hardware"),
        ("", "watch", "hardware"),
        ("", "full", "file"),
        ("disk", "lite", "file"),
    ] {
        assert_eq!(store_of(store, role), want, "{store:?} {role:?}");
    }
}

/// An admin phone that the root removed claims the group afterwards: the
/// claim counts for nothing (v2-records.json, as Go's TestRemovedAdminVectors).
#[test]
fn go_removed_admin() {
    v2_cases(&["removed admin's claim", "removed phone after a takeover", "claim after removal"]);
}

/// Admins that remove each other in order or crossed, and a root's
/// removal that cuts an admin off (v2-records.json, as Go's
/// TestRemovedAdminsVectors).
#[test]
fn go_removed_admins() {
    v2_cases(&[
        "admin removals in order",
        "admin removals crossed",
        "root removal cuts an admin",
        "chain of claims",
        "two claims",
    ]);
}

/// The root's own device after a takeover and a chain of claims
/// (v2-records.json).
#[test]
fn go_root_member() {
    v2_cases(&["removed phone after a takeover", "chain of claims"]);
}

/// What a device record and a removed admin's records decide
/// (v2-records.json, as Go's TestGoAuthorityVectors).
#[test]
fn go_authority() {
    v2_cases(&["basic", "powers", "removed admin's device", "ignored records"]);
}

/// An admin computer freezing another (v2-records.json, as Go's
/// TestGoFreezeVectors).
#[test]
fn go_freeze() {
    v2_cases(&["freeze and thaw", "freezes crossed"]);
}

/// Claims to take a group over that are disputed, void or early
/// (v2-records.json, as Go's TestGoTakeoverVectors).
#[test]
fn go_takeover() {
    v2_cases(&[
        "claim disputed",
        "claim while another waits",
        "claimed root signs early",
        "stranger's claim",
        "two histories of the root",
        "checkpoint",
        "times at the ends",
        "record of a later version",
        "device seal",
    ]);
}

/// A hello's device keeps only its valid fields.
#[test]
fn device_cleaned() {
    let good = wire::DeviceInfo {
        form: "board".into(),
        os_version: "Raspbian 13".into(),
        version: "0.5.0".into(),
        mac: "dc:a6:32:00:00:01".into(),
    };
    assert_eq!(good.cleaned(), good);
    let bad = wire::DeviceInfo {
        form: "toaster".into(),
        os_version: "9".repeat(33),
        version: "1\n2".into(),
        mac: "DC:A6:32:00:00:01".into(),
    };
    assert!(bad.cleaned().is_empty());
}

/// Commands for one member (docs/protocol.md, section 15), as Go's
/// TestGoCommandVectors writes them: who may send one, and when.
#[test]
fn go_commands() {
    let v = vectors("v2-commands.json");
    let mut s = Records::new(&cert(&v["group_ca"]));
    let (_, errs) = s.add_all(&records(&v["records"]));
    assert!(errs.is_empty(), "{errs:?}");
    let me = v["self"].as_str().unwrap();
    let now = v["now_ms"].as_i64().unwrap();
    let cs = v["commands"].as_array().unwrap();
    assert_eq!(cs.len(), 17);
    for c in cs {
        let r: Record = serde_json::from_value(c["command"].clone()).unwrap();
        let got = s.verify_command(&r, me, now);
        let name = c["name"].as_str().unwrap();
        assert_eq!(got.is_ok(), c["ok"].as_bool().unwrap(), "{name}: {got:?}");
        if let Ok(b) = got {
            assert_eq!(b.mode, c["mode"].as_str().unwrap_or(""), "{name}");
            let (sender, verified) = s.command_sender(&r, &b.by);
            assert_eq!(verified, c["verified"].as_bool().unwrap_or(false), "{name}");
            assert!(if verified { sender == b.by } else { sender.starts_with("key ") }, "{name}: {sender}");
            if b.kind == "paste" {
                assert!(b.enter && b.paste_kind == "text" && b.text.ends_with("\"done\"\n"), "{name}");
            }
        }
    }
}

/// Commands with their orders sealed to the receiver (docs/protocol.md,
/// section 15, "Sealed commands"), as Go's TestSealedCommandVectors writes
/// them: which ones the receiver takes as signed, and which of those open
/// with its secret.
#[test]
fn go_sealed_commands() {
    let v = vectors("go-sealed-commands.json");
    let s = Records::new(&cert(&v["group_ca"]));
    let me = v["self"].as_str().unwrap();
    let now = v["now_ms"].as_i64().unwrap();
    let secret = STANDARD.decode(v["secret"].as_str().unwrap()).unwrap();
    let cs = v["commands"].as_array().unwrap();
    assert_eq!(cs.len(), 10);
    for c in cs {
        let r: Record = serde_json::from_value(c["command"].clone()).unwrap();
        let name = c["name"].as_str().unwrap();
        let got = s.verify_command(&r, me, now);
        assert_eq!(got.is_ok(), c["ok"].as_bool().unwrap(), "{name}: {got:?}");
        let Ok(mut b) = got else { continue };
        let opened = b.open(&secret);
        assert_eq!(opened.is_ok(), c["opens"].as_bool().unwrap(), "{name}: {opened:?}");
        if opened.is_ok() {
            assert!(b.opened, "{name}");
            assert_eq!(b.mode, c["mode"].as_str().unwrap_or(""), "{name}");
            assert_eq!(b.text, c["text"].as_str().unwrap_or(""), "{name}");
        }
    }
}

/// A lite member's hello names the quick actions that are on there, and
/// leaves the field out when none is.
#[test]
fn hello_actions() {
    let h = crate::clip::Hello { wall: 1, current: None };
    let hello = |on: &[String], entries| {
        wire::hello(
            &h,
            String::new(),
            "lite",
            "pi",
            "linux",
            &wire::DeviceInfo::default(),
            None,
            "own",
            None,
            on,
            "file",
            None,
            entries,
            None,
        )
    };
    let on = ["reboot".to_string(), "restart".to_string()];
    let (_, body) = wire::decode_hello(hello(&on, (0, 0)).hello.as_ref()).unwrap();
    assert_eq!(body.actions, on);
    let v = hello(&[], (0, 0)).hello.unwrap();
    assert!(v.get("actions").is_none() && v.get("entries_seq").is_none() && v.get("entries_keys_seq").is_none());
    let (_, body) = wire::decode_hello(hello(&[], (3, 5)).hello.as_ref()).unwrap();
    assert_eq!((body.entries_keys_seq, body.entries_seq), (3, 5));
}

/// Quick action commands (docs/protocol.md, section 15), as Go's
/// TestGoActionVectors writes them: which ones a member takes, and the
/// signer each names, whose kind and keys the member's user may require.
#[test]
fn go_actions() {
    let v = vectors("v2-actions.json");
    let mut s = Records::new(&cert(&v["group_ca"]));
    let (_, errs) = s.add_all(&records(&v["records"]));
    assert!(errs.is_empty(), "{errs:?}");
    let me = v["self"].as_str().unwrap();
    let now = v["now_ms"].as_i64().unwrap();
    let cs = v["commands"].as_array().unwrap();
    assert_eq!(cs.len(), 6);
    for c in cs {
        let r: Record = serde_json::from_value(c["command"].clone()).unwrap();
        let got = s.verify_command(&r, me, now);
        let name = c["name"].as_str().unwrap();
        assert_eq!(got.is_ok(), c["ok"].as_bool().unwrap(), "{name}: {got:?}");
        let Ok(b) = got else { continue };
        assert_eq!(b.action, c["action"].as_str().unwrap_or(""), "{name}");
        let (d, root) = s.command_signer(&r);
        let want = &c["signer"];
        assert_eq!(root, want["root"].as_bool().unwrap_or(false), "{name}");
        assert_eq!(d.is_some(), want["found"].as_bool().unwrap_or(false), "{name}");
        if let Some(d) = d {
            assert_eq!(d.role, want["role"].as_str().unwrap(), "{name}");
            assert_eq!(d.store, want["store"].as_str().unwrap(), "{name}");
        }
    }
    for (n, ok) in [("lock", true), ("a1-b", true), ("1a", false), ("Lock", false), ("", false), ("a_b", false)] {
        assert_eq!(crate::command::valid_action_name(n), ok, "{n:?}");
    }
    assert!(crate::command::valid_action_name(&"a".repeat(32)) && !crate::command::valid_action_name(&"a".repeat(33)));
}

/// The signed files of a release (docs/protocol.md, section 16), as Go's
/// TestReleaseVectors writes them: which combinations a device takes.
#[test]
fn go_release() {
    use crate::release::{self, File, Seen};
    let v = vectors("go-release.json");
    let roots: Vec<Vec<u8>> = v["roots"].as_array().unwrap().iter().map(bytes).collect();
    let roots: Vec<&[u8]> = roots.iter().map(|r| r.as_slice()).collect();
    let name = v["channel"].as_str().unwrap();
    let now = v["now_ms"].as_i64().unwrap();
    let cases = v["vectors"].as_array().unwrap();
    assert_eq!(cases.len(), 33);
    for c in cases {
        let file = |k: &str| -> File { serde_json::from_value(c[k].clone()).unwrap() };
        let seen: Seen = serde_json::from_value(c["seen"].clone()).unwrap();
        let got = release::check(&file("keys"), &file("channel"), &file("release"), &roots, name, now, &seen);
        let label = c["name"].as_str().unwrap();
        assert_eq!(got.is_ok(), c["ok"].as_bool().unwrap(), "{label}: {:?}", got.as_ref().err().map(|e| e.message()));
        if let Ok((r, next)) = got {
            assert_eq!(r.version, c["version"].as_str().unwrap(), "{label}");
            assert_eq!(next.version, r.version, "{label}");
            assert!(r.direct("0.5.3") && !r.direct("0.3.9"), "{label}");
        }
    }
    use core::cmp::Ordering::*;
    for (a, b, want) in [
        ("0.10.0", "0.9.0", Greater),
        ("0.6.0", "0.6.0", Equal),
        ("0.6.0-rc.1", "0.6.0", Less),
        ("0.6.0-rc.2", "0.6.0-rc.10", Less),
        ("0.6.0-rc.1", "0.5.9", Greater),
        ("v0.6.0", "0.0.0", Less),
        ("0.06.0", "0.0.0", Less),
    ] {
        assert_eq!(release::compare(a, b), want, "{a} {b}");
    }
    for bad in ["0.6", "0.6.0-rc.0", "0.6.0-rc.01", "0.6.0-beta.1", "0.6.0.1", "1234567.0.0"] {
        assert!(release::parse_version(bad).is_none(), "{bad}");
    }
}

/// The signed entry points (docs/protocol.md, section 16, "Entry points"),
/// as Go's TestEntriesVectors writes them: which lists a device takes.
#[test]
fn go_entries() {
    use crate::release::{self, File, Seen};
    let v = vectors("go-entries.json");
    let roots: Vec<Vec<u8>> = v["roots"].as_array().unwrap().iter().map(bytes).collect();
    let roots: Vec<&[u8]> = roots.iter().map(|r| r.as_slice()).collect();
    let now = v["now_ms"].as_i64().unwrap();
    let cases = v["vectors"].as_array().unwrap();
    assert_eq!(cases.len(), 14);
    for c in cases {
        let file = |k: &str| -> File { serde_json::from_value(c[k].clone()).unwrap() };
        let seen: Seen = serde_json::from_value(c["seen"].clone()).unwrap();
        let got = release::check_entries(&file("keys"), &file("entries"), &roots, now, &seen);
        let label = c["name"].as_str().unwrap();
        assert_eq!(got.is_ok(), c["ok"].as_bool().unwrap(), "{label}: {:?}", got.as_ref().err().map(|e| e.message()));
        if let Ok((e, next)) = got {
            let want = c["seq"].as_u64().unwrap();
            assert_eq!((e.seq, next.entries_seq, next.entries_keys_seq, next.keys_seq), (want, want, 3, 3), "{label}");
        }
    }
}

/// The ZX Spectrum Next's files (docs/protocol.md, section 16, "The ZX
/// Spectrum Next's files"), as Go's TestZXNextVectors writes them: which
/// lists the Pi's cbb takes.
#[test]
fn go_zxnext() {
    use crate::release::{self, File};
    let v = vectors("go-zxnext.json");
    let roots: Vec<Vec<u8>> = v["roots"].as_array().unwrap().iter().map(bytes).collect();
    let roots: Vec<&[u8]> = roots.iter().map(|r| r.as_slice()).collect();
    let cases = v["vectors"].as_array().unwrap();
    assert_eq!(cases.len(), 18);
    for c in cases {
        let file = |k: &str| -> File { serde_json::from_value(c[k].clone()).unwrap() };
        let got = release::check_zxnext(
            &file("keys"),
            &file("list"),
            &roots,
            c["now_ms"].as_i64().unwrap(),
            c["installed"].as_str().unwrap(),
        );
        let label = c["name"].as_str().unwrap();
        assert_eq!(got.is_ok(), c["ok"].as_bool().unwrap(), "{label}: {:?}", got.as_ref().err().map(|e| e.message()));
        if let Ok(z) = got {
            assert_eq!(z.files.iter().find(|f| f.name == "cbb").map(|f| f.size), Some(4000), "{label}");
        }
    }
}

/// The server credentials (docs/protocol.md, section 18), as Go's
/// TestGoCredentialVectors writes them: what the records say the
/// credentials list, the signatures and types, and which sets a server
/// takes.
#[test]
fn go_credentials() {
    use crate::credential::{self, Credential, HUBS, MEMBERS, PERIOD, SERVER};
    let v = vectors("v2-credentials.json");
    let ca = cert(&v["group_ca"]);
    let mut s = Records::new(&ca);
    let (_, errs) = s.add_all(&records(&v["records"]));
    assert!(errs.is_empty(), "{errs:?}");
    let hashes = |k: &str| -> Vec<KeyHash> {
        v["lists"][k].as_array().unwrap().iter().map(|h| bytes(h).try_into().unwrap()).collect()
    };
    let l = credential::lists(&s);
    assert_eq!(l.hubs, hashes("Hubs"));
    assert_eq!(l.admins, hashes("Admins"));
    assert_eq!(l.members, hashes("Members"));

    let cred = |v: &Value| -> Credential { serde_json::from_value(v.clone()).unwrap() };
    let tag = certs::tag(&ca);
    let period = cred(&v["period"]);
    let p = period.open().unwrap();
    assert_eq!((p.kind.as_str(), p.group.as_str()), (PERIOD, tag.as_str()));
    // The group's root signed the period.
    assert_eq!(period.key, ca.spki);
    for c in v["servers"].as_array().unwrap() {
        let c = cred(c);
        let b = c.open().unwrap();
        assert_eq!((b.kind.as_str(), b.group.as_str(), b.tag.as_str()), (SERVER, tag.as_str(), p.tag.as_str()));
        assert!(s.devices().iter().any(|d| d.keys.contains(&c.signer())), "a server key that no member signed");
    }
    let (hubs, members) = (cred(&v["hubs"]), cred(&v["members"]));
    let hb = hubs.open().unwrap();
    assert_eq!((hb.kind.as_str(), hb.group.as_str()), (HUBS, p.tag.as_str()));
    assert_eq!(hubs.key, p.key);
    assert_eq!(credential::pseudonym(&hb.hubs[0]), v["pseudonym"].as_str().unwrap());
    // Padded to 4, 8, 16 or more.
    assert!(hb.hubs.len() >= l.hubs.len() && hb.hubs.len().is_power_of_two() && hb.hubs.len() >= 4);
    assert_eq!(members.open().unwrap().kind, MEMBERS);

    let now = v["now_ms"].as_i64().unwrap();
    let got = credential::check_presented(&[hubs.clone(), members.clone(), period.clone()], now).unwrap();
    assert_eq!(got.tag, p.tag);
    assert!(got.members.is_some() && got.period.is_some());
    assert!(credential::check_presented(std::slice::from_ref(&hubs), p.expires_ms).is_err(), "expired");
    for b in v["bad"].as_array().unwrap() {
        let set: Vec<Credential> = b["set"].as_array().unwrap().iter().map(cred).collect();
        assert!(credential::check_presented(&set, now).is_err(), "{}: taken", b["name"]);
    }
    // A body changed after signing does not verify.
    let mut forged = hubs.clone();
    forged.body[10] ^= 1;
    assert!(forged.open().is_err());
    // Encoding again gives the same JSON as Go's.
    assert_eq!(serde_json::to_value(&hubs).unwrap(), v["hubs"]);
}

/// What a watch's admin key may do (docs/protocol.md, section 10, "Watches"),
/// as Go's TestGoWatchVectors writes it: in a phone's group it freezes an
/// admin computer and removes an ordinary device, and nothing more; an
/// admin computer freezes it; in a group whose root is a computer it does
/// not take the group over.
#[test]
fn go_watch() {
    let v = vectors("v2-watch.json");
    let cases = v["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 3);
    for c in cases {
        let name = c["name"].as_str().unwrap();
        let mut s = Records::new(&cert(&c["group_ca"]));
        let mut rs = records(&c["records"]);
        rs.reverse();
        let (_, errs) = s.add_all(&rs);
        assert_eq!(errs.len(), c["dropped"].as_u64().unwrap_or(0) as usize, "{name}: {errs:?}");
        let got: Vec<(String, String, String, bool)> =
            s.devices().into_iter().map(|d| (d.id, d.name, d.role, d.admin)).collect();
        let want: Vec<(String, String, String, bool)> = c["devices"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| {
                (
                    d["id"].as_str().unwrap().to_string(),
                    d["name"].as_str().unwrap().to_string(),
                    d["role"].as_str().unwrap().to_string(),
                    d["admin"].as_bool().unwrap(),
                )
            })
            .collect();
        assert_eq!(got, want, "{name}");
        for k in c["keys"].as_array().unwrap() {
            let key: KeyHash = bytes(&k["key"]).try_into().unwrap();
            let what = k["name"].as_str().unwrap();
            assert_eq!(s.revoked(&key), k["revoked"].as_bool().unwrap(), "{name}: {what} revoked");
            assert_eq!(s.frozen(&key), k["frozen"].as_bool().unwrap(), "{name}: {what} frozen");
            assert_eq!(s.watch(&key), k["watch"].as_bool().unwrap(), "{name}: {what} watch");
        }
        for ch in c["chains"].as_array().into_iter().flatten() {
            let chain: Vec<Cert> = ch["chain"].as_array().unwrap().iter().map(cert).collect();
            assert_eq!(s.refused(&chain).is_some(), ch["refused"].as_bool().unwrap(), "{name}: {}", ch["name"]);
        }
        assert!(s.roots().is_empty(), "{name}");
        let hubs: Vec<String> = c["hubs"].as_array().unwrap().iter().map(|h| h.as_str().unwrap().to_string()).collect();
        assert_eq!(s.hub_order(), hubs, "{name}");
        for d in s.devices() {
            if d.role == "watch" {
                assert!(!s.may_host(&d.id), "{name}");
            }
        }
        let me = c["self"].as_str().unwrap_or("");
        let now = c["now_ms"].as_i64().unwrap_or(0);
        for cmd in c["commands"].as_array().into_iter().flatten() {
            let r: Record = serde_json::from_value(cmd["command"].clone()).unwrap();
            let got = s.verify_command(&r, me, now);
            assert_eq!(got.is_ok(), cmd["ok"].as_bool().unwrap(), "{name}: {}: {got:?}", cmd["name"]);
        }
        assert_eq!(s.digest(), c["digest"].as_str().unwrap(), "{name}");
    }
}

/// The strict form of signed bodies (strict.json): the lite member takes
/// exactly the commands and manifests the Go member does.
#[test]
fn strict() {
    let v = vectors("strict.json");
    let cases = |kind: &str| {
        v[kind]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| (c["name"].as_str().unwrap().to_string(), bytes(&c["body"]), c["valid"].as_bool().unwrap()))
            .collect::<Vec<_>>()
    };
    // The records of strict.json are of version 1, which the core no longer
    // reads; strict-generated-*.json have those of version 2.
    assert!(!cases("records").is_empty());
    for (name, body, valid) in cases("commands") {
        let got = crate::command::Command::parse(&body);
        assert_eq!(got.is_ok(), valid, "command {name:?}: {:?}", got.err());
    }
    for (name, body, valid) in cases("manifests") {
        let got = crate::media::Manifest::parse(&body);
        assert_eq!(got.is_ok(), valid, "manifest {name:?}: {:?}", got.err());
    }
}

/// The vectors the tables of docs/protocol.md give (strict-generated-*.json,
/// as Go's TestStrictGenerated writes them): the lite member takes exactly
/// the bodies the tables take, and says which row it reads otherwise.
#[test]
fn strict_generated() {
    let mut wrong = Vec::new();
    let mut n = [0; 3];
    for i in 1.. {
        let name = format!("strict-generated-{i}.json");
        if !PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../testdata/interop").join(&name).exists() {
            break;
        }
        let v = vectors(&name);
        for (j, kind) in ["records", "commands", "manifests"].iter().enumerate() {
            n[j] += v[kind].as_array().unwrap().len();
        }
        wrong.extend(strict_wrong(&v));
    }
    assert!(n.iter().all(|&k| k > 0), "no vectors of a kind: {n:?}");
    assert!(wrong.is_empty(), "{} vectors read otherwise:\n{}", wrong.len(), wrong.join("\n"));
}

/// The mutant vectors (strict-mutants-*.json): valid bodies changed byte by
/// byte, each with the verdict of the tables of docs/protocol.md. They hold
/// record bodies of version 1 only, which the core refuses.
#[test]
fn strict_mutants() {
    let mut wrong = Vec::new();
    let mut n = 0;
    for i in 1.. {
        let name = format!("strict-mutants-{i}.json");
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../testdata/interop").join(&name);
        if !path.exists() {
            break;
        }
        let v = vectors(&name);
        n += 1;
        wrong.extend(strict_wrong(&v));
    }
    assert!(n > 0, "no mutant files");
    assert!(wrong.is_empty(), "{} vectors read otherwise:\n{}", wrong.len(), wrong.join("\n"));
}

/// strict_wrong returns the vectors of a file in the form of
/// strict-generated-*.json that the lite member reads otherwise.
fn strict_wrong(v: &Value) -> Vec<String> {
    let mut wrong = Vec::new();
    for kind in ["records", "commands", "manifests"] {
        let Some(cases) = v[kind].as_array() else { continue };
        for c in cases {
            let mut body = bytes(&c["body"]);
            if let Some(pad) = c["pad"].as_u64() {
                let at = c["pad_at"].as_u64().unwrap() as usize;
                body.splice(at..at, std::iter::repeat_n(b'a', pad as usize));
            }
            let got = match kind {
                "records" => crate::authority::Body::parse(&body).map(|_| ()).map_err(|e| e.to_string()),
                "commands" => crate::command::Command::parse(&body).map(|_| ()).map_err(|e| e.to_string()),
                _ => crate::media::Manifest::parse(&body).map(|_| ()).map_err(|e| e.to_string()),
            };
            // The mutants' records are of version 1, whose verdicts were
            // those of its tables: every member refuses them now.
            let valid = c["valid"].as_bool().unwrap() && !(kind == "records" && c["rule"] == "mutant");
            if got.is_ok() != valid {
                wrong.push(format!(
                    "{kind} {:?} ({}): valid {}, got {got:?}",
                    c["name"].as_str().unwrap(),
                    c["rule"].as_str().unwrap(),
                    c["valid"]
                ));
            }
        }
    }
    wrong
}

/// The server credentials and release files of strict-files.json, which
/// Go's TestStrictGeneratedFiles writes from the tables of docs/protocol.md.
/// The lite member reads no attest-status.json, the only kind it leaves to
/// the others.
#[test]
fn strict_files() {
    let v = vectors("strict-files.json");
    let mut wrong = Vec::new();
    for section in ["credentials", "releases"] {
        let cases = v[section].as_array().unwrap();
        assert!(!cases.is_empty(), "no {section}");
        for c in cases {
            let mut body = bytes(&c["body"]);
            if let Some(pad) = c["pad"].as_u64() {
                let at = c["pad_at"].as_u64().unwrap() as usize;
                body.splice(at..at, std::iter::repeat_n(b'a', pad as usize));
            }
            let kind = c["kind"].as_str().unwrap();
            let got = match (section, kind) {
                ("credentials", _) => crate::credential::Body::parse(&body).map(|_| ()).map_err(|e| e.to_string()),
                (_, "attest-status") => continue,
                _ if body.len() > crate::release::MAX_BODY => Err("too large".to_string()),
                (_, "keys") => crate::release::decode_keys(&body).map(|_| ()).map_err(|e| e.to_string()),
                (_, "release") => crate::release::decode_release(&body).map(|_| ()).map_err(|e| e.to_string()),
                (_, "channel") => crate::release::decode_channel(&body).map(|_| ()).map_err(|e| e.to_string()),
                _ => panic!("unknown kind {kind}"),
            };
            if got.is_ok() != c["valid"].as_bool().unwrap() {
                wrong.push(format!(
                    "{section} {:?} ({}): valid {}, got {got:?}",
                    c["name"].as_str().unwrap(),
                    c["rule"].as_str().unwrap(),
                    c["valid"]
                ));
            }
        }
    }
    assert!(wrong.is_empty(), "{} vectors read otherwise:\n{}", wrong.len(), wrong.join("\n"));
}

/// The timestamps a clock took do not move how far ahead it takes the next
/// one (hlc-ahead.json, as Go's TestAheadVectors writes it).
#[test]
fn hlc_ahead() {
    let v = vectors("hlc-ahead.json");
    assert_eq!(v["max_ahead"].as_i64(), Some(crate::hlc::MAX_AHEAD));
    let now = v["now"].as_i64().unwrap();
    let c = crate::hlc::Clock::new(Box::new(move || now), Timestamp::default(), None);
    for w in v["accepted"].as_array().unwrap() {
        let ts = Timestamp { wall: w.as_i64().unwrap(), logical: 0 };
        assert!(!c.ahead(ts), "{w} refused");
        c.observe(ts);
    }
    let refused = Timestamp { wall: v["refused"].as_i64().unwrap(), logical: 0 };
    assert!(c.ahead(refused), "taken after a chain of timestamps ahead");
}

/// The names of media-names.json, as Go's TestNameVectors writes them:
/// the lite core takes the names Go takes in a manifest, and writes the
/// device names of Windows under the names Go gives them.
#[test]
fn media_names() {
    let v = vectors("media-names.json");
    let cases = v.as_array().unwrap();
    assert!(!cases.is_empty());
    for c in cases {
        let name = c["name"].as_str().unwrap();
        let valid = c["valid"].as_bool().unwrap();
        assert_eq!(crate::media::check_name(name).is_ok(), valid, "{name:?}");
        if valid {
            assert_eq!(crate::media::save_name(name), c["save"].as_str().unwrap(), "{name:?}");
        }
    }
}

/// The stop of the exchange (docs/protocol.md, section 10, "Stopping the
/// exchange") on the cases of v2-records.json, as Go's TestStopExchange: a
/// full stop stops every device and every secret, a stop of secrets every
/// secret but no connection, and the devices the state names get nothing
/// or no secrets.
#[test]
fn stop_exchange() {
    let v = vectors("v2-records.json");
    let mut seen = std::collections::BTreeSet::new();
    for case in v["cases"].as_array().unwrap() {
        if case["time_unknown"].as_bool().unwrap_or(false) {
            continue;
        }
        let want: Value = serde_json::from_str(case["state"].as_str().unwrap()).unwrap();
        let mut s = crate::group::Records::new(&cert(&case["group_ca"]));
        let now = case["now_ms"].as_i64().unwrap();
        s.set_tag(case["group"].as_str().unwrap());
        s.set_clock(move || now);
        let _ = s.add_all(&records(&case["records"]));
        if let Some(times) = case.get("first_seen") {
            s.take_claim_times(&serde_json::from_value::<Vec<crate::group::ClaimTime>>(times.clone()).unwrap());
        }
        let stop = want["stop"].as_str().unwrap();
        if s.stop() != stop {
            continue; // a record the set itself leaves out; v2_cases covers it
        }
        seen.insert(stop.to_string());
        let list = |k: &str| -> Vec<String> {
            want[k].as_array().map(|a| a.iter().map(|d| d.as_str().unwrap().to_string()).collect()).unwrap_or_default()
        };
        let (nothing, no_secrets) = (list("nothing_to"), list("no_secrets_to"));
        let mut devs = vec!["00000000000000000000000000000000".to_string()];
        devs.extend(nothing.iter().chain(&no_secrets).cloned());
        devs.extend(
            want["devices"].as_array().into_iter().flatten().map(|d| d["device"].as_str().unwrap().to_string()),
        );
        for d in &devs {
            let n = nothing.contains(d);
            assert_eq!(s.stopped(d), stop == "full" || n, "{}: stopped({d})", case["name"]);
            assert_eq!(
                s.no_secrets_to(d),
                stop != "none" || n || no_secrets.contains(d),
                "{}: no_secrets_to({d})",
                case["name"]
            );
        }
    }
    for stop in ["none", "secrets", "full"] {
        assert!(seen.contains(stop), "no case with stop {stop}");
    }
}
