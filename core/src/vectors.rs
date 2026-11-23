// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The cross-implementation test vectors in testdata/interop, which the Go
//! tests write and the phone kit reads too: a member in Rust must decode,
//! encode and decide what they say as the Go member does.

use std::path::PathBuf;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::Value;

use crate::certs::{self, Cert};
use crate::hlc::Timestamp;
use crate::wire;

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

/// A hello's device keeps only its valid fields.
#[test]
fn device_cleaned() {
    let good = wire::DeviceInfo {
        form: "board".into(),
        os_version: "Raspbian 13".into(),
        version: "0.5.0".into(),
        mac: "dc:a6:32:00:00:01".into(),
        archive: "cbb-linux-arm64.tar.gz".into(),
    };
    assert_eq!(good.cleaned(), good);
    let bad = wire::DeviceInfo {
        form: "toaster".into(),
        os_version: "9".repeat(33),
        version: "1\n2".into(),
        mac: "DC:A6:32:00:00:01".into(),
        archive: "cbb-linux-arm64.exe".into(),
    };
    assert!(bad.cleaned().is_empty());
}

/// The signed files of a release (docs/protocol.md, section 16), as Go's
/// TestReleaseVectors writes them: which combinations a device takes.
#[test]
fn go_release() {
    use crate::release::{self, File, Seen};
    let v = vectors("go-release.json");
    let roots: Vec<release::Key> = serde_json::from_value(v["roots"].clone()).unwrap();
    let name = v["channel"].as_str().unwrap();
    let now = v["now_ms"].as_i64().unwrap();
    let cases = v["vectors"].as_array().unwrap();
    assert_eq!(cases.len(), 53);
    // Every reader of release files reads up to the same sizes.
    assert_eq!(v["max_file"].as_u64(), Some(release::MAX_FILE as u64));
    assert_eq!(v["max_body"].as_u64(), Some(release::MAX_BODY as u64));
    // A release.json as it comes, under one keys.json and channel file
    // (go-release-envelopes.json): an envelope read otherwise than Go reads
    // it refuses.
    let ev = vectors("go-release-envelopes.json");
    let envelopes = ev["envelopes"].as_array().unwrap();
    assert_eq!(envelopes.len(), 61);
    let env_roots: Vec<release::Key> = serde_json::from_value(ev["roots"].clone()).unwrap();
    let keys: File = serde_json::from_value(ev["keys"].clone()).unwrap();
    let channel: File = serde_json::from_value(ev["channel_file"].clone()).unwrap();
    for e in envelopes {
        let label = e["name"].as_str().unwrap();
        let raw = crate::certs::b64::decode_str(e["release"].as_str().unwrap()).unwrap();
        let taken = File::parse(&raw).map_err(|e| alloc::format!("{e}")).and_then(|r| {
            release::check(
                &keys,
                &channel,
                &r,
                &env_roots,
                ev["channel"].as_str().unwrap(),
                ev["now_ms"].as_i64().unwrap(),
                &Seen::default(),
            )
            .map_err(|e| alloc::string::String::from(e.message()))
        });
        assert_eq!(taken.is_ok(), e["ok"].as_bool().unwrap(), "envelope {label}: {:?}", taken.err());
    }
    for c in cases {
        // Each case names its files by their index in files.
        let file =
            |k: &str| -> File { serde_json::from_value(v["files"][c[k].as_u64().unwrap() as usize].clone()).unwrap() };
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
    let roots: Vec<release::Key> = serde_json::from_value(v["roots"].clone()).unwrap();
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

/// The ZX Spectrum Next's files (docs/protocol.md, section 16, "Where the
/// files are"), as Go's TestZXNextVectors writes them: which
/// lists the Pi's cbb takes.
#[test]
fn go_zxnext() {
    use crate::release::{self, File};
    let v = vectors("go-zxnext.json");
    let roots: Vec<release::Key> = serde_json::from_value(v["roots"].clone()).unwrap();
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

/// The strict form of manifests (strict.json): the core takes exactly
/// the manifests the Go member does.
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
    for (name, body, valid) in cases("manifests") {
        let got = crate::media::Manifest::parse(&body);
        assert_eq!(got.is_ok(), valid, "manifest {name:?}: {:?}", got.err());
    }
}

/// The vectors the manifest table of docs/protocol.md gives
/// (strict-generated-*.json): the core takes exactly the bodies the table
/// takes, and says which row it reads otherwise.
#[test]
fn strict_generated() {
    let mut wrong = Vec::new();
    let mut n = 0;
    for i in 1.. {
        let name = format!("strict-generated-{i}.json");
        if !PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../testdata/interop").join(&name).exists() {
            break;
        }
        let v = vectors(&name);
        n += v["manifests"].as_array().unwrap().len();
        wrong.extend(strict_wrong(&v));
    }
    assert!(n > 0, "no manifest vectors");
    assert!(wrong.is_empty(), "{} vectors read otherwise:\n{}", wrong.len(), wrong.join("\n"));
}

/// strict_wrong returns the vectors of a file in the form of
/// strict-generated-*.json that the core reads otherwise.
fn strict_wrong(v: &Value) -> Vec<String> {
    let mut wrong = Vec::new();
    if let Some(cases) = v["manifests"].as_array() {
        for c in cases {
            let mut body = bytes(&c["body"]);
            if let Some(pad) = c["pad"].as_u64() {
                let at = c["pad_at"].as_u64().unwrap() as usize;
                body.splice(at..at, std::iter::repeat_n(b'a', pad as usize));
            }
            let got = crate::media::Manifest::parse(&body).map(|_| ()).map_err(|e| e.to_string());
            let valid = c["valid"].as_bool().unwrap();
            if got.is_ok() != valid {
                wrong.push(format!(
                    "manifest {:?} ({}): valid {}, got {got:?}",
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
#[test]
fn strict_files() {
    let v = vectors("strict-files.json");
    let mut wrong = Vec::new();
    for section in ["releases"] {
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
                _ if body.len() > crate::release::MAX_BODY => Err("too large".to_string()),
                (_, "keys") => crate::release::decode_keys(&body).map(|_| ()).map_err(|e| e.to_string()),
                (_, "release") => crate::release::decode_release(&body).map(|_| ()).map_err(|e| e.to_string()),
                (_, "channel") => crate::release::decode_channel(&body).map(|_| ()).map_err(|e| e.to_string()),
                (_, "attest-status") => crate::release::decode_status(&body).map(|_| ()).map_err(|e| e.to_string()),
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
/// the core takes the names Go takes in a manifest, and writes the
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
        assert_eq!(crate::media::clean_name(name), c["clean"].as_str().unwrap(), "{name:?}");
    }
    // The same as Go's TestCleanName and the kits' tests.
    for (given, want) in [
        ("x".repeat(800), "x".repeat(765)),
        (format!("CON.{}.x", "a".repeat(759)), format!("CON_.{}", "a".repeat(759))),
        (format!("{}.", "a".repeat(764)), "a".repeat(764)),
    ] {
        assert_eq!(crate::media::clean_name(&given), want, "{given:?}");
    }
}

/// The SLH-DSA verifier against NIST's vectors for SLH-DSA-SHA2-128s
/// (ACVP, external interface, pure, with a context), so that it answers
/// as the standard and not only as the Go library that signs the other
/// vectors.
#[test]
fn nist_slh_dsa() {
    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
    }
    let v = vectors("nist-slh-dsa-sha2-128s.json");
    let cases = v["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 17);
    for c in cases {
        let f = |k: &str| unhex(c[k].as_str().unwrap());
        let got = crate::slhdsa::verify(&f("pk"), &f("msg"), &f("sig"), &f("ctx"));
        assert_eq!(got, c["pass"].as_bool().unwrap(), "{} ({})", c["id"], c["reason"]);
    }
}
