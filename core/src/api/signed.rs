// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The entry point's call for the signed bodies that are not records
//! (docs/core-api.md, "Signed bodies"): server credentials, release files
//! and manifests. Go and the phone kits read each through
//! the core, so that every program takes exactly the same bodies.

use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::{Code, Refusal, bad_args, json, refuse};
use crate::certs::b64;
use crate::error::{Error, Result};

/// The arguments of `parse_body`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ParseArgs {
    kind: String,
    #[serde(with = "b64")]
    body: Vec<u8>,
}

/// The kinds of body `parse_body` reads.
pub const KINDS: [&str; 8] =
    ["credential", "keys", "release", "channel", "attest-status", "entries", "zxnext", "manifest"];

/// Reads a body of the kind and gives it back as its value.
fn read(kind: &str, body: &[u8]) -> Result<Value> {
    fn value<T: Serialize>(t: T) -> Result<Value> {
        serde_json::to_value(t).map_err(|e| Error::with("The body could not be written back.", e))
    }
    // The release files carry their body inside an envelope of at most
    // this size, as Go's and the kits' readers check first.
    let release = matches!(kind, "keys" | "release" | "channel" | "attest-status" | "entries" | "zxnext");
    if release && body.len() > crate::release::MAX_BODY {
        return Err(Error::msg("The file is too large."));
    }
    match kind {
        "keys" => value(crate::release::decode_keys(body)?),
        "release" => value(crate::release::decode_release(body)?),
        "channel" => value(crate::release::decode_channel(body)?),
        "attest-status" => value(crate::release::decode_status(body)?),
        "entries" => value(crate::release::decode_entries(body)?),
        "zxnext" => value(crate::release::decode_zxnext(body)?),
        "manifest" => value(crate::media::Manifest::parse(body)?),
        _ => Err(Error::msg(alloc::format!("The core reads no body of the kind {kind:?}."))),
    }
}

/// `parse_body`: a signed body of a kind other than a record, checked as
/// every program checks it (the strict form, each field against its row),
/// and given back as `{"kind": kind, "value": the body's fields}`.
fn parse_body(a: ParseArgs) -> core::result::Result<Vec<u8>, Refusal> {
    if !KINDS.contains(&a.kind.as_str()) {
        return Err(refuse(
            Code::Request,
            Error::msg(alloc::format!("The core reads no body of the kind {:?}.", a.kind)),
        ));
    }
    let v = read(&a.kind, &a.body).map_err(|e| refuse(Code::Signed, e))?;
    let mut m = Map::new();
    m.insert("kind".into(), Value::String(String::from(a.kind.as_str())));
    m.insert("value".into(), v);
    Ok(json(Value::Object(m)))
}

/// The release files of one check, each as the device fetched it: its
/// bytes in base64, read here as every reader reads them (File::parse),
/// so that a caller decodes nothing of a release file.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseArgs {
    #[serde(default, with = "b64::opt")]
    keys: Option<Vec<u8>>,
    #[serde(default, with = "b64::opt")]
    channel: Option<Vec<u8>>,
    #[serde(default, with = "b64::opt")]
    release: Option<Vec<u8>>,
    #[serde(default, with = "b64::opt")]
    status: Option<Vec<u8>>,
    #[serde(default, with = "b64::opt")]
    entries: Option<Vec<u8>>,
    /// For `release_check_entries` in place of keys and entries: the
    /// signed entry points as members pass them, `{"keys": keys.json,
    /// "entries": entries.json}`, as received.
    #[serde(default, with = "b64::opt")]
    set: Option<Vec<u8>>,
    /// The channel's name, for `release_check`.
    #[serde(default)]
    name: String,
    /// Root keys other than the pinned ones, for tests and drills; the
    /// pinned roots (release::ROOTS_PEM) when absent.
    #[serde(default)]
    roots: Option<Vec<crate::release::Key>>,
    now_ms: i64,
    #[serde(default)]
    seen: crate::release::Seen,
}

impl ReleaseArgs {
    fn roots(&self) -> Vec<crate::release::Key> {
        self.roots.clone().unwrap_or_else(crate::release::pinned_roots)
    }
}

/// Reads the file `what` of a check from its bytes; a file that does not
/// read is refused as a file that does not verify.
fn file(what: &str, b: &Option<Vec<u8>>) -> core::result::Result<crate::release::File, Refusal> {
    let b = b.as_ref().ok_or_else(|| missing(what))?;
    crate::release::File::parse(b)
        .map_err(|e| refuse(Code::Signed, Error::msg(alloc::format!("{what}: {}", e.message()))))
}

/// Reads the signed entry points as members pass them: in the strict form
/// of signed bodies, each file read from its own bytes.
fn entries_set(b: &[u8]) -> core::result::Result<(crate::release::File, crate::release::File), Refusal> {
    #[derive(Deserialize)]
    struct Set {
        keys: alloc::boxed::Box<serde_json::value::RawValue>,
        entries: alloc::boxed::Box<serde_json::value::RawValue>,
    }
    let bad = |e: Error| refuse(Code::Signed, e);
    if b.len() > 2 * crate::release::MAX_FILE + 64 {
        return Err(bad(Error::msg("the entry points are too large")));
    }
    crate::strict::check(b, &["keys", "entries"]).map_err(bad)?;
    let s: Set = serde_json::from_slice(b).map_err(|e| bad(Error::with("the entry points do not read", e)))?;
    let read = |what: &str, r: &serde_json::value::RawValue| {
        crate::release::File::parse(r.get().as_bytes())
            .map_err(|e| bad(Error::msg(alloc::format!("{what}: {}", e.message()))))
    };
    Ok((read("keys", &s.keys)?, read("entries", &s.entries)?))
}

fn missing(what: &str) -> Refusal {
    refuse(Code::Request, Error::msg(alloc::format!("The request has no {what}.")))
}

/// `release_check`, `release_check_status` and `release_check_entries`:
/// release files checked as the Rust cbb checks them (docs/protocol.md,
/// section 16): keys.json under the roots, the file under the keys it
/// certifies, both signatures of each, the expiries and that nothing is
/// older than `seen`. The answer is `{"value": the file's body, "seen":
/// the Seen to keep}`.
fn release_check(op: &str, a: ReleaseArgs) -> core::result::Result<Vec<u8>, Refusal> {
    use crate::release;
    fn answer<T: Serialize>(value: T, seen: release::Seen) -> core::result::Result<Vec<u8>, Refusal> {
        let mut m = Map::new();
        m.insert("value".into(), serde_json::to_value(value).unwrap_or_default());
        m.insert("seen".into(), serde_json::to_value(seen).unwrap_or_default());
        Ok(json(Value::Object(m)))
    }
    let roots = a.roots();
    let signed = |e: Error| refuse(Code::Signed, e);
    match op {
        "release_check_status" => {
            let (keys, status) = (file("keys", &a.keys)?, file("status", &a.status)?);
            let (st, seen) = release::check_status(&keys, &status, &roots, a.now_ms, &a.seen).map_err(signed)?;
            answer(st, seen)
        }
        "release_check_entries" => {
            let (keys, entries) = match &a.set {
                Some(set) if a.keys.is_none() && a.entries.is_none() => entries_set(set)?,
                Some(_) => return Err(refuse(Code::Request, Error::msg("The request has a set and its files."))),
                None => (file("keys", &a.keys)?, file("entries", &a.entries)?),
            };
            let (e, seen) = release::check_entries(&keys, &entries, &roots, a.now_ms, &a.seen).map_err(signed)?;
            answer(e, seen)
        }
        _ => {
            let (keys, channel, rel) =
                (file("keys", &a.keys)?, file("channel", &a.channel)?, file("release", &a.release)?);
            let (r, seen) =
                release::check(&keys, &channel, &rel, &roots, &a.name, a.now_ms, &a.seen).map_err(signed)?;
            answer(r, seen)
        }
    }
}

/// The arguments of `release_named`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NamedArgs {
    #[serde(with = "b64")]
    channel: Vec<u8>,
}

/// `release_named`: the release a channel file names, read before it is
/// checked, so that a device knows which release.json to fetch; the
/// channel file is read as every reader reads it, its signatures are not
/// checked here (`release_check` then checks both files). `{"release":
/// "X.Y.Z"}`.
fn release_named(a: NamedArgs) -> core::result::Result<Vec<u8>, Refusal> {
    let signed = |e: Error| refuse(Code::Signed, e);
    let f = crate::release::File::parse(&a.channel).map_err(signed)?;
    let c = crate::release::decode_channel(&f.body).map_err(signed)?;
    let mut m = Map::new();
    m.insert("release".into(), Value::String(c.release));
    Ok(json(Value::Object(m)))
}

/// Runs a call over a signed body; None for an op that is not one.
pub(super) fn dispatch(op: &str, args: &Value) -> Option<core::result::Result<Vec<u8>, Refusal>> {
    Some(match op {
        "parse_body" => serde_json::from_value(args.clone()).map_err(bad_args).and_then(parse_body),
        "release_named" => serde_json::from_value(args.clone()).map_err(bad_args).and_then(release_named),
        "release_check" | "release_check_status" | "release_check_entries" => {
            serde_json::from_value(args.clone()).map_err(bad_args).and_then(|a| release_check(op, a))
        }
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use alloc::format;
    use alloc::string::ToString;
    use alloc::vec;

    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use serde_json::Value;

    use super::super::call;
    use super::KINDS;

    fn ask(kind: &str, body: &[u8]) -> Value {
        let req =
            format!(r#"{{"abi":1,"op":"parse_body","args":{{"kind":"{kind}","body":"{}"}}}}"#, STANDARD.encode(body));
        serde_json::from_slice(&call(req.as_bytes())).unwrap()
    }

    fn vectors(name: &str) -> Value {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../testdata/interop").join(name);
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
    }

    fn bytes(v: &Value) -> alloc::vec::Vec<u8> {
        STANDARD.decode(v.as_str().unwrap()).unwrap()
    }

    /// Each case of the strict vectors of these kinds through the call.
    #[test]
    fn strict_vectors() {
        let mut wrong = vec![];
        let mut n = 0;
        let mut check = |kind: &str, c: &Value| {
            let mut body = bytes(&c["body"]);
            if let Some(pad) = c["pad"].as_u64() {
                let at = c["pad_at"].as_u64().unwrap() as usize;
                body.splice(at..at, std::iter::repeat_n(b'a', pad as usize));
            }
            let got = ask(kind, &body);
            let taken = got.get("ok").is_some();
            if !taken {
                assert_eq!(got["error"]["name"], "signed", "{got}");
            }
            n += 1;
            if taken != c["valid"].as_bool().unwrap() {
                wrong.push(format!("{kind} {}: valid {}, got {got}", c["name"], c["valid"]));
            }
        };
        let exists = |f: &String| {
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../testdata/interop").join(f).exists()
        };
        let mut files = vec!["strict.json".to_string()];
        files.extend((1..).map(|i| format!("strict-generated-{i}.json")).take_while(exists));
        for f in &files {
            let v = vectors(f);
            for c in v["manifests"].as_array().into_iter().flatten() {
                check("manifest", c);
            }
        }
        let v = vectors("strict-files.json");
        for c in v["releases"].as_array().unwrap() {
            check(c["kind"].as_str().unwrap(), c);
        }
        assert!(n > 100, "{n} vectors");
        assert!(wrong.is_empty(), "{} vectors read otherwise:\n{}", wrong.len(), wrong.join("\n"));
    }

    /// entries.json's body is read as Go's release package reads it: a
    /// good one comes back, and each kind of bad one is refused.
    #[test]
    fn entries() {
        let good = br#"{"v":1,"type":"entries","seq":3,"time_ms":1000,"expires_ms":2000,"forwarders":[{"name":"cbb.tools:8764","vless":[{"transport":"xhttp","server_name":"cbb.tools","port":443,"path":"/banMEJvnYJJap8S"}]}]}"#;
        let got = ask("entries", good);
        assert_eq!(got["ok"]["value"]["forwarders"][0]["vless"][0]["port"], 443, "{got}");
        let relays = br#"{"v":1,"type":"entries","seq":3,"time_ms":1000,"expires_ms":2000,"forwarders":[],"relays":[{"name":"cbb.tools:8765","endpoints":["relay.cbb.tools:8765"]}]}"#;
        let got = ask("entries", relays);
        assert_eq!(got["ok"]["value"]["relays"][0]["endpoints"][0], "relay.cbb.tools:8765", "{got}");
        let r = core::str::from_utf8(relays).unwrap();
        for bad in [
            r.replace(r#""name":"cbb.tools:8765""#, r#""name":"cbb.tools""#),
            r.replace("relay.cbb.tools:8765", "203.0.113.9:8765"),
            r.replace(r#"}]}"#, r#"},{"name":"cbb.tools:8765"}]}"#),
        ] {
            assert_eq!(ask("entries", bad.as_bytes())["error"]["name"], "signed", "{bad}");
        }
        let s = core::str::from_utf8(good).unwrap();
        for bad in [
            s.replace(r#""seq":3"#, r#""seq":0"#),
            s.replace("cbb.tools:8764", "cbb.tools:0"),
            s.replace("cbb.tools:8764", "cbb.tools:65536"),
            s.replace("cbb.tools:8764", "Cbb.tools:8764"),
            s.replace(r#""server_name":"cbb.tools""#, r#""server_name":"cbb""#),
            s.replace(r#""port":443"#, r#""port":0"#),
            s.replace("/banMEJvnYJJap8S", "/short"),
            s.replace(r#""xhttp""#, r#""reality""#),
            s.replace(r#""expires_ms":2000"#, r#""expires_ms":999"#),
            s.replace(r#"}]}]}"#, r#"}]},{"name":"cbb.tools:8764"}]}"#),
        ] {
            assert_eq!(ask("entries", bad.as_bytes())["error"]["name"], "signed", "{bad}");
        }
    }

    /// The release calls take and refuse exactly the files Go's vectors
    /// say, under the vectors' roots; the pinned roots refuse them all.
    #[test]
    fn release_checks() {
        fn run(op: &str, args: Value) -> Value {
            let req = serde_json::json!({"abi": 1, "op": op, "args": args});
            serde_json::from_slice(&call(req.to_string().as_bytes())).unwrap()
        }
        let v = vectors("go-release.json");
        let vs = v["vectors"].as_array().unwrap();
        assert_eq!(vs.len(), 53);
        // Each case names its files by their index in files.
        // Each file goes in as bytes, as a caller fetched it.
        let raw = |f: &Value| Value::String(STANDARD.encode(f.to_string()));
        let file = |c: &Value, k: &str| raw(&v["files"][c[k].as_u64().unwrap() as usize]);
        for c in vs {
            let mut args = serde_json::json!({"keys": file(c, "keys"), "channel": file(c, "channel"), "release": file(c, "release"),
                "name": v["channel"], "now_ms": v["now_ms"], "seen": c["seen"]});
            let pinned = run("release_check", args.clone());
            args["roots"] = v["roots"].clone();
            let got = run("release_check", args);
            if c["ok"] == true {
                assert_eq!(got["ok"]["value"]["version"], c["version"], "{}: {got}", c["name"]);
                assert_eq!(got["ok"]["seen"]["version"], c["version"], "{}", c["name"]);
                assert_eq!(pinned["error"]["name"], "signed", "{}: the pinned roots took a test key", c["name"]);
            } else {
                assert_eq!(got["error"]["name"], "signed", "{}: {got}", c["name"]);
            }
        }
        for c in v["status"].as_array().unwrap() {
            let args = serde_json::json!({"keys": file(c, "keys"), "status": file(c, "status"), "roots": v["roots"],
                "now_ms": v["now_ms"], "seen": c["seen"]});
            let got = run("release_check_status", args);
            if c["ok"] == true {
                assert_eq!(got["ok"]["value"]["android_revoked"], c["revoked"], "{}: {got}", c["name"]);
            } else {
                assert_eq!(got["error"]["name"], "signed", "{}: {got}", c["name"]);
            }
        }
        let e = vectors("go-entries.json");
        for c in e["vectors"].as_array().unwrap() {
            // The two files apart, and as the set members pass.
            let set = raw(&serde_json::json!({"keys": c["keys"], "entries": c["entries"]}));
            for args in [
                serde_json::json!({"keys": raw(&c["keys"]), "entries": raw(&c["entries"]), "roots": e["roots"],
                    "now_ms": e["now_ms"], "seen": c["seen"]}),
                serde_json::json!({"set": set, "roots": e["roots"], "now_ms": e["now_ms"], "seen": c["seen"]}),
            ] {
                let got = run("release_check_entries", args);
                if c["ok"] == true {
                    assert_eq!(got["ok"]["value"]["seq"], c["seq"], "{}: {got}", c["name"]);
                    assert_eq!(got["ok"]["seen"]["entries_seq"], c["seq"], "{}", c["name"]);
                } else {
                    assert_eq!(got["error"]["name"], "signed", "{}: {got}", c["name"]);
                }
            }
        }
        // A set with a file twice, or with its files beside it, is refused.
        let c = &e["vectors"][0];
        let twice = format!(r#"{{"keys":{},"entries":{},"entries":{}}}"#, c["keys"], c["entries"], c["entries"]);
        let got = run(
            "release_check_entries",
            serde_json::json!({"set": STANDARD.encode(twice), "roots": e["roots"], "now_ms": e["now_ms"]}),
        );
        assert_eq!(got["error"]["name"], "signed", "{got}");
        // The set in the strict form of signed bodies: spaces between its
        // members are that form, a name written with an escape is not.
        assert_eq!(c["ok"], true);
        for (set, ok) in [
            (format!(r#"{{ "keys" : {} , "entries" : {} }}"#, c["keys"], c["entries"]), true),
            (format!(r#"{{"k\u0065ys":{},"entries":{}}}"#, c["keys"], c["entries"]), false),
        ] {
            let got = run(
                "release_check_entries",
                serde_json::json!({"set": STANDARD.encode(&set), "roots": e["roots"], "now_ms": e["now_ms"]}),
            );
            assert_eq!(got.get("ok").is_some(), ok, "{set:.30}: {got}");
        }
        let set = raw(&serde_json::json!({"keys": c["keys"], "entries": c["entries"]}));
        let got = run(
            "release_check_entries",
            serde_json::json!({"set": set, "keys": raw(&c["keys"]), "roots": e["roots"], "now_ms": e["now_ms"]}),
        );
        assert_eq!(got["error"]["name"], "request", "{got}");
        // Each envelope as it comes, through the entry point: the same
        // answer as the File reader's.
        let ev = vectors("go-release-envelopes.json");
        for c in ev["envelopes"].as_array().unwrap() {
            let args = serde_json::json!({"keys": raw(&ev["keys"]), "channel": raw(&ev["channel_file"]), "release": c["release"],
                "name": ev["channel"], "roots": ev["roots"], "now_ms": ev["now_ms"]});
            let got = run("release_check", args);
            assert_eq!(got.get("ok").is_some(), c["ok"] == true, "{}: {got}", c["name"]);
            if c["ok"] != true {
                assert_eq!(got["error"]["name"], "signed", "{}: {got}", c["name"]);
            }
        }
        // The release a channel file names, before it is checked.
        let c = &vs[0];
        let got = run("release_named", serde_json::json!({"channel": file(c, "channel")}));
        assert_eq!(got["ok"]["release"], c["version"], "{got}");
        let got = run(
            "release_named",
            serde_json::json!({"channel": STANDARD.encode(br#"{"body":"e30=","sigs":[],"sigs":[]}"#)}),
        );
        assert_eq!(got["error"]["name"], "signed", "{got}");
        // A call without its file is a bad request, not a refused file.
        let c = &vs[0];
        let got = run("release_check", serde_json::json!({"keys": file(c, "keys"), "now_ms": 1}));
        assert_eq!(got["error"]["name"], "request", "{got}");
        let got = run("release_check_status", serde_json::json!({"keys": file(c, "keys"), "now_ms": 1, "extra": 1}));
        assert_eq!(got["error"]["name"], "request", "{got}");
    }

    /// A good body comes back as its fields; an unknown kind is refused as
    /// a request.
    #[test]
    fn answers() {
        let v = vectors("strict.json");
        let good = v["manifests"].as_array().unwrap().iter().find(|c| c["valid"] == true).unwrap();
        let got = ask("manifest", &bytes(&good["body"]));
        assert_eq!(got["ok"]["kind"], "manifest");
        assert!(got["ok"]["value"].is_object(), "{got}");
        assert_eq!(ask("nothing", b"{}")["error"]["name"], "request");
        assert_eq!(ask("command", b"{}")["error"]["name"], "request");
        assert_eq!(KINDS.len(), 8);
        for kind in KINDS {
            assert_eq!(ask(kind, b"{}")["error"]["name"], "signed", "{kind}");
        }
    }
}
