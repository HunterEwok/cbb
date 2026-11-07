// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The entry point's call for the signed bodies that are not records
//! (docs/core-api.md, "Signed bodies"): commands, server credentials,
//! release files and manifests. Go and the phone kits read each through
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
pub const KINDS: [&str; 9] =
    ["command", "credential", "keys", "release", "channel", "attest-status", "entries", "zxnext", "manifest"];

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
        "command" => value(crate::command::Command::parse(body)?),
        "credential" => value(crate::credential::Body::parse(body)?),
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

/// The arguments of `seal_command`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SealArgs {
    #[serde(with = "b64")]
    body: Vec<u8>,
    #[serde(with = "b64")]
    key: Vec<u8>,
}

/// `seal_command`: a command in the open with its orders sealed to the
/// receiver's key for sealed messages (docs/protocol.md, section 15,
/// "Sealed commands"), as `{"body": ...}` for the sender to sign.
fn seal_command(a: SealArgs) -> core::result::Result<Vec<u8>, Refusal> {
    let body = crate::command::Command::seal_body(&a.body, &a.key).map_err(|e| refuse(Code::Signed, e))?;
    Ok(json(super::body_answer(&body)))
}

/// The arguments of `seal_public`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicArgs {
    #[serde(with = "b64")]
    secret: Vec<u8>,
}

/// `seal_public`: the public key for sealed messages of `secret` (32
/// random bytes the caller keeps), as `{"key": ...}`, the `seal` its
/// hello, pairing and device record carry.
fn seal_public(a: PublicArgs) -> core::result::Result<Vec<u8>, Refusal> {
    let key = crate::seal::public_key(&a.secret).map_err(|e| refuse(Code::Request, e))?;
    let mut m = Map::new();
    m.insert("key".into(), Value::String(base64::Engine::encode(&base64::engine::general_purpose::STANDARD, key)));
    Ok(json(Value::Object(m)))
}

/// Runs a call over a signed body; None for an op that is not one.
pub(super) fn dispatch(op: &str, args: &Value) -> Option<core::result::Result<Vec<u8>, Refusal>> {
    Some(match op {
        "parse_body" => serde_json::from_value(args.clone()).map_err(bad_args).and_then(parse_body),
        "seal_command" => serde_json::from_value(args.clone()).map_err(bad_args).and_then(seal_command),
        "seal_public" => serde_json::from_value(args.clone()).map_err(bad_args).and_then(seal_public),
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

    /// A command sealed by the call opens with the receiver's secret to
    /// the same orders, under the same header, and a sealed command or a
    /// bad key is refused.
    #[test]
    fn seals_commands() {
        let secret = crate::seal::generate_secret().unwrap();
        let public = crate::seal::public_key(&secret).unwrap();
        let body = br#"{"by":"00000000000000000000000000000001","enter":true,"expires_ms":31000,"group":"g","id":"0123456789abcdef0123456789abcdef","kind":"text","mode":"paste","text":"hello","time_ms":1000,"to":"00000000000000000000000000000002","type":"paste","v":1}"#;
        let seal = |body: &[u8], key: &[u8]| -> Value {
            let req = format!(
                r#"{{"abi":1,"op":"seal_command","args":{{"body":"{}","key":"{}"}}}}"#,
                STANDARD.encode(body),
                STANDARD.encode(key)
            );
            serde_json::from_slice(&call(req.as_bytes())).unwrap()
        };
        let got = seal(body, &public);
        let sealed = bytes(&got["ok"]["body"]);
        assert_eq!(crate::strict::canonicalize(&sealed).unwrap(), sealed);
        let text = core::str::from_utf8(&sealed).unwrap();
        assert!(!text.contains("hello") && text.contains(r#""v":2"#), "{text}");
        let mut c = crate::command::Command::parse(&sealed).unwrap();
        assert!(c.sealed());
        c.open(&secret).unwrap();
        assert_eq!((c.text.as_str(), c.mode.as_str(), c.enter), ("hello", "paste", true));
        let other = crate::seal::public_key(&crate::seal::generate_secret().unwrap()).unwrap();
        let mut c = crate::command::Command::parse(&bytes(&seal(body, &other)["ok"]["body"])).unwrap();
        assert!(c.open(&secret).is_err());
        assert_eq!(seal(&sealed, &public)["error"]["name"], "signed");
        assert_eq!(seal(body, &[1, 2, 3])["error"]["name"], "signed");
    }

    /// A hub command's order to stop being a hub carries nothing else.
    #[test]
    fn hub_stop_order() {
        let body = |hub: &str| {
            format!(
                r#"{{"by":"00000000000000000000000000000001","expires_ms":31000,"group":"g","hub":{hub},"id":"0123456789abcdef0123456789abcdef","time_ms":1000,"to":"00000000000000000000000000000002","type":"hub","v":1}}"#
            )
        };
        assert!(crate::command::Command::parse(body(r#"{"stop":true}"#).as_bytes()).is_ok());
        assert!(
            crate::command::Command::parse(body(r#"{"endpoints":["203.0.113.7:8764"],"stop":true}"#).as_bytes())
                .is_err()
        );
        assert!(crate::command::Command::parse(body(r#"{"stop":false}"#).as_bytes()).is_err());
    }

    /// `seal_public` gives the public key of a secret, the one the Go
    /// vectors carry, and refuses a secret of the wrong size.
    #[test]
    fn seal_public_key() {
        let v = vectors("go-sealed-commands.json");
        let ask_key = |secret: &[u8]| -> Value {
            let req = format!(r#"{{"abi":1,"op":"seal_public","args":{{"secret":"{}"}}}}"#, STANDARD.encode(secret));
            serde_json::from_slice(&call(req.as_bytes())).unwrap()
        };
        assert_eq!(bytes(&ask_key(&bytes(&v["secret"]))["ok"]["key"]), bytes(&v["public"]));
        assert_eq!(ask_key(&[1, 2, 3])["error"]["name"], "request");
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
        files.extend((1..).map(|i| format!("strict-mutants-{i}.json")).take_while(exists));
        for f in &files {
            let v = vectors(f);
            for (section, kind) in [("commands", "command"), ("manifests", "manifest")] {
                for c in v[section].as_array().into_iter().flatten() {
                    check(kind, c);
                }
            }
        }
        let v = vectors("strict-files.json");
        for c in v["credentials"].as_array().unwrap() {
            check("credential", c);
        }
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

    /// A good body comes back as its fields; an unknown kind is refused as
    /// a request.
    #[test]
    fn answers() {
        let v = vectors("strict.json");
        let good = v["commands"].as_array().unwrap().iter().find(|c| c["valid"] == true).unwrap();
        let got = ask("command", &bytes(&good["body"]));
        assert_eq!(got["ok"]["kind"], "command");
        assert!(got["ok"]["value"]["type"].is_string(), "{got}");
        assert_eq!(ask("nothing", b"{}")["error"]["name"], "request");
        assert_eq!(KINDS.len(), 9);
        for kind in KINDS {
            assert_eq!(ask(kind, b"{}")["error"]["name"], "signed", "{kind}");
        }
    }
}
