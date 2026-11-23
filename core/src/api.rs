// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The core's one entry point (docs/core-api.md): a request in bytes, an
//! answer in bytes. Every program that uses the core's rules (the phones
//! through its C functions) calls `call` and nothing else,
//! so the bindings stay one function wide and the request's ABI version
//! says which shape of request and answer both sides speak.
//!
//! A request is a JSON object `{"abi": 1, "op": "...", "args": {...}}`. The
//! answer is `{"abi": 1, "ok": ...}` or `{"abi": 1, "error": {"code": n,
//! "name": "...", "message": "...", "details": "..."}}`, where code and name
//! are stable and listed in Code. `call` never panics on any input and
//! always answers.

mod push;
mod set;
mod signed;

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use base64::Engine as _;
use serde::Deserialize;
use serde_json::Value;
use zeroize::Zeroizing;

use crate::certs::b64;
use crate::error::Error;
use crate::strict;

/// The version of the request and answer shapes. A change that an older
/// caller would misread raises it; the core answers only its own version.
pub const ABI: u32 = 1;

/// The largest request the core reads, in bytes: far above any group's
/// records, and small enough for a microcontroller to refuse early.
pub const MAX_REQUEST: usize = 8 << 20;

/// The core's version, as its crate states it.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The commit the core was built from, when the build passes it in
/// `CBB_SOURCE` (the release builds and CI do); empty otherwise.
pub const SOURCE: &str = match option_env!("CBB_SOURCE") {
    Some(s) => s,
    None => "",
};

/// The error codes of an answer. The numbers and names never change
/// meaning; new ones are added at the end of their range.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Code {
    /// The request is not a JSON object of the right shape, or an argument
    /// is missing or of the wrong type.
    Request = 1,
    /// The request's ABI version is not the core's.
    Abi = 2,
    /// The request names an operation the core does not have.
    Op = 3,
    /// The request is larger than MAX_REQUEST.
    TooLarge = 4,
    /// The code that answers it broke (a panic, which the library around
    /// the core caught): the request did nothing.
    Panic = 5,
    /// A record body is refused: its size, form or a field.
    Body = 10,
    /// A certificate is refused.
    Cert = 11,
    /// The group's saved set file cannot be read.
    Saved = 14,
    /// A signed body that is not a record (a server credential, a release
    /// file or a manifest) is refused: its form or a field.
    Signed = 16,
    /// A push registration cannot be made, or a push body does not open
    /// with the phone's push keys.
    Push = 18,
}

impl Code {
    /// The code's stable name.
    pub fn name(self) -> &'static str {
        match self {
            Code::Request => "request",
            Code::Abi => "abi",
            Code::Op => "op",
            Code::TooLarge => "too_large",
            Code::Panic => "panic",
            Code::Body => "body",
            Code::Cert => "cert",
            Code::Saved => "saved",
            Code::Signed => "signed",
            Code::Push => "push",
        }
    }
}

/// A refused request: its code, and the core's error with the message for
/// the user and the details under it.
struct Refusal {
    code: Code,
    err: Error,
}

fn refuse(code: Code, err: Error) -> Refusal {
    Refusal { code, err }
}

fn bad_args(e: serde_json::Error) -> Refusal {
    refuse(Code::Request, Error::with("The request's arguments could not be read.", e))
}

#[derive(Deserialize)]
struct Request {
    abi: u32,
    op: String,
    #[serde(default)]
    args: Value,
}

/// Answers one request. It never panics and always returns an answer in
/// the shape above, also for bytes that are not a request at all.
pub fn call(request: &[u8]) -> Vec<u8> {
    let result = if request.len() > MAX_REQUEST {
        Err(refuse(Code::TooLarge, Error::msg("The request is too large.")))
    } else {
        serde_json::from_slice::<Request>(request)
            .map_err(|e| refuse(Code::Request, Error::with("The request could not be read.", e)))
            .and_then(|r| {
                if r.abi != ABI {
                    return Err(refuse(
                        Code::Abi,
                        Error::msg(alloc::format!(
                            "The request is for version {} of the core's calls, this core has {ABI}.",
                            r.abi
                        )),
                    ));
                }
                dispatch(&r.op, r.args)
            })
    };
    answer(result)
}

/// The answer of a request whose code broke: what the library around the
/// core gives when it catches a panic, `details` saying what broke and
/// where, as the apps show it in debug mode and log it.
pub fn panic_answer(details: &str) -> Vec<u8> {
    const MESSAGE: &str = "Something in CBB broke, and the request did nothing.";
    let err = if details.is_empty() { Error::msg(MESSAGE) } else { Error::msg(details.to_string()).context(MESSAGE) };
    answer(Err(refuse(Code::Panic, err)))
}

/// The answer in the shape above, for a result or a refusal.
fn answer(result: Result<Vec<u8>, Refusal>) -> Vec<u8> {
    let mut out = alloc::format!("{{\"abi\":{ABI},");
    match result {
        Ok(ok) => {
            out.push_str("\"ok\":");
            let mut bytes = out.into_bytes();
            bytes.extend_from_slice(&ok);
            bytes.push(b'}');
            bytes
        }
        Err(r) => {
            let mut err = BTreeMap::new();
            err.insert("code".to_string(), Value::from(r.code as u32));
            err.insert("name".to_string(), Value::from(r.code.name()));
            err.insert("message".to_string(), Value::from(r.err.message()));
            err.insert("details".to_string(), Value::from(r.err.details()));
            out.push_str("\"error\":");
            let mut bytes = out.into_bytes();
            strict::write_canonical(&mut bytes, &Value::Object(err.into_iter().collect()));
            bytes.push(b'}');
            bytes
        }
    }
}

/// Runs one operation and gives its result as JSON bytes.
fn dispatch(op: &str, args: Value) -> Result<Vec<u8>, Refusal> {
    match op {
        "version" => Ok(version()),
        "read_invite" => read_invite(serde_json::from_value(args).map_err(bad_args)?),
        "new_device_key" => new_device_key(),
        "sign_digest" => sign_digest(serde_json::from_value(args).map_err(bad_args)?),
        "keyboard" => keyboard(serde_json::from_value(args).map_err(bad_args)?),
        "why" => why(serde_json::from_value(args).map_err(bad_args)?),
        "bug_report" => bug_report(serde_json::from_value(args).map_err(bad_args)?),
        "bug_allow" => bug_allow(serde_json::from_value(args).map_err(bad_args)?),
        "bug_sent" => bug_sent(serde_json::from_value(args).map_err(bad_args)?),
        "bug_pending" => bug_pending(serde_json::from_value(args).map_err(bad_args)?),
        _ => push::dispatch(op, &args)
            .or_else(|| signed::dispatch(op, &args))
            .or_else(|| set::dispatch(op, &args))
            .unwrap_or_else(|| Err(refuse(Code::Op, Error::msg(alloc::format!("The core has no call named {op:?}."))))),
    }
}

/// The arguments of `why`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WhyArgs {
    facts: crate::why::Facts,
    now_ms: i64,
}

/// `why`: why a device does not sync (crate::why), from the facts a member
/// gathered, the reason that stops the most first.
fn why(a: WhyArgs) -> Result<Vec<u8>, Refusal> {
    let reasons = crate::why::diagnose(&a.facts, a.now_ms);
    let mut m = serde_json::Map::new();
    m.insert("why".into(), serde_json::to_value(reasons).unwrap_or_default());
    Ok(json(Value::Object(m)))
}

/// The arguments of `keyboard`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyboardArgs {
    layout: String,
    #[serde(default)]
    text: String,
}

/// `keyboard`: a phone as a Bluetooth keyboard (crate::keyboard): the
/// reports that type text in the host's layout, each base64, the report
/// map, and the characters the layout has no key for (no reports then).
fn keyboard(a: KeyboardArgs) -> Result<Vec<u8>, Refusal> {
    use crate::keyboard::{DESCRIPTOR, Layout};
    let layout = Layout::from_name(&a.layout)
        .ok_or_else(|| refuse(Code::Request, Error::msg("The core knows no such keyboard layout.")))?;
    let mut m = serde_json::Map::new();
    let untypeable: String = layout.untypeable(&a.text).into_iter().collect();
    let reports: Vec<Value> = if untypeable.is_empty() {
        layout.reports(&a.text).unwrap_or_default().iter().map(|r| b64_value(r)).collect()
    } else {
        Vec::new()
    };
    m.insert("reports".into(), Value::Array(reports));
    m.insert("untypeable".into(), Value::String(untypeable));
    m.insert("map".into(), b64_value(&DESCRIPTOR));
    Ok(json(Value::Object(m)))
}

/// The arguments of `bug_report`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BugReportArgs {
    input: crate::bug::Input,
    #[serde(default)]
    state: crate::bug::State,
}

/// The bug report's state as an answer's value.
fn bug_state(st: &crate::bug::State) -> Result<Value, Refusal> {
    serde_json::to_value(st).map_err(|e| refuse(Code::Request, Error::with("The state does not encode.", e)))
}

/// `bug_report` (docs/core-api.md, "Bug reports"): the report of a break,
/// filtered, its fingerprint, the body to post when this build can seal
/// it, and what the app does: `ask`, `send` or `skip`.
fn bug_report(a: BugReportArgs) -> Result<Vec<u8>, Refusal> {
    use crate::bug;
    let report = bug::report(&a.input).map_err(|e| refuse(Code::Request, e))?;
    let fingerprint = bug::fingerprint(&report.kind, &report.name, &report.at, &report.details);
    let post = match bug::build(&a.input) {
        Ok(b) => b.post,
        Err(_) => String::new(),
    };
    let action = a.state.action(&fingerprint, &report.version, !post.is_empty());
    let mut m = serde_json::Map::new();
    m.insert(
        "report".into(),
        serde_json::to_value(&report)
            .map_err(|e| refuse(Code::Request, Error::with("The report does not encode.", e)))?,
    );
    m.insert("fixed_in".into(), Value::String(a.state.fixed_in(&fingerprint)));
    m.insert("fingerprint".into(), Value::String(fingerprint));
    m.insert("post".into(), Value::String(post));
    m.insert("action".into(), serde_json::to_value(action).unwrap_or(Value::Null));
    m.insert("offer_always".into(), Value::Bool(a.state.offer_always()));
    m.insert("url".into(), Value::String(bug::URL.into()));
    Ok(json(Value::Object(m)))
}

/// The arguments of `bug_allow`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BugAllowArgs {
    #[serde(default)]
    state: crate::bug::State,
    #[serde(default)]
    always: bool,
}

/// `bug_allow`: the user allowed a report, and maybe always; the new state.
fn bug_allow(mut a: BugAllowArgs) -> Result<Vec<u8>, Refusal> {
    a.state.allow(a.always);
    let mut m = serde_json::Map::new();
    m.insert("state".into(), bug_state(&a.state)?);
    Ok(json(Value::Object(m)))
}

/// The arguments of `bug_sent`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BugSentArgs {
    #[serde(default)]
    state: crate::bug::State,
    fingerprint: String,
    version: String,
    #[serde(default)]
    post: String,
    ok: bool,
    #[serde(default)]
    fixed_in: String,
    now_ms: i64,
}

/// `bug_sent`: a report went (`ok`, with the version the server says
/// fixes it), or it did not and waits; the new state.
fn bug_sent(mut a: BugSentArgs) -> Result<Vec<u8>, Refusal> {
    let q = crate::bug::Queued { fingerprint: a.fingerprint, version: a.version, post: a.post, at_ms: a.now_ms };
    a.state.sent(q, a.ok, &a.fixed_in, a.now_ms);
    let mut m = serde_json::Map::new();
    m.insert("state".into(), bug_state(&a.state)?);
    Ok(json(Value::Object(m)))
}

/// The arguments of `bug_pending`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BugPendingArgs {
    #[serde(default)]
    state: crate::bug::State,
    now_ms: i64,
}

/// `bug_pending`: the reports waiting to be sent, without those too old,
/// and the new state.
fn bug_pending(mut a: BugPendingArgs) -> Result<Vec<u8>, Refusal> {
    a.state.prune(a.now_ms);
    let mut m = serde_json::Map::new();
    m.insert(
        "queue".into(),
        serde_json::to_value(&a.state.queue)
            .map_err(|e| refuse(Code::Request, Error::with("The queue does not encode.", e)))?,
    );
    m.insert("state".into(), bug_state(&a.state)?);
    Ok(json(Value::Object(m)))
}

/// `new_device_key`: a new P-256 device key for a phone that keeps it in a
/// file (Sailfish OS, a phone without a TEE: level 3), as `{"pkcs8",
/// "public"}`.
fn new_device_key() -> Result<Vec<u8>, Refusal> {
    let pkcs8 = crate::identity::new_key().map_err(|e| refuse(Code::Request, e))?;
    let key = crate::identity::signing_key(&pkcs8).map_err(|e| refuse(Code::Request, e))?;
    let public = key.verifying_key().to_sec1_point(false);
    let mut m = serde_json::Map::new();
    m.insert("pkcs8".into(), b64_value(&pkcs8));
    m.insert("public".into(), b64_value(public.as_bytes()));
    Ok(json(Value::Object(m)))
}

/// The arguments of `sign_digest`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignDigestArgs {
    #[serde(with = "b64::secret")]
    pkcs8: Zeroizing<Vec<u8>>,
    #[serde(with = "b64")]
    digest: Vec<u8>,
}

/// `sign_digest`: ECDSA P-256 over a SHA-256 digest with a PKCS #8 key, DER,
/// as `{"sig"}`: what a phone's sign callback gives for a key in a file.
fn sign_digest(a: SignDigestArgs) -> Result<Vec<u8>, Refusal> {
    use p256::ecdsa::signature::hazmat::PrehashSigner as _;
    let key = crate::identity::signing_key(&a.pkcs8).map_err(|e| refuse(Code::Request, e))?;
    if a.digest.len() != 32 {
        return Err(refuse(Code::Request, Error::msg("The digest is not 32 bytes.")));
    }
    let sig: p256::ecdsa::Signature =
        key.sign_prehash(&a.digest).map_err(|_| refuse(Code::Request, Error::msg("The key cannot sign.")))?;
    let mut m = serde_json::Map::new();
    m.insert("sig".into(), b64_value(sig.to_der().as_bytes()));
    Ok(json(Value::Object(m)))
}

fn json(v: Value) -> Vec<u8> {
    let mut out = Vec::new();
    strict::write_canonical(&mut out, &v);
    out
}

fn b64_value(data: &[u8]) -> Value {
    Value::from(base64::engine::general_purpose::STANDARD.encode(data))
}

/// `version`: the ABI, the core's version and the commit it was built from.
fn version() -> Vec<u8> {
    let mut m = serde_json::Map::new();
    m.insert("abi".into(), Value::from(ABI));
    m.insert("core".into(), Value::from(VERSION));
    if !SOURCE.is_empty() {
        m.insert("source".into(), Value::from(SOURCE));
    }
    json(Value::Object(m))
}

/// The arguments of `read_invite`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InviteArgs {
    text: String,
}

/// `read_invite`: a remote invitation's text (`cbb://join#`,
/// docs/protocol.md, section 12) read and checked before the user agrees
/// to join: `{"invitation": {"phone"}}`, true when it is a phone's, or
/// `{"refused": {"reason", "message"}}` with its stable reason and a
/// sentence for the user. The invitation carries no expiry: the hub
/// refuses it once its time is over.
fn read_invite(a: InviteArgs) -> Result<Vec<u8>, Refusal> {
    use crate::join::invitation::{Invitation, PathKind};
    let refused =
        |reason: &str, message: &str| serde_json::json!({ "refused": { "reason": reason, "message": message } });
    Ok(json(match Invitation::parse(&a.text) {
        Ok(inv) if inv.paths.iter().any(|p| p.kind == PathKind::Guest) => {
            serde_json::json!({ "invitation": { "phone": inv.profile.role == crate::records::body::ROLE_PHONE } })
        }
        Ok(_) => refused("invite/guest", "the invitation has no way in through a hub; ask for a new one"),
        Err(r) => refused(r.name(), "this is not an invitation of CBB"),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest as _, Sha256};

    fn ask(op: &str, args: Value) -> Value {
        let req = serde_json::json!({"abi": ABI, "op": op, "args": args});
        let out = call(&serde_json::to_vec(&req).unwrap());
        serde_json::from_slice(&out).unwrap_or_else(|e| panic!("{e}: {}", String::from_utf8_lossy(&out)))
    }

    /// The bug report's calls carry the app's state through a report:
    /// asked, allowed, sent once, and not made again for the version.
    #[test]
    fn bug_report_calls() {
        let input = serde_json::json!({"kind": "panic", "code": 5, "name": "panic",
            "details": "panic: boom at member/src/x.rs:3:9", "app": "android", "version": "0.6.0",
            "log": ["dialed 192.168.0.2:8764"], "now_ms": 1_762_646_400_000_i64});
        let a = ask("bug_report", serde_json::json!({"input": input}));
        let ok = &a["ok"];
        assert_eq!(ok["report"]["where"], "member/src/x.rs:3:9", "{a}");
        assert_eq!(ok["report"]["log"][0], "dialed <address>");
        // No robot key in this build yet: nothing to post, nothing to ask.
        assert_eq!(ok["action"], if crate::bug::ROBOT_KEY_B64.is_empty() { "skip" } else { "ask" });
        assert_eq!(ok["url"], crate::bug::URL);
        let fp = ok["fingerprint"].as_str().unwrap().to_string();
        let st = ask("bug_allow", serde_json::json!({"always": false}))["ok"]["state"].clone();
        assert_eq!(st["allowed"], 1);
        let st = ask(
            "bug_sent",
            serde_json::json!({"state": st, "fingerprint": fp, "version": "0.6.0", "post": "{}",
            "ok": false, "now_ms": 1}),
        )["ok"]["state"]
            .clone();
        let p = ask("bug_pending", serde_json::json!({"state": st, "now_ms": 2}));
        assert_eq!(p["ok"]["queue"][0]["fingerprint"], fp.as_str(), "{p}");
        let st = ask(
            "bug_sent",
            serde_json::json!({"state": p["ok"]["state"], "fingerprint": fp, "version": "0.6.0",
            "ok": true, "fixed_in": "0.6.1", "now_ms": 3}),
        )["ok"]["state"]
            .clone();
        let a = ask("bug_report", serde_json::json!({"input": input, "state": st}));
        assert_eq!(a["ok"]["action"], "skip", "{a}");
        assert_eq!(a["ok"]["fixed_in"], "0.6.1");
        let bad = ask("bug_report", serde_json::json!({"input": {"kind": "joke", "app": "ios", "version": "1"}}));
        assert_eq!(code(&bad), Code::Request as u64);
    }

    #[test]
    fn panic_answers_with_its_details() {
        let a: Value = serde_json::from_slice(&panic_answer("index out of bounds at member/src/x.rs:3:9")).unwrap();
        assert_eq!(code(&a), Code::Panic as u64);
        assert_eq!(a["error"]["name"], "panic");
        assert_eq!(a["error"]["details"], "index out of bounds at member/src/x.rs:3:9");
        let a: Value = serde_json::from_slice(&panic_answer("")).unwrap();
        assert_eq!(a["error"]["details"], "");
    }

    fn code(answer: &Value) -> u64 {
        assert_eq!(answer["abi"], ABI);
        assert!(answer.get("ok").is_none(), "{answer}");
        let e = &answer["error"];
        assert!(!e["message"].as_str().unwrap().is_empty(), "{answer}");
        e["code"].as_u64().unwrap()
    }

    /// why answers the vectors' reasons and refuses facts it cannot read.
    #[test]
    fn why_answers_the_vectors() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../testdata/why/vectors.json");
        let vs: Vec<Value> = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        for v in vs {
            let a = ask("why", serde_json::json!({"facts": v["facts"], "now_ms": v["now_ms"]}));
            assert_eq!(a["ok"]["why"], v["want"], "{}", v["name"]);
        }
        assert_eq!(
            code(&ask("why", serde_json::json!({"facts": {"connected": "two"}, "now_ms": 1}))),
            Code::Request as u64
        );
    }

    /// A key from new_device_key signs a digest that its public key
    /// verifies, and a digest of the wrong size or a key that is not one
    /// is refused.
    #[test]
    fn device_key_signs_digests() {
        use p256::ecdsa::signature::hazmat::PrehashVerifier as _;
        let b64 = |v: &Value| base64::engine::general_purpose::STANDARD.decode(v.as_str().unwrap()).unwrap();
        let enc = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
        let key = ask("new_device_key", Value::Null);
        let (pkcs8, public) = (b64(&key["ok"]["pkcs8"]), b64(&key["ok"]["public"]));
        assert_eq!(public.len(), 65);
        let digest = Sha256::digest(b"a copy");
        let sig = ask("sign_digest", serde_json::json!({"pkcs8": enc(&pkcs8), "digest": enc(&digest)}));
        let sig = p256::ecdsa::Signature::from_der(&b64(&sig["ok"]["sig"])).unwrap();
        p256::ecdsa::VerifyingKey::from_sec1_bytes(&public).unwrap().verify_prehash(&digest, &sig).unwrap();
        let short = ask("sign_digest", serde_json::json!({"pkcs8": enc(&pkcs8), "digest": enc(&digest[..31])}));
        assert_eq!(code(&short), Code::Request as u64);
        let bad = ask("sign_digest", serde_json::json!({"pkcs8": enc(b"key"), "digest": enc(&digest)}));
        assert_eq!(code(&bad), Code::Request as u64);
    }

    /// keyboard gives the reports that type a text, or names the
    /// characters the layout has no key for, and refuses a layout it does
    /// not know.
    #[test]
    fn keyboard_types_or_names_the_characters() {
        let b64 = |v: &Value| base64::engine::general_purpose::STANDARD.decode(v.as_str().unwrap()).unwrap();
        let ok = ask("keyboard", serde_json::json!({"layout": "us", "text": "aA"}));
        let reports: Vec<Vec<u8>> = ok["ok"]["reports"].as_array().unwrap().iter().map(b64).collect();
        assert_eq!(reports, [vec![0, 0, 4, 0, 0, 0, 0, 0], vec![0; 8], vec![2, 0, 4, 0, 0, 0, 0, 0], vec![0; 8]]);
        assert_eq!(ok["ok"]["untypeable"], "");
        assert_eq!(b64(&ok["ok"]["map"]), crate::keyboard::DESCRIPTOR);
        let no = ask("keyboard", serde_json::json!({"layout": "ru", "text": "a\u{0431}b a"}));
        assert_eq!(no["ok"]["untypeable"], "ab");
        assert!(no["ok"]["reports"].as_array().unwrap().is_empty());
        assert_eq!(code(&ask("keyboard", serde_json::json!({"layout": "dvorak"}))), Code::Request as u64);
    }

    /// read_invite takes an invitation with a guest path, says whose it
    /// is, and refuses any other text with its rule.
    #[test]
    fn reads_invitations() {
        use crate::join::invitation::{Invitation, Path, PathKind, Profile};
        use crate::records::body::{RIGHT_READ, RIGHT_SEND, ROLE_MEMBER, ROLE_PHONE};
        let guest = Path {
            kind: PathKind::Guest,
            endpoints: alloc::vec!["203.0.113.9:8764".into()],
            hub_key: Some([7; 32]),
            guest: Some(([8; 32], [9; 32])),
            obfuscation: None,
        };
        let home = Path { kind: PathKind::Home, endpoints: Vec::new(), hub_key: None, guest: None, obfuscation: None };
        let profile = |role| Profile { role, rights: RIGHT_READ | RIGHT_SEND, home_only: false, guarded: false };
        let phone = Invitation::new(alloc::vec![guest.clone()], profile(ROLE_PHONE));
        let got = ask("read_invite", serde_json::json!({"text": phone.text()}));
        assert_eq!(got["ok"]["invitation"], serde_json::json!({"phone": true}));
        let computer = Invitation::new(alloc::vec![guest], profile(ROLE_MEMBER));
        let got = ask("read_invite", serde_json::json!({"text": format!("  {}\n", computer.text())}));
        assert_eq!(got["ok"]["invitation"], serde_json::json!({"phone": false}));
        let at_home = Invitation::new(alloc::vec![home], profile(ROLE_MEMBER));
        let got = ask("read_invite", serde_json::json!({"text": at_home.text()}));
        assert_eq!(got["ok"]["refused"]["reason"], "invite/guest");
        for (text, reason) in [
            ("", "invite/shape"),
            ("cbb://invite#e30", "invite/shape"),
            ("https://cbb.tools", "invite/shape"),
            ("cbb://join#!", "invite/shape"),
            ("cbb://join#", "cbor/truncated"),
        ] {
            let got = ask("read_invite", serde_json::json!({"text": text}));
            assert_eq!(got["ok"]["refused"]["reason"], reason, "{text}");
            assert!(!got["ok"]["refused"]["message"].as_str().unwrap().is_empty());
        }
        assert_eq!(code(&ask("read_invite", serde_json::json!({}))), Code::Request as u64);
    }

    /// Requests of the wrong shape, version or size are refused with their
    /// codes, and any bytes at all get an answer.
    #[test]
    fn refuses_bad_requests() {
        let read = |b: &[u8]| -> Value { serde_json::from_slice(&call(b)).unwrap() };
        assert_eq!(code(&read(b"")), Code::Request as u64);
        assert_eq!(code(&read(b"\xff\x00[")), Code::Request as u64);
        assert_eq!(code(&read(b"[]")), Code::Request as u64);
        assert_eq!(code(&read(br#"{"abi":2,"op":"version"}"#)), Code::Abi as u64);
        assert_eq!(code(&read(br#"{"abi":1,"op":"nothing"}"#)), Code::Op as u64);
        assert_eq!(code(&read(br#"{"abi":1,"op":"read_invite","args":{}}"#)), Code::Request as u64);
        assert_eq!(code(&read(&alloc::vec![b' '; MAX_REQUEST + 1])), Code::TooLarge as u64);
        let names: Vec<_> =
            [Code::Request, Code::Abi, Code::Op, Code::TooLarge, Code::Body, Code::Cert, Code::Saved, Code::Signed]
                .iter()
                .map(|c| c.name())
                .collect();
        assert_eq!(names, ["request", "abi", "op", "too_large", "body", "cert", "saved", "signed"]);
    }

    /// version names the ABI and the core's version.
    #[test]
    fn tells_its_version() {
        let v = ask("version", Value::Null);
        assert_eq!(v["ok"]["abi"], ABI);
        assert_eq!(v["ok"]["core"], VERSION);
    }
}
