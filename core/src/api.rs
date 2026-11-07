// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The core's one entry point (docs/core-api.md): a request in bytes, an
//! answer in bytes. Every program that uses the core's rules (the phones
//! through its C functions, Go through cgo or wasm) calls `call` and nothing else,
//! so the bindings stay one function wide and the request's ABI version
//! says which shape of request and answer both sides speak.
//!
//! A request is a JSON object `{"abi": 1, "op": "...", "args": {...}}`. The
//! answer is `{"abi": 1, "ok": ...}` or `{"abi": 1, "error": {"code": n,
//! "name": "...", "message": "...", "details": "..."}}`, where code and name
//! are stable and listed in Code. `call` never panics on any input and
//! always answers.

mod group;
mod signed;

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use base64::Engine as _;
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;

use crate::authority::{self, Body, Hash, Input, Record, SigCache, State};
use crate::certs::{self, Cert, b64};
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
    /// A record body is refused: its size, form or a field.
    Body = 10,
    /// A certificate is refused.
    Cert = 11,
    /// A signed body is not in the strict canonical form.
    Strict = 12,
    /// The record set is older than the one the member saved: a signer's
    /// highest seq is lower than the saved one.
    Rollback = 13,
    /// The saved state cannot be read, is of another version or group, or
    /// its check with the member's secret does not match.
    Saved = 14,
    /// A command is refused: its signer, its target, its time or its
    /// limits.
    Command = 15,
    /// A signed body that is not a record (a command, a server
    /// credential, a release file or a manifest) is refused: its form or a
    /// field.
    Signed = 16,
    /// A copy is refused or cannot be sealed: its origin, its signature, a
    /// field, or it does not open with this device's key.
    Copy = 17,
}

impl Code {
    /// The code's stable name.
    pub fn name(self) -> &'static str {
        match self {
            Code::Request => "request",
            Code::Abi => "abi",
            Code::Op => "op",
            Code::TooLarge => "too_large",
            Code::Body => "body",
            Code::Cert => "cert",
            Code::Strict => "strict",
            Code::Rollback => "rollback",
            Code::Saved => "saved",
            Code::Command => "command",
            Code::Signed => "signed",
            Code::Copy => "copy",
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
        "evaluate" => evaluate(serde_json::from_value(args).map_err(bad_args)?),
        "evaluate_saved" => evaluate_saved(serde_json::from_value(args).map_err(bad_args)?),
        "canonical_body" => canonical_body(args),
        "check_body" => check_body(serde_json::from_value(args).map_err(bad_args)?),
        "canonicalize" => canonicalize(serde_json::from_value(args).map_err(bad_args)?),
        "check_member" => check_member(serde_json::from_value(args).map_err(bad_args)?),
        "read_invite" => read_invite(serde_json::from_value(args).map_err(bad_args)?),
        "recovery_sheet" => recovery_sheet(serde_json::from_value(args).map_err(bad_args)?),
        "read_recovery_sheet" => read_recovery_sheet(serde_json::from_value(args).map_err(bad_args)?),
        "open_copy" => open_copy(serde_json::from_value(args).map_err(bad_args)?),
        "seal_segment" => segment(serde_json::from_value(args).map_err(bad_args)?, true),
        "open_segment" => segment(serde_json::from_value(args).map_err(bad_args)?, false),
        "copy_verdict" => copy_verdict(serde_json::from_value(args).map_err(bad_args)?),
        "new_device_key" => new_device_key(),
        "sign_digest" => sign_digest(serde_json::from_value(args).map_err(bad_args)?),
        _ => group::dispatch(op, &args)
            .or_else(|| signed::dispatch(op, &args))
            .unwrap_or_else(|| Err(refuse(Code::Op, Error::msg(alloc::format!("The core has no call named {op:?}."))))),
    }
}

/// `copy_verdict`: whether the group's current copy goes into the
/// member's clipboard, by the one rule of crate::rule, as `{"verdict"}`:
/// `write`, or why not.
fn copy_verdict(i: crate::rule::Incoming) -> Result<Vec<u8>, Refusal> {
    let mut m = serde_json::Map::new();
    m.insert("verdict".into(), serde_json::to_value(crate::rule::incoming(&i)).unwrap_or_default());
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
    #[serde(with = "b64")]
    pkcs8: Vec<u8>,
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

#[derive(Deserialize)]
struct OpenCopyArgs {
    event: crate::copy::Sealed,
    me: String,
    #[serde(with = "b64")]
    secret: Vec<u8>,
}

/// `open_copy`: opens a copy with the reader's secret for sealed messages:
/// its kind, way, text and manifest, and the copy's key, which opens its
/// blob. It does not check the origin (`group_check_copy` does).
fn open_copy(a: OpenCopyArgs) -> Result<Vec<u8>, Refusal> {
    let refused = |e: Error| refuse(Code::Copy, e.context("The copy does not open on this device."));
    a.event.validate().map_err(refused)?;
    let (c, key) = a.event.open(&a.me, &a.secret).map_err(refused)?;
    let mut m = serde_json::Map::new();
    m.insert("kind".into(), serde_json::to_value(c.kind).unwrap_or_default());
    m.insert("via".into(), serde_json::to_value(c.via).unwrap_or_default());
    m.insert("text".into(), Value::from(c.text));
    if let Some(media) = c.media {
        m.insert(
            "media".into(),
            serde_json::to_value(&media)
                .map_err(|e| refuse(Code::Request, Error::with("The manifest does not encode.", e)))?,
        );
    }
    m.insert("key".into(), b64_value(&key));
    Ok(json(Value::Object(m)))
}

#[derive(Deserialize)]
struct SegmentArgs {
    #[serde(with = "b64")]
    key: Vec<u8>,
    index: u64,
    last: bool,
    #[serde(with = "b64")]
    data: Vec<u8>,
}

/// `seal_segment` and `open_segment`: one segment of a copy's blob
/// (docs/protocol.md, section 4, "The blob").
fn segment(a: SegmentArgs, seal: bool) -> Result<Vec<u8>, Refusal> {
    let key: [u8; crate::copy::KEY_SIZE] = a
        .key
        .as_slice()
        .try_into()
        .map_err(|_| refuse(Code::Request, Error::msg("The copy's key is not 32 bytes.")))?;
    let out = if seal {
        crate::copy::seal_segment(&key, a.index, a.last, &a.data)
    } else {
        crate::copy::open_segment(&key, a.index, a.last, &a.data)
    }
    .map_err(|e| refuse(Code::Copy, e))?;
    let mut m = serde_json::Map::new();
    m.insert("data".into(), b64_value(&out));
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

/// The arguments of `evaluate`, as a case of v2-records.json holds them.
#[derive(Deserialize)]
struct EvalArgs {
    #[serde(with = "b64")]
    group_ca: Vec<u8>,
    group: String,
    now_ms: i64,
    #[serde(default)]
    time_unknown: bool,
    #[serde(default)]
    first_seen: Vec<FirstSeen>,
    records: Vec<Record>,
}

#[derive(Deserialize)]
struct FirstSeen {
    record: Hash,
    ms: i64,
}

/// `evaluate`: the group's state from a record set (docs/records-v2.md,
/// "The state"). Records that do not verify are left out, never an error.
fn evaluate(a: EvalArgs) -> Result<Vec<u8>, Refusal> {
    Ok(run(&a)?.0.encode())
}

/// The signatures this core checked, shared by every call of the process.
static SIGS: SigCache = SigCache::new();

fn run(a: &EvalArgs) -> Result<(State, BTreeMap<Hash, i64>), Refusal> {
    let ca = Cert::parse(&a.group_ca)
        .map_err(|e| refuse(Code::Cert, e.context("The group's certificate could not be read.")))?;
    let first_seen: BTreeMap<Hash, i64> = a.first_seen.iter().map(|f| (f.record, f.ms)).collect();
    Ok(authority::evaluate_seqs(&Input {
        group_ca: &ca,
        group: &a.group,
        records: &a.records,
        now_ms: a.now_ms,
        first_seen: &first_seen,
        time_unknown: a.time_unknown,
        sigs: Some(&SIGS),
    }))
}

/// The version of the saved state's format.
pub const SAVED_VERSION: u32 = 1;

/// The shortest secret a member keeps for its saved state.
pub const MIN_SECRET: usize = 16;

#[derive(Deserialize)]
struct SavedArgs {
    #[serde(flatten)]
    eval: EvalArgs,
    #[serde(with = "b64")]
    secret: Vec<u8>,
    #[serde(default, with = "b64::opt")]
    saved: Option<Vec<u8>>,
}

/// What a member saves between evaluations (docs/core-api.md, "The saved
/// state"), without its check.
#[derive(Serialize, Deserialize)]
struct Saved {
    v: u32,
    group: String,
    seqs: Vec<SavedSeq>,
    #[serde(with = "b64::list")]
    sigs: Vec<Vec<u8>>,
}

#[derive(Serialize, Deserialize)]
struct SavedSeq {
    key: Hash,
    seq: i64,
}

fn saved_mac(secret: &[u8], body: &[u8]) -> Result<Hmac<Sha256>, Refusal> {
    // HMAC takes a key of any length; the error is never expected.
    let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(secret)
        .map_err(|e| refuse(Code::Request, Error::msg(alloc::format!("the device's secret: {e}"))))?;
    m.update(b"cbb saved state v1\n");
    m.update(body);
    Ok(m)
}

/// Reads a saved state: canonical JSON of Saved with `mac`, the HMAC with
/// the member's secret over the rest.
fn read_saved(secret: &[u8], data: &[u8], group: &str) -> Result<Saved, Refusal> {
    let bad = |e: Error| refuse(Code::Saved, e.context("The device's saved group state could not be read."));
    let mut v: Value = serde_json::from_slice(data).map_err(|e| bad(Error::with("not JSON", e)))?;
    let mac = v
        .as_object_mut()
        .and_then(|m| m.remove("mac"))
        .and_then(|m| m.as_str().map(String::from))
        .ok_or_else(|| bad(Error::msg("no mac")))?;
    let mac = base64::engine::general_purpose::STANDARD
        .decode(mac)
        .map_err(|e| bad(Error::msg(alloc::format!("its mac: {e}"))))?;
    if saved_mac(secret, &json(v.clone()))?.verify_slice(&mac).is_err() {
        return Err(bad(Error::msg("its check with this device's secret does not match")));
    }
    let s: Saved = serde_json::from_value(v).map_err(|e| bad(Error::with("its fields", e)))?;
    if s.v != SAVED_VERSION {
        return Err(bad(Error::msg(alloc::format!("version {} is not {SAVED_VERSION}", s.v))));
    }
    if s.group != group {
        return Err(bad(Error::msg("it is of another group")));
    }
    Ok(s)
}

fn write_saved(secret: &[u8], s: &Saved) -> Result<Vec<u8>, Refusal> {
    let mut v = serde_json::to_value(s).unwrap_or_default();
    let mac = saved_mac(secret, &json(v.clone()))?.finalize().into_bytes();
    if let Some(m) = v.as_object_mut() {
        m.insert("mac".into(), b64_value(&mac));
    }
    Ok(json(v))
}

/// `evaluate_saved`: evaluate, with the state the member saved after its
/// last evaluation. It refuses a record set in which a signer's whole
/// chain ends below the seq saved, and answers `{"state", "saved"}`, the state
/// and the new saved state.
fn evaluate_saved(a: SavedArgs) -> Result<Vec<u8>, Refusal> {
    if a.secret.len() < MIN_SECRET {
        return Err(refuse(Code::Request, Error::msg("The device's secret for its saved state is too short.")));
    }
    let old = match &a.saved {
        Some(data) => Some(read_saved(&a.secret, data, &a.eval.group)?),
        None => None,
    };
    if let Some(old) = &old {
        SIGS.add(old.sigs.iter().filter_map(|e| <[u8; 32]>::try_from(e.as_slice()).ok()));
    }
    let (state, mut seqs) = run(&a.eval)?;
    for o in old.iter().flat_map(|o| &o.seqs) {
        let now = seqs.get(&o.key).copied().unwrap_or(0);
        if now < o.seq {
            return Err(refuse(
                Code::Rollback,
                Error::msg("The group's records are older than the ones this device held before.").context(
                    alloc::format!("signer {} has records up to seq {now}, the device saw seq {}", o.key.text(), o.seq),
                ),
            ));
        }
        let s = seqs.entry(o.key).or_insert(0);
        *s = o.seq.max(*s);
    }
    let saved = Saved {
        v: SAVED_VERSION,
        group: a.eval.group.clone(),
        seqs: seqs.into_iter().map(|(key, seq)| SavedSeq { key, seq }).collect(),
        sigs: SIGS.entries().into_iter().map(|e| e.to_vec()).collect(),
    };
    let saved = write_saved(&a.secret, &saved)?;
    let mut out = b"{\"saved\":".to_vec();
    strict::write_canonical(&mut out, &b64_value(&saved));
    out.extend_from_slice(b",\"state\":");
    out.extend_from_slice(&state.encode());
    out.push(b'}');
    Ok(out)
}

/// `canonical_body`: a body the caller built (any order, `v` and `signer`
/// set) as the canonical bytes it signs, after each field is checked
/// against its row. The answer is `{"body": base64}`.
fn canonical_body(args: Value) -> Result<Vec<u8>, Refusal> {
    let mut body: Body = serde_json::from_value(args)
        .map_err(|e| refuse(Code::Body, Error::with("The record could not be written.", e)))?;
    body.sort();
    let bytes = body.encode().map_err(|e| refuse(Code::Body, e))?;
    Ok(json(body_answer(&bytes)))
}

fn body_answer(bytes: &[u8]) -> Value {
    let mut m = serde_json::Map::new();
    m.insert("body".into(), b64_value(bytes));
    Value::Object(m)
}

#[derive(Deserialize)]
struct BodyArgs {
    #[serde(with = "b64")]
    body: Vec<u8>,
}

/// `check_body`: checks a received body (its size, the canonical form, no
/// unknown or empty field, each field against its row) and answers with
/// the body as it is.
fn check_body(a: BodyArgs) -> Result<Vec<u8>, Refusal> {
    Body::parse(&a.body).map_err(|e| refuse(Code::Body, e))?;
    Ok(json(body_answer(&a.body)))
}

/// `canonicalize`: the strict canonical form of a signed body, for the
/// other signed files of version 2.
fn canonicalize(a: BodyArgs) -> Result<Vec<u8>, Refusal> {
    let bytes = strict::canonicalize(&a.body).map_err(|e| refuse(Code::Strict, e))?;
    Ok(json(body_answer(&bytes)))
}

/// The arguments of `check_member`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MemberArgs {
    #[serde(with = "b64::list")]
    chain: Vec<Vec<u8>>,
    #[serde(with = "b64::list")]
    trusted: Vec<Vec<u8>>,
    usage: String,
    now_ms: i64,
}

/// `check_member`: a peer's member chain checked against the roots the
/// member trusts, the current root first, at now_ms raised to that root's
/// start, as a member whose clock is years behind still connects.
fn check_member(a: MemberArgs) -> Result<Vec<u8>, Refusal> {
    let usage = match a.usage.as_str() {
        "server" => certs::Usage::Server,
        "client" => certs::Usage::Client,
        _ => return Err(refuse(Code::Request, Error::msg("The usage is neither \"server\" nor \"client\"."))),
    };
    let parse = |ders: &[Vec<u8>]| ders.iter().map(|d| Cert::parse(d)).collect::<crate::error::Result<Vec<_>>>();
    let trusted = parse(&a.trusted).map_err(|e| refuse(Code::Cert, e))?;
    let current = trusted.first().ok_or_else(|| refuse(Code::Request, Error::msg("No root is trusted.")))?;
    let chain = parse(&a.chain).map_err(|e| refuse(Code::Cert, e))?;
    let t = a.now_ms.div_euclid(1000).max(current.not_before);
    let (dev, used) = certs::member_chain(chain, &trusted, t, usage).map_err(|e| refuse(Code::Cert, e))?;
    let used: Vec<Value> = used.iter().map(|c| b64_value(&c.der)).collect();
    Ok(json(serde_json::json!({ "device": dev.as_str(), "used": used })))
}

/// The arguments of `read_invite`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InviteArgs {
    text: String,
}

/// `read_invite`: a remote invitation's text read and checked (docs/protocol.md,
/// section 12): `{"invitation"}` when it is taken, `{"refused": {"reason",
/// "message"}}` with its stable reason and a sentence for the user when it
/// is not. The caller checks the expiry against its clock.
fn read_invite(a: InviteArgs) -> Result<Vec<u8>, Refusal> {
    Ok(json(match crate::invite::parse(&a.text) {
        Ok(inv) => serde_json::json!({ "invitation": inv.to_json() }),
        Err(r) => serde_json::json!({ "refused": { "reason": r.name(), "message": r.message() } }),
    }))
}

/// The arguments of `recovery_sheet`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SheetArgs {
    #[serde(with = "b64")]
    key: Vec<u8>,
    #[serde(with = "b64")]
    cert: Vec<u8>,
    group: String,
}

/// `recovery_sheet`: the recovery sheet for a key of 32 bytes, its admin
/// CA and the group's tag: `{"qr", "text", "admin"}`, the QR code's text,
/// the key as groups of four, and the key's hash as the `recovery` record
/// names it.
fn recovery_sheet(a: SheetArgs) -> Result<Vec<u8>, Refusal> {
    use crate::recovery::{self, Reason};
    let key = recovery::secret_key(&a.key)
        .ok_or_else(|| refuse(Code::Request, Error::msg("The recovery key is not a P-256 key of 32 bytes.")))?;
    let qr = recovery::qr(&key, &a.cert, &a.group).map_err(|r| {
        let code = if r == Reason::Group { Code::Request } else { Code::Cert };
        refuse(code, Error::msg(alloc::format!("The recovery sheet cannot be made: {}.", r.message())))
    })?;
    let sheet = recovery::Sheet { key, cert: None, group: None };
    let admin =
        sheet.admin().ok_or_else(|| refuse(Code::Request, Error::msg("The recovery key's hash cannot be made.")))?;
    Ok(json(serde_json::json!({
        "qr": qr,
        "text": recovery::text(&sheet.key),
        "admin": b64_value(&admin),
    })))
}

/// `read_recovery_sheet`: a recovery sheet's QR code or text read and
/// checked: `{"sheet": {"key", "pkcs8", "public", "admin", "cert",
/// "group"}}` (cert and group only from the QR code), or `{"refused":
/// {"reason", "message"}}` as read_invite.
fn read_recovery_sheet(a: InviteArgs) -> Result<Vec<u8>, Refusal> {
    let s = match crate::recovery::read(&a.text) {
        Ok(s) => s,
        Err(r) => {
            return Ok(json(serde_json::json!({ "refused": { "reason": r.name(), "message": r.message() } })));
        }
    };
    let (pkcs8, admin) = s
        .pkcs8()
        .zip(s.admin())
        .ok_or_else(|| refuse(Code::Request, Error::msg("The recovery key cannot be encoded.")))?;
    let mut m = serde_json::Map::new();
    m.insert("key".into(), b64_value(&s.scalar()));
    m.insert("pkcs8".into(), b64_value(&pkcs8));
    m.insert("public".into(), b64_value(&s.public()));
    m.insert("admin".into(), b64_value(&admin));
    if let Some(cert) = &s.cert {
        m.insert("cert".into(), b64_value(cert));
    }
    if let Some(group) = &s.group {
        m.insert("group".into(), Value::from(group.as_str()));
    }
    Ok(json(serde_json::json!({ "sheet": Value::Object(m) })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest as _;

    fn vectors() -> Value {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../testdata/interop/v2-records.json");
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap()
    }

    fn ask(op: &str, args: Value) -> Value {
        let req = serde_json::json!({"abi": ABI, "op": op, "args": args});
        let out = call(&serde_json::to_vec(&req).unwrap());
        serde_json::from_slice(&out).unwrap_or_else(|e| panic!("{e}: {}", String::from_utf8_lossy(&out)))
    }

    fn code(answer: &Value) -> u64 {
        assert_eq!(answer["abi"], ABI);
        assert!(answer.get("ok").is_none(), "{answer}");
        let e = &answer["error"];
        assert!(!e["message"].as_str().unwrap().is_empty(), "{answer}");
        e["code"].as_u64().unwrap()
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

    /// evaluate gives each case's state from the case's own JSON.
    #[test]
    fn evaluates_the_vectors() {
        for c in vectors()["cases"].as_array().unwrap() {
            let req = serde_json::json!({"abi": ABI, "op": "evaluate", "args": c});
            let out = call(&serde_json::to_vec(&req).unwrap());
            let want = alloc::format!("{{\"abi\":{ABI},\"ok\":{}}}", c["state"].as_str().unwrap());
            assert_eq!(String::from_utf8(out).unwrap(), want, "{}", c["name"]);
        }
    }

    /// recovery_sheet and read_recovery_sheet give what
    /// testdata/interop/recovery-sheet.json says, and refuse bad requests.
    #[test]
    fn recovery_sheets() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../testdata/interop/recovery-sheet.json");
        let v: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let s = &v["sheet"];
        let args = serde_json::json!({"key": s["key"], "cert": s["cert"], "group": s["group"]});
        let got = ask("recovery_sheet", args.clone());
        assert_eq!(got["ok"], serde_json::json!({"qr": s["qr"], "text": s["text"], "admin": s["admin"]}));

        let got = &ask("read_recovery_sheet", serde_json::json!({"text": s["qr"]}))["ok"]["sheet"];
        for f in ["key", "cert", "group", "admin"] {
            assert_eq!(got[f], s[f], "{f}");
        }
        let pkcs8 = base64::engine::general_purpose::STANDARD.decode(got["pkcs8"].as_str().unwrap()).unwrap();
        assert_eq!(
            crate::identity::public_key(&pkcs8).unwrap(),
            base64::engine::general_purpose::STANDARD.decode(got["public"].as_str().unwrap()).unwrap()
        );
        let got = &ask("read_recovery_sheet", serde_json::json!({"text": s["text"]}))["ok"]["sheet"];
        assert_eq!(got["key"], s["key"]);
        assert_eq!(got["admin"], s["admin"]);
        assert!(got.get("cert").is_none() && got.get("group").is_none(), "{got}");
        for c in v["refused"].as_array().unwrap() {
            let got = ask("read_recovery_sheet", serde_json::json!({"text": c["text"]}));
            assert_eq!(got["ok"]["refused"]["reason"], c["reason"], "{c}");
            assert!(!got["ok"]["refused"]["message"].as_str().unwrap().is_empty());
        }

        let mut bad = args.clone();
        bad["key"] = Value::from("AAAA");
        assert_eq!(code(&ask("recovery_sheet", bad)), Code::Request as u64);
        let mut bad = args.clone();
        bad["group"] = Value::from("nope");
        assert_eq!(code(&ask("recovery_sheet", bad)), Code::Request as u64);
        let mut bad = args.clone();
        bad["key"] = v["texts"][1]["key"].clone();
        assert_eq!(code(&ask("recovery_sheet", bad)), Code::Cert as u64);
        assert_eq!(code(&ask("recovery_sheet", serde_json::json!({}))), Code::Request as u64);
        assert_eq!(code(&ask("read_recovery_sheet", serde_json::json!({}))), Code::Request as u64);
    }

    /// read_invite answers each text of testdata/interop/invites.json as
    /// the file says: the invitation, or the reason it is refused.
    #[test]
    fn reads_invitations() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../testdata/interop/invites.json");
        let v: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        for c in v["valid"].as_array().unwrap() {
            let got = ask("read_invite", serde_json::json!({"text": c["text"]}));
            let mut want = c.clone();
            want.as_object_mut().unwrap().retain(|k, _| k != "name" && k != "text");
            assert_eq!(got["ok"]["invitation"], want, "{}", c["name"]);
        }
        for c in v["refused"].as_array().unwrap() {
            let got = ask("read_invite", serde_json::json!({"text": c["text"]}));
            assert_eq!(got["ok"]["refused"]["reason"], c["reason"], "{}", c["name"]);
            assert!(!got["ok"]["refused"]["message"].as_str().unwrap().is_empty());
        }
        assert_eq!(code(&ask("read_invite", serde_json::json!({}))), Code::Request as u64);
    }

    /// A body built in any order comes back canonical and checks; the
    /// refusals carry their codes.
    #[test]
    fn writes_and_checks_bodies() {
        let v = vectors();
        let b64 = v["cases"][0]["records"][0]["body"].clone();
        let body = base64::engine::general_purpose::STANDARD.decode(b64.as_str().unwrap()).unwrap();
        let mut value: Value = serde_json::from_slice(&body).unwrap();
        let ok = ask("canonical_body", value.clone());
        assert_eq!(ok["ok"]["body"], b64);
        let ok = ask("check_body", serde_json::json!({"body": b64}));
        assert_eq!(ok["ok"]["body"], b64);
        let ok = ask("canonicalize", serde_json::json!({"body": b64}));
        assert_eq!(ok["ok"]["body"], b64);

        value["v"] = 1.into();
        let refused = ask("canonical_body", value);
        assert_eq!(code(&refused), Code::Body as u64);
        assert!(refused["error"]["message"].as_str().unwrap().contains("version 1"), "{refused}");
        // A body every receiver would refuse for its size is not written.
        let revoke = v["cases"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|c| c["records"].as_array().unwrap())
            .map(|r| base64::engine::general_purpose::STANDARD.decode(r["body"].as_str().unwrap()).unwrap())
            .find(|b| b.windows(15).any(|w| w == b"\"type\":\"revoke\""))
            .unwrap();
        let mut big: Value = serde_json::from_slice(&revoke).unwrap();
        let keys: Vec<Value> = (0..200u32)
            .map(|i| base64::engine::general_purpose::STANDARD.encode(Sha256::digest(i.to_be_bytes())).into())
            .collect();
        big["keys"] = keys.into();
        let refused = ask("canonical_body", big);
        assert_eq!(code(&refused), Code::Body as u64);
        assert!(refused["error"]["message"].to_string().contains("over"), "{refused}");
        let empty = base64::engine::general_purpose::STANDARD.encode(b"{}");
        assert_eq!(code(&ask("check_body", serde_json::json!({"body": empty}))), Code::Body as u64);
        let cut = base64::engine::general_purpose::STANDARD.encode(b"{\"a\":");
        assert_eq!(code(&ask("canonicalize", serde_json::json!({"body": cut}))), Code::Strict as u64);
        assert_eq!(
            code(&ask("evaluate", serde_json::json!({"group_ca": "AAAA", "group": "x", "now_ms": 0, "records": []}))),
            Code::Cert as u64
        );
    }

    /// A device's seal is a key of crate::seal's size, not a byte more or
    /// less, and only in a device record.
    #[test]
    fn checks_the_seal() {
        let v = vectors();
        let bodies: Vec<Value> = v["cases"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|c| c["records"].as_array().unwrap())
            .map(|r| {
                let b = base64::engine::general_purpose::STANDARD.decode(r["body"].as_str().unwrap()).unwrap();
                serde_json::from_slice(&b).unwrap()
            })
            .collect();
        let device = bodies.iter().find(|b| b["type"] == "device").unwrap();
        let revoke = bodies.iter().find(|b| b["type"] == "revoke").unwrap();
        let with = |b: &Value, n: usize| {
            let mut b = b.clone();
            b["seal"] = base64::engine::general_purpose::STANDARD.encode(vec![7u8; n]).into();
            b
        };
        let size = crate::seal::PUBLIC_KEY_SIZE;
        assert!(ask("canonical_body", with(device, size)).get("ok").is_some());
        for n in [size - 1, size + 1] {
            assert_eq!(code(&ask("canonical_body", with(device, n))), Code::Body as u64, "{n}");
        }
        assert_eq!(code(&ask("canonical_body", with(revoke, size))), Code::Body as u64);
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
        assert_eq!(code(&read(br#"{"abi":1,"op":"evaluate","args":{}}"#)), Code::Request as u64);
        assert_eq!(code(&read(&alloc::vec![b' '; MAX_REQUEST + 1])), Code::TooLarge as u64);
        let names: Vec<_> = [
            Code::Request,
            Code::Abi,
            Code::Op,
            Code::TooLarge,
            Code::Body,
            Code::Cert,
            Code::Strict,
            Code::Rollback,
            Code::Saved,
            Code::Command,
        ]
        .iter()
        .map(|c| c.name())
        .collect();
        assert_eq!(
            names,
            ["request", "abi", "op", "too_large", "body", "cert", "strict", "rollback", "saved", "command"]
        );
    }

    /// evaluate_saved gives evaluate's state and a saved state that the
    /// next call takes; it refuses a set rolled back and a saved state
    /// changed, of another secret or of another group.
    #[test]
    fn saves_and_refuses_rollback() {
        let v = vectors();
        // The case with a record of the highest seq, which is dropped below.
        let (case, drop) = v["cases"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|c| {
                let recs = c["records"].as_array()?;
                let (i, seq) = recs
                    .iter()
                    .enumerate()
                    .filter_map(|(i, r)| {
                        let body = base64::engine::general_purpose::STANDARD.decode(r["body"].as_str()?).ok()?;
                        let b: Value = serde_json::from_slice(&body).ok()?;
                        Some((i, b["seq"].as_i64()?))
                    })
                    .max_by_key(|(_, seq)| *seq)?;
                (seq > 1 && c["state"].as_str()?.contains("\"devices\"")).then_some((c.clone(), i))
            })
            .next()
            .unwrap();
        let secret = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        let mut args = case.clone();
        args["secret"] = secret.clone().into();
        let first = ask("evaluate_saved", args.clone());
        let state = &first["ok"]["state"];
        let want: Value = serde_json::from_str(case["state"].as_str().unwrap()).unwrap();
        assert_eq!(state, &want, "{first}");
        let saved = first["ok"]["saved"].clone();
        assert!(saved.is_string(), "{first}");
        args["saved"] = saved.clone();
        let again = ask("evaluate_saved", args.clone());
        assert_eq!(&again["ok"]["state"], state, "{again}");

        let mut rolled = args.clone();
        rolled["records"].as_array_mut().unwrap().remove(drop);
        assert_eq!(code(&ask("evaluate_saved", rolled)), Code::Rollback as u64);

        let mut other = args.clone();
        other["secret"] = base64::engine::general_purpose::STANDARD.encode([8u8; 32]).into();
        assert_eq!(code(&ask("evaluate_saved", other)), Code::Saved as u64);
        let mut raw = base64::engine::general_purpose::STANDARD.decode(saved.as_str().unwrap()).unwrap();
        let at = raw.windows(6).position(|w| w == b"\"seq\":").unwrap() + 6;
        raw[at] = b'9';
        let mut changed = args.clone();
        changed["saved"] = base64::engine::general_purpose::STANDARD.encode(&raw).into();
        assert_eq!(code(&ask("evaluate_saved", changed)), Code::Saved as u64);
        let mut group = args.clone();
        group["group"] = "another".into();
        assert_eq!(code(&ask("evaluate_saved", group)), Code::Saved as u64);
        let mut short = args.clone();
        short["secret"] = "AAAA".into();
        assert_eq!(code(&ask("evaluate_saved", short)), Code::Request as u64);
    }

    /// A record taken from the middle of a chain is a rollback too, though
    /// the chain's highest seq is still held.
    #[test]
    fn refuses_a_hole_in_a_chain() {
        let v = vectors();
        let secret = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        let mut found = 0;
        for case in v["cases"].as_array().unwrap() {
            let recs = case["records"].as_array().unwrap();
            let bodies: Vec<Value> = recs
                .iter()
                .map(|r| {
                    let body = base64::engine::general_purpose::STANDARD.decode(r["body"].as_str().unwrap()).unwrap();
                    serde_json::from_slice(&body).unwrap()
                })
                .collect();
            // A case with a checkpoint may drop the record
            // (a_pruned_set_is_no_rollback).
            if bodies.iter().any(|b| b["type"] == "checkpoint") {
                continue;
            }
            let heads: Vec<(String, i64)> = bodies
                .iter()
                .map(|b| (b["signer"].as_str().unwrap_or_default().into(), b["seq"].as_i64().unwrap_or(0)))
                .collect();
            // A record with the next seq of its signer after it, and no
            // other record of that seq.
            let Some(hole) = (0..heads.len()).find(|&i| {
                let (k, s) = &heads[i];
                heads.iter().filter(|h| h == &&heads[i]).count() == 1
                    && heads.iter().any(|(k2, s2)| k2 == k && *s2 == s + 1)
            }) else {
                continue;
            };
            let mut args = case.clone();
            args["secret"] = secret.clone().into();
            let first = ask("evaluate_saved", args.clone());
            args["saved"] = first["ok"]["saved"].clone();
            args["records"].as_array_mut().unwrap().remove(hole);
            assert_eq!(code(&ask("evaluate_saved", args)), Code::Rollback as u64, "{}", case["name"]);
            found += 1;
        }
        assert!(found > 0);
    }

    /// The set a root's checkpoint prunes evaluates as the full one did,
    /// and is no rollback.
    #[test]
    fn a_pruned_set_is_no_rollback() {
        let v = vectors();
        let dec = |s: &Value| base64::engine::general_purpose::STANDARD.decode(s.as_str().unwrap()).unwrap();
        let mut found = 0;
        for case in v["cases"].as_array().unwrap() {
            let bodies: Vec<Value> = case["records"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| serde_json::from_slice(&dec(&r["body"])).unwrap())
                .collect();
            // The checkpoint that counts, as the state names it.
            let state: Value = serde_json::from_str(case["state"].as_str().unwrap()).unwrap();
            let Some(cp) = state["checkpoint"].as_str() else { continue };
            let recs = case["records"].as_array().unwrap();
            let cp = bodies
                .iter()
                .zip(recs)
                .find(|(_, r)| base64::engine::general_purpose::STANDARD.encode(Sha256::digest(dec(&r["body"]))) == cp)
                .map(|(b, _)| b)
                .unwrap();
            let heads = cp["heads"].as_array().unwrap();
            let mut anchors: Vec<Value> = heads.iter().map(|h| h["id"].clone()).collect();
            anchors.extend(cp["keep"].as_array().into_iter().flatten().cloned());
            let mut args = case.clone();
            args["secret"] = base64::engine::general_purpose::STANDARD.encode([7u8; 32]).into();
            let first = ask("evaluate_saved", args.clone());
            args["saved"] = first["ok"]["saved"].clone();
            let kept: Vec<Value> = case["records"]
                .as_array()
                .unwrap()
                .iter()
                .zip(&bodies)
                .filter(|(r, b)| {
                    let id: Value =
                        base64::engine::general_purpose::STANDARD.encode(Sha256::digest(dec(&r["body"]))).into();
                    let below = heads.iter().any(|h| h["key"] == b["signer"] && b["seq"].as_i64() <= h["seq"].as_i64());
                    !below || anchors.contains(&id)
                })
                .map(|(r, _)| r.clone())
                .collect();
            if kept.len() == bodies.len() {
                continue;
            }
            args["records"] = kept.into();
            let again = ask("evaluate_saved", args);
            assert_eq!(again["ok"]["state"], first["ok"]["state"], "{}: {again}", case["name"]);
            found += 1;
        }
        assert!(found > 0);
    }

    /// Records under a root that only a stranger's claim names can be taken
    /// away again: they never counted, so it is no rollback.
    #[test]
    fn saves_only_the_groups_signers() {
        let v = vectors();
        let case = v["cases"].as_array().unwrap().iter().find(|c| c["name"] == "stranger's claim 2").unwrap();
        let mut args = case.clone();
        args["secret"] = base64::engine::general_purpose::STANDARD.encode([7u8; 32]).into();
        let first = ask("evaluate_saved", args.clone());
        args["saved"] = first["ok"]["saved"].clone();
        let recs = args["records"].as_array_mut().unwrap();
        recs.truncate(recs.len() - 2);
        let mut again = ask("evaluate_saved", args);
        let mut first = first;
        // Only the list of records left out changes.
        for v in [&mut again, &mut first] {
            if let Some(s) = v["ok"]["state"].as_object_mut() {
                s.remove("ignored");
            }
        }
        assert!(again["ok"]["state"].is_object(), "{again}");
        assert_eq!(again["ok"]["state"], first["ok"]["state"], "{again}");
    }

    /// version names the ABI and the core's version.
    #[test]
    fn tells_its_version() {
        let v = ask("version", Value::Null);
        assert_eq!(v["ok"]["abi"], ABI);
        assert_eq!(v["ok"]["core"], VERSION);
    }

    /// check_member gives each case of member-chains.json, written by Go
    /// from crypto/tls's chain building, the device and the certificates
    /// Go gives, or refuses it with code 11.
    #[test]
    fn checks_member_chains() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../testdata/interop/member-chains.json");
        let v: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let cases = v["cases"].as_array().unwrap();
        assert!(cases.len() >= 20);
        for c in cases {
            let name = c["name"].as_str().unwrap();
            let mut args = c.clone();
            let m = args.as_object_mut().unwrap();
            for k in ["name", "device", "used"] {
                m.remove(k);
            }
            let a = ask("check_member", args);
            let want = c["device"].as_str().unwrap();
            if want.is_empty() {
                assert_eq!(code(&a), Code::Cert as u64, "{name}: {a}");
                continue;
            }
            assert_eq!(a["ok"]["device"], want, "{name}: {a}");
            assert_eq!(a["ok"]["used"], c["used"], "{name}");
        }
        // A request of the wrong shape is no certificate's fault.
        let bad = serde_json::json!({"chain": [], "trusted": [], "usage": "server", "now_ms": 0});
        assert_eq!(code(&ask("check_member", bad)), Code::Request as u64);
        let first = &cases[0];
        let mut bad = first.clone();
        bad["usage"] = "both".into();
        bad.as_object_mut().unwrap().retain(|k, _| ["chain", "trusted", "usage", "now_ms"].contains(&k.as_str()));
        assert_eq!(code(&ask("check_member", bad)), Code::Request as u64);
    }

    /// seal_segment and open_segment round-trip a blob's segment, which
    /// opens only at its place; open_copy refuses a copy it cannot read.
    #[test]
    fn copy_segments() {
        use base64::engine::general_purpose::STANDARD;
        let key = STANDARD.encode([5u8; 32]);
        let data = STANDARD.encode(b"some bytes of a file");
        let sealed = ask("seal_segment", serde_json::json!({"key": key, "index": 3, "last": true, "data": data}));
        let seg = sealed["ok"]["data"].clone();
        assert_eq!(STANDARD.decode(seg.as_str().unwrap()).unwrap().len(), crate::copy::SEALED_SEGMENT);
        let opened = ask("open_segment", serde_json::json!({"key": key, "index": 3, "last": true, "data": seg}));
        let got = STANDARD.decode(opened["ok"]["data"].as_str().unwrap()).unwrap();
        assert!(got.starts_with(b"some bytes of a file"));
        let moved = ask("open_segment", serde_json::json!({"key": key, "index": 4, "last": true, "data": seg}));
        assert_eq!(code(&moved), Code::Copy as u64);
        let short = ask("seal_segment", serde_json::json!({"key": "AAAA", "index": 0, "last": true, "data": data}));
        assert_eq!(code(&short), Code::Request as u64);
        let none = ask("open_copy", serde_json::json!({"event": {}, "me": "ab", "secret": "AAAA"}));
        assert_eq!(code(&none), Code::Copy as u64, "an empty copy");
    }
}
