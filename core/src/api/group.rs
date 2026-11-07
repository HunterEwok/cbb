// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The entry point's calls over a member's record set (docs/core-api.md,
//! "The record set"): the phones keep the set as the records file that
//! `crate::group::Records` writes, and ask the core what it says, so that
//! no rule of the group is written again in Swift or Kotlin. Each call
//! reads the file afresh; the signatures already checked are not checked
//! again (`crate::authority::SigCache`).

use alloc::string::String;
use alloc::vec::Vec;

use serde::Deserialize;
use serde_json::{Map, Value};

use super::{Code, Refusal, b64_value, bad_args, json, refuse};
use crate::authority::{Body, Hash, Record};
use crate::certs::{Cert, KeyHash, b64};
use crate::clip::{Kind, Via};
use crate::copy::{self, Blob, Content, Sealed};
use crate::error::Error;
use crate::group::{ClaimTime, Device, Records, Refusal as Verdict};
use crate::hlc::Timestamp;
use crate::media::Manifest;

/// What every call over the set takes: the group CA, the member's clock
/// and the records file, none for an empty set. `group` names the group
/// with another tag than the CA's own, for the vectors.
#[derive(Deserialize)]
struct SetArgs {
    #[serde(with = "b64")]
    group_ca: Vec<u8>,
    #[serde(default)]
    group: Option<String>,
    now_ms: i64,
    #[serde(default, with = "b64::opt")]
    file: Option<Vec<u8>>,
}

impl SetArgs {
    fn open(&self) -> Result<Records, Refusal> {
        let ca = Cert::parse(&self.group_ca)
            .map_err(|e| refuse(Code::Cert, e.context("The group's certificate could not be read.")))?;
        let now = self.now_ms;
        let mut s = match &self.file {
            Some(data) => Records::from_file_with(data, &ca, move || now)
                .map_err(|e| refuse(Code::Request, e.context("The records file could not be read.")))?,
            None => {
                let mut s = Records::new(&ca);
                s.set_clock(move || now);
                s
            }
        };
        if let Some(tag) = &self.group {
            // The file's records were checked under the CA's own tag; read
            // them again under this one.
            let mut t = Records::new(&ca);
            t.set_tag(tag);
            t.set_clock(move || now);
            if let Some(data) = &self.file {
                let f: RawFile = serde_json::from_slice(data)
                    .map_err(|e| refuse(Code::Request, Error::with("The records file could not be read.", e)))?;
                t.add_all(&f.records);
                t.take_claim_times(&f.first_seen);
            }
            s = t;
        }
        Ok(s)
    }
}

/// The records file as group.rs writes it, read raw.
#[derive(Deserialize)]
struct RawFile {
    #[serde(default)]
    records: Vec<Record>,
    #[serde(default)]
    first_seen: Vec<ClaimTime>,
}

fn file_of(s: &Records) -> Result<Value, Refusal> {
    let data = s.to_file().map_err(|e| refuse(Code::Request, e.context("The records file could not be written.")))?;
    Ok(b64_value(&data))
}

fn certs_of(list: &[Vec<u8>]) -> Result<Vec<Cert>, Refusal> {
    list.iter()
        .map(|d| Cert::parse(d).map_err(|e| refuse(Code::Cert, e.context("A certificate could not be read."))))
        .collect()
}

fn device_value(d: &Device, s: &Records) -> Value {
    let mut m = Map::new();
    m.insert("device".into(), Value::from(d.id.as_str()));
    m.insert("name".into(), Value::from(d.name.as_str()));
    m.insert("role".into(), Value::from(d.role.as_str()));
    if !d.os.is_empty() {
        m.insert("os".into(), Value::from(d.os.as_str()));
    }
    m.insert("key".into(), b64_value(&d.key));
    m.insert("store".into(), Value::from(d.store.as_str()));
    if !d.kind.is_empty() {
        m.insert("kind".into(), Value::from(d.kind.as_str()));
    }
    if !d.proof.is_empty() {
        m.insert("proof".into(), Value::from(d.proof.as_str()));
    }
    if !d.seal.is_empty() {
        m.insert("seal".into(), b64_value(&d.seal));
    }
    if d.forward_only {
        m.insert("forward_only".into(), Value::from(true));
    }
    if d.admin {
        m.insert("admin".into(), Value::from(true));
    }
    if let Some(k) = &d.admin_key {
        m.insert("admin_key".into(), b64_value(k));
    }
    if !d.powers.is_empty() {
        m.insert("powers".into(), Value::from(d.powers.clone()));
    }
    if !d.commands.is_empty() {
        m.insert("commands".into(), Value::from(d.commands.clone()));
    }
    if d.frozen {
        m.insert("frozen".into(), Value::from(true));
        if let Some(k) = &d.admin_key {
            let ids: Vec<Value> = s.freezes_of(k).iter().map(|h| b64_value(&h.0)).collect();
            m.insert("freezes".into(), Value::from(ids));
        }
    }
    m.insert("keys".into(), Value::from(d.keys.iter().map(|k| b64_value(k)).collect::<Vec<_>>()));
    Value::Object(m)
}

fn verdict(v: Option<Verdict>, taken: Option<(String, KeyHash)>) -> Vec<u8> {
    let mut m = Map::new();
    if let (Some(_), Some((dev, admin))) = (&v, taken) {
        m.insert("verdict".into(), Value::from("taken_over"));
        m.insert(
            "why".into(),
            Value::from("the group was taken over from this root; its connection carries records only"),
        );
        m.insert("claimant".into(), claimant(&dev, &admin));
        return json(Value::Object(m));
    }
    match v {
        None => {
            m.insert("verdict".into(), Value::from("ok"));
        }
        Some(Verdict::NotListed) => {
            m.insert("verdict".into(), Value::from("not_listed"));
            m.insert("why".into(), Value::from(Verdict::NotListed.why()));
        }
        Some(Verdict::Stopped) => {
            m.insert("verdict".into(), Value::from("stopped"));
            m.insert("why".into(), Value::from(Verdict::Stopped.why()));
        }
        Some(Verdict::Refused(why)) => {
            m.insert("verdict".into(), Value::from("refused"));
            m.insert("why".into(), Value::from(why));
        }
    }
    json(Value::Object(m))
}

/// Runs a call over the record set; None for an op that is not one.
pub(super) fn dispatch(op: &str, args: &Value) -> Option<Result<Vec<u8>, Refusal>> {
    Some(match op {
        "group_add" => serde_json::from_value(args.clone()).map_err(bad_args).and_then(add),
        "group_view" => serde_json::from_value(args.clone()).map_err(bad_args).and_then(|a: SetArgs| view(&a)),
        "group_refused" => serde_json::from_value(args.clone()).map_err(bad_args).and_then(refused),
        "group_refused_admin_ca" => serde_json::from_value(args.clone()).map_err(bad_args).and_then(refused_admin_ca),
        "group_taken_over" => serde_json::from_value(args.clone()).map_err(bad_args).and_then(taken_over),
        "group_admin_peer" => serde_json::from_value(args.clone()).map_err(bad_args).and_then(admin_peer),
        "group_hub_peer" => serde_json::from_value(args.clone()).map_err(bad_args).and_then(hub_peer),
        "group_seal_copy" => serde_json::from_value(args.clone()).map_err(bad_args).and_then(seal_copy),
        "seal_copy_to" => serde_json::from_value(args.clone()).map_err(bad_args).and_then(seal_copy_to),
        "group_check_copy" => serde_json::from_value(args.clone()).map_err(bad_args).and_then(check_copy),
        "group_command" => serde_json::from_value(args.clone()).map_err(bad_args).and_then(command),
        "group_claim_times" => serde_json::from_value(args.clone()).map_err(bad_args).and_then(claim_times),
        "group_body" => serde_json::from_value(args.clone()).map_err(bad_args).and_then(body),
        _ => return None,
    })
}

#[derive(Deserialize)]
struct AddArgs {
    #[serde(flatten)]
    set: SetArgs,
    records: Vec<Record>,
}

/// `group_add`: adds records to the set; `fresh` holds those it took
/// that it did not hold, `errors` why it left others out.
fn add(a: AddArgs) -> Result<Vec<u8>, Refusal> {
    let mut s = a.set.open()?;
    let (fresh, errors) = s.add_all(&a.records);
    let mut m = Map::new();
    m.insert("file".into(), file_of(&s)?);
    m.insert(
        "fresh".into(),
        serde_json::to_value(&fresh)
            .map_err(|e| refuse(Code::Request, Error::with("The records do not encode.", e)))?,
    );
    let errors: Vec<Value> = errors.iter().map(|e| Value::from(e.message())).collect();
    if !errors.is_empty() {
        m.insert("errors".into(), Value::from(errors));
    }
    Ok(json(Value::Object(m)))
}

/// `group_view`: what the set says, for the apps' lists and the member's
/// decisions: the state, the devices list, the roots on the path, the
/// device that holds the root, the hubs in their order, the admin key the
/// root handed the group to, the digest a hello carries and when the set
/// first held each claim.
fn view(a: &SetArgs) -> Result<Vec<u8>, Refusal> {
    let s = a.open()?;
    let st = s.state();
    let mut m = Map::new();
    m.insert(
        "state".into(),
        serde_json::from_slice(&st.encode())
            .map_err(|e| refuse(Code::Request, Error::with("The state does not encode.", e)))?,
    );
    m.insert("devices".into(), Value::from(s.devices().iter().map(|d| device_value(d, &s)).collect::<Vec<_>>()));
    m.insert("path".into(), Value::from(s.path_certs().iter().map(|c| b64_value(&c.der)).collect::<Vec<_>>()));
    if let Some((dev, key)) = s.root_member() {
        let mut r = Map::new();
        r.insert("device".into(), Value::from(dev));
        r.insert("key".into(), b64_value(&key));
        m.insert("root_member".into(), Value::Object(r));
    }
    m.insert("hub_order".into(), Value::from(s.hub_order()));
    if let Some(k) = s.handed_to() {
        m.insert("handed_to".into(), b64_value(&k));
    }
    let digest = s.digest();
    if !digest.is_empty() {
        m.insert("digest".into(), Value::from(digest));
    }
    let times = s.claim_times();
    if !times.is_empty() {
        m.insert(
            "claim_times".into(),
            serde_json::to_value(&times)
                .map_err(|e| refuse(Code::Request, Error::with("The times do not encode.", e)))?,
        );
    }
    m.insert("known".into(), Value::from(s.known()));
    m.insert("records".into(), Value::from(s.len()));
    Ok(json(Value::Object(m)))
}

#[derive(Deserialize)]
struct ChainArgs {
    #[serde(flatten)]
    set: SetArgs,
    #[serde(with = "b64::list")]
    chain: Vec<Vec<u8>>,
    #[serde(default)]
    device: String,
}

/// `group_refused`: whether the set takes a member's chain, leaf first,
/// already verified to a trusted root (`check_member`).
fn refused(a: ChainArgs) -> Result<Vec<u8>, Refusal> {
    let s = a.set.open()?;
    let chain = certs_of(&a.chain)?;
    Ok(verdict(s.refused(&chain), s.taken_over(&chain)))
}

#[derive(Deserialize)]
struct CaArgs {
    #[serde(flatten)]
    set: SetArgs,
    #[serde(with = "b64")]
    ca: Vec<u8>,
}

/// `group_refused_admin_ca`: whether the set takes an admin CA.
fn refused_admin_ca(a: CaArgs) -> Result<Vec<u8>, Refusal> {
    let s = a.set.open()?;
    let ca = Cert::parse(&a.ca).map_err(|e| refuse(Code::Cert, e.context("The admin CA could not be read.")))?;
    Ok(verdict(s.refused_admin_ca(&ca), None))
}

fn claimant(dev: &str, admin: &KeyHash) -> Value {
    let mut c = Map::new();
    c.insert("device".into(), Value::from(dev));
    c.insert("admin".into(), b64_value(admin));
    Value::Object(c)
}

/// `group_taken_over`: whether a claim took the group over from the root
/// whose own device has the chain, and who claimed it.
fn taken_over(a: ChainArgs) -> Result<Vec<u8>, Refusal> {
    let s = a.set.open()?;
    let mut m = Map::new();
    if let Some((dev, admin)) = s.taken_over(&certs_of(&a.chain)?) {
        m.insert("claimant".into(), claimant(&dev, &admin));
    }
    Ok(json(Value::Object(m)))
}

/// `group_admin_peer`: whether the device with the chain is the group's
/// root or an admin, which alone may be a hub.
fn admin_peer(a: ChainArgs) -> Result<Vec<u8>, Refusal> {
    let s = a.set.open()?;
    let mut m = Map::new();
    m.insert("admin".into(), Value::from(s.admin_peer(&a.device, &certs_of(&a.chain)?)));
    Ok(json(Value::Object(m)))
}

/// `group_hub_peer`: whether the device with the chain may be a hub of
/// the group, whose offers a member keeps: the root, an admin, or a device
/// that only passes copies on (docs/protocol.md, section 11).
fn hub_peer(a: ChainArgs) -> Result<Vec<u8>, Refusal> {
    let s = a.set.open()?;
    let mut m = Map::new();
    m.insert("hub".into(), Value::from(s.hub_peer(&a.device, &certs_of(&a.chain)?)));
    Ok(json(Value::Object(m)))
}

#[derive(Deserialize)]
struct SealCopyArgs {
    #[serde(flatten)]
    set: SetArgs,
    id: String,
    origin: String,
    time: Timestamp,
    #[serde(with = "b64")]
    cert: Vec<u8>,
    #[serde(with = "b64", default)]
    issuer: Vec<u8>,
    kind: Kind,
    #[serde(default)]
    via: Via,
    text: String,
    #[serde(default)]
    media: Option<Manifest>,
    #[serde(default)]
    blob: Option<Blob>,
    /// The copy's key, which sealed its blob; the core makes one when
    /// there is no blob and it is left out.
    #[serde(with = "b64::opt", default)]
    key: Option<Vec<u8>>,
}

/// `group_seal_copy`: seals a copy to the readers the set names
/// (docs/protocol.md, section 4, "Sealing"). The answer holds the event
/// without its signature, `to_sign`, which the origin signs with its member
/// key and puts in the event's `sig`, the readers, and the key when the
/// core made it.
fn seal_copy(a: SealCopyArgs) -> Result<Vec<u8>, Refusal> {
    let s = a.set.open()?;
    let bad = |e: Error| refuse(Code::Copy, e.context("The copy cannot be sealed."));
    let made = a.key.is_none();
    let key: [u8; copy::KEY_SIZE] = match &a.key {
        Some(k) => k.as_slice().try_into().map_err(|_| bad(Error::msg("the copy's key is not 32 bytes")))?,
        None if a.blob.is_none() => copy::new_key(),
        None => return Err(bad(Error::msg("a copy with a blob needs the key that sealed it"))),
    };
    let readers = copy::readers(&s, a.kind == Kind::Secret);
    let content = Content { kind: a.kind, via: a.via, text: a.text, media: a.media };
    let d = copy::seal(&a.id, &a.origin, a.time, &a.cert, &a.issuer, &readers, &content, a.blob, &key).map_err(bad)?;
    let mut m = Map::new();
    m.insert(
        "event".into(),
        serde_json::to_value(&d.sealed)
            .map_err(|e| refuse(Code::Request, Error::with("The copy does not encode.", e)))?,
    );
    m.insert("to_sign".into(), b64_value(&d.to_sign));
    m.insert("readers".into(), Value::from(readers.into_iter().map(|(id, _)| id).collect::<Vec<_>>()));
    if made {
        m.insert("key".into(), b64_value(&key));
    }
    Ok(json(Value::Object(m)))
}

/// A reader of `seal_copy_to`: its device ID and its public key for sealed
/// messages.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReaderArg {
    id: String,
    #[serde(with = "b64")]
    seal: Vec<u8>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SealCopyToArgs {
    id: String,
    origin: String,
    time: Timestamp,
    #[serde(with = "b64")]
    cert: Vec<u8>,
    #[serde(with = "b64", default)]
    issuer: Vec<u8>,
    readers: Vec<ReaderArg>,
    kind: Kind,
    #[serde(default)]
    via: Via,
    text: String,
    #[serde(default)]
    media: Option<Manifest>,
    #[serde(default)]
    blob: Option<Blob>,
    #[serde(with = "b64")]
    key: Vec<u8>,
}

/// `seal_copy_to`: seals a copy to the readers the caller names, for a
/// member that keeps its records itself (the Go service): the same sealing
/// as `group_seal_copy`, without the set. The answer holds the event
/// without its signature and `to_sign`.
fn seal_copy_to(a: SealCopyToArgs) -> Result<Vec<u8>, Refusal> {
    let bad = |e: Error| refuse(Code::Copy, e.context("The copy cannot be sealed."));
    let key: [u8; copy::KEY_SIZE] =
        a.key.as_slice().try_into().map_err(|_| bad(Error::msg("the copy's key is not 32 bytes")))?;
    let readers: Vec<(String, Vec<u8>)> = a.readers.into_iter().map(|r| (r.id, r.seal)).collect();
    let content = Content { kind: a.kind, via: a.via, text: a.text, media: a.media };
    let d = copy::seal(&a.id, &a.origin, a.time, &a.cert, &a.issuer, &readers, &content, a.blob, &key).map_err(bad)?;
    let mut m = Map::new();
    m.insert(
        "event".into(),
        serde_json::to_value(&d.sealed)
            .map_err(|e| refuse(Code::Request, Error::with("The copy does not encode.", e)))?,
    );
    m.insert("to_sign".into(), b64_value(&d.to_sign));
    Ok(json(Value::Object(m)))
}

#[derive(Deserialize)]
struct CheckCopyArgs {
    #[serde(flatten)]
    set: SetArgs,
    event: Sealed,
}

/// `group_check_copy`: checks a copy's origin and signature against the
/// set, as a member does before it passes the copy on.
fn check_copy(a: CheckCopyArgs) -> Result<Vec<u8>, Refusal> {
    let s = a.set.open()?;
    a.event
        .check(&s, a.set.now_ms.div_euclid(1000))
        .map_err(|e| refuse(Code::Copy, e.context("The copy is refused.")))?;
    Ok(json(Value::Object(Map::new())))
}

#[derive(Deserialize)]
struct CommandArgs {
    #[serde(flatten)]
    set: SetArgs,
    command: Record,
    me: String,
    /// The member's secret for sealed messages, which opens a sealed
    /// command; left out by a member that has none.
    #[serde(with = "b64", default)]
    secret: Vec<u8>,
}

/// `group_command`: checks a command for the member `me` and gives its
/// body, the device that signed it and whom the limits count it for. A
/// sealed command's orders are opened with `secret` and put in the body,
/// with `opened`; a paste in the open for a member whose device record has
/// a `seal` key is refused, as the members refuse it (docs/protocol.md,
/// section 15, "Sealed commands").
fn command(a: CommandArgs) -> Result<Vec<u8>, Refusal> {
    let s = a.set.open()?;
    let mut body = s
        .verify_command(&a.command, &a.me, a.set.now_ms)
        .map_err(|e| refuse(Code::Command, e.context("The command is refused.")))?;
    let sealed_to_me = s.devices().iter().any(|d| d.id == a.me && !d.seal.is_empty());
    if body.sealed() {
        if a.secret.is_empty() {
            return Err(refuse(
                Code::Command,
                Error::msg("the command is sealed, and this device has no key to open it")
                    .context("The command is refused."),
            ));
        }
        body.open(&a.secret).map_err(|e| refuse(Code::Command, e.context("The command is refused.")))?;
    } else if sealed_to_me && body.kind == "paste" {
        return Err(refuse(
            Code::Command,
            Error::msg("a paste for this device must be sealed to its key, and this one came in the open")
                .context("The command is refused."),
        ));
    }
    let (dev, root) = s.command_signer(&a.command);
    let (sender, verified) = s.command_sender(&a.command, &body.by);
    let mut m = Map::new();
    let mut fields: Value = serde_json::from_slice(&a.command.body)
        .map_err(|e| refuse(Code::Request, Error::with("The command's body does not read.", e)))?;
    if body.opened {
        if let Some(f) = fields.as_object_mut() {
            for (k, v) in [
                ("mode", Value::from(body.mode.as_str())),
                ("kind", Value::from(body.paste_kind.as_str())),
                ("text", Value::from(body.text.as_str())),
                ("action", Value::from(body.action.as_str())),
            ] {
                if v.as_str() != Some("") {
                    f.insert(k.into(), v);
                }
            }
            if body.enter {
                f.insert("enter".into(), Value::from(true));
            }
            if body.for_ms != 0 {
                f.insert("for_ms".into(), Value::from(body.for_ms));
            }
            if let Some(h) = body.hub.clone() {
                f.insert("hub".into(), h);
            }
        }
        m.insert("opened".into(), Value::from(true));
    }
    m.insert("command".into(), fields);
    if let Some(d) = dev {
        m.insert("signer".into(), device_value(&d, &s));
    }
    if root {
        m.insert("root".into(), Value::from(true));
    }
    m.insert("sender".into(), Value::from(sender));
    if verified {
        m.insert("verified".into(), Value::from(true));
    }
    Ok(json(Value::Object(m)))
}

#[derive(Deserialize)]
struct TimesArgs {
    #[serde(flatten)]
    set: SetArgs,
    claim_times: Vec<ClaimTime>,
}

/// `group_claim_times`: takes the claim times a Welcome brought, those
/// earlier than the set's own and not in the future.
fn claim_times(a: TimesArgs) -> Result<Vec<u8>, Refusal> {
    let mut s = a.set.open()?;
    s.take_claim_times(&a.claim_times);
    let mut m = Map::new();
    m.insert("file".into(), file_of(&s)?);
    Ok(json(Value::Object(m)))
}

#[derive(Deserialize)]
struct BodyArgs {
    #[serde(flatten)]
    set: SetArgs,
    body: Map<String, Value>,
}

/// `group_body`: the canonical bytes of the signer's next record, to sign:
/// the body as `canonical_body` takes it, with the group, seq and prev set
/// from the set, and for a removal, a freeze or a claim the seen the set
/// gives, the signer's own previous seq among them.
fn body(a: BodyArgs) -> Result<Vec<u8>, Refusal> {
    let s = a.set.open()?;
    let mut b = a.body;
    // The signer is checked first, for its own refusal.
    let _signer: Hash = b
        .get("signer")
        .cloned()
        .ok_or_else(|| refuse(Code::Body, Error::msg("The record names no signer.")))
        .and_then(|v| {
            serde_json::from_value(v)
                .map_err(|e| refuse(Code::Body, Error::with("The record's signer does not read.", e)))
        })?;
    // The set fills these in; they only have to be there to read.
    b.insert("group".into(), Value::from(s.tag()));
    b.insert("seq".into(), Value::from(1));
    let body: Body = serde_json::from_value(Value::Object(b))
        .map_err(|e| refuse(Code::Body, Error::with("The record could not be written.", e)))?;
    let bytes = s.next_body(body).map_err(|e| refuse(Code::Body, e))?;
    Ok(json(super::body_answer(&bytes)))
}

#[cfg(test)]
mod tests {
    use alloc::string::String;
    use alloc::vec::Vec;

    use base64::Engine as _;
    use serde_json::Value;

    use super::super::{ABI, Code, call};

    fn vectors() -> Value {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../testdata/interop/v2-records.json");
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap()
    }

    fn ask(op: &str, args: Value) -> Value {
        let req = serde_json::json!({"abi": ABI, "op": op, "args": args});
        let out = call(&serde_json::to_vec(&req).unwrap());
        serde_json::from_slice(&out).unwrap_or_else(|e| panic!("{e}: {}", String::from_utf8_lossy(&out)))
    }

    fn ok(op: &str, args: Value) -> Value {
        let a = ask(op, args);
        assert!(a.get("error").is_none(), "{op}: {a}");
        a["ok"].clone()
    }

    fn set_of(case: &Value) -> Value {
        serde_json::json!({"group_ca": case["group_ca"], "group": case["group"], "now_ms": case["now_ms"]})
    }

    /// Records added to the file a few at a time give each case's
    /// state, as the evaluation of all of them at once does.
    #[test]
    fn the_file_gives_each_cases_state() {
        let v = vectors();
        for case in v["cases"].as_array().unwrap() {
            if case["time_unknown"].as_bool().unwrap_or(false) {
                continue;
            }
            let name = case["name"].as_str().unwrap();
            let mut set = set_of(case);
            for r in case["records"].as_array().unwrap().chunks(4) {
                let mut args = set.clone();
                args["records"] = Value::from(r.to_vec());
                let got = ok("group_add", args);
                set["file"] = got["file"].clone();
            }
            if let Some(times) = case.get("first_seen") {
                let mut args = set.clone();
                args["claim_times"] = times.clone();
                set["file"] = ok("group_claim_times", args)["file"].clone();
            }
            let view = ok("group_view", set.clone());
            let mut want: Value = serde_json::from_str(case["state"].as_str().unwrap()).unwrap();
            let mut got = view["state"].clone();
            // The set does not keep the records it refuses, which the
            // evaluation of all of them lists as ignored.
            let ignored = |v: &mut Value| {
                v.as_object_mut().unwrap().remove("ignored").map_or_else(Vec::new, |i| i.as_array().unwrap().clone())
            };
            let (kept, all) = (ignored(&mut got), ignored(&mut want));
            assert!(kept.iter().all(|i| all.contains(i)), "{name}");
            assert_eq!(got, want, "{name}");
            let held = view["records"].as_u64().unwrap() as usize;
            // A record given twice is held once.
            assert!(held + all.len() - kept.len() <= case["records"].as_array().unwrap().len(), "{name}");
            let devices = view["devices"].as_array().unwrap();
            let known = view["known"].as_array().unwrap();
            assert!(devices.iter().all(|d| known.contains(&d["device"])), "{name}");
            for d in devices.iter().filter(|d| d["frozen"] == true && d.get("admin_key").is_some()) {
                assert!(!d["freezes"].as_array().unwrap().is_empty(), "{name}");
            }
            // Adding them all again changes nothing.
            let mut again = set.clone();
            again["records"] = case["records"].clone();
            let got = ok("group_add", again);
            assert_eq!(got["fresh"], Value::from(Vec::<Value>::new()), "{name}");
        }
    }

    /// The next record of a signer follows its highest seq and names what
    /// the set holds in seen; a signer the set does not know starts at 1.
    #[test]
    fn body_follows_the_signers_chain() {
        let v = vectors();
        let case = &v["cases"][0];
        let mut set = set_of(case);
        let mut args = set.clone();
        args["records"] = case["records"].clone();
        set["file"] = ok("group_add", args)["file"].clone();
        let dec = |s: &Value| base64::engine::general_purpose::STANDARD.decode(s.as_str().unwrap()).unwrap();
        let first: Value = serde_json::from_slice(&dec(&case["records"][0]["body"])).unwrap();
        let signer = first["signer"].clone();
        let highest = case["records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| serde_json::from_slice::<Value>(&dec(&r["body"])).unwrap())
            .filter(|b| b["signer"] == signer)
            .map(|b| b["seq"].as_i64().unwrap())
            .max()
            .unwrap();
        let other = base64::engine::general_purpose::STANDARD.encode([9u8; 32]);
        let revoke = serde_json::json!({"v": 2, "alg": first["alg"], "type": "revoke", "signer": signer,
            "time_ms": 5, "keys": [other], "prev": other, "seen": []});
        let mut a = set.clone();
        a["body"] = revoke.clone();
        let got: Value = serde_json::from_slice(&dec(&ok("group_body", a)["body"])).unwrap();
        assert_eq!(got["seq"], highest + 1);
        assert_eq!(got["group"], case["group"]);
        assert!(got["prev"].is_string());
        assert_ne!(got["prev"], other);
        assert!(got["seen"].as_array().unwrap().iter().any(|e| e["key"] == signer), "{got}");
        let mut a = set.clone();
        let mut fresh = revoke.clone();
        fresh["signer"] = other.clone().into();
        a["body"] = fresh;
        let got: Value = serde_json::from_slice(&dec(&ok("group_body", a)["body"])).unwrap();
        assert_eq!(got["seq"], 1);
        assert!(got.get("prev").is_none());
        assert!(got["seen"].as_array().unwrap().iter().any(|e| e["key"] == other && e["seq"] == 0), "{got}");
        let mut a = set.clone();
        a["body"] = serde_json::json!({"type": "revoke"});
        assert_eq!(ask("group_body", a)["error"]["code"], Code::Body as u64);
    }

    /// A sealed command the root signed opens in the check with the
    /// member's secret, its orders in the body, and is refused without it.
    #[test]
    fn group_command_opens_sealed_commands() {
        let path =
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../testdata/interop/go-sealed-commands.json");
        let v: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let set = serde_json::json!({"group_ca": v["group_ca"], "now_ms": v["now_ms"]});
        let mut opened = 0;
        for c in v["commands"].as_array().unwrap() {
            if !(c["ok"] == true && c["opens"] == true) {
                continue;
            }
            let mut a = set.clone();
            a["command"] = c["command"].clone();
            a["me"] = v["self"].clone();
            let without = ask("group_command", a.clone());
            assert_eq!(without["error"]["code"], Code::Command as u64, "{without}");
            a["secret"] = v["secret"].clone();
            let got = ok("group_command", a);
            assert_eq!(got["opened"], true, "{got}");
            assert_eq!(got["command"]["mode"], c["mode"], "{got}");
            if let Some(t) = c.get("text") {
                assert_eq!(got["command"]["text"], *t, "{got}");
            }
            opened += 1;
        }
        assert_eq!(opened, 2);
    }

    /// A claim time from a Welcome is kept when it is earlier than the
    /// set's own, and dropped when it is in the future.
    #[test]
    fn claim_times_come_in_only_earlier() {
        let v = vectors();
        for case in v["cases"].as_array().unwrap() {
            let mut set = set_of(case);
            set["now_ms"] = Value::from(1_000_000i64);
            let mut args = set.clone();
            args["records"] = case["records"].clone();
            set["file"] = ok("group_add", args)["file"].clone();
            let view = ok("group_view", set.clone());
            let Some(times) = view["claim_times"].as_array().cloned() else { continue };
            let mut earlier = times.clone();
            for t in &mut earlier {
                t["ms"] = Value::from(10i64);
            }
            let mut later = times.clone();
            for t in &mut later {
                t["ms"] = Value::from(9_000_000i64);
            }
            let mut a = set.clone();
            a["claim_times"] = Value::from(later);
            let mut s2 = set.clone();
            s2["file"] = ok("group_claim_times", a)["file"].clone();
            assert_eq!(ok("group_view", s2)["claim_times"], Value::from(times.clone()));
            let mut a = set.clone();
            a["claim_times"] = Value::from(earlier.clone());
            let mut s3 = set.clone();
            s3["file"] = ok("group_claim_times", a)["file"].clone();
            assert_eq!(ok("group_view", s3)["claim_times"], Value::from(earlier));
            return;
        }
        panic!("no case has a claim");
    }

    /// Bad arguments, a bad file and a command no one signed are refused
    /// with their codes.
    #[test]
    fn refusals() {
        let v = vectors();
        let case = &v["cases"][0];
        let set = set_of(case);
        let code = |a: &Value| a["error"]["code"].as_u64().unwrap_or_else(|| panic!("{a}"));
        assert_eq!(code(&ask("group_view", serde_json::json!({}))), Code::Request as u64);
        let mut bad = set.clone();
        bad["file"] = base64::engine::general_purpose::STANDARD.encode(b"not a file").into();
        assert_eq!(code(&ask("group_view", bad)), Code::Request as u64);
        let mut bad = set.clone();
        bad["group_ca"] = "AAAA".into();
        assert_eq!(code(&ask("group_view", bad)), Code::Cert as u64);
        let mut cmd = set.clone();
        cmd["command"] = case["records"][0].clone();
        cmd["me"] = "0123".into();
        assert_eq!(code(&ask("group_command", cmd)), Code::Command as u64);
        let mut chain = set.clone();
        chain["chain"] = Value::from(alloc::vec![case["group_ca"].clone()]);
        let got = ok("group_refused", chain.clone());
        assert_ne!(got["verdict"], "ok", "{got}");
        assert_eq!(ok("group_taken_over", chain.clone()), serde_json::json!({}));
        chain["device"] = "0123".into();
        assert_eq!(ok("group_admin_peer", chain)["admin"], false);
        assert_eq!(code(&ask("group_nothing", set)), Code::Op as u64);
    }
}
