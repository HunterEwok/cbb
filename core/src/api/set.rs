// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The entry point's calls over a group's records v3 (docs/core-api.md,
//! "The group"): the phones and Go keep the group as a set file
//! (`crate::setfile`) and ask the core what it says and what to write, so
//! that no rule of the group is written again in Swift, Kotlin or Go. Each
//! call reads the file afresh and gives the new file back when it changed.
//!
//! A key the core does not hold (a phone's root or admin key in the Secure
//! Enclave or Keystore, a computer's in its TPM) signs in rounds: a call
//! that needs a signature answers `{"sign": [{key, digest}]}`, the caller
//! signs each digest (ECDSA P-256 over the SHA-256 digest as given) and
//! calls again with the same arguments and `sigs`, the signatures so far.
//! A record's ID covers its body only, so the bodies, and with them the
//! digests, are the same in every round; a call that writes two records
//! (an admin's acknowledgement, then its record) asks for the second
//! digest once the first signature is given.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use serde::Deserialize;
use serde_json::{Map, Value};
use zeroize::Zeroizing;

use super::{Code, Refusal, b64_value, bad_args, json, refuse};
use crate::certs::b64;
use crate::error::{Error, Result};
use crate::identity::ExternalKey;
use crate::records::body::{self, AdminKind, Device, Kind, Settings};
use crate::records::eval::{ChangeState, ConflictKind, Stop};
use crate::records::set::{Added, Outcome, Refused};
use crate::records::{DeviceId, Key, KeyHash, Record, RecordId, RecordSet, Recovery, State};

/// The error a key without the signature gives: the call asks for it.
const NEEDS_SIGNATURE: &str = "a signature is needed";

/// A signature the caller made in an earlier round.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Sig {
    /// The digest, base64.
    digest: String,
    /// The signature, base64: DER, or the 64 bytes r ‖ s.
    #[serde(with = "b64")]
    sig: Vec<u8>,
}

/// A key the caller holds: it signs the digests it was given signatures
/// for and asks for the rest.
struct Asked {
    public: Vec<u8>,
    sigs: BTreeMap<[u8; 32], Vec<u8>>,
    wanted: spin::Mutex<Vec<[u8; 32]>>,
}

impl Asked {
    fn new(public: Vec<u8>, sigs: &[Sig]) -> core::result::Result<Asked, Refusal> {
        let mut map = BTreeMap::new();
        for s in sigs {
            let d = b64_32(&s.digest)
                .ok_or_else(|| refuse(Code::Request, Error::msg("A signature's digest is not 32 bytes in base64.")))?;
            let der = if s.sig.len() == 64 {
                p256::ecdsa::Signature::from_slice(&s.sig)
                    .map_err(|_| refuse(Code::Request, Error::msg("A signature is not a P-256 signature.")))?
                    .to_der()
                    .as_bytes()
                    .to_vec()
            } else {
                s.sig.clone()
            };
            map.insert(d, der);
        }
        Ok(Asked { public, sigs: map, wanted: spin::Mutex::new(Vec::new()) })
    }

    fn wanted(&self) -> Vec<[u8; 32]> {
        self.wanted.lock().clone()
    }
}

impl ExternalKey for Asked {
    fn public(&self) -> Vec<u8> {
        self.public.clone()
    }

    fn sign_digest(&self, digest: &[u8; 32]) -> Result<Vec<u8>> {
        if let Some(s) = self.sigs.get(digest) {
            return Ok(s.clone());
        }
        let mut w = self.wanted.lock();
        if !w.contains(digest) {
            w.push(*digest);
        }
        Err(Error::msg(NEEDS_SIGNATURE))
    }
}

/// A key the core holds for one call: K1 of a recovery secret.
struct Held(p256::ecdsa::SigningKey);

impl ExternalKey for Held {
    fn public(&self) -> Vec<u8> {
        self.0.verifying_key().to_sec1_point(false).as_bytes().to_vec()
    }

    fn sign_digest(&self, digest: &[u8; 32]) -> Result<Vec<u8>> {
        use p256::ecdsa::signature::hazmat::PrehashSigner as _;
        let sig: p256::ecdsa::Signature =
            self.0.sign_prehash(digest).map_err(|_| Error::msg("cannot sign with the recovery key"))?;
        Ok(sig.to_der().as_bytes().to_vec())
    }
}

fn fixed<const N: usize>(s: &str) -> Option<[u8; N]> {
    use base64::Engine as _;
    let b = base64::engine::general_purpose::STANDARD.decode(s).ok()?;
    b.as_slice().try_into().ok()
}

fn b64_32(s: &str) -> Option<[u8; 32]> {
    fixed::<32>(s)
}

fn record_id(s: &str) -> core::result::Result<RecordId, Refusal> {
    b64_32(s).map(RecordId).ok_or_else(|| refuse(Code::Request, Error::msg("A record ID is not 32 bytes in base64.")))
}

fn key_hash(s: &str) -> core::result::Result<KeyHash, Refusal> {
    b64_32(s).map(KeyHash).ok_or_else(|| refuse(Code::Request, Error::msg("A key hash is not 32 bytes in base64.")))
}

fn es256(public: &[u8]) -> core::result::Result<Key, Refusal> {
    let k = Key::es256(public.to_vec());
    match k.check() {
        Ok(crate::records::key::KeyCheck::Good) => Ok(k),
        _ => Err(refuse(Code::Request, Error::msg("A key is not a P-256 public key (SEC1, 65 bytes)."))),
    }
}

/// What every call over a set takes: the set file, and the device's local
/// key when the file is pinned to it.
#[derive(Deserialize)]
struct SetArgs {
    #[serde(with = "b64")]
    set: Vec<u8>,
    #[serde(default, with = "b64::opt")]
    local: Option<Vec<u8>>,
}

impl SetArgs {
    fn local(&self) -> core::result::Result<Option<Zeroizing<[u8; 32]>>, Refusal> {
        match &self.local {
            None => Ok(None),
            Some(l) => <[u8; 32]>::try_from(l.as_slice())
                .map(|a| Some(Zeroizing::new(a)))
                .map_err(|_| refuse(Code::Request, Error::msg("The local key is not 32 bytes."))),
        }
    }

    fn open(&self) -> core::result::Result<RecordSet, Refusal> {
        let local = self.local()?;
        crate::setfile::load(&self.set, local.as_deref())
            .map_err(|e| refuse(Code::Saved, e.context("The group's set file could not be read.")))
    }

    fn save(&self, set: &RecordSet) -> core::result::Result<Value, Refusal> {
        let local = self.local()?;
        Ok(b64_value(&crate::setfile::save(set, local.as_deref())))
    }
}

/// Dispatches the calls of this module; None for another op.
pub(super) fn dispatch(op: &str, args: &Value) -> Option<core::result::Result<Vec<u8>, Refusal>> {
    fn run<A: for<'de> Deserialize<'de>>(
        args: &Value,
        f: fn(A) -> core::result::Result<Vec<u8>, Refusal>,
    ) -> core::result::Result<Vec<u8>, Refusal> {
        serde_json::from_value(args.clone()).map_err(bad_args).and_then(f)
    }
    Some(match op {
        "set_new" => run(args, new),
        "set_add" => run(args, add),
        "set_view" => run(args, |a: SetArgs| a.open().map(|s| json(Value::Object(view(&s, &s.state()))))),
        "set_records" => run(args, records),
        "set_write" => run(args, write),
        "set_remove" => run(args, remove),
        "set_dismiss" => run(args, dismiss),
        "set_change_preview" => run(args, change_preview),
        "set_change" => run(args, change),
        "set_standing" => run(args, standing),
        _ => return None,
    })
}

/// The arguments of `set_new`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewArgs {
    /// The group's first root key, SEC1.
    #[serde(with = "b64")]
    root: Vec<u8>,
    /// K1 of the recovery key, SEC1.
    #[serde(with = "b64")]
    recovery: Vec<u8>,
    /// K2 of the recovery key, the SLH-DSA public key.
    #[serde(with = "b64")]
    recovery2: Vec<u8>,
    #[serde(default, with = "b64::opt")]
    local: Option<Vec<u8>>,
}

/// `set_new`: the empty set of a group, as its creator or a joiner starts.
fn new(a: NewArgs) -> core::result::Result<Vec<u8>, Refusal> {
    let root = es256(&a.root)?;
    let k2 = Key::new(crate::records::key::ALG_SLH_DSA, a.recovery2.clone());
    let recovery = Recovery::new(es256(&a.recovery)?, k2)
        .ok_or_else(|| refuse(Code::Request, Error::msg("The recovery key is not a valid pair.")))?;
    if root == recovery.k1 {
        return Err(refuse(Code::Request, Error::msg("The root key and the recovery key must differ.")));
    }
    let set = RecordSet::new(root, recovery);
    let sa = SetArgs { set: Vec::new(), local: a.local };
    let mut m = view(&set, &set.state());
    m.insert("set".into(), sa.save(&set)?);
    Ok(json(Value::Object(m)))
}

/// The arguments of `set_add`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AddArgs {
    #[serde(flatten)]
    set: SetArgs,
    /// Record envelopes, base64.
    #[serde(default)]
    records: Vec<String>,
    /// Lists, base64.
    #[serde(default)]
    lists: Vec<String>,
}

fn unb64(s: &str) -> core::result::Result<Vec<u8>, Refusal> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| refuse(Code::Request, Error::msg(alloc::format!("A value is not base64: {e}"))))
}

/// `set_add`: records and lists from a peer, each checked before it is
/// kept; the new file, what was kept and what was refused, and the view.
fn add(a: AddArgs) -> core::result::Result<Vec<u8>, Refusal> {
    let mut set = a.set.open()?;
    let mut refused = Vec::new();
    let mut records = Vec::new();
    for r in &a.records {
        match Record::decode(&unb64(r)?) {
            Ok(rec) => records.push(rec),
            Err(rule) => refused.push(Value::Object(Map::from_iter([
                ("id".into(), Value::Null),
                ("why".into(), Value::String(alloc::format!("{rule}"))),
            ]))),
        }
    }
    let lists: Vec<Vec<u8>> = a.lists.iter().map(|l| unb64(l)).collect::<core::result::Result<_, _>>()?;
    let before = set.digest();
    // Round after round, as a record may wait for a list or another record.
    let mut stored = Vec::new();
    let rounds = records.len().saturating_add(lists.len()).saturating_add(2);
    let mut last_refused = Vec::new();
    for _ in 0..rounds {
        let d = set.digest();
        for l in &lists {
            let _ = set.insert_list(l);
        }
        last_refused.clear();
        for r in &records {
            match set.insert(r.clone()) {
                Ok(Added::Stored) => stored.push(b64_value(&r.id().0)),
                Ok(_) => {}
                Err(e) => last_refused.push((r.id(), e)),
            }
        }
        if set.digest() == d {
            break;
        }
    }
    for (id, e) in last_refused {
        let why = match e {
            Refused::Group => String::from("group"),
            Refused::UnknownSigner => String::from("unknown_signer"),
            Refused::Broken(rule) => alloc::format!("{rule}"),
        };
        refused
            .push(Value::Object(Map::from_iter([("id".into(), b64_value(&id.0)), ("why".into(), Value::String(why))])));
    }
    let st = set.state();
    let mut m = view(&set, &st);
    m.insert("changed".into(), Value::Bool(set.digest() != before || !stored.is_empty()));
    m.insert("stored".into(), Value::Array(stored));
    m.insert("refused".into(), Value::Array(refused));
    m.insert("set".into(), a.set.save(&set)?);
    Ok(json(Value::Object(m)))
}

/// The arguments of `set_records`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordsArgs {
    #[serde(flatten)]
    set: SetArgs,
    /// The peer's member key hash, base64: only what that peer may have.
    #[serde(default)]
    peer: Option<String>,
}

/// `set_records`: the records and lists to send, in dependency order;
/// with `peer`, what the set gives that peer.
fn records(a: RecordsArgs) -> core::result::Result<Vec<u8>, Refusal> {
    let set = a.set.open()?;
    let (records, lists): (Vec<&Record>, Vec<&[u8]>) = match &a.peer {
        Some(p) => {
            let st = set.state();
            let p = key_hash(p)?;
            (set.for_peer(&st, &p), set.lists_for_peer(&st, &p))
        }
        None => (set.in_dependency_order(), set.lists().collect()),
    };
    let mut m = Map::new();
    m.insert("records".into(), Value::Array(records.iter().map(|r| b64_value(&r.envelope())).collect()));
    m.insert("lists".into(), Value::Array(lists.iter().map(|l| b64_value(l)).collect()));
    m.insert("digest".into(), b64_value(&set.digest()));
    Ok(json(Value::Object(m)))
}

/// A record to write, as the caller names it.
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
#[allow(clippy::large_enum_variant, reason = "read once per call from the request")]
enum WriteKind {
    /// A device record: a new device, or a device's record written again.
    Device {
        #[serde(with = "b64")]
        key: Vec<u8>,
        name: String,
        /// `member`, `phone`, `watch` or `leaf`.
        role: String,
        #[serde(default)]
        rights: Vec<String>,
        #[serde(default)]
        caps: Vec<String>,
        #[serde(default)]
        os: u64,
        /// `file`, `hardware`, `rootless` or `proven`.
        #[serde(default)]
        store: Option<String>,
        /// The device's admin key, SEC1, and what kind of admin it is.
        #[serde(default, with = "b64::opt")]
        admin: Option<Vec<u8>>,
        /// `watch`, `computer` or `phone`, with `admin`.
        #[serde(default)]
        admin_kind: Option<String>,
        #[serde(default)]
        holds_root: bool,
        #[serde(default)]
        guarded: bool,
        /// The key hash, base64, of the device this one replaces.
        #[serde(default)]
        replaces: Option<String>,
    },
    Freeze {
        keys: Vec<String>,
    },
    Thaw {
        ids: Vec<String>,
    },
    Resolve {
        ids: Vec<String>,
    },
    Settings {
        #[serde(default)]
        key_level: u64,
        #[serde(default)]
        min_rules: u64,
        #[serde(default)]
        shared: bool,
    },
    Copies {
        ttl_ms: u64,
        /// 0 for none: the default, a minute.
        #[serde(default)]
        secret_ttl_ms: u64,
    },
    Hubs {
        /// Device IDs, base64.
        hubs: Vec<String>,
    },
    /// An admin key's acknowledgement, with a spare admin key its device
    /// made, SEC1.
    Ack {
        #[serde(default, with = "b64::opt")]
        spare: Option<Vec<u8>>,
    },
    /// The root's checkpoint.
    Checkpoint,
}

fn role(s: &str) -> core::result::Result<u64, Refusal> {
    Ok(match s {
        "member" => body::ROLE_MEMBER,
        "phone" => body::ROLE_PHONE,
        "watch" => body::ROLE_WATCH,
        "leaf" => body::ROLE_LEAF,
        _ => return Err(refuse(Code::Request, Error::msg(alloc::format!("The core knows no role {s:?}.")))),
    })
}

fn bits(names: &[String], table: &[(&str, u64)], what: &str) -> core::result::Result<u64, Refusal> {
    let mut out = 0;
    for n in names {
        let Some((_, b)) = table.iter().find(|(t, _)| t == n) else {
            return Err(refuse(Code::Request, Error::msg(alloc::format!("The core knows no {what} {n:?}."))));
        };
        out |= b;
    }
    Ok(out)
}

const RIGHTS: &[(&str, u64)] = &[
    ("read", body::RIGHT_READ),
    ("send", body::RIGHT_SEND),
    ("hub", body::RIGHT_HUB),
    ("secrets", body::RIGHT_SECRETS),
];
const CAPS: &[(&str, u64)] = &[("admin", body::CAP_ADMIN), ("dials", body::CAP_DIALS), ("hub", body::CAP_HUB)];
const STORES: &[(&str, u64)] = &[
    ("file", body::STORE_FILE),
    ("hardware", body::STORE_HARDWARE),
    ("rootless", body::STORE_ROOTLESS),
    ("proven", body::STORE_PROVEN),
];

fn names(n: u64, table: &[(&str, u64)]) -> Value {
    Value::Array(table.iter().filter(|(_, b)| n & b != 0).map(|(t, _)| Value::String((*t).into())).collect())
}

impl WriteKind {
    fn kind(self) -> core::result::Result<Kind, Refusal> {
        let ids = |v: &[String]| v.iter().map(|s| record_id(s)).collect::<core::result::Result<Vec<_>, _>>();
        Ok(match self {
            WriteKind::Device {
                key,
                name,
                role: r,
                rights,
                caps,
                os,
                store,
                admin,
                admin_kind,
                holds_root,
                guarded,
                replaces,
            } => {
                let mut d = Device::new(es256(&key)?, &name, role(&r)?);
                d.rights = bits(&rights, RIGHTS, "right")?;
                d.caps = bits(&caps, CAPS, "capability")?;
                d.os = os;
                if let Some(s) = store {
                    d.store = bits(&[s], STORES, "key store")?;
                }
                if let Some(a) = admin {
                    let kind = match admin_kind.as_deref() {
                        Some("watch") => AdminKind::Watch,
                        Some("computer") => AdminKind::Computer,
                        Some("phone") => AdminKind::Phone,
                        _ => {
                            return Err(refuse(
                                Code::Request,
                                Error::msg("An admin key needs admin_kind: watch, computer or phone."),
                            ));
                        }
                    };
                    d.admin = Some(es256(&a)?);
                    (d.powers, d.commands) = kind.grants();
                }
                d.holds_root = holds_root;
                d.guarded = guarded;
                d.replaces = replaces.as_deref().map(key_hash).transpose()?;
                Kind::device(d)
            }
            WriteKind::Freeze { keys } => Kind::Freeze(body::Removal {
                keys: keys.iter().map(|k| key_hash(k)).collect::<core::result::Result<_, _>>()?,
                seen: Vec::new(),
            }),
            WriteKind::Thaw { ids: v } => Kind::Thaw { ids: ids(&v)?, seen: Vec::new() },
            WriteKind::Resolve { ids: v } => Kind::Resolve(ids(&v)?),
            WriteKind::Settings { key_level, min_rules, shared } => {
                Kind::settings(Settings { key_level, min_rules, shared, servers: Vec::new() })
            }
            WriteKind::Copies { ttl_ms, secret_ttl_ms } => Kind::Copies { secret_ttl_ms, ttl_ms, seen: Vec::new() },
            WriteKind::Hubs { hubs } => Kind::Hubs {
                hubs: hubs
                    .iter()
                    .map(|h| {
                        fixed::<16>(h)
                            .map(DeviceId)
                            .ok_or_else(|| refuse(Code::Request, Error::msg("A device ID is not 16 bytes in base64.")))
                    })
                    .collect::<core::result::Result<_, _>>()?,
                seen: Vec::new(),
            },
            WriteKind::Ack { .. } | WriteKind::Checkpoint => {
                return Err(refuse(Code::Request, Error::msg("This record is not written as a plain record.")));
            }
        })
    }
}

/// The arguments of `set_write`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WriteArgs {
    #[serde(flatten)]
    set: SetArgs,
    /// The key that signs, SEC1: the root's or an admin's.
    #[serde(with = "b64")]
    signer: Vec<u8>,
    record: WriteKind,
    time_ms: u64,
    #[serde(default)]
    sigs: Vec<Sig>,
}

/// What a writer call gives: the records written and the new file, or the
/// digests still to sign.
fn written(
    sa: &SetArgs,
    keys: &[&Asked],
    out: Result<(RecordSet, Vec<Record>, Map<String, Value>)>,
) -> core::result::Result<Vec<u8>, Refusal> {
    let wanted: Vec<Value> = keys
        .iter()
        .flat_map(|k| {
            k.wanted().into_iter().map(|d| {
                Value::Object(Map::from_iter([("key".into(), b64_value(&k.public)), ("digest".into(), b64_value(&d))]))
            })
        })
        .collect();
    match out {
        Err(_) if !wanted.is_empty() => {
            Ok(json(Value::Object(Map::from_iter([("sign".into(), Value::Array(wanted))]))))
        }
        Err(e) => Err(refuse(Code::Body, e.context("The record could not be written."))),
        Ok((set, recs, mut extra)) => {
            let st = set.state();
            let mut m = view(&set, &st);
            m.append(&mut extra);
            m.insert("records".into(), Value::Array(recs.iter().map(|r| b64_value(&r.envelope())).collect()));
            m.insert("set".into(), sa.save(&set)?);
            Ok(json(Value::Object(m)))
        }
    }
}

/// `set_write`: a record of the root or an admin, signed in rounds; an
/// admin key's first record after its grant is preceded by its
/// acknowledgement, which the call writes too.
fn write(a: WriteArgs) -> core::result::Result<Vec<u8>, Refusal> {
    let mut set = a.set.open()?;
    let st = set.state();
    let key = Asked::new(a.signer.clone(), &a.sigs)?;
    let out = match a.record {
        WriteKind::Ack { spare } => match spare {
            Some(s) => {
                let spare = es256(&s)?;
                set.write_ack_spare(&st, &key, &spare, a.time_ms).map(|r| alloc::vec![r])
            }
            None => set.write_ack(&st, &key, a.time_ms).map(|r| alloc::vec![r]),
        },
        WriteKind::Checkpoint => set.write_checkpoint(&st, &key, a.time_ms).and_then(|r| {
            set.insert(r.clone()).map_err(|e| Error::msg(alloc::format!("the checkpoint was not kept: {e:?}")))?;
            Ok(alloc::vec![r])
        }),
        kind => {
            let mut kind = kind.kind()?;
            // The call names no servers: a new settings record keeps the
            // group's (format 4.4, field 15), which only `cbb global relay`
            // on the root changes.
            if let Kind::Settings(s) = &mut kind {
                s.servers = st.settings.servers.clone();
            }
            set.write_record(&st, &key, kind, a.time_ms)
        }
    };
    written(&a.set, &[&key], out.map(|r| (set, r, Map::new())))
}

/// The arguments of `set_remove`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RemoveArgs {
    #[serde(flatten)]
    set: SetArgs,
    #[serde(with = "b64")]
    signer: Vec<u8>,
    /// The member keys' hashes, base64, of the devices to remove.
    keys: Vec<String>,
    time_ms: u64,
    #[serde(default)]
    sigs: Vec<Sig>,
}

/// `set_remove`: the removal of devices, by the root (with what a key in
/// two histories needs) or an admin with the power to remove.
fn remove(a: RemoveArgs) -> core::result::Result<Vec<u8>, Refusal> {
    let mut set = a.set.open()?;
    let st = set.state();
    let key = Asked::new(a.signer.clone(), &a.sigs)?;
    let keys: Vec<KeyHash> = a.keys.iter().map(|k| key_hash(k)).collect::<core::result::Result<_, _>>()?;
    let signer = Key::es256(a.signer.clone()).hash();
    let out = if st.roots.last() == Some(&signer) {
        set.write_removal(&st, &key, &keys, a.time_ms)
    } else {
        set.write_record(&st, &key, Kind::Revoke(body::Removal { keys, seen: Vec::new() }), a.time_ms)
    };
    written(&a.set, &[&key], out.map(|r| (set, r, Map::new())))
}

/// The arguments of `set_dismiss`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DismissArgs {
    #[serde(flatten)]
    set: SetArgs,
    id: String,
}

/// `set_dismiss`: a notice the person has read; it is not shown again.
fn dismiss(a: DismissArgs) -> core::result::Result<Vec<u8>, Refusal> {
    let mut set = a.set.open()?;
    set.dismiss(&record_id(&a.id)?);
    let mut m = view(&set, &set.state());
    m.insert("set".into(), a.set.save(&set)?);
    Ok(json(Value::Object(m)))
}

/// The arguments of `set_change_preview`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreviewArgs {
    #[serde(flatten)]
    set: SetArgs,
    /// The key hashes, base64, of the devices the person leaves out.
    #[serde(default)]
    leave_out: Vec<String>,
}

fn outcome(o: Outcome) -> &'static str {
    match o {
        Outcome::Stays => "stays",
        Outcome::Out => "out",
        Outcome::AdminKeptWithSpare => "admin_kept_with_spare",
        Outcome::AdminRightsLost => "admin_rights_lost",
        Outcome::Frozen => "frozen",
    }
}

/// `set_change_preview`: what a change of root would do to each device,
/// for the "who stays" list.
fn change_preview(a: PreviewArgs) -> core::result::Result<Vec<u8>, Refusal> {
    let set = a.set.open()?;
    let st = set.state();
    let out: Vec<KeyHash> = a.leave_out.iter().map(|k| key_hash(k)).collect::<core::result::Result<_, _>>()?;
    let lines: Vec<Value> = set
        .change_preview(&st, &out)
        .into_iter()
        .map(|p| {
            Value::Object(Map::from_iter([
                ("device".into(), b64_value(&p.device.0)),
                ("outcome".into(), Value::String(outcome(p.outcome).into())),
                ("frozen".into(), Value::Bool(p.frozen)),
            ]))
        })
        .collect();
    Ok(json(Value::Object(Map::from_iter([("preview".into(), Value::Array(lines))]))))
}

/// The arguments of `set_change`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChangeArgs {
    #[serde(flatten)]
    set: SetArgs,
    /// The recovery secret, from the recovery sheet: both halves of the
    /// recovery key come of it. It is used for this call and forgotten.
    #[serde(with = "b64")]
    recovery_secret: Vec<u8>,
    /// The new root key, SEC1, which signs in rounds.
    #[serde(with = "b64")]
    new_root: Vec<u8>,
    /// The new root's own device record.
    device: WriteKind,
    #[serde(default)]
    leave_out: Vec<String>,
    #[serde(default)]
    drop_hubs: bool,
    /// Write past a change the set holds and has not applied.
    #[serde(default)]
    over_waiting: bool,
    time_ms: u64,
    #[serde(default)]
    sigs: Vec<Sig>,
}

/// `set_change`: a change of root by the recovery key (rule 33): the
/// recovery record, its list and the new root's first records.
fn change(a: ChangeArgs) -> core::result::Result<Vec<u8>, Refusal> {
    let mut set = a.set.open()?;
    let st = set.state();
    let secret = Zeroizing::new(
        <[u8; 32]>::try_from(a.recovery_secret.as_slice())
            .map_err(|_| refuse(Code::Request, Error::msg("The recovery secret is not 32 bytes.")))?,
    );
    let (k1, k2) = crate::records::pq::recovery_keys(&secret).map_err(|e| refuse(Code::Request, e))?;
    let k1 = Held(p256::ecdsa::SigningKey::from(k1));
    if Key::es256(k1.public()) != set.recovery().k1 || k2.key() != set.recovery().k2 {
        return Err(refuse(Code::Request, Error::msg("This recovery sheet is not the group's.")));
    }
    let root = Asked::new(a.new_root.clone(), &a.sigs)?;
    let Kind::Device(device) = a.device.kind()? else {
        return Err(refuse(Code::Request, Error::msg("The new root's device must be a device record.")));
    };
    let out: Vec<KeyHash> = a.leave_out.iter().map(|k| key_hash(k)).collect::<core::result::Result<_, _>>()?;
    let w = if a.over_waiting {
        set.write_change_over_waiting(&st, &k1, &k2, &root, *device, &out, a.drop_hubs, a.time_ms)
    } else {
        set.write_change(&st, &k1, &k2, &root, *device, &out, a.drop_hubs, a.time_ms)
    };
    let out = w.map(|w| {
        let mut recs = alloc::vec![w.record];
        recs.extend(w.first);
        let extra = Map::from_iter([
            ("list".into(), b64_value(&w.list.encode())),
            ("again".into(), Value::Bool(w.again)),
            ("blind".into(), Value::Bool(w.blind)),
        ]);
        (set, recs, extra)
    });
    written(&a.set, &[&root], out)
}

/// The arguments of `set_standing`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StandingArgs {
    #[serde(flatten)]
    set: SetArgs,
    /// This device's member key, SEC1.
    #[serde(with = "b64")]
    own: Vec<u8>,
    /// The peer's member key, SEC1, as its TLS key container shows it.
    #[serde(with = "b64")]
    peer: Vec<u8>,
}

/// `set_standing`: where a peer's key stands in the records
/// (`crate::peer::standing`), as TLS by key and the intro ask.
fn standing(a: StandingArgs) -> core::result::Result<Vec<u8>, Refusal> {
    use crate::peer::Standing;
    let set = a.set.open()?;
    let peer: [u8; 65] = a
        .peer
        .as_slice()
        .try_into()
        .map_err(|_| refuse(Code::Request, Error::msg("The peer's key is not 65 bytes.")))?;
    let own = crate::format::KeyHash(Key::es256(a.own).hash().0);
    let (name, device, reason) = match crate::peer::standing(&set.state(), &own, &peer) {
        Standing::Member(d) => ("member", Some(b64_value(&d.0)), None),
        Standing::Unknown => ("unknown", None, None),
        Standing::Refused(why) => ("refused", None, Some(why)),
        Standing::Halted => ("halted", None, None),
        Standing::ForkProof => ("fork_proof", None, None),
    };
    let mut m = Map::new();
    m.insert("standing".into(), Value::String(name.into()));
    if let Some(d) = device {
        m.insert("device".into(), d);
    }
    if let Some(r) = reason {
        m.insert("reason".into(), Value::String(r.into()));
    }
    Ok(json(Value::Object(m)))
}

fn b64s<'a, const N: usize>(v: impl IntoIterator<Item = &'a [u8; N]>) -> Value {
    Value::Array(v.into_iter().map(|b| b64_value(b)).collect())
}

/// The group as the apps draw it: its ID and keys, the devices with their
/// roles and rights, the roots, the stop and its reasons, the change of
/// root and what waits, and the notices.
fn view(set: &RecordSet, st: &State) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("group".into(), b64_value(&st.group.0));
    m.insert("digest".into(), b64_value(&set.digest()));
    m.insert("record_count".into(), Value::from(set.len() as u64));
    m.insert("bytes".into(), Value::from(set.bytes() as u64));
    m.insert("first_root".into(), b64_value(set.root().public()));
    m.insert("recovery".into(), b64_value(&st.recovery.0));
    m.insert("roots".into(), b64s(st.roots.iter().map(|k| &k.0)));
    if let Some(d) = st.root_device {
        m.insert("root_device".into(), b64_value(&d.0));
    }
    let devices: Vec<Value> = st
        .devices
        .iter()
        .map(|d| {
            let mut o = Map::new();
            o.insert("id".into(), b64_value(&d.id.0));
            o.insert("key".into(), b64_value(d.key.public()));
            o.insert("key_hash".into(), b64_value(&d.key.hash().0));
            o.insert("name".into(), Value::String(d.name.clone()));
            let role = match d.role {
                body::ROLE_MEMBER => "member",
                body::ROLE_PHONE => "phone",
                body::ROLE_WATCH => "watch",
                body::ROLE_LEAF => "leaf",
                _ => "unknown",
            };
            o.insert("role".into(), Value::String(role.into()));
            o.insert("rights".into(), names(d.rights, RIGHTS));
            o.insert("caps".into(), names(d.caps, CAPS));
            o.insert("os".into(), Value::from(d.os));
            o.insert(
                "store".into(),
                names(d.store, STORES).as_array().and_then(|a| a.first().cloned()).unwrap_or(Value::Null),
            );
            if let Some(a) = &d.admin {
                o.insert("admin".into(), b64_value(&a.0));
                o.insert("powers".into(), Value::from(d.powers));
                o.insert("commands".into(), Value::from(d.commands));
            }
            o.insert("root".into(), Value::Bool(st.root_device == Some(d.id)));
            o.insert("frozen".into(), Value::Bool(d.frozen));
            o.insert("guarded".into(), Value::Bool(d.guarded));
            o.insert("by_root".into(), Value::Bool(d.by_root));
            o.insert("no_secrets".into(), Value::Bool(st.no_secrets_to.contains(&d.id)));
            o.insert("nothing".into(), Value::Bool(st.nothing_to.contains(&d.id)));
            Value::Object(o)
        })
        .collect();
    m.insert("devices".into(), Value::Array(devices));
    m.insert("revoked".into(), b64s(st.revoked.iter().map(|k| &k.0)));
    m.insert("hubs".into(), b64s(st.hubs.iter().map(|d| &d.0)));
    let stop = match st.stop {
        Stop::None => "",
        Stop::Secrets => "secrets",
        Stop::Full => "full",
    };
    m.insert("stop".into(), Value::String(stop.into()));
    m.insert("stopped".into(), Value::Bool(st.stopped()));
    m.insert("halted".into(), Value::Bool(st.halted()));
    m.insert("too_old".into(), Value::Bool(st.too_old));
    m.insert("update_needed".into(), Value::Bool(st.update_needed));
    if let Some(ms) = st.ttl_ms {
        m.insert("ttl_ms".into(), Value::from(ms));
    }
    if let Some(ms) = st.secret_ttl_ms {
        m.insert("secret_ttl_ms".into(), Value::from(ms));
    }
    let conflicts: Vec<Value> = st
        .conflicts
        .iter()
        .map(|c| {
            let kind = match c.kind {
                ConflictKind::Admins => "admins",
                ConflictKind::Fork => "fork",
                ConflictKind::TwoHistories => "two_histories",
                ConflictKind::Admits => "admits",
                ConflictKind::Ids => "ids",
            };
            Value::Object(Map::from_iter([
                ("kind".into(), Value::String(kind.into())),
                ("records".into(), b64s(c.records.iter().map(|r| &r.0))),
                ("signers".into(), b64s(c.signers.iter().map(|k| &k.0))),
            ]))
        })
        .collect();
    m.insert("conflicts".into(), Value::Array(conflicts));
    let changes: Vec<Value> = st
        .changes
        .iter()
        .map(|c| {
            let state = match c.state {
                ChangeState::Effective => "effective",
                ChangeState::Void => "void",
                ChangeState::Competing => "competing",
            };
            Value::Object(Map::from_iter([
                ("record".into(), b64_value(&c.record.0)),
                ("seq".into(), Value::from(c.seq)),
                ("root".into(), b64_value(&c.root.0)),
                ("state".into(), Value::String(state.into())),
            ]))
        })
        .collect();
    m.insert("changes".into(), Value::Array(changes));
    if let Some(l) = st.list_missing {
        m.insert("list_missing".into(), b64_value(&l));
    }
    if let Some(r) = st.first_missing {
        m.insert("change_arriving".into(), b64_value(&r.0));
    }
    m.insert("newer".into(), b64s(st.newer.iter().map(|r| &r.0)));
    let notices: Vec<Value> = set
        .notices(st)
        .into_iter()
        .map(|(id, keys)| {
            Value::Object(Map::from_iter([
                ("id".into(), b64_value(&id.0)),
                ("keys".into(), b64s(keys.iter().map(|k| &k.0))),
            ]))
        })
        .collect();
    m.insert("notices".into(), Value::Array(notices));
    let (arrivals, _) = set.arrivals();
    let came_in: Vec<Value> = arrivals
        .iter()
        .map(|(id, seq, keys)| {
            Value::Object(Map::from_iter([
                ("change".into(), b64_value(&id.0)),
                ("seq".into(), Value::from(*seq)),
                ("keys".into(), b64s(keys.iter().map(|k| &k.0))),
            ]))
        })
        .collect();
    m.insert("came_in".into(), Value::Array(came_in));
    m
}

#[cfg(test)]
mod tests {
    use super::super::{ABI, call};
    use base64::Engine as _;
    use p256::ecdsa::SigningKey;
    use p256::ecdsa::signature::hazmat::PrehashSigner as _;
    use serde_json::{Value, json};

    fn ask(op: &str, args: Value) -> Value {
        let req = json!({"abi": ABI, "op": op, "args": args});
        let out = call(&serde_json::to_vec(&req).unwrap());
        serde_json::from_slice(&out).unwrap()
    }

    fn ok(op: &str, args: Value) -> Value {
        let a = ask(op, args);
        assert!(a.get("error").is_none(), "{op}: {a}");
        a["ok"].clone()
    }

    fn enc(b: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(b)
    }

    fn dec(v: &Value) -> Vec<u8> {
        base64::engine::general_purpose::STANDARD.decode(v.as_str().unwrap()).unwrap()
    }

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_slice(&[seed; 32]).unwrap()
    }

    fn public(k: &SigningKey) -> String {
        enc(k.verifying_key().to_sec1_point(false).as_bytes())
    }

    fn hash(k: &SigningKey) -> String {
        enc(&crate::records::Key::es256(dec(&Value::String(public(k)))).hash().0)
    }

    /// A call that signs in rounds with keys, as an app does; how many
    /// rounds it took comes back too.
    fn signed(op: &str, mut args: Value, keys: &[&SigningKey]) -> (Value, usize) {
        for round in 0..6 {
            let got = ok(op, args.clone());
            let Some(wanted) = got.get("sign") else { return (got, round) };
            for w in wanted.as_array().unwrap() {
                let k = keys.iter().find(|k| public(k) == w["key"].as_str().unwrap()).expect("a key asked for");
                let d: [u8; 32] = dec(&w["digest"]).try_into().unwrap();
                let sig: p256::ecdsa::Signature = k.sign_prehash(&d).unwrap();
                let sigs = args["sigs"].as_array().cloned().unwrap_or_default();
                let mut sigs = sigs;
                sigs.push(json!({"digest": w["digest"], "sig": enc(&sig.to_bytes())}));
                args["sigs"] = Value::Array(sigs);
            }
        }
        panic!("{op} asked for signatures too many times");
    }

    const SECRET: [u8; 32] = [7; 32];

    /// A group of a root phone: its set and keys.
    fn group(local: Option<&[u8; 32]>) -> Value {
        let (k1, k2) = crate::records::pq::recovery_keys(&SECRET).unwrap();
        let k1 = SigningKey::from(k1);
        let mut args = json!({
            "root": public(&key(1)),
            "recovery": public(&k1),
            "recovery2": enc(&k2.public()),
        });
        if let Some(l) = local {
            args["local"] = Value::String(enc(l));
        }
        ok("set_new", args)
    }

    fn device(member: &SigningKey, name: &str, extra: Value) -> Value {
        let mut d = json!({"type": "device", "key": public(member), "name": name, "role": "member",
            "rights": ["read", "send", "secrets"]});
        if let (Some(d), Some(e)) = (d.as_object_mut(), extra.as_object()) {
            d.extend(e.clone());
        }
        d
    }

    /// A settings record the call writes keeps the group's servers, which
    /// the call does not name.
    #[test]
    fn settings_keep_the_groups_servers() {
        use crate::records::body::{Kind, SERVER_RELAY, Server, Settings};
        let g = group(None);
        let root = key(1);
        let mut set = crate::setfile::load(&dec(&g["set"]), None).unwrap();
        let st = set.state();
        let servers = alloc::vec![Server { kind: SERVER_RELAY, endpoint: "203.0.113.9:8764".into(), pin: [5; 32] }];
        let s = Settings { servers: servers.clone(), ..Settings::default() };
        set.write_record(&st, &super::Held(root.clone()), Kind::settings(s), 1).unwrap();
        let file = enc(&crate::setfile::save(&set, None));
        let (w, _) = signed(
            "set_write",
            json!({"set": file, "signer": public(&root), "record": {"type": "settings", "shared": true}, "time_ms": 2}),
            &[&root],
        );
        let set = crate::setfile::load(&dec(&w["set"]), None).unwrap();
        let st = set.state();
        assert!(st.settings.shared, "the new record counts");
        assert_eq!(st.settings.servers, servers);
    }

    #[test]
    fn writes_adds_and_views_a_group() {
        let g = group(None);
        assert_eq!(g["devices"], json!([]));
        let root = key(1);
        // The root's own phone, then a laptop: one signature each.
        let phone = device(&key(2), "phone", json!({"role": "phone", "holds_root": true}));
        let (w, rounds) = signed(
            "set_write",
            json!({"set": g["set"], "signer": public(&root), "record": phone,
            "time_ms": 1}),
            &[&root],
        );
        assert_eq!(rounds, 1);
        let (w, _) = signed(
            "set_write",
            json!({"set": w["set"], "signer": public(&root),
            "record": device(&key(3), "laptop", json!({"caps": ["dials"]})), "time_ms": 2}),
            &[&root],
        );
        let names: Vec<&str> = w["devices"].as_array().unwrap().iter().map(|d| d["name"].as_str().unwrap()).collect();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"phone") && names.contains(&"laptop"));
        assert_eq!(w["stop"], "");

        // Another member takes the records from the first set's file.
        let recs = ok("set_records", json!({"set": w["set"]}));
        let other = group(None);
        let got = ok("set_add", json!({"set": other["set"], "records": recs["records"], "lists": recs["lists"]}));
        assert_eq!(got["devices"], w["devices"]);
        assert_eq!(got["digest"], w["digest"]);
        assert_eq!(got["stored"].as_array().unwrap().len(), 2);
        // Again: nothing new.
        let again = ok("set_add", json!({"set": got["set"], "records": recs["records"]}));
        assert_eq!(again["changed"], false);

        // Bytes that are no record are refused, and say why; so is a
        // record of another group.
        let bad = ok("set_add", json!({"set": other["set"], "records": [enc(b"not a record")]}));
        assert_eq!(bad["refused"].as_array().unwrap().len(), 1);
        let (k1, k2) = crate::records::pq::recovery_keys(&[9; 32]).unwrap();
        let foreign = ok(
            "set_new",
            json!({"root": public(&key(1)),
            "recovery": public(&SigningKey::from(k1)), "recovery2": enc(&k2.public())}),
        );
        let got = ok("set_add", json!({"set": foreign["set"], "records": recs["records"]}));
        assert_eq!(got["devices"], json!([]));
        assert!(got["refused"].as_array().unwrap().iter().all(|r| r["why"] == "group"), "{}", got["refused"]);

        // Where peers stand.
        let st = ok("set_standing", json!({"set": w["set"], "own": public(&key(2)), "peer": public(&key(3))}));
        assert_eq!(st["standing"], "member");
        let st = ok("set_standing", json!({"set": w["set"], "own": public(&key(2)), "peer": public(&key(4))}));
        assert_eq!(st["standing"], "unknown");

        // The root removes the laptop; it then stands refused.
        let (r, _) = signed(
            "set_remove",
            json!({"set": w["set"], "signer": public(&root), "keys": [hash(&key(3))],
            "time_ms": 3}),
            &[&root],
        );
        assert_eq!(r["devices"].as_array().unwrap().len(), 1);
        assert_eq!(r["revoked"], json!([hash(&key(3))]));
        let st = ok("set_standing", json!({"set": r["set"], "own": public(&key(2)), "peer": public(&key(3))}));
        assert_eq!(st["standing"], "refused");
    }

    /// An admin's first record after its grant goes with its
    /// acknowledgement: two signatures, asked for one after the other.
    #[test]
    fn an_admin_signs_its_ack_first() {
        let root = key(1);
        let admin = key(5);
        let g = group(None);
        let phone = device(&key(2), "phone", json!({"role": "phone", "holds_root": true}));
        let (w, _) = signed(
            "set_write",
            json!({"set": g["set"], "signer": public(&root), "record": phone,
            "time_ms": 1}),
            &[&root],
        );
        let mac = device(&key(3), "mac", json!({"caps": ["admin"], "admin": public(&admin), "admin_kind": "computer"}));
        let (w, _) = signed(
            "set_write",
            json!({"set": w["set"], "signer": public(&root), "record": mac,
            "time_ms": 2}),
            &[&root],
        );
        let (w, rounds) = signed(
            "set_write",
            json!({"set": w["set"], "signer": public(&admin),
            "record": device(&key(4), "pi", json!({})), "time_ms": 3}),
            &[&admin],
        );
        assert_eq!(rounds, 2, "the ack's digest, then the record's");
        assert_eq!(w["records"].as_array().unwrap().len(), 2);
        assert!(w["devices"].as_array().unwrap().iter().any(|d| d["name"] == "pi"));
        // A key that is no admin writes nothing: refused before or after
        // its signature.
        let args = json!({"set": w["set"], "signer": public(&key(4)), "record": device(&key(6), "x", json!({})),
            "time_ms": 4});
        let first = ask("set_write", args.clone());
        let refused = match first["ok"].get("sign") {
            None => first,
            Some(w) => {
                let d: [u8; 32] = dec(&w[0]["digest"]).try_into().unwrap();
                let sig: p256::ecdsa::Signature = key(4).sign_prehash(&d).unwrap();
                let mut a = args;
                a["sigs"] = json!([{"digest": w[0]["digest"], "sig": enc(&sig.to_bytes())}]);
                ask("set_write", a)
            }
        };
        assert_eq!(refused["error"]["name"], "body", "{refused}");
    }

    /// The set file keeps the set, and pinned to a local key it is refused
    /// under another one.
    #[test]
    fn the_file_is_pinned() {
        let local = [3u8; 32];
        let g = group(Some(&local));
        let root = key(1);
        let phone = device(&key(2), "phone", json!({"role": "phone", "holds_root": true}));
        let (w, _) = signed(
            "set_write",
            json!({"set": g["set"], "local": enc(&local), "signer": public(&root),
            "record": phone, "time_ms": 1}),
            &[&root],
        );
        let v = ok("set_view", json!({"set": w["set"], "local": enc(&local)}));
        assert_eq!(v["digest"], w["digest"]);
        let err = ask("set_view", json!({"set": w["set"], "local": enc(&[4u8; 32])}));
        assert_eq!(err["error"]["name"], "saved");
        // Without the local key every record is verified, and it reads.
        assert_eq!(ok("set_view", json!({"set": w["set"]}))["digest"], w["digest"]);
        // A file that is not one.
        assert_eq!(ask("set_view", json!({"set": enc(b"\xa0")}))["error"]["name"], "saved");
    }

    /// A change of root by the recovery sheet: the preview lists who stays,
    /// and the change makes the new root.
    #[test]
    fn changes_the_root() {
        let root = key(1);
        let g = group(None);
        let phone = device(&key(2), "phone", json!({"role": "phone", "holds_root": true}));
        let (w, _) = signed(
            "set_write",
            json!({"set": g["set"], "signer": public(&root), "record": phone,
            "time_ms": 1}),
            &[&root],
        );
        let (w, _) = signed(
            "set_write",
            json!({"set": w["set"], "signer": public(&root),
            "record": device(&key(3), "laptop", json!({})), "time_ms": 2}),
            &[&root],
        );
        let p = ok("set_change_preview", json!({"set": w["set"], "leave_out": [hash(&key(2))]}));
        let lines = p["preview"].as_array().unwrap();
        assert!(lines.iter().any(|l| l["outcome"] == "out"));
        assert!(lines.iter().any(|l| l["outcome"] == "stays"));

        let new_root = key(8);
        let new_phone = device(&key(9), "new phone", json!({"role": "phone", "holds_root": true}));
        let (c, _) = signed(
            "set_change",
            json!({"set": w["set"], "recovery_secret": enc(&SECRET),
            "new_root": public(&new_root), "device": new_phone, "leave_out": [hash(&key(2))], "time_ms": 10}),
            &[&new_root],
        );
        assert_eq!(c["roots"].as_array().unwrap().len(), 2);
        assert_eq!(c["roots"][1], hash(&new_root));
        let names: Vec<&str> = c["devices"].as_array().unwrap().iter().map(|d| d["name"].as_str().unwrap()).collect();
        assert!(names.contains(&"laptop") && names.contains(&"new phone") && !names.contains(&"phone"), "{names:?}");
        // Another member applies it from the records and the list.
        let recs = ok("set_records", json!({"set": c["set"]}));
        let other = ok("set_add", json!({"set": w["set"], "records": recs["records"], "lists": recs["lists"]}));
        assert_eq!(other["roots"], c["roots"]);
        // Both files read back to what they said, what came in through
        // the change included.
        for v in [&c, &other] {
            let mut back = ok("set_view", json!({"set": v["set"]}));
            let mut want = v.clone();
            for m in [&mut back, &mut want] {
                for f in ["set", "records", "stored", "refused", "changed", "list", "again", "blind"] {
                    m.as_object_mut().unwrap().remove(f);
                }
            }
            assert_eq!(back, want);
        }
        // A sheet that is not the group's is refused.
        let err = ask(
            "set_change",
            json!({"set": w["set"], "recovery_secret": enc(&[8; 32]),
            "new_root": public(&new_root), "device": device(&key(9), "p", json!({})), "time_ms": 10}),
        );
        assert_eq!(err["error"]["name"], "request");
    }
}
