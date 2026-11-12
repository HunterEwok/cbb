// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The phones' push calls (format section 20.4): a new push key, the
//! limits of a platform, the frame of message `push` and opening a body
//! that arrived. The apps hold no number of the format: they ask these.
//!
//! `push_open` is what a notification extension calls. It holds only the
//! push keys, the copy-opening secrets and the origins the app last saved:
//! never the member key, which signs; the store below refuses to sign.

use alloc::string::ToString;
use alloc::vec::Vec;

use serde::Deserialize;
use serde_json::{Map, Value};
use zeroize::Zeroizing;

use super::{Code, Refusal, b64_value, bad_args, json, refuse};
use crate::certs::b64;
use crate::content::{TYPE_FILES, TYPE_MEDIA, TYPE_TEXT};
use crate::copies::{self, Opened, OriginMap};
use crate::error::Error;
use crate::format::cbor;
use crate::keystore::{Epoch, KeyStore};
use crate::push::{self, Body, On, Registration, UnifiedPush};
use crate::records::eval::State;
use crate::records::key::{DeviceId, Key};

/// Runs a push operation, or None when `op` is not one.
pub(super) fn dispatch(op: &str, args: &Value) -> Option<Result<Vec<u8>, Refusal>> {
    let parse = |a: &Value| a.clone();
    Some(match op {
        "push_key" => new_key(),
        "push_limits" => serde_json::from_value(parse(args)).map_err(bad_args).map(limits),
        "push_registration" => serde_json::from_value(parse(args)).map_err(bad_args).and_then(registration),
        "push_open" => serde_json::from_value(parse(args)).map_err(bad_args).and_then(open),
        _ => return None,
    })
}

fn refused(e: impl core::fmt::Display, message: &str) -> Refusal {
    refuse(Code::Push, Error::msg(e.to_string()).context(message.to_string()))
}

/// `push_key`: a new push key, 32 random bytes, a new send key (P-256,
/// PKCS #8) and a new slot, 16 random bytes. The phone draws a push key
/// and a slot per group (a new key whenever it registers again after a
/// membership change; the slot kept), and a send key with each new token.
fn new_key() -> Result<Vec<u8>, Refusal> {
    let key = Zeroizing::new(crate::certs::random_bytes::<32>());
    let send = Zeroizing::new(crate::identity::new_key().map_err(|e| refuse(Code::Push, e))?);
    let slot = crate::certs::random_bytes::<16>();
    let mut m = Map::new();
    m.insert("key".into(), b64_value(&key[..]));
    m.insert("send_key".into(), b64_value(&send[..]));
    m.insert("slot".into(), b64_value(&slot));
    Ok(json(Value::Object(m)))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LimitsArgs {
    env: u64,
}

/// `push_limits`: what a platform's tokens and bodies may be.
fn limits(a: LimitsArgs) -> Vec<u8> {
    let mut m = Map::new();
    m.insert("known".into(), Value::from(push::body_len(a.env).is_some()));
    m.insert("body".into(), Value::from(push::body_len(a.env).unwrap_or(0)));
    m.insert("token".into(), Value::from(push::MAX_TOKEN));
    m.insert("kinds".into(), Value::from(push::KIND_COPIES | push::KIND_EVENTS));
    json(Value::Object(m))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpArgs {
    url: alloc::string::String,
    #[serde(with = "b64")]
    p256dh: Vec<u8>,
    #[serde(with = "b64")]
    auth: Vec<u8>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistrationArgs {
    /// The number of the last registration the phone saved, if any.
    #[serde(default)]
    saved_seq: Option<u64>,
    now_ms: u64,
    kinds: u64,
    #[serde(default)]
    env: Option<u64>,
    #[serde(default, with = "b64::opt")]
    token: Option<Vec<u8>>,
    #[serde(default)]
    unifiedpush: Option<UpArgs>,
    #[serde(default, with = "b64::secret::opt")]
    key: Option<Zeroizing<Vec<u8>>>,
    /// The send key, PKCS #8.
    #[serde(default, with = "b64::secret::opt")]
    send_key: Option<Zeroizing<Vec<u8>>>,
    /// The group's slot, 16 bytes.
    #[serde(default, with = "b64::opt")]
    slot: Option<Vec<u8>>,
    /// The last challenge the push service sent to the token, 16 bytes,
    /// which the registration's signature then covers.
    #[serde(default, with = "b64::opt")]
    challenge: Option<Vec<u8>>,
}

/// `push_registration`: the frame of message `push` (t 28) the phone sends
/// over each member connection of the group, and its number, which the
/// phone saves; `kinds` 0 turns push off.
fn registration(a: RegistrationArgs) -> Result<Vec<u8>, Refusal> {
    const BAD: &str = "The push registration cannot be made.";
    let seq = push::next_seq(a.saved_seq, a.now_ms);
    let on = if a.kinds == 0 {
        None
    } else {
        let env = a.env.ok_or_else(|| refused("env is missing", BAD))?;
        let token = match (a.token, a.unifiedpush) {
            (Some(t), None) => t,
            (None, Some(up)) => {
                let p256dh: &[u8; 65] =
                    up.p256dh.as_slice().try_into().map_err(|_| refused("p256dh is not 65 bytes", BAD))?;
                let auth: &[u8; 16] =
                    up.auth.as_slice().try_into().map_err(|_| refused("auth is not 16 bytes", BAD))?;
                let t = UnifiedPush { url: &up.url, p256dh, auth }.write();
                // The service reads it so; refused here first.
                UnifiedPush::read(&t).map_err(|r| refused(r, BAD))?;
                t
            }
            _ => return Err(refused("give either token or unifiedpush", BAD)),
        };
        let key: [u8; 32] = a
            .key
            .as_ref()
            .and_then(|k| k.as_slice().try_into().ok())
            .ok_or_else(|| refused("the push key is not 32 bytes", BAD))?;
        let pkcs8 = a.send_key.as_ref().ok_or_else(|| refused("the send key is missing", BAD))?;
        let signer = crate::identity::signing_key(pkcs8).map_err(|e| refused(e, BAD))?;
        let public = signer.verifying_key().to_sec1_point(false).as_bytes().to_vec();
        let slot: [u8; 16] = a
            .slot
            .as_deref()
            .and_then(|s| s.try_into().ok())
            .ok_or_else(|| refused("the slot is not 16 bytes", BAD))?;
        let challenge: Option<[u8; 16]> = match a.challenge.as_deref() {
            None => None,
            Some(c) => Some(c.try_into().map_err(|_| refused("the challenge is not 16 bytes", BAD))?),
        };
        let signed = push::Signed { env, token: &token, slot: &slot, seq, challenge: challenge.as_ref() };
        let sig = push::sign_send(&Pkcs8Signer(signer), &signed).map_err(|e| refused(e, BAD))?;
        Some(On {
            token,
            env,
            key: Zeroizing::new(key),
            send_key: Key::es256(public),
            send_sig: sig.to_vec(),
            slot,
            challenge,
        })
    };
    // The writer gives no frame its reader would refuse.
    let frame =
        Registration { seq, kinds: a.kinds, on }.write().ok_or_else(|| refused("a field breaks its row", BAD))?;
    let mut m = Map::new();
    m.insert("frame".into(), b64_value(&frame));
    m.insert("seq".into(), Value::from(seq));
    Ok(json(Value::Object(m)))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PushKey {
    #[serde(with = "b64::secret")]
    key: Zeroizing<Vec<u8>>,
    seq: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OriginArgs {
    /// The device's member key as the records encode it.
    #[serde(with = "b64")]
    key: Vec<u8>,
    rights: u64,
    #[serde(default)]
    frozen: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SealingArgs {
    epoch: u64,
    #[serde(with = "b64::secret")]
    secret: Zeroizing<Vec<u8>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OpenArgs {
    /// The group's push keys the phone holds, the current one first.
    keys: Vec<PushKey>,
    #[serde(with = "b64")]
    body: Vec<u8>,
    #[serde(with = "b64")]
    me: Vec<u8>,
    #[serde(default)]
    origins: Vec<OriginArgs>,
    #[serde(default)]
    sealing: Vec<SealingArgs>,
    #[serde(default)]
    too_old: bool,
    /// The group is halted: nothing but the neutral hint. Needed, as are
    /// `hints_only`, `now_ms` and `window_ms`: with one left out the body
    /// is the neutral hint.
    #[serde(default)]
    halted: Option<bool>,
    /// The phone heard of a membership change (event 2, 4 or 6) since its
    /// last registration: a copy is shown only as a hint.
    #[serde(default)]
    hints_only: Option<bool>,
    /// The phone's clock, and the group's window for an incoming copy: an
    /// older copy is a hint, an event older than a day the neutral hint.
    #[serde(default)]
    now_ms: Option<u64>,
    #[serde(default)]
    window_ms: Option<u64>,
}

/// How old an event may be and still be named, and how far ahead of the
/// phone's clock its time may be.
const EVENT_AGE_MS: u64 = 86_400_000;
const EVENT_AHEAD_MS: u64 = 5 * 60_000;

/// The send key in a file, as the phone keeps it.
struct Pkcs8Signer(p256::ecdsa::SigningKey);

impl crate::identity::ExternalKey for Pkcs8Signer {
    fn public(&self) -> Vec<u8> {
        self.0.verifying_key().to_sec1_point(false).as_bytes().to_vec()
    }
    fn sign_digest(&self, digest: &[u8; 32]) -> crate::error::Result<Vec<u8>> {
        use p256::ecdsa::signature::hazmat::PrehashSigner as _;
        let sig: p256::ecdsa::Signature =
            self.0.sign_prehash(digest).map_err(|_| Error::msg("The send key cannot sign."))?;
        Ok(sig.to_der().as_bytes().to_vec())
    }
}

/// The copy-opening secrets an extension holds; it signs nothing.
struct Opener(Vec<(u64, Zeroizing<[u8; 32]>)>);

struct NoSigner;

impl crate::identity::ExternalKey for NoSigner {
    fn public(&self) -> Vec<u8> {
        Vec::new()
    }
    fn sign_digest(&self, _: &[u8; 32]) -> crate::error::Result<Vec<u8>> {
        Err(Error::msg("The notification extension signs nothing."))
    }
}

impl KeyStore for Opener {
    fn member(&self) -> &dyn crate::identity::ExternalKey {
        &NoSigner
    }
    fn sealing(&self, epoch: u64) -> Option<[u8; 32]> {
        self.0.iter().find(|(e, _)| *e == epoch).map(|(_, s)| **s)
    }
    fn epochs(&self) -> Vec<Epoch> {
        Vec::new()
    }
    fn put(&mut self, _: Epoch, _: [u8; 32]) -> crate::error::Result<()> {
        Err(Error::msg("The notification extension keeps no key."))
    }
    fn erase(&mut self, _: u64) -> crate::error::Result<()> {
        Err(Error::msg("The notification extension keeps no key."))
    }
}

/// `push_open`: the body opened with the first push key it opens with.
/// A copy shows its text only once the origin, its signature and `commit`
/// hold; anything else is a hint, which the app shows as "open the app".
fn open(a: OpenArgs) -> Result<Vec<u8>, Refusal> {
    const BAD: &str = "The notification does not open on this device.";
    let me = DeviceId::from_slice(&a.me).ok_or_else(|| refused("me is not a device ID", BAD))?;
    let mut opened = None;
    for (i, k) in a.keys.iter().enumerate() {
        let Ok(key) = <[u8; 32]>::try_from(k.key.as_slice()) else { continue };
        let key = Zeroizing::new(key);
        if let Ok(body) = push::open(&key, k.seq, &a.body) {
            opened = Some((i, body));
            break;
        }
    }
    let (key_index, body) = opened.ok_or_else(|| refused("no push key opens it", BAD))?;
    let mut m = Map::new();
    m.insert("key_index".into(), Value::from(key_index));
    // Every input the rules need, or the neutral hint.
    let (Some(now), Some(_), Some(halted), Some(_)) = (a.now_ms, a.window_ms, a.halted, a.hints_only) else {
        m.insert("kind".into(), Value::from("hint"));
        return Ok(json(Value::Object(m)));
    };
    if halted {
        m.insert("kind".into(), Value::from("hint"));
        return Ok(json(Value::Object(m)));
    }
    let fresh = |t: Option<u64>| {
        t.is_some_and(|t| now.saturating_sub(t) <= EVENT_AGE_MS && t <= now.saturating_add(EVENT_AHEAD_MS))
    };
    match body {
        Body::Copy(reduced) => copy(&a, &me, &reduced, &mut m),
        Body::Waits { id, origin } => {
            m.insert("kind".into(), Value::from("waits"));
            m.insert("id".into(), b64_value(&id));
            m.insert("origin".into(), b64_value(&origin));
        }
        Body::Event { time_ms, .. } if !fresh(time_ms) => {
            m.insert("kind".into(), Value::from("hint"));
        }
        Body::Event { id, event, device, time_ms } => {
            m.insert("kind".into(), Value::from("event"));
            m.insert("id".into(), b64_value(&id));
            m.insert("event".into(), Value::from(event));
            if let Some(d) = device {
                m.insert("device".into(), b64_value(&d));
            }
            if let Some(t) = time_ms {
                m.insert("time_ms".into(), Value::from(t));
            }
        }
        Body::Unknown(_) => {
            m.insert("kind".into(), Value::from("hint"));
        }
    }
    Ok(json(Value::Object(m)))
}

/// A copy in a body: its text when everything holds, else "waits" with
/// what the copy names, or the neutral hint.
fn copy(a: &OpenArgs, me: &DeviceId, reduced: &[u8], m: &mut Map<alloc::string::String, Value>) {
    let mut origins = OriginMap::default();
    for o in &a.origins {
        if let Ok(v) = cbor::decode(&o.key)
            && let Ok(k) = Key::read(&v)
        {
            origins.insert(k, o.rights, o.frozen);
        }
    }
    let store = Opener(
        a.sealing
            .iter()
            .filter_map(|s| <[u8; 32]>::try_from(s.secret.as_slice()).ok().map(|k| (s.epoch, Zeroizing::new(k))))
            .collect(),
    );
    let state = State { too_old: a.too_old, ..State::default() };
    let Ok(v) = cbor::decode(reduced) else {
        m.insert("kind".into(), Value::from("hint"));
        return;
    };
    let checked = match copies::check(&v, &origins) {
        Ok(c) => c,
        Err(_) => {
            m.insert("kind".into(), Value::from("hint"));
            return;
        }
    };
    m.insert("id".into(), b64_value(&checked.id));
    m.insert("origin".into(), b64_value(&checked.origin.0));
    let wall = u64::try_from(checked.time.wall).unwrap_or(0);
    let stale = match (a.now_ms, a.window_ms) {
        (Some(now), Some(window)) => now.saturating_sub(wall) > window,
        _ => true,
    };
    let hold = a.halted != Some(false) || a.hints_only != Some(false);
    let content = if hold || stale { None } else { copies::open(&checked, me, &store, &state).ok() };
    match content {
        Some(Opened::Content { content, .. }) if !content.unknown => {
            m.insert("kind".into(), Value::from("copy"));
            let ty = match content.kind {
                TYPE_TEXT => "text",
                TYPE_MEDIA => "media",
                TYPE_FILES => "files",
                _ => "other",
            };
            m.insert("type".into(), Value::from(ty));
            m.insert("secret".into(), Value::from(content.is_secret()));
            if let Some(t) = content.ttl_ms() {
                m.insert("ttl_ms".into(), Value::from(t));
            }
            if let Some(text) = content.text {
                m.insert("text".into(), Value::from(text));
            }
        }
        _ => {
            m.insert("kind".into(), Value::from("waits"));
        }
    }
}
