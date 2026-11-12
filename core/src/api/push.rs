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
use crate::format::{cbor, frame};
use crate::keystore::{Epoch, KeyStore};
use crate::push::{self, Body, On, Registration, UnifiedPush};
use crate::records::eval::State;
use crate::records::key::{DeviceId, Key};

/// Runs a push operation, or None when `op` is not one.
pub(super) fn dispatch(op: &str, args: &Value) -> Option<Result<Vec<u8>, Refusal>> {
    let parse = |a: &Value| a.clone();
    Some(match op {
        "push_key" => Ok(new_key()),
        "push_limits" => serde_json::from_value(parse(args)).map_err(bad_args).map(limits),
        "push_registration" => serde_json::from_value(parse(args)).map_err(bad_args).and_then(registration),
        "push_open" => serde_json::from_value(parse(args)).map_err(bad_args).and_then(open),
        _ => return None,
    })
}

fn refused(e: impl core::fmt::Display, message: &str) -> Refusal {
    refuse(Code::Push, Error::msg(e.to_string()).context(message.to_string()))
}

/// `push_key`: a new push key, 32 random bytes. The phone draws one per
/// group and a new one whenever it registers again after a removal.
fn new_key() -> Vec<u8> {
    let key = Zeroizing::new(crate::certs::random_bytes::<32>());
    let mut m = Map::new();
    m.insert("key".into(), b64_value(&key[..]));
    json(Value::Object(m))
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
    seq: u64,
    kinds: u64,
    #[serde(default)]
    env: Option<u64>,
    #[serde(default, with = "b64::opt")]
    token: Option<Vec<u8>>,
    #[serde(default)]
    unifiedpush: Option<UpArgs>,
    #[serde(default, with = "b64::secret::opt")]
    key: Option<Zeroizing<Vec<u8>>>,
}

/// `push_registration`: the frame of message `push` (t 28) the phone sends
/// over each member connection of the group; `kinds` 0 turns push off.
fn registration(a: RegistrationArgs) -> Result<Vec<u8>, Refusal> {
    const BAD: &str = "The push registration cannot be made.";
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
        Some(On { token, env, key: Zeroizing::new(key) })
    };
    let frame = Registration { seq: a.seq, kinds: a.kinds, on }.write();
    // The frame is checked as a member reads it.
    let msg = frame::read(&frame, frame::LIMIT_MEMBER).map_err(|r| refused(r, BAD))?;
    Registration::read(&msg.map).map_err(|r| refused(r, BAD))?;
    let mut m = Map::new();
    m.insert("frame".into(), b64_value(&frame));
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
    #[serde(default)]
    halted: bool,
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
    match body {
        Body::Copy(reduced) => copy(&a, &me, &reduced, &mut m),
        Body::Waits { id, origin } => {
            m.insert("kind".into(), Value::from("waits"));
            m.insert("id".into(), b64_value(&id));
            m.insert("origin".into(), b64_value(&origin));
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
    let content = if a.halted { None } else { copies::open(&checked, me, &store, &state).ok() };
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
