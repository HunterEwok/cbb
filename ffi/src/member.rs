// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The member inside a phone's app (the Aurora app, the iPhone and Android
//! apps): cbb's node (`cbb_member::phone`) with the app's key,
//! which stays where the app keeps it and signs through the callback the
//! join takes too. The node runs on threads of its own: it dials the
//! members mDNS finds or the app hands in, syncs with them, and calls the
//! app back with each event (`Event`). The app asks it everything else
//! through one call, `cbb_member_call`, a JSON request `{op, args}` and its
//! answer, as `cbb_call` asks the core (docs/core-api.md, "The member").

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use cbb_core::authority::{Body, Record};
use cbb_core::certs::{self, Cert, DeviceId};
use cbb_core::clip::{Event as Copy, Kind};
use cbb_core::error::{Error, Result};
use cbb_core::identity::Identity;
use cbb_core::manage::{Change, Order, Signer};
use cbb_core::media::Part;
use cbb_core::root::{self, Setting};
use cbb_core::takeover::How;
use cbb_core::wire::CommandResult;
use cbb_member::content::Source;
use cbb_member::node::{Peer, WriteReq};
use cbb_member::phone::{self, Listen, Member as Node};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::join::{AppKey, SignFn, answer};

/// Gets an event as JSON bytes, on one of the member's threads.
pub use crate::join::EventFn;

/// The app's keys for the servers (cbb_member_servers): op HAS answers 0
/// when the app holds the key name, PUBLIC writes its public point (SEC1,
/// 65 bytes) to out, making the key first when there is none, SIGN writes
/// the key's signature (DER) of the 32-byte digest to out, and KEEP drops
/// every key but those name lists, one a line; out has room for 72 bytes,
/// and out_len gets how many it holds. Any other answer than 0 is a
/// failure.
pub type KeysFn = unsafe extern "C" fn(
    ctx: *mut core::ffi::c_void,
    op: i32,
    name: *const u8,
    name_len: usize,
    digest: *const u8,
    out: *mut u8,
    out_len: *mut usize,
) -> i32;

const KEYS_HAS: i32 = 0;
const KEYS_PUBLIC: i32 = 1;
const KEYS_SIGN: i32 = 2;
const KEYS_KEEP: i32 = 3;

/// The app's keys for the servers behind its callback.
#[derive(Clone, Copy)]
struct AppKeys {
    f: KeysFn,
    ctx: usize,
}

impl AppKeys {
    /// Calls the app with op for the key name; the bytes it wrote, or its
    /// answer when it is not 0.
    fn call(&self, op: i32, name: &str, digest: Option<&[u8; 32]>) -> core::result::Result<Vec<u8>, i32> {
        let mut out = [0u8; 72];
        let mut n = 0usize;
        // SAFETY: the app gave a callback valid for the rest of the process
        // that reads name_len bytes at name, 32 at digest when it is not
        // null, and writes at most 72 bytes at out.
        let rc = unsafe {
            (self.f)(
                self.ctx as *mut core::ffi::c_void,
                op,
                name.as_ptr(),
                name.len(),
                digest.map_or(core::ptr::null(), |d| d.as_ptr()),
                out.as_mut_ptr(),
                &mut n,
            )
        };
        if rc != 0 {
            return Err(rc);
        }
        Ok(out.get(..n).unwrap_or_default().to_vec())
    }
}

/// One key for the servers that the app holds.
struct HeldKey {
    keys: AppKeys,
    name: String,
    public: Vec<u8>,
}

impl cbb_core::identity::ExternalKey for HeldKey {
    fn public(&self) -> Vec<u8> {
        self.public.clone()
    }

    fn sign_digest(&self, digest: &[u8; 32]) -> Result<Vec<u8>> {
        match self.keys.call(KEYS_SIGN, &self.name, Some(digest)) {
            Ok(sig) if !sig.is_empty() => Ok(sig),
            Ok(_) | Err(_) => Err(Error::msg(format!("the app's key {} did not sign", self.name))),
        }
    }
}

impl cbb_member::credentials::HeldKeys for AppKeys {
    fn has(&self, name: &str) -> bool {
        self.call(KEYS_HAS, name, None).is_ok()
    }

    fn get(&self, name: &str) -> Result<Arc<dyn cbb_core::identity::ExternalKey>> {
        let public = self
            .call(KEYS_PUBLIC, name, None)
            .map_err(|rc| Error::msg(format!("the app gave no key {name} (code {rc})")))?;
        if public.len() != 65 || public.first() != Some(&4) {
            return Err(Error::msg(format!("the app's key {name} is not a P-256 key")));
        }
        Ok(Arc::new(HeldKey { keys: *self, name: name.to_string(), public }))
    }

    fn keep(&self, names: &[String]) -> Result<()> {
        self.call(KEYS_KEEP, &names.join("\n"), None)
            .map(|_| ())
            .map_err(|rc| Error::msg(format!("the app did not drop the keys of an earlier period (code {rc})")))
    }
}

#[derive(Deserialize)]
struct StartArgs {
    /// The app's data directory: records.json, the clock's mark, the entries.
    dir: String,
    name: String,
    /// The phone's system, `aurora` or `sailfish`, its version and the
    /// app's.
    os: String,
    #[serde(default)]
    os_version: String,
    #[serde(default)]
    version: String,
    /// Where the key lives: `hardware` (the default) or `file`.
    #[serde(default = "hardware")]
    key_store: String,
    device: String,
    #[serde(with = "certs::b64")]
    public: Vec<u8>,
    /// The secret for sealed messages.
    #[serde(with = "certs::b64")]
    seal: Vec<u8>,
    #[serde(with = "certs::b64")]
    cert: Vec<u8>,
    #[serde(with = "certs::b64::opt", default)]
    issuer: Option<Vec<u8>>,
    #[serde(with = "certs::b64")]
    group_ca: Vec<u8>,
    #[serde(with = "certs::b64::list", default)]
    roots: Vec<Vec<u8>>,
    /// Members to dial at these addresses, host:port, besides those mDNS
    /// finds.
    #[serde(default)]
    peers: Vec<String>,
    /// false to find no members by mDNS (the tests).
    #[serde(default = "yes")]
    mdns: bool,
}

fn yes() -> bool {
    true
}

/// A request of cbb_member_call.
#[derive(Deserialize)]
struct Request {
    op: String,
    #[serde(default)]
    args: Value,
}

#[derive(Deserialize)]
struct CopyArgs {
    text: String,
    /// text (the default) or secret, as the control socket's copy.
    #[serde(default)]
    kind: String,
    /// The text came from the phone's clipboard (the default), not from
    /// another app's share.
    #[serde(default = "yes")]
    board: bool,
}

/// A part of images or files the app hands in: clipboard data (`type`)
/// with its bytes in `data`, or a file or folder (`path`) with the file on
/// the phone in `file`.
#[derive(Deserialize)]
struct PartArgs {
    #[serde(rename = "type", default)]
    kind: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    dir: bool,
    #[serde(with = "certs::b64::opt", default)]
    data: Option<Vec<u8>>,
    #[serde(default)]
    file: Option<String>,
}

#[derive(Deserialize)]
struct MediaArgs {
    #[serde(default)]
    text: String,
    parts: Vec<PartArgs>,
    /// The images came from the phone's clipboard; files and what another
    /// app shares do not (the default).
    #[serde(default)]
    board: bool,
}

#[derive(Deserialize)]
struct FetchArgs {
    id: String,
    /// The most bytes of the sealed blob the phone fetches.
    max: u64,
    /// A new folder to open the copy into.
    out: String,
}

#[derive(Deserialize)]
struct FoundArgs {
    key: String,
    addrs: Vec<String>,
    #[serde(default)]
    device: Option<String>,
}

#[derive(Deserialize)]
struct ToArgs {
    to: String,
    #[serde(with = "certs::b64::opt", default)]
    cert: Option<Vec<u8>>,
    #[serde(with = "certs::b64::opt", default)]
    issuer: Option<Vec<u8>>,
    #[serde(with = "certs::b64::opt", default)]
    ca: Option<Vec<u8>>,
    #[serde(default)]
    offer: Option<Value>,
}

#[derive(Deserialize)]
struct CommandArgs {
    command: Record,
    #[serde(default = "ten_seconds")]
    timeout_ms: u64,
}

/// What cbb_member_manage does: `action` is remove, rename, thaw,
/// make_admin (as the root, for a computer connected), mute, unmute,
/// paste or paste_off, for `device`; renew, which renews every
/// certificate due; or resolve, the root's decision on an alert, which
/// voids its `records`.
#[derive(Deserialize)]
struct ManageArgs {
    action: String,
    /// With recover_with_sheet: the recovery sheet's QR code.
    #[serde(default)]
    sheet: String,
    #[serde(default)]
    device: String,
    /// With make_admin: the user consented to a computer that keeps its
    /// keys in a file, which the group's key level must allow too.
    #[serde(default)]
    allow_file_key: bool,
    /// With resolve: the records an alert names, which the root voids.
    #[serde(default)]
    records: Vec<cbb_core::authority::Hash>,
    /// With rename: the new name.
    #[serde(default)]
    name: String,
    /// With mute: how long, 0 for until an unmute.
    #[serde(default)]
    for_ms: i64,
    /// With paste: `paste` (by the clipboard) or `type` (key by key).
    #[serde(default)]
    method: String,
    /// With paste: `text`, `secret` (no trace in the device's log or
    /// clipboard) or `media` (the group's copy of images or files whose ID
    /// is `text`, made just before with copy_media).
    #[serde(default)]
    kind: String,
    /// With paste: the text, or the media copy's ID.
    #[serde(default)]
    text: String,
    /// With paste: press Enter after it.
    #[serde(default)]
    enter: bool,
    /// The public point of the key that signs, SEC1 uncompressed: the
    /// phone's admin key, or the root's key when it holds the root.
    #[serde(with = "certs::b64")]
    public: Vec<u8>,
    /// The phone's admin CA, DER; absent when it signs with the root.
    #[serde(with = "certs::b64::opt", default)]
    admin_ca: Option<Vec<u8>>,
    /// How long a command waits for its result.
    #[serde(default = "ten_seconds")]
    timeout_ms: u64,
    /// With take_over, take_handed_over, recover and finish_takeover: the
    /// new root CA (DER) that root_ca made, which the app keeps first.
    #[serde(with = "certs::b64::opt", default)]
    root_ca: Option<Vec<u8>>,
    /// With finish_takeover, for a phone the records do not list yet (one
    /// that claimed with the recovery key): its system, where its keys
    /// live, and its key for sealed messages.
    #[serde(default)]
    os: String,
    #[serde(default = "hardware")]
    store: String,
    #[serde(with = "certs::b64::opt", default)]
    seal: Option<Vec<u8>>,
    /// With takeover_delay: how long a claim from a lost root waits, in
    /// milliseconds.
    #[serde(default)]
    delay_ms: Option<i64>,
    /// With key_level: proven, hardware or files.
    #[serde(default)]
    level: String,
    /// With recovery_for: the recovery key a YubiKey made, as a
    /// SubjectPublicKeyInfo (DER).
    #[serde(with = "certs::b64::opt", default)]
    key: Option<Vec<u8>>,
}

fn hardware() -> String {
    "hardware".into()
}

fn ten_seconds() -> u64 {
    10_000
}

/// How long a command for the phone itself waits for the app's answer.
const ANSWER_WAIT: Duration = Duration::from_secs(10);
/// How long a relay's call waits for the app to name its caller.
const CALLER_WAIT: Duration = Duration::from_secs(5);

#[derive(Deserialize)]
struct AnswerArgs {
    /// The command event's token.
    token: u64,
    status: String,
    #[serde(default)]
    reason: String,
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum Event<'a> {
    /// A text for the phone's clipboard; ttl_ms bounds how long a secret
    /// may stay there.
    Write {
        text: &'a str,
        kind: &'a str,
        ttl_ms: Option<u64>,
    },
    Log {
        line: &'a str,
    },
    /// Something in the member broke (a panic in one of its threads,
    /// docs/core-api.md "Panics"): what and where. The app shows it and
    /// starts the member again.
    Panic {
        details: &'a str,
    },
    /// A copy that became the group's current one from another member.
    Copy {
        copy: Value,
    },
    /// An admin, hubs or credentials message a peer sent, for the app to
    /// keep: `message` as it came.
    Message {
        from: String,
        message: Value,
    },
    /// A peer whose hello the node took, as `peers` shows it.
    Peer {
        peer: Value,
    },
    /// A tunnel offer of the group's root or an admin (docs/protocol.md,
    /// section 11), as it came.
    Tunnel {
        from: String,
        offer: Value,
    },
    /// A command for this phone itself (docs/protocol.md, section 15), which
    /// a peer sent: the app checks and carries it out, and answers with
    /// `answer` and the token within ten seconds, or it is refused.
    Command {
        token: u64,
        from: String,
        command: Value,
    },
    /// A call that came to the relay's port from the loopback port `port`:
    /// the app names the device the relay announced from there with the op
    /// `caller` and the token, within five seconds, or the call is closed;
    /// `device` is the one its certificate names.
    Caller {
        token: u64,
        port: u16,
        device: String,
    },
    /// The phone's place in the group changed: a certificate an admin
    /// renewed, or a new root. The app keeps it in its file.
    Identity {
        #[serde(with = "certs::b64")]
        cert: Vec<u8>,
        #[serde(with = "certs::b64::opt")]
        issuer: Option<Vec<u8>>,
        #[serde(with = "certs::b64::list")]
        roots: Vec<Vec<u8>>,
    },
    /// An admin muted the phone, or ended its mute: for_ms is how long it
    /// lasts, 0 for until an admin unmutes it.
    Mute {
        muted: bool,
        for_ms: i64,
        by: &'a str,
    },
}

#[derive(Deserialize)]
struct SyncArgs {
    on: bool,
    #[serde(default)]
    for_ms: i64,
}

/// A copy as the app reads it: its header, its content when this phone
/// opened it, and the key the button compares it by.
fn copy_json(ev: &Copy, key: &str) -> Value {
    json!({
        "id": ev.id,
        "origin": ev.origin,
        "age_ms": ev.age,
        "kind": ev.kind,
        "via": ev.via,
        "text": ev.text,
        "media": ev.media,
        "unread": ev.unread,
        // The devices the copy is sealed to: a paste of it must come from one.
        "readers": ev.sealed.as_ref().map(|s| s.wraps.iter().map(|w| w.to.clone()).collect::<Vec<_>>()).unwrap_or_default(),
        "key": key,
    })
}

fn peer_json(p: &Peer) -> Value {
    json!({
        "device": p.id.to_string(),
        "name": p.name,
        "role": p.role,
        "os": p.os,
        "key_store": p.key_store,
        "mode": p.mode,
        "muted": p.muted,
        "muted_for_ms": p.muted_for_ms,
        "actions": p.actions,
        "info": p.device,
        "admin_key": p.admin_key.as_deref().map(b64),
        "tunnel_key": p.tunnel_key.as_ref().map(|(k, _)| b64(k)),
        "tunnel_psk": p.tunnel_key.as_ref().map(|(_, k)| b64(k)),
        "reach": p.reach.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "records_only": p.records_only,
        "features": p.features,
        "caps": p.caps,
        "chain": p.chain.iter().map(|c| b64(c)).collect::<Vec<_>>(),
    })
}

fn part_json(p: &Part, at: &std::path::Path) -> Value {
    json!({
        "type": p.kind,
        "path": p.path,
        "dir": p.dir,
        "size": p.size,
        "file": at.to_string_lossy(),
    })
}

fn b64(b: &[u8]) -> Value {
    #[derive(Serialize)]
    struct B<'a>(#[serde(with = "certs::b64")] &'a [u8]);
    serde_json::to_value(B(b)).unwrap_or(Value::Null)
}

fn args<T: for<'de> Deserialize<'de>>(v: Value) -> Result<T> {
    serde_json::from_value(v).map_err(|e| Error::msg(format!("the request's arguments do not decode: {e}")))
}

fn device(s: &str) -> Result<DeviceId> {
    DeviceId::parse(s)
}

/// What a member port is for: `home` (every address), `tunnel` or `relay`
/// (the loopback address); None when the request names none.
fn listen_kind(v: &Value) -> Result<Option<Listen>> {
    match v.as_str() {
        None => Ok(None),
        Some("home") => Ok(Some(Listen::Home)),
        Some("tunnel") => Ok(Some(Listen::Tunnel)),
        Some("relay") => Ok(Some(Listen::Relay)),
        Some(k) => Err(Error::msg(format!("a member port is for home, tunnel or relay, not {k:?}"))),
    }
}

/// The app's callback and its context, called from the member's threads.
#[derive(Clone, Copy)]
struct Events {
    f: EventFn,
    ctx: usize,
}

impl Events {
    fn send(&self, e: &Event<'_>) {
        if let Ok(b) = serde_json::to_vec(e) {
            // SAFETY: the app gave a callback that stays valid, and may be
            // called from any thread, until cbb_member_stop returns.
            unsafe { (self.f)(self.ctx as *mut core::ffi::c_void, b.as_ptr(), b.len()) }
        }
    }
}

/// The commands for the phone itself that wait for the app's answer, by
/// token.
#[derive(Default)]
struct Answers {
    next: AtomicU64,
    waiting: Mutex<HashMap<u64, mpsc::SyncSender<CommandResult>>>,
    /// The relay's calls that wait for the app to name their caller.
    callers: Mutex<HashMap<u64, mpsc::SyncSender<Option<String>>>>,
}

/// The lock's value, also after a thread panicked holding it.
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

pub struct Member {
    node: Arc<Node>,
    answers: Arc<Answers>,
    events: Events,
    /// Set by stop: the member stays allocated, and answers no more.
    stopped: std::sync::atomic::AtomicBool,
    /// The guard's number for the member's panic events.
    panics: u64,
}

impl Member {
    /// Starts the member from the app's request, with its key's callback
    /// and its events' callback; with the answer.
    pub fn start(request: &[u8], sign: SignFn, events: EventFn, ctx: usize) -> (Option<Member>, Vec<u8>) {
        let made = (|| -> Result<Member> {
            let a: StartArgs = serde_json::from_slice(request)
                .map_err(|e| Error::msg(format!("the member's request does not decode: {e}")))?;
            let key = Arc::new(AppKey { public: a.public, sign, ctx });
            let identity = Identity {
                id: DeviceId::parse(&a.device)?,
                key: Vec::new(),
                external: Some(key),
                cert: Cert::parse(&a.cert)?,
                issuer: a.issuer.as_deref().map(Cert::parse).transpose()?,
                group_ca: Cert::parse(&a.group_ca)?,
                roots: a.roots.iter().map(|d| Cert::parse(d)).collect::<Result<_>>()?,
            };
            identity.check()?;
            let peers = a
                .peers
                .iter()
                .map(|p| p.parse().map_err(|_| Error::msg(format!("{p} is not an address host:port"))))
                .collect::<Result<Vec<std::net::SocketAddr>>>()?;
            let ev = Events { f: events, ctx };
            let node = Node::start(phone::Config {
                identity,
                name: a.name,
                os: a.os,
                os_version: a.os_version,
                version: a.version,
                key_store: a.key_store,
                state_dir: PathBuf::from(a.dir),
                peers,
                mdns: a.mdns,
                seal_secret: a.seal,
                on_write: Box::new(move |w: WriteReq| {
                    let kind = match w.kind {
                        Kind::Text => "text",
                        Kind::Secret => "secret",
                        Kind::Media => "media",
                    };
                    let ttl_ms = w.ttl.map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
                    ev.send(&Event::Write { text: &w.text, kind, ttl_ms });
                }),
                keep_identity: Box::new(move |id: &Identity| {
                    ev.send(&Event::Identity {
                        cert: id.cert.der.clone(),
                        issuer: id.issuer.as_ref().map(|c| c.der.clone()),
                        roots: id.roots.iter().map(|c| c.der.clone()).collect(),
                    });
                    Ok(())
                }),
                on_mute: Box::new(move |until: Option<i64>, by: &str| {
                    let for_ms = until
                        .map_or(0, |u| if u == 0 { 0 } else { u.saturating_sub(cbb_member::uptime::wall_ms()).max(1) });
                    ev.send(&Event::Mute { muted: until.is_some(), for_ms, by });
                }),
                log: Arc::new(move |line: &str| ev.send(&Event::Log { line })),
            })?;
            node.on_change(Box::new(move |c: &Copy| {
                let key = cbb_member::button::key_of(c).unwrap_or_default();
                ev.send(&Event::Copy { copy: copy_json(c, &key) });
            }));
            node.on_message(Box::new(move |from, m| {
                ev.send(&Event::Message {
                    from: from.to_string(),
                    message: serde_json::to_value(m).unwrap_or(Value::Null),
                });
            }));
            node.on_peer(Box::new(move |p: &Peer| ev.send(&Event::Peer { peer: peer_json(p) })));
            node.on_tunnel(Box::new(move |from, offer, _| {
                ev.send(&Event::Tunnel { from: from.to_string(), offer: offer.clone() });
            }));
            let answers = Arc::new(Answers::default());
            let waiting = answers.clone();
            node.on_command(Arc::new(move |from: &DeviceId, r: &Record| {
                let id = serde_json::from_slice::<Value>(&r.body)
                    .ok()
                    .and_then(|v| v.get("id").and_then(Value::as_str).map(String::from))
                    .unwrap_or_default();
                let token = waiting.next.fetch_add(1, Ordering::SeqCst);
                let (tx, rx) = mpsc::sync_channel(1);
                lock(&waiting.waiting).insert(token, tx);
                ev.send(&Event::Command {
                    token,
                    from: from.to_string(),
                    command: serde_json::to_value(r).unwrap_or(Value::Null),
                });
                let got = rx.recv_timeout(ANSWER_WAIT);
                lock(&waiting.waiting).remove(&token);
                let mut res = got.unwrap_or_else(|_| CommandResult {
                    status: "refused".into(),
                    reason: "the app did not answer".into(),
                    ..CommandResult::default()
                });
                res.id = id;
                res
            }));
            let panics = crate::guard::watch(Box::new(move |details: &str| ev.send(&Event::Panic { details })));
            Ok(Member {
                node: Arc::new(node),
                answers,
                events: ev,
                stopped: std::sync::atomic::AtomicBool::new(false),
                panics,
            })
        })();
        match made {
            Ok(m) => (Some(m), answer(Ok(serde_json::json!({})))),
            Err(e) => (None, answer::<()>(Err(e))),
        }
    }

    /// Answers a request of cbb_member_call, `{op, args}`.
    pub fn call(&self, request: &[u8]) -> Vec<u8> {
        answer((|| -> Result<Value> {
            if self.stopped.load(Ordering::SeqCst) {
                return Err(Error::msg("the member stopped"));
            }
            let r: Request = serde_json::from_slice(request)
                .map_err(|e| Error::msg(format!("the member's request does not decode: {e}")))?;
            self.op(&r.op, r.args)
        })())
    }

    fn op(&self, op: &str, a: Value) -> Result<Value> {
        /// The argument k, null when the request leaves it out.
        fn arg<'v>(a: &'v Value, k: &str) -> &'v Value {
            a.get(k).unwrap_or(&Value::Null)
        }
        let n = &self.node;
        let done = || Ok(json!({}));
        match op {
            // The clipboard and the button (docs/design.md, "The one button").
            "copy" => {
                let a: CopyArgs = args(a)?;
                let secret = match a.kind.as_str() {
                    "" | "text" => false,
                    "secret" => true,
                    other => return Err(Error::msg(format!("a copy is a text or a secret, not {other:?}"))),
                };
                n.copy(&a.text, secret, a.board)?;
                done()
            }
            "copy_media" => {
                let a: MediaArgs = args(a)?;
                let parts = a
                    .parts
                    .into_iter()
                    .map(|p| {
                        let src = match (p.dir, p.data, p.file) {
                            (true, _, _) => Source::Dir,
                            (false, Some(d), _) => Source::Bytes(d),
                            (false, None, Some(f)) => Source::File(PathBuf::from(f)),
                            _ => return Err(Error::msg("a part with neither data nor a file")),
                        };
                        Ok((Part { kind: p.kind, path: p.path, dir: p.dir, ..Part::default() }, src))
                    })
                    .collect::<Result<Vec<_>>>()?;
                let c = n.copy_media(&a.text, parts, a.board)?;
                Ok(json!({ "copy": copy_json(&c.event, &c.key) }))
            }
            "current" => Ok(json!({ "copy": n.current().map(|c| copy_json(&c.event, &c.key)) })),
            "waiting" => Ok(json!({ "copy": n.waiting().map(|c| copy_json(&c.event, &c.key)) })),
            "took" => {
                let id = arg(&a, "id").as_str().ok_or_else(|| Error::msg("took needs the copy's id"))?;
                n.took(id);
                done()
            }
            "sends" => {
                let board = arg(&a, "board").as_str().unwrap_or_default();
                Ok(json!({ "sends": n.sends(board) }))
            }
            "fetch" => {
                let a: FetchArgs = args(a)?;
                let parts = n.fetch(&a.id, a.max, std::path::Path::new(&a.out))?;
                Ok(json!({ "parts": parts.iter().map(|(p, at)| part_json(p, at)).collect::<Vec<_>>() }))
            }
            "served" => {
                let id = arg(&a, "id").as_str().ok_or_else(|| Error::msg("served needs the copy's id"))?;
                let (served, size) = n.served(id).unwrap_or((0, 0));
                Ok(json!({ "served": served, "size": size }))
            }
            // Finding the members, listening, the app's life.
            "found" => {
                let a: FoundArgs = args(a)?;
                let addrs = a
                    .addrs
                    .iter()
                    .map(|s| s.parse().map_err(|_| Error::msg(format!("{s} is not an address host:port"))))
                    .collect::<Result<Vec<std::net::SocketAddr>>>()?;
                let dev = a.device.as_deref().map(device).transpose()?;
                n.found(&a.key, addrs, dev);
                done()
            }
            "lost" => {
                n.lost(arg(&a, "key").as_str().unwrap_or_default());
                done()
            }
            "listen" => {
                let port =
                    u16::try_from(arg(&a, "port").as_u64().unwrap_or(0)).map_err(|_| Error::msg("not a port"))?;
                let what = listen_kind(arg(&a, "kind"))?.unwrap_or(Listen::Home);
                let admit = (what == Listen::Relay).then(|| self.caller_check());
                Ok(json!({ "port": n.listen(what, port, admit)? }))
            }
            "unlisten" => {
                n.unlisten(listen_kind(arg(&a, "kind"))?);
                done()
            }
            "caller" => {
                let token = arg(&a, "token").as_u64().ok_or_else(|| Error::msg("caller needs the call's token"))?;
                let tx = lock(&self.answers.callers).remove(&token);
                let tx = tx.ok_or_else(|| Error::msg("no call waits for that caller"))?;
                let _ = tx.try_send(arg(&a, "device").as_str().map(String::from));
                done()
            }
            "pause" => {
                n.pause();
                done()
            }
            "resume" => {
                n.resume();
                done()
            }
            "wait" => {
                let ms = arg(&a, "timeout_ms").as_u64().unwrap_or(5_000).min(60_000);
                Ok(json!({ "connected": n.wait_connected(Duration::from_millis(ms)) }))
            }
            "set_mute" => {
                n.set_mute(arg(&a, "until_ms").as_i64());
                done()
            }
            // The phone's sync: `{"on": false, "for_ms"}` (0 for until it
            // is turned on) or `{"on": true}`.
            "sync" => {
                let a: SyncArgs = args(a)?;
                if a.on && a.for_ms != 0 {
                    return Err(Error::msg("a time goes only with sync off"));
                }
                n.set_sync(a.on, a.for_ms)?;
                Ok(self.state())
            }
            "muted" => Ok(self.state()),
            // What the app shows.
            "peers" => {
                let all = arg(&a, "all").as_bool().unwrap_or(false);
                let ps = if all { n.all_peers() } else { n.peers() };
                Ok(json!({ "peers": ps.iter().map(peer_json).collect::<Vec<_>>() }))
            }
            "records" => Ok(json!({ "records": n.records() })),
            // The root's settings: {delay_ms, key_level, recovery, handed_to}.
            "root_view" => Ok(serde_json::to_value(n.root_view()).map_err(|e| Error::msg(e.to_string()))?),
            // The phone's own part.
            "answer" => {
                let a: AnswerArgs = args(a)?;
                let tx = lock(&self.answers.waiting).remove(&a.token);
                let tx = tx.ok_or_else(|| Error::msg("no command waits for that answer"))?;
                let _ = tx.try_send(CommandResult { status: a.status, reason: a.reason, ..CommandResult::default() });
                done()
            }
            // A command event's record, checked and opened (docs/core-api.md).
            "check_command" => {
                let c: Record = args(arg(&a, "command").clone())?;
                n.check_command(&c).map_err(|e| e.context("The command is refused."))
            }
            "tunnel_key" => {
                #[derive(Deserialize)]
                struct K {
                    #[serde(with = "certs::b64::opt", default)]
                    key: Option<Vec<u8>>,
                    #[serde(with = "certs::b64::opt", default)]
                    psk: Option<Vec<u8>>,
                }
                let k: K = args(a)?;
                let keys = match (k.key, k.psk) {
                    (Some(key), Some(psk)) if key.len() == 32 && psk.len() == 32 => Some((key, psk)),
                    (None, None) => None,
                    _ => return Err(Error::msg("a tunnel key and its preshared key are 32 bytes each")),
                };
                n.set_tunnel_key(keys);
                done()
            }
            "evidence" => {
                let list = arg(&a, "evidence").as_array().cloned().unwrap_or_default();
                n.set_evidence(list);
                done()
            }
            "disconnect" => {
                n.disconnect(&device(arg(&a, "device").as_str().unwrap_or_default())?);
                done()
            }
            // What the group's records stop, for the alerts card.
            "alerts" => Ok(json!({ "alerts": n.alerts() })),
            // Why the phone does not sync, for the screen in the advanced
            // settings (docs/apps.md, "Why it does not sync"); `away`, the
            // facts of a tunnel the app runs itself, or none.
            "why" => {
                let away: Option<cbb_core::why::AwayFacts> = args(arg(&a, "away").clone())?;
                Ok(json!({ "why": n.why(away) }))
            }
            // Sync away from home: on with new tunnel keys, or off; and its
            // state, null while it is off.
            "away" => {
                if arg(&a, "on").as_bool().unwrap_or(false) {
                    n.away_on()?
                } else {
                    n.away_off()?
                }
                Ok(json!({ "away": n.away_status() }))
            }
            "away_status" => Ok(json!({ "away": n.away_status() })),
            // Once the member serves the servers (cbb_member_servers): this
            // phone as one of the group's hubs, or not; the blind relay; and
            // whether the root's next period waits for the app.
            "hub" => {
                let s = |k: &str| arg(&a, k).as_str().unwrap_or_default().to_string();
                let b = |k: &str| arg(&a, k).as_bool().unwrap_or(false);
                n.hub_on(&s("forwarder"), &s("key"), b("obfuscate_off"), b("vless_off"))?;
                Ok(json!({ "away": n.away_status() }))
            }
            "hub_off" => {
                n.hub_off(arg(&a, "anyway").as_bool().unwrap_or(false))?;
                Ok(json!({ "away": n.away_status() }))
            }
            "relay" => {
                let s = |k: &str| arg(&a, k).as_str().unwrap_or_default().to_string();
                n.relay(&s("relay"), &s("key"))?;
                Ok(json!({ "away": n.away_status() }))
            }
            "servers" => Ok(json!({ "period_due": n.period_due() })),
            // The phone joined by a remote invitation and stored its
            // identity: sync away from home goes on, and the member offers
            // its tunnel key to the hub through the invitation's guest
            // tunnel.
            "joined_by_invite" => {
                n.joined_by_invite(arg(&a, "invite").as_str().unwrap_or_default())?;
                Ok(json!({ "away": n.away_status() }))
            }
            // Every device of the group as the app shows it.
            "devices" => Ok(json!({ "devices": devices_of(n) })),
            // The tiles to draw, and the user's change of their order
            // (docs/apps.md, "What the member shows").
            // The view's warnings are why: `away` is the app's own tunnel.
            "view" => {
                let away: Option<cbb_core::why::AwayFacts> = args(arg(&a, "away").clone())?;
                Ok(json!({ "view": n.view(devices_of(n), None, away)? }))
            }
            "arrange" => {
                let op: cbb_core::arrange::Op = args(arg(&a, "arrange").clone())?;
                let away: Option<cbb_core::why::AwayFacts> = args(arg(&a, "away").clone())?;
                Ok(json!({ "view": n.view(devices_of(n), Some(&op), away)? }))
            }
            // What an admin's app signed.
            "add_records" => {
                let rs: Vec<Record> = args(arg(&a, "records").clone())?;
                n.add_records(&rs);
                done()
            }
            "command" => {
                let a: CommandArgs = args(a)?;
                let res = n.command(&a.command, Duration::from_millis(a.timeout_ms.min(60_000)))?;
                Ok(json!({ "result": res }))
            }
            "send_cert" => {
                let a: ToArgs = args(a)?;
                let cert = a.cert.ok_or_else(|| Error::msg("send_cert needs the certificate"))?;
                Ok(json!({ "sent": n.send_cert(&device(&a.to)?, &cert, a.issuer.as_deref()) }))
            }
            "send_admin_ca" => {
                let a: ToArgs = args(a)?;
                let ca = a.ca.ok_or_else(|| Error::msg("send_admin_ca needs the admin CA"))?;
                Ok(json!({ "sent": n.send_admin_ca(&device(&a.to)?, &ca) }))
            }
            "send_tunnel" => {
                let a: ToArgs = args(a)?;
                let offer = a.offer.ok_or_else(|| Error::msg("send_tunnel needs the offer"))?;
                Ok(json!({ "sent": n.send_tunnel(&device(&a.to)?, &offer) }))
            }
            "send_hubs" => {
                let only = arg(&a, "to").as_str().map(device).transpose()?;
                let to = n.send_hubs(arg(&a, "share"), only.as_ref());
                Ok(json!({ "to": to.iter().map(ToString::to_string).collect::<Vec<_>>() }))
            }
            "send_credentials" => {
                let only = arg(&a, "to").as_str().map(device).transpose()?;
                let except = arg(&a, "except").as_str().map(device).transpose()?;
                let to = n.send_credentials(arg(&a, "credentials"), only.as_ref(), except.as_ref());
                Ok(json!({ "to": to.iter().map(ToString::to_string).collect::<Vec<_>>() }))
            }
            _ => Err(Error::msg(format!("the member has no operation {op:?}"))),
        }
    }

    /// The check of the relay's port: the app names the device the relay
    /// announced from the call's loopback port, and the call is served only
    /// when its certificate names the same device.
    fn caller_check(&self) -> cbb_member::node::Admit {
        let (answers, ev) = (self.answers.clone(), self.events);
        Arc::new(move |port: u16, id: &DeviceId| {
            let token = answers.next.fetch_add(1, Ordering::SeqCst);
            let (tx, rx) = mpsc::sync_channel(1);
            lock(&answers.callers).insert(token, tx);
            ev.send(&Event::Caller { token, port, device: id.to_string() });
            let named = rx.recv_timeout(CALLER_WAIT).ok().flatten();
            lock(&answers.callers).remove(&token);
            named.as_deref() == Some(id.as_str())
        })
    }

    /// Whether sync is off and whether an admin muted the phone:
    /// `{"sync_off", "sync_off_ms", "muted", "muted_ms"}`, the times what
    /// is left, 0 for until it is lifted.
    fn state(&self) -> serde_json::Value {
        serde_json::to_value(self.node.muted()).unwrap_or_default()
    }

    /// Makes the member serve the servers (phone::Member::serve_servers)
    /// with the app's keys for them behind keys, which must work with ctx
    /// for the rest of the process.
    pub fn servers(&self, keys: KeysFn, ctx: usize) -> Vec<u8> {
        answer((|| -> Result<Value> {
            if self.stopped.load(Ordering::SeqCst) {
                return Err(Error::msg("the member stopped"));
            }
            self.node.serve_servers(Arc::new(AppKeys { f: keys, ctx }))?;
            Ok(json!({}))
        })())
    }

    /// Stops the member once; calls answer that it stopped from then on.
    pub fn stop(&self) {
        if !self.stopped.swap(true, Ordering::SeqCst) {
            crate::guard::unwatch(self.panics);
            self.node.stop();
        }
    }

    /// Signs a change to a device of the group, or a command for it, with
    /// the key the request's `public` names, the phone's admin key or the
    /// root's (ManageArgs), and answers `{}`, or `{"result"}` for a
    /// command.
    pub fn manage(&self, request: &[u8], sign: SignFn, ctx: usize) -> Vec<u8> {
        answer((|| -> Result<Value> {
            let a: ManageArgs = serde_json::from_slice(request)
                .map_err(|e| Error::msg(format!("the manage request does not decode: {e}")))?;
            let identity = self.node.identity();
            let me = identity.id.to_string();
            let key = AppKey { public: a.public.clone(), sign, ctx };
            let new_root = || a.root_ca.as_deref().ok_or_else(|| Error::msg("the action needs root_ca"));
            match a.action.as_str() {
                // A root CA for the new key public, before a claim.
                "root_ca" => {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(0));
                    let der = cbb_core::issue::root_ca(&a.public, now, &mut |tbs| {
                        cbb_core::identity::sign_external(&key, tbs)
                    })?;
                    return Ok(json!({ "root_ca": b64(&der) }));
                }
                // The new root signs once the claim took effect; until then
                // it signs nothing, and the answer is where the claim stands.
                "finish_takeover" => {
                    let der = new_root()?;
                    let state = self.node.claim_state(der);
                    if state.as_ref().is_none_or(|c| c.state != "effective") {
                        return Ok(json!({
                            "state": state.as_ref().map_or("none", |c| c.state.as_str()),
                            "left_ms": state.map_or(0, |c| c.left_ms),
                        }));
                    }
                    let root = Cert::parse(der)?;
                    if root.public_key() != a.public.as_slice() {
                        return Err(Error::msg("the key does not belong to the new root"));
                    }
                    let seal = a.seal.clone().unwrap_or_default();
                    let os = if a.os.is_empty() { "ios" } else { a.os.as_str() };
                    let name = if a.name.trim().is_empty() { "Phone" } else { a.name.trim() };
                    let own =
                        cbb_core::takeover::Own { name, role: "phone", caps: &[], os, store: &a.store, seal: &seal };
                    let s = Signer { ca: &root, key: &key, me: &me };
                    let cert = self.node.finish_takeover(&s, &own)?;
                    return Ok(json!({ "state": "effective", "cert": b64(&cert) }));
                }
                // The next period of the server credentials, on the root,
                // with the root key the app unlocked after asking.
                "period" => {
                    self.node.sign_period(Arc::new(AppKey { public: a.public.clone(), sign, ctx }))?;
                    return Ok(json!({ "period_due": self.node.period_due() }));
                }
                // A new phone that restored the group (cbb_restore) claims
                // it with the recovery key from the sheet, which signs the
                // claim here and is not kept.
                "recover_with_sheet" => {
                    let sheet = cbb_core::recovery::read(&a.sheet).map_err(|r| Error::msg(r.message()))?;
                    let der = sheet.cert.as_deref().ok_or_else(|| Error::msg(cbb_member::restore::NEEDS_QR))?;
                    let ca = Cert::parse(der)?;
                    let pkcs8 = sheet.pkcs8().ok_or_else(|| Error::msg("the recovery key cannot be encoded"))?;
                    let key = cbb_core::identity::FileKey::new(&pkcs8)?;
                    if sheet.admin() != Some(ca.key_hash()) {
                        return Err(Error::msg("the sheet's admin CA is for another key"));
                    }
                    let s = Signer { ca: &ca, key: &key, me: &me };
                    self.node.claim(&s, How::Recovery, new_root()?)?;
                    return Ok(json!({}));
                }
                _ => {}
            }
            let ca = match &a.admin_ca {
                Some(der) => Cert::parse(der)?,
                None => identity.root().clone(),
            };
            if ca.public_key() != a.public.as_slice() {
                return Err(Error::msg("the key does not belong to the CA this phone signs with"));
            }
            let s = Signer { ca: &ca, key: &key, me: &me };
            // The root's own records (cbb_core::root).
            let rooted = |make: &dyn Fn(&cbb_core::group::Records, i64) -> Result<Record>| -> Result<Value> {
                self.node.add_root_record(make)?;
                Ok(json!({}))
            };
            match a.action.as_str() {
                "takeover_delay" => {
                    let ms = a.delay_ms.ok_or_else(|| Error::msg("the action needs delay_ms"))?;
                    return rooted(&|rs, now| root::settings(rs, &s, &Setting::Delay(ms), now));
                }
                "key_level" => {
                    rooted(&|rs, now| root::settings(rs, &s, &Setting::KeyLevel(&a.level), now))?;
                    let below = self.node.below_level(&a.level);
                    return Ok(json!({ "below": below }));
                }
                "hand_over" => return rooted(&|rs, now| root::hand_over(rs, &s, &a.device, now)),
                "remove_recovery" => return rooted(&|rs, now| root::remove_recovery(rs, &s, now)),
                // The sheet goes to the app once, with its QR code's
                // modules to show; nothing of the key stays here.
                "make_recovery" => {
                    let made = std::cell::RefCell::new(None);
                    rooted(&|rs, now| {
                        let m = root::make_recovery(rs, &s, now)?;
                        let r = m.record.clone();
                        *made.borrow_mut() = Some(m);
                        Ok(r)
                    })?;
                    let m = made.into_inner().ok_or_else(|| Error::msg("the recovery key was not made"))?;
                    let modules = crate::join::modules(&m.qr)?;
                    let admin = Body::parse(&m.record.body)?.admin.map(|h| h.0.to_vec()).unwrap_or_default();
                    return Ok(json!({ "qr": m.qr, "text": m.text, "modules": modules, "admin": b64(&admin) }));
                }
                // The recovery key a YubiKey made, which never leaves it:
                // its admin CA goes into the card's slot.
                "recovery_for" => {
                    let spki = a.key.as_deref().ok_or_else(|| Error::msg("the action needs key"))?;
                    let point = certs::p256_spki(spki)
                        .ok_or_else(|| Error::msg("the recovery key is no P-256 key"))?
                        .to_sec1_point(false)
                        .as_bytes()
                        .to_vec();
                    let ca = std::cell::RefCell::new(Vec::new());
                    rooted(&|rs, now| {
                        let (der, r) = root::recovery_for(rs, &s, &point, now)?;
                        *ca.borrow_mut() = der;
                        Ok(r)
                    })?;
                    return Ok(json!({ "admin_ca": b64(&ca.into_inner()) }));
                }
                _ => {}
            }
            let order = |o: Order| -> Result<Value> {
                let res = self.node.order(&s, &a.device, &o, Duration::from_millis(a.timeout_ms.min(60_000)))?;
                Ok(json!({ "result": res }))
            };
            match a.action.as_str() {
                "remove" => self.node.change(&s, &a.device, &Change::Remove)?,
                "rename" => self.node.change(&s, &a.device, &Change::Rename(&a.name))?,
                "thaw" => self.node.change(&s, &a.device, &Change::Thaw)?,
                "resolve" => self.node.change(&s, "", &Change::Resolve(a.records.clone()))?,
                "make_admin" => self.node.make_admin(&s, &a.device, a.allow_file_key)?,
                "renew" => return Ok(json!({ "renewed": self.node.renew(&s)? })),
                "take_over" => self.node.claim(&s, How::From(&a.device), new_root()?)?,
                "take_handed_over" => self.node.claim(&s, How::HandedOver, new_root()?)?,
                "recover" => self.node.claim(&s, How::Recovery, new_root()?)?,
                "mute" => return order(Order::Mute(a.for_ms)),
                "unmute" => return order(Order::Unmute),
                "sync_on" => return order(Order::Sync(true)),
                "sync_off" => return order(Order::Sync(false)),
                "paste" => return order(paste_order(&a)?),
                "paste_off" => return order(Order::PasteOff),
                other => return Err(Error::msg(format!("there is no action {other:?}"))),
            }
            Ok(json!({}))
        })())
    }

    /// Starts admitting the device whose QR code the app scanned
    /// (src/admit.rs), with the issuing key's callback.
    pub fn admit(&self, request: &[u8], sign: SignFn, ctx: usize) -> (Option<crate::admit::Admit>, Vec<u8>) {
        crate::admit::Admit::new(self.node.clone(), request, sign, ctx)
    }

    /// Makes a remote invitation as an admin (src/invite.rs).
    pub fn invite(&self, request: &[u8], sign: SignFn, ctx: usize) -> (Option<crate::invite::Invite>, Vec<u8>) {
        crate::invite::Invite::new(self.node.clone(), request, sign, ctx)
    }
}

/// The paste order of a manage request, as `cbb paste -on` makes it: a
/// text cleaned of what may not go in (and refused when nothing is left),
/// or a media copy's ID, which is pasted, never typed.
fn paste_order(a: &ManageArgs) -> Result<Order> {
    let mode = if a.method.is_empty() { "paste" } else { a.method.as_str() };
    if mode != "paste" && mode != "type" {
        return Err(Error::msg(format!("a paste is pasted or typed, not {mode:?}")));
    }
    let kind = if a.kind.is_empty() { "text" } else { a.kind.as_str() };
    let text = match kind {
        "text" | "secret" => phone::clean_paste(&a.text),
        "media" if mode == "paste" => a.text.clone(),
        "media" => return Err(Error::msg("images and files are pasted, not typed")),
        other => return Err(Error::msg(format!("a paste is a text, a secret or media, not {other:?}"))),
    };
    if text.is_empty() {
        return Err(Error::msg("nothing to paste: the text is empty or only control characters"));
    }
    Ok(Order::Paste { mode: mode.into(), kind: kind.into(), text, enter: a.enter })
}

/// Every device of the group as the app shows it: the same devices, in the
/// same form, as the control socket's devices answers on a computer.
fn devices_of(n: &cbb_member::phone::Member) -> Vec<cbb_member::control::Device> {
    n.device_views()
        .into_iter()
        .map(|d| cbb_member::control::Device {
            id: d.id,
            name: d.name,
            role: d.role,
            caps: d.caps,
            os: d.os,
            admin: d.admin,
            root: d.root,
            frozen: d.frozen,
            online: d.online,
            this: d.this,
            listed: d.listed,
            mode: match d.sync.as_str() {
                "on" => "shared".into(),
                "off" => "own".into(),
                _ => String::new(),
            },
            version: d.version,
            os_version: d.os_version,
            mac: d.mac,
            ..Default::default()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(method: &str, kind: &str, text: &str) -> ManageArgs {
        serde_json::from_value(json!({
            "action": "paste", "device": "pc", "public": "", "method": method, "kind": kind, "text": text, "enter": true,
        }))
        .unwrap()
    }

    #[test]
    fn paste_orders() {
        let o = paste_order(&request("", "", "ls\u{1b}[2J\r\n")).unwrap();
        assert!(
            matches!(&o, Order::Paste { mode, kind, text, enter: true } if mode == "paste" && kind == "text" && text == "ls\n"),
            "a text is cleaned"
        );
        let o = paste_order(&request("type", "secret", "pin")).unwrap();
        assert!(matches!(&o, Order::Paste { mode, kind, .. } if mode == "type" && kind == "secret"));
        let o = paste_order(&request("paste", "media", "copy-id")).unwrap();
        assert!(matches!(&o, Order::Paste { kind, text, .. } if kind == "media" && text == "copy-id"));
        for (method, kind, text) in [
            ("type", "media", "copy-id"),
            ("say", "text", "hi"),
            ("paste", "file", "hi"),
            ("paste", "text", "\u{7}\u{1b}[0m"),
            ("paste", "media", ""),
        ] {
            assert!(paste_order(&request(method, kind, text)).is_err(), "{method} {kind} {text:?} is refused");
        }
    }
}
