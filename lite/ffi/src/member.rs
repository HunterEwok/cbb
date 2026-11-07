// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The member inside a phone's app (the Aurora app, the iPhone and Android
//! apps): the lite member's node (`cbb_lite::phone`) with the app's key,
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

use cbb_core::authority::Record;
use cbb_core::certs::{self, Cert, DeviceId};
use cbb_core::clip::{Event as Copy, Kind, Mode};
use cbb_core::error::{Error, Result};
use cbb_core::identity::Identity;
use cbb_core::manage::{Change, Order, Signer};
use cbb_core::media::Part;
use cbb_core::wire::CommandResult;
use cbb_lite::content::Source;
use cbb_lite::node::{Peer, WriteReq};
use cbb_lite::phone::{self, Listen, Member as Node};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::join::{AppKey, SignFn, answer};

/// Gets an event as JSON bytes, on one of the member's threads.
pub use crate::join::EventFn;

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

fn hardware() -> String {
    "hardware".into()
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
    #[serde(default)]
    secret: bool,
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
/// make_admin (as the root, for a computer connected), mute or unmute, for
/// `device`; renew, which renews every certificate due; or resolve, the
/// root's decision on an alert, which voids its `records`.
#[derive(Deserialize)]
struct ManageArgs {
    action: String,
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
struct PauseArgs {
    pause: bool,
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

#[derive(Serialize)]
struct DeviceAnswer {
    device: String,
    name: String,
    role: String,
    os: String,
    admin: bool,
    root: bool,
    frozen: bool,
    online: bool,
    #[serde(rename = "self")]
    this: bool,
    listed: bool,
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
                        .map_or(0, |u| if u == 0 { 0 } else { u.saturating_sub(cbb_lite::uptime::wall_ms()).max(1) });
                    ev.send(&Event::Mute { muted: until.is_some(), for_ms, by });
                }),
                log: Arc::new(move |line: &str| ev.send(&Event::Log { line })),
            })?;
            node.on_change(Box::new(move |c: &Copy| {
                let key = cbb_lite::button::key_of(c).unwrap_or_default();
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
            Ok(Member { node: Arc::new(node), answers, events: ev, stopped: std::sync::atomic::AtomicBool::new(false) })
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
                n.copy(&a.text, a.secret, a.board)?;
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
            "mode" => {
                n.set_mode(Mode::parse(arg(&a, "mode").as_str().unwrap_or_default())?);
                done()
            }
            "mute" => {
                n.set_mute(arg(&a, "until_ms").as_i64());
                done()
            }
            // The user's pause of the group's copies: `{"pause": true,
            // "for_ms"}` (0 for until it is turned on) or `{"pause": false}`.
            "pause_receiving" => {
                let a: PauseArgs = args(a)?;
                if a.pause {
                    n.pause_receiving(a.for_ms)?;
                } else {
                    n.resume_receiving()?;
                }
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
            // The phone's own part.
            "answer" => {
                let a: AnswerArgs = args(a)?;
                let tx = lock(&self.answers.waiting).remove(&a.token);
                let tx = tx.ok_or_else(|| Error::msg("no command waits for that answer"))?;
                let _ = tx.try_send(CommandResult { status: a.status, reason: a.reason, ..CommandResult::default() });
                done()
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
            // Every device of the group as the app shows it.
            "devices" => {
                let ds: Vec<DeviceAnswer> = n
                    .device_views()
                    .into_iter()
                    .map(|d| DeviceAnswer {
                        device: d.id,
                        name: d.name,
                        role: d.role,
                        os: d.os,
                        admin: d.admin,
                        root: d.root,
                        frozen: d.frozen,
                        online: d.online,
                        this: d.this,
                        listed: d.listed,
                    })
                    .collect();
                Ok(json!({ "devices": ds }))
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
    fn caller_check(&self) -> cbb_lite::node::Admit {
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

    /// Whether receiving is paused and whether an admin muted the phone:
    /// `{"paused", "paused_ms", "muted", "muted_ms"}`, the times what is
    /// left, 0 for until it is lifted.
    fn state(&self) -> serde_json::Value {
        let (paused, muted) = self.node.muted();
        serde_json::json!({
            "paused": paused.is_some(),
            "paused_ms": paused.unwrap_or(0),
            "muted": muted.is_some(),
            "muted_ms": muted.unwrap_or(0),
        })
    }

    /// Stops the member once; calls answer that it stopped from then on.
    pub fn stop(&self) {
        if !self.stopped.swap(true, Ordering::SeqCst) {
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
            let ca = match &a.admin_ca {
                Some(der) => Cert::parse(der)?,
                None => identity.root().clone(),
            };
            if ca.public_key() != a.public.as_slice() {
                return Err(Error::msg("the key does not belong to the CA this phone signs with"));
            }
            let key = AppKey { public: a.public.clone(), sign, ctx };
            let me = identity.id.to_string();
            let s = Signer { ca: &ca, key: &key, me: &me };
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
                "mute" => return order(Order::Mute(a.for_ms)),
                "unmute" => return order(Order::Unmute),
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
}
