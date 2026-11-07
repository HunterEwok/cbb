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

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use cbb_core::authority::Record;
use cbb_core::certs::{self, Cert, DeviceId};
use cbb_core::clip::{Event as Copy, Kind, Mode};
use cbb_core::error::{Error, Result};
use cbb_core::identity::Identity;
use cbb_core::media::Part;
use cbb_lite::content::Source;
use cbb_lite::node::{Peer, WriteReq};
use cbb_lite::phone::{self, Member as Node};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::join::{AppKey, SignFn, answer};

/// Gets an event as JSON bytes, on one of the member's threads.
pub type EventFn = unsafe extern "C" fn(ctx: *mut core::ffi::c_void, event: *const u8, len: usize);

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

fn ten_seconds() -> u64 {
    10_000
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

pub struct Member {
    node: Node,
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
            Ok(Member { node })
        })();
        match made {
            Ok(m) => (Some(m), answer(Ok(serde_json::json!({})))),
            Err(e) => (None, answer::<()>(Err(e))),
        }
    }

    /// Answers a request of cbb_member_call, `{op, args}`.
    pub fn call(&self, request: &[u8]) -> Vec<u8> {
        answer((|| -> Result<Value> {
            let r: Request = serde_json::from_slice(request)
                .map_err(|e| Error::msg(format!("the member's request does not decode: {e}")))?;
            self.op(&r.op, r.args)
        })())
    }

    fn op(&self, op: &str, a: Value) -> Result<Value> {
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
                let id = a["id"].as_str().ok_or_else(|| Error::msg("took needs the copy's id"))?;
                n.took(id);
                done()
            }
            "sends" => {
                let board = a["board"].as_str().unwrap_or_default();
                Ok(json!({ "sends": n.sends(board) }))
            }
            "fetch" => {
                let a: FetchArgs = args(a)?;
                let parts = n.fetch(&a.id, a.max, std::path::Path::new(&a.out))?;
                Ok(json!({ "parts": parts.iter().map(|(p, at)| part_json(p, at)).collect::<Vec<_>>() }))
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
                n.lost(a["key"].as_str().unwrap_or_default());
                done()
            }
            "listen" => {
                let port = u16::try_from(a["port"].as_u64().unwrap_or(0)).map_err(|_| Error::msg("not a port"))?;
                Ok(json!({ "port": n.listen(port)? }))
            }
            "unlisten" => {
                n.unlisten();
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
                let ms = a["timeout_ms"].as_u64().unwrap_or(5_000).min(60_000);
                Ok(json!({ "connected": n.wait_connected(Duration::from_millis(ms)) }))
            }
            "mode" => {
                n.set_mode(Mode::parse(a["mode"].as_str().unwrap_or_default())?);
                done()
            }
            "mute" => {
                n.set_mute(a["until_ms"].as_i64());
                done()
            }
            // What the app shows.
            "peers" => {
                let all = a["all"].as_bool().unwrap_or(false);
                let ps = if all { n.all_peers() } else { n.peers() };
                Ok(json!({ "peers": ps.iter().map(peer_json).collect::<Vec<_>>() }))
            }
            "records" => Ok(json!({ "records": n.records() })),
            // What an admin's app signed.
            "add_records" => {
                let rs: Vec<Record> = args(a["records"].clone())?;
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
                let to = n.send_hubs(&a["share"]);
                Ok(json!({ "to": to.iter().map(ToString::to_string).collect::<Vec<_>>() }))
            }
            "send_credentials" => {
                let to = n.send_credentials(&a["credentials"]);
                Ok(json!({ "to": to.iter().map(ToString::to_string).collect::<Vec<_>>() }))
            }
            _ => Err(Error::msg(format!("the member has no operation {op:?}"))),
        }
    }

    pub fn stop(&self) {
        self.node.stop();
    }
}
