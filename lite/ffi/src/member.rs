// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The member inside a phone's app (the Aurora app): the lite member's node
//! (`cbb_lite::phone`) with the app's key, which stays where the app keeps
//! it and signs through the callback the join takes too. The node runs on
//! threads of its own: it dials the members mDNS finds, syncs with them,
//! and calls the app back with each text for the phone's clipboard and
//! each log line.

use std::path::PathBuf;
use std::sync::Arc;

use cbb_core::certs::{self, Cert, DeviceId};
use cbb_core::clip::Kind;
use cbb_core::error::{Error, Result};
use cbb_core::identity::Identity;
use cbb_lite::node::WriteReq;
use cbb_lite::phone::{self, Member as Node};
use serde::{Deserialize, Serialize};

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

#[derive(Deserialize)]
struct CopyArgs {
    text: String,
    #[serde(default)]
    secret: bool,
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
}

#[derive(Serialize)]
struct PeerAnswer {
    device: String,
    name: String,
    role: String,
    os: String,
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
                log: Arc::new(move |line: &str| ev.send(&Event::Log { line })),
            })?;
            Ok(Member { node })
        })();
        match made {
            Ok(m) => (Some(m), answer(Ok(serde_json::json!({})))),
            Err(e) => (None, answer::<()>(Err(e))),
        }
    }

    /// Sends a text the user handed to the app.
    pub fn copy(&self, request: &[u8]) -> Vec<u8> {
        answer((|| -> Result<serde_json::Value> {
            let a: CopyArgs =
                serde_json::from_slice(request).map_err(|e| Error::msg(format!("the copy does not decode: {e}")))?;
            self.node.copy(&a.text, a.secret)?;
            Ok(serde_json::json!({}))
        })())
    }

    /// The members connected now.
    pub fn peers(&self) -> Vec<u8> {
        let peers: Vec<PeerAnswer> = self
            .node
            .peers()
            .into_iter()
            .map(|p| PeerAnswer { device: p.id.to_string(), name: p.name, role: p.role, os: p.os })
            .collect();
        answer(Ok(serde_json::json!({ "peers": peers })))
    }

    pub fn stop(&self) {
        self.node.stop();
    }
}
