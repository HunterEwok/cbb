// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The phone's member on the records of 0.6 (`cbb_member::live`): what
//! `cbb_member_start` runs when the app's folder holds the group's
//! `group.cbor`. The member key stays in the app and signs through its
//! callback; the app finds the members itself and hands them in with
//! `found`, as on 0.5. The operations that have not moved to the records of
//! 0.6 yet answer the error of `cbb_member::live::not_yet`, whose cause
//! debug builds show, never a silent no-op.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use cbb_core::certs;
use cbb_core::clip::{Kind, Via};
use cbb_core::error::{Error, Result};
use cbb_core::identity::ExternalKey;
use cbb_member::board::Current;
use cbb_member::control::{Device, Status};
use cbb_member::discovery::{Dialers, Listener};
use cbb_member::live::{Live, Write, not_yet};
use cbb_member::own::Own;
use cbb_member::roster::{self, id_text};
use cbb_member::writers;
use serde::Deserialize;
use serde_json::{Value, json};

use super::{Event, EventFn, Events, KeysFn, Request, SyncArgs, args, lock};
use crate::join::{AppKey, SignFn, answer};

/// Whether the app's folder in a start request holds a group of 0.6.
pub(super) fn on_06(request: &[u8]) -> bool {
    #[derive(Deserialize)]
    struct Dir {
        #[serde(default)]
        dir: String,
    }
    serde_json::from_slice::<Dir>(request)
        .is_ok_and(|d| !d.dir.is_empty() && Path::new(&d.dir).join(cbb_member::set::FILE_NAME).is_file())
}

/// What `cbb_member_start` takes for a group of 0.6: the fields of 0.5's
/// request that still mean something; the certificates are not needed, as
/// the records name the group's devices and keys.
#[derive(Deserialize)]
struct StartArgs {
    dir: String,
    name: String,
    os: String,
    #[serde(default)]
    os_version: String,
    #[serde(default)]
    version: String,
    /// The device ID the app keeps; it must be the one the member key
    /// makes.
    device: String,
    /// The member key's public point, SEC1 uncompressed.
    #[serde(with = "certs::b64")]
    public: Vec<u8>,
    #[serde(default)]
    peers: Vec<String>,
    #[serde(default = "super::yes")]
    mdns: bool,
}

#[derive(Deserialize)]
struct CopyArgs {
    text: String,
    #[serde(default)]
    kind: String,
}

#[derive(Deserialize)]
struct FoundArgs {
    key: String,
    addrs: Vec<String>,
    #[serde(default)]
    device: Option<String>,
}

/// What `cbb_member_manage` takes on 0.6: the action, its device and new
/// name, and the key that signs.
#[derive(Deserialize)]
struct ManageArgs {
    action: String,
    #[serde(default)]
    device: String,
    #[serde(default)]
    name: String,
    /// How long a mute lasts, 0 for until an admin ends it.
    #[serde(default)]
    for_ms: i64,
    /// A paste: its text, pasted or typed (`method`), with Enter after it,
    /// a text or a secret (`kind`), or `media` for the group's copy of
    /// images or files.
    #[serde(default)]
    text: String,
    #[serde(default)]
    method: String,
    #[serde(default)]
    enter: bool,
    #[serde(default)]
    kind: String,
    /// With make_admin: the person consented to a device that keeps its
    /// keys in a file, which the group's key level must allow too.
    #[serde(default)]
    allow_file_key: bool,
    /// With hubs: the devices the root names as the group's hubs, 1 to 16
    /// in their order, by name or device ID.
    #[serde(default)]
    hubs: Vec<String>,
    /// With relay, on the root: the group's relays, each "address pin"
    /// (its key's pin in base64), or "default" alone for the project's;
    /// none meets at no relay.
    #[serde(default)]
    relays: Vec<String>,
    /// With key_level: proven, hardware or files.
    #[serde(default)]
    level: String,
    /// With forwarder, on the root: the hub's forwarder, `host:port` or
    /// `default` for the project's, and its key's pin in base64 (`key`).
    #[serde(default)]
    forwarder: String,
    #[serde(default)]
    key: String,
    /// With add_watch: the watch's system (watchos, wearos or harmonyos);
    /// its admin key is `key`, a SubjectPublicKeyInfo in base64.
    #[serde(default)]
    os: String,
    #[serde(with = "certs::b64")]
    public: Vec<u8>,
}

/// What the phone says of itself in its hellos.
#[derive(Clone)]
struct Me {
    name: String,
    os: String,
    os_version: String,
    version: String,
    log: Arc<dyn Fn(&str) + Send + Sync>,
}

impl Me {
    /// Puts the phone's hello, with its board's mode and mute, in the
    /// member's hellos, and sends it to the members connected now, so
    /// that they show a mute or sync turned off at once.
    fn hello(&self, live: &Live) {
        self.set_hello(live);
        if let Err(e) = live.mesh.changed() {
            (self.log)(&format!("cbb: the new hello did not go: {}", e.for_log()));
        }
    }

    fn set_hello(&self, live: &Live) {
        let b = &live.board;
        let muted = b.mute_left();
        live.mesh.set_hello(cbb_member::hello::Hello {
            name: self.name.clone(),
            os: cbb_core::format::print::os_number(&self.os),
            mode: if b.mode() == cbb_core::clip::Mode::Own { 2 } else { 1 },
            muted: muted.is_some(),
            muted_for_ms: muted.map_or(0, |l| u64::try_from(l).unwrap_or(0)),
            device: cbb_member::hello::Device {
                form: roster::form_number("phone"),
                version: self.version.clone(),
                os_version: self.os_version.clone(),
                ..Default::default()
            },
            ..Default::default()
        });
    }
}

/// Why a watch does nothing to a group of 0.6 from the wrist.
const WATCH_SIGNS_NOTHING: &str =
    "on a group of 0.6 the watch shows the group and signs nothing: its emergency actions come with cbb 0.7";

/// The phone's member on the records of 0.6.
pub struct Phone {
    live: Arc<Live>,
    dir: PathBuf,
    me: Me,
    dialers: Dialers,
    /// The member port the app opened while it is in the front.
    port: Mutex<Option<Listener>>,
    log: Arc<dyn Fn(&str) + Send + Sync>,
    stopped: AtomicBool,
    panics: u64,
    /// What the phone itself sent or took last, for the one button's rule.
    own: cbb_member::button::Own,
}

fn addrs(list: &[String]) -> Result<Vec<std::net::SocketAddr>> {
    list.iter().map(|s| s.parse().map_err(|_| Error::msg(format!("{s} is not an address host:port")))).collect()
}

fn kind_name(k: Kind) -> &'static str {
    match k {
        Kind::Text => "text",
        Kind::Secret => "secret",
        Kind::Media => "media",
    }
}

/// A copy the button's rule gives, as the app reads it, in the shape of
/// 0.5's.
fn event_json(e: &cbb_core::clip::Event) -> Value {
    json!({
        "id": e.id,
        "origin": e.origin,
        "age_ms": e.age,
        "kind": kind_name(e.kind),
        "text": e.text,
        "media": e.media,
        "key": cbb_member::button::key_of(e).unwrap_or_default(),
    })
}

/// The group's current copy as the app reads it, in the shape of 0.5's.
fn current_json(c: &Current, now_ms: i64) -> Value {
    let kind = if c.content.manifest.is_some() {
        Kind::Media
    } else if c.content.is_secret() {
        Kind::Secret
    } else {
        Kind::Text
    };
    let id = certs::hex(&c.id);
    json!({
        "id": id,
        "origin": id_text(&c.origin),
        "age_ms": now_ms.saturating_sub(c.at_ms).max(0),
        "kind": kind_name(kind),
        "text": c.content.text.clone().unwrap_or_default(),
        "key": id,
    })
}

impl Phone {
    /// Opens the group of 0.6 in the app's folder with the member key
    /// behind sign, and starts finding its members.
    pub fn start(request: &[u8], sign: SignFn, events: EventFn, ctx: usize) -> Result<Phone> {
        let a: StartArgs = serde_json::from_slice(request)
            .map_err(|e| Error::msg(format!("the member's request does not decode: {e}")))?;
        let ev = Events { f: events, ctx };
        let log: Arc<dyn Fn(&str) + Send + Sync> = Arc::new(move |line: &str| ev.send(&Event::Log { line }));
        let key: Arc<dyn ExternalKey> = Arc::new(AppKey { public: a.public, sign, ctx });
        let dir = PathBuf::from(&a.dir);
        let live = Live::open(&dir, Own::from_keys(key, None, None), log.clone())?;
        let me = id_text(&live.mesh.device());
        if !me.eq_ignore_ascii_case(&a.device) {
            live.close();
            return Err(Error::msg(format!(
                "the app's device ID {} is not the one its member key makes ({me})",
                a.device
            )));
        }
        if let Err(e) = cbb_member::sync::load(&dir, &live.board) {
            log(&format!("cbb: sync on or off: {}; sync is on", e.for_log()));
        }
        if let Err(e) = cbb_member::mute::load(&dir, &live.board) {
            log(&format!("cbb: the mute: {}; not muted", e.for_log()));
        }
        live.on_write(Box::new(move |w| deliver(&ev, &w)));
        // The Android evidence the peers send, which the phone checks while
        // it is the group's root, when its app hands it the root key.
        live.with_phone_attestations();
        // Sync away from home, with its state in the app's folder: on at
        // once for a phone that joined by an invitation, which reaches the
        // hub through the invitation's guest tunnel until it holds the
        // hub's offer.
        live.start_away(dir.clone(), None, log.clone())?;
        let me = Me { name: a.name, os: a.os, os_version: a.os_version, version: a.version, log: log.clone() };
        {
            // The commands for the phone itself, which the core took and
            // checked; the member holds the live member weakly, as the
            // member holds this.
            let (weak, me, dir) = (Arc::downgrade(&live), me.clone(), dir.clone());
            live.mesh.on_command(Box::new(move |t| match weak.upgrade() {
                Some(l) => carry_out(&l, &me, &dir, &ev, t),
                None => Err(Error::msg("the member stopped")),
            }));
        }
        let panics = crate::guard::watch(Box::new(move |details: &str| ev.send(&Event::Panic { details })));
        let p = Phone {
            live,
            dir,
            me,
            dialers: Dialers::default(),
            port: Mutex::new(None),
            log,
            stopped: AtomicBool::new(false),
            panics,
            own: cbb_member::button::Own::default(),
        };
        p.me.set_hello(&p.live);
        let tag = p.live.tag();
        cbb_member::discovery::start(p.live.clone(), tag.clone(), addrs(&a.peers)?, false, None, p.log.clone());
        if a.mdns {
            cbb_member::discovery::start_as_phone(p.live.clone(), tag, p.log.clone());
        }
        Ok(p)
    }

    /// What the phone says of itself in its hellos, sent at once.
    fn hello(&self) {
        self.me.hello(&self.live);
    }

    /// Answers a request of cbb_member_call.
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
        let arg = |k: &str| a.get(k).cloned().unwrap_or(Value::Null);
        let l = &self.live;
        let done = || Ok(json!({}));
        match op {
            "copy" => {
                let c: CopyArgs = args(a)?;
                let kind = match c.kind.as_str() {
                    "" | "text" => Kind::Text,
                    "secret" => Kind::Secret,
                    other => return Err(Error::msg(format!("a copy is a text or a secret, not {other:?}"))),
                };
                l.send(&c.text, kind, Via::Phone)?;
                self.own.sent(&c.text);
                done()
            }
            // Images or files the phone copies, sealed and kept to serve, as
            // the service's copy_media; a phone's copy is always deliberate.
            "copy_media" => {
                use cbb_member::content::Source;
                let a: super::MediaArgs = args(a)?;
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
                        let part =
                            cbb_core::media::Part { kind: p.kind, path: p.path, dir: p.dir, ..Default::default() };
                        Ok((part, src))
                    })
                    .collect::<Result<Vec<_>>>()?;
                l.copy_media(&a.text, parts, Via::Phone, true)?;
                Ok(json!({ "copy": self.own_media_json(&a.text) }))
            }
            // The images or files of a copy from the group, fetched from the
            // member it came from and opened into a new folder.
            "fetch" => {
                let a: super::FetchArgs = args(a)?;
                let from = l.media_to_paste(&a.id)?;
                let parts = l.open_media(&from, a.max, Path::new(&a.out))?;
                Ok(json!({ "parts": parts.iter().map(|(p, at)| super::part_json(p, at)).collect::<Vec<_>>() }))
            }
            // The one button's rule (cbb_member::button), on the group's
            // current copy.
            "waiting" => {
                let me = id_text(&l.mesh.device());
                let window = Duration::from_millis(l.board.lifetimes().0);
                let ev = cbb_member::button::waiting(self.current_event(), &me, window, &self.own);
                Ok(json!({ "copy": ev.map(|e| event_json(&e)) }))
            }
            "took" => {
                let id = arg("id");
                let id = id.as_str().ok_or_else(|| Error::msg("took needs the copy's id"))?;
                if let Some(ev) = self.current_event().filter(|e| e.id == id) {
                    self.own.took(&ev);
                }
                done()
            }
            "sends" => {
                let board = arg("board");
                let board = board.as_str().unwrap_or_default();
                Ok(json!({ "sends": cbb_member::button::sends(board, self.current_event().as_ref(), &self.own) }))
            }
            "current" => {
                Ok(json!({ "copy": l.board.current().map(|c| current_json(&c, cbb_member::uptime::wall_ms())) }))
            }
            "found" => {
                let f: FoundArgs = args(a)?;
                let dev = f.device.as_deref().map(certs::DeviceId::parse).transpose()?;
                self.dialers.found(l, &f.key, addrs(&f.addrs)?, dev);
                done()
            }
            "lost" => {
                self.dialers.lost(&**l, arg("key").as_str().unwrap_or_default());
                done()
            }
            "listen" => {
                match arg("kind").as_str() {
                    None | Some("home") => {}
                    Some(k) => return Err(not_yet(&format!("a member port for {k}"))),
                }
                let port = u16::try_from(arg("port").as_u64().unwrap_or(0)).map_err(|_| Error::msg("not a port"))?;
                let mut held = lock(&self.port);
                if let Some(old) = held.take() {
                    old.stop();
                }
                let ln = Listener::open(l.clone(), port, self.log.clone())
                    .ok_or_else(|| Error::msg(format!("cannot listen on port {port}")))?;
                let port = ln.port;
                *held = Some(ln);
                Ok(json!({ "port": port }))
            }
            "unlisten" => {
                match arg("kind").as_str() {
                    None | Some("home") => {}
                    Some(k) => return Err(not_yet(&format!("a member port for {k}"))),
                }
                if let Some(ln) = lock(&self.port).take() {
                    ln.stop();
                }
                done()
            }
            "pause" => {
                l.pause();
                done()
            }
            "resume" => {
                l.resume();
                done()
            }
            "wait" => {
                let ms = arg("timeout_ms").as_u64().unwrap_or(5_000).min(60_000);
                let until = Instant::now().checked_add(Duration::from_millis(ms)).unwrap_or_else(Instant::now);
                while l.mesh.connected().is_empty() && Instant::now() < until && !self.stopped.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(50));
                }
                Ok(json!({ "connected": !l.mesh.connected().is_empty() }))
            }
            "set_mute" => {
                match arg("until_ms").as_i64() {
                    Some(u) => l.board.set_mute(u),
                    None => l.board.unmute(),
                }
                let me = id_text(&l.mesh.device());
                cbb_member::mute::save(&self.dir, &l.board, &me)?;
                self.hello();
                done()
            }
            "sync" => {
                let s: SyncArgs = args(a)?;
                if s.on && s.for_ms != 0 {
                    return Err(Error::msg("a time goes only with sync off"));
                }
                cbb_member::sync::set(&self.dir, &l.board, s.on, s.for_ms)?;
                (self.log)(&cbb_member::sync::line(&l.board));
                self.hello();
                Ok(self.state())
            }
            "muted" => Ok(self.state()),
            "peers" => {
                let all = arg("all").as_bool().unwrap_or(false);
                // What each connected member says it reaches (protocol.md,
                // section 4, "Reach"), so that the app shows the members
                // behind a hub as online through it.
                let reach: std::collections::HashMap<String, Vec<String>> = l
                    .mesh
                    .connected()
                    .iter()
                    .map(|p| (id_text(p), l.mesh.reach_of(p).iter().map(id_text).collect()))
                    .collect();
                let ps: Vec<Value> = self
                    .devices()
                    .iter()
                    .filter(|d| !d.this && (all || d.online))
                    .map(|d| {
                        json!({
                            "device": d.id, "name": d.name, "role": d.role, "os": d.os,
                            "key_store": d.store, "mode": d.mode, "muted": d.muted,
                            "reach": reach.get(&d.id).cloned().unwrap_or_default(),
                        })
                    })
                    .collect();
                Ok(json!({ "peers": ps }))
            }
            "devices" => Ok(json!({ "devices": self.devices() })),
            // Sync away from home: on with new tunnel keys, or off; and its
            // state, null while it is off.
            "away" => {
                if arg("on").as_bool().unwrap_or(false) {
                    l.away_on()?;
                } else {
                    l.away_off(std::time::Duration::ZERO)?;
                }
                Ok(self.away_answer())
            }
            // The phone as a hub of the group (the records must make it
            // one: an admin key), as cbb global hub does on a computer and
            // with the arguments of the phone of 0.5: reached away from
            // home through the forwarder (`forwarder`, its key's pin `key`,
            // or `default` for the project's) or at `addrs` ("ip:port") on
            // the UDP `port`, hidden as `obfuscate_off` and `vless_off` say.
            // The Live hub serves its clients and the guests of invitations
            // at the guest address.
            "hub" => {
                if !l.mesh.may_be_hub(&l.mesh.device()) {
                    return Err(Error::msg(
                        "the group's records do not make this phone a hub; only an admin phone can be one",
                    ));
                }
                let away = l.away().ok_or_else(|| Error::msg("sync away from home did not start on this phone"))?;
                let text = |k: &str| arg(k).as_str().unwrap_or_default().to_string();
                let addrs = arg("addrs")
                    .as_array()
                    .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
                    .unwrap_or_default();
                // No forwarder given: the one the group's root set, if any.
                let (forwarder, key) = match (text("forwarder"), root_forwarder(&self.dir)) {
                    (f, Some(r)) if f.is_empty() => (r.endpoint, r.key),
                    (f, _) => (resolve(&f)?, text("key")),
                };
                let h = cbb_member::control::Header {
                    name: "hub".into(),
                    forwarder,
                    forwarder_key: key,
                    obfuscate_off: arg("obfuscate_off").as_bool().unwrap_or(false),
                    vless_off: arg("vless_off").as_bool().unwrap_or(false),
                    port: arg("port").as_i64().unwrap_or(0),
                    addrs,
                    consent: true,
                    ..Default::default()
                };
                away.make_hub(&h)?;
                Ok(self.away_answer())
            }
            // A Live hub that stops hands its clients to the next hub in
            // the group's order (D-122), so `anyway` of 0.5 is not needed.
            "hub_off" => {
                l.stop_being_hub()?;
                Ok(self.away_answer())
            }
            "away_status" => Ok(self.away_answer()),
            "group" => Ok(group_view(&lock(&l.mesh.set()), &l.mesh.device())),
            "why" => Ok(json!({ "why": self.why() })),
            // The revocation list of Android attestations the app fetched,
            // and how many peers' evidence waits for the root key.
            "attest_status" => {
                let file = |k: &str| -> Result<cbb_core::release::File> {
                    serde_json::from_value(arg(k))
                        .map_err(|_| Error::msg(format!("the revocation list's {k} does not decode")))
                };
                let revoked = l.attest_status(file("keys")?, file("status")?)?;
                Ok(json!({ "revoked": revoked, "pending": l.attest_pending() }))
            }
            "attest" => Ok(json!({ "pending": l.attest_pending() })),
            "check_command" | "answer" => Err(not_yet("a command for this phone")),
            _ => Err(not_yet(&format!("the operation {op:?}"))),
        }
    }

    /// The group's current copy as the button's rule reads it.
    /// The copy of images or files the phone just made, as the app lists
    /// it: its ID once it went to the group, and the manifest kept to
    /// serve it.
    fn own_media_json(&self, text: &str) -> Value {
        let l = &self.live;
        let manifest = match l.media_to_paste("") {
            Ok(cbb_member::live::MediaFrom::Own(m)) => Some(m.manifest),
            _ => None,
        };
        let id = l.media_copy().map(|i| certs::hex(&i)).unwrap_or_default();
        let ev = cbb_core::clip::Event {
            id,
            origin: id_text(&l.mesh.device()),
            kind: Kind::Media,
            text: text.to_string(),
            media: manifest,
            ..Default::default()
        };
        event_json(&ev)
    }

    fn current_event(&self) -> Option<cbb_core::clip::Event> {
        let c = self.live.board.current()?;
        let kind = if c.content.manifest.is_some() {
            Kind::Media
        } else if c.content.is_secret() {
            Kind::Secret
        } else {
            Kind::Text
        };
        Some(cbb_core::clip::Event {
            id: certs::hex(&c.id),
            origin: id_text(&c.origin),
            age: cbb_member::uptime::wall_ms().saturating_sub(c.at_ms).max(0),
            kind,
            text: c.content.text.clone().unwrap_or_default(),
            media: c.content.manifest.clone(),
            ..Default::default()
        })
    }

    /// Every device of the group as the app shows it.
    fn devices(&self) -> Vec<Device> {
        let l = &self.live;
        let muted = l.board.mute_left();
        let me = roster::Me {
            id: l.mesh.device(),
            mode: if l.board.mode() == cbb_core::clip::Mode::Own { "own" } else { "shared" }.into(),
            muted_until_ms: muted.map(|m| if m == 0 { 0 } else { cbb_member::uptime::wall_ms().saturating_add(m) }),
            os_version: self.me.os_version.clone(),
            version: self.me.version.clone(),
            ..Default::default()
        };
        roster::devices(&lock(&l.mesh.set()), &me, &l.mesh.hellos(), cbb_member::uptime::wall_ms())
    }

    /// Why the phone does not sync: the facts its member and the group's
    /// records give.
    fn why(&self) -> Vec<cbb_core::why::Reason> {
        let l = &self.live;
        let devices = self.devices();
        let st = l.mesh.state();
        let me = l.mesh.device();
        let mine = st.devices.iter().find(|d| d.id == me);
        let muted = l.board.mute_left();
        let status = Status {
            device: id_text(&me),
            group: l.tag(),
            mode: l.board.mode().name().into(),
            muted: muted.is_some(),
            muted_until_ms: muted.filter(|m| *m > 0).map_or(0, |m| cbb_member::uptime::wall_ms().saturating_add(m)),
            sync_until_ms: l.board.sync().1,
            peers: devices.iter().filter(|d| d.online && !d.this).cloned().collect(),
            removed: mine.is_none(),
            frozen: mine.is_some_and(|d| d.frozen),
            ..Default::default()
        };
        let mut facts = cbb_member::why::facts(&status, &devices);
        cbb_core::why::group_facts(&mut facts, &st, &me);
        facts.checkpoint_stuck = !lock(&l.mesh.set()).stuck_checkpoints().is_empty();
        cbb_core::why::diagnose(&facts, cbb_member::uptime::wall_ms())
    }

    /// Sync away from home as the away ops answer it: its state, null
    /// while it is off, and the forwarder the group's root set for this
    /// phone as a hub (`endpoint`, `key`), null while it set none, which
    /// the apps show as the root's setting; and on the root phone whether
    /// the group's server credentials need its root key (`period_due`,
    /// which the manage action `period` renews) and whether they expired
    /// already (`period_overdue`), so that the group's relay and its hubs'
    /// forwarders take nobody until then.
    fn away_answer(&self) -> Value {
        let (due, overdue) = self.live.mesh.periods();
        json!({
            "away": self.live.away_status(),
            "root_forwarder": root_forwarder(&self.dir),
            "period_due": due,
            "period_overdue": overdue,
        })
    }

    /// Whether sync is off and whether the phone is muted, as on 0.5.
    fn state(&self) -> Value {
        serde_json::to_value(cbb_member::sync::standing(&self.live.board)).unwrap_or_default()
    }

    /// The servers are not on the records of 0.6 yet.
    pub fn servers(&self, _keys: KeysFn, _ctx: usize) -> Vec<u8> {
        answer::<()>(Err(not_yet("serving the group's servers")))
    }

    /// Stops the member once; calls answer that it stopped from then on.
    pub fn stop(&self) {
        if !self.stopped.swap(true, Ordering::SeqCst) {
            crate::guard::unwatch(self.panics);
            if let Some(ln) = lock(&self.port).take() {
                ln.stop();
            }
            self.live.close();
        }
    }

    /// An admin's change to a device, signed with the app's admin or root
    /// key: remove, rename, freeze and thaw, or a command for another
    /// device (mute, unmute, sync_off, sync_on, paste, paste_off,
    /// actions_off, away_off), sent as the computer's service sends it and
    /// answered by that device (`{status, reason}`); the records judge
    /// whether the key may.
    pub fn manage(&self, request: &[u8], sign: SignFn, ctx: usize) -> Vec<u8> {
        answer((|| -> Result<Value> {
            if self.stopped.load(Ordering::SeqCst) {
                return Err(Error::msg("the member stopped"));
            }
            let a: ManageArgs = serde_json::from_slice(request)
                .map_err(|e| Error::msg(format!("the manage request does not decode: {e}")))?;
            let key = AppKey { public: a.public.clone(), sign, ctx };
            let now = cbb_member::uptime::wall_ms().max(0).unsigned_abs();
            let mesh = &self.live.mesh;
            let named_me = || writers::find(&mesh.state(), &a.device).is_ok_and(|d| d.id == mesh.device());
            let d = match a.action.as_str() {
                "remove" => {
                    if named_me() {
                        return Err(Error::msg("a device cannot remove itself; remove it from another member"));
                    }
                    mesh.write_by(&key, |set, k| writers::remove(set, k, &a.device, now))?.0
                }
                "rename" => mesh.write_by(&key, |set, k| writers::rename(set, k, &a.device, &a.name, now))?.0,
                "freeze" | "thaw" => {
                    if named_me() {
                        return Err(Error::msg("a device cannot freeze or unfreeze itself"));
                    }
                    let on = a.action == "freeze";
                    mesh.write_by(&key, |set, k| writers::freeze(set, k, &a.device, on, now))?.0
                }
                "mute" | "unmute" | "sync_off" | "sync_on" | "paste" | "paste_off" | "actions_off" | "away_off" => {
                    if named_me() {
                        return Err(Error::msg("this phone's own switches are its own, not a command"));
                    }
                    let o = self.order(&a)?;
                    let d = writers::find(&mesh.state(), &a.device)?.clone();
                    let r = mesh
                        .command(&key, d.id, o.kind(), o.orders()?.as_deref())
                        .map_err(|e| Error::msg(format!("{}: {}", d.name, e.message())))?;
                    let status = match r.status {
                        1 => "done",
                        s if s == cbb_core::commands::STATUS_REFUSED => "refused",
                        _ => "failed",
                    };
                    return Ok(
                        json!({ "device": id_text(&d.id), "name": d.name, "status": status, "reason": r.reason }),
                    );
                }
                "relay" => {
                    let given: Vec<(String, String)> = a
                        .relays
                        .iter()
                        .map(|r| match r.trim().split_once(' ') {
                            Some((addr, pin)) => (addr.to_string(), pin.trim().to_string()),
                            None if r.trim() == "default" => (String::new(), "default".to_string()),
                            None => (r.trim().to_string(), String::new()),
                        })
                        .collect();
                    let relays = self.live.set_relays(Some(&key), &given)?;
                    self.renew_by(&key);
                    return Ok(json!({ "relays": relays.into_iter().map(|r| r.endpoint).collect::<Vec<_>>() }));
                }
                // The root's key, handed over to renew the group's server
                // credentials: the root phone signs the period for each of
                // the group's servers that needs one (protocol.md, section
                // 18), as the root computer does by itself.
                "period" => {
                    mesh.refresh_faces_by(&key)?;
                    let (due, overdue) = mesh.periods();
                    return Ok(json!({ "period_due": due, "period_overdue": overdue }));
                }
                // The root names the forwarder of an admin phone that is a
                // hub (`forwarder`, its key's pin `key`, or `default` for the
                // project's) with the hub command, as cbb global hub -on
                // does, and makes the group's credentials for it there.
                "forwarder" => {
                    let r = self.name_forwarder(&a, &key)?;
                    self.renew_by(&key);
                    return Ok(r);
                }
                "hubs" => {
                    mesh.write_by(&key, |set, k| writers::set_hubs(set, k, &a.hubs, now))?;
                    self.renew_by(&key);
                    return Ok(json!({ "hubs": a.hubs }));
                }
                "make_admin" => self.make_admin(&a, &key, now)?,
                "key_level" => return self.key_level(&a, &key, now),
                "add_watch" => return self.add_watch(&a, &key, now),
                // On 0.6 a watch signs nothing from the wrist (D-124): it
                // shows the group and may do nothing to a device.
                "watch_actions" => return Ok(json!({ "actions": [] })),
                // The root's key, handed over for the Android evidence that
                // waits: the phone checks it and records what it proves
                // (protocol.md, section 17), as a root computer's helper does.
                "attest" => {
                    let recorded = self.live.attest_record(&key)?;
                    return Ok(json!({ "recorded": recorded, "pending": self.live.attest_pending() }));
                }
                other => return Err(not_yet(&format!("the admin's action {other:?}"))),
            };
            Ok(json!({ "device": id_text(&d.id), "name": d.name }))
        })())
    }

    /// The root's hub command that names the forwarder of the device
    /// `a.device`, a hub of the group by the records, which takes it as its
    /// forwarder setting: answered as a command is (`{status, reason}`).
    fn name_forwarder(&self, a: &ManageArgs, key: &AppKey) -> Result<Value> {
        let mesh = &self.live.mesh;
        let st = mesh.state();
        if st.roots.last() != Some(&cbb_core::records::Key::es256(key.public.clone()).hash()) {
            return Err(Error::msg("only the group's root names a hub's forwarder"));
        }
        let d = writers::find(&st, &a.device)?.clone();
        if d.id == mesh.device() {
            return Err(Error::msg("this phone, the group's root, is no hub"));
        }
        if !st.may_be_hub(&d.id) {
            return Err(Error::msg(format!(
                "the group's records do not make {} a hub; only an admin or a hub the root names can be one",
                d.name
            )));
        }
        drop(st);
        let f = cbb_member::forwarder_named(&resolve(&a.forwarder)?, &a.key)?
            .ok_or_else(|| Error::msg("name the forwarder: its address with its key's pin, or default"))?;
        let o = cbb_member::orders::Order::Hub(cbb_member::orders::Hub {
            forwarders: vec![f.clone()],
            ..Default::default()
        });
        let r = mesh
            .command(key, d.id, o.kind(), o.orders()?.as_deref())
            .map_err(|e| Error::msg(format!("{}: {}", d.name, e.message())))?;
        let status = match r.status {
            1 => "done",
            s if s == cbb_core::commands::STATUS_REFUSED => "refused",
            _ => "failed",
        };
        if status == "done" {
            mesh.set_hub_forwarders(d.id, vec![cbb_member::faces::Server { pin: f.1, address: f.0 }])?;
        }
        Ok(json!({ "device": id_text(&d.id), "name": d.name, "status": status, "reason": r.reason }))
    }

    /// Renews the group's server credentials with the root's key that a
    /// root action handed over, while it is here: the next root action
    /// renews a period that is due, so the app asks for no key at another
    /// moment. Another key renews nothing.
    fn renew_by(&self, key: &AppKey) {
        let mesh = &self.live.mesh;
        if mesh.state().roots.last() == Some(&cbb_core::records::Key::es256(key.public.clone()).hash())
            && mesh.periods().0
            && let Err(e) = mesh.refresh_faces_by(key)
        {
            (self.log)(&format!("cbb: renewing the group's server credentials: {}", e.for_log()));
        }
    }

    /// The group's key level as the records set it.
    fn level(&self) -> &'static str {
        use cbb_core::records::body::{LEVEL_FILES, LEVEL_PROVEN};
        match self.live.mesh.state().settings.level() {
            LEVEL_PROVEN => "proven",
            LEVEL_FILES => "files",
            _ => "hardware",
        }
    }

    /// The root's "Make it an admin", as the service's cbb admin: the
    /// device's record again with the admin key it offered when it paired
    /// with this phone (`cbb_member::offered`), if the key level allows
    /// where it keeps its keys.
    fn make_admin(&self, a: &ManageArgs, key: &AppKey, now: u64) -> Result<cbb_core::records::eval::DeviceState> {
        use cbb_core::records::body::{CAP_ADMIN, ROLE_PHONE, STORE_ROOTLESS};
        let mesh = &self.live.mesh;
        let st = mesh.state();
        if st.roots.last() != Some(&cbb_core::records::Key::es256(key.public.clone()).hash()) {
            return Err(Error::msg("only the group's root makes admins"));
        }
        let d = writers::find(&st, &a.device)?.clone();
        if d.id == mesh.device() {
            return Err(Error::msg("this phone is the group's root, which is more than an admin"));
        }
        if d.role != ROLE_PHONE && d.caps & CAP_ADMIN == 0 {
            return Err(Error::msg(format!(
                "{} cannot hold an admin key; only a phone or a member with the cap admin can be an admin",
                d.name
            )));
        }
        if d.admin.is_some() {
            return Err(Error::msg(format!("{} is already an admin", d.name)));
        }
        if d.store == STORE_ROOTLESS {
            return Err(Error::msg(format!(
                "{} is installed without root, so every program of its user can read its keys; such a device is never an admin (D-79)",
                d.name
            )));
        }
        let Some(point) = cbb_member::offered::get(mesh.dir(), &id_text(&d.id))? else {
            return Err(Error::msg(format!(
                "{} offered this phone no admin key when it joined (another admin admitted it, or it cannot be one then): pair it with this phone again to make it an admin",
                d.name
            )));
        };
        let store = self.devices().into_iter().find(|x| x.id == id_text(&d.id)).map(|x| x.store).unwrap_or_default();
        cbb_core::keylevel::allows(self.level(), &store, &d.name, "allow keys in a file for it", a.allow_file_key)?;
        Ok(mesh.write_by(key, |set, k| writers::make_admin(set, k, &a.device, &point, now))?.0)
    }

    /// The root's key level, as the service's cbb keys: never one this
    /// phone's own keys do not pass. Answers `{below}`, the admins and hubs
    /// whose keys the new level would not let in, which stay until removed.
    fn key_level(&self, a: &ManageArgs, key: &AppKey, now: u64) -> Result<Value> {
        use cbb_core::records::body::{LEVEL_FILES, LEVEL_HARDWARE, LEVEL_PROVEN};
        let level = match a.level.as_str() {
            "proven" => LEVEL_PROVEN,
            "hardware" => LEVEL_HARDWARE,
            "files" => LEVEL_FILES,
            _ => return Err(Error::msg("the key level is proven, hardware or files")),
        };
        let mesh = &self.live.mesh;
        let me = id_text(&mesh.device());
        let devices = self.devices();
        let own = devices.iter().find(|d| d.id == me).map(|d| d.store.clone()).unwrap_or_default();
        cbb_core::keylevel::allows(&a.level, &own, "this phone, the group's root,", "", true)?;
        // The default, hardware, is written as no level at all (format 4.5).
        let kept = if level == LEVEL_HARDWARE { 0 } else { level };
        mesh.write_by(key, |set, k| writers::set_settings(set, k, |s| s.key_level = kept, now))?;
        let st = mesh.state();
        let below: Vec<String> = devices
            .into_iter()
            .filter(|d| d.id != me)
            .filter(|d| d.admin || st.hubs.iter().any(|h| id_text(h) == d.id))
            .filter(|d| cbb_core::keylevel::allows(&a.level, &d.store, &d.name, "", true).is_err())
            .map(|d| d.name)
            .collect();
        Ok(json!({ "below": below }))
    }

    /// The command a manage request names, built and checked as the
    /// service builds it (`cbb_member::orders`).
    fn order(&self, a: &ManageArgs) -> Result<cbb_member::orders::Order> {
        use cbb_member::orders::{Order, Way, What};
        Ok(match a.action.as_str() {
            "mute" => {
                cbb_member::mute::until(a.for_ms)?;
                Order::Mute((a.for_ms > 0).then_some(a.for_ms.unsigned_abs()))
            }
            "unmute" => Order::Unmute,
            "sync_off" => Order::Mode(cbb_core::clip::Mode::Own),
            "sync_on" => Order::Mode(cbb_core::clip::Mode::Shared),
            "paste_off" => Order::PasteOff,
            "actions_off" => Order::ActionsOff,
            "away_off" => Order::AwayOff,
            _ => {
                let way = match a.method.as_str() {
                    "" | "paste" => Way::Paste,
                    "type" => Way::Type,
                    m => return Err(Error::msg(format!("a paste is pasted or typed, not {m:?}"))),
                };
                let what = match a.kind.as_str() {
                    "" | "text" => What::Text(a.text.clone()),
                    "secret" => What::Secret(a.text.clone()),
                    "media" => {
                        if way == Way::Type {
                            return Err(Error::msg("images and files are pasted, not typed"));
                        }
                        let id = self.live.media_copy().ok_or_else(|| {
                            Error::msg("the group's current copy is no images or files that this phone reads")
                        })?;
                        What::Media(id)
                    }
                    k => return Err(Error::msg(format!("a paste is a text or a secret, not {k:?}"))),
                };
                Order::Paste { way, enter: a.enter, what }
            }
        })
    }

    /// Opens a pairing window with the admitting key behind sign
    /// (`crate::window`): the member port must listen.
    /// The member underneath, for the inviter of `cbb_invite_new`.
    pub fn live(&self) -> Arc<Live> {
        self.live.clone()
    }

    pub fn window(&self, request: &[u8], sign: SignFn, ctx: usize) -> (Option<crate::window::Window>, Vec<u8>) {
        if self.stopped.load(Ordering::SeqCst) {
            return (None, answer::<()>(Err(Error::msg("the member stopped"))));
        }
        let port = lock(&self.port).as_ref().map(|l| l.port);
        crate::window::Window::open(self.live.clone(), port, request, sign, ctx)
    }

    /// What the watch asks is not on the records of 0.6 yet.
    /// An action from the watch's wrist: none on 0.6, where the watch
    /// signs nothing and only shows the group (D-124; signing on the watch
    /// comes with 0.7).
    pub fn manage_watch(&self) -> Vec<u8> {
        answer::<()>(Err(Error::msg(WATCH_SIGNS_NOTHING)))
    }

    /// The root makes the watch a device of the group whose admin key is
    /// the one the watch made (`a.key`, a SubjectPublicKeyInfo in base64),
    /// with a member key nobody keeps (D-124): answers its device ID and
    /// name.
    fn add_watch(&self, a: &ManageArgs, key: &AppKey, now: u64) -> Result<Value> {
        #[derive(serde::Deserialize)]
        struct Der(#[serde(with = "certs::b64")] Vec<u8>);
        let Der(spki) =
            serde_json::from_value(json!(a.key.trim())).map_err(|_| Error::msg("the watch's key is not base64"))?;
        let point = certs::p256_spki(&spki)
            .ok_or_else(|| Error::msg("the watch's key is no P-256 key"))?
            .to_sec1_point(false)
            .as_bytes()
            .to_vec();
        let name = if a.name.trim().is_empty() { "Watch" } else { a.name.trim() };
        let os = if a.os.is_empty() { "harmonyos" } else { a.os.as_str() };
        let (id, _) = self.live.mesh.write_by(key, |set, k| writers::add_watch(set, k, name, os, &point, now))?;
        Ok(json!({ "device": id_text(&id), "name": name }))
    }
}

/// Carries out a command for the phone itself that the core took and
/// checked (format section 6, `cbb_member::orders`), as the computer's
/// member does: a mute or its end and the mode (sync off or on) here, the
/// app hearing of each; the switches a phone does not have are off
/// already; an error refuses or fails it, with why.
fn carry_out(live: &Live, me: &Me, dir: &Path, ev: &Events, t: &cbb_member::commands::Taken) -> Result<()> {
    use cbb_member::commands::refuse;
    use cbb_member::orders::Order;
    let st = live.mesh.state();
    // Who signed it: a device's own key or its admin key, or the root's.
    let root = st.roots.last() == Some(&t.signer);
    let by = st
        .devices
        .iter()
        .find(|d| d.key.hash() == t.signer || d.admin.as_ref() == Some(&t.signer))
        .or_else(|| if root { st.root_device.and_then(|r| st.devices.iter().find(|d| d.id == r)) } else { None });
    let by_id = by.map(|d| id_text(&d.id)).unwrap_or_default();
    let who = by.map(|d| d.name.clone()).filter(|n| !n.is_empty()).unwrap_or_else(|| by_id.clone());
    let log = |line: &str| ev.send(&Event::Log { line });
    match Order::read(t.kind, t.orders.as_deref())? {
        Order::Mute(ms) => {
            let now = cbb_member::uptime::wall_ms();
            let until = ms.map_or(0, |ms| now.saturating_add(i64::try_from(ms).unwrap_or(i64::MAX)));
            live.board.set_mute(until);
            cbb_member::mute::save(dir, &live.board, &by_id)?;
            me.hello(live);
            let for_ms = if until == 0 { 0 } else { until.saturating_sub(now).max(1) };
            log(&format!("cbb: {who} muted this phone"));
            ev.send(&Event::Mute { muted: true, for_ms, by: &by_id });
            Ok(())
        }
        Order::Unmute => {
            live.board.unmute();
            cbb_member::mute::save(dir, &live.board, &by_id)?;
            me.hello(live);
            log(&format!("cbb: {who} ended this phone's mute"));
            ev.send(&Event::Mute { muted: false, for_ms: 0, by: &by_id });
            Ok(())
        }
        Order::Mode(m) => {
            let on = m == cbb_core::clip::Mode::Shared;
            cbb_member::sync::set(dir, &live.board, on, 0)?;
            me.hello(live);
            log(&format!("cbb: {who} turned sync {} on this phone", if on { "on" } else { "off" }));
            ev.send(&Event::Sync { off: !on, by: &by_id });
            Ok(())
        }
        // A phone of 0.6 takes no remote paste, has no quick actions and
        // does not sync away from home: each of them is off already.
        Order::PasteOff | Order::ActionsOff | Order::AwayOff => Ok(()),
        Order::Action(_) => Err(refuse("a phone has no quick actions")),
        Order::Hub(h) => {
            if !root {
                return Err(refuse("only the group's root sets a phone's forwarder"));
            }
            if h.stop {
                return Err(refuse("a phone stops being a hub by its own switch, not by a command"));
            }
            take_forwarder(live, dir, &h)?;
            log(&format!("cbb: {who} set this phone's forwarder"));
            Ok(())
        }
        Order::Device { .. } => Err(refuse("a phone carries out no small device's own command")),
        Order::Paste { .. } => Err(not_yet("a remote paste on a phone")),
    }
}

/// The forwarder the group's root set for this phone as a hub, in the
/// phone's folder: the root's hub command names it, and the root
/// makes the blind credentials the forwarder asks of it.
const ROOT_FORWARDER: &str = "root_forwarder.json";

/// A forwarder as the root set it: its address and its key's pin.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, Deserialize)]
struct RootForwarder {
    endpoint: String,
    /// The pin of the forwarder's key, standard base64.
    key: String,
}

/// The forwarder the root set for this phone, if any.
fn root_forwarder(dir: &Path) -> Option<RootForwarder> {
    let b = std::fs::read(dir.join(ROOT_FORWARDER)).ok()?;
    serde_json::from_slice(&b).ok()
}

/// Takes the root's hub command on a phone only as the phone's forwarder
/// setting: it keeps the first forwarder the command names (none clears
/// it) and, while the user's switch has the phone serve as a hub, serves
/// again through it, hidden as before. It never turns the hub on: that is
/// the user's switch on the phone.
fn take_forwarder(live: &Live, dir: &Path, h: &cbb_member::orders::Hub) -> Result<()> {
    let path = dir.join(ROOT_FORWARDER);
    let Some((endpoint, pin)) = h.forwarders.first() else {
        return match std::fs::remove_file(&path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                Err(Error::with("cannot forget the root's forwarder", e))
            }
            _ => Ok(()),
        };
    };
    let fw = RootForwarder { endpoint: endpoint.clone(), key: certs::b64::encode(pin) };
    let b = serde_json::to_vec(&fw).map_err(|e| Error::with("cannot write the root's forwarder", e))?;
    cbb_member::files::write_atomic(&path, &b, 0o600)?;
    let Some(away) = live.away().filter(|a| a.is_hub_now()) else { return Ok(()) };
    let st = live.away_status().unwrap_or_default();
    let port = away.hub_settings().map_or(0, |(_, _, port)| i64::from(port));
    let hdr = cbb_member::control::Header {
        name: "hub".into(),
        forwarder: fw.endpoint,
        forwarder_key: fw.key,
        obfuscate_off: !st.obfuscated,
        vless_off: !st.vless,
        port,
        consent: true,
        ..Default::default()
    };
    away.make_hub(&hdr)?;
    Ok(())
}

/// A copy from the group to write to the phone's clipboard: its text, and
/// the copy itself for the app's list, with the manifest of its images or
/// files, which the app fetches (the op `fetch`) and writes itself.
fn deliver(ev: &Events, w: &Write) {
    let kind = if w.media.is_some() { Kind::Media } else { w.kind };
    let ttl_ms = w.ttl.map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
    ev.send(&Event::Write { text: &w.text, kind: kind_name(kind), ttl_ms });
    let id = certs::hex(&w.id);
    ev.send(&Event::Copy {
        copy: json!({
            "id": id,
            "origin": id_text(&w.from),
            "age_ms": 0,
            "kind": kind_name(kind),
            "text": w.text,
            "media": w.media,
            "key": id,
        }),
    });
}

/// The group's state as the apps show it (inventory 4.5): the group,
/// its root, this device's place and the devices that count. A device is
/// an admin when the admin key the records name for it is one of the
/// group's admins. Removed devices are not listed: the apps get no more
/// of the group than they show.
fn group_view(set: &cbb_core::records::RecordSet, me: &cbb_core::records::DeviceId) -> Value {
    use cbb_core::records::body::{ROLE_LEAF, ROLE_MEMBER, ROLE_PHONE, ROLE_WATCH};
    use cbb_core::records::eval::{DeviceState, Stop};
    let role = |r: u64| match r {
        ROLE_MEMBER => "computer",
        ROLE_PHONE => "phone",
        ROLE_WATCH => "watch",
        ROLE_LEAF => "leaf",
        _ => "unknown",
    };
    let st = &set.state();
    let admin = |d: &DeviceState| d.admin.as_ref().is_some_and(|h| set.is_admin(h));
    let mine = st.devices.iter().find(|d| d.id == *me);
    let devices: Vec<Value> = st
        .devices
        .iter()
        .map(|d| {
            json!({
                "device": id_text(&d.id), "name": d.name, "os": cbb_core::format::print::os_name(d.os),
                "role": role(d.role), "admin": admin(d), "frozen": d.frozen, "hub": st.hubs.contains(&d.id),
            })
        })
        .collect();
    json!({
        "group": certs::b64::encode(&st.group.0),
        "root": st.roots.last().map(|r| certs::b64::encode(&r.0)).unwrap_or_default(),
        "root_device": st.root_device.as_ref().map(id_text).unwrap_or_default(),
        "me": {
            "device": id_text(me),
            "role": mine.map_or("", |d| role(d.role)),
            "admin": mine.is_some_and(admin),
            "frozen": mine.is_some_and(|d| d.frozen),
            "leaf": mine.is_some_and(|d| d.role == ROLE_LEAF),
        },
        "stop": match st.stop {
            Stop::None => "none",
            Stop::Secrets => "secrets",
            Stop::Full => "full",
        },
        "halted": st.halted(),
        "update_needed": st.update_needed,
        "too_old": st.too_old,
        "change_arriving": st.first_missing.is_some() || st.list_missing.is_some(),
        "devices": devices,
    })
}

/// A forwarder's address as `ip:port`, looked up when it is a name (an IPv4
/// address first); empty stays empty.
fn resolve(s: &str) -> Result<String> {
    use std::net::{SocketAddr, ToSocketAddrs as _};
    let s = s.trim();
    if s.is_empty() || s.parse::<SocketAddr>().is_ok() {
        return Ok(s.to_string());
    }
    let addrs: Vec<SocketAddr> =
        s.to_socket_addrs().map_err(|e| Error::with(format!("cannot look up {s}"), e))?.collect();
    addrs
        .iter()
        .find(|a| a.is_ipv4())
        .or(addrs.first())
        .map(SocketAddr::to_string)
        .ok_or_else(|| Error::msg(format!("{s} has no address")))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

    use super::super::Member;
    use super::*;

    /// A key the test's callbacks sign with, as an app's would.
    struct Signer(Arc<dyn ExternalKey>);

    unsafe extern "C" fn sign(
        ctx: *mut core::ffi::c_void,
        digest: *const u8,
        sig: *mut u8,
        sig_len: *mut usize,
    ) -> i32 {
        // SAFETY: ctx is a Signer the test keeps for the process, digest
        // 32 bytes and sig room for 72, as the callback's contract says.
        unsafe {
            let k = &*(ctx as *const Signer);
            let d: [u8; 32] = core::slice::from_raw_parts(digest, 32).try_into().unwrap();
            let Ok(s) = k.0.sign_digest(&d) else { return 1 };
            core::ptr::copy_nonoverlapping(s.as_ptr(), sig, s.len());
            *sig_len = s.len();
        }
        0
    }

    unsafe extern "C" fn events(_ctx: *mut core::ffi::c_void, _event: *const u8, _len: usize) {}

    fn ok(answer: &[u8]) -> Value {
        let v: Value = serde_json::from_slice(answer).unwrap();
        v.get("ok").cloned().unwrap_or_else(|| panic!("an error: {v}"))
    }

    fn error(answer: &[u8]) -> String {
        let v: Value = serde_json::from_slice(answer).unwrap();
        v["error"]["message"].as_str().unwrap_or_else(|| panic!("no error: {v}")).to_string()
    }

    #[test]
    fn a_phone_on_a_group_of_0_6_runs_the_member_of_0_6() {
        let dir = std::env::temp_dir().join(format!("cbb-ffi-live-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let empty = json!({ "dir": dir.to_string_lossy() }).to_string();
        assert!(!on_06(empty.as_bytes()), "a folder without group.cbor is 0.5's");

        let me = cbb_member::founding::Me { name: "phone", os: 0, caps: 0 };
        let now = cbb_member::uptime::wall_ms().max(0).unsigned_abs();
        cbb_member::founding::found_with(&dir, &me, now, &|| None).unwrap();
        let own = Own::load(&dir).unwrap();
        let device = id_text(&own.device());
        let member: &'static Signer = Box::leak(Box::new(Signer(own.member.clone())));
        let root: &'static Signer = Box::leak(Box::new(Signer(own.root.clone().unwrap())));
        let ctx = |s: &'static Signer| s as *const Signer as usize;

        let req = json!({
            "dir": dir.to_string_lossy(), "name": "phone", "os": "ios", "device": device,
            "public": b64(&member.0.public()), "mdns": false,
        })
        .to_string();
        assert!(on_06(req.as_bytes()));
        let wrong = req.replace(&device, "00000000000000000000000000000000");
        let (m, a) = Member::start(wrong.as_bytes(), sign, events, ctx(member));
        assert!(m.is_none() && error(&a).contains("is not the one its member key makes"));

        let (m, a) = Member::start(req.as_bytes(), sign, events, ctx(member));
        ok(&a);
        let m = m.unwrap();
        assert!(matches!(m, Member::Live(_)));
        let call = |op: &str, args: Value| m.call(json!({ "op": op, "args": args }).to_string().as_bytes());

        ok(&call("copy", json!({ "text": "hello" })));
        let devs = ok(&call("devices", Value::Null));
        assert_eq!(devs["devices"][0]["name"], "phone");
        ok(&call("sync", json!({ "on": false })));
        assert_eq!(ok(&call("muted", Value::Null))["sync_off"], true);
        ok(&call("sync", json!({ "on": true })));
        assert!(ok(&call("why", Value::Null))["why"].is_array());
        let g = ok(&call("group", Value::Null));
        assert_eq!(g["root_device"], device.as_str(), "{g}");
        assert_eq!(g["me"]["device"], device.as_str());
        assert_eq!(g["me"]["role"], "computer");
        assert_eq!(g["me"]["admin"], false, "the root is no admin");
        assert_eq!((g["stop"].as_str(), g["halted"].as_bool()), (Some("none"), Some(false)));
        assert_eq!(g["devices"].as_array().unwrap().len(), 1);
        assert_eq!(g["devices"][0]["name"], "phone");

        // What has not moved answers why, never nothing.
        for op in ["records", "answer"] {
            assert!(error(&call(op, Value::Null)).contains("does not work in this build yet"), "{op}");
        }
        // A root phone is no hub until the root names it.
        assert!(error(&call("hub", Value::Null)).contains("do not make this phone a hub"));
        let manage = |action: &str, device: &str, name: &str| {
            let r = json!({ "action": action, "device": device, "name": name, "public": b64(&root.0.public()) });
            m.manage(r.to_string().as_bytes(), sign, ctx(root))
        };
        assert_eq!(ok(&manage("rename", "phone", "tablet"))["name"], "phone");
        assert_eq!(ok(&call("devices", Value::Null))["devices"][0]["name"], "tablet");
        assert!(error(&manage("remove", "tablet", "")).contains("cannot remove itself"));
        // A command names another device; this phone's own switches are its own.
        assert!(error(&manage("mute", "tablet", "")).contains("its own, not a command"));
        assert!(error(&manage("hand_over", "tablet", "")).contains("does not work in this build yet"));
        // The root sets the group's relays, and none again.
        let pin = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
        let relay = json!({ "action": "relay", "relays": [format!("203.0.113.9:8764 {pin}")], "public": b64(&root.0.public()) });
        assert_eq!(ok(&m.manage(relay.to_string().as_bytes(), sign, ctx(root)))["relays"], json!(["203.0.113.9:8764"]));
        let bad = json!({ "action": "relay", "relays": ["203.0.113.9:8764 nope"], "public": b64(&root.0.public()) });
        assert!(error(&m.manage(bad.to_string().as_bytes(), sign, ctx(root))).contains("is not a relay's key"));
        let none = json!({ "action": "relay", "relays": [], "public": b64(&root.0.public()) });
        assert_eq!(ok(&m.manage(none.to_string().as_bytes(), sign, ctx(root)))["relays"], json!([]));
        // The root names its hubs, which the records judge: a phone is a hub
        // only with an admin key, never by the hubs record.
        let hubs = json!({ "action": "hubs", "hubs": ["tablet"], "public": b64(&root.0.public()) });
        assert!(error(&m.manage(hubs.to_string().as_bytes(), sign, ctx(root))).contains("may not be a hub"));
        let none = json!({ "action": "hubs", "hubs": [], "public": b64(&root.0.public()) });
        assert!(error(&m.manage(none.to_string().as_bytes(), sign, ctx(root))).contains("1 to 16 hubs"));

        m.stop();
        assert_eq!(error(&call("devices", Value::Null)), "the member stopped");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The root's hub command on a phone only sets the phone's forwarder:
    /// it never switches the hub on, a command of another key or one to
    /// stop is refused, and a command with no forwarder clears it.
    #[test]
    fn a_hub_command_on_a_phone_sets_its_forwarder_and_does_not_switch_the_hub_on() {
        use cbb_member::orders::{Hub, Order};
        let dir = std::env::temp_dir().join(format!("cbb-ffi-live-fw-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let me = cbb_member::founding::Me { name: "phone", os: 0, caps: 0 };
        let now = cbb_member::uptime::wall_ms().max(0).unsigned_abs();
        cbb_member::founding::found_with(&dir, &me, now, &|| None).unwrap();
        let own = Own::load(&dir).unwrap();
        let member: &'static Signer = Box::leak(Box::new(Signer(own.member.clone())));
        let req = json!({
            "dir": dir.to_string_lossy(), "name": "phone", "os": "ios", "device": id_text(&own.device()),
            "public": b64(&member.0.public()), "mdns": false,
        })
        .to_string();
        let (m, a) = Member::start(req.as_bytes(), sign, events, member as *const Signer as usize);
        ok(&a);
        let m = m.unwrap();
        let Member::Live(phone) = &m else { panic!("not the member of 0.6") };
        let call = |op: &str, args: Value| m.call(json!({ "op": op, "args": args }).to_string().as_bytes());
        ok(&call("away", json!({ "on": true })));
        let none = ok(&call("away_status", Value::Null));
        assert!(none["root_forwarder"].is_null(), "{none}");

        let ev = Events { f: events, ctx: 0 };
        let st = phone.live.mesh.state();
        let root = *st.roots.last().unwrap();
        let other = phone.live.mesh.own().hash();
        drop(st);
        let taken = |o: &Order, signer| cbb_member::commands::Taken {
            kind: o.kind(),
            id: [1; 16],
            signer,
            orders: o.orders().unwrap(),
        };
        let set = Order::Hub(Hub { forwarders: vec![("203.0.113.9:8764".into(), [7; 32])], ..Hub::default() });
        assert!(
            carry_out(&phone.live, &phone.me, &dir, &ev, &taken(&set, other))
                .unwrap_err()
                .message()
                .contains("only the group's root")
        );
        assert!(root_forwarder(&dir).is_none(), "a command of another key changed nothing");
        let stop = Order::Hub(Hub { stop: true, ..Hub::default() });
        assert!(
            carry_out(&phone.live, &phone.me, &dir, &ev, &taken(&stop, root))
                .unwrap_err()
                .message()
                .contains("its own switch")
        );

        carry_out(&phone.live, &phone.me, &dir, &ev, &taken(&set, root)).unwrap();
        let got = ok(&call("away_status", Value::Null));
        assert_eq!(
            got["root_forwarder"],
            json!({ "endpoint": "203.0.113.9:8764", "key": certs::b64::encode(&[7; 32]) }),
            "{got}"
        );
        assert!(!got["away"]["hub"].as_bool().unwrap_or(false), "the command did not switch the hub on: {got}");

        // A command that names the phone's own address and no forwarder clears it.
        let clear = Order::Hub(Hub { hub: Some(("198.51.100.7:8764".into(), other.0)), ..Hub::default() });
        carry_out(&phone.live, &phone.me, &dir, &ev, &taken(&clear, root)).unwrap();
        assert!(ok(&call("away_status", Value::Null))["root_forwarder"].is_null());
        m.stop();
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn b64(b: &[u8]) -> Value {
        super::super::b64(b)
    }
}
