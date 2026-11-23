// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The phone's member on the records of 0.6 (`cbb_member::live`): what
//! `cbb_member_start` runs when the app's folder holds the group's
//! `group.cbor`. The member key stays in the app and signs through its
//! callback; the app finds the members itself and hands them in with
//! `found`. The operations this version does not have answer the error of
//! `cbb_member::live::not_yet`, whose cause debug builds show, never a
//! silent no-op.

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
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{Event, EventFn, Events, Request, SyncArgs, args, lock};
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

/// What `cbb_member_start` takes: the records name the group's devices
/// and keys, so the app hands in no certificates.
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

/// `push`'s argument: this phone's registration, message `push` (t 28) as
/// the core's `push_registration` made it, base64; none stops sending one.
#[derive(Deserialize)]
struct PushArgs {
    #[serde(default)]
    frame: Option<B64>,
}

#[derive(Deserialize)]
struct B64(#[serde(with = "certs::b64")] Vec<u8>);

/// Bytes as JSON, base64.
fn b64_value(b: &[u8]) -> Value {
    #[derive(serde::Serialize)]
    struct B<'a>(#[serde(with = "certs::b64")] &'a [u8]);
    serde_json::to_value(B(b)).unwrap_or(Value::Null)
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
    /// With ttl: the group's lifetime of an ordinary copy, in
    /// milliseconds; absent keeps the group's.
    #[serde(default)]
    ttl_ms: Option<u64>,
    /// With ttl: the group's lifetime of a secret, in milliseconds; absent
    /// keeps the group's.
    #[serde(default)]
    secret_ttl_ms: Option<u64>,
    /// With forwarder, on the root: the hub's forwarder, `host:port` or
    /// `default` for the project's, and its key's pin in base64 (`key`).
    #[serde(default)]
    forwarder: String,
    #[serde(default)]
    key: String,
    /// With change_preview and change_root: the group's recovery key, as
    /// `{qr}` or `{text}` from the sheet or `{secret}` (base64, 32 bytes)
    /// a YubiKey opened; the devices that do not stay, by name or ID; and
    /// how the change goes (`writers::Change`).
    #[serde(default)]
    recovery: Value,
    #[serde(default)]
    leave_out: Vec<String>,
    #[serde(default)]
    drop_hubs: bool,
    #[serde(default)]
    over_waiting: bool,
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

/// Why a takeover, a handover or a claim's delay is refused on 0.6 (D-117).
const ROOT_BY_RECOVERY: &str = "the group's root changes only with its recovery key on the records of 0.6 (change the root with the recovery sheet or YubiKey); a takeover, a handover and a claim's delay are gone";

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

/// The recovery key the app gives: `{"qr"}` or `{"text"}` of the sheet, or
/// `{"secret"}`, the 32 bytes in base64 that a YubiKey opened
/// (`cbb_piv`'s `open`).
pub(crate) fn recovery_read(r: &Value) -> Result<cbb_core::sheet::Read> {
    Ok(if let Some(t) = r.get("qr").or_else(|| r.get("text")).and_then(Value::as_str) {
        cbb_core::sheet::read(t).map_err(|e| Error::msg(e.message()))?
    } else if let Some(s) = r.get("secret") {
        #[derive(serde::Deserialize)]
        struct Der(#[serde(with = "certs::b64")] Vec<u8>);
        let Der(b) = serde_json::from_value(s.clone()).map_err(|_| Error::msg("the recovery secret is not base64"))?;
        let b = cbb_core::secret::Zeroizing::new(b);
        let secret: [u8; 32] =
            b.as_slice().try_into().map_err(|_| Error::msg("the recovery secret is not 32 bytes"))?;
        cbb_core::sheet::Read { secret: cbb_core::secret::Zeroizing::new(secret), group: None }
    } else {
        return Err(Error::msg("give the recovery key: the sheet's QR code or text, or the secret a YubiKey opened"));
    })
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

/// What a gesture or an opening does, as the app reads it: `sends`, and
/// the copy that comes in (`copy`), or null.
fn swap_json(s: cbb_member::button::Swap) -> Value {
    json!({ "sends": s.sends, "copy": s.takes.map(|e| event_json(&e)) })
}

/// A copy the button's rule gives, as the app reads it.
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

/// The group's current copy as the app reads it.
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
        // Its images or files, which the app fetches (the op `fetch`) and
        // saves, also when the board did not write the copy (a phone
        // that takes no media by itself), and the lifetime its sender
        // stamped (D-129), by which the app hides its "Last received".
        "media": c.content.manifest,
        "unread": !c.content.writable(),
        "key": id,
        "ttl_ms": c.content.ttl_ms(),
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
        // The signed entry points, whose keys.json names the push service
        // the phone's face is for.
        live.keep_signed(&dir, &*log);
        live.on_write(Box::new(move |w| deliver(&ev, &w)));
        watch_records(&live, &dir, ev, log.clone());
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
            // The one button and the app's opening (cbb_member::button,
            // D-128), on the group's current copy: whether the clipboard
            // (its key, `board`) goes out, and the copy that comes in.
            "swap" => {
                let board = arg("board");
                let s = cbb_member::button::swap(board.as_str().unwrap_or_default(), self.current_event(), &self.own);
                Ok(swap_json(s))
            }
            "opened" => {
                let board = arg("board");
                let changed = arg("changed").as_bool().unwrap_or(false);
                let s = cbb_member::button::opened(
                    board.as_str().unwrap_or_default(),
                    changed,
                    self.current_event(),
                    &self.own,
                );
                Ok(swap_json(s))
            }
            "took" => {
                let id = arg("id");
                let id = id.as_str().ok_or_else(|| Error::msg("took needs the copy's id"))?;
                if let Some(ev) = self.current_event().filter(|e| e.id == id) {
                    self.own.took(&ev);
                }
                done()
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
            // Push to this phone while its app is closed (docs/core-api.md,
            // "Push"): the group's face the registration names, the
            // registration the members get, and the members' push-renew.
            "push_face" => Ok(json!({ "face": l.mesh.push_face().map(|f| b64_value(&f)) })),
            "push" => {
                let p: PushArgs = args(a)?;
                l.mesh.set_own_push(p.frame.map(|B64(f)| f))?;
                done()
            }
            "push_renewals" => {
                let r: Vec<Value> = l
                    .mesh
                    .take_renewals()
                    .iter()
                    .map(|(slot, ahead)| json!({ "slot": b64_value(slot), "ahead": ahead }))
                    .collect();
                Ok(json!({ "renewals": r }))
            }
            "away_status" => Ok(self.away_answer()),
            "group" => Ok(group_view(&lock(&l.mesh.set()), &l.mesh.device(), l.mesh.dir())),
            "why" => Ok(json!({ "why": self.why(away_arg(&arg("away"))?) })),
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
            // The attestation of the phone's own member key its app made,
            // which every peer gets (t 19).
            "evidence" => {
                let list = arg("evidence").as_array().cloned().unwrap_or_default();
                l.set_own_evidence(&list)?;
                done()
            }
            // The tiles to draw, and the person's change of their order
            // (docs/apps.md, "What the member shows"); the view's
            // warnings are why's reasons.
            "view" | "arrange" => {
                let op: Option<cbb_core::arrange::Op> = if op == "arrange" {
                    Some(serde_json::from_value(arg("arrange")).map_err(|e| Error::msg(format!("arrange: {e}")))?)
                } else {
                    None
                };
                let tiles = cbb_member::view::Tiles::new(&self.dir);
                let mut view = tiles.view(&l.tag(), self.devices(), op.as_ref())?;
                view.warnings = self.why(away_arg(&arg("away"))?);
                Ok(json!({ "view": view }))
            }
            "notices" => Ok(json!({ "notices": self.notices() })),
            // The person saw the change of root the member told of: it is
            // not told again, not even after a restart.
            "root_change_seen" => {
                if let Some(mut seen) = root_seen(&self.dir) {
                    seen.pending = None;
                    keep_root_seen(&self.dir, &seen)?;
                }
                done()
            }
            // A notice the person hid: the set keeps it dismissed.
            "dismiss" => {
                let id = arg("id");
                let id = id.as_str().and_then(record_id).ok_or_else(|| Error::msg("dismiss needs a notice's id"))?;
                lock(&l.mesh.set()).dismiss(&id);
                l.mesh.changed()?;
                done()
            }
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
    /// records give; away, where a tunnel the app runs itself stands, in
    /// place of the member's own.
    fn why(&self, away: Option<cbb_core::why::AwayFacts>) -> Vec<cbb_core::why::Reason> {
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
        if away.is_some() {
            facts.away = away;
        }
        cbb_core::why::group_facts(&mut facts, &st, &me);
        facts.checkpoint_stuck = !lock(&l.mesh.set()).stuck_checkpoints().is_empty();
        cbb_core::why::diagnose(&facts, cbb_member::uptime::wall_ms())
    }

    /// The member's notices about the group (`notices_of`).
    fn notices(&self) -> Vec<Value> {
        let held = self.live.mesh.set();
        let set = lock(&held);
        notices_of(&set, &self.live.mesh.device())
    }

    /// Sync away from home as the away ops answer it: its state, null
    /// while it is off; and on the root phone whether
    /// the group's server credentials need its root key (`period_due`,
    /// which the manage action `period` renews) and whether they expired
    /// already (`period_overdue`), so that the group's relay and its hubs'
    /// forwarders take nobody until then.
    fn away_answer(&self) -> Value {
        let (due, overdue) = self.live.mesh.periods();
        json!({
            "away": self.live.away_status(),
            "period_due": due,
            "period_overdue": overdue,
        })
    }

    /// Whether sync is off and whether the phone is muted.
    fn state(&self) -> Value {
        serde_json::to_value(cbb_member::sync::standing(&self.live.board)).unwrap_or_default()
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
                // The group's lifetimes of copies, which every member's
                // copies carry, set by the root or an admin (format,
                // "copies").
                "ttl" => {
                    mesh.write_by(&key, |set, k| writers::set_ttl(set, k, a.ttl_ms, a.secret_ttl_ms, now))?;
                    let st = mesh.state();
                    return Ok(json!({ "ttl_ms": st.ttl_ms, "secret_ttl_ms": st.secret_ttl_ms }));
                }
                "hubs" => {
                    mesh.write_by(&key, |set, k| writers::set_hubs(set, k, &a.hubs, now))?;
                    self.renew_by(&key);
                    return Ok(json!({ "hubs": a.hubs }));
                }
                "make_admin" => self.make_admin(&a, &key, now)?,
                "key_level" => return self.key_level(&a, &key, now),
                "add_watch" => return self.add_watch(&a, &key, now),
                "change_preview" => return self.change_preview(&a),
                "change_root" => return self.change_root(&a, &key, now),
                // On 0.6 the root changes only with the recovery key (D-117).
                "take_over" | "take_handed_over" | "recover" | "hand_over" | "takeover_delay" | "finish_takeover" => {
                    return Err(Error::msg(ROOT_BY_RECOVERY));
                }
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
        if !st.may_be_hub(&d.id) {
            return Err(Error::msg(format!(
                "the group's records do not make {} a hub; only a computer with an admin key or one the root names can be one",
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
        level_name(self.live.mesh.state().settings.level())
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
        // The default, hardware, is written as no level at all (format 4.4).
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
                // Cleaned as the computer cleans it (remotepaste::to_paste), so
                // that a text with nothing left is refused here, before anything
                // is signed or sent.
                let what = match a.kind.as_str() {
                    "" | "text" => What::Text(cbb_core::remotepaste::to_paste(&a.text)?),
                    "secret" => What::Secret(cbb_core::remotepaste::to_paste(&a.text)?),
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

    /// An action from the watch's wrist: none on 0.6, where the watch
    /// signs nothing and only shows the group (D-124; signing on the watch
    /// comes with 0.7).
    pub fn manage_watch(&self) -> Vec<u8> {
        answer::<()>(Err(Error::msg(WATCH_SIGNS_NOTHING)))
    }

    /// The recovery key the request gives, checked against the group's:
    /// both its halves, which live only for the call.
    fn recovery_keys(&self, a: &ManageArgs) -> Result<(cbb_core::identity::FileKey, cbb_core::records::pq::PqKey)> {
        let read = recovery_read(&a.recovery)?;
        let mesh = &self.live.mesh;
        let st = mesh.state();
        let recovery = lock(&mesh.set()).recovery().clone();
        cbb_core::sheet::check(&read, &st.group, &recovery).map_err(|e| Error::msg(e.message()))?;
        writers::recovery_keys(&read.secret)
    }

    /// The keys of the devices the person left out of a change of root,
    /// by name or ID; never this phone, which becomes the root.
    fn left_out(&self, a: &ManageArgs) -> Result<Vec<cbb_core::records::KeyHash>> {
        let mesh = &self.live.mesh;
        let st = mesh.state();
        let mut out = Vec::new();
        for name in &a.leave_out {
            let d = writers::find(&st, name)?;
            if d.id == mesh.device() {
                return Err(Error::msg("this phone becomes the root: it stays in the group"));
            }
            out.extend(writers::keys_of(d));
        }
        Ok(out)
    }

    /// Fails when this phone is the group's root already.
    fn not_root_yet(&self) -> Result<()> {
        if self.live.mesh.state().root_device == Some(self.live.mesh.device()) {
            return Err(Error::msg("this phone is the group's root already"));
        }
        Ok(())
    }

    /// Who stays after a change of root with the recovery key, before
    /// anything is signed (`RecordSet::change_preview`): each other device
    /// with what the change does to it, and whether a change already waits
    /// for its records.
    fn change_preview(&self, a: &ManageArgs) -> Result<Value> {
        self.not_root_yet()?;
        drop(self.recovery_keys(a)?);
        let out = self.left_out(a)?;
        let mesh = &self.live.mesh;
        let st = mesh.state();
        let me = mesh.device();
        let devices = self.devices();
        let rows: Vec<Value> = lock(&mesh.set())
            .change_preview(&st, &out)
            .into_iter()
            .filter(|p| p.device != me)
            .map(|p| {
                use cbb_core::records::set::Outcome;
                let id = id_text(&p.device);
                let d = devices.iter().find(|d| d.id == id);
                let outcome = match p.outcome {
                    Outcome::Stays => "stays",
                    Outcome::Out => "out",
                    Outcome::AdminKeptWithSpare => "admin_kept",
                    Outcome::AdminRightsLost => "admin_lost",
                    Outcome::Frozen => "frozen",
                };
                json!({
                    "device": id,
                    "name": d.map(|d| d.name.clone()).unwrap_or_default(),
                    "os": d.map(|d| d.os.clone()).unwrap_or_default(),
                    "outcome": outcome,
                    "frozen": p.frozen,
                })
            })
            .collect();
        Ok(json!({ "rows": rows, "waiting": st.first_missing.is_some() || st.list_missing.is_some() }))
    }

    /// Makes this phone the group's root with the recovery key (rule 33):
    /// both halves of the key sign the change, the app's new root key
    /// (`key`) its first records, and the devices left out go in the same
    /// act. Answers the change's step.
    fn change_root(&self, a: &ManageArgs, key: &AppKey, now: u64) -> Result<Value> {
        self.not_root_yet()?;
        let (k1, k2) = self.recovery_keys(a)?;
        let out = self.left_out(a)?;
        let me = self.live.mesh.device();
        let how = writers::Change { drop_hubs: a.drop_hubs, over_waiting: a.over_waiting };
        let w = self.live.mesh.write_by(key, |set, k| writers::recover_with(set, &k1, &k2, k, &me, &out, how, now))?;
        (self.log)("cbb: this phone is the group's root now, by the group's recovery key");
        Ok(json!({ "seq": w.record.body().seq }))
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
        Order::Hub(_) => Err(refuse("a phone is no hub: a hub is a computer, a router or a board")),
        Order::Device { .. } => Err(refuse("a phone carries out no small device's own command")),
        Order::Paste { .. } => Err(not_yet("a remote paste on a phone")),
    }
}

/// The share of the root's room that removals waiting for admins take
/// before the root phone says so (docs/apps.md, "Notices").
const ROOT_ROOM_WARN_PERCENT: u64 = 50;

/// The member's notices about the group (docs/apps.md, "Notices"), as
/// the apps show them: `{id, kind, args, dismissable}`. Only the notices of
/// removed devices that count again (`returned_after_removal`, by the
/// removal's or the change's record ID) may be hidden; the others stay
/// until what they say is over. `root_room_waiting` shows on the root's
/// own device.
fn notices_of(set: &cbb_core::records::RecordSet, me: &cbb_core::records::DeviceId) -> Vec<Value> {
    let st = set.state();
    let device_of = |k: &cbb_core::records::KeyHash| {
        st.devices.iter().find(|d| d.key.hash() == *k || d.admin.as_ref() == Some(k)).map(|d| id_text(&d.id))
    };
    let notice = |id: String, kind: &str, args: Value, dismissable: bool| json!({ "id": id, "kind": kind, "args": args, "dismissable": dismissable });
    let mut out = Vec::new();
    if set.change_arriving(&st).is_some() {
        out.push(notice("change_arriving".into(), "change_arriving", json!({}), false));
    }
    if !set.removals_waiting(&st).is_empty() {
        out.push(notice("removals_waiting".into(), "removals_waiting", json!({}), false));
    }
    if let Some(w) = set.root_room_waiting(&st, ROOT_ROOM_WARN_PERCENT).filter(|_| st.root_device == Some(*me)) {
        let percent = w.waiting_units.saturating_mul(100).checked_div(w.room.cap.max(1)).unwrap_or(0);
        out.push(notice("root_room_waiting".into(), "root_room_waiting", json!({ "percent": percent }), false));
    }
    let own_admin = st.devices.iter().find(|d| d.id == *me).and_then(|d| d.admin);
    if let Some(o) = own_admin.and_then(|k| set.ack_owed(&st, &k, wall_ms_u64())) {
        out.push(notice(
            "ack_owed".into(),
            "ack_owed",
            json!({ "removals": o.removals, "days_left": o.days_left }),
            false,
        ));
    }
    for f in set.frozen_holding(&st) {
        let d = id_text(&f.device);
        out.push(notice(format!("frozen_holding:{d}"), "frozen_holding", json!({ "device": d }), false));
    }
    if !set.stuck_checkpoints().is_empty() {
        out.push(notice("checkpoint_stuck".into(), "checkpoint_stuck", json!({}), false));
    }
    for (id, keys) in set.notices(&st) {
        let devices: Vec<String> = keys.iter().filter_map(device_of).collect();
        let Some(first) = devices.first() else { continue };
        out.push(notice(
            certs::b64::encode(&id.0),
            "returned_after_removal",
            json!({ "device": first, "devices": devices.len() }),
            true,
        ));
    }
    out
}

/// Where the phone keeps the group's root as it last told its app of it.
const ROOT_SEEN: &str = "root_seen.json";

/// The group's root as the phone last saw it: how many roots the group
/// has had and the root's device, and the change the person has not seen
/// yet.
#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq)]
struct RootSeen {
    seq: u64,
    device: String,
    #[serde(default)]
    pending: Option<RootChange>,
}

/// A change of root to tell the app of.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
struct RootChange {
    from: String,
    to: String,
    seq: u64,
}

fn root_seen(dir: &Path) -> Option<RootSeen> {
    serde_json::from_slice(&std::fs::read(dir.join(ROOT_SEEN)).ok()?).ok()
}

fn keep_root_seen(dir: &Path, seen: &RootSeen) -> Result<()> {
    let b = serde_json::to_vec(seen).map_err(|e| Error::msg(format!("cannot encode the root seen: {e}")))?;
    cbb_member::files::write_atomic(&dir.join(ROOT_SEEN), &b, 0o600)?;
    Ok(())
}

/// Notes the group's root in state against what the phone saw last: a new
/// root (more roots than before) is a change the person must see, kept as
/// pending until `root_change_seen`. The first time it only notes the root:
/// a phone that joins sees no change.
fn note_root(dir: &Path, st: &cbb_core::records::eval::State) -> Result<Option<RootChange>> {
    let seq = st.roots.len() as u64;
    let device = st.root_device.as_ref().map(id_text).unwrap_or_default();
    match root_seen(dir) {
        None => {
            keep_root_seen(dir, &RootSeen { seq, device, pending: None })?;
            Ok(None)
        }
        Some(s) if seq > s.seq => {
            let change = RootChange { from: s.device, to: device.clone(), seq };
            keep_root_seen(dir, &RootSeen { seq, device, pending: Some(change.clone()) })?;
            Ok(Some(change))
        }
        Some(_) => Ok(None),
    }
}

fn send_root_change(ev: &Events, c: &RootChange) {
    ev.send(&Event::RootChanged { from: &c.from, to: &c.to, seq: c.seq });
}

/// The notices of now that were not among the IDs shown, which then
/// become now's.
fn new_notices(shown: &mut Vec<String>, now: &[Value]) -> Vec<Value> {
    let id = |n: &Value| n["id"].as_str().map(String::from);
    let new = now.iter().filter(|n| id(n).is_some_and(|i| !shown.contains(&i))).cloned().collect();
    *shown = now.iter().filter_map(id).collect();
    new
}

/// Tells the app what the group's records change (docs/core-api.md, "The
/// member", events): the group's state on each change, each notice that
/// was not there before, and a change of root, at once and, while the
/// person has not seen it, again when the member starts.
fn watch_records(live: &Arc<Live>, dir: &Path, ev: Events, log: Arc<dyn Fn(&str) + Send + Sync>) {
    let me = live.mesh.device();
    let (shown, pending) = {
        let held = live.mesh.set();
        let set = lock(&held);
        if let Err(e) = note_root(dir, &set.state()) {
            log(&format!("cbb: the group's root as seen: {}", e.for_log()));
        }
        let mut ids = Vec::new();
        new_notices(&mut ids, &notices_of(&set, &me));
        (Arc::new(Mutex::new(ids)), root_seen(dir).and_then(|s| s.pending))
    };
    if let Some(c) = pending {
        send_root_change(&ev, &c);
    }
    // The set's lock is held while the records change: the events go to
    // the app from a thread of their own, so that an app that answers one
    // by calling the member does not wait for that lock. The thread ends
    // with the member.
    let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
    let weak = Arc::downgrade(live);
    std::thread::spawn(move || {
        while let Ok(b) = rx.recv() {
            match weak.upgrade() {
                Some(l) if !l.mesh.is_closed() => ev.send_bytes(&b),
                _ => break,
            }
        }
    });
    let queue = move |e: &Event<'_>| {
        if let Ok(b) = serde_json::to_vec(e) {
            let _ = tx.send(b);
        }
    };
    let dir = dir.to_path_buf();
    live.on_records(Box::new(move |set| {
        let st = set.state();
        match note_root(&dir, &st) {
            Ok(Some(c)) => queue(&Event::RootChanged { from: &c.from, to: &c.to, seq: c.seq }),
            Ok(None) => {}
            Err(e) => log(&format!("cbb: the group's root as seen: {}", e.for_log())),
        }
        let now = notices_of(set, &me);
        for n in new_notices(&mut lock(&shown), &now) {
            queue(&Event::Notice { notice: n });
        }
        queue(&Event::State { state: group_view(set, &me, &dir) });
    }));
}

/// The app's own tunnel as why takes it (`away`), none when it is null.
fn away_arg(v: &Value) -> Result<Option<cbb_core::why::AwayFacts>> {
    serde_json::from_value(v.clone()).map_err(|e| Error::msg(format!("away: {e}")))
}

/// A record's ID in base64, as the notices name it.
fn record_id(s: &str) -> Option<cbb_core::records::RecordId> {
    let b = certs::b64::decode_str(s)?;
    Some(cbb_core::records::RecordId(b.try_into().ok()?))
}

/// The wall clock in milliseconds, as the records count it.
fn wall_ms_u64() -> u64 {
    u64::try_from(cbb_member::uptime::wall_ms()).unwrap_or(0)
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
            "ttl_ms": ttl_ms,
        }),
    });
}

/// The group's state as the apps show it (inventory 4.5): the group,
/// its root, this device's place and the devices that count. A device is
/// an admin when the admin key the records name for it is one of the
/// group's admins. Removed devices are not listed: the apps get no more
/// of the group than they show.
/// A key level's name: proven, hardware (the default) or files.
fn level_name(level: u64) -> &'static str {
    use cbb_core::records::body::{LEVEL_FILES, LEVEL_PROVEN};
    match level {
        LEVEL_PROVEN => "proven",
        LEVEL_FILES => "files",
        _ => "hardware",
    }
}

/// The group as the apps show it. `dir` is the member's own, where the
/// admin keys offered at pairing wait (`cbb_member::offered`): a device that
/// offered one and is no admin yet `offers_admin`, which the root's "Make it
/// an admin" needs.
fn group_view(set: &cbb_core::records::RecordSet, me: &cbb_core::records::DeviceId, dir: &std::path::Path) -> Value {
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
                "offers_admin": d.admin.is_none() && cbb_member::offered::get(dir, &id_text(&d.id)).ok().flatten().is_some(),
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
        "key_level": level_name(st.settings.level()),
        "ttl_ms": st.ttl_ms,
        "secret_ttl_ms": st.secret_ttl_ms,
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

    /// The op current names the copy's images or files and its lifetime,
    /// so that the app shows and fetches a copy the board did not write.
    #[test]
    fn the_current_copy_carries_its_media_and_lifetime() {
        let manifest = cbb_core::media::Manifest { size: 3, parts: Vec::new() };
        let content = cbb_core::content::Content {
            kind: cbb_core::content::TYPE_FILES,
            manifest: Some(manifest),
            ttl: 120_000,
            ..Default::default()
        };
        let d = cbb_core::records::DeviceId([7; 16]);
        let c = Current { id: [1; 16], content, origin: d, blob: None, from: d, at_ms: 1_000 };
        let v = current_json(&c, 1_500);
        assert_eq!(
            (v["kind"].as_str(), v["age_ms"].as_i64(), v["ttl_ms"].as_u64()),
            (Some("media"), Some(500), Some(120_000))
        );
        assert_eq!(v["media"]["size"], 3);
        let plain = current_json(&Current { content: cbb_core::content::Content::text("x", false), ..c }, 1_000);
        assert_eq!((&plain["media"], &plain["ttl_ms"]), (&Value::Null, &Value::Null));
    }

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
        assert!(!on_06(empty.as_bytes()), "a folder without group.cbor holds a group made before 0.6");
        // A group made before 0.6 runs no member: the app says to make a new
        // one (D-126), and the folder stays as it is.
        let (m, a) = Member::start(empty.as_bytes(), sign, events, 0);
        assert!(m.is_none());
        assert_eq!(error(&a), super::super::BEFORE_06);
        assert!(dir.is_dir());

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
        let manage = |action: &str, device: &str, name: &str| {
            let r = json!({ "action": action, "device": device, "name": name, "public": b64(&root.0.public()) });
            m.manage(r.to_string().as_bytes(), sign, ctx(root))
        };
        assert_eq!(ok(&manage("rename", "phone", "tablet"))["name"], "phone");
        assert_eq!(ok(&call("devices", Value::Null))["devices"][0]["name"], "tablet");
        assert!(error(&manage("remove", "tablet", "")).contains("cannot remove itself"));
        // A command names another device; this phone's own switches are its own.
        assert!(error(&manage("mute", "tablet", "")).contains("its own, not a command"));
        // A remote paste is cleaned and checked before anything is signed
        // or sent, as the computer cleans it.
        {
            use cbb_member::orders::{Order, Way, What};
            let order = |method: &str, kind: &str, text: &str| {
                let a: ManageArgs = serde_json::from_value(json!({
                    "action": "paste", "device": "pc", "public": b64(&root.0.public()),
                    "method": method, "kind": kind, "text": text, "enter": true,
                }))
                .unwrap();
                m.0.order(&a)
            };
            let o = order("", "", "ls\u{1b}[2J\r\n").unwrap();
            assert!(
                matches!(&o, Order::Paste { way: Way::Paste, enter: true, what: What::Text(t) } if t == "ls\n"),
                "a text is cleaned"
            );
            let o = order("type", "secret", "pin").unwrap();
            assert!(matches!(&o, Order::Paste { way: Way::Type, what: What::Secret(_), .. }));
            for (method, kind, text) in [
                ("type", "media", "copy-id"),
                ("say", "text", "hi"),
                ("paste", "file", "hi"),
                ("paste", "text", "\u{7}\u{1b}[0m"),
                ("paste", "media", ""),
            ] {
                assert!(order(method, kind, text).is_err(), "{method} {kind} {text:?} is refused");
            }
        }
        // The root changes only with the recovery key (D-117).
        assert!(error(&manage("hand_over", "tablet", "")).contains("only with its recovery key"));
        // The root sets the group's relays, and none again.
        let pin = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
        let relay = json!({ "action": "relay", "relays": [format!("203.0.113.9:8764 {pin}")], "public": b64(&root.0.public()) });
        assert_eq!(ok(&m.manage(relay.to_string().as_bytes(), sign, ctx(root)))["relays"], json!(["203.0.113.9:8764"]));
        let bad = json!({ "action": "relay", "relays": ["203.0.113.9:8764 nope"], "public": b64(&root.0.public()) });
        assert!(error(&m.manage(bad.to_string().as_bytes(), sign, ctx(root))).contains("is not a relay's key"));
        let none = json!({ "action": "relay", "relays": [], "public": b64(&root.0.public()) });
        assert_eq!(ok(&m.manage(none.to_string().as_bytes(), sign, ctx(root)))["relays"], json!([]));
        // The root names its hubs, which the records judge: the hubs record
        // names only a device whose record gives it the hub's right, which a
        // phone's does not.
        let hubs = json!({ "action": "hubs", "hubs": ["tablet"], "public": b64(&root.0.public()) });
        assert!(error(&m.manage(hubs.to_string().as_bytes(), sign, ctx(root))).contains("may not be a hub"));
        let none = json!({ "action": "hubs", "hubs": [], "public": b64(&root.0.public()) });
        assert!(error(&m.manage(none.to_string().as_bytes(), sign, ctx(root))).contains("1 to 16 hubs"));
        // The group's view names the key level and the window for incoming
        // copies, which an admin sets with a copies record.
        let g = ok(&call("group", Value::Null));
        assert_eq!(g["key_level"], "files", "the test's group keeps its keys in files");
        assert_eq!((&g["ttl_ms"], &g["secret_ttl_ms"]), (&Value::Null, &Value::Null));
        let ttl = json!({ "action": "ttl", "ttl_ms": 120_000, "public": b64(&root.0.public()) });
        assert_eq!(ok(&m.manage(ttl.to_string().as_bytes(), sign, ctx(root)))["ttl_ms"], 120_000);
        let secret = json!({ "action": "ttl", "secret_ttl_ms": 30_000, "public": b64(&root.0.public()) });
        assert_eq!(ok(&m.manage(secret.to_string().as_bytes(), sign, ctx(root)))["secret_ttl_ms"], 30_000);
        let g = ok(&call("group", Value::Null));
        assert_eq!((&g["ttl_ms"], &g["secret_ttl_ms"]), (&json!(120_000), &json!(30_000)));

        m.stop();
        assert_eq!(error(&call("devices", Value::Null)), "the member stopped");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The test's callbacks' context: the member key, and the events the
    /// member sent the app.
    struct Caught {
        key: Signer,
        events: Mutex<Vec<Value>>,
    }

    unsafe extern "C" fn caught_sign(
        ctx: *mut core::ffi::c_void,
        digest: *const u8,
        sig: *mut u8,
        sig_len: *mut usize,
    ) -> i32 {
        // SAFETY: ctx is a Caught the test keeps for the process.
        unsafe {
            let c = &*(ctx as *const Caught);
            sign(&c.key as *const Signer as *mut core::ffi::c_void, digest, sig, sig_len)
        }
    }

    unsafe extern "C" fn caught(ctx: *mut core::ffi::c_void, event: *const u8, len: usize) {
        // SAFETY: ctx is a Caught the test keeps for the process, and event
        // len bytes the member keeps during the call.
        unsafe {
            let c = &*(ctx as *const Caught);
            if let Ok(v) = serde_json::from_slice::<Value>(core::slice::from_raw_parts(event, len)) {
                c.events.lock().unwrap().push(v);
            }
        }
    }

    /// A change of root reaches the app as an event, again at each start
    /// until the person saw it; a change of the records sends the group's
    /// state.
    #[test]
    fn a_phone_tells_its_app_of_a_change_of_root_and_of_its_records() {
        let dir = std::env::temp_dir().join(format!("cbb-ffi-live-events-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let me = cbb_member::founding::Me { name: "phone", os: 0, caps: 0 };
        let now = cbb_member::uptime::wall_ms().max(0).unsigned_abs();
        cbb_member::founding::found_with(&dir, &me, now, &|| None).unwrap();
        let own = Own::load(&dir).unwrap();
        let device = id_text(&own.device());
        let c: &'static Caught =
            Box::leak(Box::new(Caught { key: Signer(own.member.clone()), events: Mutex::new(Vec::new()) }));
        let root: &'static Signer = Box::leak(Box::new(Signer(own.root.clone().unwrap())));
        let req = json!({
            "dir": dir.to_string_lossy(), "name": "phone", "os": "ios", "device": device,
            "public": b64(&c.key.0.public()), "mdns": false,
        })
        .to_string();
        let old = "01010101010101010101010101010101";
        // The phone last saw no root of its group: the group's root now is
        // a change it tells of.
        keep_root_seen(&dir, &RootSeen { seq: 0, device: old.into(), pending: None }).unwrap();
        let start = || {
            c.events.lock().unwrap().clear();
            let (m, a) = Member::start(req.as_bytes(), caught_sign, caught, c as *const Caught as usize);
            ok(&a);
            m.unwrap()
        };
        let changes = || -> Vec<Value> {
            c.events.lock().unwrap().iter().filter(|e| e["type"] == "root_changed").cloned().collect()
        };
        let m = start();
        let want = json!({ "type": "root_changed", "from": old, "to": device, "seq": 1 });
        assert_eq!(changes(), vec![want.clone()]);
        m.stop();
        // Not seen yet: told again when the member starts.
        let m = start();
        assert_eq!(changes(), vec![want]);
        ok(&m.call(json!({ "op": "root_change_seen" }).to_string().as_bytes()));
        assert_eq!(root_seen(&dir).unwrap().pending, None);
        m.stop();
        let m = start();
        assert!(changes().is_empty(), "a change the person saw is not told again");

        // The root renames the phone: the app gets the group's new state.
        let r = json!({ "action": "rename", "device": device, "name": "desk", "public": b64(&root.0.public()) });
        ok(&m.manage(r.to_string().as_bytes(), sign, root as *const Signer as usize));
        let named = || {
            c.events.lock().unwrap().iter().any(|e| {
                e["type"] == "state"
                    && e["state"]["devices"].as_array().is_some_and(|d| d.iter().any(|d| d["name"] == "desk"))
            })
        };
        let until = Instant::now() + Duration::from_secs(5);
        while !named() && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(named(), "{:?}", c.events.lock().unwrap());
        m.stop();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A root seen for the first time is noted, not told; more roots than
    /// before are a change from the old root's device to the new one's.
    #[test]
    fn a_new_root_is_a_change_once() {
        let dir = std::env::temp_dir().join(format!("cbb-ffi-root-seen-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut st = cbb_core::records::eval::State::default();
        let (a, b) = (cbb_core::records::DeviceId([1; 16]), cbb_core::records::DeviceId([2; 16]));
        st.roots = vec![cbb_core::records::KeyHash([1; 32])];
        st.root_device = Some(a);
        assert_eq!(note_root(&dir, &st).unwrap(), None, "a phone that joins sees no change");
        assert_eq!(note_root(&dir, &st).unwrap(), None);
        st.roots.push(cbb_core::records::KeyHash([2; 32]));
        st.root_device = Some(b);
        let want = RootChange { from: id_text(&a), to: id_text(&b), seq: 2 };
        assert_eq!(note_root(&dir, &st).unwrap(), Some(want.clone()));
        assert_eq!(note_root(&dir, &st).unwrap(), None, "told once");
        assert_eq!(root_seen(&dir).unwrap().pending, Some(want), "kept until the person saw it");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Only the notices not shown before are new.
    #[test]
    fn new_notices_are_those_not_shown() {
        let n = |id: &str| json!({ "id": id, "kind": "checkpoint_stuck", "args": {}, "dismissable": false });
        let mut shown = Vec::new();
        assert_eq!(new_notices(&mut shown, &[n("a")]), vec![n("a")]);
        assert_eq!(new_notices(&mut shown, &[n("a"), n("b")]), vec![n("b")]);
        assert!(new_notices(&mut shown, &[n("b")]).is_empty());
        assert_eq!(new_notices(&mut shown, &[n("a"), n("b")]), vec![n("a")], "a notice gone and back is new again");
    }

    /// The ops the apps' screens read: the tiles and the person's order of
    /// them, and the group's notices and hiding one.
    #[test]
    fn a_phone_answers_its_view_and_notices() {
        let dir = std::env::temp_dir().join(format!("cbb-ffi-live-view-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let me = cbb_member::founding::Me { name: "phone", os: 0, caps: 0 };
        let now = cbb_member::uptime::wall_ms().max(0).unsigned_abs();
        cbb_member::founding::found_with(&dir, &me, now, &|| None).unwrap();
        let own = Own::load(&dir).unwrap();
        let device = id_text(&own.device());
        let member: &'static Signer = Box::leak(Box::new(Signer(own.member.clone())));
        let req = json!({
            "dir": dir.to_string_lossy(), "name": "phone", "os": "ios", "device": device,
            "public": b64(&member.0.public()), "mdns": false,
        })
        .to_string();
        let (m, a) = Member::start(req.as_bytes(), sign, events, member as *const Signer as usize);
        ok(&a);
        let m = m.unwrap();
        let call = |op: &str, args: Value| m.call(json!({ "op": op, "args": args }).to_string().as_bytes());

        // The view: this phone's tile, no others, no order of the person's,
        // and the reasons why it does not sync as its warnings.
        let v = ok(&call("view", Value::Null))["view"].clone();
        assert_eq!(v["tiles"].as_array().unwrap().len(), 1, "{v}");
        assert_eq!(v["tiles"][0]["device"]["id"], device.as_str(), "{v}");
        assert_eq!(
            (v["online"].as_u64(), v["others"].as_u64(), v["custom"].as_bool()),
            (Some(0), Some(0), Some(false))
        );
        let why = ok(&call("why", Value::Null))["why"].clone();
        assert_eq!(v.get("warnings").cloned().unwrap_or(json!([])), why, "the view warns as why answers");
        // The app's own tunnel, when it runs one, stands in for the member's.
        let away = json!({ "away": { "hub": true, "forwarder": true, "error": "no answer" } });
        let why = ok(&call("why", away.clone()))["why"].clone();
        let down = why.as_array().unwrap().iter().find(|r| r["code"] == "forwarder_down").cloned();
        assert_eq!(down.map(|r| r["detail"].clone()), Some(json!("no answer")), "{why}");
        let v = ok(&call("view", away))["view"].clone();
        assert!(v["warnings"].as_array().unwrap().iter().any(|r| r["code"] == "forwarder_down"), "{v}");
        assert!(error(&call("why", json!({ "away": 7 }))).starts_with("away:"));
        // A collection the person makes is kept, and ungrouping undoes it.
        let made = json!({ "arrange": { "op": "new", "name": "Desk", "devices": [device] } });
        let v = ok(&call("arrange", made))["view"].clone();
        assert_eq!(v["custom"], true, "{v}");
        assert_eq!(v["tiles"][0]["collection"]["name"], "Desk", "{v}");
        assert!(dir.join(cbb_member::view::FILE).is_file(), "the order stays in the phone's folder");
        assert_eq!(ok(&call("view", Value::Null))["view"]["tiles"][0]["collection"]["name"], "Desk");
        let bad = json!({ "arrange": { "op": "into", "device": device, "collection": "none" } });
        assert!(m.call(json!({ "op": "arrange", "args": bad }).to_string().as_bytes()).starts_with(b"{\"error\""));
        assert!(error(&call("arrange", json!({ "arrange": { "op": "fly" } }))).starts_with("arrange:"));
        let c = ok(&call("view", Value::Null))["view"]["tiles"][0]["collection"]["id"].clone();
        let v = ok(&call("arrange", json!({ "arrange": { "op": "ungroup", "collection": c } })))["view"].clone();
        assert_eq!(v["tiles"][0]["device"]["id"], device.as_str(), "{v}");

        // A new group tells nothing; a notice hidden stays hidden in the set.
        assert_eq!(ok(&call("notices", Value::Null))["notices"], json!([]));
        assert!(error(&call("dismiss", Value::Null)).contains("a notice's id"));
        assert!(error(&call("dismiss", json!({ "id": "AAAA" }))).contains("a notice's id"));
        let id = certs::b64::encode(&[9; 32]);
        ok(&call("dismiss", json!({ "id": id })));
        let phone = &*m.0;
        let rid = record_id(&id).unwrap();
        assert!(lock(&phone.live.mesh.set()).dismissed().any(|d| *d == rid));
        assert_eq!(ok(&call("notices", Value::Null))["notices"], json!([]));

        m.stop();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A phone is no hub (D-134): it refuses the hub command, the root's
    /// too, and has no op to turn a hub on.
    #[test]
    fn a_phone_refuses_to_be_a_hub() {
        use cbb_member::orders::{Hub, Order};
        let dir = std::env::temp_dir().join(format!("cbb-ffi-live-nohub-{}", std::process::id()));
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
        let phone = &*m.0;
        let call = |op: &str, args: Value| m.call(json!({ "op": op, "args": args }).to_string().as_bytes());
        for op in ["hub", "hub_off"] {
            assert!(!error(&call(op, Value::Null)).is_empty(), "{op}");
        }

        let ev = Events { f: events, ctx: 0 };
        let root = *phone.live.mesh.state().roots.last().unwrap();
        let taken = |o: &Order| cbb_member::commands::Taken {
            kind: o.kind(),
            id: [1; 16],
            signer: root,
            orders: o.orders().unwrap(),
        };
        for o in [
            Order::Hub(Hub { forwarders: vec![("203.0.113.9:8764".into(), [7; 32])], ..Hub::default() }),
            Order::Hub(Hub { stop: true, ..Hub::default() }),
        ] {
            let e = carry_out(&phone.live, &phone.me, &dir, &ev, &taken(&o)).unwrap_err();
            assert!(e.message().contains("a phone is no hub"), "{}", e.message());
        }
        m.stop();
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn b64(b: &[u8]) -> Value {
        super::super::b64(b)
    }
}
