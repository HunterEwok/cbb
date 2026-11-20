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
                let ps: Vec<Value> = self
                    .devices()
                    .iter()
                    .filter(|d| !d.this && (all || d.online))
                    .map(|d| {
                        json!({
                            "device": d.id, "name": d.name, "role": d.role, "os": d.os,
                            "key_store": d.store, "mode": d.mode, "muted": d.muted,
                        })
                    })
                    .collect();
                Ok(json!({ "peers": ps }))
            }
            "devices" => Ok(json!({ "devices": self.devices() })),
            "group" => Ok(group_view(&lock(&l.mesh.set()), &l.mesh.device())),
            "why" => Ok(json!({ "why": self.why() })),
            "check_command" | "answer" => Err(not_yet("a command for this phone")),
            _ => Err(not_yet(&format!("the operation {op:?}"))),
        }
    }

    /// The group's current copy as the button's rule reads it.
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
    /// key: remove, rename, freeze and thaw; the records judge whether the
    /// key may.
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
                other => return Err(not_yet(&format!("the admin's action {other:?}"))),
            };
            Ok(json!({ "device": id_text(&d.id), "name": d.name }))
        })())
    }

    /// Opens a pairing window with the admitting key behind sign
    /// (`crate::window`): the member port must listen.
    pub fn window(&self, request: &[u8], sign: SignFn, ctx: usize) -> (Option<crate::window::Window>, Vec<u8>) {
        if self.stopped.load(Ordering::SeqCst) {
            return (None, answer::<()>(Err(Error::msg("the member stopped"))));
        }
        let port = lock(&self.port).as_ref().map(|l| l.port);
        crate::window::Window::open(self.live.clone(), port, request, sign, ctx)
    }

    /// What the watch asks is not on the records of 0.6 yet.
    pub fn manage_watch(&self) -> Vec<u8> {
        answer::<()>(Err(not_yet("an admin's action from the watch")))
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
        Order::Hub(_) => {
            Err(refuse("a phone does not become the hub by a command; move the hub from the phone that is the hub"))
        }
        Order::Device { .. } => Err(refuse("a phone carries out no small device's own command")),
        Order::Paste { .. } => Err(not_yet("a remote paste on a phone")),
    }
}

/// A copy from the group to write to the phone's clipboard: its text, and
/// the copy itself for the app's list. Images and files are not fetched on
/// the records of 0.6 yet: their text goes, and the log says why the rest
/// does not.
fn deliver(ev: &Events, w: &Write) {
    let mut kind = w.kind;
    if w.media.is_some() {
        let e = not_yet("writing a copy's images or files");
        ev.send(&Event::Log { line: &format!("cbb: a copy from the group: {}", e.for_log()) });
        if w.text.is_empty() {
            return;
        }
        kind = Kind::Text;
    }
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
        for op in ["away", "hub", "records"] {
            assert!(error(&call(op, Value::Null)).contains("does not work in this build yet"), "{op}");
        }
        let manage = |action: &str, device: &str, name: &str| {
            let r = json!({ "action": action, "device": device, "name": name, "public": b64(&root.0.public()) });
            m.manage(r.to_string().as_bytes(), sign, ctx(root))
        };
        assert_eq!(ok(&manage("rename", "phone", "tablet"))["name"], "phone");
        assert_eq!(ok(&call("devices", Value::Null))["devices"][0]["name"], "tablet");
        assert!(error(&manage("remove", "tablet", "")).contains("cannot remove itself"));
        assert!(error(&manage("mute", "tablet", "")).contains("does not work in this build yet"));
        let (a, ans) = m.admit(b"{}", sign, ctx(root));
        assert!(a.is_none() && error(&ans).contains("does not work in this build yet"));

        m.stop();
        assert_eq!(error(&call("devices", Value::Null)), "the member stopped");
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn b64(b: &[u8]) -> Value {
        super::super::b64(b)
    }
}
