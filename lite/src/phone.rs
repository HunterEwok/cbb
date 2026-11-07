// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The member as a phone's app runs it in its own process (the Aurora app,
//! through lite/ffi): the same node as the service, with the device key
//! where the app keeps it and no control socket. A phone dials the members
//! it finds (docs/protocol.md, section 3), by mDNS or as its app hands them
//! in; while the app is in the front it may also listen as the group's hub
//! at home (`listen`), and in the background it pauses. Away from home it
//! reaches the group's hub through the same tunnel as the lite member
//! (`crate::away`, in a build with the feature `tunnel`), once the user
//! turns sync away from home on.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cbb_core::admit::{self, Admitted, Admitter, GroupView};
use cbb_core::certs::DeviceId;
use cbb_core::clip::{Engine, Event, Kind, Via};
use cbb_core::identity::Identity;
use cbb_core::manage::{self, Change, Order, Signer};
use cbb_core::wire::{self, CommandResult, DeviceInfo};

use crate::away::Away;
use crate::button::{self, Own};
use crate::content::Source;
use crate::discovery::{Dialers, Listener};
use crate::error::{Error, Result};
use crate::node::{KeepIdentity, Node, OnMessage, Peer, Presence, WriteReq};
use crate::records::{Record, Records, Stored as _};
use crate::{discovery, mute, service, uptime};
use cbb_core::media::Part;

/// Hears an admin's mute: until when in Unix milliseconds (0 for until an
/// admin unmutes it), None for not muted, and who.
pub type OnMute = Box<dyn Fn(Option<i64>, &str) + Send + Sync>;

/// What the phone's member starts from.
pub struct Config {
    /// The app's identity in the group, its key external.
    pub identity: Identity,
    /// The name the other members show.
    pub name: String,
    /// The phone's system (`aurora`, `sailfish`), its version and the app's.
    pub os: String,
    pub os_version: String,
    pub version: String,
    /// Where the phone's key lives, as its hello says: `hardware` (a TEE)
    /// or `file`.
    pub key_store: String,
    /// Where the records, the clock's mark and the entries are kept.
    pub state_dir: PathBuf,
    /// Members to dial at these addresses besides those mDNS finds.
    pub peers: Vec<std::net::SocketAddr>,
    /// Whether to find the members by mDNS.
    pub mdns: bool,
    /// The secret for sealed messages (docs/protocol.md, section 4).
    pub seal_secret: Vec<u8>,
    /// Gets each text to put into the phone's clipboard.
    pub on_write: Box<dyn Fn(WriteReq) + Send + Sync>,
    /// Keeps the identity when it changes: a certificate an admin renewed,
    /// the root a takeover made. The app keeps it in its own file.
    pub keep_identity: KeepIdentity,
    /// Hears that an admin muted this phone or ended its mute: until when
    /// in Unix milliseconds (0 for until an admin unmutes it), None for not
    /// muted, and who.
    pub on_mute: OnMute,
    pub log: Arc<dyn Fn(&str) + Send + Sync>,
}

/// A device of the group as the phone's app shows it.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct DeviceView {
    pub id: String,
    pub name: String,
    /// `full`, `phone`, `lite` or `watch`.
    pub role: String,
    /// Its system, from its hello when it is connected, else its record's;
    /// empty when neither tells.
    pub os: String,
    pub admin: bool,
    /// It holds the group's root.
    pub root: bool,
    /// Another admin froze it.
    pub frozen: bool,
    /// It is connected to this phone now.
    pub online: bool,
    /// It is this phone.
    pub this: bool,
    /// The group's records list it; a connected member they do not list
    /// yet is shown too.
    pub listed: bool,
}

/// A running member of a phone's app.
pub struct Member {
    node: Arc<Node>,
    dialers: Dialers,
    listener: Mutex<Option<Listener>>,
    own: Own,
    log: Arc<dyn Fn(&str) + Send + Sync>,
    state_dir: PathBuf,
    away: Arc<Away>,
}

/// The group's copy as the app shows it and the button fetches it.
#[derive(Clone, Debug)]
pub struct Copy {
    pub event: Event,
    /// The key the button compares it by (crate::button).
    pub key: String,
}

/// The most commands a phone remembers having carried out.
const MAX_COMMANDS: usize = 4096;

impl Member {
    /// Starts the member: it loads the records and dials the members at the
    /// given addresses and those mDNS finds.
    pub fn start(cfg: Config) -> Result<Member> {
        let log = cfg.log;
        crate::sealkey::set(cfg.seal_secret)?;
        let records = Records::load(&cfg.state_dir, &cfg.identity.group_ca)?;
        // The roots the records lead to, as the service takes them; the app
        // keeps its identity itself.
        let mut ident = cfg.identity;
        if !records.is_empty() {
            ident.roots = records.roots();
        }
        log(&format!("cbb: device {} in group {}", ident.id, ident.tag()));
        let engine = Arc::new(Engine::new(
            ident.id.as_str(),
            service::clock(&cfg.state_dir),
            Box::new(uptime::wall_ms),
            Box::new(uptime::now),
        ));
        let tag = ident.tag();
        let away = Arc::new(Away::new(cfg.state_dir.clone(), tag.clone(), ident.id.clone(), log.clone()));
        let device =
            DeviceInfo { form: "phone".into(), os_version: cfg.os_version, version: cfg.version, mac: String::new() }
                .cleaned();
        if let Err(e) = mute::load(&cfg.state_dir, &engine) {
            log(&format!("cbb: the mute: {}; not muted", e.for_log()));
        }
        if let Err(e) = crate::sync::load(&cfg.state_dir, &engine) {
            log(&format!("cbb: sync on or off: {}; sync is on", e.for_log()));
        }
        let state_dir = cfg.state_dir.clone();
        let node = Node::new(ident, &cfg.name, engine.clone(), records, cfg.state_dir, cfg.on_write, log.clone())
            .presenting(Presence { role: "phone".into(), name: cfg.name, os: cfg.os, key_store: cfg.key_store, device })
            .keeping_identity(cfg.keep_identity)
            .with_content();
        let node = Arc::new(node);
        engine.set_seal(node.sealer());
        let commands = Commands {
            node: Arc::downgrade(&node),
            state_dir: state_dir.clone(),
            started_ms: uptime::wall_ms(),
            seen: Mutex::new(HashMap::new()),
            on_mute: cfg.on_mute,
            log: log.clone(),
        };
        node.on_command(Arc::new(move |peer, c| commands.command(peer, c)));
        node.set_tunnel_key(away.key());
        {
            let away = away.clone();
            let n = Arc::downgrade(&node);
            node.on_tunnel(Box::new(move |from, v, may_host| {
                if let (Some(hub), Some(node)) = (away.offered(from, v, may_host), n.upgrade()) {
                    away.retry(&node, &hub);
                }
            }));
        }
        discovery::start(node.clone(), tag.clone(), cfg.peers, false, None, log.clone());
        if cfg.mdns {
            discovery::start_as_phone(node.clone(), tag, log.clone());
        }
        {
            let (away, node) = (away.clone(), node.clone());
            std::thread::spawn(move || away.run(node));
        }
        Ok(Member {
            node,
            dialers: Dialers::default(),
            listener: Mutex::new(None),
            own: Own::default(),
            log,
            state_dir,
            away,
        })
    }

    /// Turns sync away from home on (docs/protocol.md, section 11): new
    /// tunnel keys, which the hellos offer the group's hubs from now on, so
    /// their offers come on the next connection at home. An error in a
    /// build without the tunnel.
    pub fn away_on(&self) -> Result<()> {
        let keys = self.away.turn_on()?;
        self.node.set_tunnel_key(Some(keys));
        Ok(())
    }

    /// Turns sync away from home off, forgets its keys and the hubs'
    /// offers, and ends the link through the tunnel.
    pub fn away_off(&self) -> Result<()> {
        self.away.turn_off()?;
        self.node.set_tunnel_key(None);
        for id in self.node.hub_order().iter().filter_map(|d| DeviceId::parse(d).ok()) {
            if !self.node.at_home(&id) {
                self.node.disconnect(&id);
            }
        }
        Ok(())
    }

    /// Sync away from home as the app shows it, as `cbb global` shows it on
    /// the lite member; None while it is off.
    pub fn away_status(&self) -> Option<serde_json::Value> {
        self.away.status(&self.node).and_then(|a| serde_json::to_value(a).ok())
    }

    /// Turns the phone's sync on, or off for ms milliseconds (0 for until
    /// it is turned on): the clipboard is then the phone's own (design.md,
    /// "Sync on and off"). The members see it at the next connection.
    pub fn set_sync(&self, on: bool, ms: i64) -> Result<()> {
        crate::sync::set(&self.state_dir, &self.node.engine, on, ms)?;
        self.node.reconnect();
        Ok(())
    }

    /// How long sync stays off and how long an admin's mute lasts, in
    /// milliseconds: 0 for until it is lifted, None for neither.
    pub fn muted(&self) -> (Option<i64>, Option<i64>) {
        let off = match self.node.engine.sync() {
            (true, _) => None,
            (false, 0) => Some(0),
            (false, u) => Some(u.saturating_sub(uptime::wall_ms()).max(1)),
        };
        (off, self.node.engine.mute_left())
    }

    /// Sends a text the user handed to the app; board says it came from
    /// the phone's clipboard, which the button then compares with it. A
    /// text shared from another app leaves the clipboard as it was, so the
    /// button goes on comparing with what the clipboard last sent.
    pub fn copy(&self, text: &str, secret: bool, board: bool) -> Result<()> {
        self.node.send(text, if secret { Kind::Secret } else { Kind::Text }, Via::Phone)?;
        if board {
            self.own.sent(text);
        }
        Ok(())
    }

    /// Sends images or files the user handed to the app: clipboard data
    /// such as an image (parts with a type), or files and folders (parts
    /// with a path), with a plain-text alternative or "". board says it
    /// came from the phone's clipboard, as copy does; images or files
    /// shared from another app do not, and a text the clipboard sent before
    /// them stays out of the button's sending (trace b1).
    pub fn copy_media(&self, text: &str, parts: Vec<(Part, Source)>, board: bool) -> Result<Copy> {
        let event = self.node.send_media(text, parts)?;
        let key = button::key_of(&event).unwrap_or_default();
        if board {
            self.own.sent(&key);
        }
        Ok(Copy { event, key })
    }

    /// Fetches the images or files of the group's copy id, unless larger
    /// than max bytes, and opens them into the new folder out; each part
    /// with where it is. A copy no longer the group's current one is gone.
    pub fn fetch(&self, id: &str, max: u64, out: &std::path::Path) -> Result<Vec<(Part, std::path::PathBuf)>> {
        let ev = self
            .node
            .engine
            .current()
            .filter(|e| e.id == id)
            .ok_or_else(|| crate::error::Error::msg("the copy is no longer the group's"))?;
        self.node.fetch(&ev, max)?;
        self.node.open_media(&ev, out)
    }

    /// The members connected now.
    pub fn peers(&self) -> Vec<Peer> {
        self.node.peers()
    }

    /// The members connected now, those that carry records only among them.
    pub fn all_peers(&self) -> Vec<Peer> {
        self.node.all_peers()
    }

    /// The device IDs of the group's devices the records list.
    pub fn devices(&self) -> Vec<crate::records::Device> {
        self.node.devices()
    }

    /// The group's records, to show and to sign new ones over.
    pub fn records(&self) -> Vec<Record> {
        self.node.records().lock().unwrap().all()
    }

    /// The group's current copy, live or not, unless there is none or it is
    /// an expired secret.
    pub fn current(&self) -> Option<Copy> {
        let event = self.node.engine.current()?;
        let key = button::key_of(&event).unwrap_or_default();
        Some(Copy { event, key })
    }

    /// The copy from another device that waits for the phone (the button's
    /// first case), which the app then takes and reports with took.
    pub fn waiting(&self) -> Option<Copy> {
        let me = self.node.identity().id.to_string();
        let event = button::waiting(self.node.engine.current(), &me, self.node.engine.live_window(), &self.own)?;
        let key = button::key_of(&event).unwrap_or_default();
        Some(Copy { event, key })
    }

    /// The app took the copy id into the phone's clipboard, or saved its
    /// files, so that it waits no more.
    pub fn took(&self, id: &str) {
        if let Some(ev) = self.node.engine.current().filter(|e| e.id == id) {
            self.own.took(&ev);
        }
    }

    /// Whether the button sends what the phone's clipboard holds, by its
    /// key (the button's second case); the app sends it then, with copy.
    pub fn sends(&self, board: &str) -> bool {
        button::sends(board, self.node.engine.current().as_ref(), &self.own)
    }

    /// Dials the member the app found as key (a Bonjour or NSD name, the
    /// tunnel) at addrs; device is its device ID when known.
    pub fn found(&self, key: &str, addrs: Vec<SocketAddr>, device: Option<DeviceId>) {
        self.dialers.found(&self.node, key, addrs, device);
    }

    /// Stops dialing the member the app lost.
    pub fn lost(&self, key: &str) {
        self.dialers.lost(&self.node, key);
    }

    /// Listens on port (0: a free one) for the members that dial this phone
    /// as the group's hub; returns the port, which the app publishes with
    /// `r=phone`. A port already open stays.
    pub fn listen(&self, port: u16) -> Result<u16> {
        let mut l = self.listener.lock().unwrap();
        if let Some(l) = l.as_ref() {
            return Ok(l.port);
        }
        let opened = Listener::open(self.node.clone(), port, self.log.clone())
            .ok_or_else(|| crate::error::Error::msg(format!("cannot listen on port {port}")))?;
        let p = opened.port;
        *l = Some(opened);
        Ok(p)
    }

    /// Closes the port listen opened.
    pub fn unlisten(&self) {
        if let Some(l) = self.listener.lock().unwrap().take() {
            l.stop();
        }
    }

    /// Closes every connection with a goodbye and the port, and makes no
    /// new connection until resume: the app went to the background.
    pub fn pause(&self) {
        self.unlisten();
        self.node.pause();
    }

    /// Connects again at once after pause.
    pub fn resume(&self) {
        self.node.resume();
    }

    /// Waits up to timeout for a member to connect; for one pass of the
    /// iPhone's background refresh: resume, wait, take what waits, pause.
    pub fn wait_connected(&self, timeout: Duration) -> bool {
        self.node.wait_connected(timeout)
    }

    /// Mutes the phone until until_ms (0: until unmute): its copies stay on
    /// it.
    pub fn set_mute(&self, until_ms: Option<i64>) {
        match until_ms {
            Some(t) => self.node.engine.set_mute(t),
            None => self.node.engine.unmute(),
        }
        self.node.reconnect();
    }

    /// Sends a command the app's admin key signed and waits for its result.
    pub fn command(&self, r: &Record, timeout: Duration) -> Result<CommandResult> {
        self.node.command(r, timeout)
    }

    /// Takes records the app signed and sends them to the members.
    pub fn add_records(&self, rs: &[Record]) {
        self.node.add_own_records(rs);
    }

    /// Sends a renewed member certificate to the member to.
    pub fn send_cert(&self, to: &DeviceId, cert: &[u8], issuer: Option<&[u8]>) -> bool {
        self.node.send_to(to, wire::cert(cert, issuer))
    }

    /// Sends a full member the admin CA for the admin key its hello offered.
    pub fn send_admin_ca(&self, to: &DeviceId, ca: &[u8]) -> bool {
        self.node.send_to(to, wire::admin(ca))
    }

    /// Sends the member to this hub's offer for its tunnel key.
    pub fn send_tunnel(&self, to: &DeviceId, offer: &serde_json::Value) -> bool {
        self.node.send_to(to, wire::tunnel(offer))
    }

    /// Sends what this hub shares to the group's other hubs connected, the
    /// full members among the root and the admins; returns those it went to.
    pub fn send_hubs(&self, share: &serde_json::Value) -> Vec<DeviceId> {
        self.node.send_to_hubs(&wire::hubs(share))
    }

    /// Sends the group's server credentials the app keeps to every member.
    pub fn send_credentials(&self, list: &serde_json::Value) -> Vec<DeviceId> {
        self.node.broadcast(&wire::credentials(list), |_| true)
    }

    /// Sets what gets each copy that becomes the group's current one from
    /// another member: a text or secret the phone may take by itself, or
    /// images or files to fetch.
    pub fn on_change(&self, f: crate::node::OnChange) {
        self.node.on_change(f);
    }

    /// Sets what gets the admin, hubs and credentials messages peers send.
    pub fn on_message(&self, f: OnMessage) {
        self.node.on_message(f);
    }

    /// Every device of the group as the app shows it: the group's device
    /// records, the system a connected member's hello names over its
    /// record's, and after them the connected members no record lists yet.
    pub fn device_views(&self) -> Vec<DeviceView> {
        let me = self.node.identity().id.to_string();
        let peers = self.node.peers();
        let root = self.node.records().lock().unwrap().root_member().map(|(id, _)| id);
        let mut out: Vec<DeviceView> = self
            .node
            .devices()
            .into_iter()
            .map(|d| {
                let peer = peers.iter().find(|p| p.id.as_str() == d.id);
                DeviceView {
                    os: peer.filter(|p| !p.os.is_empty()).map_or(d.os.clone(), |p| p.os.clone()),
                    online: peer.is_some(),
                    this: d.id == me,
                    root: root.as_deref() == Some(d.id.as_str()),
                    listed: true,
                    admin: d.admin,
                    frozen: d.frozen,
                    id: d.id,
                    name: d.name,
                    role: d.role,
                }
            })
            .collect();
        for p in peers {
            if !out.iter().any(|d| d.id == p.id.as_str()) {
                out.push(DeviceView {
                    id: p.id.to_string(),
                    name: p.name,
                    role: p.role,
                    os: p.os,
                    online: true,
                    ..Default::default()
                });
            }
        }
        out
    }

    /// The member's identity, with the roots the records lead to.
    pub fn identity(&self) -> Arc<Identity> {
        self.node.identity()
    }

    /// What admitting a device takes from the group's records.
    pub fn group_view(&self) -> GroupView {
        GroupView::of(&self.node.records().lock().unwrap())
    }

    /// Adds the device record of a device this phone admitted, signed by
    /// the admitter's CA key, and passes it to the group.
    pub fn record_admitted(&self, admitter: &Admitter, a: &Admitted) -> Result<()> {
        let records = self.node.records();
        let r = admit::device_record(&records.lock().unwrap(), admitter, a, uptime::wall_ms())?;
        self.node.add_own_records(&[r]);
        Ok(())
    }

    /// What the group's records stop and what ends it, for the app's card.
    pub fn alerts(&self) -> Vec<manage::Alert> {
        manage::alerts(&self.node.records().lock().unwrap())
    }

    /// Signs a change to a device of the group with the app's admin key or
    /// the root's (cbb_core::manage), adds it and passes it to the group.
    pub fn change(&self, s: &Signer, device: &str, c: &Change) -> Result<()> {
        let records = self.node.records();
        let r = manage::change(&records.lock().unwrap(), s, device, c, uptime::wall_ms())?;
        self.node.add_own_records(std::slice::from_ref(&r));
        if !records.lock().unwrap().has(&r) {
            return Err(Error::msg("the group's records did not take the change; the log says why"));
        }
        Ok(())
    }

    /// Signs a command for a device of the group as change does, sends it
    /// and waits up to timeout for its result.
    pub fn order(&self, s: &Signer, device: &str, o: &Order, timeout: Duration) -> Result<CommandResult> {
        let r = manage::order(&self.node.records().lock().unwrap(), s, device, o, uptime::wall_ms())?;
        self.node.command(&r, timeout)
    }

    /// Makes the computer device an admin as the group's root: the admin CA
    /// for the admin key its hello offers, its device record again, added
    /// and sent, and the admin message with the CA. The computer must be
    /// connected, since the key comes from its hello.
    pub fn make_admin(&self, s: &Signer, device: &str, allow_file_key: bool) -> Result<()> {
        let p = self
            .node
            .peers()
            .into_iter()
            .find(|p| p.id.as_str() == device)
            .ok_or_else(|| Error::msg("the computer is not connected; it offers its admin key when it is"))?;
        let key = p.admin_key.ok_or_else(|| Error::msg("the computer offers no admin key"))?;
        let records = self.node.records();
        let made = manage::make_admin(
            &records.lock().unwrap(),
            s,
            device,
            &key,
            &p.key_store,
            allow_file_key,
            uptime::wall_ms(),
        )?;
        self.node.add_own_records(std::slice::from_ref(&made.record));
        if !records.lock().unwrap().devices().iter().any(|d| d.id == device && d.admin) {
            return Err(Error::msg("the group's records did not take the computer as an admin; the log says why"));
        }
        if !self.node.send_to(&p.id, wire::admin(&made.admin_ca)) {
            return Err(Error::msg("the computer is an admin now, but it went away before it got its admin CA"));
        }
        Ok(())
    }

    /// Renews the member certificates that are due, as an admin: each
    /// connected member's, sent to it, and this phone's own, kept. It
    /// returns how many it renewed.
    pub fn renew(&self, s: &Signer) -> Result<usize> {
        let now = uptime::wall_ms() / 1000;
        let ident = self.node.identity();
        let mut roots = self.node.records().lock().unwrap().roots();
        if roots.is_empty() {
            roots.push(ident.root().clone());
        }
        let issuer = (!roots.iter().any(|r| r == s.ca)).then(|| s.ca.der.clone());
        let mut n = 0;
        for (to, chain) in self.node.peer_chains() {
            match manage::renewal(&chain, &roots, s, now) {
                Ok(Some(cert)) => {
                    if self.node.send_to(&to, wire::cert(&cert, issuer.as_deref())) {
                        n += 1;
                    }
                }
                Ok(None) => {}
                Err(e) => self.node.logf(&format!("cbb: renewing the certificate of {to}: {}", e.for_log())),
            }
        }
        let own: Vec<_> = std::iter::once(ident.cert.clone()).chain(ident.issuer.clone()).collect();
        if let Some(cert) = manage::renewal(&own, &roots, s, now)? {
            self.node.renewed(&cert, issuer.as_deref())?;
            n += 1;
        }
        Ok(n)
    }

    /// Stops the member and closes its connections.
    pub fn stop(&self) {
        self.unlisten();
        self.node.close();
    }
}

impl Drop for Member {
    fn drop(&mut self) {
        self.node.close();
    }
}

/// What carries out the commands admins send the phone: only mute and
/// unmute, which the user cannot give the app otherwise; the phone has no
/// remote paste, quick actions or sync modes to change.
struct Commands {
    node: std::sync::Weak<Node>,
    state_dir: PathBuf,
    started_ms: i64,
    seen: Mutex<HashMap<String, i64>>,
    on_mute: OnMute,
    log: Arc<dyn Fn(&str) + Send + Sync>,
}

impl Commands {
    fn command(&self, peer: &crate::certs::DeviceId, c: &crate::records::Record) -> wire::CommandResult {
        let refused = |id: &str, why: String| {
            (self.log)(&format!("cbb: refused a command from {peer}: {why}"));
            wire::CommandResult { id: id.to_string(), by: String::new(), status: "refused".into(), reason: why }
        };
        let Some(node) = self.node.upgrade() else {
            return refused("", "the member stopped".into());
        };
        let now = uptime::wall_ms();
        let me = node.identity().id.to_string();
        let verified = node.records().lock().unwrap().verify_command(c, &me, now);
        let mut body = match verified {
            Ok(b) => b,
            Err(e) => return refused("", e.message().to_string()),
        };
        if body.sealed() {
            let Some(secret) = crate::sealkey::secret() else {
                return refused(
                    &body.id,
                    "the command is sealed, and this device has no key for sealed commands".into(),
                );
            };
            if let Err(e) = body.open(secret) {
                return refused(&body.id, e.message().to_string());
            }
        }
        if body.kind != "mute" && body.kind != "unmute" {
            return refused(&body.id, format!("this phone takes no {} commands", body.kind));
        }
        if body.time_ms < self.started_ms {
            return refused(
                &body.id,
                "this device started after the command was signed, so it may have carried it out already; send it again"
                    .into(),
            );
        }
        {
            let mut seen = self.seen.lock().unwrap();
            seen.retain(|_, exp| *exp > now);
            if seen.contains_key(&body.id) {
                return refused(&body.id, "this command was carried out already".into());
            }
            if seen.len() >= MAX_COMMANDS {
                return refused(&body.id, "too many commands; try again in a minute".into());
            }
            seen.insert(body.id.clone(), body.expires_ms);
        }
        let until = if body.for_ms == 0 { 0 } else { now + body.for_ms };
        match self.set_muted(&node, body.kind == "mute", until, &body.by) {
            Ok(()) => {
                wire::CommandResult { id: body.id, by: String::new(), status: "done".into(), reason: String::new() }
            }
            Err(e) => {
                (self.log)(&format!("cbb: a mute from {peer}: {}", e.for_log()));
                wire::CommandResult {
                    id: body.id,
                    by: String::new(),
                    status: "failed".into(),
                    reason: e.message().to_string(),
                }
            }
        }
    }

    /// Mutes the phone until `until` (0 for until an admin lifts it), or
    /// ends its mute, saves it, tells the app, and connects to the members
    /// again once the result had a moment to go back, so that their hellos
    /// show it.
    fn set_muted(&self, node: &Arc<Node>, on: bool, until: i64, by: &str) -> Result<()> {
        if on {
            node.engine.set_mute(until);
        } else {
            node.engine.unmute();
        }
        mute::save(&self.state_dir, &node.engine)?;
        (self.log)(&match (on, until) {
            (false, _) => format!("cbb: {by} ended the mute: this device's copies reach the group again"),
            (true, 0) => format!("cbb: {by} muted this device until an admin unmutes it"),
            (true, _) => format!("cbb: {by} muted this device for {} s", (until - uptime::wall_ms()) / 1000),
        });
        (self.on_mute)(on.then_some(until), by);
        let node = node.clone();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(500));
            node.reconnect();
        });
        Ok(())
    }
}
