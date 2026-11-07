// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The member as a phone's app runs it in its own process (the Aurora app,
//! through lite/ffi): the same node as the service, with the device key
//! where the app keeps it and no control socket. A phone dials the members
//! it finds (docs/protocol.md, section 3), by mDNS or as its app hands them
//! in; while the app is in the front it may also listen as the group's hub
//! at home (`listen`), and in the background it pauses.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cbb_core::certs::DeviceId;
use cbb_core::clip::{Engine, Event, Kind, Mode, Via};
use cbb_core::identity::Identity;
use cbb_core::wire::{self, CommandResult, DeviceInfo};

use crate::button::{self, Own};
use crate::content::Source;
use crate::discovery::{Dialers, Listener};
use crate::error::Result;
use crate::node::{KeepIdentity, Node, OnMessage, Peer, Presence, WriteReq};
use crate::records::{Record, Records, Stored as _};
use crate::{discovery, service, uptime};
use cbb_core::media::Part;

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
    pub log: Arc<dyn Fn(&str) + Send + Sync>,
}

/// A running member of a phone's app.
pub struct Member {
    node: Arc<Node>,
    dialers: Dialers,
    listener: Mutex<Option<Listener>>,
    own: Own,
    log: Arc<dyn Fn(&str) + Send + Sync>,
}

/// The group's copy as the app shows it and the button fetches it.
#[derive(Clone, Debug)]
pub struct Copy {
    pub event: Event,
    /// The key the button compares it by (crate::button).
    pub key: String,
}

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
        let device =
            DeviceInfo { form: "phone".into(), os_version: cfg.os_version, version: cfg.version, mac: String::new() }
                .cleaned();
        let node = Node::new(ident, &cfg.name, engine.clone(), records, cfg.state_dir, cfg.on_write, log.clone())
            .presenting(Presence { role: "phone".into(), name: cfg.name, os: cfg.os, key_store: cfg.key_store, device })
            .keeping_identity(cfg.keep_identity)
            .with_content();
        let node = Arc::new(node);
        engine.set_seal(node.sealer());
        discovery::start(node.clone(), tag.clone(), cfg.peers, false, None, log.clone());
        if cfg.mdns {
            discovery::start_as_phone(node.clone(), tag, log.clone());
        }
        Ok(Member { node, dialers: Dialers::default(), listener: Mutex::new(None), own: Own::default(), log })
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

    /// Sets the phone's sync mode, which its hellos say; the members see it
    /// at the next connection.
    pub fn set_mode(&self, mode: Mode) {
        self.node.engine.set_mode(mode);
        self.node.reconnect();
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
