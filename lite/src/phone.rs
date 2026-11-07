// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The member as a phone's app runs it in its own process (the Aurora app,
//! through lite/ffi): the same node as the service, with the device key
//! where the app keeps it, no control socket and no listening port. A
//! phone dials the members it finds (docs/protocol.md, section 3).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use cbb_core::clip::{Engine, Kind, Via};
use cbb_core::identity::Identity;
use cbb_core::wire::DeviceInfo;

use crate::error::Result;
use crate::node::{KeepIdentity, Node, Peer, Presence, WriteReq};
use crate::records::{Records, Stored as _};
use crate::{discovery, mute, service, uptime, wire};

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

/// A running member of a phone's app.
pub struct Member {
    node: Arc<Node>,
    state_dir: PathBuf,
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
        let device =
            DeviceInfo { form: "phone".into(), os_version: cfg.os_version, version: cfg.version, mac: String::new() }
                .cleaned();
        if let Err(e) = mute::load(&cfg.state_dir, &engine) {
            log(&format!("cbb: the mute: {}; not muted", e.for_log()));
        }
        let state_dir = cfg.state_dir.clone();
        let node = Node::new(ident, &cfg.name, engine.clone(), records, cfg.state_dir, cfg.on_write, log.clone())
            .presenting(Presence { role: "phone".into(), name: cfg.name, os: cfg.os, key_store: cfg.key_store, device })
            .keeping_identity(cfg.keep_identity);
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
        discovery::start(node.clone(), tag.clone(), cfg.peers, false, None, log.clone());
        if cfg.mdns {
            discovery::start_as_phone(node.clone(), tag, log);
        }
        Ok(Member { node, state_dir })
    }

    /// Keeps the group's copies out of the phone's clipboard for ms
    /// milliseconds (0 for until [`Member::resume`]); its own copies still
    /// go out (design.md, "Muting a device").
    pub fn pause(&self, ms: i64) -> Result<()> {
        self.node.engine.pause(mute::until(ms)?);
        mute::save(&self.state_dir, &self.node.engine)
    }

    /// Takes the group's copies again.
    pub fn resume(&self) -> Result<()> {
        self.node.engine.resume();
        mute::save(&self.state_dir, &self.node.engine)
    }

    /// How long receiving stays paused and how long an admin's mute lasts,
    /// in milliseconds: 0 for until it is lifted, None for neither.
    pub fn muted(&self) -> (Option<i64>, Option<i64>) {
        (self.node.engine.pause_left(), self.node.engine.mute_left())
    }

    /// Sends a text the user copied on the phone and handed to the app.
    pub fn copy(&self, text: &str, secret: bool) -> Result<()> {
        self.node.send(text, if secret { Kind::Secret } else { Kind::Text }, Via::Phone)
    }

    /// The members connected now.
    pub fn peers(&self) -> Vec<Peer> {
        self.node.peers()
    }

    /// Stops the member and closes its connections.
    pub fn stop(&self) {
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
            wire::CommandResult { id: id.to_string(), status: "refused".into(), reason: why }
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
            Ok(()) => wire::CommandResult { id: body.id, status: "done".into(), reason: String::new() },
            Err(e) => {
                (self.log)(&format!("cbb: a mute from {peer}: {}", e.for_log()));
                wire::CommandResult { id: body.id, status: "failed".into(), reason: e.message().to_string() }
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
