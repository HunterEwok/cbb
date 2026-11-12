// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The member as a phone's app runs it in its own process (the Aurora app,
//! through ffi/): the same node as the service, with the device key
//! where the app keeps it and no control socket. A phone dials the members
//! it finds (docs/protocol.md, section 3), by mDNS or as its app hands them
//! in; while the app is in the front it may also listen as the group's hub
//! at home (`listen`), and in the background it pauses. Away from home it
//! reaches the group's hub through the same tunnel as cbb
//! (`crate::away`, in a build with the feature `tunnel`), once the user
//! turns sync away from home on. With `serve_servers` (the apps that sign
//! through the core) the member does the rest as the service does: the
//! group's server credentials, the phone as one of the group's hubs with
//! its forwarder, and the blind relay.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use cbb_core::admit::{self, Admitted, Admitter, GroupView};
use cbb_core::certs::DeviceId;
use cbb_core::clip::{Engine, Event, Kind, Via};
use cbb_core::identity::Identity;
use cbb_core::manage::{self, Change, Order, Signer};
use cbb_core::takeover::{self, ClaimState, How};
use cbb_core::wire::{self, CommandResult, DeviceInfo};

use crate::away::Away;
pub use crate::away::GuestTunnel;
use crate::button::{self, Own};
use crate::content::Source;
use crate::discovery::{Dialers, Listener};
use crate::error::{Error, Result};
pub use crate::inviter::Invite;
use crate::node::{KeepIdentity, Node, OnCommand, OnMessage, OnPeer, OnTunnel, Peer, Presence, WriteReq};
use crate::records::{Record, Records, Stored as _};
/// A remote paste's text as it may go in, as the computers clean it, for
/// the paste commands the phone signs.
pub use crate::remotepaste::clean as clean_paste;
pub use crate::window::{CONFIRM_WAIT, Confirm, Joined};
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
    /// `member`, `phone` or `watch`.
    pub role: String,
    /// What a member can do, from its record, or from its hello while no
    /// record lists it.
    pub caps: Vec<String>,
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
    /// Its sync, from its hello's mode: `on` (shared), `off` (own) or empty
    /// while it is not connected or sent another mode.
    pub sync: String,
    /// The CBB version, system version and MAC address its hello names;
    /// empty when it is not connected or named none.
    pub version: String,
    pub os_version: String,
    pub mac: String,
}

/// A running member of a phone's app.
pub struct Member {
    node: Arc<Node>,
    dialers: Dialers,
    /// The member ports open now, by what they are for.
    listeners: Mutex<HashMap<Listen, Listener>>,
    own: Own,
    log: Arc<dyn Fn(&str) + Send + Sync>,
    state_dir: PathBuf,
    /// What carries out the commands for the phone other than a mute.
    others: Arc<RwLock<Option<OnCommand>>>,
    /// What gets the tunnel offers besides sync away from home, which
    /// always gets them.
    tunnels: Arc<RwLock<Option<OnTunnel>>>,
    away: Arc<Away>,
    /// The admins given a new admin CA, by device, with the root it is from.
    admin_cas: Mutex<std::collections::BTreeMap<String, crate::takeover::AdminCaSent>>,
    /// The user's order of the tiles (crate::view).
    tiles: crate::view::Tiles,
    /// The group's server credentials once serve_servers ran.
    servers: Arc<std::sync::OnceLock<Arc<crate::credentials::Credentials>>>,
    /// What gets the messages the member does not take itself: the app's.
    app_messages: Arc<RwLock<Option<OnMessage>>>,
}

/// How often the server credentials are looked at when nothing changed,
/// as the service's credential_check.
const CREDENTIAL_CHECK: Duration = Duration::from_secs(12 * 3600);

/// What a member port a phone opens is for.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Listen {
    /// The home network, while the phone is the hub: every address.
    Home,
    /// The hub's tunnel, whose connections come to the loopback address.
    Tunnel,
    /// A blind relay's calls, on the loopback address, each only from the
    /// device the relay announced (the admit check).
    Relay,
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
        let device = DeviceInfo {
            form: "phone".into(),
            os_version: cfg.os_version,
            version: cfg.version,
            mac: String::new(),
            archive: String::new(),
        }
        .cleaned();
        if let Err(e) = mute::load(&cfg.state_dir, &engine) {
            log(&format!("cbb: the mute: {}; not muted", e.for_log()));
        }
        if let Err(e) = crate::sync::load(&cfg.state_dir, &engine) {
            log(&format!("cbb: sync on or off: {}; sync is on", e.for_log()));
        }
        let state_dir = cfg.state_dir.clone();
        let node = Node::new(ident, &cfg.name, engine.clone(), records, cfg.state_dir, cfg.on_write, log.clone())
            .presenting(Presence {
                role: "phone".into(),
                caps: Vec::new(),
                name: cfg.name,
                os: cfg.os,
                key_store: cfg.key_store,
                device,
                admin_key: Default::default(),
            })
            .keeping_identity(cfg.keep_identity)
            .with_content();
        let node = Arc::new(node);
        engine.set_seal(node.sealer());
        let others: Arc<RwLock<Option<OnCommand>>> = Arc::new(RwLock::new(None));
        let commands = Commands {
            node: Arc::downgrade(&node),
            state_dir: state_dir.clone(),
            started_ms: uptime::wall_ms(),
            seen: Mutex::new(HashMap::new()),
            on_mute: cfg.on_mute,
            others: others.clone(),
            log: log.clone(),
        };
        node.on_command(Arc::new(move |peer, c| commands.command(peer, c)));
        node.set_tunnel_key(away.key());
        let tunnels: Arc<RwLock<Option<OnTunnel>>> = Arc::new(RwLock::new(None));
        {
            let (away, app) = (away.clone(), tunnels.clone());
            let n = Arc::downgrade(&node);
            node.on_tunnel(Box::new(move |from, v, may_host| {
                if let (Some(hub), Some(node)) = (away.offered(from, v, may_host), n.upgrade()) {
                    away.retry(&node, &hub);
                }
                if let Some(f) = app.read().unwrap().as_ref() {
                    f(from, v, may_host);
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
        // The credentials and what the group's hubs share go to the member
        // itself once it serves the servers, the rest to the app.
        let servers: Arc<std::sync::OnceLock<Arc<crate::credentials::Credentials>>> = Arc::default();
        let app_messages: Arc<RwLock<Option<OnMessage>>> = Arc::default();
        {
            let (servers, app, away, n) = (servers.clone(), app_messages.clone(), away.clone(), Arc::downgrade(&node));
            node.on_message(Box::new(move |from, m| {
                if let (Some(creds), Some(node)) = (servers.get(), n.upgrade()) {
                    if let (Some(v), "credentials") = (m.credentials.as_ref(), m.kind.as_str()) {
                        creds.received(&node, from, v);
                        return;
                    }
                    if let (Some(v), "hubs") = (m.hubs.as_ref(), m.kind.as_str()) {
                        away.hubs_shared(&node, from, &node.chain_of(from), v);
                        return;
                    }
                }
                if let Some(f) = app.read().unwrap().as_ref() {
                    f(from, m);
                }
            }));
        }
        Ok(Member {
            node,
            dialers: Dialers::default(),
            listeners: Mutex::new(HashMap::new()),
            own: Own::default(),
            log,
            others,
            tunnels,
            away,
            admin_cas: Mutex::new(std::collections::BTreeMap::new()),
            tiles: crate::view::Tiles::new(&state_dir),
            state_dir,
            servers,
            app_messages,
        })
    }

    /// Makes the member do what the service does for the servers, for an
    /// app that signs through the core: it keeps the group's server
    /// credentials (docs/protocol.md, section 18) with its keys for the
    /// servers where the app holds them, takes and passes on those its
    /// peers send, and brings them up to date when the records or the
    /// credentials change and twice a day; as one of the group's hubs it
    /// admits the tunnel keys the hellos offer and takes what the other hubs
    /// share. Once per member.
    pub fn serve_servers(&self, held: Arc<dyn crate::credentials::HeldKeys>) -> Result<()> {
        if self.servers.get().is_some() {
            return Ok(());
        }
        let creds = crate::credentials::Credentials::load_held(&self.state_dir, &self.node, held, self.log.clone());
        self.away.set_credentials(creds.clone());
        if self.servers.set(creds.clone()).is_err() {
            return Ok(());
        }
        {
            let (away, n, creds) = (self.away.clone(), Arc::downgrade(&self.node), creds.clone());
            self.node.on_hello(Box::new(move |from, peer, chain| match n.upgrade() {
                Some(node) => {
                    let mut out = away.hello(&node, from, peer, chain);
                    out.extend(creds.message());
                    out
                }
                None => Vec::new(),
            }));
        }
        {
            let away = self.away.clone();
            self.node.on_guest(Box::new(move |node, from, chain, g| away.guest_message(node, from, chain, g)));
        }
        let (away, node) = (self.away.clone(), self.node.clone());
        std::thread::spawn(move || {
            let (mut seen, mut at) = ((String::new(), usize::MAX), std::time::Instant::now());
            while !node.is_closed() {
                let now = (node.records().lock().unwrap().digest(), creds.changes());
                if now != seen || at.elapsed() >= CREDENTIAL_CHECK {
                    creds.refresh(&node);
                    seen = (node.records().lock().unwrap().digest(), creds.changes());
                    at = std::time::Instant::now();
                }
                // A hub drops the clients the records now refuse, and every
                // member the offers of devices that may no longer be hubs.
                away.prune(&node);
                node.records_nap(Duration::from_secs(30));
            }
        });
        Ok(())
    }

    fn credentials(&self) -> Result<&Arc<crate::credentials::Credentials>> {
        self.servers.get().ok_or_else(|| Error::msg("the member does not serve the servers"))
    }

    /// Whether this phone holds the root and the next period of the
    /// server credentials waits for the app to sign it (sign_period).
    pub fn period_due(&self) -> bool {
        self.servers.get().is_some_and(|c| c.period_due())
    }

    /// Signs the next period of the server credentials with the root key
    /// the app hands in for this call, after asking the user, when one is
    /// due.
    pub fn sign_period(&self, key: Arc<dyn cbb_core::identity::ExternalKey>) -> Result<()> {
        self.credentials()?.sign_period(&self.node, key)
    }

    /// Makes this phone one of the group's hubs (docs/protocol.md, section
    /// 11), reached away from home through the forwarder at forwarder
    /// (`host:port`), whose key's pin is key, or `default` for the
    /// project's; with AmneziaWG unless obfuscate_off, and VLESS at the
    /// forwarder unless vless_off. Sync away from home goes on with it.
    /// Only the group's root or an admin is a hub.
    pub fn hub_on(&self, forwarder: &str, key: &str, obfuscate_off: bool, vless_off: bool) -> Result<()> {
        self.credentials()?;
        let me = self.node.identity().id.to_string();
        if !self.node.records().lock().unwrap().may_host(&me) {
            return Err(Error::msg(
                "only the group's root or an admin can be its hub, since the members take the hub's offer from them only",
            ));
        }
        let h = crate::control::Header {
            name: "hub".into(),
            forwarder: resolve(forwarder)?,
            forwarder_key: key.to_string(),
            obfuscate_off,
            vless_off,
            consent: true,
            ..Default::default()
        };
        self.node.set_tunnel_key(Some(self.away.make_hub(&h)?));
        self.away.serve_if_first(&self.node);
        // The members connected get the hub's offer without connecting
        // again (docs/protocol.md, section 4, "Presence").
        self.node.announce(true);
        Ok(())
    }

    /// Makes this phone, a hub, stop being one; without anyway it refuses
    /// while the group has no other hub. Sync away from home stays on.
    pub fn hub_off(&self, anyway: bool) -> Result<()> {
        self.away.stop_hub(&self.node, anyway)
    }

    /// Meets the group at the blind relay at relay (`host:port`), whose
    /// key's pin is key, or `default` for the project's, in place of the
    /// group's hubs, once the user read what a relay learns
    /// (docs/protocol.md, section 14); with relay empty it leaves the relay
    /// and turns sync away from home on again with new keys.
    pub fn relay(&self, relay: &str, key: &str) -> Result<()> {
        self.credentials()?;
        if relay.is_empty() {
            self.away_off()?;
            return self.away_on();
        }
        let h = crate::control::Header {
            name: "relay".into(),
            relay: resolve(relay)?,
            relay_key: key.to_string(),
            consent: true,
            ..Default::default()
        };
        self.node.set_tunnel_key(Some(self.away.meet_at(&self.node, &h)?));
        Ok(())
    }

    /// The tiles to draw for devices, the group's devices as the app's
    /// devices call lists them, with the user's change op first (crate::view),
    /// and why this device does not sync, with away the app's own tunnel.
    pub fn view(
        &self,
        devices: Vec<crate::control::Device>,
        op: Option<&cbb_core::arrange::Op>,
        away: Option<cbb_core::why::AwayFacts>,
    ) -> Result<crate::view::View> {
        let view = self.tiles.view(&self.node.identity().tag(), devices, op)?;
        Ok(crate::view::View { warnings: self.why(away), ..view })
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
    /// cbb; None while it is off.
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
    pub fn muted(&self) -> crate::sync::Standing {
        crate::sync::standing(&self.node.engine)
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
        let event = self.node.send_media(text, parts, Via::Phone)?;
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

    /// How far the peers read the images or files of the group's copy id,
    /// and their sealed size, as a share waits for a computer to fetch
    /// them; None when id is not the group's copy or holds no bytes.
    pub fn served(&self, id: &str) -> Option<(u64, u64)> {
        self.node.served(id)
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

    /// A command the node passed to the app (its `others`), checked again
    /// with the records and opened when sealed, as the core's
    /// `group_command` answers it, with a paste's text as it may go in
    /// (`clean`, as the computers clean it): the app takes its orders from
    /// here.
    pub fn check_command(&self, c: &Record) -> Result<serde_json::Value> {
        let me = self.node.identity().id.to_string();
        let mut v = {
            let records = self.node.records();
            let records = records.lock().unwrap();
            let secret = crate::sealkey::secret().unwrap_or_default();
            cbb_core::api::checked_command(&records, c, &me, uptime::wall_ms(), secret)?
        };
        let text = v.pointer("/command/text").and_then(serde_json::Value::as_str).map(crate::remotepaste::clean);
        if let (Some(t), Some(o)) = (text, v.as_object_mut()) {
            o.insert("clean".into(), t.into());
        }
        Ok(v)
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

    /// Opens a member port for what: on the home network (every address)
    /// for the members that dial this phone as the group's hub, which the
    /// app publishes with `r=phone`, or on the loopback address for the
    /// hub's tunnel or a blind relay's calls; port 0 takes a free one.
    /// admit checks each connection before it is served. A port already
    /// open for what stays; returns the port.
    pub fn listen(&self, what: Listen, port: u16, admit: Option<crate::node::Admit>) -> Result<u16> {
        let mut ls = self.listeners.lock().unwrap();
        if let Some(l) = ls.get(&what) {
            return Ok(l.port);
        }
        let loopback = what != Listen::Home;
        let opened = Listener::open_with(self.node.clone(), port, loopback, admit, self.log.clone())
            .ok_or_else(|| crate::error::Error::msg(format!("cannot listen on port {port}")))?;
        let p = opened.port;
        ls.insert(what, opened);
        Ok(p)
    }

    /// Closes the port listen opened for what, or every port with None.
    pub fn unlisten(&self, what: Option<Listen>) {
        let mut ls = self.listeners.lock().unwrap();
        let gone: Vec<Listener> = match what {
            Some(w) => ls.remove(&w).into_iter().collect(),
            None => ls.drain().map(|(_, l)| l).collect(),
        };
        drop(ls);
        for l in gone {
            l.stop();
        }
    }

    /// Closes every connection with a goodbye and the port, and makes no
    /// new connection until resume: the app went to the background.
    pub fn pause(&self) {
        self.unlisten(None);
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
        self.node.announce(false);
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
    /// full members among the root and the admins, or to the member to
    /// only; returns those it went to.
    pub fn send_hubs(&self, share: &serde_json::Value, to: Option<&DeviceId>) -> Vec<DeviceId> {
        let m = wire::hubs(share);
        match to {
            Some(d) => self.node.send_to(d, m).then(|| d.clone()).into_iter().collect(),
            None => self.node.send_to_hubs(&m),
        }
    }

    /// Sends the group's server credentials the app keeps: to the member to
    /// only (a peer that just connected), or to every member but except
    /// (the one that sent them).
    pub fn send_credentials(
        &self,
        list: &serde_json::Value,
        to: Option<&DeviceId>,
        except: Option<&DeviceId>,
    ) -> Vec<DeviceId> {
        let m = wire::credentials(list);
        match to {
            Some(d) => self.node.send_to(d, m).then(|| d.clone()).into_iter().collect(),
            None => self.node.broadcast(&m, |p| Some(&p.id) != except),
        }
    }

    /// Sets what gets each copy that becomes the group's current one from
    /// another member: a text or secret the phone may take by itself, or
    /// images or files to fetch.
    pub fn on_change(&self, f: crate::node::OnChange) {
        self.node.on_change(f);
    }

    /// Sets what gets the admin, hubs, credentials and evidence messages
    /// peers send; once the member serves the servers it takes the hubs
    /// and credentials messages itself.
    pub fn on_message(&self, f: OnMessage) {
        *self.app_messages.write().unwrap() = Some(f);
    }

    /// Sets what gets each peer once its hello is taken: an admin's app
    /// renews its certificate, the root's sends it its admin CA, the hub's
    /// answers its tunnel key.
    pub fn on_peer(&self, f: OnPeer) {
        self.node.on_peer(f);
    }

    /// Sets what gets the tunnel offers of the group's root and admins, for
    /// the app's tunnel to the hub (docs/protocol.md, section 11). Sync away
    /// from home in the core gets them too, before it.
    pub fn on_tunnel(&self, f: OnTunnel) {
        *self.tunnels.write().unwrap() = Some(f);
    }

    /// Sets what carries out the commands for this phone itself other than
    /// a mute, which the member carries out (a sync mode, sync away from home
    /// off); without it the phone refuses them. Commands for other devices it
    /// passes on.
    pub fn on_command(&self, f: OnCommand) {
        *self.others.write().unwrap() = Some(f);
    }

    /// Sets the tunnel key and preshared key the hellos offer the group's
    /// hubs, None while sync away from home is off, and connects to the
    /// full members again so that they get them.
    pub fn set_tunnel_key(&self, key: Option<(Vec<u8>, Vec<u8>)>) {
        self.node.set_tunnel_key(key);
    }

    /// Sets the attestations of the phone's keys every peer gets after its
    /// hello (docs/protocol.md, section 17, "Evidence").
    pub fn set_evidence(&self, list: Vec<serde_json::Value>) {
        self.node.set_evidence(list);
    }

    /// Ends the connection to the member id with a goodbye, as for a device
    /// the app removed or whose hub moved; it is dialed again later.
    pub fn disconnect(&self, id: &DeviceId) {
        self.node.disconnect(id);
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
                    sync: peer.map(|p| sync_of(&p.mode)).unwrap_or_default(),
                    version: peer.map(|p| p.device.version.clone()).unwrap_or_default(),
                    os_version: peer.map(|p| p.device.os_version.clone()).unwrap_or_default(),
                    mac: peer.map(|p| p.device.mac.clone()).unwrap_or_default(),
                    online: peer.is_some(),
                    this: d.id == me,
                    root: root.as_deref() == Some(d.id.as_str()),
                    listed: true,
                    admin: d.admin,
                    frozen: d.frozen,
                    id: d.id,
                    name: d.name,
                    role: d.role,
                    caps: d.caps,
                }
            })
            .collect();
        for p in peers {
            if !out.iter().any(|d| d.id == p.id.as_str()) {
                out.push(DeviceView {
                    id: p.id.to_string(),
                    sync: sync_of(&p.mode),
                    version: p.device.version.clone(),
                    os_version: p.device.os_version.clone(),
                    mac: p.device.mac.clone(),
                    name: p.name,
                    role: p.role,
                    caps: p.caps,
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

    /// Why the phone does not sync (cbb_core::why), from the same status
    /// a computer's control socket gives: its sync and mute, the group's
    /// records, the members connected and sync away from home. An app
    /// whose tunnel runs outside the member (the iPhone's and Android's)
    /// hands in away, where its tunnel stands; None takes the member's own.
    pub fn why(&self, away: Option<cbb_core::why::AwayFacts>) -> Vec<cbb_core::why::Reason> {
        let n = &self.node;
        let standing = self.muted();
        let now = uptime::wall_ms();
        let st = crate::control::Status {
            device: n.identity().id.to_string(),
            group: n.identity().tag(),
            mode: if standing.sync_off { "own" } else { "shared" }.into(),
            sync_until_ms: if standing.sync_off && standing.sync_off_ms > 0 { now + standing.sync_off_ms } else { 0 },
            muted: standing.muted,
            muted_until_ms: if standing.muted && standing.muted_ms > 0 { now + standing.muted_ms } else { 0 },
            peers: n
                .peers()
                .into_iter()
                .map(|p| crate::control::Device { id: p.id.to_string(), ..Default::default() })
                .collect(),
            away: self.away.status(n),
            stop: n.stop(),
            cert_ends_ms: n.identity().cert.not_after.saturating_mul(1000),
            ..crate::why::group_status(n)
        };
        let removed = n.removed() && !st.frozen && st.taken_over_by.is_empty();
        let st = crate::control::Status { removed, ..st };
        let devs: Vec<crate::control::Device> = self
            .device_views()
            .into_iter()
            .map(|d| crate::control::Device {
                mode: match d.sync.as_str() {
                    "off" => "own".into(),
                    _ => String::new(),
                },
                id: d.id,
                name: d.name,
                online: d.online,
                this: d.this,
                ..Default::default()
            })
            .collect();
        let mut facts = crate::why::facts(&st, &devs);
        if let Some(mut a) = away {
            // The app names the hub by its device ID.
            if let Some(d) = devs.iter().find(|d| d.id == a.hub_device && !d.name.is_empty()) {
                a.hub_device.clone_from(&d.name);
            }
            facts.away = Some(a);
        }
        cbb_core::why::diagnose(&facts, now)
    }

    /// Makes a remote invitation as an admin of the group, with admitter's
    /// CA key, valid for lifetime (an hour when zero, a day at most): its
    /// guest tunnel on this phone when it is the group's hub, else through
    /// hub or the first connected hub that takes it (docs/protocol.md,
    /// section 12). confirm is asked about each device that uses it; the
    /// app waits on the invitation and closes it.
    pub fn invite(
        &self,
        admitter: Admitter,
        lifetime: Duration,
        hub: Option<&DeviceId>,
        confirm: crate::window::Confirm,
    ) -> Result<crate::inviter::Invite> {
        let group = self.node.identity().tag();
        let (node, away) = (&self.node, &self.away);
        let open = |keys: &crate::inviter::GuestKeys, w: &Arc<crate::window::Window>, life: Duration| {
            crate::inviter::open_where(node, away, hub, keys, w, life)
        };
        let inv = crate::inviter::Invite::start(admitter, &group, lifetime, confirm, &open)?;
        (self.log)(&format!("cbb: an invitation is open for {} minutes", inv.lifetime.as_secs() / 60));
        Ok(inv)
    }

    /// Takes up the invitation this phone joined with, once the app stored
    /// its identity: sync away from home goes on, and the member offers its
    /// own tunnel key to the invitation's hub through the guest tunnel until
    /// the hub answers.
    pub fn joined_by_invite(&self, text: &str) -> Result<()> {
        cbb_core::invite::parse(text).map_err(|r| Error::msg(r.message()))?;
        self.away_on()?;
        crate::away::keep_guest(&self.state_dir, text)
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

    /// Claims the group for new_root (DER), a root CA for a new key of the
    /// phone that the app keeps before it calls this (src/takeover.rs).
    pub fn claim(&self, s: &Signer, how: How, new_root: &[u8]) -> Result<()> {
        crate::takeover::claim(&self.node, s, how, new_root)
    }

    /// Where the claim to new_root stands; None when the records hold none.
    pub fn claim_state(&self, new_root: &[u8]) -> Option<ClaimState> {
        takeover::claim_state(&self.node.records().lock().unwrap(), new_root)
    }

    /// Adds a record the root signed about the group itself
    /// (cbb_core::root), which make signs from the group's records at the
    /// wall clock's milliseconds, and passes it to the group.
    pub fn add_root_record(
        &self,
        make: impl FnOnce(&cbb_core::group::Records, i64) -> cbb_core::error::Result<Record>,
    ) -> Result<()> {
        let records = self.node.records();
        let r = make(&records.lock().unwrap(), uptime::wall_ms())?;
        self.node.add_own_records(std::slice::from_ref(&r));
        if !records.lock().unwrap().has(&r) {
            return Err(Error::msg("the group's records did not take the record; the log says why"));
        }
        Ok(())
    }

    /// The group's takeover delay, key level, recovery key and handover, for
    /// the root's settings (cbb_core::root::view).
    pub fn root_view(&self) -> cbb_core::root::View {
        cbb_core::root::view(&self.node.records().lock().unwrap())
    }

    /// The admins and hubs other than this phone whose keys the key level
    /// would not let in, by device ID (cbb_core::root::below_level).
    pub fn below_level(&self, level: &str) -> Vec<String> {
        let me = self.node.identity().id.to_string();
        cbb_core::root::below_level(&self.node.records().lock().unwrap(), &me, level)
    }

    /// Makes the phone the group's root once its claim took effect: s is
    /// the new root, which signs the phone's member certificate from it and
    /// the records a new root starts with. The identity event gives the
    /// app the new certificate. It returns the certificate.
    pub fn finish_takeover(&self, s: &Signer, own: &takeover::Own) -> Result<Vec<u8>> {
        let f = crate::takeover::finished(&self.node, s, own)?;
        crate::takeover::become_root(&self.node, &f)?;
        Ok(f.cert)
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
    /// connected member's, sent to it, and this phone's own, kept; as the
    /// current root also each connected admin's CA from an earlier root,
    /// as after a takeover. It returns how many it renewed.
    pub fn renew(&self, s: &Signer) -> Result<usize> {
        let mut n = self.node.renew_due(s)?;
        let mut roots = self.node.records().lock().unwrap().roots();
        if roots.is_empty() {
            roots.push(self.node.identity().root().clone());
        }
        if roots.last() == Some(s.ca) {
            n += crate::takeover::renew_admin_cas(&self.node, s, &self.admin_cas);
        }
        Ok(n)
    }

    /// Stops the member and closes its connections.
    pub fn stop(&self) {
        self.unlisten(None);
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
    /// What carries out the other commands for the phone: its app's.
    others: Arc<RwLock<Option<OnCommand>>>,
    log: Arc<dyn Fn(&str) + Send + Sync>,
}

impl Commands {
    fn command(&self, peer: &crate::certs::DeviceId, c: &crate::records::Record) -> wire::CommandResult {
        let refused = |id: &str, why: String| {
            (self.log)(&format!("cbb: refused a command from {peer}: {why}"));
            wire::CommandResult {
                id: id.to_string(),
                by: String::new(),
                status: "refused".into(),
                reason: why,
                tunnel: None,
            }
        };
        let Some(node) = self.node.upgrade() else {
            return refused(&crate::node::command_id(c), "the member stopped".into());
        };
        let now = uptime::wall_ms();
        let me = node.identity().id.to_string();
        let verified = node.records().lock().unwrap().verify_command(c, &me, now);
        let mut body = match verified {
            Ok(b) => b,
            Err(e) => return refused(&crate::node::command_id(c), e.message().to_string()),
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
            // The app carries out the others it takes (a sync mode, sync
            // away from home off), with its own checks; without it they are
            // refused.
            let app = self.others.read().unwrap().clone();
            return match app {
                Some(f) => f(peer, c),
                None => refused(&body.id, format!("this phone takes no {} commands", body.kind)),
            };
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
            Ok(()) => wire::CommandResult {
                id: body.id,
                by: String::new(),
                status: "done".into(),
                reason: String::new(),
                tunnel: None,
            },
            Err(e) => {
                (self.log)(&format!("cbb: a mute from {peer}: {}", e.for_log()));
                wire::CommandResult {
                    id: body.id,
                    by: String::new(),
                    status: "failed".into(),
                    reason: e.message().to_string(),
                    tunnel: None,
                }
            }
        }
    }

    /// Mutes the phone until `until` (0 for until an admin lifts it), or
    /// ends its mute, saves it, tells the app, and tells the members
    /// connected in a presence message, without connecting again.
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
        node.announce(false);
        Ok(())
    }
}

/// A hello's mode as the device's house: `on` for shared, `off` for own,
/// empty for another mode or none.
fn sync_of(mode: &str) -> String {
    match mode {
        "shared" => "on",
        "own" => "off",
        _ => "",
    }
    .to_string()
}

/// A server's address as the hub and the relay take it, `ip:port`, from
/// `host:port`, its name looked up now, IPv4 first; empty stays empty.
fn resolve(s: &str) -> Result<String> {
    use std::net::ToSocketAddrs as _;
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
    use super::sync_of;

    /// A device's house reads its hello's mode: shared is on, own is off,
    /// and the old modes show nothing.
    #[test]
    fn house_from_mode() {
        assert_eq!(sync_of("shared"), "on");
        assert_eq!(sync_of("own"), "off");
        assert_eq!(sync_of("receive"), "");
        assert_eq!(sync_of(""), "");
    }
}
