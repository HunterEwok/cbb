// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The service on the records of 0.6 (`live.rs`): a device whose group is
//! kept in `group.cbor` runs the member of 0.6 in place of the old one.
//! The clipboard (watchers, copy, paste), status, devices, sync, the mute
//! of this device, leaving, and the records an admin writes (remove,
//! rename, freeze, thaw, hubs, incoming) run here, and the commands one
//! device sends another (orders.rs); every other operation
//! answers that it is not on the records of 0.6 yet (`live::not_yet`),
//! never a silent no-op, until its part moves over.

use super::*;

use crate::discovery::Peers as _;
use crate::live::{self, Live, not_yet};
use crate::own::Own;
use crate::roster::{self, id_text};
use crate::writers;
use cbb_core::records::body::{MAX_INCOMING_MS, MIN_INCOMING_MS};
use cbb_core::secret::Zeroizing;
use p256::pkcs8::EncodePrivateKey as _;

/// How often this device's sealing keys are checked for a new epoch.
const ROTATE_EVERY: Duration = Duration::from_secs(3600);

/// ROTATE_EVERY, or in a test build what CBB_TEST_RENEW_EVERY gives in
/// milliseconds, as the Go service's tests shorten it.
fn rotate_every() -> Duration {
    crate::testbuild::env("CBB_TEST_RENEW_EVERY")
        .and_then(|v| v.parse().ok())
        .map_or(ROTATE_EVERY, Duration::from_millis)
}

mod orders;

/// Whether the device's group is kept on the records of 0.6.
pub(super) fn in_group(dir: &Path) -> bool {
    dir.join(crate::set::FILE_NAME).exists()
}

/// The clipboard side of the member that runs.
pub(super) struct Group(Arc<Live>);

impl Group {
    /// The text this device's own clipboard holds, as the member knows it.
    pub(super) fn local_text(&self) -> Option<String> {
        self.0.board.local().map(|(t, ..)| t)
    }

    /// A watcher says what its clipboard holds.
    pub(super) fn clipboard_is(&self, text: &str, kind: Kind) {
        self.0.board.clipboard_is(text, kind)
    }

    /// A watcher saw the clipboard change.
    pub(super) fn copied(&self, text: &str, kind: Kind, via: Via) -> Result<()> {
        self.0.copied(text, kind, via)
    }
}

impl Service {
    /// The member of 0.6, once it runs.
    pub(super) fn live(&self) -> Option<Arc<Live>> {
        self.live.read().unwrap().clone()
    }

    /// The clipboard side of the member that runs.
    pub(super) fn group(&self) -> Result<Group> {
        self.started(|| self.live()).map(Group)
    }

    /// Starts the member of 0.6 on the group in the state directory: it
    /// finds and dials its members, listens on the member port and passes
    /// the copies to write to the watchers.
    pub(super) fn start_live(self: &Arc<Self>, cfg: &Config) -> Result<Arc<Live>> {
        let log = self.log.clone();
        let own = Own::load(&cfg.state_dir)?;
        // The blobs of the copies are a cache that a service starts empty,
        // as on the old member.
        crate::content::empty(&cfg.state_dir, &|s| log(s));
        let live = Live::open(&cfg.state_dir, own, log.clone())?;
        // The signed release and entry points, kept and passed on as the
        // old member does (docs/protocol.md, section 16).
        {
            let (now, roots) = (uptime::wall_ms(), crate::update::release_roots);
            live.mesh.with_signed(
                Arc::new(crate::releases::Releases::open(&cfg.state_dir, roots(), now, &*log)),
                Arc::new(crate::entries::Entries::open(&cfg.state_dir, roots(), now, &*log)),
            );
        }
        if let Err(e) = crate::sync::load(&cfg.state_dir, &live.board) {
            log(&format!("cbb: sync on or off: {}; sync is on", e.for_log()));
        }
        log(&crate::sync::line(&live.board));
        if let Err(e) = crate::mute::load(&cfg.state_dir, &live.board) {
            log(&format!("cbb: the mute: {}; not muted", e.for_log()));
        }
        {
            let svc = self.clone();
            live.on_write(Box::new(move |w| svc.deliver_live(w)));
        }
        {
            let (svc, w) = (self.clone(), Arc::downgrade(&live));
            live.mesh.on_command(Box::new(move |t| match w.upgrade() {
                Some(l) => svc.live_command(&l, t),
                None => Err(Error::msg("the service is stopping")),
            }));
        }
        self.live_hello(&live);
        // -tunnel-via sends the tunnel's packets to a local UDP port that
        // leads to the hub (cbb next link -udp).
        live.start_away(cfg.state_dir.clone(), cfg.tunnel_via, log.clone())?;
        live.set_networks(crate::networks::Networks::load(&cfg.state_dir, true, log.clone()));
        // The attestations of member keys (docs/protocol.md, section 17).
        live.with_attestations();
        live.mesh.set_away_limit(u64::try_from(self.limits.lock().unwrap().away).unwrap_or(0));
        *self.live.write().unwrap() = Some(live.clone());
        let tag = live.tag();
        log(&format!(
            "cbb: device {} in group {tag} on the records of 0.6, version {VERSION}",
            id_text(&live.mesh.device())
        ));
        let port = cfg.port.and_then(|p| discovery::listen(live.clone(), p, log.clone()));
        *self.port.lock().unwrap() = port;
        if let Some(p) = port {
            log(&format!("cbb: listening on port {p}"));
        }
        discovery::start(live.clone(), tag, cfg.peers.clone(), cfg.mdns, port, log.clone());
        // The address this device joined at, given by hand (an SSH forward,
        // a VPN address that mDNS does not reach), is dialed while the
        // device has no connection; with mDNS only once discovery had a
        // moment and found none of the group, or found one that did not
        // dial within the fallback's wait, so that of two members the lower
        // ID still dials (section 4, "Who dials whom").
        if let Some(addr) = self.joined_at.lock().unwrap().take() {
            let wait = cfg.mdns.then(|| (DISCOVERY_MOMENT, discovery::fallback() + Duration::from_secs(5)));
            keep_joined(Arc::downgrade(&live), addr, wait, log.clone());
        }
        {
            // On the group's root: where a member's keys live, as its hello
            // says (docs/protocol.md, section 17).
            let (w, log) = (Arc::downgrade(&live), log.clone());
            live.mesh.on_peer_hello(Box::new(move |peer| {
                let Some(l) = w.upgrade() else { return };
                let Some(store) = l.mesh.hellos().get(peer).map(|h| h.key_store) else { return };
                let st = l.mesh.state();
                let root = l
                    .mesh
                    .own()
                    .root
                    .as_ref()
                    .is_some_and(|k| st.roots.last() == Some(&cbb_core::records::Key::es256(k.public()).hash()));
                if !root {
                    return;
                }
                let now = uptime::wall_ms().max(0) as u64;
                match l.mesh.write(|set, k| writers::store_from_hello(set, k, peer, store, now)) {
                    Ok(Some(d)) => log(&format!(
                        "cbb: {} ({}) keeps its keys {}, as its hello says",
                        d.name,
                        id_text(&d.id),
                        crate::roster::store_name(store)
                    )),
                    Ok(None) => {}
                    Err(e) => log(&format!("cbb: {}", e.for_log())),
                }
            }));
        }
        {
            let (l, log) = (live.clone(), log.clone());
            std::thread::spawn(move || {
                while !l.is_closed() && !STOP.load(Ordering::SeqCst) {
                    wait_unless_stopping(rotate_every());
                    if let Err(e) = l.mesh.rotate() {
                        log(&format!("cbb: {}", e.for_log()));
                    }
                }
            });
        }
        Ok(live)
    }

    /// What this device says of itself in its hellos: its name, system,
    /// version, mode, mute and where its keys live.
    pub(super) fn live_hello(&self, live: &Live) {
        let muted = live.board.mute_left();
        live.mesh.set_hello(crate::hello::Hello {
            name: self.name.clone(),
            os: cbb_core::format::print::os_number(crate::admin::os_name()),
            mode: if live.board.mode() == Mode::Own { 2 } else { 1 },
            muted: muted.is_some(),
            muted_for_ms: muted.map_or(0, |l| u64::try_from(l).unwrap_or(0)),
            // The archive cbb update installs here, for the group's hub to
            // fetch (docs/protocol.md, section 16, "In the group").
            device: crate::hello::Device {
                version: VERSION.into(),
                archive: crate::device::own().archive.clone(),
                ..Default::default()
            },
            features: crate::hello::FEATURE_MEDIA,
            actions: actions::load(&self.state_dir).map(|s| s.on()).unwrap_or_default(),
            key_store: own_store(live.mesh.own()),
            ..Default::default()
        });
    }

    /// A copy from the group to write: to the watchers as a write. Images
    /// and files are fetched first, as deliver does on the old member.
    fn deliver_live(self: &Arc<Self>, w: live::Write) {
        let seq = {
            let mut l = self.latest.lock().unwrap();
            *l += 1;
            *l
        };
        let req = WriteReq {
            text: w.text.clone(),
            media: None,
            kind: if w.media.is_some() { Kind::Text } else { w.kind },
            via: Via::Copy,
            seq,
            ttl: w.ttl,
        };
        let Some(m) = w.media.clone() else {
            self.deliver(req);
            return;
        };
        // Images or files: fetched whatever the watchers take, as on the
        // old member; then whole to the watchers that take them, and the
        // plain-text alternative to the others.
        let alt = (!w.text.is_empty()).then_some(req.clone());
        let whole = WriteReq { media: Some(m.clone()), kind: Kind::Media, ..req };
        let takers = self.watchers.lock().unwrap().iter().any(|x| (x.board || x.target == NEXT) && x.takes(&m));
        if let Some(live) = self.live() {
            let (svc, alt) = (self.clone(), alt.clone());
            std::thread::spawn(move || {
                let limit = svc.limits.lock().unwrap().home;
                let size = w.blob.map_or(0, |b| b.size);
                let fetched = match w.blob {
                    Some(_) if size > limit as u64 => Err(Error::msg(format!(
                        "a {} copy from {} is over this device's limit of {}",
                        copies::size_text(size as i64),
                        id_text(&w.from),
                        copies::size_text(limit)
                    ))),
                    Some(b) => {
                        // Again after a pause while no member gives it,
                        // until a newer write comes or FETCH_FOR passes.
                        let start = Instant::now();
                        loop {
                            let res = live.mesh.fetch(&b, &w.from, limit as u64);
                            if res.is_ok() || *svc.latest.lock().unwrap() != seq || start.elapsed() >= FETCH_FOR {
                                break res;
                            }
                            wait_unless_stopping(Duration::from_secs(2));
                        }
                    }
                    None => Ok(()),
                };
                if *svc.latest.lock().unwrap() != seq {
                    return; // a newer write came
                }
                let mut failed = svc.fetch_failed.lock().unwrap();
                match &fetched {
                    Ok(()) => {
                        failed.clear();
                        (svc.log)(&format!("cbb: fetched a copy of {}", copies::size_text(size as i64)));
                    }
                    Err(e) => {
                        (svc.log)(&format!("cbb: fetching a copy's images or files: {}", e.for_log()));
                        *failed = e.message().to_string();
                    }
                }
                drop(failed);
                if takers {
                    let whole = fetched.is_ok().then_some(whole);
                    svc.send_writes(|x| if x.takes(&m) { whole.clone().or_else(|| alt.clone()) } else { None });
                }
            });
        }
        let Some(alt) = alt else { return };
        let m = w.media.clone().unwrap_or_default();
        if !self.send_writes(|x| if x.takes(&m) && takers { None } else { Some(alt.clone()) }) && !takers {
            *self.pending.lock().unwrap() = Some(alt);
        }
    }

    /// The status of a device in a group of 0.6.
    pub(super) fn live_status(&self, live: &Live) -> Status {
        let peripherals = self.peripherals.status();
        let st = live.mesh.state();
        let devices = self.live_devices(live);
        let me = live.mesh.device();
        let mine = st.devices.iter().find(|d| d.id == me);
        let peers = devices
            .iter()
            .filter(|d| d.online && !d.this)
            .map(|d| Device {
                id: d.id.clone(),
                name: d.name.clone(),
                role: d.role.clone(),
                os: d.os.clone(),
                online: true,
                ..Default::default()
            })
            .collect();
        let muted = live.board.mute_left();
        // Its own statement: the set's lock ends here, before the fields
        // below take it again.
        let relay_group = relay_group(&live.mesh.set().lock().unwrap_or_else(std::sync::PoisonError::into_inner));
        // The newest signed release the group passed around, offered when
        // newer than this device's version.
        let release = live.mesh.releases().and_then(|r| r.version(uptime::wall_ms()));
        let status = Status {
            device: id_text(&me),
            group: live.tag(),
            relay_group,
            role: "member".into(),
            os: crate::admin::os_name().into(),
            peers,
            version: VERSION.into(),
            mode: live.board.mode().name().into(),
            muted: muted.is_some(),
            muted_until_ms: muted.filter(|l| *l > 0).map_or(0, |l| uptime::wall_ms() + l),
            sync_until_ms: live.board.sync().1,
            paste: self.paste_status(),
            keyboard: peripherals.as_ref().and_then(|p| p.keyboard.clone()),
            tvs: peripherals.map(|p| p.tvs).unwrap_or_default(),
            release: release.clone().unwrap_or_default(),
            update: release.filter(|v| crate::releases::offered(v)).unwrap_or_default(),
            actions: action_status(&actions::load(&self.state_dir).unwrap_or_default()),
            removed: mine.is_none(),
            frozen: mine.is_some_and(|d| d.frozen),
            media: Some(self.media_status()),
            key_level: match st.settings.level() {
                cbb_core::records::body::LEVEL_PROVEN => "proven",
                cbb_core::records::body::LEVEL_FILES => "files",
                _ => "hardware",
            }
            .into(),
            incoming_ms: st.incoming_ms.map_or(cbb_core::authority::DEFAULT_INCOMING, |ms| ms as i64),
            unreached: live.unreached(),
            port: self.port.lock().unwrap().map_or(0, i64::from),
            quiet: live.networks().map(|n| n.unknown()).unwrap_or_default(),
            bug: self.bugs.waiting(),
            away: away_status(live),
            stop: match st.stop {
                cbb_core::records::eval::Stop::None => "",
                cbb_core::records::eval::Stop::Secrets => "secrets",
                _ => "full",
            }
            .into(),
            conflicts: live_conflicts(&st),
            ..Default::default()
        };
        // The reasons: what the status says, and what the records of 0.6
        // say of this device and the group.
        let mut facts = crate::why::facts(&status, &devices);
        cbb_core::why::group_facts(&mut facts, &st, &me);
        facts.checkpoint_stuck = !live.mesh.set().lock().unwrap().stuck_checkpoints().is_empty();
        Status { why: cbb_core::why::diagnose(&facts, uptime::wall_ms()), ..status }
    }

    /// The devices of a group of 0.6, as `cbb devices` shows them.
    pub(super) fn live_devices(&self, live: &Live) -> Vec<Device> {
        let muted = live.board.mute_left();
        let me = roster::Me {
            id: live.mesh.device(),
            mode: if live.board.mode() == Mode::Own { "own" } else { "shared" }.into(),
            muted_until_ms: muted.map(|l| if l == 0 { 0 } else { uptime::wall_ms() + l }),
            version: VERSION.into(),
            ..Default::default()
        };
        let mut list = roster::devices(
            &live.mesh.set().lock().unwrap_or_else(std::sync::PoisonError::into_inner),
            &me,
            &live.mesh.hellos(),
            uptime::wall_ms(),
        );
        // A hub as this device knows (`control::Device::hub`): with sync
        // away from home on, itself while it serves or a hub whose offer it
        // keeps; with it off, a device the root's hubs record names.
        if let Some(a) = live.away().filter(|a| a.is_on()) {
            let (serving, held) = (a.is_hub_now(), a.held_hubs());
            for d in &mut list {
                d.hub = if d.this { serving } else { held.contains(&d.id) };
            }
        }
        list
    }

    /// Writes records with this device's root or admin key, and names the
    /// device they are about.
    fn live_write(
        &self,
        live: &Live,
        f: impl FnOnce(
            &mut cbb_core::records::RecordSet,
            &dyn cbb_core::identity::ExternalKey,
            u64,
        ) -> Result<(cbb_core::records::eval::DeviceState, Vec<cbb_core::records::Record>)>,
    ) -> Result<Message> {
        let now = uptime::wall_ms().max(0) as u64;
        let (d, _) = live.mesh.write(|set, key| f(set, key, now))?;
        Ok(control::reply(Header { name: d.name, done: true, ..Default::default() }, Vec::new()))
    }

    /// Mutes this device until `until` (0 for until it is lifted), or ends
    /// its mute, saves it and says so in the hellos.
    pub(super) fn live_mute(&self, live: &Live, on: bool, until: i64, by: &str) -> Result<()> {
        if on {
            live.board.set_mute(until);
        } else {
            live.board.unmute();
        }
        crate::mute::save(&self.state_dir, &live.board, by)?;
        self.live_hello(live);
        (self.log)(&match (on, until) {
            (false, _) => format!("cbb: {by} ended the mute: this device's copies reach the group again"),
            (true, 0) => format!("cbb: {by} muted this device until an admin unmutes it"),
            (true, _) => format!("cbb: {by} muted this device for {} s", (until - uptime::wall_ms()) / 1000),
        });
        Ok(())
    }

    /// The answer to sync and muted.
    pub(super) fn live_standing(&self, live: &Live) -> Message {
        let standing = crate::sync::standing(&live.board);
        control::reply(Header { standing: Some(standing), done: true, ..Default::default() }, Vec::new())
    }

    /// A request on the records of 0.6: its answer, or None for one that
    /// needs no group, which the service answers as ever.
    pub(super) fn live_request(&self, live: &Arc<Live>, m: &Message) -> Option<Result<Message>> {
        let h = &m.header;
        if matches!(h.op.as_str(), control::op::TAKEOVER_DELAY | control::op::TAKE_OVER | control::op::HAND_OVER) {
            return Some(Err(Error::msg(ROOT_BY_RECOVERY)));
        }
        if h.op == "pair" && !(h.code.is_empty() && h.addrs.is_empty() && h.fingerprint.is_empty()) {
            return Some(Err(Error::msg(LISTENING_JOINER_GONE)));
        }
        if let Some(why) = refusal(live, h) {
            return Some(Err(Error::msg(why)));
        }
        if let Some(r) = self.live_orders(live, h, &m.payload) {
            return Some(r);
        }
        let res = match h.op.as_str() {
            op if needs_no_group(op) || op == "paste_receive" => return None,
            "copy" => String::from_utf8(m.payload.clone())
                .context("the text is not UTF-8")
                .and_then(|text| live.send(&text, kind_of(&h.kind)?, via_of(&h.via)?))
                .map(|()| control::reply(Header::default(), Vec::new())),
            "paste" => self.live_paste(live),
            // Signed entry points the user gives (cbb update brings them),
            // kept and passed on.
            "entries" => serde_json::from_slice::<Box<serde_json::value::RawValue>>(&m.payload)
                .map_err(|e| Error::with("the request carries no entry points", e))
                .and_then(|set| live.mesh.put_entries(&set))
                .map(|_| control::reply(Header { done: true, ..Default::default() }, Vec::new())),
            "release" => serde_json::from_slice::<Box<serde_json::value::RawValue>>(&m.payload)
                .map_err(|e| Error::with("the request carries no release", e))
                .and_then(|set| live.mesh.put_release(&set))
                .map(|_| control::reply(Header { done: true, ..Default::default() }, Vec::new())),
            "release_held" => live
                .mesh
                .releases()
                .and_then(|r| r.current(uptime::wall_ms()))
                .ok_or_else(|| Error::msg("this device holds no signed release"))
                .map(|set| control::reply(Header { done: true, ..Default::default() }, set.get().as_bytes().to_vec())),
            "release_want" => serde_json::to_vec(&live.wanted_release_files())
                .map_err(|e| Error::with("cannot encode the files", e))
                .map(|data| control::reply(Header { done: true, ..Default::default() }, data)),
            "update_way" => {
                #[cfg(feature = "tunnel")]
                let way = live.update_way();
                // Built without the tunnel: no hub, so no way over VLESS.
                #[cfg(not(feature = "tunnel"))]
                let way: Option<serde_json::Value> = None;
                match way.map(|v| serde_json::to_vec(&v)).transpose() {
                    Ok(data) => {
                        Ok(control::reply(Header { done: true, ..Default::default() }, data.unwrap_or_default()))
                    }
                    Err(e) => Err(Error::with("cannot encode the VLESS settings", e)),
                }
            }
            "entries_get" => live
                .mesh
                .entries()
                .and_then(|e| e.current(uptime::wall_ms()))
                .ok_or_else(|| Error::msg("this device holds no signed entry points"))
                .map(|set| control::reply(Header { done: true, ..Default::default() }, set.get().as_bytes().to_vec())),
            "status" => {
                Ok(control::reply(Header { status: Some(self.live_status(live)), ..Default::default() }, Vec::new()))
            }
            "devices" => {
                Ok(control::reply(Header { devices: self.live_devices(live), ..Default::default() }, Vec::new()))
            }
            "view" | "arrange" => self.live_view(live, h),
            "network" => {
                if let Some(n) = live.networks()
                    && n.learn_all()
                {
                    (self.log)("cbb: the networks this device is on now are known; it publishes itself on them");
                }
                let status = self.live_status(live);
                Ok(control::reply(Header { status: Some(status), done: true, ..Default::default() }, Vec::new()))
            }
            "sync" => self.live_sync(live, h),
            "muted" => Ok(self.live_standing(live)),
            "mute" | "unmute" => self.live_mute_op(live, h),
            "remove" => {
                if self_named(live, &h.device) {
                    return Some(Err(Error::msg("a device cannot remove itself; run cbb remove on another member")));
                }
                self.live_write(live, |set, k, now| writers::remove(set, k, &h.device, now))
            }
            "rename" => self.live_write(live, |set, k, now| writers::rename(set, k, &h.device, &h.name, now)),
            "freeze" | "thaw" => {
                if self_named(live, &h.device) {
                    return Some(Err(Error::msg("a device cannot freeze or unfreeze itself")));
                }
                // A computer freezes only admins: an ordinary device is
                // removed. A device a change of root carried over frozen,
                // an admin no more, the new root thaws (docs/protocol.md,
                // section 10, "Re-issue"): a `thaw` record signed by the
                // root's own key, which the core's records rules count
                // whatever the frozen key ("Who signs what": `thaw` by "a
                // root's own key"; core records/eval.rs `collect` leaves out
                // a freeze that a counting thaw names).
                let st = live.mesh.state();
                let on = h.op == "freeze";
                if let Ok(d) = writers::find(&st, &h.device)
                    && d.admin.is_none()
                    && Some(d.id) != st.root_device
                    && (on || !d.frozen)
                {
                    return Some(Err(Error::msg(format!(
                        "{} is no admin computer; only those are frozen, and an ordinary device is removed with cbb remove",
                        d.name
                    ))));
                }
                self.live_write(live, |set, k, now| writers::freeze(set, k, &h.device, on, now))
            }
            "resolve" => {
                let now = uptime::wall_ms().max(0) as u64;
                live.mesh.write(|set, k| writers::resolve(set, k, now)).map(|(who, _)| {
                    (self.log)(&format!("cbb: voided both histories of {}", who.join(", ")));
                    control::reply(Header { name: who.join(", "), done: true, ..Default::default() }, Vec::new())
                })
            }
            "hubs" => {
                let now = uptime::wall_ms().max(0) as u64;
                live.mesh
                    .write(|set, k| writers::set_hubs(set, k, &h.hubs, now))
                    .map(|_| control::reply(Header::default(), Vec::new()))
            }
            "incoming" => self.live_incoming(live, &h.value),
            control::op::KEY_LEVEL => self.live_key_level(live, &h.value),
            control::op::MAKE_ADMIN => self.live_make_admin(live, h),
            control::op::RECOVER => self.live_recover(live, h, &m.payload),
            control::op::LEAVE => self.live_leave(live),
            control::op::NEW => Err(Error::msg("this device is already in a group; cbb status shows it")),
            "away" if h.name == "relay" => self.live_relay(live, h),
            "away" if matches!(h.name.as_str(), "" | "on" | "off" | "hub") && h.device.is_empty() => {
                self.live_away(live, h)
            }
            op if !MOVING.contains(&op) => return None,
            op => Err(not_yet(&format!("the operation {op:?}"))),
        };
        Some(res)
    }

    /// cbb global, cbb global on and cbb global off on this device, on the
    /// records of 0.6: sync away from home turned on sends `tunnel` to the
    /// hubs connected (`live::away`); the reply shows where it stands.
    fn live_away(&self, live: &Live, h: &Header) -> Result<Message> {
        let away = live.away().ok_or_else(|| Error::msg("sync away from home did not start on this device"))?;
        match h.name.as_str() {
            "on" if !h.consent => {
                return Err(Error::msg(
                    "this device keeps its keys in files, so sync away from home needs your consent; run cbb global on and read what it says",
                ));
            }
            "on" => {
                away.turn_on()?;
                live.tunnel_to_hubs();
            }
            "off" => live.away_off(Duration::ZERO)?,
            // The records must make this device a hub: an admin key, or the
            // root's hubs record (cbb global hubs).
            "hub" if !live.mesh.may_be_hub(&live.mesh.device()) => {
                return Err(Error::msg(
                    "the group's records do not make this device a hub; the root names its hubs with cbb global hubs",
                ));
            }
            "hub" => {
                away.make_hub(h)?;
            }
            _ => {}
        }
        let status = Status { away: away_status(live), ..Default::default() };
        Ok(control::reply(Header { status: Some(status), ..Default::default() }, Vec::new()))
    }

    /// cbb paste: the local clipboard's text in a mode that takes the
    /// group's copies, the group's current text in one that does not.
    fn live_paste(&self, live: &Live) -> Result<Message> {
        live.refuse_forward_only()?;
        let receives = live.board.mode().receives();
        let got = if receives {
            live.board.local().map(|(t, k, _)| (t, k))
        } else {
            live.board.current().and_then(|c| {
                let kind = if c.content.is_secret() { Kind::Secret } else { Kind::Text };
                c.content.text.filter(|t| !t.is_empty()).map(|t| (t, kind))
            })
        };
        let Some((text, kind)) = got else {
            let media = if receives {
                live.board.local_media().is_some()
            } else {
                live.board.current().is_some_and(|c| c.content.manifest.is_some())
            };
            return Err(Error::msg(if media {
                "the clipboard holds images or files without a text; cbb paste -o DIR saves them"
            } else {
                "the clipboard is empty"
            }));
        };
        Ok(control::reply(Header { kind: kind_name(kind).into(), ..Default::default() }, text.into_bytes()))
    }

    /// The tiles to draw, and the user's change of their order.
    fn live_view(&self, live: &Live, h: &Header) -> Result<Message> {
        let op = match (&*h.op, &h.arrange) {
            ("arrange", Some(v)) => Some(
                serde_json::from_value::<cbb_core::arrange::Op>(v.clone())
                    .map_err(|e| Error::msg(format!("arrange: the change does not read: {e}")))?,
            ),
            ("arrange", None) => return Err(Error::msg("arrange: which change?")),
            _ => None,
        };
        let view = self.tiles.view(&live.tag(), self.live_devices(live), op.as_ref())?;
        let view = crate::view::View { warnings: self.live_status(live).why, ..view };
        let view = serde_json::to_value(view).context("cannot encode the view")?;
        Ok(control::reply(Header { view: Some(view), ..Default::default() }, Vec::new()))
    }

    /// cbb sync on or off, on this device.
    fn live_sync(&self, live: &Live, h: &Header) -> Result<Message> {
        let on = h.on.ok_or_else(|| Error::msg("sync needs on, true or false"))?;
        if on && h.for_ms != 0 {
            return Err(Error::msg("a time goes only with cbb sync off"));
        }
        crate::sync::set(&self.state_dir, &live.board, on, h.for_ms)?;
        (self.log)(&crate::sync::line(&live.board));
        self.live_hello(live);
        Ok(self.live_standing(live))
    }

    /// cbb mute and cbb unmute, which name a device: this one is muted at
    /// once; another gets a command, which is not on 0.6 yet.
    fn live_mute_op(&self, live: &Live, h: &Header) -> Result<Message> {
        if h.device.is_empty() {
            return Err(Error::msg(
                "cbb mute and cbb unmute name a device with -on, as an admin; cbb sync off turns this device's own sync off",
            ));
        }
        // Another device gets a command (orders.rs); this one mutes here.
        let me = live.mesh.device();
        let on = h.op == "mute";
        let until = crate::mute::until(h.for_ms)?;
        let me = id_text(&me);
        // A mute an admin set on this device only an admin ends, after a
        // restart too (mute.json keeps who set it).
        let by = crate::mute::by(&self.state_dir, &live.board)?;
        if !on && !by.is_empty() && by != me && writers::signer(live.mesh.own(), &live.mesh.state()).is_none() {
            return Err(Error::msg(MUTE_NOT_ADMIN));
        }
        let saved =
            if on { crate::mute::kept_by(&crate::mute::by(&self.state_dir, &live.board)?, &me) } else { me.clone() };
        self.live_mute(live, on, until, &saved)?;
        Ok(control::reply(Header::default(), Vec::new()))
    }

    /// cbb keys: the group's key level, on its root, which its own keys
    /// must meet; the answer names the admins and hubs below it, which
    /// stay until the user removes them.
    fn live_key_level(&self, live: &Live, value: &str) -> Result<Message> {
        use cbb_core::records::body::{LEVEL_FILES, LEVEL_HARDWARE, LEVEL_PROVEN};
        let level = match value {
            "proven" => LEVEL_PROVEN,
            "hardware" => LEVEL_HARDWARE,
            "files" => LEVEL_FILES,
            _ => return Err(Error::msg("the key level is proven, hardware or files")),
        };
        let own = live.mesh.own();
        let root_store = match own.root.as_ref().and_then(|k| k.held()) {
            Some(_) => "hardware",
            None => "file",
        };
        crate::admin::level_allows(value, root_store, "this device, the group's root,", "", true)?;
        let now = uptime::wall_ms().max(0) as u64;
        // The default, hardware, is written as no level at all (format 4.5).
        let kept = if level == LEVEL_HARDWARE { 0 } else { level };
        live.mesh.write(|set, k| writers::set_settings(set, k, |s| s.key_level = kept, now))?;
        (self.log)(&format!("cbb: the group's key level is {value} now"));
        let st = live.mesh.state();
        let me = live.mesh.device();
        let below = self
            .live_devices(live)
            .into_iter()
            .filter(|d| d.id != id_text(&me))
            .filter(|d| d.admin || st.hubs.iter().any(|h| id_text(h) == d.id))
            .filter(|d| crate::admin::level_allows(value, &d.store, &d.name, "", true).is_err())
            .map(|d| d.name)
            .collect();
        Ok(control::reply(Header { below, done: true, ..Default::default() }, Vec::new()))
    }

    /// cbb global relay: the group's own relay, which the root signs in the
    /// group's settings (format 4.5, field 15; D-121), so that every device
    /// takes it from there and shows it a face (`faces::group_servers`).
    /// The relays given (`relay` and `relays`) take the place of those the
    /// settings named; `default`, the project's relay, leaves the group
    /// with the project's alone. The answer's `relays` names them. Only the
    /// root sets them, an admin as well as a member is told so.
    fn live_relay(&self, live: &Live, h: &Header) -> Result<Message> {
        let off = h.relay == "off" && h.relays.is_empty();
        if !h.consent && !off {
            return Err(Error::msg(
                "a relay learns which devices of the group talk, when and how much, and their addresses; run cbb global relay and read what it says",
            ));
        }
        let given: Vec<(String, String)> = std::iter::once((h.relay.clone(), h.relay_key.clone()))
            .chain(h.relays.iter().map(|r| {
                let (a, k) = r.split_once(' ').unwrap_or((r, ""));
                (a.to_string(), k.to_string())
            }))
            .collect();
        let relays = live.set_relays(None, if off { &[] } else { &given })?;
        let endpoints: Vec<String> = relays.into_iter().map(|r| r.endpoint).collect();
        (self.log)(&if endpoints.is_empty() {
            "cbb: the group meets at no relay now".to_string()
        } else {
            format!("cbb: the group's relays are {} now", endpoints.join(", "))
        });
        Ok(control::reply(Header { relays: endpoints, done: true, ..Default::default() }, Vec::new()))
    }

    /// cbb admin: makes a device an admin, on the group's root, with the
    /// admin key it offered when it paired with the root (offered.rs).
    fn live_make_admin(&self, live: &Live, h: &Header) -> Result<Message> {
        use cbb_core::records::body::{CAP_ADMIN, ROLE_PHONE, STORE_ROOTLESS};
        let st = live.mesh.state();
        let d = writers::find(&st, &h.device)?.clone();
        if d.id == live.mesh.device() {
            return Err(Error::msg("this device is the group's root, which is more than an admin"));
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
        let Some(point) = crate::offered::get(&self.state_dir, &id_text(&d.id))? else {
            return Err(Error::msg(format!(
                "{} offered this device no admin key when it joined (another admin admitted it, or it cannot be one then): pair this device with the root to make it an admin",
                d.name
            )));
        };
        let shown = self.live_devices(live).into_iter().find(|x| x.id == id_text(&d.id));
        let store = shown.map(|x| x.store).unwrap_or_default();
        let level = self.live_status(live).key_level;
        crate::admin::level_allows(
            &level,
            &store,
            &d.name,
            &format!("run cbb admin -allow-file-key {}", h.device),
            h.allow_file_key,
        )?;
        let now = uptime::wall_ms().max(0) as u64;
        let (d, _) = live.mesh.write(|set, k| writers::make_admin(set, k, &h.device, &point, now))?;
        (self.log)(&format!("cbb: made {} ({}) an admin of the group", d.name, id_text(&d.id)));
        Ok(control::reply(Header { name: d.name, done: true, ..Default::default() }, Vec::new()))
    }

    /// cbb recovery: this device becomes the group's root with the
    /// recovery key typed from the sheet (rule 33). It makes a new root key,
    /// writes the change of root with both halves of the recovery key, and
    /// restarts, so that the member signs with the new key; the recovery
    /// key is not kept.
    fn live_recover(&self, live: &Live, h: &Header, payload: &[u8]) -> Result<Message> {
        let st = live.mesh.state();
        let own = live.mesh.own();
        // The records name it the root as soon as a recovery wrote them,
        // before the restart gives it the new root key.
        if st.root_device == Some(live.mesh.device())
            || own
                .root
                .as_ref()
                .is_some_and(|k| st.roots.last() == Some(&cbb_core::records::Key::es256(k.public()).hash()))
        {
            return Err(Error::msg("this device is the group's root already"));
        }
        let text = Zeroizing::new(String::from_utf8_lossy(payload).into_owned());
        let set = live.mesh.set();
        let recovery = set.lock().unwrap_or_else(std::sync::PoisonError::into_inner).recovery().clone();
        // The secret from the sheet, or opened on the YubiKey with its PIN
        // (protocol.md, "The recovery key on a YubiKey (0.6)").
        let secret = if h.name == "yubikey" {
            let secret = crate::piv::recovery::open_one(text.trim())?;
            cbb_core::sheet::yubikey::check(&secret, &recovery).map_err(|r| Error::msg(r.message()))?;
            secret
        } else {
            let read = cbb_core::sheet::read(&text).map_err(|r| Error::msg(r.message()))?;
            cbb_core::sheet::check(&read, &st.group, &recovery).map_err(|r| Error::msg(r.message()))?;
            read.secret
        };
        let (k1, k2) = cbb_core::records::pq::recovery_keys(&secret)
            .map_err(|e| e.context("cannot make the recovery key from the sheet"))?;
        let pkcs8 = Zeroizing::new(
            p256::ecdsa::SigningKey::from(k1)
                .to_pkcs8_der()
                .map_err(|_| Error::msg("cannot encode the recovery key"))?
                .as_bytes()
                .to_vec(),
        );
        let k1 = cbb_core::identity::FileKey::new(&pkcs8)?;
        // Who does not stay: by name or ID, never this device.
        let mut leave_out = Vec::new();
        for name in &h.leave {
            let d = writers::find(&st, name)?;
            if d.id == live.mesh.device() {
                return Err(Error::msg("this device becomes the root: it stays in the group"));
            }
            leave_out.extend(writers::keys_of(d));
        }
        let mut own = Own::load(&self.state_dir)?;
        let root = own.make(&self.state_dir, crate::own::Which::Root)?;
        let now = uptime::wall_ms().max(0) as u64;
        {
            let mut set = set.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            writers::recover(&mut set, &k1, &k2, &*root, &live.mesh.device(), &leave_out, now)?;
        }
        live.mesh.changed()?;
        let left = if h.leave.is_empty() {
            "every device stays (cbb remove takes out a lost one)".to_string()
        } else {
            format!("these left the group: {}", h.leave.join(", "))
        };
        (self.log)(&format!(
            "cbb: this device is the group's root now, by the group's recovery key; {left}; it restarts to sign with its new root key"
        ));
        std::thread::spawn(|| {
            std::thread::sleep(RESTART_AFTER);
            super::RESTART.store(true, Ordering::SeqCst);
            STOP.store(true, Ordering::SeqCst);
        });
        Ok(control::reply(Header { done: true, ..Default::default() }, Vec::new()))
    }

    /// cbb incoming: how long a copy from another device stays live.
    fn live_incoming(&self, live: &Live, value: &str) -> Result<Message> {
        let ms = crate::go_duration_ms(value.trim())
            .and_then(|ms| u64::try_from(ms).ok())
            .filter(|ms| (MIN_INCOMING_MS..=MAX_INCOMING_MS).contains(ms))
            .ok_or_else(|| Error::msg("how long an incoming copy stays live is a duration from 5s to 1h, as 1m"))?;
        let now = uptime::wall_ms().max(0) as u64;
        live.mesh.write(|set, k| writers::set_incoming(set, k, ms, now))?;
        (self.log)(&format!(
            "cbb: a copy from another device now stays live for {} after it arrives",
            crate::cli::go_duration(ms as i64)
        ));
        Ok(control::reply(Header::default(), Vec::new()))
    }

    /// cbb leave: the member stops, the group's files and this device's
    /// keys go, and the service starts again in no group. The group's root
    /// leaves only alone.
    fn live_leave(&self, live: &Live) -> Result<Message> {
        let st = live.mesh.state();
        let me = live.mesh.device();
        if st.root_device == Some(me) {
            let others: Vec<String> = st.devices.iter().filter(|d| d.id != me).map(|d| d.name.clone()).collect();
            if !others.is_empty() {
                return Err(Error::msg(format!(
                    "this device is the group's root, and the group has other devices ({}): remove them first",
                    others.join(", ")
                )));
            }
        }
        live.close();
        let res = crate::leave::leave_group(&self.state_dir);
        match &res {
            Ok(()) => (self.log)(
                "cbb: this device left its group: its keys and the group's files are deleted; it restarts in no group",
            ),
            Err(e) => (self.log)(&format!("cbb: {}", e.for_log())),
        }
        std::thread::spawn(|| {
            std::thread::sleep(RESTART_AFTER);
            LEFT.store(true, Ordering::SeqCst);
            STOP.store(true, Ordering::SeqCst);
        });
        res.map(|()| control::reply(Header::default(), Vec::new()))
    }
}

/// Closes a pairing window of the member of 0.6 when dropped.
struct LiveWindow<'a> {
    svc: &'a Service,
    live: Arc<Live>,
}

impl Drop for LiveWindow<'_> {
    fn drop(&mut self) {
        self.live.mesh.on_pair(None);
        self.live.set_window(None);
        *self.svc.pairing.lock().unwrap() = None;
    }
}

impl Service {
    /// cbb pair on the root or an admin of a group of 0.6: a home window on
    /// the member port for one device, for five minutes (docs/protocol.md,
    /// "Pairing in 0.6"). The answers: the window opened, with its six
    /// digits (`code`), its QR code's text (`invite`) and an address; a
    /// partial `refused` with why for each device that failed (a wrong
    /// code spends one of three tries); the device's name once it is in
    /// the group. The third failure closes the window.
    pub(super) fn live_pair_window(
        &self,
        live: &Arc<Live>,
        mut r: control::Reader<UnixStream>,
        out: &mut UnixStream,
    ) -> Result<()> {
        if writers::signer(live.mesh.own(), &live.mesh.state()).is_none() {
            return Err(Error::msg(NOT_ADMITTER));
        }
        // The client hanging up (Ctrl+C) closes the window.
        let hung = Arc::new(AtomicBool::new(false));
        {
            let hung = hung.clone();
            std::thread::spawn(move || {
                while let Ok(Some(_)) = r.read() {}
                hung.store(true, Ordering::SeqCst);
            });
        }
        {
            let mut slot = self.pairing.lock().unwrap();
            if slot.is_some() {
                return Err(Error::msg(
                    "a pairing window is already open: stop the cbb pair that opened it (Ctrl+C in its terminal), or wait until it closes, 5 minutes after it opened",
                ));
            }
            *slot = Some(Pairing::Live);
        }
        let _open = LiveWindow { svc: self, live: live.clone() };
        // The user opens a window where the group is.
        if let Some(n) = live.networks() {
            n.learn_all();
        }
        let now = crate::admitting::home_window_ms;
        let (mut open, digits) = crate::admitting::home_window(now(), crate::admitting::WINDOW_LIFETIME);
        let (tx, rx) = mpsc::sync_channel(1);
        live.mesh.on_pair(Some(Box::new(move |sock, s, x| {
            // One device at a time; another is dropped.
            let _ = tx.try_send((sock, s, x));
        })));
        live.set_window(Some(open.invitation.id));
        let port = *self.port.lock().unwrap();
        let addrs = port.map(crate::pair::qr_addresses).unwrap_or_default();
        // A computer with no home address still gives its link, for this
        // computer's own joiners; it shows no QR code (no `address`).
        let link_addrs = match (addrs.is_empty(), port) {
            (true, Some(p)) => vec![std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, p)).to_string()],
            _ => addrs.iter().take(cbb_core::join::invitation::MAX_WINDOW_ADDRS).cloned().collect(),
        };
        let link = cbb_core::join::invitation::WindowLink {
            addrs: link_addrs,
            fp: live.mesh.own().hash(),
            id: open.invitation.id,
            digits: digits.clone(),
        };
        let opened = Header {
            kind: crate::admit_cli::HOME_WINDOW.into(),
            expires: crate::admitting::WINDOW_LIFETIME.as_secs() as i64,
            address: addrs.first().cloned().unwrap_or_default(),
            code: digits,
            invite: if link.addrs.is_empty() { String::new() } else { link.text() },
            ..Default::default()
        };
        control::write(out, &control::partial(opened))?;
        // Five minutes of this device's running time, which a wall clock
        // set ahead does not move (docs/protocol.md, "Pairing in 0.6").
        let end = crate::uptime::now() + crate::admitting::WINDOW_LIFETIME;
        loop {
            if hung.load(Ordering::SeqCst) {
                (self.log)("cbb: the pairing window closed: its cbb pair ended");
                return Ok(());
            }
            let left = end.saturating_sub(crate::uptime::now());
            if left.is_zero() {
                return Err(Error::msg("the pairing window expired: no device paired within 5 minutes"));
            }
            let attempts = open.next_attempt;
            match rx.recv_timeout(left.min(Duration::from_secs(1))) {
                // A device that dials after the client hung up finds the
                // window closed.
                Ok(_) if hung.load(Ordering::SeqCst) => {}
                Ok((sock, s, x)) => match crate::admitting::at_home(&live.mesh, sock, s, x, &mut open) {
                    // A connection that ended before the device began an
                    // attempt (one that dialed before the window opened, or
                    // found another window's key here) tried nothing: it is
                    // logged, and the window is not told of a try.
                    Err(e) if open.next_attempt == attempts => {
                        (self.log)(&format!("cbb: a connection to the pairing window tried nothing: {}", e.for_log()));
                    }
                    Ok(info) => {
                        (self.log)(&format!("cbb: {} joined the group", info.name));
                        let done = Header { name: info.name, done: true, ..Default::default() };
                        return control::write(out, &control::reply(done, Vec::new()));
                    }
                    Err(e) => {
                        (self.log)(&format!("cbb: a device did not pair: {}", e.for_log()));
                        if let Err(closed) = open.may_use(cbb_core::join::invitation::Network::Home, now()) {
                            let why = match closed {
                                cbb_core::join::PairError::TooMany => {
                                    "the pairing window closed after three failed tries: run cbb pair again for a new code"
                                }
                                _ => "the pairing window closed",
                            };
                            return Err(e.context(why));
                        }
                        let tried = Header { refused: true, detail: e.for_log(), ..Default::default() };
                        control::write(out, &control::partial(tried))?;
                    }
                },
                Err(RecvTimeoutError::Timeout) if !STOP.load(Ordering::SeqCst) => {}
                Err(_) => return Err(Error::msg("the service is stopping")),
            }
        }
    }

    /// cbb invite on a hub of a group of 0.6, by its root or an admin: a
    /// remote invitation through this hub's tunnel (docs/protocol.md,
    /// section 12), for a computer, or a phone with `kind` "phone", valid
    /// for `expires` seconds (an hour when 0, a day at most). The answers:
    /// the invitation's text with its lifetime; for each device that proved
    /// its secret, a partial `joining` that the client answers (`answer`
    /// with `consent`) before anything is written, and a partial `refused`
    /// with why for each that failed; the device's name once it is in the
    /// group. A client that hangs up cancels it.
    pub(super) fn live_invite(
        &self,
        live: &Arc<Live>,
        m: &Message,
        r: control::Reader<UnixStream>,
        out: &mut UnixStream,
    ) -> Result<()> {
        use cbb_core::records::body::{ROLE_MEMBER, ROLE_PHONE};
        let h = &m.header;
        if writers::signer(live.mesh.own(), &live.mesh.state()).is_none() {
            return Err(Error::msg(NOT_ADMITTER));
        }
        // On this hub, unless another is named or this device serves as
        // none: then through a hub (docs/protocol.md, section 12).
        let named = match h.device.as_str() {
            "" => None,
            d => Some(writers::find(&live.mesh.state(), d)?.id),
        };
        let expires = match h.expires {
            n if n <= 0 => None,
            n => Some(Duration::from_secs(n as u64)),
        };
        let role = match h.kind.as_str() {
            "" | "computer" => ROLE_MEMBER,
            "phone" => ROLE_PHONE,
            k => return Err(Error::msg(format!("an invitation is for a computer or a phone, not {k:?}"))),
        };
        let mut o = live.open_invitation(named, role, expires)?;
        if let Some(hub) = o.through {
            (self.log)(&format!("cbb: the invitation goes through the hub {}", id_text(&hub)));
        }
        // However it ends, the guest goes, unless a device was admitted.
        let mut admitted = None;
        let lifetime = o.lifetime;
        let res = self.run_invite(&mut o.open, &o.pairs, lifetime, r, out, live, &mut admitted);
        live.invitation_ended(&o, admitted);
        res
    }

    /// The invitation's window: answers with its text, then takes its
    /// guest's pairing connections until a device is admitted (noted in
    /// admitted), the invitation ends, or the client hangs up.
    #[allow(clippy::too_many_arguments)]
    fn run_invite(
        &self,
        open: &mut cbb_core::join::invitation::Open,
        pairs: &mpsc::Receiver<crate::live::invite::Pair>,
        lifetime: Duration,
        mut r: control::Reader<UnixStream>,
        out: &mut UnixStream,
        live: &Arc<Live>,
        admitted: &mut Option<cbb_core::records::DeviceId>,
    ) -> Result<()> {
        use cbb_core::join::invitation::Network;
        let now = || crate::uptime::wall_ms().max(0) as u64;
        // The client's answers, and its hang-up.
        let (answers, asked) = mpsc::sync_channel::<bool>(1);
        let hung = Arc::new(AtomicBool::new(false));
        {
            let hung = hung.clone();
            std::thread::spawn(move || {
                while let Ok(Some(m)) = r.read() {
                    if m.header.op == "answer" {
                        let _ = answers.try_send(m.header.consent);
                    }
                }
                hung.store(true, Ordering::SeqCst);
            });
        }
        (self.log)(&format!("cbb: an invitation is open for {} minutes", lifetime.as_secs() / 60));
        let text = Header { invite: open.invitation.text(), expires: lifetime.as_secs() as i64, ..Default::default() };
        control::write(out, &control::partial(text))?;
        let end = Instant::now() + lifetime;
        loop {
            if hung.load(Ordering::SeqCst) {
                return Ok(());
            }
            let left = end.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(Error::msg("the invitation's time is over: no device joined with it"));
            }
            let (sock, s, x) = match pairs.recv_timeout(left.min(Duration::from_secs(1))) {
                Ok(p) => p,
                Err(RecvTimeoutError::Timeout) if !STOP.load(Ordering::SeqCst) => continue,
                Err(_) => return Err(Error::msg("the service is stopping")),
            };
            let mut device = None;
            let mut confirm = |a: &crate::admitting::Asked<'_>| {
                device = Some(a.device);
                let joining = control::Joining {
                    id: id_text(&a.device),
                    name: a.info.name.clone(),
                    os: cbb_core::format::print::os_name(a.info.os).to_string(),
                    fingerprint: a.fingerprint.clone(),
                };
                if control::write(out, &control::partial(Header { joining: Some(joining), ..Default::default() }))
                    .is_err()
                {
                    return false;
                }
                // Drops an answer left from before.
                while asked.try_recv().is_ok() {}
                let until = Instant::now() + crate::pair::CONFIRM_WAIT;
                while !hung.load(Ordering::SeqCst) && Instant::now() < until {
                    match asked.recv_timeout(Duration::from_millis(200)) {
                        Ok(yes) => return yes,
                        Err(RecvTimeoutError::Timeout) => {}
                        Err(RecvTimeoutError::Disconnected) => return false,
                    }
                }
                false
            };
            let way = crate::join::Way { open: &mut *open, network: Network::Guest };
            match crate::admitting::admit(&live.mesh, sock, s, x, way, &mut confirm) {
                Ok(info) => {
                    *admitted = device;
                    (self.log)(&format!("cbb: {} joined the group with an invitation", info.name));
                    let done = Header { name: info.name, done: true, ..Default::default() };
                    return control::write(out, &control::reply(done, Vec::new()));
                }
                Err(e) => {
                    (self.log)(&format!("cbb: a device did not join with the invitation: {}", e.for_log()));
                    if let Err(closed) = open.may_use(Network::Guest, now()) {
                        let why = match closed {
                            cbb_core::join::PairError::TooMany => {
                                "the invitation closed after three failed attempts: make a new one with cbb invite"
                            }
                            _ => "the invitation closed",
                        };
                        return Err(e.context(why));
                    }
                    let tried = Header { refused: true, detail: e.for_log(), ..Default::default() };
                    control::write(out, &control::partial(tried))?;
                }
            }
        }
    }

    /// cbb pair -code on a computer in no group: joins the group of 0.6 by
    /// its home window. `code` is the window's six digits, with the window
    /// found by mDNS (at `address` when given), or the window's QR code
    /// text, which names its addresses, ID and member key. Answers done;
    /// the service starts in the group it kept.
    pub(super) fn live_join(&self, m: &Message, _r: control::Reader<UnixStream>, out: &mut UnixStream) -> Result<()> {
        let h = &m.header;
        if in_group(&self.state_dir) || matches!(Identity::load(&self.state_dir), Ok(Some(_))) {
            return Err(Error::msg("this device is already in a group"));
        }
        let _one = self.creating.try_lock().map_err(|_| Error::msg("a join or a pairing is already running here"))?;
        // cbb pair's -name and -caps, when it gave them, else the service's.
        let name = if h.name.is_empty() { self.name.clone() } else { h.name.clone() };
        let caps = match &h.caps {
            Some(c) => crate::parse_caps(&c.join(","))?,
            None => self.caps.clone(),
        };
        let me = crate::joining::Me {
            name: &name,
            os: cbb_core::format::print::os_number(crate::admin::os_name()),
            caps: roster::caps_number(&caps),
        };
        // A remote invitation: through its guest tunnel to the hub, with
        // sync away from home on, which the user agreed to.
        if !h.invite.is_empty() {
            if !h.consent {
                return Err(Error::msg(
                    "a device that joins with an invitation syncs away from home, so it needs your consent; run cbb pair -invite and read what it says",
                ));
            }
            std::fs::create_dir_all(&self.state_dir)
                .map_err(|e| Error::with(format!("cannot make {}", self.state_dir.display()), e))?;
            let fp = Own::load(&self.state_dir)?.hash();
            let shown = Header {
                fingerprint: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, fp.0),
                ..Default::default()
            };
            control::write(out, &control::partial(shown))?;
            crate::live::invite::join(&self.state_dir, &me, &h.invite, self.log.clone())?;
            (self.log)(&format!("cbb: joined a group of 0.6 with an invitation as {name}"));
            return control::write(out, &control::reply(Header { done: true, ..Default::default() }, Vec::new()));
        }
        let at = if h.address.is_empty() { None } else { Some(crate::resolve(&h.address)?) };
        let (addrs, invitation, fp) = crate::joining::window_of(&h.code, at)?;
        let mut last = Error::msg("no address to dial");
        for a in addrs {
            match crate::joining::at_home(&self.state_dir, a, &me, invitation.clone(), fp) {
                Ok(_) => {
                    // The new member dials first the address it joined at.
                    *self.joined_at.lock().unwrap() = Some(a);
                    (self.log)(&format!("cbb: joined a group of 0.6 as {name}"));
                    return control::write(
                        out,
                        &control::reply(Header { done: true, ..Default::default() }, Vec::new()),
                    );
                }
                // Another address of the same window, only when this one
                // did not answer: once a session ran, it spent a try.
                Err(e) if e.message().starts_with("cannot reach") => last = e,
                Err(e) => return Err(e),
            }
        }
        Err(last)
    }
}

/// The group as `cbb relay -group` lists it: the root key and the two
/// halves of the recovery key, in hex, separated by colons (relayd's
/// Listed::parse reads it back).
fn relay_group(set: &cbb_core::records::RecordSet) -> String {
    let hex = crate::certs::hex;
    let r = set.recovery();
    format!("{}:{}:{}", hex(set.root().public()), hex(r.k1.public()), hex(r.k2.public()))
}

/// Sync away from home on a group of 0.6 for status.
fn away_status(live: &Live) -> Option<control::Away> {
    live.away_status()
}

#[cfg(test)]
mod tests;

/// The service's operations that need a group and have not moved to the
/// records of 0.6 yet; any other the service answers as ever (an unknown
/// one with why).
const MOVING: &[&str] = &["away"];

const NOT_ADMIN: &str =
    "only an admin can change the devices list: the group's root, an admin it made (cbb admin), or an admin phone";
const NOT_COMMANDER: &str = "only an admin pastes on another device, runs its actions or turns either off: the group's root, an admin it made (cbb admin), or an admin phone";
/// What a handover, a claim and a claim's delay answer on the records of
/// 0.6, where the root changes only with the group's recovery key (rule
/// 33; docs/decisions.md).
pub(super) const ROOT_BY_RECOVERY: &str = "the group's root changes only with its recovery key on the records of 0.6 (cbb recovery); a handover and a claim's delay are gone";

/// Why a frozen admin computer is refused what an admin does.
const FROZEN: &str = "another admin froze this computer's admin key: it changes nothing until the group's root or an admin phone unfreezes it";

/// Whether h writes the group's records, or commands another device
/// (other), as only an admin does.
fn writes(h: &Header, other: bool) -> bool {
    match h.op.as_str() {
        "rename" | "remove" | "freeze" | "thaw" | "resolve" | "hubs" => true,
        "incoming" => !h.value.is_empty(),
        "mute" | "unmute" | "sync" | "away" | "action_on" | "actions_off" | "paste_receive" | "paste_on" => other,
        _ => false,
    }
}

/// What cbb pair -qr answers on the records of 0.6: a device that waits
/// for the group to dial it is gone (D-119).
pub(crate) const LISTENING_JOINER_GONE: &str = "on the records of 0.6 no device waits for the group to dial it, so a QR code or a code from the new device admits nothing: open a pairing window here with cbb pair, and the new device dials it (cbb pair -code on a computer, the QR code of the window on a phone)";

/// Why a device that is no admin, or not the group's root, is refused.
pub(super) const NOT_ADMITTER: &str = "this device is in a group already (cbb status lists it); only the group's root or an admin adds devices, and this device is neither";

/// Why this device may not do what h asks, by the keys it holds: the
/// group's root key, an admin key, or neither. None when it may try.
fn refusal(live: &Live, h: &Header) -> Option<&'static str> {
    let st = live.mesh.state();
    let own = live.mesh.own();
    let root =
        own.root.as_ref().is_some_and(|k| st.roots.last() == Some(&cbb_core::records::Key::es256(k.public()).hash()));
    let admin = writers::signer(own, &st).is_some();
    // An admin key the records name, but frozen.
    let frozen = own.admin.as_ref().is_some_and(|k| {
        let h = cbb_core::records::Key::es256(k.public()).hash();
        st.devices.iter().any(|d| d.admin == Some(h) && d.frozen)
    });
    let other = !h.device.is_empty() && !self_named(live, &h.device);
    let why = match h.op.as_str() {
        "make_admin" if !root => {
            "only the group's root makes admins: run cbb admin on the computer that created the group, or use \"Make it an admin\" on the root phone"
        }
        "key_level" if !root => "only the group's root sets the key level",
        _ if !admin && frozen && writes(h, other) => FROZEN,
        "rename" | "remove" | "freeze" | "thaw" | "resolve" if !admin => NOT_ADMIN,
        "incoming" if !admin && !h.value.is_empty() => {
            "only the group's root or an admin sets how long an incoming copy stays live"
        }
        "hubs" if !admin => "only the group's root or an admin that may be a hub sets the main hubs",
        "mute" | "unmute" if !admin && other => MUTE_NOT_ADMIN,
        "sync" if !admin && other => {
            "only an admin turns another device's sync on or off: the group's root, an admin it made (cbb admin), or an admin phone"
        }
        "away" if !admin && other => {
            "only an admin turns sync away from home off on another device: the group's root, an admin it made (cbb admin), or an admin phone"
        }
        "action_on" | "actions_off" | "paste_receive" | "paste_on" if !admin && other => NOT_COMMANDER,
        _ => return None,
    };
    Some(why)
}

/// How long discovery has to find a device of the group before a device
/// that joined at an address dials it.
const DISCOVERY_MOMENT: Duration = Duration::from_secs(3);

/// Dials `addr`, where this device joined, while it has no connection to
/// the group, as the old member's keep_joined. `wait`, with mDNS: how long
/// discovery has to find a device of the group, and how long one it found
/// has to connect, before the dial.
fn keep_joined(
    live: std::sync::Weak<Live>,
    addr: std::net::SocketAddr,
    wait: Option<(Duration, Duration)>,
    log: Arc<dyn Fn(&str) + Send + Sync>,
) {
    const MIN: Duration = Duration::from_secs(1);
    const MAX: Duration = Duration::from_secs(30);
    let start = Instant::now();
    std::thread::spawn(move || {
        let mut backoff = MIN;
        while let Some(l) = live.upgrade() {
            if l.is_closed() {
                return;
            }
            let waits = wait.is_some_and(|(moment, grace)| {
                start.elapsed() < moment || (l.any_at_home() && start.elapsed() < grace)
            });
            if waits || !l.mesh.connected().is_empty() {
                drop(l);
                std::thread::sleep(MIN);
                continue;
            }
            let start = Instant::now();
            if let Err(e) = l.mesh.dial(addr, None) {
                log(&format!("cbb: connection at {addr}, where this device joined: {}", e.for_log()));
            }
            drop(l);
            if start.elapsed() > MAX {
                backoff = MIN;
            }
            std::thread::sleep(backoff);
            backoff = (backoff * 2).min(MAX);
        }
    });
}

/// Why a member that is no admin mutes no other device and ends no mute
/// of another's, nor its own on the control socket.
pub(super) const MUTE_NOT_ADMIN: &str = "only an admin mutes a device or ends its mute: the group's root, an admin it made (cbb admin), or an admin phone; cbb sync off turns this device's own sync off";

/// The operations the service answers without a group.
pub(super) fn needs_no_group(op: &str) -> bool {
    matches!(op, "version" | "config" | "keyboard" | "remote" | "bug" | "bug_allow" | "bug_cancel")
}

/// Whether target names this device.
fn self_named(live: &Live, target: &str) -> bool {
    writers::find(&live.mesh.state(), target).is_ok_and(|d| d.id == live.mesh.device())
}

/// Where this device's keys live, for its hello (docs/protocol.md, section
/// 17): `rootless` for an install without root, `file` while it holds the
/// group's root key (the CA key is a file) or its member key is in one,
/// else `hardware`.
fn own_store(own: &Own) -> u64 {
    use cbb_core::records::body::{STORE_FILE, STORE_HARDWARE, STORE_ROOTLESS};
    if crate::rootless::is() {
        STORE_ROOTLESS
    } else if own.root.is_none() && own.member.held().is_some() {
        STORE_HARDWARE
    } else {
        STORE_FILE
    }
}

/// The conflicts of the group's records, as `cbb status` shows them: the
/// kind, and the devices of the keys that signed them (the first bytes of
/// a key in hex when no device has it).
fn live_conflicts(st: &cbb_core::records::State) -> Vec<control::Conflict> {
    use cbb_core::records::eval::ConflictKind;
    st.conflicts
        .iter()
        .map(|c| control::Conflict {
            kind: match c.kind {
                ConflictKind::Admins => "admins",
                ConflictKind::Fork => "fork",
                ConflictKind::TwoHistories => "two_histories",
                ConflictKind::Admits => "admits",
                ConflictKind::Ids => "ids",
            }
            .into(),
            devices: c
                .signers
                .iter()
                .map(|k| {
                    st.devices
                        .iter()
                        .find(|d| d.key.hash() == *k || d.admin == Some(*k))
                        .or_else(|| {
                            (st.roots.last() == Some(k)).then(|| st.root_device.and_then(|r| st.device(&r))).flatten()
                        })
                        .map_or_else(|| crate::certs::hex(&k.0[..4]), |d| d.name.clone())
                })
                .collect(),
        })
        .collect()
}
