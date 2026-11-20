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

mod orders;

/// Whether the device's group is kept on the records of 0.6.
pub(super) fn in_group(dir: &Path) -> bool {
    dir.join(crate::set::FILE_NAME).exists()
}

/// The clipboard side of the member that runs: the old member's engine or
/// the member of 0.6, for what both do the same.
pub(super) enum Group {
    Old(Arc<Node>),
    Live(Arc<Live>),
}

impl Group {
    /// The text this device's own clipboard holds, as the member knows it.
    pub(super) fn local_text(&self) -> Option<String> {
        match self {
            Group::Old(n) => n.engine.local().map(|(t, ..)| t),
            Group::Live(l) => l.board.local().map(|(t, ..)| t),
        }
    }

    /// A watcher says what its clipboard holds.
    pub(super) fn clipboard_is(&self, text: &str, kind: Kind) {
        match self {
            Group::Old(n) => n.engine.clipboard_is(text, kind),
            Group::Live(l) => l.board.clipboard_is(text, kind),
        }
    }

    /// A watcher saw the clipboard change.
    pub(super) fn copied(&self, text: &str, kind: Kind, via: Via) -> Result<()> {
        match self {
            Group::Old(n) => n.copied(text, kind, via),
            Group::Live(l) => l.copied(text, kind, via),
        }
    }
}

impl Service {
    /// The member of 0.6, once it runs.
    pub(super) fn live(&self) -> Option<Arc<Live>> {
        self.live.read().unwrap().clone()
    }

    /// The clipboard side of the member that runs.
    pub(super) fn group(&self) -> Result<Group> {
        match self.live() {
            Some(l) => Ok(Group::Live(l)),
            None => self.node().map(Group::Old),
        }
    }

    /// Starts the member of 0.6 on the group in the state directory: it
    /// finds and dials its members, listens on the member port and passes
    /// the copies to write to the watchers.
    pub(super) fn start_live(self: &Arc<Self>, cfg: &Config) -> Result<Arc<Live>> {
        let log = self.log.clone();
        let own = Own::load(&cfg.state_dir)?;
        let live = Live::open(&cfg.state_dir, own, log.clone())?;
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
        live.set_networks(crate::networks::Networks::load(&cfg.state_dir, true, log.clone()));
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
        // The address this device joined at, given by hand (an SSH forward,
        // a VPN address that mDNS does not reach), is dialed too.
        let mut peers = cfg.peers.clone();
        peers.extend(self.joined_at.lock().unwrap().take());
        discovery::start(live.clone(), tag, peers, cfg.mdns, port, log.clone());
        {
            let (l, log) = (live.clone(), log.clone());
            std::thread::spawn(move || {
                while !l.is_closed() && !STOP.load(Ordering::SeqCst) {
                    wait_unless_stopping(ROTATE_EVERY);
                    if let Err(e) = l.mesh.rotate() {
                        log(&format!("cbb: {}", e.for_log()));
                    }
                }
            });
        }
        Ok(live)
    }

    /// What this device says of itself in its hellos: its name, system,
    /// version, mode and mute.
    pub(super) fn live_hello(&self, live: &Live) {
        let muted = live.board.mute_left();
        live.mesh.set_hello(crate::hello::Hello {
            name: self.name.clone(),
            os: cbb_core::format::print::os_number(crate::admin::os_name()),
            mode: if live.board.mode() == Mode::Own { 2 } else { 1 },
            muted: muted.is_some(),
            muted_for_ms: muted.map_or(0, |l| u64::try_from(l).unwrap_or(0)),
            device: crate::hello::Device { version: VERSION.into(), ..Default::default() },
            features: crate::hello::FEATURE_MEDIA,
            actions: actions::load(&self.state_dir).map(|s| s.on()).unwrap_or_default(),
            ..Default::default()
        });
    }

    /// A copy from the group to write: to the watchers as a write. Images
    /// and files are not fetched on the records of 0.6 yet: their text
    /// goes, and the log says why the rest does not.
    fn deliver_live(self: &Arc<Self>, w: live::Write) {
        let seq = {
            let mut l = self.latest.lock().unwrap();
            *l += 1;
            *l
        };
        let media = w.media.is_some();
        if media {
            (self.log)(&format!("cbb: a copy from the group: {}", not_yet("writing its images or files").for_log()));
            if w.text.is_empty() {
                return;
            }
        }
        self.deliver(WriteReq {
            id: crate::certs::hex(&w.id),
            text: w.text,
            media: None,
            kind: if media { Kind::Text } else { w.kind },
            via: Via::Copy,
            seq,
            ttl: w.ttl,
            event: None,
        });
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
                ..Default::default()
            })
            .collect();
        let muted = live.board.mute_left();
        let status = Status {
            device: id_text(&me),
            group: live.tag(),
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
        roster::devices(
            &live.mesh.set().lock().unwrap_or_else(std::sync::PoisonError::into_inner),
            &me,
            &live.mesh.hellos(),
            uptime::wall_ms(),
        )
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
                // removed.
                let st = live.mesh.state();
                if let Ok(d) = writers::find(&st, &h.device)
                    && d.admin.is_none()
                    && Some(d.id) != st.root_device
                {
                    return Some(Err(Error::msg(format!(
                        "{} is no admin computer; only those are frozen, and an ordinary device is removed with cbb remove",
                        d.name
                    ))));
                }
                let on = h.op == "freeze";
                self.live_write(live, |set, k, now| writers::freeze(set, k, &h.device, on, now))
            }
            "resolve" => {
                if writers::two_histories(&live.mesh.state()).is_empty() {
                    Err(Error::msg("no key of the group signed two histories"))
                } else {
                    Err(not_yet("voiding two histories"))
                }
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
            op if !MOVING.contains(&op) => return None,
            op => Err(not_yet(&format!("the operation {op:?}"))),
        };
        Some(res)
    }

    /// cbb paste: the local clipboard's text in a mode that takes the
    /// group's copies, the group's current text in one that does not.
    fn live_paste(&self, live: &Live) -> Result<Message> {
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
        if own.root.as_ref().is_some_and(|k| st.roots.last() == Some(&cbb_core::records::Key::es256(k.public()).hash()))
        {
            return Err(Error::msg("this device is the group's root already"));
        }
        if h.name == "yubikey" {
            return Err(not_yet("a recovery key on a YubiKey"));
        }
        let text = Zeroizing::new(String::from_utf8_lossy(payload).into_owned());
        let read = cbb_core::sheet::read(&text).map_err(|r| Error::msg(r.message()))?;
        let set = live.mesh.set();
        let recovery = set.lock().unwrap_or_else(std::sync::PoisonError::into_inner).recovery().clone();
        cbb_core::sheet::check(&read, &st.group, &recovery).map_err(|r| Error::msg(r.message()))?;
        let (k1, k2) = cbb_core::records::pq::recovery_keys(&read.secret)
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

/// Asks the person at cbb pair whether the other device shows the same
/// code: the code goes to the client, and its answer (`answer`, with
/// consent for yes) comes back; a client that hangs up says no.
fn ask_client(out: &mut UnixStream, r: &mut control::Reader<UnixStream>, code: &str) -> bool {
    let h = Header { code: code.to_string(), ..Default::default() };
    if control::write(out, &control::partial(h)).is_err() {
        return false;
    }
    matches!(r.read(), Ok(Some(m)) if m.header.op == "answer" && m.header.consent)
}

/// Closes a pairing window of the member of 0.6 when dropped.
struct LiveWindow<'a> {
    svc: &'a Service,
    live: Arc<Live>,
}

impl Drop for LiveWindow<'_> {
    fn drop(&mut self) {
        self.live.mesh.on_pair(None);
        self.live.set_window_open(false);
        *self.svc.pairing.lock().unwrap() = None;
    }
}

impl Service {
    /// cbb pair on the root or an admin of a group of 0.6: a pairing window
    /// on the member port for one device, for five minutes. The answers:
    /// the window opened; the code to compare once a device pairs, which
    /// the client answers; the device's name once it is in the group.
    pub(super) fn live_pair_window(
        &self,
        live: &Arc<Live>,
        mut r: control::Reader<UnixStream>,
        out: &mut UnixStream,
    ) -> Result<()> {
        if writers::signer(live.mesh.own(), &live.mesh.state()).is_none() {
            return Err(Error::msg(NOT_ADMITTER));
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
        let (tx, rx) = mpsc::sync_channel(1);
        live.mesh.on_pair(Some(Box::new(move |sock, s, x| {
            // One device at a time; another is dropped.
            let _ = tx.try_send((sock, s, x));
        })));
        live.set_window_open(true);
        let port = *self.port.lock().unwrap();
        let address = port.and_then(|p| crate::pair::qr_addresses(p).into_iter().next()).unwrap_or_default();
        let opened = Header { expires: window::LIFETIME.as_secs() as i64, address, ..Default::default() };
        control::write(out, &control::partial(opened))?;
        let end = Instant::now() + window::LIFETIME;
        loop {
            let left = end.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(Error::msg("the pairing window closed: no device paired within 5 minutes"));
            }
            match rx.recv_timeout(left.min(Duration::from_secs(1))) {
                Ok((sock, s, x)) => {
                    let info =
                        crate::admitting::at_home(&live.mesh, sock, s, x, &mut |code| ask_client(out, &mut r, code))?;
                    (self.log)(&format!("cbb: {} joined the group", info.name));
                    let done = Header { name: info.name, done: true, ..Default::default() };
                    return control::write(out, &control::reply(done, Vec::new()));
                }
                Err(RecvTimeoutError::Timeout) if !STOP.load(Ordering::SeqCst) => {}
                Err(_) => return Err(Error::msg("the service is stopping")),
            }
        }
    }

    /// cbb pair -code on a computer in no group: joins the group of 0.6 whose
    /// pairing window mDNS finds, or at the address given. The answers: the
    /// code to compare, which the client answers, then done; the service
    /// starts in the group it kept.
    pub(super) fn live_join(
        &self,
        m: &Message,
        mut r: control::Reader<UnixStream>,
        out: &mut UnixStream,
    ) -> Result<()> {
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
        let addrs = if h.address.is_empty() {
            crate::discovery::find_pairing(crate::discovery::PAIRING_BROWSE)?
        } else {
            let a = crate::resolve(&h.address)?;
            *self.joined_at.lock().unwrap() = Some(a);
            vec![a]
        };
        let mut last = Error::msg("no address to dial");
        for a in addrs {
            match crate::joining::at_home(&self.state_dir, a, &me, &mut |code| ask_client(out, &mut r, code)) {
                Ok(_) => {
                    (self.log)(&format!("cbb: joined a group of 0.6 as {name}"));
                    return control::write(
                        out,
                        &control::reply(Header { done: true, ..Default::default() }, Vec::new()),
                    );
                }
                // Another address of the same window, only when this one
                // did not answer: once a session ran, the codes were shown.
                Err(e) if e.message().starts_with("cannot reach") => last = e,
                Err(e) => return Err(e),
            }
        }
        Err(last)
    }
}

#[cfg(test)]
mod tests;

/// The service's operations that need a group and have not moved to the
/// records of 0.6 yet; any other the service answers as ever (an unknown
/// one with why).
const MOVING: &[&str] =
    &["away", "entries", "entries_get", "release", "release_want", "release_held", "update_way", "invite"];

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
pub(super) const LISTENING_JOINER_GONE: &str = "on the records of 0.6 no device waits for the group to dial it, so a QR code or a code from the new device admits nothing: open a pairing window here with cbb pair, and the new device dials it (cbb pair -code on a computer, the QR code of the window on a phone)";

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
        "mute" | "unmute" if !admin && other => {
            "only an admin mutes a device or ends its mute: the group's root, an admin it made (cbb admin), or an admin phone; cbb sync off turns this device's own sync off"
        }
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

/// The operations the service answers without a group.
pub(super) fn needs_no_group(op: &str) -> bool {
    matches!(op, "version" | "config" | "keyboard" | "remote" | "bug" | "bug_allow" | "bug_cancel")
}

/// Whether target names this device.
fn self_named(live: &Live, target: &str) -> bool {
    writers::find(&live.mesh.state(), target).is_ok_and(|d| d.id == live.mesh.device())
}
