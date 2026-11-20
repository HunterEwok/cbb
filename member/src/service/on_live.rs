// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The service on the records of 0.6 (`live.rs`): a device whose group is
//! kept in `group.cbor` runs the member of 0.6 in place of the old one.
//! The clipboard (watchers, copy, paste), status, devices, sync, the mute
//! of this device, leaving, and the records an admin writes (remove,
//! rename, freeze, thaw, hubs, incoming) run here; every other operation
//! answers that it is not on the records of 0.6 yet (`live::not_yet`),
//! never a silent no-op, until its part moves over.

use super::*;

use crate::discovery::Peers as _;
use crate::live::{self, Live, not_yet};
use crate::own::Own;
use crate::roster::{self, id_text};
use crate::writers;
use cbb_core::records::body::{MAX_INCOMING_MS, MIN_INCOMING_MS};

/// How often this device's sealing keys are checked for a new epoch.
const ROTATE_EVERY: Duration = Duration::from_secs(3600);

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
        discovery::start(live.clone(), tag, cfg.peers.clone(), cfg.mdns, port, log.clone());
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
    fn live_hello(&self, live: &Live) {
        let muted = live.board.mute_left();
        live.mesh.set_hello(crate::hello::Hello {
            name: self.name.clone(),
            os: cbb_core::format::print::os_number(crate::admin::os_name()),
            mode: if live.board.mode() == Mode::Own { 2 } else { 1 },
            muted: muted.is_some(),
            muted_for_ms: muted.map_or(0, |l| u64::try_from(l).unwrap_or(0)),
            device: crate::hello::Device { version: VERSION.into(), ..Default::default() },
            features: crate::hello::FEATURE_MEDIA,
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
            incoming_ms: st.incoming_ms.map_or(cbb_core::authority::DEFAULT_INCOMING, |ms| ms as i64),
            unreached: live.unreached(),
            port: self.port.lock().unwrap().map_or(0, i64::from),
            quiet: live.networks().map(|n| n.unknown()).unwrap_or_default(),
            bug: self.bugs.waiting(),
            ..Default::default()
        };
        Status { why: crate::why::reasons(&status, &devices, uptime::wall_ms()), ..status }
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
        roster::devices(&live.mesh.state(), &me, &live.mesh.hellos(), uptime::wall_ms())
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
    fn live_mute(&self, live: &Live, on: bool, until: i64, by: &str) -> Result<()> {
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
    fn live_standing(&self, live: &Live) -> Message {
        let standing = crate::sync::standing(&live.board);
        control::reply(Header { standing: Some(standing), done: true, ..Default::default() }, Vec::new())
    }

    /// A request on the records of 0.6: its answer, or None for one that
    /// needs no group, which the service answers as ever.
    pub(super) fn live_request(&self, live: &Arc<Live>, m: &Message) -> Option<Result<Message>> {
        let h = &m.header;
        let res = match h.op.as_str() {
            "version" | "config" | "keyboard" | "remote" | "bug" | "bug_allow" | "bug_cancel" | "paste_receive" => {
                return None;
            }
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
            "remove" => self.live_write(live, |set, k, now| writers::remove(set, k, &h.device, now)),
            "rename" => self.live_write(live, |set, k, now| writers::rename(set, k, &h.device, &h.name, now)),
            "freeze" | "thaw" => {
                let on = h.op == "freeze";
                self.live_write(live, |set, k, now| writers::freeze(set, k, &h.device, on, now))
            }
            "hubs" => {
                let now = uptime::wall_ms().max(0) as u64;
                live.mesh
                    .write(|set, k| writers::set_hubs(set, k, &h.hubs, now))
                    .map(|_| control::reply(Header::default(), Vec::new()))
            }
            "incoming" => self.live_incoming(live, &h.value),
            control::op::LEAVE => self.live_leave(live),
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
        if !h.device.is_empty() {
            return Err(not_yet("turning another device's sync on or off"));
        }
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
        let me = live.mesh.device();
        let d = writers::find(&live.mesh.state(), &h.device)?.clone();
        if d.id != me {
            return Err(not_yet("muting another device"));
        }
        let on = h.op == "mute";
        let until = crate::mute::until(h.for_ms)?;
        let me = id_text(&me);
        let saved =
            if on { crate::mute::kept_by(&crate::mute::by(&self.state_dir, &live.board)?, &me) } else { me.clone() };
        self.live_mute(live, on, until, &saved)?;
        Ok(control::reply(Header::default(), Vec::new()))
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
                    "this device is the group's root, and the group has other devices ({}): remove them first, or hand the group over to an admin (not on the records of 0.6 yet)",
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

#[cfg(test)]
mod tests;
