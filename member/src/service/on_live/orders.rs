// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Commands on the records of 0.6 (format section 6, `crate::orders`):
//! those this device's root or admin key sends to another device (mute,
//! sync, remote paste, quick actions and turning them off), and those it
//! takes and carries out, with the same checks of its user's switches as
//! on the old records. A hub, away-off or a small device's own command
//! answers that it is not on the records of 0.6 yet.

use super::*;

use crate::commands::{Taken, refuse};
use crate::orders::{Order, Way, What};
use cbb_core::records::{KeyHash, State};

/// Who signed a command, as the records show it: the device ID text and
/// name, whether it is the group's root key, and its device's role and
/// key store.
struct Signed {
    id: String,
    name: String,
    root: bool,
    role: String,
    store: String,
}

fn signed(st: &State, key: &KeyHash) -> Signed {
    let root = st.roots.last() == Some(key);
    let d = st
        .devices
        .iter()
        .find(|d| d.key.hash() == *key || d.admin.as_ref() == Some(key))
        .or_else(|| if root { st.root_device.and_then(|r| st.devices.iter().find(|d| d.id == r)) } else { None });
    let devs = roster::devices(st, &roster::Me::default(), &HashMap::new(), 0);
    let shown = d.and_then(|d| devs.iter().find(|x| x.id == id_text(&d.id)));
    Signed {
        id: d.map(|d| id_text(&d.id)).unwrap_or_default(),
        name: d.map(|d| d.name.clone()).unwrap_or_default(),
        root,
        role: shown.map(|x| x.role.clone()).unwrap_or_default(),
        store: shown.map(|x| x.store.clone()).unwrap_or_default(),
    }
}

/// Whether the key still signs for the group: the root's, or a device's
/// that is not frozen.
fn still_signs(st: &State, key: &KeyHash) -> bool {
    st.roots.last() == Some(key)
        || st.devices.iter().any(|d| !d.frozen && (d.key.hash() == *key || d.admin.as_ref() == Some(key)))
}

/// A command's result as an error for the one who sent it: done is Ok.
fn outcome(status: &str, reason: &str) -> Result<()> {
    match status {
        "done" => Ok(()),
        "refused" => Err(refuse(reason.to_string())),
        _ => Err(Error::msg(reason.to_string())),
    }
}

impl Service {
    /// Carries out a command another member sent this device, which the
    /// core took: an error refuses or fails it, with why.
    pub(super) fn live_command(&self, live: &Live, t: &Taken) -> Result<()> {
        let st = live.mesh.state();
        let by = signed(&st, &t.signer);
        let who = if by.name.is_empty() { by.id.clone() } else { by.name.clone() };
        let order = Order::read(t.kind, t.orders.as_deref())?;
        match order {
            Order::Mute(ms) => {
                let until = ms.map_or(0, |ms| uptime::wall_ms().saturating_add(i64::try_from(ms).unwrap_or(i64::MAX)));
                self.live_mute(live, true, until, &by.id)
            }
            Order::Unmute => self.live_mute(live, false, 0, &by.id),
            Order::Mode(m) => {
                crate::sync::set(&self.state_dir, &live.board, m == Mode::Shared, 0)?;
                (self.log)(&format!("cbb: {who} turned sync {} here", if m == Mode::Own { "off" } else { "on" }));
                self.live_hello(live);
                Ok(())
            }
            Order::PasteOff => {
                remotepaste::save(&self.state_dir, remotepaste::Settings::default())
                    .map_err(|e| e.context("turning remote paste off"))?;
                (self.log)(&format!("cbb: {who} turned remote paste off here"));
                Ok(())
            }
            Order::ActionsOff => {
                self.live_actions_off(live)?;
                (self.log)(&format!("cbb: {who} turned the quick actions off here"));
                Ok(())
            }
            Order::Paste { way, enter, what } => {
                let mut body = crate::records::Command::default();
                body.kind = "paste".into();
                body.id = crate::certs::hex(&t.id);
                body.by = by.id.clone();
                body.time_ms = uptime::wall_ms();
                body.mode = if way == Way::Type { "type" } else { "paste" }.into();
                body.enter = enter;
                (body.paste_kind, body.text) = match what {
                    What::Text(t) => ("text".into(), t),
                    What::Secret(t) => ("secret".into(), t),
                    What::Media(id) => ("media".into(), crate::certs::hex(&id)),
                };
                let from = Sender { key: crate::certs::hex(&t.signer.0), verified: true, name: by.name.clone() };
                let secrets_stopped = st.stop != cbb_core::records::eval::Stop::None;
                let res = self.paste_from(
                    &from,
                    &body,
                    secrets_stopped,
                    &|_| {
                        let e = not_yet("pasting a copy's images or files");
                        (self.log)(&format!("cbb: a paste from {who}: {}", e.for_log()));
                        wire::CommandResult { status: "failed".into(), reason: e.to_string(), ..Default::default() }
                    },
                    &|len| self.live_watch_typing(live, t.signer, len),
                );
                outcome(&res.status, &res.reason)
            }
            Order::Action(name) => {
                let mut body = crate::records::Command::default();
                body.kind = "action".into();
                body.id = crate::certs::hex(&t.id);
                body.by = by.id.clone();
                body.time_ms = uptime::wall_ms();
                body.action = name;
                let from = Sender { key: crate::certs::hex(&t.signer.0), verified: true, name: by.name.clone() };
                let res = self.act_from(&from, &body, || actions::Signer {
                    root: by.root,
                    role: by.role.clone(),
                    store: by.store.clone(),
                });
                outcome(&res.status, &res.reason)
            }
            Order::AwayOff => {
                // The member of 0.6 syncs only at home: sync away from home
                // is off here unless an old one still runs.
                if let Some(a) = self.away.read().unwrap().clone() {
                    a.turn_off()?;
                }
                (self.log)(&format!("cbb: {who} turned sync away from home off here"));
                Ok(())
            }
            Order::Hub(_) | Order::Device { .. } => Err(not_yet(&format!("carrying out a {} command", order.name()))),
        }
    }

    /// Stops a paste a peripheral types after its answer once the signer's
    /// key no longer signs for the group (removed or frozen meanwhile).
    fn live_watch_typing(&self, live: &Live, key: KeyHash, len: usize) {
        let (mesh, p) = (live.mesh.clone(), self.peripherals.clone());
        let until = Instant::now() + Duration::from_secs(60) + Duration::from_millis(200) * len as u32;
        std::thread::spawn(move || {
            while Instant::now() < until && !STOP.load(Ordering::SeqCst) && !mesh.is_closed() {
                std::thread::sleep(TYPING_CHECK);
                if !still_signs(&mesh.state(), &key) {
                    p.stop();
                    return;
                }
            }
        });
    }

    /// Turns every quick action off here, and says so in the hellos.
    pub(super) fn live_actions_off(&self, live: &Live) -> Result<()> {
        let mut set = actions::load(&self.state_dir)?;
        set.all_off();
        actions::save(&self.state_dir, &set)?;
        self.live_hello(live);
        Ok(())
    }

    /// Sends the device target a command with order o, signed by this
    /// device's root or admin key, and waits for its result: the device's
    /// name once it carried it out.
    pub(super) fn live_order(&self, live: &Live, target: &str, o: &Order) -> Result<String> {
        let st = live.mesh.state();
        let d = writers::find(&st, target)?.clone();
        let signer = writers::signer(live.mesh.own(), &st).ok_or_else(|| Error::msg(NOT_COMMANDER))?;
        let orders = o.orders()?;
        let r = live
            .mesh
            .command(signer, d.id, o.kind(), orders.as_deref())
            .map_err(|e| Error::msg(format!("{}: {}", d.name, e.message())))?;
        match r.status {
            1 => Ok(d.name),
            s => {
                let status = if s == cbb_core::commands::STATUS_REFUSED { "refused" } else { "failed" };
                Err(Error::msg(format!("{} {status} it: {}", d.name, r.reason)))
            }
        }
    }

    /// The operations that send a command, on the records of 0.6; None
    /// for one that is this device's own matter, which the service answers
    /// as ever.
    pub(super) fn live_orders(&self, live: &Live, h: &Header, payload: &[u8]) -> Option<Result<Message>> {
        let done = || control::reply(Header { done: true, ..Default::default() }, Vec::new());
        let other = !h.device.is_empty() && !self_named(live, &h.device);
        let res = match h.op.as_str() {
            "mute" | "unmute" if other => {
                let o = if h.op == "mute" {
                    if let Err(e) = crate::mute::until(h.for_ms) {
                        return Some(Err(e));
                    }
                    Order::Mute((h.for_ms > 0).then_some(h.for_ms.unsigned_abs()))
                } else {
                    Order::Unmute
                };
                self.live_order(live, &h.device, &o).map(|_| control::reply(Header::default(), Vec::new()))
            }
            "sync" if !h.device.is_empty() => {
                let Some(on) = h.on else { return Some(Err(Error::msg("sync needs on, true or false"))) };
                if h.for_ms != 0 {
                    return Some(Err(Error::msg("-on turns another device's sync on or off with no time")));
                }
                if !other {
                    return None;
                }
                let o = Order::Mode(if on { Mode::Shared } else { Mode::Own });
                self.live_order(live, &h.device, &o).map(|name| {
                    (self.log)(&format!("cbb: turned sync {} on {name}", if on { "on" } else { "off" }));
                    control::reply(Header { name, done: true, ..Default::default() }, Vec::new())
                })
            }
            "away" if h.name == "off" && !h.device.is_empty() => {
                if !other {
                    return Some(Err(Error::msg("-on names this device; cbb global off turns it off here")));
                }
                self.live_order(live, &h.device, &Order::AwayOff).map(|_| done())
            }
            "paste_on" => self.live_paste_on(live, h, payload).map(|()| done()),
            "action_on" => {
                if !cbb_core::command::valid_action_name(&h.name) {
                    return Some(Err(Error::msg(format!("{:?} is not an action's name", h.name))));
                }
                if !other {
                    return Some(Err(Error::msg("an action runs on another device; here, do it yourself")));
                }
                self.live_order(live, &h.device, &Order::Action(h.name.clone())).map(|_| done())
            }
            "paste_receive" if h.name == "off" && (!h.device.is_empty() || h.all) => {
                self.live_off_on(live, h, true).map(|()| {
                    let status = Status { paste: self.paste_status(), ..Default::default() };
                    control::reply(Header { status: Some(status), ..Default::default() }, Vec::new())
                })
            }
            "actions_off" => {
                self.live_off_on(live, h, false).and_then(|()| Ok(self.action_reply(&actions::load(&self.state_dir)?)))
            }
            _ => return None,
        };
        Some(res)
    }

    /// cbb paste -on on the records of 0.6: a paste command to another
    /// device.
    fn live_paste_on(&self, live: &Live, h: &Header, payload: &[u8]) -> Result<()> {
        if h.device.is_empty() || self_named(live, &h.device) {
            return Err(Error::msg("remote paste is for another device; this one is where you type"));
        }
        let way = match h.method.as_str() {
            "" | "paste" => Way::Paste,
            "type" => Way::Type,
            m => return Err(Error::msg(format!("a paste is pasted or typed, not {m:?}"))),
        };
        let text = || {
            let t = remotepaste::clean(&String::from_utf8_lossy(payload));
            if t.is_empty() {
                Err(Error::msg("nothing to paste: the text is empty or only control characters"))
            } else {
                Ok(t)
            }
        };
        let what = match h.kind.as_str() {
            "" | "text" => What::Text(text()?),
            "secret" => What::Secret(text()?),
            "media" => {
                if way == Way::Type {
                    return Err(Error::msg("images and files are pasted, not typed"));
                }
                let c = live.board.current().filter(|c| c.content.manifest.is_some()).ok_or_else(|| {
                    Error::msg("the group's current copy is no images or files that this device reads")
                })?;
                What::Media(c.id)
            }
            k => return Err(Error::msg(format!("a paste is a text or a secret, not {k:?}"))),
        };
        self.live_order(live, &h.device, &Order::Paste { way, enter: h.enter, what }).map(|_| ())
    }

    /// Turns remote paste (paste true) or every quick action off on the
    /// device h names, here when it names this one, or with all on every
    /// device of the group.
    fn live_off_on(&self, live: &Live, h: &Header, paste: bool) -> Result<()> {
        let st = live.mesh.state();
        let me = live.mesh.device();
        let targets: Vec<String> = if h.all {
            st.devices.iter().filter(|d| d.id != me).map(|d| id_text(&d.id)).collect()
        } else if h.device.is_empty() {
            Vec::new()
        } else {
            vec![id_text(&writers::find(&st, &h.device)?.id)]
        };
        let here = h.all || h.device.is_empty() || self_named(live, &h.device);
        if here {
            if paste {
                remotepaste::save(&self.state_dir, remotepaste::Settings::default())
                    .map_err(|e| e.context("saving the remote paste settings"))?;
                (self.log)("cbb: remote paste is off here");
            } else {
                self.live_actions_off(live)?;
                (self.log)("cbb: the quick actions are off here");
            }
        }
        let o = if paste { Order::PasteOff } else { Order::ActionsOff };
        let failed: Vec<String> = targets
            .iter()
            .filter(|t| **t != id_text(&me))
            .filter_map(|t| self.live_order(live, t, &o).err())
            .map(|e| e.message().to_string())
            .collect();
        if !failed.is_empty() {
            let what = if paste { "remote paste" } else { "the quick actions" };
            return Err(Error::msg(format!("{what} may still be on: {}", failed.join("; "))));
        }
        Ok(())
    }
}
