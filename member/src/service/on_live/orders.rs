// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Commands on the records of 0.6 (format section 6, `crate::orders`):
//! those this device's root or admin key sends to another device (mute,
//! sync, remote paste, quick actions and turning them off), and those it
//! takes and carries out, with the same checks of its user's switches as
//! on the old records. Away-off turns sync away from home off here, and a
//! hub command makes this device a hub or stops it being one; a small
//! device's own command is refused, since this device has none.

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
    Signed {
        id: d.map(|d| id_text(&d.id)).unwrap_or_default(),
        name: d.map(|d| d.name.clone()).unwrap_or_default(),
        root,
        role: d.map(|d| roster::role_name(d.role).to_string()).unwrap_or_default(),
        store: d.map(|d| roster::store_name(d.store).to_string()).unwrap_or_default(),
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
                let (paste_kind, text) = match what {
                    What::Text(t) => ("text".into(), t),
                    What::Secret(t) => ("secret".into(), t),
                    What::Media(id) => ("media".into(), crate::certs::hex(&id)),
                };
                let body = crate::records::Command {
                    id: crate::certs::hex(&t.id),
                    by: by.id.clone(),
                    mode: if way == Way::Type { "type" } else { "paste" }.into(),
                    enter,
                    paste_kind,
                    text,
                    ..Default::default()
                };
                let from = Sender { key: crate::certs::hex(&t.signer.0), verified: true, name: by.name.clone() };
                let secrets_stopped = st.stop != cbb_core::records::eval::Stop::None;
                let res = self.paste_from(
                    &from,
                    &body,
                    secrets_stopped,
                    &|set| self.live_paste_copy(live, &body, set, &by.name),
                    &|len| self.live_watch_typing(live, t.signer, len),
                );
                outcome(&res.status, &res.reason)
            }
            Order::Action(name) => {
                let body = crate::records::Command {
                    id: crate::certs::hex(&t.id),
                    by: by.id.clone(),
                    action: name,
                    ..Default::default()
                };
                let from = Sender { key: crate::certs::hex(&t.signer.0), verified: true, name: by.name.clone() };
                let res = self.act_from(&from, &body, || actions::Signer {
                    root: by.root,
                    role: by.role.clone(),
                    store: by.store.clone(),
                });
                outcome(&res.status, &res.reason)
            }
            Order::AwayOff => {
                live.away_off(Duration::from_millis(500))?;
                (self.log)(&format!("cbb: {who} turned sync away from home off here"));
                Ok(())
            }
            Order::Hub(h) => self.live_take_hub(live, &who, &h),
            // A computer or a Pi defines no commands of its own: the
            // small devices that do (the leaves) come with 0.7.
            Order::Device { name, .. } => {
                (self.log)(&format!("cbb: {who} sent the command {name:?}, which this device does not have"));
                Err(refuse(format!("this device has no command {name}")))
            }
        }
    }

    /// Carries out a hub command: stop being a hub, or become one at the
    /// address away from home and with the first forwarder it names, when
    /// it names this device as the hub (field 10, the address and the hash
    /// of the hub's member key).
    fn live_take_hub(&self, live: &Live, who: &str, h: &crate::orders::Hub) -> Result<()> {
        use base64::Engine as _;
        let away = live.away().ok_or_else(|| refuse("sync away from home did not start on this device"))?;
        if h.stop {
            if !away.is_hub_now() {
                return Err(refuse("this device is no hub of the group"));
            }
            live.stop_being_hub()?;
            (self.log)(&format!("cbb: {who} stopped this device being a hub of the group"));
            return Ok(());
        }
        if let Some((_, k)) = &h.hub
            && *k != live.mesh.own().hash().0
        {
            return Err(refuse("the hub command names another device as the hub"));
        }
        if !live.mesh.may_be_hub(&live.mesh.device()) {
            return Err(refuse(format!("{NOT_A_HUB_YET}; the root names its hubs with cbb global hubs")));
        }
        let (fwd, key) = h
            .forwarders
            .first()
            .map(|(a, pin)| (a.clone(), base64::engine::general_purpose::STANDARD.encode(pin)))
            .unwrap_or_default();
        // A hub set again keeps the UDP port it listens on; a new one
        // listens on the port of the address it is reached at, which the
        // router away from home forwards.
        let given = h.hub.as_ref().and_then(|(e, _)| e.parse::<std::net::SocketAddr>().ok()).map_or(0, |a| a.port());
        let port = away.hub_settings().map_or(i64::from(given), |(_, _, port)| i64::from(port));
        let hdr = Header {
            addrs: h.hub.iter().map(|(e, _)| e.clone()).collect(),
            port,
            forwarder: fwd,
            forwarder_key: key,
            ..Default::default()
        };
        away.make_hub(&hdr).map_err(|e| refuse(e.message().to_string()))?;
        (self.log)(&format!("cbb: {who} made this device one of the group's hubs"));
        Ok(())
    }

    /// The hub command that makes the device target a hub at the address
    /// addrs gives, with the forwarder fwd names (else this hub's own).
    fn hub_order_for(&self, live: &Live, target: &str, addrs: &[String], fwd: (&str, &str)) -> Result<Order> {
        let st = live.mesh.state();
        let d = writers::find(&st, target)?;
        if !st.may_be_hub(&d.id) {
            return Err(Error::msg(format!(
                "the group's records do not make {} a hub; the root names its hubs with cbb global hubs",
                d.name
            )));
        }
        if addrs.len() > 1 {
            return Err(Error::msg("a hub command of 0.6 gives the new hub one address away from home"));
        }
        let forwarder = match crate::away::forwarder_named(fwd.0, fwd.1)? {
            Some(f) => Some(f),
            None => live.away().and_then(|a| a.own_forwarder()),
        };
        if addrs.is_empty() && forwarder.is_none() {
            return Err(Error::msg("the hub needs an address away from home or a forwarder"));
        }
        Ok(Order::Hub(crate::orders::Hub {
            hub: addrs.first().map(|a| (a.clone(), d.key.hash().0)),
            forwarders: forwarder.into_iter().collect(),
            stop: false,
        }))
    }

    /// cbb global hub -on DEVICE, cbb global hub off [-on DEVICE] and cbb
    /// global move DEVICE on the records of 0.6.
    fn live_hubs_op(&self, live: &Live, h: &Header, other: bool) -> Result<String> {
        match h.name.as_str() {
            "hub" if !other => Err(Error::msg("-on names this device; cbb global hub makes it a hub here")),
            "hub" => {
                if h.forward_only {
                    // The device's record and the hubs record, which the
                    // root alone gives (an admin grants base rights only).
                    if !live.mesh.is_root() {
                        return Err(not_yet(
                            "an admin making a hub that only passes copies on; the group's root does it",
                        ));
                    }
                    let now = crate::uptime::wall_ms().max(0) as u64;
                    live.mesh.write(|set, k| writers::set_forward_only(set, k, &h.device, now))?;
                }
                let o = self.hub_order_for(live, &h.device, &h.addrs, (&h.forwarder, &h.forwarder_key))?;
                let name = self.live_order_after_records(live, &h.device, &o)?;
                note_forwarders(live, &h.device, &o)?;
                (self.log)(&format!("cbb: {name} is one of the group's hubs now"));
                Ok(name)
            }
            "hub-off" => {
                // The hubs that serve, as this device knows: itself while
                // it serves, and those whose offers it keeps. A device
                // that serves not is told so, rather than that it is the
                // last hub.
                let (serving, held) = live.away().map_or((false, Vec::new()), |a| (a.is_hub_now(), a.held_hubs()));
                if !other && !serving {
                    return Err(Error::msg("this device is no hub of the group"));
                }
                let target_serves = !other || {
                    let st = live.mesh.state();
                    writers::find(&st, &h.device).is_ok_and(|d| held.contains(&crate::roster::id_text(&d.id)))
                };
                // Whether another serves: as this device knows when the
                // target is one it knows serves, else by the records'
                // order of hubs.
                let others =
                    if target_serves { usize::from(serving) + held.len() } else { live.mesh.hub_order().len() };
                if others < 2 && !h.force {
                    return Err(Error::msg(crate::NO_OTHER_HUB));
                }
                if other {
                    let o = Order::Hub(crate::orders::Hub { stop: true, ..Default::default() });
                    let name = self.live_order(live, &h.device, &o)?;
                    note_forwarders(live, &h.device, &o)?;
                    (self.log)(&format!("cbb: {name} is no hub of the group any more"));
                    Ok(name)
                } else {
                    live.stop_being_hub()?;
                    Ok(String::new())
                }
            }
            _ => {
                if h.device.is_empty() {
                    return Err(Error::msg("cbb global move names the device to move the hub to"));
                }
                if !other {
                    return Err(Error::msg("-on names this device, which is the hub already"));
                }
                if !live.away().is_some_and(|a| a.is_hub_now()) {
                    return Err(Error::msg("this device is no hub of the group, so it has no hub to move"));
                }
                let o = self.hub_order_for(live, &h.device, &h.addrs, (&h.forwarder, &h.forwarder_key))?;
                let name = self.live_order(live, &h.device, &o)?;
                note_forwarders(live, &h.device, &o)?;
                // The clients away move once the new hub serves (D-122).
                let to = writers::find(&live.mesh.state(), &h.device)?.id;
                // The handover outlives this command: it holds the member.
                let arc =
                    self.live().filter(|a| std::ptr::eq(&**a, live)).ok_or_else(|| Error::msg("the group stopped"))?;
                arc.hand_hub_to(to)?;
                (self.log)(&format!("cbb: the hub moves to {name} once it serves"));
                Ok(name)
            }
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

    /// A paste of the group's copy of images or files on the records of
    /// 0.6: the copy the command names, once it arrived here and while it
    /// is the current one, fetched and pasted as on the old records. A
    /// copy of 0.6 is sealed to every reader the group lists, the sender
    /// among them, so there is no wrap to look for.
    fn live_paste_copy(
        &self,
        live: &Live,
        body: &crate::records::Command,
        set: remotepaste::Settings,
        name: &str,
    ) -> wire::CommandResult {
        let res = wire::CommandResult { id: body.id.clone(), status: "refused".into(), ..Default::default() };
        let until = Instant::now() + COPY_WAIT;
        let c = loop {
            if let Some(c) = live.board.current().filter(|c| crate::certs::hex(&c.id) == body.text) {
                break c;
            }
            if Instant::now() >= until {
                let reason = "the copy to paste did not arrive here, or a newer copy replaced it".into();
                return wire::CommandResult { reason, ..res };
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        let Some(m) = c.content.manifest.clone().filter(|_| c.content.writable()) else {
            let reason = if c.content.writable() {
                "the copy to paste holds no images or files"
            } else {
                "this device cannot read the copy to paste"
            };
            return wire::CommandResult { reason: reason.into(), ..res };
        };
        self.inject_copy(body, set, name, &m, res, || match c.blob {
            Some(b) => live.mesh.fetch(&b, &c.from, self.limits.lock().unwrap().home as u64),
            None => Ok(()),
        })
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

    /// As live_order, for an order that records just written allow: the
    /// target refuses it until those records reach it, which a command may
    /// overtake, so a refusal for want of them is asked again until the
    /// target has them, for a while.
    fn live_order_after_records(&self, live: &Live, target: &str, o: &Order) -> Result<String> {
        let until = Instant::now() + RECORDS_REACH;
        loop {
            match self.live_order(live, target, o) {
                Err(e) if e.message().contains(NOT_A_HUB_YET) && Instant::now() < until => {
                    std::thread::sleep(Duration::from_millis(250));
                }
                res => return res,
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
            "away" if matches!(h.name.as_str(), "hub-off" | "move") || (h.name == "hub" && !h.device.is_empty()) => {
                self.live_hubs_op(live, h, other)
                    .map(|name| control::reply(Header { name, done: true, ..Default::default() }, Vec::new()))
            }
            "away" if h.name == "off" && !h.device.is_empty() => {
                if !other {
                    return Some(Err(Error::msg("-on names this device; cbb global off turns it off here")));
                }
                self.live_order(live, &h.device, &Order::AwayOff).map(|_| done())
            }
            "paste_on" => self.live_paste_on(live, h, payload).map(|()| done()),
            "action_on" => {
                if !cbb_core::commands::orders::valid_action_name(&h.name) {
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
        let text = || remotepaste::to_paste(&String::from_utf8_lossy(payload));
        let what = match h.kind.as_str() {
            "" | "text" => What::Text(text()?),
            "secret" => What::Secret(text()?),
            "media" => {
                if way == Way::Type {
                    return Err(Error::msg("images and files are pasted, not typed"));
                }
                let id = live.media_copy().ok_or_else(|| {
                    Error::msg("the group's current copy is no images or files that this device reads")
                })?;
                What::Media(id)
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

/// On the root, the forwarders a hub command it sent named become the
/// hub's (`Mesh::set_hub_forwarders`), each with a face of its own; a stop
/// forgets them. An admin's names none: the root alone makes faces.
fn note_forwarders(live: &Live, target: &str, o: &Order) -> Result<()> {
    let Order::Hub(h) = o else { return Ok(()) };
    if !live.mesh.is_root() {
        return Ok(());
    }
    let hub = writers::find(&live.mesh.state(), target)?.id;
    let servers =
        h.forwarders.iter().map(|(address, pin)| crate::faces::Server { pin: *pin, address: address.clone() });
    live.mesh.set_hub_forwarders(hub, servers.collect())
}

/// Why a device refuses a hub command while its records do not make it a
/// hub.
const NOT_A_HUB_YET: &str = "the group's records do not make this device a hub";

/// How long a hub command waits for the records that allow it to reach its
/// target.
const RECORDS_REACH: Duration = Duration::from_secs(15);
