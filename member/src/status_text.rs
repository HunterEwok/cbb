// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! What cbb status prints, in the Go cbb's words (cmd/cbb's writeStatus,
//! writeDevices and the lines they call): this device, its group and the
//! group's devices as a table.

use std::fmt::Write;

use crate::control::{Away, Device, Media, Status};

/// How long before its end status warns that this device's member
/// certificate was not renewed, as Go's certWarning.
const CERT_WARNING_MS: i64 = 30 * 24 * 3600 * 1000;

/// What a hub of the project's forwarder is told when its entry points
/// may be out of date, as Go's entriesStale.
const ENTRIES_STALE: &str = "The list of the project's entry points is out of date, and the forwarder does not answer on the ways this device knows. Update CBB on a computer of the group (sudo cbb update), or import a new list there (cbb global entries import); the group passes it on.";

/// The whole status, as Go's writeStatus; now_ms is the wall clock.
pub fn write_status(st: &Status, devs: &[Device], now_ms: i64, limit: &str) -> String {
    let mut w = String::new();
    let _ = writeln!(w, "{}", st.version);
    if !st.update.is_empty() {
        let _ = writeln!(w, "CBB {} is available. To install it: {}", st.update, update_command());
    }
    if st.group.is_empty() {
        if st.left_old_group {
            w.push_str("This device left its group, which was made before 0.6: groups are set up again from 0.6 on.\n");
        }
        w.push_str("Not in a group. Run cbb new here to start one, or cbb pair to join one.\n");
        return w;
    }
    let _ = writeln!(w, "Device {} ({}, {}), group {}", st.device, os_name(&st.os), st.role, st.group);
    let level = crate::cli::key_level_line(&st.key_level);
    if !level.is_empty() {
        let _ = writeln!(w, "{level}");
    }
    if st.removed {
        w.push_str("This device was removed from the group: its members refuse it. To join this group again or another one, leave it here first: sudo cbb leave, then cbb pair.\n");
    } else if st.frozen {
        w.push_str("Another admin froze this computer's admin key: its members refuse it until the group's root or an admin phone unfreezes it (cbb unfreeze on the root).\n");
    } else if !st.taken_over_by.is_empty() {
        let by = &st.taken_over_by;
        let _ = writeln!(
            w,
            "{by}, an admin, took the group over from this computer, its root, while it was away. If this computer is not lost, sudo cbb remove {by} undoes it; otherwise the group is {by}'s now."
        );
    } else if let Some(c) = renewal_line(st.cert_ends_ms, now_ms) {
        let _ = writeln!(w, "{c}");
    }
    for l in stop_lines(st) {
        let _ = writeln!(w, "{l}");
    }
    if !st.mode.is_empty() {
        let _ = writeln!(w, "{}", sync_line(st));
    }
    if st.muted && st.muted_until_ms == 0 {
        w.push_str("An admin muted this device: its copies do not reach the group until an admin unmutes it.\n");
    } else if st.muted {
        let _ = writeln!(
            w,
            "An admin muted this device until {}: its copies do not reach the group until then.",
            crate::cli::local_minute(st.muted_until_ms)
        );
    }
    if !st.quiet.is_empty() {
        let _ = writeln!(
            w,
            "Quiet on {}: a network where this computer has not met its group, so it does not publish itself or take connections there, and only looks for the members. It does once it connects to a member there; at home after a new router, run sudo cbb network.",
            st.quiet.join(", ")
        );
    }
    write_away(&mut w, st.away.as_ref(), limit);
    write_media(&mut w, st.media.as_ref());
    if st.peers.is_empty() {
        w.push_str("No members connected.\n");
    }
    write_unreached(&mut w, st, devs);
    write_devices(&mut w, devs, &st.peers, &st.release, now_ms);
    w
}

/// Says when members at home could not connect to this device and sync
/// with it only because it dials them back, as Go's writeUnreached: a
/// firewall here drops the member port, and a phone would not sync.
fn write_unreached(w: &mut String, st: &Status, devs: &[Device]) {
    if st.unreached.is_empty() {
        return;
    }
    let names: Vec<&str> = st
        .unreached
        .iter()
        .map(|id| devs.iter().find(|d| &d.id == id && !d.name.is_empty()).map_or(id.as_str(), |d| d.name.as_str()))
        .collect();
    let port = if st.port == 0 { 8764 } else { st.port };
    let express = if cfg!(windows) { "-Express" } else { "--express" };
    let _ = writeln!(
        w,
        "Warning: {} could not connect to this device; they sync only because this device connects to them.",
        names.join(", ")
    );
    let _ = writeln!(
        w,
        "A firewall here likely drops TCP {port} from the home network, and phones cannot reach this device."
    );
    let _ =
        writeln!(w, "Allow TCP {port} and UDP 5353 from the home network, or run the installer again with {express}.");
}

/// How this system's cbb updates itself, as Go's updateCommand.
fn update_command() -> &'static str {
    if cfg!(windows) { "cbb update (as administrator)" } else { "sudo cbb update" }
}

/// A system's name for people, as Go's group.OSName.
pub fn os_name(os: &str) -> &'static str {
    match os {
        "linux" => "Linux",
        "windows" => "Windows",
        "macos" => "macOS",
        "ios" => "iOS",
        "android" => "Android",
        "aurora" => "Aurora OS",
        "sailfish" => "Sailfish OS",
        "harmonyos" => "HarmonyOS",
        "watchos" => "watchOS",
        "wearos" => "Wear OS",
        "none" => "device",
        _ => "?",
    }
}

/// A local date, YYYY-MM-DD.
fn local_date(ms: i64) -> String {
    let t = crate::sys::local_time_at(ms);
    format!("{:04}-{:02}-{:02}", t.year, t.month, t.day)
}

/// Warns when this device's member certificate has ended or ends soon, as
/// Go's certLine.
fn renewal_line(ends_ms: i64, now_ms: i64) -> Option<String> {
    if ends_ms == 0 {
        return None;
    }
    if now_ms >= ends_ms {
        return Some(format!(
            "This device's certificate ended on {}, before an admin renewed it: the group's members refuse it. If this device's date ({}) is wrong, set it right; otherwise, to join again, leave the group here (sudo cbb leave) and join.",
            local_date(ends_ms),
            local_date(now_ms)
        ));
    }
    (ends_ms - now_ms < CERT_WARNING_MS).then(|| {
        format!(
            "This device's certificate ends on {} and no admin has renewed it: connect it to the group's root or an admin before then, or it must join again.",
            local_date(ends_ms)
        )
    })
}

/// Why the group stops, as Go's stopLines.
fn stop_lines(st: &Status) -> Vec<String> {
    let mut out = Vec::new();
    match st.stop.as_str() {
        "full" => out.push(
            tr!(
                "The group is stopped: its members exchange records only, no clipboard, until the group's root decides."
            )
            .to_string(),
        ),
        "secrets" => out.push(tr!("The group sends no secrets until its root decides.").to_string()),
        _ => {}
    }
    for c in &st.conflicts {
        let who = if c.devices.is_empty() { "devices unknown here".to_string() } else { c.devices.join(", ") };
        out.push(match c.kind.as_str() {
            "admins" => format!(
                "Admins removed or froze each other without seeing it ({who}): the root decides by removing one of them (cbb remove NAME on a root computer, or on the root phone)."
            ),
            "claims" => {
                format!("Two claims to take the group over ({who}): the root cancels one or both by removing its admin.")
            }
            "two_histories" => format!(
                "{who} signed two histories with one key, as a stolen key or a device brought back from a backup would: the group's root voids both (cbb resolve on a root computer, or on the root phone), and the device signs its records again."
            ),
            k => format!("A conflict of kind {k} ({who}): the root decides."),
        });
    }
    for c in &st.claims {
        match c.state.as_str() {
            "pending" => {
                let left = if c.left_ms > 0 {
                    format!("in {}", roughly(c.left_ms))
                } else {
                    "once this device knows how long it has held it".to_string()
                };
                out.push(format!(
                    "{} claims the group, to take it over from its root: it takes effect {left}, unless the root cancels it by removing {}.",
                    c.by, c.by
                ));
            }
            "disputed" => out.push(format!(
                "{} claims the group, and another admin removed it: the group is stopped until the root decides.",
                c.by
            )),
            "competing" => out.push(format!(
                "{} claims the group while another admin claims it too: the group is stopped until the root decides.",
                c.by
            )),
            _ => {}
        }
    }
    if st.newer > 0 {
        out.push(format!("The group holds {} records of a later version of CBB: update it to read them.", st.newer));
    }
    out
}

/// A duration in days, hours or minutes, as Go's roughly.
fn roughly(ms: i64) -> String {
    let (h, m) = (ms / 3_600_000, ms / 60_000);
    match () {
        _ if h >= 48 => format!("{} days", h / 24),
        _ if h >= 2 => format!("{h} hours"),
        _ if m >= 2 => format!("{m} minutes"),
        _ => "a minute".to_string(),
    }
}

/// Whether sync is on, and until when it is off, as Go's syncLine.
pub fn sync_line(st: &Status) -> String {
    if st.mode == "shared" {
        return tr!("Sync is on: copies here go to the group, and the group's copies come here.").to_string();
    }
    let until =
        if st.sync_until_ms != 0 { crate::cli::local_minute(st.sync_until_ms) } else { "cbb sync on".to_string() };
    format!(
        "Sync is off until {until}: this clipboard is this device's own; cbb paste prints the group's text, and cbb copy sends to the group."
    )
}

/// Sync away from home, as Go's writeAway, with the underlying error in
/// debug mode.
pub fn write_away(w: &mut String, a: Option<&Away>, limit: &str) {
    let Some(a) = a else {
        w.push_str("Sync away from home: off (cbb global on turns it on).\n");
        w.push_str(limit);
        return;
    };
    w.push_str(limit);
    let detail = |w: &mut String, d: &str| {
        if !d.is_empty() && crate::error::show_details() {
            let _ = writeln!(w, "  Detail: {d}");
        }
    };
    if a.hub && a.standby {
        if a.hub_device.is_empty() {
            w.push_str("Sync away from home: on; this device is one of the group's hubs. It looks for the hubs above it, and serves if none answers.\n");
        } else {
            let _ = writeln!(
                w,
                "Sync away from home: on; this device is one of the group's hubs. The hub {}, above it, serves, so this one stands by as its client.",
                a.hub_device
            );
        }
    } else if a.hub {
        let devices = if a.clients == 1 { "device" } else { "devices" };
        let _ = writeln!(
            w,
            "Sync away from home: on; this device is the hub, on UDP port {}, for {} {devices}.",
            a.port, a.clients
        );
        if a.obfuscated {
            w.push_str("  Obfuscated: the tunnel speaks AmneziaWG, so it does not look like WireGuard.\n");
        }
        if a.vless {
            w.push_str("  VLESS: the clients try AmneziaWG over UDP first and reach the forwarder over VLESS, which looks like HTTPS to a website, where UDP does not pass.\n");
        }
        if !a.endpoints.is_empty() {
            let _ = writeln!(w, "  Reached at {}.", a.endpoints.join(", "));
            let _ = writeln!(
                w,
                "  The router must forward UDP port {} to this device, and its firewall must allow it.",
                a.port
            );
        } else if a.forwarder.is_none() {
            w.push_str("  The hub has no address away from home: cbb global hub address:port...\n");
        }
        if let Some(f) = &a.forwarder {
            if f.registered && !f.seen.is_empty() {
                let _ = writeln!(
                    w,
                    "  Registered with the forwarder at {}, which reaches this hub at {}.",
                    f.endpoint, f.seen
                );
            } else if f.registered {
                let _ = writeln!(
                    w,
                    "  Registered with the forwarder at {}; it has not heard the hub's UDP port yet.",
                    f.endpoint
                );
            } else if f.error.is_empty() {
                let _ = writeln!(w, "  Registering with the forwarder at {}.", f.endpoint);
            } else {
                let _ = writeln!(w, "  Not registered with the forwarder at {}: {}.", f.endpoint, f.error);
                detail(w, &f.detail);
            }
            if f.entries_stale {
                let _ = writeln!(w, "  {ENTRIES_STALE}");
            }
        }
    } else if let Some(r) = &a.relay {
        if r.connected && a.through {
            let _ = writeln!(
                w,
                "Sync away from home: on; connected to the relay at {} and through it to other devices.",
                r.endpoint
            );
        } else if r.connected && r.online.is_empty() {
            let _ = writeln!(
                w,
                "Sync away from home: on; connected to the relay at {}; no other device of the group is there now.",
                r.endpoint
            );
        } else if r.connected {
            let _ = writeln!(
                w,
                "Sync away from home: on; connected to the relay at {}, with {} other devices of the group there.",
                r.endpoint,
                r.online.len()
            );
        } else if r.error.is_empty() {
            let _ = writeln!(w, "Sync away from home: on; connecting to the relay at {}.", r.endpoint);
        } else {
            let _ = writeln!(w, "Sync away from home: on; not connected to the relay at {}: {}.", r.endpoint, r.error);
            detail(w, &r.detail);
        }
    } else if a.hub_device.is_empty() {
        w.push_str("Sync away from home: on; waiting to meet the group's hub on the home network. The hub\n");
        w.push_str("learns this device's keys there, so away from home it syncs only after that.\n");
    } else if a.through {
        let _ = writeln!(
            w,
            "{}",
            tr!("Sync away from home: on; connected to the hub {} through the tunnel.", a.hub_device)
        );
    } else if a.vless {
        let _ = writeln!(
            w,
            "Sync away from home: on; the hub is {}, reached over VLESS through its forwarder; not connected through the tunnel.",
            a.hub_device
        );
    } else {
        let _ = writeln!(
            w,
            "{}",
            tr!(
                "Sync away from home: on; the hub is {}, at {}; not connected through the tunnel.",
                a.hub_device,
                a.endpoints.join(", ")
            )
        );
    }
    if a.vless && !a.hub {
        w.push_str(
            "  VLESS: the tunnel goes inside VLESS to the hub's forwarder, which looks like HTTPS to a website.\n",
        );
    }
    if !a.error.is_empty() {
        let _ = writeln!(w, "  Problem: {}.", a.error);
        detail(w, &a.detail);
    }
}

/// Why the last copy of images or files was not fetched, as Go's
/// writeMedia.
fn write_media(w: &mut String, m: Option<&Media>) {
    if let Some(m) = m
        && !m.failed.is_empty()
    {
        let _ = writeln!(w, "The last copy of images or files was not fetched: {}.", m.failed);
    }
}

/// The devices as a table, with the clock of each connected peer, as Go's
/// writeDevices.
fn write_devices(w: &mut String, devs: &[Device], peers: &[Device], newest: &str, now_ms: i64) {
    if devs.is_empty() {
        return;
    }
    let mut rows =
        vec![["NAME", "SYSTEM", "VERSION", "ROLE", "ADMIN", "KEYS", "SYNC", "SEEN", "CLOCK", "ID"].map(String::from)];
    let (mut unlisted, mut old) = (false, false);
    for d in devs {
        let mut name = d.name.clone();
        if d.this {
            name += " (this device)";
        }
        if !d.listed {
            name += " *";
            unlisted = true;
        }
        let admin = if d.root {
            "root"
        } else if d.frozen {
            "frozen"
        } else if d.admin {
            "admin"
        } else {
            ""
        };
        let clock = match peers.iter().find(|p| p.id == d.id) {
            Some(p) if p.skew_ms.abs() > 5000 => {
                format!(
                    "off by {}; check its time",
                    crate::cli::go_duration(p.skew_ms.signum() * ((p.skew_ms.abs() + 500) / 1000) * 1000)
                )
            }
            Some(_) => "ok".to_string(),
            None => String::new(),
        };
        let mut ver = d.version.clone();
        if !ver.is_empty() && !newest.is_empty() && cbb_core::release::compare(&ver, newest) == std::cmp::Ordering::Less
        {
            ver += " (old)";
            old = true;
        }
        let mut role = d.role.clone();
        if d.forward_only {
            role += ", hub that only passes copies on";
        } else if d.hub {
            role += ", hub";
        }
        let mut mode = match d.mode.as_str() {
            "shared" => "on",
            "own" => "off",
            _ => "",
        }
        .to_string();
        if d.muted {
            mode = format!("{mode} muted").trim().to_string();
        }
        rows.push([
            name,
            os_name(&d.os).to_string(),
            ver,
            role,
            admin.to_string(),
            keys(d).to_string(),
            mode,
            seen(d, now_ms),
            clock,
            d.id.clone(),
        ]);
    }
    table(w, &rows);
    if unlisted {
        w.push_str("* not in the devices list yet; the group's root adds it when they meet.\n");
    }
    if old {
        let _ = writeln!(w, "(old): below CBB {newest}, the newest release the group passed around; update it.");
    }
}

/// Lays rows out as Go's tabwriter with padding 2 does: each column but
/// the last as wide as its widest cell and two spaces.
fn table<const N: usize>(w: &mut String, rows: &[[String; N]]) {
    let mut widths = [0usize; N];
    for r in rows {
        for (i, c) in r.iter().enumerate() {
            widths[i] = widths[i].max(c.chars().count());
        }
    }
    for r in rows {
        for (i, c) in r.iter().enumerate() {
            if i + 1 == N {
                w.push_str(c);
            } else {
                let _ = write!(w, "{c}{}", " ".repeat(widths[i] - c.chars().count() + 2));
            }
        }
        w.push('\n');
    }
}

/// Where a device's keys live, as Go's keys.
fn keys(d: &Device) -> &'static str {
    match d.store.as_str() {
        "proven" => "proven hardware",
        "hardware" => "hardware",
        "file" => "in a file",
        "rootless" => "in a file, rootless",
        _ => "",
    }
}

/// When a device was last seen, in words, as Go's seen.
fn seen(d: &Device, now_ms: i64) -> String {
    if d.online {
        return "online".into();
    }
    if d.last_seen_ms == 0 {
        return "not seen here".into();
    }
    let ago = now_ms - d.last_seen_ms;
    match () {
        _ if ago < 60_000 => "just now".into(),
        _ if ago < 3_600_000 => format!("{} min ago", ago / 60_000),
        _ if ago < 48 * 3_600_000 => format!("{} h ago", ago / 3_600_000),
        _ => format!("{} days ago", ago / (24 * 3_600_000)),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn unreached() {
        let mut w = String::new();
        write_unreached(&mut w, &Status { port: 9000, ..Default::default() }, &[]);
        assert!(w.is_empty(), "nothing unreached, yet: {w}");
        let st = Status { port: 9000, unreached: vec!["id1".into(), "id2".into()], ..Default::default() };
        let devs = [Device { id: "id1".into(), name: "deck".into(), ..Default::default() }];
        write_unreached(&mut w, &st, &devs);
        assert!(w.contains("deck, id2 could not connect") && w.contains("TCP 9000"), "unreached: {w}");
    }

    use super::*;

    #[test]
    fn devices_table() {
        let devs = vec![
            Device {
                id: "aa".into(),
                name: "pi".into(),
                os: "linux".into(),
                role: "member".into(),
                version: "0.6.0".into(),
                store: "hardware".into(),
                mode: "shared".into(),
                root: true,
                this: true,
                listed: true,
                online: true,
                ..Default::default()
            },
            Device {
                id: "bb".into(),
                name: "phone".into(),
                os: "ios".into(),
                role: "phone".into(),
                version: "0.5.0".into(),
                store: "file".into(),
                mode: "own".into(),
                muted: true,
                last_seen_ms: 1_000,
                ..Default::default()
            },
        ];
        let peers = vec![Device { id: "aa".into(), skew_ms: -7_400, ..Default::default() }];
        let mut w = String::new();
        write_devices(&mut w, &devs, &peers, "0.6.0", 1_000 + 3 * 3_600_000);
        assert_eq!(
            w,
            "NAME              SYSTEM  VERSION      ROLE    ADMIN  KEYS       SYNC       SEEN     CLOCK                       ID\n\
             pi (this device)  Linux   0.6.0        member  root   hardware   on         online   off by -7s; check its time  aa\n\
             phone *           iOS     0.5.0 (old)  phone          in a file  off muted  3 h ago                              bb\n\
             * not in the devices list yet; the group's root adds it when they meet.\n\
             (old): below CBB 0.6.0, the newest release the group passed around; update it.\n"
        );
    }

    #[test]
    fn hubs_in_the_table() {
        let d = |id: &str, hub, forward_only| Device {
            id: id.into(),
            name: id.into(),
            os: "linux".into(),
            role: "member".into(),
            listed: true,
            hub,
            forward_only,
            ..Default::default()
        };
        let mut w = String::new();
        write_devices(&mut w, &[d("deck", true, false), d("nas", true, true), d("pi", false, false)], &[], "0.6.0", 0);
        let line = |id: &str| w.lines().find(|l| l.starts_with(id)).unwrap_or_default().to_string();
        assert!(line("deck").contains("member, hub "), "{w}");
        assert!(line("nas").contains("member, hub that only passes copies on"), "{w}");
        assert!(!line("pi").contains("hub"), "{w}");
    }

    #[test]
    fn durations() {
        assert_eq!(roughly(3 * 24 * 3_600_000), "3 days");
        assert_eq!(roughly(5 * 3_600_000), "5 hours");
        assert_eq!(roughly(10 * 60_000), "10 minutes");
        assert_eq!(roughly(30_000), "a minute");
    }

    #[test]
    fn no_group() {
        let st = Status { version: "cbb dev".into(), ..Default::default() };
        assert_eq!(
            write_status(&st, &[], 0, ""),
            "cbb dev\nNot in a group. Run cbb new here to start one, or cbb pair to join one.\n"
        );
    }
}
