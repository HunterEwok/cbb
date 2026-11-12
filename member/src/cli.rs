// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The command line's commands that change the group or this device's
//! settings, as the Go cbb's (cmd/cbb): each sends one request to the
//! service and says what it did, in the same words.

use crate::control::{Header, Message};
use crate::error::{Error, Result};
use crate::{Global, flag, request};

/// A usage error: main prints it and exits with 2, as the Go cbb.
pub(crate) fn usage(msg: impl Into<String>) -> Error {
    Error::msg(format!("usage: {}", msg.into()))
}

/// Reports whether an error is a usage error.
pub(crate) fn is_usage(e: &Error) -> bool {
    e.message().starts_with("usage: ")
}

/// Whether a command's only argument asks for its usage, which no device's
/// name or ID can be taken for (Go's helpFlag).
fn help_flag(a: &str) -> bool {
    matches!(a, "-h" | "-help" | "--help")
}

/// One request with the header h, its answer.
fn ask(g: &Global, h: Header) -> Result<Message> {
    request(g, &Message::new(h, Vec::new()))
}

fn header(op: &str) -> Header {
    Header { op: op.into(), ..Default::default() }
}

/// The one argument that names a device, or the usage.
fn one_device<'a>(args: &'a [String], use_: &str) -> Result<&'a str> {
    match args {
        [a] if !help_flag(a) => Ok(a),
        _ => Err(usage(use_)),
    }
}

/// cbb remove.
pub(crate) fn remove(g: &Global, args: &[String]) -> Result<()> {
    let name = one_device(args, "cbb remove <name or device ID>; cbb status lists them")?;
    let m = ask(g, Header { device: name.into(), ..header("remove") })?;
    println!(
        "{}",
        tr!("Removed {} from the group. The other members refuse it as soon as they hear of it.", m.header.name)
    );
    Ok(())
}

/// cbb rename, on an admin.
pub(crate) fn rename(g: &Global, args: &[String]) -> Result<()> {
    let [name, new_name] = args else {
        return Err(usage("cbb rename <name or device ID> <new name>; cbb status lists them"));
    };
    let m = ask(g, Header { device: name.clone(), name: new_name.clone(), ..header("rename") })?;
    println!(
        "{}",
        tr!(
            "Renamed {} to {}. The other devices show the new name as soon as they hear of it.",
            m.header.name,
            new_name.trim()
        )
    );
    Ok(())
}

/// cbb takeover, on an admin, or -delay on the root.
pub(crate) fn takeover(g: &Global, args: &[String]) -> Result<()> {
    if args.first().is_some_and(|a| a == "-delay") {
        let [d] = &args[1..] else {
            return Err(usage("cbb takeover -delay <duration>, from 0s to 168h, as 72h"));
        };
        if help_flag(d) {
            return Err(usage("cbb takeover -delay <duration>, from 0s to 168h, as 72h"));
        }
        ask(g, Header { value: d.clone(), ..header("takeover_delay") })?;
        println!(
            "{}",
            tr!("A claim to take the group over now waits {} on each member, from when it first holds the claim.", d)
        );
        return Ok(());
    }
    let name = one_device(args, "cbb takeover <name or device ID of the lost root>; cbb status shows it")?;
    let m = ask(g, Header { device: name.into(), ..header("take_over") })?;
    println!(
        "{}",
        tr!(
            "Claimed the group from {}. This device becomes its root when the waiting time ends (72 hours unless the root set another), unless the root cancels the claim; cbb status shows the time left.",
            m.header.name
        )
    );
    println!("{}", tr!("Then it removes the old root."));
    Ok(())
}

/// This device's status, or an error in no group.
fn status_in_group(g: &Global) -> Result<crate::control::Status> {
    let m = ask(g, header("status"))?;
    m.header.status.filter(|s| !s.group.is_empty()).ok_or_else(|| Error::msg(tr!("this device is in no group")))
}

/// cbb incoming: shows or sets how long a copy from another device stays
/// live after it arrives.
pub(crate) fn incoming(g: &Global, args: &[String]) -> Result<()> {
    const USE: &str = "cbb incoming [duration], from 5s to 1h, as 1m";
    match args {
        [] => {
            let s = status_in_group(g)?;
            println!("{}", incoming_line(s.incoming_ms));
        }
        [a] if !help_flag(a) => {
            let ms = crate::go_duration_ms(a).ok_or_else(|| usage(USE))?;
            ask(g, Header { value: a.clone(), ..header("incoming") })?;
            println!("{}", incoming_line(ms));
        }
        _ => return Err(usage(USE)),
    }
    Ok(())
}

/// What happens to a copy from another device (Go's incomingLine).
fn incoming_line(ms: i64) -> String {
    let mut s = go_duration(ms);
    if s.ends_with("m0s") {
        s.truncate(s.len() - 2);
    }
    if s.ends_with("h0m") {
        s.truncate(s.len() - 2);
    }
    tr!(
        "A copy from another device goes into the clipboard for {} after it arrives; after that this device keeps its own clipboard, however old.",
        s
    )
}

/// A duration in milliseconds as Go's time.Duration prints it: 72h0m0s,
/// 1m0s, 5s, 500ms, 0s.
pub(crate) fn go_duration(ms: i64) -> String {
    if ms == 0 {
        return "0s".into();
    }
    if ms.abs() < 1000 {
        return format!("{ms}ms");
    }
    let sign = if ms < 0 { "-" } else { "" };
    let ms = ms.abs();
    let (h, m, sec, rest) = (ms / 3_600_000, ms / 60_000 % 60, ms / 1000 % 60, ms % 1000);
    let secs =
        if rest == 0 { format!("{sec}s") } else { format!("{sec}.{}s", format!("{rest:03}").trim_end_matches('0')) };
    match (h, m) {
        (0, 0) => format!("{sign}{secs}"),
        (0, _) => format!("{sign}{m}m{secs}"),
        _ => format!("{sign}{h}h{m}m{secs}"),
    }
}

/// cbb keys: shows the group's key level, or sets it on the root.
pub(crate) fn keys(g: &Global, args: &[String]) -> Result<()> {
    match args {
        [] => {
            let s = status_in_group(g)?;
            println!("{}", key_level_line(&s.key_level));
        }
        [a] if !help_flag(a) => {
            let m = ask(g, Header { value: a.clone(), ..header("key_level") })?;
            println!("{}", key_level_line(a));
            if !m.header.below.is_empty() {
                println!(
                    "{}",
                    tr!(
                        "Below it: {}. They stay until you remove them (cbb remove) or take back their admin or hub role.",
                        m.header.below.join(", ")
                    )
                );
            }
        }
        _ => return Err(usage("cbb keys [proven|hardware|files]")),
    }
    Ok(())
}

/// What the group's key level lets in (Go's keyLevelLine).
pub(crate) fn key_level_line(level: &str) -> &'static str {
    match level {
        "proven" => tr!(
            "Key level proven: only keys that attestation proves are in hardware may be the group's root, an admin or a hub."
        ),
        "hardware" => tr!(
            "Key level hardware: only keys in hardware (a TPM, the Secure Enclave, a phone's keystore) may be the group's root, an admin or a hub."
        ),
        "files" => {
            tr!("Key level files: keys in files may be the group's root, an admin or a hub too, each after a warning.")
        }
        _ => "",
    }
}

/// cbb global hubs: the group's main hubs, in the order they serve.
pub(crate) fn hubs(g: &Global, args: &[String]) -> Result<()> {
    if args.is_empty() || matches!(args, [a] if help_flag(a)) {
        return Err(usage("cbb global hubs <name or ID>..., the group's main hubs in the order they serve"));
    }
    ask(g, Header { hubs: args.to_vec(), ..header("hubs") })?;
    println!(
        "{}",
        tr!("The group's main hubs are now {}, in this order; the other hubs serve after them.", args.join(", "))
    );
    Ok(())
}

/// cbb freeze and cbb unfreeze.
pub(crate) fn freeze(g: &Global, args: &[String], on: bool) -> Result<()> {
    let (op, cmd) = if on { ("freeze", "freeze") } else { ("thaw", "unfreeze") };
    let name = one_device(args, &format!("cbb {cmd} <name or device ID>; cbb status lists them"))?;
    let m = ask(g, Header { device: name.into(), ..header(op) })?;
    if on {
        println!(
            "{}",
            tr!(
                "Froze {}: it is no admin and the members refuse it as soon as they hear of it.\nThe group's root or an admin phone unfreezes it (cbb unfreeze) or removes it (cbb remove).",
                m.header.name
            )
        );
    } else {
        println!("{}", tr!("Unfroze {}: it is an admin again.", m.header.name));
    }
    Ok(())
}

/// cbb admin, on the group's root.
pub(crate) fn admin(g: &Global, args: &[String]) -> Result<()> {
    const USE: &str = "cbb admin [-allow-file-key] <name or device ID>; cbb status lists them";
    let mut allow = false;
    let mut names = Vec::new();
    for a in args {
        match flag(a) {
            Some("allow-file-key") => allow = true,
            Some(_) if names.is_empty() => return Err(usage(USE)),
            _ => names.push(a.clone()),
        }
    }
    let [name] = names.as_slice() else { return Err(usage(USE)) };
    let m = ask(g, Header { device: name.clone(), allow_file_key: allow, ..header("make_admin") })?;
    println!("{}", tr!("{} is an admin now: it can admit and remove devices.", m.header.name));
    if allow {
        println!(
            "{}",
            tr!(
                "If it keeps its keys in a file, guard it: whoever copies that file acts as an admin until another admin removes {}.",
                m.header.name
            )
        );
    }
    Ok(())
}

/// cbb resolve, on the group's root.
pub(crate) fn resolve(g: &Global, args: &[String]) -> Result<()> {
    if !args.is_empty() {
        return Err(usage(
            "cbb resolve; on the group's root, it voids both histories of every key that signed two (cbb status shows them)",
        ));
    }
    let m = ask(g, header("resolve"))?;
    println!(
        "{}",
        tr!(
            "Voided both histories of {}: each goes on from the record before them, and signs again what it still needs.\nCheck that the group's devices are the ones you expect (cbb status): records signed with a stolen key are gone too.",
            m.header.name
        )
    );
    Ok(())
}

/// cbb handover, on the group's root.
pub(crate) fn handover(g: &Global, args: &[String]) -> Result<()> {
    let name = one_device(
        args,
        "cbb handover <name or device ID of an admin>; on the group's root, it lets that admin take the group over at once",
    )?;
    let m = ask(g, Header { device: name.into(), ..header("hand_over") })?;
    println!(
        "{}",
        tr!(
            "Handed the group over to {}: when it claims the group, its claim takes effect at once and it becomes the root.",
            m.header.name
        )
    );
    Ok(())
}

/// cbb mute and cbb unmute, on an admin.
pub(crate) fn mute(g: &Global, args: &[String], unmute: bool) -> Result<()> {
    let use_ = if unmute { "cbb unmute -on DEVICE" } else { "cbb mute -on DEVICE [-for DURATION]" };
    let (mut on, mut for_ms) = (String::new(), 0i64);
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match flag(a) {
            Some("on") => on = it.next().cloned().ok_or_else(|| usage(use_))?,
            Some("for") if !unmute => {
                let d = it.next().ok_or_else(|| usage(use_))?;
                for_ms = crate::go_duration_ms(d).ok_or_else(|| usage(use_))?;
                if !(1..=crate::mute::MAX_MS).contains(&for_ms) {
                    return Err(usage(format!("-for is from 1ms to {}", go_duration(crate::mute::MAX_MS))));
                }
            }
            _ => return Err(usage(use_)),
        }
    }
    if on.is_empty() {
        return Err(usage(format!("{use_}\ncbb sync off turns this device's own sync off.")));
    }
    let op = if unmute { "unmute" } else { "mute" };
    ask(g, Header { device: on.clone(), for_ms, ..header(op) })?;
    if unmute {
        println!("{}", tr!("{} is no longer muted: its copies reach the group again.", on));
    } else if for_ms > 0 {
        let until = local_minute(crate::uptime::wall_ms() + for_ms);
        println!("{}", tr!("{} is muted until {}: its copies do not reach the group.", on, until));
    } else {
        println!("{}", tr!("{} is muted until an admin unmutes it: its copies do not reach the group.", on));
    }
    Ok(())
}

/// A moment as Go's "2006-01-02 15:04" in local time.
pub(crate) fn local_minute(ms: i64) -> String {
    let t = crate::sys::local_time_at(ms);
    format!("{:04}-{:02}-{:02} {:02}:{:02}", t.year, t.month, t.day, t.hour, t.minute)
}

/// cbb config: shows or sets the largest copy of images and files.
pub(crate) fn config(g: &Global, args: &[String]) -> Result<()> {
    let (name, value) = match args {
        [] => (String::new(), String::new()),
        [n, v] => (n.clone(), v.clone()),
        _ => {
            return Err(usage("cbb config\n       cbb config max-copy|max-copy-away SIZE (such as 200MiB)"));
        }
    };
    let m = ask(g, Header { name, value, ..header("config") })?;
    let media = m.header.status.and_then(|s| s.media).ok_or_else(|| {
        Error::msg(tr!("this device is in no group; run cbb new here to start one, or cbb pair to join one"))
    })?;
    println!(
        "{}",
        tr!(
            "max-copy       {}  the largest copy of images and files this device sends or fetches at home",
            crate::copies::size_text(media.max_copy)
        )
    );
    println!("{}", tr!("max-copy-away  {}  the same away from home", crate::copies::size_text(media.max_copy_away)));
    Ok(())
}

/// cbb network: takes this network as one where the group is.
pub(crate) fn network(g: &Global, args: &[String]) -> Result<()> {
    if !args.is_empty() {
        return Err(usage("cbb network"));
    }
    ask(g, header("network"))?;
    println!(
        "{}",
        tr!("This network is one where the group is now: this computer publishes itself and takes connections here.")
    );
    Ok(())
}

/// cbb new: a group with this computer as its root.
pub(crate) fn new(g: &Global, args: &[String]) -> Result<()> {
    if !args.is_empty() {
        return Err(usage("new takes no arguments"));
    }
    let m = ask(g, header("new"))?;
    let s = m.header.status.unwrap_or_default();
    println!("{}", tr!("Created the group {}; this computer is its root.", s.group));
    println!(
        "{}",
        tr!(
            "Its root key is a file here: guard this computer, since whoever copies the file can act as the group's root. A group made on a phone keeps its root key in the phone's hardware."
        )
    );
    if !s.key_problem.is_empty() {
        println!("{}", tr!("This computer's own key is in a file too, although it has a TPM: {}.", s.key_problem));
    }
    if s.key_level == "files" {
        println!(
            "{}",
            tr!(
                "So the group's key level is files: an admin or a hub may keep its keys in a file too, each after a warning (cbb keys)."
            )
        );
    }
    println!(
        "{}",
        tr!("Add a device: on it, join a group, which shows a code; then type that code here with cbb pair -qr.")
    );
    Ok(())
}

/// The most cbb recovery reads: the QR code's text with its admin CA fits
/// well within it, as the core's own limit.
const MAX_SHEET_TEXT: usize = 4096;

/// One line of standard input without echo where it is a terminal, at most
/// limit bytes, trimmed, as Go's readSecretLine.
fn read_secret_line(limit: usize) -> Result<String> {
    use std::io::{BufRead, Read};
    let _quiet = crate::sys::NoEcho::new();
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .take(limit as u64 + 1)
        .read_line(&mut line)
        .map_err(|e| Error::with("cannot read standard input", e))?;
    if line.trim_end_matches(['\r', '\n']).len() > limit {
        return Err(Error::msg(format!("that is longer than {limit} characters")));
    }
    Ok(line.trim().to_string())
}

/// cbb recovery: claims the group with its recovery key, typed from the
/// sheet or its QR code's text, or on a YubiKey with -yubikey, as Go's
/// cmdRecovery. The key comes from standard input, never the command line.
pub(crate) fn recovery(g: &Global, args: &[String]) -> Result<()> {
    use std::io::IsTerminal;
    let mut h = Header { kind: "secret".into(), ..header("recover") };
    match args {
        [] => {}
        [a] if flag(a) == Some("yubikey") => h.name = "yubikey".into(),
        _ => {
            return Err(usage(
                "cbb recovery [-yubikey], then type the recovery key from the sheet (or paste its QR code's text), or with -yubikey the YubiKey's PIN; cbb status shows the claim",
            ));
        }
    }
    let terminal = std::io::stdin().is_terminal();
    let card = h.name == "yubikey";
    if terminal {
        if card {
            eprint!(
                "{}",
                tr!("Plug in the YubiKey with the group's recovery key, then type its PIN and press Enter: ")
            );
        } else {
            eprintln!(
                "{}",
                tr!(
                    "Type the recovery key from the sheet, in groups of four, or paste the text of its QR code, then press Enter (it does not show):"
                )
            );
        }
    }
    let text = read_secret_line(if card { 64 } else { MAX_SHEET_TEXT })?;
    if text.is_empty() {
        return Err(usage(if card { "no PIN was typed" } else { "no recovery key was typed" }));
    }
    if card && terminal {
        eprintln!("{}", tr!("Touch the YubiKey when it blinks."));
    }
    request(g, &Message::new(h, text.into_bytes()))?;
    println!(
        "{}",
        tr!(
            "Claimed the group with its recovery key. This device becomes the group's root when the waiting time ends (72 hours unless the root set another), unless the root phone cancels the claim; cbb status shows the time left."
        )
    );
    println!(
        "{}",
        tr!("Then a new phone joins it (cbb pair -admin), and cbb handover gives that phone the group at once.")
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_print_as_go_does() {
        for (ms, want) in [
            (0, "0s"),
            (500, "500ms"),
            (5_000, "5s"),
            (60_000, "1m0s"),
            (90_000, "1m30s"),
            (3_600_000, "1h0m0s"),
            (72 * 3_600_000, "72h0m0s"),
            (1_500, "1.5s"),
        ] {
            assert_eq!(go_duration(ms), want);
        }
    }

    #[test]
    fn incoming_line_drops_zero_units() {
        assert!(incoming_line(60_000).contains(" for 1m after"));
        assert!(incoming_line(3_600_000).contains(" for 1h after"));
        assert!(incoming_line(5_000).contains(" for 5s after"));
        assert!(incoming_line(90_000).contains(" for 1m30s after"));
    }

    #[test]
    fn usage_errors_are_told_apart() {
        assert!(is_usage(&usage("cbb network")));
        assert!(!is_usage(&Error::msg("this device is in no group")));
    }
}
