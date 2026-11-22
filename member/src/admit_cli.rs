// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The command line's admitting commands, as the Go cbb's (cmd/cbb): cbb
//! pair on the group's root or an admin, which opens a pairing window, and
//! cbb invite, a remote invitation
//! the admin confirms here.

use std::io::{BufRead, Read, Write};

use crate::cli::usage;
use crate::control::{self, Header, Message, Reader};
use crate::error::{Context, Error, Result};
use crate::sys::UnixStream;
use crate::{Global, check, flag, open, request};

/// The longest line cbb pair -code reads: a window's QR code text, with
/// its addresses, ID and key, with room to spare.
const MAX_QR_TEXT: usize = 1024;

/// How long an invitation is valid by default, and at most, as Go's
/// invite.DefaultLifetime and invite.MaxLifetime.
const INVITE_LIFETIME_MS: i64 = 3_600_000;
const INVITE_MAX_MS: i64 = 24 * 3_600_000;

/// The file cbb invite writes by default, as Go's defaultInviteFile.
const INVITE_FILE: &str = "cbb.cbbinvite";

/// A request on its own connection, for the operations that answer more
/// than once: the writer, the reader and the first answer.
pub(crate) fn stream(g: &Global, mut h: Header) -> Result<(UnixStream, Reader<UnixStream>, Message)> {
    let conn = open(g, &mut h)?;
    let mut w = conn.try_clone().context("cannot reach the service")?;
    control::write(&mut w, &Message::new(h, Vec::new()))?;
    let mut r = Reader::new(conn);
    let first = check(next(&mut r)?)?;
    Ok((w, r, first))
}

/// The service's next message on r.
pub(crate) fn next(r: &mut Reader<UnixStream>) -> Result<Message> {
    r.read()?.ok_or_else(|| Error::msg("the service closed the connection"))
}

/// A line from standard input, at most max bytes, without its line ending.
fn read_line(max: usize) -> Result<String> {
    let mut line = String::new();
    std::io::stdin().lock().take(max as u64 + 1).read_line(&mut line).context("cannot read standard input")?;
    if line.len() > max {
        return Err(Error::msg(format!("the input is longer than {max} bytes")));
    }
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

/// Whether standard input is a terminal, where a prompt helps.
fn interactive() -> bool {
    use std::io::IsTerminal;
    std::io::stdin().is_terminal()
}

/// cbb pair in a group, on its root or an admin: a window opens for a new
/// device; -admin, on the root, makes the phone that joins an admin; -app
/// FILE writes the window into an app's file instead of the terminal. -qr
/// admitted a device that waited for the group to dial it, which is gone
/// on 0.6 (D-119).
pub(crate) fn pair(g: &Global, args: &[String]) -> Result<()> {
    let (mut admins, mut app) = (false, None);
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match flag(a) {
            Some("admin") => admins = true,
            Some("app") => app = Some(it.next().cloned().ok_or_else(|| usage(PAIR_USAGE))?),
            Some("qr") => return Err(Error::msg(crate::service::on_live::LISTENING_JOINER_GONE)),
            _ => return Err(usage(PAIR_USAGE)),
        }
    }
    match app {
        Some(app) => window_app(g, admins, &app),
        None => window(g, admins),
    }
}

/// What cbb pair takes, as Go's pairUsage.
pub(crate) const PAIR_USAGE: &str =
    "cbb pair [-admin] [-app FILE]   in a group, on its root or an admin: open a pairing
                                window with six digits and a QR code; -admin, on the root,
                                makes the phone that joins an admin; -app writes the window
                                into an app's FILE
       cbb pair -code [address:port]   in no group: join a pairing window by its six digits
       cbb pair -invite FILE    in no group: join from afar with an invitation";

/// Opens a pairing window and waits for the device that joins with its
/// code.
fn window(g: &Global, admins: bool) -> Result<()> {
    let (_w, mut r, m) = stream(g, Header { op: "pair".into(), admins, ..Default::default() })?;
    if m.header.kind != HOME_WINDOW {
        return Err(Error::msg(NO_HOME_WINDOW));
    }
    if admins {
        println!("The phone that joins with this code becomes an admin of the group. It may then");
        println!("add, remove and renew devices, freeze other admins and choose the hub. Give");
        println!("the code only to your own phone.");
        println!();
    }
    home_window(g, &mut r, &m)
}

/// Why a window that is not of 0.6 opens nothing.
const NO_HOME_WINDOW: &str = "the service opened no pairing window of a group of 0.6";

/// cbb pair -app FILE: the window as one line of JSON in the app's own
/// file (code, the six digits; qr, the QR code's text; address; expires,
/// its seconds), rewritten with refused when a device fails and done and
/// name when one joins. Removing the file closes the window.
fn window_app(g: &Global, admins: bool, app: &str) -> Result<()> {
    let out = std::sync::Mutex::new(crate::open_app_file(app)?);
    let (_w, mut r, m) = stream(g, Header { op: "pair".into(), admins, ..Default::default() })?;
    if m.header.kind != HOME_WINDOW {
        return Err(Error::msg(NO_HOME_WINDOW));
    }
    let base = serde_json::json!({
        "code": m.header.code,
        "qr": m.header.invite,
        "address": m.header.address,
        "expires": m.header.expires,
    });
    let write = |extra: serde_json::Value| -> Result<()> {
        let mut line = base.clone();
        if let (Some(o), Some(e)) = (line.as_object_mut(), extra.as_object()) {
            o.extend(e.clone());
        }
        let mut f = out.lock().unwrap_or_else(|e| e.into_inner());
        f.set_len(0)
            .and_then(|_| std::io::Seek::rewind(&mut *f))
            .and_then(|_| f.write_all(format!("{line}\n").as_bytes()))
            .and_then(|_| f.sync_all())
            .context("cannot write the pairing window")
    };
    write(serde_json::json!({}))?;
    crate::watch_app_file(app.to_string());
    loop {
        let m = check(next(&mut r)?)?;
        if m.header.done {
            return write(serde_json::json!({"done": true, "name": m.header.name}));
        }
        if m.header.refused {
            write(serde_json::json!({"refused": m.header.detail}))?;
        }
    }
}

/// The kind of the answer that opens a home window of a group of 0.6.
pub(crate) const HOME_WINDOW: &str = "home-window";

/// A home window of a group of 0.6 (docs/protocol.md, "Pairing in 0.6"):
/// its six digits and its QR code, which carries them for a phone; each
/// device that fails is told here, and the third failure closes the
/// window.
fn home_window(g: &Global, r: &mut Reader<UnixStream>, m: &Message) -> Result<()> {
    let code = &m.header.code;
    let (a, b) = code.split_at(3.min(code.len()));
    println!("Pairing code: {a} {b}\n");
    if !m.header.invite.is_empty() && !m.header.address.is_empty() {
        print!("{}", crate::qr(&m.header.invite));
        println!("\nOn a phone, scan this QR code in the app.");
    }
    println!("On the new computer run cbb pair -code and type the code.");
    // Six digits name no window: without mDNS the new computer finds the
    // window by its QR code's text, which carries its addresses, ID and
    // key (cbb pair -code ADDRESS dials another address for it).
    match (m.header.address.is_empty(), m.header.invite.is_empty()) {
        (false, false) => {
            println!(
                "If it cannot find this one: cbb pair -code {}, and type this line instead of the code:",
                m.header.address
            );
            println!("  {}", m.header.invite);
        }
        (true, false) => {
            println!("If it cannot find this one, type this line instead of the code:");
            println!("  {}", m.header.invite);
        }
        (false, true) => println!("If it cannot find this one: cbb pair -code {}", m.header.address),
        (true, true) => {}
    }
    println!("\nWaiting up to {} minutes. Press Ctrl+C to cancel.", m.header.expires / 60);
    loop {
        std::io::stdout().flush().ok();
        let m = check(next(r)?)?;
        if m.header.done {
            println!("{} joined the group.", m.header.name);
            admin_hint(g);
            return Ok(());
        }
        if m.header.refused {
            println!("A device did not pair: {}", m.header.detail);
            println!("The window stays open; a wrong code spends one of three tries.");
        }
    }
}

/// The six digits a home window shows (spaces dropped), or its QR code's
/// text, from standard input, with a prompt on a terminal.
pub(crate) fn window_code() -> Result<cbb_core::secret::Zeroizing<String>> {
    if interactive() {
        print!("The six digits the pairing window shows (or its QR code's text): ");
        std::io::stdout().flush().ok();
    }
    let line = cbb_core::secret::Zeroizing::new(read_line(MAX_QR_TEXT)?);
    let text = line.trim();
    if text.starts_with(cbb_core::join::invitation::WINDOW_PREFIX) {
        return Ok(cbb_core::secret::Zeroizing::new(text.to_string()));
    }
    let digits: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    if cbb_core::join::invitation::home_secret(&digits).is_none() {
        return Err(Error::msg(
            "type the six digits the pairing window shows (cbb pair on the group's root or an admin), or its QR code's text",
        ));
    }
    Ok(cbb_core::secret::Zeroizing::new(digits))
}

/// Suggests a second admin when this computer, the root, is the group's
/// only one, as Go's adminHint.
fn admin_hint(g: &Global) {
    let Ok(m) = request(g, &Message::new(Header { op: "devices".into(), ..Default::default() }, Vec::new())) else {
        return;
    };
    let devs = &m.header.devices;
    if devs.iter().any(|d| d.admin && !d.root) || !devs.iter().any(|d| d.this && d.root) {
        return;
    }
    println!("This computer is the group's only admin. Make another computer one with cbb admin NAME,");
    println!("so that it can take the group over if this one is lost (cbb takeover).");
}

/// cbb invite: a remote invitation as a QR code and in a file, valid for a
/// while, and the confirmation here of the device that uses it. On an
/// admin that is not the hub it goes through a hub, the first connected
/// one or -hub's.
pub(crate) fn invite(g: &Global, args: &[String]) -> Result<()> {
    const USE: &str =
        "cbb invite [-phone] [-for 1h] [-o file | -app FILE -answers FILE] [-hub DEVICE]   (valid for up to 24h)";
    let (mut valid, mut out, mut hub) = (INVITE_LIFETIME_MS, INVITE_FILE.to_string(), String::new());
    let mut phone = false;
    let (mut app, mut answers) = (None, None);
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match flag(a) {
            Some("for") => {
                valid = it.next().and_then(|d| crate::go_duration_ms(d)).ok_or_else(|| usage(USE))?;
            }
            Some("o") => out = it.next().cloned().ok_or_else(|| usage(USE))?,
            Some("hub") => hub = it.next().cloned().ok_or_else(|| usage(USE))?,
            Some("phone") => phone = true,
            Some("app") => app = Some(it.next().cloned().ok_or_else(|| usage(USE))?),
            Some("answers") => answers = Some(it.next().cloned().ok_or_else(|| usage(USE))?),
            _ => return Err(usage(USE)),
        }
    }
    if valid <= 0 || valid > INVITE_MAX_MS || app.is_some() != answers.is_some() {
        return Err(usage(USE));
    }
    // A group of 0.6 invites a computer, or with -phone a phone.
    let kind = if phone { "phone".to_string() } else { String::new() };
    let h = Header { op: "invite".into(), expires: valid / 1000, device: hub, kind, ..Default::default() };
    if let (Some(app), Some(answers)) = (app, answers) {
        return invite_app(g, h, &app, &answers);
    }
    let (mut w, mut r, m) = stream(g, h)?;
    // The file is a secret until it is used: only its owner reads it, and
    // it never replaces another file.
    write_new(&out, &format!("{}\n", m.header.invite)).context("writing the invitation")?;
    let _remove = Removed(out.clone());
    on_interrupt(&out);
    let until = crate::sys::local_time_at(crate::uptime::wall_ms() + m.header.expires * 1000);
    println!(
        "The invitation is valid until {:02}:{:02} on {} {}.\n",
        until.hour,
        until.minute,
        MONTHS[(until.month as usize).clamp(1, 12) - 1],
        until.day
    );
    // A group of 0.6 invites one kind of device: a computer, or a phone.
    let only = m.header.invite.starts_with(cbb_core::join::invitation::PREFIX);
    if !only || phone {
        println!("On a new phone, open the CBB app, tap Join with an invitation and scan this:\n");
        print!("{}", crate::qr(&m.header.invite));
    }
    if !only || !phone {
        println!("\nSend it in the file {out}. On the new computer run:");
        println!("\n  cbb pair -invite {out}\n");
    }
    println!("Pass the code or the file only through a channel you trust: until it is used,");
    println!("whoever has it can ask to join.");
    println!("You confirm the device here before it is admitted. Keep this running; Ctrl+C");
    println!("cancels the invitation, and the file is deleted when it ends.");
    loop {
        std::io::stdout().flush().ok();
        let m = check(next(&mut r)?)?;
        if m.header.done {
            println!("{} joined the group.", m.header.name);
            return Ok(());
        }
        if m.header.refused {
            println!("\nA device tried the invitation and was not admitted: {}", m.header.detail);
            println!("The invitation stays open for another attempt.");
            continue;
        }
        let Some(j) = m.header.joining else { continue };
        println!("\n{} ({}, device {}) used the invitation.", j.name, crate::status_text::os_name(&j.os), j.id);
        println!("Its key fingerprint:  {}", j.fingerprint.get(..23).unwrap_or(&j.fingerprint));
        println!("The new device shows its fingerprint too; admit it only if they are the same.");
        print!("Admit it? Type yes to admit: ");
        std::io::stdout().flush().ok();
        let yes = read_line(256).is_ok_and(|l| l.trim().eq_ignore_ascii_case("yes"));
        control::write(
            &mut w,
            &Message::new(Header { op: "answer".into(), consent: yes, ..Default::default() }, Vec::new()),
        )?;
        if !yes {
            println!("Not admitted. The invitation stays open for another attempt.");
        }
    }
}

/// cbb invite -app: the desktop apps' invitation, as cbb runs as the
/// administrator for them. The app makes both files; cbb writes the
/// invitation's state into app, one line of JSON each time it changes
/// ({"invite","expires"}, with "joining" {"name","os","id","fingerprint"}
/// while it asks, and "done" with "name" at the end), and reads the user's
/// answers, a line of yes or no each, from answers. Removing app cancels.
fn invite_app(g: &Global, h: Header, app: &str, answers: &str) -> Result<()> {
    let out = std::sync::Mutex::new(crate::open_app_file(app)?);
    // Opened now, as app is, so that no link put in its place later counts.
    let mut answers = crate::open_app_file_read(answers)?;
    let (mut w, mut r, m) = stream(g, h)?;
    let (text, expires) = (m.header.invite.clone(), m.header.expires);
    let write = |extra: serde_json::Value| -> Result<()> {
        let mut line = serde_json::json!({"invite": text, "expires": expires});
        if let (Some(o), Some(e)) = (line.as_object_mut(), extra.as_object()) {
            o.extend(e.clone());
        }
        let mut f = out.lock().unwrap_or_else(|e| e.into_inner());
        f.set_len(0)
            .and_then(|_| std::io::Seek::rewind(&mut *f))
            .and_then(|_| f.write_all(format!("{line}\n").as_bytes()))
            .and_then(|_| f.sync_all())
            .context("cannot write the invitation")
    };
    write(serde_json::json!({}))?;
    crate::watch_app_file(app.to_string());
    let mut used = 0;
    loop {
        let m = check(next(&mut r)?)?;
        if m.header.done {
            write(serde_json::json!({"done": true, "name": m.header.name}))?;
            return Ok(());
        }
        let Some(j) = m.header.joining else { continue };
        write(serde_json::json!({"joining": {"name": j.name, "os": j.os, "id": j.id, "fingerprint": j.fingerprint}}))?;
        let yes = next_answer(&mut answers, &mut used)?;
        control::write(
            &mut w,
            &Message::new(Header { op: "answer".into(), consent: yes, ..Default::default() }, Vec::new()),
        )?;
        write(serde_json::json!({}))?;
    }
}

/// The app's next answer in its answers file, the line after the used
/// ones: waits for it as long as the service waits for the user.
fn next_answer(f: &mut std::fs::File, used: &mut usize) -> Result<bool> {
    let until = std::time::Instant::now() + crate::pair::CONFIRM_WAIT + std::time::Duration::from_secs(10);
    loop {
        let mut all = String::new();
        std::io::Seek::rewind(f).context("cannot read the answers")?;
        Read::by_ref(f).take(64 * 1024).read_to_string(&mut all).context("cannot read the answers")?;
        // A line counts once it is whole: a later one, or the newline, ends it.
        if let Some(line) = all.lines().nth(*used)
            && (all.ends_with('\n') || all.lines().count() > *used + 1)
        {
            *used += 1;
            return Ok(line.trim().eq_ignore_ascii_case("yes"));
        }
        if std::time::Instant::now() > until {
            *used = all.lines().count();
            return Ok(false);
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}

/// The months as Go's time layout "Jan" names them.
const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/// Writes a new file only its owner reads; an existing one stays.
fn write_new(path: &str, text: &str) -> std::io::Result<()> {
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
    let mut f = o.open(path)?;
    // On Windows the file would take its folder's access list: it is
    // narrowed to its owner before the invitation goes in.
    #[cfg(windows)]
    if let Err(e) = crate::sys::owner_only(std::path::Path::new(path)) {
        drop(f);
        let _ = std::fs::remove_file(path);
        return Err(std::io::Error::other(e.for_log()));
    }
    f.write_all(text.as_bytes())?;
    f.sync_all()
}

/// Removes the invitation's file when cbb invite ends.
struct Removed(String);

impl Drop for Removed {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// The invitation's file, for Ctrl+C.
static INVITATION: std::sync::OnceLock<std::ffi::CString> = std::sync::OnceLock::new();

/// What Ctrl+C says once it cancelled the invitation.
const CANCELLED: &[u8] = b"\nThe invitation is cancelled and its file deleted.\n";

/// Has Ctrl+C, or a stop, delete the invitation's file at path before the
/// process ends: the invitation goes with the connection.
fn on_interrupt(path: &str) {
    let Ok(c) = std::ffi::CString::new(path) else { return };
    if INVITATION.set(c).is_err() {
        return;
    }
    #[cfg(unix)]
    {
        extern "C" fn cancel(_: libc::c_int) {
            // Only what is safe in a signal handler.
            unsafe {
                if let Some(p) = INVITATION.get() {
                    libc::unlink(p.as_ptr());
                }
                libc::write(1, CANCELLED.as_ptr().cast(), CANCELLED.len());
                libc::_exit(130);
            }
        }
        unsafe {
            libc::signal(libc::SIGINT, cancel as *const () as libc::sighandler_t);
            libc::signal(libc::SIGTERM, cancel as *const () as libc::sighandler_t);
        }
    }
    #[cfg(windows)]
    {
        unsafe extern "system" fn cancel(_: u32) -> windows_sys::core::BOOL {
            if let Some(p) = INVITATION.get() {
                let _ = std::fs::remove_file(p.to_string_lossy().as_ref());
            }
            let _ = std::io::stdout().write_all(CANCELLED);
            std::process::exit(130);
        }
        unsafe {
            windows_sys::Win32::System::Console::SetConsoleCtrlHandler(Some(cancel), 1);
        }
    }
}
