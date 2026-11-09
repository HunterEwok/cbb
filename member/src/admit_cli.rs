// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The command line's admitting commands, as the Go cbb's (cmd/cbb): cbb
//! pair on the group's root or an admin, which opens a pairing window or
//! admits a device that shows a code, and cbb invite, a remote invitation
//! the admin confirms here.

use std::io::{BufRead, Read, Write};

use crate::cli::usage;
use crate::control::{self, Header, Message, Reader};
use crate::error::{Context, Error, Result};
use crate::sys::UnixStream;
use crate::{Global, check, flag, open, request};

/// The longest text cbb pair -qr reads: a code, four addresses and a
/// fingerprint, with room to spare.
const MAX_QR_TEXT: usize = 1024;

/// How long an invitation is valid by default, and at most, as Go's
/// invite.DefaultLifetime and invite.MaxLifetime.
const INVITE_LIFETIME_MS: i64 = 3_600_000;
const INVITE_MAX_MS: i64 = 24 * 3_600_000;

/// The file cbb invite writes by default, as Go's defaultInviteFile.
const INVITE_FILE: &str = "cbb.cbbinvite";

/// A request on its own connection, for the operations that answer more
/// than once: the writer, the reader and the first answer.
fn stream(g: &Global, h: Header) -> Result<(UnixStream, Reader<UnixStream>, Message)> {
    let conn = open(g, &h)?;
    let mut w = conn.try_clone().context("cannot reach the service")?;
    control::write(&mut w, &Message::new(h, Vec::new()))?;
    let mut r = Reader::new(conn);
    let first = check(next(&mut r)?)?;
    Ok((w, r, first))
}

/// The service's next message on r.
fn next(r: &mut Reader<UnixStream>) -> Result<Message> {
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

/// cbb pair in a group, on its root or an admin: -qr admits the device
/// that shows a code, or else a window opens for a new computer; -admin, on
/// the root, makes the phone that joins an admin.
pub(crate) fn pair(g: &Global, args: &[String]) -> Result<()> {
    let (mut admins, mut qr) = (false, false);
    for a in args {
        match flag(a) {
            Some("admin") => admins = true,
            Some("qr") => qr = true,
            _ => return Err(usage(PAIR_USAGE)),
        }
    }
    if !qr {
        return window(g, admins);
    }
    // From standard input, never the command line, where other users
    // could read the code.
    if interactive() {
        print!("The code the new device shows, or its QR code's text: ");
        std::io::stdout().flush().ok();
    }
    let text = read_line(MAX_QR_TEXT)?;
    if let Ok(code) = cbb_core::pair::normalize_code(&text) {
        println!("Looking for the device that shows the code {} {}...", &code[..3], &code[3..]);
        let m =
            request(g, &Message::new(Header { op: "pair".into(), code, admins, ..Default::default() }, Vec::new()))?;
        println!("{} joined the group.", m.header.name);
        return Ok(());
    }
    let link = cbb_core::pair::parse_join_qr(&text).map_err(|_| {
        Error::msg("neither the six-digit code nor the QR code of a device that waits to join (cbb://join?...)")
    })?;
    if admins {
        println!("The phone that joins now becomes an admin of the group. It may then add, remove");
        println!("and renew devices, freeze other admins, choose the hub, and take the group over");
        println!("from this computer after the takeover delay. Admit only your own phone.");
        println!();
    }
    let (a, b) = link.code.split_at(3.min(link.code.len()));
    println!("Admitting the device at {} with the code {a} {b}...", link.addrs.join(", "));
    let h = Header {
        op: "pair".into(),
        code: link.code,
        addrs: link.addrs,
        fingerprint: link.fingerprint,
        admins,
        ..Default::default()
    };
    let m = request(g, &Message::new(h, Vec::new()))?;
    println!("{} joined the group.", m.header.name);
    Ok(())
}

/// What cbb pair takes, as Go's pairUsage.
pub(crate) const PAIR_USAGE: &str = "cbb pair                  in a group: show a code for a new computer;
                                in no group: join by the phone's QR code or a typed code
       cbb pair -admin          on the group's root: show a code for a phone with the app,
                                which joins as an admin
       cbb pair -qr [-admin]    on the root or an admin: admit the device that shows a QR
                                code and a code and waits, the code or the QR code's text read
                                from standard input; with -admin, on the root, the phone
                                becomes an admin
       cbb pair -code [address:port]   join with the code, read from standard input";

/// Opens a pairing window and waits for the device that joins with its
/// code, as Go's admit.
fn window(g: &Global, admins: bool) -> Result<()> {
    let (_w, mut r, m) = stream(g, Header { op: "pair".into(), admins, ..Default::default() })?;
    if admins {
        println!("The phone that joins with this code becomes an admin of the group. It may then");
        println!("add, remove and renew devices, freeze other admins, choose the hub, and take");
        println!("the group over from this computer after the takeover delay. Give the code only");
        println!("to your own phone.");
        println!();
    }
    let code = &m.header.code;
    let (a, b) = code.split_at(3.min(code.len()));
    println!("Pairing code: {a} {b}\n");
    if admins {
        println!("In the phone's app, choose to join a computer's group and type the code.");
    } else {
        println!("On the new computer run cbb pair and type the code.");
    }
    if !m.header.address.is_empty() {
        println!("If it cannot find this one: cbb pair -code {}", m.header.address);
    }
    println!("\nWaiting up to {} minutes. Press Ctrl+C to cancel.", m.header.expires / 60);
    std::io::stdout().flush().ok();
    let m = check(next(&mut r)?)?;
    println!("{} joined the group.", m.header.name);
    admin_hint(g);
    Ok(())
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
        "cbb invite [-for 1h] [-o file | -app FILE -answers FILE] [-hub DEVICE]   (valid for up to 24h)";
    let (mut valid, mut out, mut hub) = (INVITE_LIFETIME_MS, INVITE_FILE.to_string(), String::new());
    let (mut app, mut answers) = (None, None);
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match flag(a) {
            Some("for") => {
                valid = it.next().and_then(|d| crate::go_duration_ms(d)).ok_or_else(|| usage(USE))?;
            }
            Some("o") => out = it.next().cloned().ok_or_else(|| usage(USE))?,
            Some("hub") => hub = it.next().cloned().ok_or_else(|| usage(USE))?,
            Some("app") => app = Some(it.next().cloned().ok_or_else(|| usage(USE))?),
            Some("answers") => answers = Some(it.next().cloned().ok_or_else(|| usage(USE))?),
            _ => return Err(usage(USE)),
        }
    }
    if valid <= 0 || valid > INVITE_MAX_MS || app.is_some() != answers.is_some() {
        return Err(usage(USE));
    }
    let h = Header { op: "invite".into(), expires: valid / 1000, device: hub, ..Default::default() };
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
    println!("On a new phone, open the CBB app, tap Join with an invitation and scan this:\n");
    print!("{}", crate::qr(&m.header.invite));
    println!("\nOr send it in the file {out}. On a new computer run:");
    println!("\n  cbb pair -invite {out}\n");
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
    let until = std::time::Instant::now() + crate::window::CONFIRM_WAIT + std::time::Duration::from_secs(10);
    loop {
        let mut all = String::new();
        std::io::Seek::rewind(f).context("cannot read the answers")?;
        Read::by_ref(f).take(64 * 1024).read_to_string(&mut all).context("cannot read the answers")?;
        if let Some(line) = all.lines().nth(*used) {
            if all.ends_with('\n') || all.lines().count() > *used + 1 {
                *used += 1;
                return Ok(line.trim().eq_ignore_ascii_case("yes"));
            }
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
