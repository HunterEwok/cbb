// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Confirming an admin action that comes on the control socket
//! (docs/design.md, "Confirming admin actions"). What changes the group
//! goes to the admin socket, which only root reaches (D-62); a user of the
//! apps confirms it instead with the system's own prompt, without running
//! cbb as the administrator: Touch ID or the password on a Mac, polkit's
//! dialog on Linux, Windows Hello on Windows. One confirmation lasts five
//! minutes for the group's everyday changes; what cannot be undone, or
//! changes who holds the group, asks every time.
//!
//! The service checks the confirmation itself, from the system, never from
//! what the caller claims: on a Mac the caller's authorization (its external
//! form in the request's `auth`) must hold the right, on Linux polkit must
//! authorize the calling process, which the kernel names, and on Windows the
//! request carries a Windows Hello signature of a challenge the service gave,
//! by the key the user's account registered once as the administrator.

// FreeBSD keeps the administrator's way.
#![cfg_attr(not(any(target_os = "macos", target_os = "linux", windows)), allow(dead_code))]

use crate::control::{Header, op};
use crate::error::{Error, Result};
#[cfg_attr(not(target_os = "linux"), allow(unused_imports))]
use crate::sys::UnixStream;

/// How long one confirmation of an everyday change lasts, in seconds.
#[cfg_attr(not(any(target_os = "macos", windows)), allow(dead_code))]
pub const KEEP_SECS: u32 = 300;

/// What the service says when the user cancelled the prompt; cbb then exits
/// with CANCELLED_EXIT, and the apps say nothing.
pub const CANCELLED: &str = "the confirmation was cancelled";
/// What the service says when nothing here confirms an admin action for
/// this user (no polkit, no prompt in the session, a user who may not);
/// cbb then exits with NEED_ADMIN_EXIT, and the apps run it as the
/// administrator instead.
pub const UNAVAILABLE: &str =
    "this computer cannot confirm the admin action for this user, so only the administrator may run it";

pub const CANCELLED_EXIT: i32 = 75;
pub const NEED_ADMIN_EXIT: i32 = 77;

/// The right, or polkit action, that one confirmation for five minutes
/// gives.
pub const RIGHT_KEPT: &str = "tools.cbb.admin";
/// The right that is asked for each time.
pub const RIGHT_EACH: &str = "tools.cbb.admin.each";

/// The operations confirmed each time: making a group, leaving it, taking
/// it over or handing it on, recovering its root, making a device an admin,
/// the settings that decide who may hold the group, and what lets another
/// device in for good or sends this device's copies elsewhere: admitting a
/// device here or by an invitation, joining a group, a hub and sync away
/// from home, taking remote pastes, and pairing a Bluetooth keyboard or a
/// TV's remote, which type what the group sends.
pub const EACH_TIME: [&str; 16] = [
    op::NEW,
    op::LEAVE,
    op::TAKE_OVER,
    op::RECOVER,
    op::HAND_OVER,
    op::KEY_LEVEL,
    op::TAKEOVER_DELAY,
    op::MAKE_ADMIN,
    "pair",
    "join",
    "invite",
    "away",
    "hubs",
    "paste_receive",
    "keyboard",
    "remote",
];

/// The group's everyday changes, which one confirmation covers for five
/// minutes: none of them lets a device in or sends copies anywhere new.
/// Every other operation, also one added later and not listed here, is
/// confirmed each time.
pub const KEPT: [&str; 18] = [
    "sync",
    "mute",
    "unmute",
    "rename",
    "remove",
    "freeze",
    "thaw",
    "resolve",
    "incoming",
    "network",
    "paste_on",
    "action_set",
    "action_remove",
    "action_on",
    "actions_off",
    "release_file",
    "release_want",
    "update_way",
];

/// Whether op is confirmed each time: those of EACH_TIME, and every
/// operation but the everyday ones of KEPT.
pub fn each_time(op: &str) -> bool {
    EACH_TIME.contains(&op) || !KEPT.contains(&op)
}

/// The right op takes.
pub fn right(op: &str) -> &'static str {
    if each_time(op) { RIGHT_EACH } else { RIGHT_KEPT }
}

/// The exit code of cbb for an error that comes from confirming.
pub fn exit_code(e: &Error) -> Option<i32> {
    match e.message() {
        CANCELLED => Some(CANCELLED_EXIT),
        UNAVAILABLE => Some(NEED_ADMIN_EXIT),
        m if m == crate::awaynet::NEED_ROOT => Some(NEED_ADMIN_EXIT),
        _ => None,
    }
}

/// The prompt's text for the right, in English; the catalogs translate it
/// (`member/l10n`), and the system shows the user's language.
pub fn prompt(right: &str) -> &'static str {
    if right == RIGHT_EACH { PROMPT_EACH } else { PROMPT_KEPT }
}

const PROMPT_KEPT: &str = "Confirm a change to your CBB group.";
const PROMPT_EACH: &str = "Confirm an important change to your CBB group: it cannot be undone.";

/// What the prompt names besides its text: the action and the device or
/// value it is for, as cbb's command line would put them, so that the user
/// sees what they confirm. Only printable characters, at most 80 of them:
/// the names come from the caller.
pub fn action(h: &Header) -> String {
    let mut out = format!("cbb {}", h.op.replace('_', "-"));
    for part in [&h.name, &h.device] {
        if !part.is_empty() {
            out.push(' ');
            out.push_str(part);
        }
    }
    let mut clean: String = out.chars().filter(|c| !c.is_control()).collect();
    if clean.chars().count() > 80 {
        clean = clean.chars().take(79).collect();
        clean.push('…');
    }
    clean
}

/// The prompt's text for h in the user's language, and on a line of its
/// own the action it confirms.
#[cfg_attr(not(any(target_os = "macos", windows)), allow(dead_code))]
pub fn prompt_for(h: &Header) -> String {
    let text = prompt(right(&h.op));
    format!("{}\n\n{}", crate::l10n::text(text), action(h))
}

/// How a user's prompts are paced: one at a time, and after a cancelled
/// one a pause that doubles up to five minutes, so that a program cannot
/// show prompt after prompt until one is answered by mistake.
pub struct Pace {
    users: std::sync::Mutex<std::collections::HashMap<String, PaceState>>,
}

#[derive(Default)]
struct PaceState {
    busy: bool,
    until: Option<std::time::Instant>,
    pause: std::time::Duration,
}

/// The first pause after a cancelled prompt, and the longest.
const FIRST_PAUSE: std::time::Duration = std::time::Duration::from_secs(5);
const LONGEST_PAUSE: std::time::Duration = std::time::Duration::from_secs(300);

/// What the service says while a user's prompt waits, or pauses.
pub const BUSY: &str = "another confirmation is waiting, or one was just cancelled; try again in a moment";

impl Default for Pace {
    fn default() -> Self {
        Self::new()
    }
}

impl Pace {
    pub fn new() -> Self {
        Pace { users: std::sync::Mutex::new(std::collections::HashMap::new()) }
    }

    /// Starts a prompt for user, or says BUSY.
    pub fn begin(&self, user: &str, now: std::time::Instant) -> Result<()> {
        let mut g = self.users.lock().unwrap_or_else(|e| e.into_inner());
        // Users whose pause is over and who wait for nothing are forgotten.
        g.retain(|_, s| s.busy || s.until.is_some_and(|t| now < t + LONGEST_PAUSE));
        let s = g.entry(user.to_string()).or_default();
        if s.busy || s.until.is_some_and(|t| now < t) {
            return Err(Error::msg(BUSY));
        }
        s.busy = true;
        Ok(())
    }

    /// Ends user's prompt with its result: a cancelled one pauses the
    /// next, a confirmed one ends the pauses.
    pub fn end(&self, user: &str, res: &Result<()>, now: std::time::Instant) {
        let mut g = self.users.lock().unwrap_or_else(|e| e.into_inner());
        let s = g.entry(user.to_string()).or_default();
        s.busy = false;
        match res {
            Ok(()) => {
                s.until = None;
                s.pause = std::time::Duration::ZERO;
            }
            Err(e) if e.message() == CANCELLED => {
                s.pause = if s.pause.is_zero() { FIRST_PAUSE } else { (s.pause * 2).min(LONGEST_PAUSE) };
                s.until = Some(now + s.pause);
            }
            Err(_) => {}
        }
    }
}

/// Marks the prompts for the catalogs, which take what tr! names
/// (l10n.rs, catalogs_are_complete).
#[cfg(test)]
fn _catalog_marks() -> [&'static str; 2] {
    [
        tr!("Confirm a change to your CBB group."),
        tr!("Confirm an important change to your CBB group: it cannot be undone."),
    ]
}

/// The prompt in each language of the project: the language's code ("" for
/// English) and the text.
pub fn prompts(right: &str) -> Vec<(&'static str, &'static str)> {
    let english = prompt(right);
    let mut out = vec![("", english)];
    for lang in crate::l10n::LANGS {
        out.push((lang, crate::l10n::lookup(lang, english).unwrap_or(english)));
    }
    out
}

/// Whether cbb confirms an admin action itself on this system, instead of
/// running as the administrator.
pub fn supported() -> bool {
    cfg!(any(target_os = "macos", target_os = "linux", all(windows, feature = "tunnel")))
}

/// The service's check of the admin request h, which came on the control
/// socket on conn, accepted at `accepted` (clock()): Ok when the user at
/// the screen confirmed it.
#[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
pub fn check(conn: &UnixStream, h: &Header, accepted: u64) -> Result<()> {
    #[cfg(target_os = "macos")]
    return mac::check(&h.auth, right(&h.op));
    #[cfg(target_os = "linux")]
    return linux::check(conn, h, accepted);
    #[cfg(all(windows, feature = "tunnel"))]
    return win::check(conn, h);
    #[cfg(not(any(target_os = "macos", target_os = "linux", all(windows, feature = "tunnel"))))]
    Err(Error::msg(UNAVAILABLE))
}

/// When a connection came, for check: on Linux the clock ticks after boot,
/// as a process's start time counts them; 0 elsewhere, where it is not
/// needed.
pub fn clock() -> u64 {
    #[cfg(target_os = "linux")]
    return linux::now_ticks();
    #[cfg(not(target_os = "linux"))]
    0
}

/// The operations of confirming on the control socket that take no admin:
/// on Windows, the challenge to sign (`confirm`); everywhere else nothing.
pub const OP_CHALLENGE: &str = "confirm";
/// The administrator's registration of a user's Windows Hello key, on the
/// admin socket.
pub const OP_REGISTER: &str = "confirm_key";

/// The service's answer to a confirm request on conn (OP_CHALLENGE), or to
/// a registration on the admin socket (OP_REGISTER).
#[cfg_attr(not(all(windows, feature = "tunnel")), allow(unused_variables))]
pub fn answer(conn: &UnixStream, h: &Header) -> Result<crate::control::Message> {
    #[cfg(all(windows, feature = "tunnel"))]
    return if h.op == OP_REGISTER { win::register(h) } else { win::challenge(conn, h) };
    #[cfg(not(all(windows, feature = "tunnel")))]
    Err(Error::msg(UNAVAILABLE))
}

/// Sets up what the prompts need when the service starts: the rights on a
/// Mac, the polkit actions on Linux. A failure is logged and leaves the
/// administrator's way.
#[cfg_attr(not(all(windows, feature = "tunnel")), allow(unused_variables))]
pub fn install(log: &dyn Fn(&str), state: &std::path::Path) {
    #[cfg(all(windows, feature = "tunnel"))]
    win::install(state);
    #[cfg(target_os = "macos")]
    if let Err(e) = mac::install() {
        log(&format!("cbb: the rights that confirm admin actions: {}", e.for_log()));
    }
    #[cfg(target_os = "linux")]
    if let Err(e) = linux::install(std::path::Path::new(linux::ACTIONS_DIR), &linux::service_user()) {
        log(&format!("cbb: the polkit actions that confirm admin actions: {}", e.for_log()));
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let _ = log;
}

/// cbb confirm-setup [USER], which the installer runs as root: writes the
/// rights on a Mac and the polkit actions on Linux, for a service that
/// runs as USER (cbb unless named) and so cannot write them itself.
pub fn setup_cli(args: &[String]) -> Result<()> {
    let user = match args {
        [] => "cbb".to_string(),
        [u] if !u.is_empty() && u.chars().all(|c| c.is_ascii_alphanumeric() || "_-.".contains(c)) => u.clone(),
        _ => return Err(Error::msg("usage: cbb confirm-setup [USER]")),
    };
    // SAFETY: geteuid has no preconditions and cannot fail.
    #[cfg(unix)]
    if unsafe { libc::geteuid() } != 0 {
        return Err(Error::msg("cbb confirm-setup writes the system's settings, so it runs as root"));
    }
    #[cfg(target_os = "linux")]
    return linux::install(std::path::Path::new(linux::ACTIONS_DIR), &user);
    // A Mac's rights name no owner: the service checks a caller's own
    // authorization.
    #[cfg(not(target_os = "linux"))]
    {
        let _ = user;
        #[cfg(target_os = "macos")]
        mac::install()?;
        Ok(())
    }
}

/// Fills in h.auth before cbb sends an admin request on the control socket:
/// on a Mac it asks for the right first, so the prompt comes from cbb
/// itself, in the user's session; on Windows it signs the service's
/// challenge with Windows Hello, which ask sends for (a request on the
/// control socket); on Linux it says when cbb started, which polkit checks.
#[cfg_attr(not(all(windows, feature = "tunnel")), allow(unused_variables))]
pub fn prepare(h: &mut Header, ask: &dyn Fn(Header) -> Result<Header>) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        h.auth = mac::authorize(right(&h.op), &prompt_for(h))?;
    }
    #[cfg(all(windows, feature = "tunnel"))]
    win::prepare(h, ask)?;
    #[cfg(target_os = "linux")]
    {
        h.auth = linux::start_time(std::process::id() as i32)
            .ok_or_else(|| Error::msg("cannot read when cbb started").context(UNAVAILABLE))?
            .to_string();
    }
    Ok(())
}

/// cbb confirm-key SID KEY, which cbb runs as the administrator through
/// UAC to register the user's Windows Hello key (OP_REGISTER), and cbb
/// confirm-key -remove SID, which removes it.
#[cfg_attr(not(all(windows, feature = "tunnel")), allow(unused_variables))]
pub fn register_cli(args: &[String], request: &dyn Fn(Header) -> Result<Header>) -> Result<()> {
    let (sid, key) = match args {
        [flag, sid] if flag == "-remove" => (sid, String::new()),
        [sid, key] if !key.is_empty() && !sid.starts_with('-') => (sid, key.clone()),
        _ => return Err(Error::msg("usage: cbb confirm-key SID KEY\n       cbb confirm-key -remove SID")),
    };
    request(Header { op: OP_REGISTER.into(), name: sid.clone(), value: key, ..Default::default() })?;
    Ok(())
}

/// What a confirmation on Windows signs: the action the user was shown
/// (action, with its device or name) and the service's challenge, after a
/// fixed prefix that nothing else signs. The service derives the action
/// from the request itself, so a signature for one action confirms no
/// other.
#[cfg_attr(not(all(windows, feature = "tunnel")), allow(dead_code))]
pub fn hello_message(h: &Header, challenge: &[u8]) -> Vec<u8> {
    let mut m = b"cbb confirm v2\n".to_vec();
    m.extend_from_slice(action(h).as_bytes());
    m.push(b'\n');
    m.extend_from_slice(challenge);
    m
}

/// polkit's action file, with one action for each right. Each message
/// ends with the action it confirms ($(cbb_action), the detail the service
/// passes), and the service's user `owner` may ask polkit about another
/// user's process (org.freedesktop.policykit.owner), which polkit allows
/// only root otherwise.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn polkit_policy(owner: &str) -> String {
    let mut out = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE policyconfig PUBLIC \"-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN\"\n \
         \"http://www.freedesktop.org/standards/PolicyKit/1/policyconfig.dtd\">\n\
         <!-- Written by cbb (docs/design.md, \"Confirming admin actions\"). -->\n\
         <policyconfig>\n  <vendor>CBB</vendor>\n  <vendor_url>https://cbb.tools</vendor_url>\n",
    );
    for (right, keep) in [(RIGHT_KEPT, true), (RIGHT_EACH, false)] {
        out.push_str(&format!("  <action id=\"{right}\">\n"));
        for (lang, text) in prompts(right) {
            let attr = if lang.is_empty() { String::new() } else { format!(" xml:lang=\"{lang}\"") };
            out.push_str(&format!("    <message{attr}>{} $(cbb_action)</message>\n", xml_escape(text)));
        }
        let active = if keep { "auth_admin_keep" } else { "auth_admin" };
        out.push_str(&format!(
            "    <defaults>\n      <allow_any>no</allow_any>\n      <allow_inactive>no</allow_inactive>\n      \
             <allow_active>{active}</allow_active>\n    </defaults>\n"
        ));
        if !owner.is_empty() {
            out.push_str(&format!(
                "    <annotate key=\"org.freedesktop.policykit.owner\">unix-user:{}</annotate>\n",
                xml_escape(owner)
            ));
        }
        out.push_str("  </action>\n");
    }
    out.push_str("</policyconfig>\n");
    out
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

#[cfg(target_os = "linux")]
mod linux {
    use std::os::fd::AsRawFd;
    use std::path::Path;
    use std::process::{Command, Stdio};

    use super::{CANCELLED, UNAVAILABLE};
    use crate::error::{Context, Error, Result};
    use crate::sys::UnixStream;

    /// Where polkit reads the actions.
    pub const ACTIONS_DIR: &str = "/usr/share/polkit-1/actions";
    const FILE: &str = "tools.cbb.admin.policy";

    /// Writes the actions where polkit reads them, unless they are there
    /// already; nothing on a system without polkit.
    pub fn install(dir: &Path, owner: &str) -> Result<()> {
        if !dir.is_dir() {
            return Ok(());
        }
        let path = dir.join(FILE);
        let want = super::polkit_policy(owner);
        if std::fs::read_to_string(&path).is_ok_and(|have| have == want) {
            return Ok(());
        }
        let tmp = dir.join(format!(".{FILE}.{}", std::process::id()));
        std::fs::write(&tmp, &want).context(format!("cannot write {}", tmp.display()))?;
        std::fs::rename(&tmp, &path).map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            Error::msg(format!("cannot move the actions to {}: {e}", path.display()))
        })
    }

    /// Asks polkit whether the process at the other end of conn may take
    /// the action, letting it ask the user in the session: pkcheck with the
    /// process's ID and user, which the kernel gives, and the start time
    /// the process sent in its request (prepare). polkit checks all three
    /// against the process itself, so another process cannot pass for it;
    /// and a start time after the connection came is refused, so a process
    /// that took the ID of one that connected and left is never asked
    /// about. The service reads nothing of another user's process: its
    /// unit hides them (ProtectProc=invisible).
    pub fn check(conn: &UnixStream, h: &super::Header, accepted: u64) -> Result<()> {
        let Some((pid, uid)) = peer(conn) else { return Err(Error::msg(UNAVAILABLE)) };
        let Some(start) = h.auth.parse::<u64>().ok().filter(|&s| s > 0 && s <= accepted) else {
            return Err(Error::msg("the request did not say when its process started").context(UNAVAILABLE));
        };
        let action = super::right(&h.op);
        let out = match Command::new(pkcheck())
            .args(["--action-id", action, "--process", &format!("{pid},{start},{uid}")])
            .args(["--detail", DETAIL, &super::action(h), "--allow-user-interaction"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
        {
            Ok(o) => o,
            Err(e) => return Err(Error::msg(format!("pkcheck: {e}")).context(UNAVAILABLE)),
        };
        verdict(out.status.code(), &String::from_utf8_lossy(&out.stderr))
    }

    /// The user the service runs as, who owns the actions; none for root,
    /// which polkit lets ask anyway.
    pub fn service_user() -> String {
        // SAFETY: geteuid has no preconditions; getpwuid_r writes into pw
        // and buf, which live for the call, and the name it points at lies
        // in buf.
        unsafe {
            let uid = libc::geteuid();
            if uid == 0 {
                return String::new();
            }
            let mut pw: libc::passwd = std::mem::zeroed();
            let mut buf = vec![0 as libc::c_char; 4096];
            let mut out: *mut libc::passwd = std::ptr::null_mut();
            if libc::getpwuid_r(uid, &mut pw, buf.as_mut_ptr(), buf.len(), &mut out) != 0 || out.is_null() {
                return String::new();
            }
            std::ffi::CStr::from_ptr(pw.pw_name).to_string_lossy().into_owned()
        }
    }

    /// The detail that names the action in polkit's dialog, as $(cbb_action)
    /// in the actions' messages.
    pub const DETAIL: &str = "cbb_action";

    /// Now, in the clock ticks after boot that a process's start time
    /// counts (CLOCK_BOOTTIME, as /proc/PID/stat).
    pub fn now_ticks() -> u64 {
        let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        // SAFETY: ts is valid for the call to write; sysconf has no
        // preconditions.
        let (ok, hz) =
            unsafe { (libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) == 0, libc::sysconf(libc::_SC_CLK_TCK)) };
        if !ok || hz <= 0 {
            return 0;
        }
        // Rounded up: a process that started in this tick is not after now.
        ts.tv_sec as u64 * hz as u64 + (ts.tv_nsec as u64 * hz as u64).div_ceil(1_000_000_000)
    }

    /// pkcheck's answer: 0 authorized, 3 the dialog dismissed; 1 and 2 not
    /// authorized (no agent in the session, a user who may not), the rest
    /// an error.
    pub fn verdict(code: Option<i32>, stderr: &str) -> Result<()> {
        match code {
            Some(0) => Ok(()),
            Some(3) => Err(Error::msg(CANCELLED)),
            _ => Err(Error::msg(format!("pkcheck exited with {code:?}: {}", stderr.trim())).context(UNAVAILABLE)),
        }
    }

    /// pkcheck from the system's own directories, never from PATH.
    fn pkcheck() -> &'static str {
        ["/usr/bin/pkcheck", "/bin/pkcheck"].into_iter().find(|p| Path::new(p).exists()).unwrap_or("/usr/bin/pkcheck")
    }

    /// The process and user at the other end of conn, from the kernel.
    fn peer(conn: &UnixStream) -> Option<(i32, u32)> {
        let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: cred and len are valid for the kernel to write a ucred,
        // and the descriptor stays open while conn lives.
        let ok = unsafe {
            libc::getsockopt(conn.as_raw_fd(), libc::SOL_SOCKET, libc::SO_PEERCRED, (&raw mut cred).cast(), &mut len)
        } == 0;
        (ok && cred.pid > 0).then_some((cred.pid, cred.uid))
    }

    /// When the process started, in clock ticks after boot: the 22nd field
    /// of /proc/PID/stat, counted after the name in parentheses, which may
    /// hold spaces.
    pub fn start_time(pid: i32) -> Option<u64> {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        parse_start(&stat)
    }

    pub fn parse_start(stat: &str) -> Option<u64> {
        let rest = &stat[stat.rfind(')')? + 1..];
        // After the name: state is field 3, start time field 22.
        rest.split_whitespace().nth(19)?.parse().ok()
    }
}

#[cfg(target_os = "macos")]
mod mac {
    use std::ffi::{CString, c_char, c_long, c_void};

    use base64::Engine as _;

    use super::{CANCELLED, KEEP_SECS, RIGHT_EACH, RIGHT_KEPT, UNAVAILABLE};
    use crate::error::{Error, Result};
    use crate::sekey::CFDictionaryCallBacks;

    type OSStatus = i32;
    type AuthorizationRef = *mut c_void;
    type CFTypeRef = *const c_void;
    type CFStringRef = CFTypeRef;
    type CFDictionaryRef = CFTypeRef;

    #[repr(C)]
    struct AuthorizationItem {
        name: *const c_char,
        value_length: usize,
        value: *mut c_void,
        flags: u32,
    }

    #[repr(C)]
    struct AuthorizationRights {
        count: u32,
        items: *mut AuthorizationItem,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct AuthorizationExternalForm {
        bytes: [u8; 32],
    }

    const INTERACTION_ALLOWED: u32 = 1 << 0;
    const EXTEND_RIGHTS: u32 = 1 << 1;
    const ERR_CANCELED: OSStatus = -60006;
    const ERR_DENIED: OSStatus = -60005;
    const K_CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;
    const K_CF_NUMBER_INT_TYPE: c_long = 9;

    #[link(name = "Security", kind = "framework")]
    unsafe extern "C" {
        fn AuthorizationCreate(
            rights: *const AuthorizationRights,
            env: *const c_void,
            flags: u32,
            out: *mut AuthorizationRef,
        ) -> OSStatus;
        fn AuthorizationCopyRights(
            a: AuthorizationRef,
            rights: *const AuthorizationRights,
            env: *const c_void,
            flags: u32,
            out: *mut *mut AuthorizationRights,
        ) -> OSStatus;
        fn AuthorizationMakeExternalForm(a: AuthorizationRef, out: *mut AuthorizationExternalForm) -> OSStatus;
        fn AuthorizationCreateFromExternalForm(
            form: *const AuthorizationExternalForm,
            out: *mut AuthorizationRef,
        ) -> OSStatus;
        fn AuthorizationFree(a: AuthorizationRef, flags: u32) -> OSStatus;
        fn AuthorizationRightSet(
            a: AuthorizationRef,
            right: *const c_char,
            definition: CFTypeRef,
            description_key: CFStringRef,
            bundle: CFTypeRef,
            table: CFStringRef,
        ) -> OSStatus;
        fn AuthorizationRightGet(right: *const c_char, definition: *mut CFDictionaryRef) -> OSStatus;
    }

    /// The environment item that gives the prompt's text.
    const ENV_PROMPT: &[u8] = b"prompt\0";

    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        static kCFTypeDictionaryKeyCallBacks: CFDictionaryCallBacks;
        static kCFTypeDictionaryValueCallBacks: CFDictionaryCallBacks;
        static kCFBooleanTrue: CFTypeRef;
        static kCFBooleanFalse: CFTypeRef;
        fn CFRelease(cf: CFTypeRef);
        fn CFStringCreateWithCString(a: CFTypeRef, s: *const c_char, enc: u32) -> CFStringRef;
        fn CFNumberCreate(a: CFTypeRef, t: c_long, v: *const c_void) -> CFTypeRef;
        fn CFDictionaryCreate(
            a: CFTypeRef,
            keys: *const CFTypeRef,
            values: *const CFTypeRef,
            n: c_long,
            kcb: *const CFDictionaryCallBacks,
            vcb: *const CFDictionaryCallBacks,
        ) -> CFDictionaryRef;
    }

    /// Owns Core Foundation objects and releases them when dropped.
    struct Owned(Vec<CFTypeRef>);

    impl Owned {
        fn keep(&mut self, cf: CFTypeRef) -> Result<CFTypeRef> {
            if cf.is_null() {
                return Err(Error::msg("Core Foundation could not make an object"));
            }
            self.0.push(cf);
            Ok(cf)
        }

        fn string(&mut self, s: &str) -> Result<CFStringRef> {
            let c = CString::new(s).map_err(|_| Error::msg("a text with a NUL"))?;
            // SAFETY: c is a NUL-terminated UTF-8 string that outlives the call.
            let cf = unsafe { CFStringCreateWithCString(std::ptr::null(), c.as_ptr(), K_CF_STRING_ENCODING_UTF8) };
            self.keep(cf)
        }

        fn dict(&mut self, pairs: &[(CFTypeRef, CFTypeRef)]) -> Result<CFDictionaryRef> {
            let keys: Vec<CFTypeRef> = pairs.iter().map(|p| p.0).collect();
            let values: Vec<CFTypeRef> = pairs.iter().map(|p| p.1).collect();
            // SAFETY: keys and values hold pairs.len() live objects each, and
            // the callbacks are Core Foundation's own statics.
            let cf = unsafe {
                CFDictionaryCreate(
                    std::ptr::null(),
                    keys.as_ptr(),
                    values.as_ptr(),
                    pairs.len() as c_long,
                    &raw const kCFTypeDictionaryKeyCallBacks,
                    &raw const kCFTypeDictionaryValueCallBacks,
                )
            };
            self.keep(cf)
        }
    }

    impl Drop for Owned {
        fn drop(&mut self) {
            for cf in self.0.drain(..) {
                // SAFETY: each object was created here and is released once.
                unsafe { CFRelease(cf) };
            }
        }
    }

    /// Writes both rights to the authorization database: an administrator
    /// of this Mac (Touch ID where the Mac has it, else the password), for
    /// five minutes in the user's session, or each time. Only root writes
    /// them: for anyone else, changing a right asks for a password that a
    /// service has no screen to show, and the call would wait for ever.
    pub fn install() -> Result<()> {
        // SAFETY: geteuid has no preconditions and cannot fail.
        if unsafe { libc::geteuid() } != 0 {
            return Ok(());
        }
        let mut auth: AuthorizationRef = std::ptr::null_mut();
        // SAFETY: an empty authorization; the service runs as root, which
        // may change the rights.
        let st = unsafe { AuthorizationCreate(std::ptr::null(), std::ptr::null(), 0, &mut auth) };
        if st != 0 {
            return Err(Error::msg(format!("AuthorizationCreate: {st}")));
        }
        let res = (|| {
            for right in [RIGHT_KEPT, RIGHT_EACH] {
                let mut o = Owned(Vec::new());
                let keep = right == RIGHT_KEPT;
                let timeout: i32 = if keep { KEEP_SECS as i32 } else { 0 };
                let mut prompts = Vec::new();
                for (lang, text) in super::prompts(right) {
                    prompts.push((o.string(lang)?, o.string(text)?));
                }
                let prompt = o.dict(&prompts)?;
                // SAFETY: timeout lives for the call; the number copies it.
                let timeout = o.keep(unsafe {
                    CFNumberCreate(std::ptr::null(), K_CF_NUMBER_INT_TYPE, (&raw const timeout).cast())
                })?;
                // SAFETY: Core Foundation's boolean constants live forever.
                let (yes, no) = unsafe { (kCFBooleanTrue, kCFBooleanFalse) };
                let pairs = [
                    ("class", o.string("user")?),
                    ("group", o.string("admin")?),
                    ("authenticate-user", yes),
                    ("session-owner", no),
                    ("allow-root", yes),
                    ("shared", if keep { yes } else { no }),
                    ("timeout", timeout),
                    ("default-prompt", prompt),
                    ("comment", o.string("Written by the cbb service: confirms an admin action of CBB.")?),
                ];
                let mut keyed = Vec::with_capacity(pairs.len());
                for (k, v) in pairs {
                    keyed.push((o.string(k)?, v));
                }
                let def = o.dict(&keyed)?;
                let name = CString::new(right).map_err(|_| Error::msg("a right with a NUL"))?;
                let key = o.string(super::prompt(right))?;
                // SAFETY: every argument is a live object or null where the
                // API takes null (no bundle, no table).
                let st =
                    unsafe { AuthorizationRightSet(auth, name.as_ptr(), def, key, std::ptr::null(), std::ptr::null()) };
                if st != 0 {
                    return Err(Error::msg(format!("AuthorizationRightSet {right}: {st}")));
                }
            }
            Ok(())
        })();
        // SAFETY: auth was created above and is freed once.
        unsafe { AuthorizationFree(auth, 0) };
        res
    }

    fn rights_of(name: &CString, item: &mut AuthorizationItem) -> AuthorizationRights {
        *item = AuthorizationItem { name: name.as_ptr(), value_length: 0, value: std::ptr::null_mut(), flags: 0 };
        AuthorizationRights { count: 1, items: item }
    }

    fn status(st: OSStatus, what: &str) -> Result<()> {
        match st {
            0 => Ok(()),
            ERR_CANCELED => Err(Error::msg(CANCELLED)),
            ERR_DENIED => Err(Error::msg(format!("{what}: denied ({st})")).context(UNAVAILABLE)),
            _ => Err(Error::msg(format!("{what}: {st}")).context(UNAVAILABLE)),
        }
    }

    /// cbb's side: an authorization that holds the right, asked for with
    /// the system's prompt in the user's session, as its external form. The
    /// authorization stays for as long as cbb runs, so that the service
    /// finds it.
    pub fn authorize(right: &str, prompt: &str) -> Result<String> {
        let mut auth: AuthorizationRef = std::ptr::null_mut();
        // SAFETY: an empty authorization of this process.
        status(
            unsafe { AuthorizationCreate(std::ptr::null(), std::ptr::null(), 0, &mut auth) },
            "AuthorizationCreate",
        )?;
        let name = CString::new(right).map_err(|_| Error::msg("a right with a NUL"))?;
        let mut item =
            AuthorizationItem { name: std::ptr::null(), value_length: 0, value: std::ptr::null_mut(), flags: 0 };
        let rights = rights_of(&name, &mut item);
        // The prompt names the action (kAuthorizationEnvironmentPrompt).
        let mut text = prompt.as_bytes().to_vec();
        let mut shown = AuthorizationItem {
            name: ENV_PROMPT.as_ptr().cast(),
            value_length: text.len(),
            value: text.as_mut_ptr().cast(),
            flags: 0,
        };
        let env = AuthorizationRights { count: 1, items: &mut shown };
        // SAFETY: rights points at one item whose name lives for the call,
        // and env at one whose name and text do too.
        let st = unsafe {
            AuthorizationCopyRights(
                auth,
                &rights,
                (&raw const env).cast(),
                INTERACTION_ALLOWED | EXTEND_RIGHTS,
                std::ptr::null_mut(),
            )
        };
        status(st, "AuthorizationCopyRights")?;
        let mut form = AuthorizationExternalForm { bytes: [0; 32] };
        // SAFETY: auth is live and form has room for the external form.
        status(unsafe { AuthorizationMakeExternalForm(auth, &mut form) }, "AuthorizationMakeExternalForm")?;
        Ok(base64::engine::general_purpose::STANDARD.encode(form.bytes))
    }

    /// Whether the right is in the authorization database, as the installer
    /// wrote it; a right that is not would fall to the system's default
    /// rule, which is not CBB's.
    fn defined(name: &CString) -> bool {
        let mut def: CFDictionaryRef = std::ptr::null();
        // SAFETY: name is NUL-terminated; def is valid for the call to
        // write, and what it gets is released once.
        let st = unsafe { AuthorizationRightGet(name.as_ptr(), &mut def) };
        if !def.is_null() {
            // SAFETY: the definition was copied for this call.
            unsafe { CFRelease(def) };
        }
        st == 0
    }

    /// The service's side: the caller's authorization, from its external
    /// form, must hold the right, which the installer defined. The service
    /// shows no prompt of its own (it has no screen): a right whose five
    /// minutes passed meanwhile is refused, and cbb asks again.
    pub fn check(auth: &str, right: &str) -> Result<()> {
        let name = CString::new(right).map_err(|_| Error::msg("a right with a NUL"))?;
        if !defined(&name) {
            return Err(
                Error::msg(format!("the right {right} is not set up; run sudo cbb confirm-setup")).context(UNAVAILABLE)
            );
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(auth)
            .ok()
            .filter(|b| b.len() == 32)
            .ok_or_else(|| Error::msg(UNAVAILABLE))?;
        let mut form = AuthorizationExternalForm { bytes: [0; 32] };
        form.bytes.copy_from_slice(&bytes);
        let mut a: AuthorizationRef = std::ptr::null_mut();
        // SAFETY: form holds 32 bytes, as the API reads.
        status(unsafe { AuthorizationCreateFromExternalForm(&form, &mut a) }, "AuthorizationCreateFromExternalForm")?;
        let mut item =
            AuthorizationItem { name: std::ptr::null(), value_length: 0, value: std::ptr::null_mut(), flags: 0 };
        let rights = rights_of(&name, &mut item);
        // SAFETY: a is live, rights points at one item whose name lives for
        // the call.
        let st = unsafe { AuthorizationCopyRights(a, &rights, std::ptr::null(), EXTEND_RIGHTS, std::ptr::null_mut()) };
        // SAFETY: a was made above and is freed once; the caller's own
        // authorization stays.
        unsafe { AuthorizationFree(a, 0) };
        status(st, "AuthorizationCopyRights")
    }
}

#[cfg(all(windows, feature = "tunnel"))]
mod win {
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    use base64::Engine as _;
    use windows::Security::Credentials::{
        KeyCredential, KeyCredentialCreationOption, KeyCredentialManager, KeyCredentialStatus,
    };
    use windows::Security::Cryptography::Core::CryptographicPublicKeyBlobType;
    use windows::Security::Cryptography::CryptographicBuffer;
    use windows::Storage::Streams::IBuffer;
    use windows::core::{Array, HSTRING};

    use super::{CANCELLED, KEEP_SECS, OP_CHALLENGE, RIGHT_KEPT, UNAVAILABLE};
    use crate::control::{Header, Message};
    use crate::error::{Context, Error, Result};
    use crate::sys::UnixStream;

    /// The Windows Hello key's name, the same for every user.
    const KEY_NAME: &str = "tools.cbb.admin";
    /// The users' keys, by SID, in the service's state folder.
    const FILE: &str = "confirm-keys.json";
    /// How long a challenge waits for its signature.
    const CHALLENGE_TIME: Duration = Duration::from_secs(120);
    /// At most this many challenges wait at once; the oldest go first.
    const MAX_CHALLENGES: usize = 32;

    /// At most this many challenges for one user a minute: each shows a
    /// prompt, and a program of the user must not show one after another.
    const CHALLENGES_A_MINUTE: usize = 6;

    struct State {
        dir: PathBuf,
        challenges: Vec<(Vec<u8>, String, String, Instant)>,
        kept: HashMap<String, Instant>,
        /// When each user was last given challenges, within the minute.
        asked: HashMap<String, Vec<Instant>>,
    }

    static STATE: Mutex<Option<State>> = Mutex::new(None);

    pub fn install(dir: &Path) {
        *STATE.lock().unwrap_or_else(|e| e.into_inner()) =
            Some(State { dir: dir.to_path_buf(), challenges: Vec::new(), kept: HashMap::new(), asked: HashMap::new() });
    }

    fn with<T>(f: impl FnOnce(&mut State) -> Result<T>) -> Result<T> {
        let mut g = STATE.lock().unwrap_or_else(|e| e.into_inner());
        f(g.as_mut().ok_or_else(|| Error::msg(UNAVAILABLE))?)
    }

    fn keys(dir: &Path) -> HashMap<String, String> {
        std::fs::read(dir.join(FILE)).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
    }

    /// The user at the screen at the other end of conn, by SID.
    fn user(conn: &UnixStream) -> Result<String> {
        match crate::peer::sid_at_screen(conn) {
            Some((sid, true)) => Ok(sid),
            _ => Err(Error::msg(UNAVAILABLE)),
        }
    }

    fn kept(st: &State, sid: &str, op: &str) -> bool {
        super::right(op) == RIGHT_KEPT && st.kept.get(sid).is_some_and(|t| Instant::now() < *t)
    }

    /// The answer to a confirm request: "kept" while the user's last
    /// confirmation lasts, "register" for a user with no key, else "sign"
    /// with a new challenge for the operation h.value.
    pub fn challenge(conn: &UnixStream, h: &Header) -> Result<Message> {
        let sid = user(conn)?;
        let (name, value) = with(|st| {
            if kept(st, &sid, &h.value) {
                return Ok(("kept", String::new()));
            }
            if !keys(&st.dir).contains_key(&sid) {
                return Ok(("register", String::new()));
            }
            let now = Instant::now();
            st.asked.retain(|_, t| {
                t.retain(|t| now.duration_since(*t) < Duration::from_secs(60));
                !t.is_empty()
            });
            let asked = st.asked.entry(sid.clone()).or_default();
            if asked.len() >= CHALLENGES_A_MINUTE {
                return Err(Error::msg(super::BUSY));
            }
            asked.push(now);
            let mut nonce = vec![0u8; 32];
            getrandom::fill(&mut nonce).map_err(|e| Error::msg(format!("no random numbers: {e}")))?;
            st.challenges.retain(|c| c.3.elapsed() < CHALLENGE_TIME);
            if st.challenges.len() >= MAX_CHALLENGES {
                st.challenges.remove(0);
            }
            st.challenges.push((nonce.clone(), sid.clone(), h.value.clone(), Instant::now()));
            Ok(("sign", base64::engine::general_purpose::STANDARD.encode(nonce)))
        })?;
        let header = Header { op: OP_CHALLENGE.into(), name: name.into(), value, done: true, ..Default::default() };
        Ok(crate::control::reply(header, Vec::new()))
    }

    /// The service's check: the user's last confirmation still lasts, or
    /// h.auth signs a challenge given to this user for this operation, with
    /// the key the user registered.
    pub fn check(conn: &UnixStream, h: &Header) -> Result<()> {
        let sid = user(conn)?;
        // An administrator of this PC now, not only when the key was
        // registered: a user taken out of the Administrators loses it, and
        // the key goes.
        if !administrator(&sid) {
            let _ = with(|st| {
                st.kept.remove(&sid);
                let mut all = keys(&st.dir);
                if all.remove(&sid).is_some() {
                    save(&st.dir, &all)?;
                }
                Ok(())
            });
            return Err(Error::msg("this user is no administrator of this PC").context(UNAVAILABLE));
        }
        with(|st| {
            if kept(st, &sid, &h.op) {
                return Ok(());
            }
            let b64 = &base64::engine::general_purpose::STANDARD;
            let (challenge, sig) = h
                .auth
                .split_once('.')
                .and_then(|(n, s)| Some((b64.decode(n).ok()?, b64.decode(s).ok()?)))
                .ok_or_else(|| Error::msg(UNAVAILABLE))?;
            let at = st
                .challenges
                .iter()
                .position(|c| c.0 == challenge && c.1 == sid && c.2 == h.op && c.3.elapsed() < CHALLENGE_TIME)
                .ok_or_else(|| Error::msg("the confirmation came too late or for another action; try again"))?;
            st.challenges.remove(at);
            let key =
                keys(&st.dir).get(&sid).and_then(|k| b64.decode(k).ok()).ok_or_else(|| Error::msg(UNAVAILABLE))?;
            if !cbb_core::tls::web::verify_rsa_pkcs1_sha256(&key, &super::hello_message(h, &challenge), &sig) {
                return Err(Error::msg("the Windows Hello signature does not match this user's key"));
            }
            if super::right(&h.op) == RIGHT_KEPT {
                st.kept.insert(sid.clone(), Instant::now() + Duration::from_secs(KEEP_SECS.into()));
            }
            Ok(())
        })
    }

    fn save(dir: &Path, all: &HashMap<String, String>) -> Result<()> {
        let data = serde_json::to_vec_pretty(all).map_err(|e| Error::with("encoding the keys", e))?;
        crate::files::write_atomic(&dir.join(FILE), &data, 0o600)
    }

    /// Registers the user h.name's key h.value, on the admin socket, or
    /// with no key removes the user's.
    pub fn register(h: &Header) -> Result<Message> {
        if !h.name.starts_with("S-1-") || h.name.len() > 200 {
            return Err(Error::msg("cbb confirm-key takes the user's SID"));
        }
        if h.value.is_empty() {
            with(|st| {
                st.kept.remove(&h.name);
                let mut all = keys(&st.dir);
                if all.remove(&h.name).is_some() {
                    save(&st.dir, &all)?;
                }
                Ok(())
            })?;
            return Ok(crate::control::reply(Header { done: true, ..Default::default() }, Vec::new()));
        }
        let key = base64::engine::general_purpose::STANDARD
            .decode(&h.value)
            .ok()
            .filter(|k| cbb_core::tls::web::rsa_public_key_ok(k))
            .ok_or_else(|| Error::msg("cbb confirm-key takes an RSA key of 2048 bits or more, in base64"))?;
        // Only an administrator's key confirms an admin action, as an
        // administrator's password does on a Mac and polkit on Linux.
        if !administrator(&h.name) {
            return Err(Error::msg("only an administrator of this PC confirms admin actions of CBB"));
        }
        with(|st| {
            let mut all = keys(&st.dir);
            all.insert(h.name.clone(), base64::engine::general_purpose::STANDARD.encode(key));
            save(&st.dir, &all)?;
            st.kept.remove(&h.name);
            Ok(())
        })?;
        Ok(crate::control::reply(Header { done: true, ..Default::default() }, Vec::new()))
    }

    /// Whether the user sid is a member of this PC's Administrators group,
    /// whose name the system gives for its well-known SID. A member through
    /// a domain's group is not counted: such a user confirms as the
    /// administrator, through UAC.
    fn administrator(sid: &str) -> bool {
        use windows_sys::Win32::Foundation::LocalFree;
        use windows_sys::Win32::NetworkManagement::NetManagement::{
            LOCALGROUP_MEMBERS_INFO_0, MAX_PREFERRED_LENGTH, NetApiBufferFree, NetLocalGroupGetMembers,
        };
        use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
        use windows_sys::Win32::Security::{
            CreateWellKnownSid, LookupAccountSidW, SID_NAME_USE, WinBuiltinAdministratorsSid,
        };
        // SAFETY: every buffer is as large as the call is told; the list
        // NetLocalGroupGetMembers allocates is read within its count and
        // freed, and so is each string the conversion allocates.
        unsafe {
            let mut group = [0u8; 68];
            let mut size = group.len() as u32;
            if CreateWellKnownSid(
                WinBuiltinAdministratorsSid,
                std::ptr::null_mut(),
                group.as_mut_ptr().cast(),
                &mut size,
            ) == 0
            {
                return false;
            }
            let (mut name, mut domain) = ([0u16; 256], [0u16; 256]);
            let (mut nlen, mut dlen) = (name.len() as u32, domain.len() as u32);
            let mut kind: SID_NAME_USE = 0;
            if LookupAccountSidW(
                std::ptr::null(),
                group.as_ptr().cast_mut().cast(),
                name.as_mut_ptr(),
                &mut nlen,
                domain.as_mut_ptr(),
                &mut dlen,
                &mut kind,
            ) == 0
            {
                return false;
            }
            let mut buf: *mut u8 = std::ptr::null_mut();
            let (mut read, mut total, mut resume) = (0u32, 0u32, 0usize);
            if NetLocalGroupGetMembers(
                std::ptr::null(),
                name.as_ptr(),
                0,
                &mut buf,
                MAX_PREFERRED_LENGTH,
                &mut read,
                &mut total,
                &mut resume,
            ) != 0
                || buf.is_null()
            {
                return false;
            }
            let members = std::slice::from_raw_parts(buf as *const LOCALGROUP_MEMBERS_INFO_0, read as usize);
            let mut found = false;
            for m in members {
                let mut p: *mut u16 = std::ptr::null_mut();
                if ConvertSidToStringSidW(m.lgrmi0_sid, &mut p) == 0 {
                    continue;
                }
                let len = (0..).take_while(|&i| *p.add(i) != 0).count();
                found |= String::from_utf16_lossy(std::slice::from_raw_parts(p, len)) == sid;
                LocalFree(p.cast());
            }
            NetApiBufferFree(buf.cast());
            found
        }
    }

    // cbb's side, as the user.

    pub fn prepare(h: &mut Header, ask: &dyn Fn(Header) -> Result<Header>) -> Result<()> {
        let mut registered = false;
        loop {
            let a = ask(Header { op: OP_CHALLENGE.into(), value: h.op.clone(), ..Default::default() })?;
            match a.name.as_str() {
                "kept" => return Ok(()),
                "sign" => {
                    let b64 = &base64::engine::general_purpose::STANDARD;
                    let nonce =
                        b64.decode(&a.value).map_err(|_| Error::msg("the service's challenge is not base64"))?;
                    // Windows Hello's prompt cannot say what it confirms:
                    // CBB says it first.
                    if !agree(&super::prompt_for(h))? {
                        return Err(Error::msg(CANCELLED));
                    }
                    match sign(&super::hello_message(h, &nonce))? {
                        Some(sig) => {
                            h.auth = format!("{}.{}", a.value, b64.encode(sig));
                            return Ok(());
                        }
                        // The key is gone from this account: make it again.
                        None if !registered => {}
                        None => return Err(Error::msg(UNAVAILABLE)),
                    }
                }
                "register" if !registered => {}
                _ => return Err(Error::msg(UNAVAILABLE)),
            }
            let key = create()?;
            elevate_register(&key)?;
            registered = true;
        }
    }

    /// Shows text in a dialog of CBB's, with OK and Cancel; whether the
    /// user chose OK.
    fn agree(text: &str) -> Result<bool> {
        use windows_sys::Win32::UI::WindowsAndMessaging::{
            IDOK, MB_ICONQUESTION, MB_OKCANCEL, MB_SETFOREGROUND, MB_TOPMOST, MessageBoxW,
        };
        let wide = |s: &str| s.encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>();
        let (text, title) = (wide(text), wide("CBB"));
        // SAFETY: both strings are NUL-terminated and outlive the call; no
        // owner window.
        let r = unsafe {
            MessageBoxW(
                std::ptr::null_mut(),
                text.as_ptr(),
                title.as_ptr(),
                MB_OKCANCEL | MB_ICONQUESTION | MB_TOPMOST | MB_SETFOREGROUND,
            )
        };
        if r == 0 {
            return Err(
                Error::msg(format!("cannot show the dialog: {}", std::io::Error::last_os_error())).context(UNAVAILABLE)
            );
        }
        Ok(r == IDOK)
    }

    fn status(s: KeyCredentialStatus) -> Result<()> {
        match s {
            KeyCredentialStatus::Success => Ok(()),
            KeyCredentialStatus::UserCanceled => Err(Error::msg(CANCELLED)),
            other => Err(Error::msg(format!("Windows Hello: status {}", other.0)).context(UNAVAILABLE)),
        }
    }

    fn win(e: windows::core::Error) -> Error {
        Error::msg(format!("Windows Hello: {e}")).context(UNAVAILABLE)
    }

    fn bytes(b: &IBuffer) -> Result<Vec<u8>> {
        let mut out = Array::<u8>::new();
        CryptographicBuffer::CopyToByteArray(b, &mut out).map_err(win)?;
        Ok(out.to_vec())
    }

    /// Makes the user's Windows Hello key, replacing an old one, and
    /// returns its public key (PKCS #1).
    fn create() -> Result<Vec<u8>> {
        if !KeyCredentialManager::IsSupportedAsync().map_err(win)?.join().map_err(win)? {
            return Err(Error::msg("Windows Hello is not set up for this user").context(UNAVAILABLE));
        }
        let r = KeyCredentialManager::RequestCreateAsync(
            &HSTRING::from(KEY_NAME),
            KeyCredentialCreationOption::ReplaceExisting,
        )
        .map_err(win)?
        .join()
        .map_err(win)?;
        status(r.Status().map_err(win)?)?;
        let cred: KeyCredential = r.Credential().map_err(win)?;
        bytes(&cred.RetrievePublicKeyWithBlobType(CryptographicPublicKeyBlobType::Pkcs1RsaPublicKey).map_err(win)?)
    }

    /// Signs data with the user's Windows Hello key, which shows its
    /// prompt; None when the account has no such key.
    fn sign(data: &[u8]) -> Result<Option<Vec<u8>>> {
        let r = KeyCredentialManager::OpenAsync(&HSTRING::from(KEY_NAME)).map_err(win)?.join().map_err(win)?;
        if r.Status().map_err(win)? == KeyCredentialStatus::NotFound {
            return Ok(None);
        }
        status(r.Status().map_err(win)?)?;
        let buf = CryptographicBuffer::CreateFromByteArray(data).map_err(win)?;
        let s = r.Credential().map_err(win)?.RequestSignAsync(&buf).map_err(win)?.join().map_err(win)?;
        status(s.Status().map_err(win)?)?;
        Ok(Some(bytes(&s.Result().map_err(win)?)?))
    }

    /// Runs cbb confirm-key with this user's SID and key as the
    /// administrator, through the UAC prompt, once for the account.
    fn elevate_register(key: &[u8]) -> Result<()> {
        use windows_sys::Win32::Foundation::{CloseHandle, ERROR_CANCELLED, WAIT_OBJECT_0};
        use windows_sys::Win32::System::Threading::{GetExitCodeProcess, INFINITE, WaitForSingleObject};
        use windows_sys::Win32::UI::Shell::{SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW};
        use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;
        let sid = crate::peer::own_sid().ok_or_else(|| Error::msg("cannot read this user's SID"))?;
        let exe = std::env::current_exe().context("cannot find cbb itself")?;
        let wide = |s: &str| s.encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>();
        let file = wide(&exe.to_string_lossy());
        let params = wide(&format!("confirm-key {sid} {}", base64::engine::general_purpose::STANDARD.encode(key)));
        let verb = wide("runas");
        // SAFETY: an all-zero SHELLEXECUTEINFOW is a valid start; the
        // strings outlive the call, and the process handle it returns is
        // waited on and closed.
        unsafe {
            let mut info: SHELLEXECUTEINFOW = std::mem::zeroed();
            info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
            info.fMask = SEE_MASK_NOCLOSEPROCESS;
            info.lpVerb = verb.as_ptr();
            info.lpFile = file.as_ptr();
            info.lpParameters = params.as_ptr();
            info.nShow = SW_HIDE;
            if ShellExecuteExW(&mut info) == 0 {
                let e = std::io::Error::last_os_error();
                if e.raw_os_error() == Some(ERROR_CANCELLED as i32) {
                    return Err(Error::msg(CANCELLED));
                }
                return Err(Error::msg(format!("cannot run cbb as the administrator: {e}")).context(UNAVAILABLE));
            }
            let mut code = 1u32;
            let waited = WaitForSingleObject(info.hProcess, INFINITE) == WAIT_OBJECT_0;
            let read = GetExitCodeProcess(info.hProcess, &mut code) != 0;
            CloseHandle(info.hProcess);
            if !(waited && read && code == 0) {
                return Err(Error::msg(format!("cbb confirm-key exited with {code}")).context(UNAVAILABLE));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tiers() {
        for op in KEPT {
            assert_eq!(right(op), RIGHT_KEPT, "{op}");
            assert!(!EACH_TIME.contains(&op), "{op} is in both tiers");
        }
        for op in EACH_TIME {
            assert_eq!(right(op), RIGHT_EACH, "{op}");
        }
        // Fail closed: what is not listed is confirmed each time.
        for op in ["", "takeover", "revoke", "an_operation_added_later", OP_REGISTER] {
            assert_eq!(right(op), RIGHT_EACH, "{op}");
        }
    }

    /// Every operation of the computers' control socket (docs/core-api.md,
    /// "The member's operations", and the arms the service dispatches on)
    /// is one the socket takes without the admin, or one in a tier; every
    /// name in a tier is an operation; and those that make, leave, take
    /// over, hand on or recover the group, make an admin or set who may
    /// hold the group are confirmed each time.
    #[test]
    fn every_operation_has_a_tier() {
        let doc = include_str!("../../docs/core-api.md");
        let start = doc.find("### The member's operations").expect("the operations' table");
        let mut ops: Vec<String> = Vec::new();
        for line in doc[start..].lines().skip_while(|l| !l.starts_with("| `")) {
            if !line.starts_with('|') {
                break;
            }
            let cells: Vec<&str> = line.split('|').map(str::trim).collect();
            // The header row names the columns, `op` and where.
            if cells.len() > 2
                && cells[2] != "phone"
                && cells[2] != "where"
                && let Some(op) = cells[1].strip_prefix('`').and_then(|c| c.strip_suffix('`'))
            {
                ops.push(op.to_string());
            }
        }
        let service = include_str!("service.rs");
        let body = &service[service.find("fn request(&self").expect("the service's dispatch")..];
        // Up to the next method: the arms of its match, not of others.
        let body = &body[..body[1..].find("\n    fn ").map_or(body.len(), |i| i + 1)];
        for line in body.lines() {
            let arm = line.trim_start();
            if !line.starts_with("            \"") || !arm.contains("=>") {
                continue;
            }
            let pattern = &arm[..arm.find("=>").unwrap()];
            // A guard follows the names.
            let pattern = pattern.split(" if ").next().unwrap_or(pattern);
            for name in pattern.split('|') {
                let name = name.trim().trim_matches('"');
                if !ops.iter().any(|o| o == name) {
                    ops.push(name.to_string());
                }
            }
        }
        assert!(ops.len() > 40, "read only {} operations", ops.len());
        for op in &ops {
            if crate::control::is_admin(op) {
                assert!(
                    KEPT.contains(&op.as_str()) || EACH_TIME.contains(&op.as_str()) || op == OP_REGISTER,
                    "{op} needs the admin but is in no confirmation tier"
                );
            }
        }
        for op in KEPT.iter().chain(EACH_TIME.iter()) {
            assert!(ops.iter().any(|o| o == op), "{op} is in a tier but is no operation");
            assert!(crate::control::is_admin(op), "{op} is in a tier but needs no admin");
        }
        for op in [
            "new",
            "leave",
            "take_over",
            "recover",
            "hand_over",
            "key_level",
            "takeover_delay",
            "make_admin",
            "pair",
            "join",
            "invite",
            "away",
            "hubs",
            "paste_receive",
            "keyboard",
            "remote",
        ] {
            assert!(EACH_TIME.contains(&op) && each_time(op), "{op} is not confirmed each time");
        }
    }

    /// What Windows Hello signs names the action, its device and the
    /// challenge.
    #[test]
    fn hello() {
        let challenge: Vec<u8> = (1..=2).collect();
        let h = |op: &str, device: &str| Header { op: op.into(), device: device.into(), ..Default::default() };
        assert_eq!(hello_message(&h("remove", "laptop"), &challenge), b"cbb confirm v2\ncbb remove laptop\n\x01\x02");
        // Another device, or another action, is another message.
        assert_ne!(
            hello_message(&h("remove", "laptop"), &challenge),
            hello_message(&h("remove", "tablet"), &challenge)
        );
        assert_ne!(
            hello_message(&h("remove", "laptop"), &challenge),
            hello_message(&h("freeze", "laptop"), &challenge)
        );
        assert!(crate::control::is_admin(OP_REGISTER) && !crate::control::is_admin(OP_CHALLENGE));
    }

    #[test]
    fn exit_codes() {
        assert_eq!(exit_code(&Error::msg(CANCELLED)), Some(CANCELLED_EXIT));
        assert_eq!(exit_code(&Error::msg("pkcheck").context(UNAVAILABLE)), Some(NEED_ADMIN_EXIT));
        assert_eq!(exit_code(&Error::msg(crate::awaynet::NEED_ROOT)), Some(NEED_ADMIN_EXIT));
        assert_eq!(exit_code(&Error::msg("no device")), None);
    }

    /// The prompts come in every language of the project, and polkit's file
    /// names both actions with them, the action they confirm, and the
    /// service's user as their owner.
    #[test]
    fn policy() {
        let p = polkit_policy("cbb");
        assert!(p.contains("<action id=\"tools.cbb.admin\">") && p.contains("<action id=\"tools.cbb.admin.each\">"));
        assert!(
            p.contains("<allow_active>auth_admin_keep</allow_active>")
                && p.contains("<allow_active>auth_admin</allow_active>")
        );
        assert_eq!(p.matches("<allow_any>no</allow_any>").count(), 2);
        assert_eq!(p.matches("<annotate key=\"org.freedesktop.policykit.owner\">unix-user:cbb</annotate>").count(), 2);
        assert_eq!(p.matches(" $(cbb_action)</message>").count(), p.matches("<message").count());
        assert!(!polkit_policy("").contains("policykit.owner"), "root needs no owner");
        for lang in crate::l10n::LANGS {
            assert!(p.contains(&format!("xml:lang=\"{lang}\"")), "{lang}");
            assert_ne!(crate::l10n::lookup(lang, PROMPT_KEPT), None, "{lang}");
            assert_ne!(crate::l10n::lookup(lang, PROMPT_EACH), None, "{lang}");
        }
        assert_eq!(_catalog_marks(), [PROMPT_KEPT, PROMPT_EACH]);
    }

    /// The prompt names the action and its device, without what could
    /// change how it reads, and the most it shows.
    #[test]
    fn prompt_names_the_action() {
        let h = Header { op: "make_admin".into(), device: "Laptop".into(), ..Default::default() };
        assert_eq!(action(&h), "cbb make-admin Laptop");
        assert!(prompt_for(&h).starts_with(PROMPT_EACH) && prompt_for(&h).ends_with("\n\ncbb make-admin Laptop"));
        let h = Header { op: "away".into(), name: "relay".into(), ..Default::default() };
        assert_eq!(action(&h), "cbb away relay");
        let h = Header {
            op: "rename".into(),
            device: "a\nb\u{1b}[2Jc".into(),
            name: "x".repeat(200),
            ..Default::default()
        };
        let a = action(&h);
        assert!(!a.chars().any(char::is_control), "{a:?}");
        assert_eq!(a.chars().count(), 80);
        assert!(a.ends_with('…'));
    }

    /// One prompt of a user at a time; after a cancelled one a pause that
    /// doubles up to five minutes; a confirmed one ends the pauses; other
    /// users are not held up.
    #[test]
    fn prompts_are_paced() {
        let p = Pace::new();
        let t = std::time::Instant::now();
        let s = std::time::Duration::from_secs;
        p.begin("1000", t).unwrap();
        assert_eq!(p.begin("1000", t).unwrap_err().message(), BUSY);
        p.begin("1001", t).unwrap();
        p.end("1001", &Ok(()), t);
        p.end("1000", &Err(Error::msg(CANCELLED)), t);
        assert_eq!(p.begin("1000", t + s(4)).unwrap_err().message(), BUSY);
        p.begin("1000", t + s(5)).unwrap();
        p.end("1000", &Err(Error::msg(CANCELLED)), t + s(5));
        assert!(p.begin("1000", t + s(14)).is_err(), "the pause doubles");
        p.begin("1000", t + s(15)).unwrap();
        let mut now = t + s(15);
        for _ in 0..10 {
            p.end("1000", &Err(Error::msg(CANCELLED)), now);
            now += s(300);
            p.begin("1000", now).unwrap();
        }
        p.end("1000", &Err(Error::msg(CANCELLED)), now);
        assert!(p.begin("1000", now + s(299)).is_err(), "at most five minutes");
        p.begin("1000", now + s(300)).unwrap();
        p.end("1000", &Ok(()), now + s(300));
        p.begin("1000", now + s(300)).unwrap();
        // An error that is no cancel pauses nothing.
        p.end("1000", &Err(Error::msg(UNAVAILABLE)), now + s(300));
        p.begin("1000", now + s(300)).unwrap();
    }

    #[test]
    fn confirm_key_cli() {
        let sent = std::cell::RefCell::new(Vec::new());
        let req = |h: Header| {
            sent.borrow_mut().push((h.op.clone(), h.name.clone(), h.value.clone()));
            Ok(h)
        };
        register_cli(&["S-1-5-21-1".into(), "a2V5".into()], &req).unwrap();
        register_cli(&["-remove".into(), "S-1-5-21-1".into()], &req).unwrap();
        assert!(register_cli(&["S-1-5-21-1".into()], &req).is_err());
        assert!(register_cli(&["S-1-5-21-1".into(), String::new()], &req).is_err());
        assert_eq!(
            *sent.borrow(),
            [
                (OP_REGISTER.to_string(), "S-1-5-21-1".to_string(), "a2V5".to_string()),
                (OP_REGISTER.to_string(), "S-1-5-21-1".to_string(), String::new())
            ]
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn polkit() {
        assert_eq!(linux::parse_start("42 (a b) c) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 777 19"), Some(777));
        let own = linux::start_time(std::process::id() as i32).unwrap();
        // This process started before now, in the same clock.
        assert!(own <= linux::now_ticks() && linux::now_ticks() > 0);
        assert!(linux::verdict(Some(0), "").is_ok());
        assert_eq!(linux::verdict(Some(3), "").unwrap_err().message(), CANCELLED);
        assert_eq!(linux::verdict(Some(1), "not authorized").unwrap_err().message(), UNAVAILABLE);
        let dir = std::env::temp_dir().join(format!("cbb-polkit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        linux::install(&dir, "cbb").unwrap();
        assert_eq!(std::fs::read_to_string(dir.join("tools.cbb.admin.policy")).unwrap(), polkit_policy("cbb"));
        linux::install(&dir, "cbb").unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        linux::install(&dir, "cbb").unwrap();
    }

    /// The service asks polkit only about a process that says when it
    /// started, and started before its connection came: a process that
    /// took the ID of one that connected and left is never asked about.
    #[cfg(target_os = "linux")]
    #[test]
    fn polkit_subject_started_before_the_connection() {
        let (a, _b) = crate::sys::UnixStream::pair().unwrap();
        let own = linux::start_time(std::process::id() as i32).unwrap();
        for auth in [String::new(), "x".into(), "0".into(), (own + 1).to_string()] {
            let h = Header { op: "remove".into(), auth, ..Default::default() };
            let e = linux::check(&a, &h, own).unwrap_err();
            assert_eq!(e.message(), UNAVAILABLE, "{:?}", h.auth);
            assert!(e.for_log().contains("did not say when its process started"), "{}", e.for_log());
        }
    }
}
