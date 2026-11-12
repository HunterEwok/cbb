// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The user at the other end of a control connection, as the full member's
//! internal/service/peer.go: a watcher that offers a paste target gets its
//! remote pastes only when its user may take them (docs/protocol.md,
//! section 8). The control socket's group is for the clipboard, while a
//! remote paste goes to the screen or the console of one user.

#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::process::{Command, Stdio};

use crate::sys::UnixStream;

/// Whether a watcher's user may take what goes to a target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Refused,
    /// Nothing tells who is at the screen (no logind).
    Unchecked,
    Allowed,
}

/// The user at the other end of a connection: a uid on Unix.
#[cfg(unix)]
pub type Who = u32;

/// The user at the other end of a connection on Windows, as Go's peer: its
/// session, whether it is the system or the service's own account, and its
/// SID, kept as a number that tells users apart within this process.
#[cfg(windows)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Who {
    session: u32,
    privileged: bool,
    user: u64,
}

#[cfg(windows)]
impl std::fmt::Display for Who {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:016x}", self.user)
    }
}

/// The user of the process at the other end of s, from the kernel.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn uid(s: &UnixStream) -> Option<Who> {
    let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: cred and len are valid for the kernel to write a ucred, and
    // the descriptor stays open while s lives.
    let ok = unsafe {
        libc::getsockopt(s.as_raw_fd(), libc::SOL_SOCKET, libc::SO_PEERCRED, (&raw mut cred).cast(), &mut len)
    } == 0;
    ok.then_some(cred.uid)
}

/// The user of the process at the other end of s, from the kernel.
#[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
pub fn uid(s: &UnixStream) -> Option<Who> {
    let (mut uid, mut gid) = (0, 0);
    // SAFETY: uid and gid are valid for the kernel to write, and the
    // descriptor stays open while s lives.
    (unsafe { libc::getpeereid(s.as_raw_fd(), &mut uid, &mut gid) } == 0).then_some(uid)
}

/// The user of the process at the other end of s: its process from
/// SIO_AF_UNIX_GETPEERPID, then that process's session and user.
#[cfg(windows)]
pub fn uid(s: &UnixStream) -> Option<Who> {
    let pid = s.peer_pid()?;
    let session = win::session_of(pid)?;
    let sid = win::sid_of(Some(pid))?;
    let privileged = sid == "S-1-5-18" || win::sid_of(None).is_some_and(|own| own == sid);
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    sid.hash(&mut h);
    Some(Who { session, privileged, user: h.finish() })
}

/// The SID of the account this process runs as.
#[cfg(windows)]
pub fn own_sid() -> Option<String> {
    win::sid_of(None)
}

/// The SID of the user at the other end of s, and whether its process runs
/// in an active session: at the console or over Remote Desktop.
#[cfg(windows)]
pub fn sid_at_screen(s: &UnixStream) -> Option<(String, bool)> {
    let pid = s.peer_pid()?;
    let session = win::session_of(pid)?;
    Some((win::sid_of(Some(pid))?, win::active(session)))
}

/// Root and the service's own user, which take every target.
#[cfg(unix)]
pub fn privileged(uid: Who) -> bool {
    // SAFETY: geteuid has no preconditions and cannot fail.
    uid == 0 || uid == unsafe { libc::geteuid() }
}

/// The system's account and the service's own, which take every target.
#[cfg(windows)]
pub fn privileged(w: Who) -> bool {
    w.privileged
}

/// Whether the user uid may take the remote pastes of target: root and the
/// service's own user every one; the console only them; tmux and the
/// desktop the user at the screen, as at_screen tells.
pub fn may_take(uid: Option<Who>, target: &str, at_screen: impl Fn(Who, &str) -> Verdict) -> Verdict {
    match uid {
        None => Verdict::Refused,
        Some(u) if privileged(u) => Verdict::Allowed,
        Some(_) if target == crate::service::CONSOLE || target == crate::service::NEXT => Verdict::Refused,
        Some(u) => at_screen(u, target),
    }
}

/// Allows a process in an active session, as Go's atScreen on Windows:
/// the one at the console, or one connected by Remote Desktop.
#[cfg(windows)]
pub fn at_screen(w: Who, _target: &str) -> Verdict {
    if win::active(w.session) { Verdict::Allowed } else { Verdict::Refused }
}

/// Asks logind: the desktop goes to the user of an active graphical
/// session, tmux to a user with a session, as one over SSH. Without logind
/// nothing tells who is at the screen.
#[cfg(unix)]
pub fn at_screen(uid: u32, target: &str) -> Verdict {
    let Some(list) = loginctl(&["list-sessions", "--no-legend"]) else {
        return Verdict::Unchecked;
    };
    for id in list.lines().filter_map(|l| l.split_whitespace().next()) {
        let props = loginctl(&[
            "show-session",
            id,
            "-p",
            "User",
            "-p",
            "State",
            "-p",
            "Class",
            "-p",
            "Type",
            "-p",
            "Remote",
            "-p",
            "Seat",
        ])
        .unwrap_or_default();
        if at_screen_in(&props, uid, target) {
            return Verdict::Allowed;
        }
    }
    Verdict::Refused
}

/// Whether a session whose logind properties are props puts the user uid at
/// the screen for target, as Go's atScreenIn: a session of the user's own
/// (not its service manager or a greeter); for tmux any that is active or
/// online, as over SSH; for the desktop an active graphical one, X11 or
/// Wayland, on a seat or not remote, so that a user signed in over SSH alone
/// takes none, even where SSH lets the session name its type.
#[cfg(unix)]
fn at_screen_in(props: &str, uid: u32, target: &str) -> bool {
    let get = |k: &str| props.lines().find_map(|l| l.trim().strip_prefix(k)?.strip_prefix('=')).unwrap_or("");
    if get("User") != uid.to_string() || !get("Class").starts_with("user") {
        return false;
    }
    let state = get("State");
    if target == crate::service::TMUX {
        return state == "active" || state == "online";
    }
    state == "active" && matches!(get("Type"), "x11" | "wayland") && (!get("Seat").is_empty() || get("Remote") == "no")
}

#[cfg(unix)]
fn loginctl(args: &[&str]) -> Option<String> {
    let out = Command::new("loginctl").args(args).stdin(Stdio::null()).stderr(Stdio::null()).output().ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// The Windows calls behind uid and at_screen.
#[cfg(windows)]
mod win {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LocalFree};
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser};
    use windows_sys::Win32::System::RemoteDesktop::{
        ProcessIdToSessionId, WTS_SESSION_INFOW, WTSActive, WTSEnumerateSessionsW, WTSFreeMemory,
        WTSGetActiveConsoleSessionId,
    };
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    pub fn session_of(pid: u32) -> Option<u32> {
        let mut s = 0u32;
        // SAFETY: s is valid for the call to write.
        (unsafe { ProcessIdToSessionId(pid, &mut s) } != 0).then_some(s)
    }

    /// The SID of the user the process pid runs as, or this process's.
    pub fn sid_of(pid: Option<u32>) -> Option<String> {
        // SAFETY: every handle is checked and closed, the buffer is large
        // enough for the size the first call asks for, and the string the
        // conversion allocates is freed.
        unsafe {
            let (proc, own): (HANDLE, bool) = match pid {
                Some(p) => (OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, p), false),
                None => (GetCurrentProcess(), true),
            };
            if proc.is_null() {
                return None;
            }
            let mut tok: HANDLE = std::ptr::null_mut();
            let opened = OpenProcessToken(proc, TOKEN_QUERY, &mut tok) != 0;
            if !own {
                CloseHandle(proc);
            }
            if !opened {
                return None;
            }
            let mut n = 0u32;
            GetTokenInformation(tok, TokenUser, std::ptr::null_mut(), 0, &mut n);
            let mut buf = vec![0u64; (n as usize).div_ceil(8).max(1)];
            let ok = GetTokenInformation(tok, TokenUser, buf.as_mut_ptr().cast(), n, &mut n) != 0;
            CloseHandle(tok);
            if !ok {
                return None;
            }
            let user = &*(buf.as_ptr() as *const TOKEN_USER);
            let mut p: *mut u16 = std::ptr::null_mut();
            if ConvertSidToStringSidW(user.User.Sid, &mut p) == 0 {
                return None;
            }
            let len = (0..).take_while(|&i| *p.add(i) != 0).count();
            let sid = String::from_utf16_lossy(std::slice::from_raw_parts(p, len));
            LocalFree(p.cast());
            Some(sid)
        }
    }

    /// Whether the session is the console's, or an active one such as a
    /// Remote Desktop connection. The console's is asked first, which needs
    /// no rights: a service account may be refused the list of sessions.
    pub fn active(session: u32) -> bool {
        // SAFETY: the list WTSEnumerateSessionsW allocates is read within
        // its count and freed.
        unsafe {
            let c = WTSGetActiveConsoleSessionId();
            if c != 0xFFFF_FFFF && c == session {
                return true;
            }
            let (mut info, mut n): (*mut WTS_SESSION_INFOW, u32) = (std::ptr::null_mut(), 0);
            if WTSEnumerateSessionsW(std::ptr::null_mut(), 0, 1, &mut info, &mut n) == 0 {
                return false;
            }
            let found = std::slice::from_raw_parts(info, n as usize)
                .iter()
                .any(|s| s.SessionId == session && s.State == WTSActive);
            WTSFreeMemory(info.cast());
            found
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::service::{CONSOLE, DESKTOP, TMUX};

    #[test]
    fn reads_its_own_user() {
        let (a, _b) = UnixStream::pair().unwrap();
        // SAFETY: geteuid has no preconditions.
        assert_eq!(uid(&a), Some(unsafe { libc::geteuid() }));
    }

    #[test]
    fn takes_only_the_user_at_the_screen() {
        // A user that is neither root nor this test's.
        // SAFETY: geteuid has no preconditions.
        let other = if unsafe { libc::geteuid() } == 1001 { 1002 } else { 1001 };
        let screen = |u: u32, _: &str| if u == other { Verdict::Allowed } else { Verdict::Refused };
        assert_eq!(may_take(None, DESKTOP, screen), Verdict::Refused);
        assert_eq!(may_take(Some(0), CONSOLE, screen), Verdict::Allowed);
        assert_eq!(may_take(Some(other), CONSOLE, screen), Verdict::Refused);
        assert_eq!(may_take(Some(other), TMUX, screen), Verdict::Allowed);
        assert_eq!(may_take(Some(other + 1), DESKTOP, screen), Verdict::Refused);
        assert_eq!(may_take(Some(other), DESKTOP, |_, _| Verdict::Unchecked), Verdict::Unchecked);
    }

    #[test]
    fn ssh_alone_is_not_at_the_screen() {
        let session = |state: &str, class: &str, typ: &str| {
            format!("User=1003\nState={state}\nClass={class}\nType={typ}\nRemote=no\nSeat=seat0\n")
        };
        let remote = |typ: &str, seat: &str| {
            format!("User=1003\nState=active\nClass=user\nType={typ}\nRemote=yes\nSeat={seat}\n")
        };
        for (name, props, desktop, tmux) in [
            ("a desktop on X11", session("active", "user", "x11"), true, true),
            ("a desktop on Wayland", session("active", "user", "wayland"), true, true),
            ("a desktop in the background", session("online", "user", "wayland"), false, true),
            ("SSH", remote("tty", ""), false, true),
            ("SSH that names a Wayland session", remote("wayland", ""), false, true),
            ("a remote desktop on a seat", remote("x11", "seat0"), true, true),
            (
                "a local desktop with no seat",
                "User=1003\nState=active\nClass=user\nType=wayland\nRemote=no\nSeat=\n".into(),
                true,
                true,
            ),
            ("the service manager", session("active", "manager", "unspecified"), false, false),
            ("the login screen", session("active", "greeter", "wayland"), false, false),
            ("another user", "User=1000\nState=active\nClass=user\nType=x11\n".to_string(), false, false),
        ] {
            assert_eq!(at_screen_in(&props, 1003, DESKTOP), desktop, "{name}: the desktop");
            assert_eq!(at_screen_in(&props, 1003, TMUX), tmux, "{name}: tmux");
        }
    }
}
