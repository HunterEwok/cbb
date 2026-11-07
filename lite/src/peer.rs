// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The user at the other end of a control connection, as the full member's
//! internal/service/peer.go: a watcher that offers a paste target gets its
//! remote pastes only when its user may take them (docs/protocol.md,
//! section 8). The control socket's group is for the clipboard, while a
//! remote paste goes to the screen or the console of one user.

use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};

/// Whether a watcher's user may take what goes to a target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Refused,
    /// Nothing tells who is at the screen (no logind).
    Unchecked,
    Allowed,
}

/// The user of the process at the other end of s, from the kernel.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn uid(s: &UnixStream) -> Option<u32> {
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
#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn uid(s: &UnixStream) -> Option<u32> {
    let (mut uid, mut gid) = (0, 0);
    // SAFETY: uid and gid are valid for the kernel to write, and the
    // descriptor stays open while s lives.
    (unsafe { libc::getpeereid(s.as_raw_fd(), &mut uid, &mut gid) } == 0).then_some(uid)
}

/// Root and the service's own user, which take every target.
pub fn privileged(uid: u32) -> bool {
    // SAFETY: geteuid has no preconditions and cannot fail.
    uid == 0 || uid == unsafe { libc::geteuid() }
}

/// Whether the user uid may take the remote pastes of target: root and the
/// service's own user every one; the console only them; tmux and the
/// desktop the user at the screen, as at_screen tells.
pub fn may_take(uid: Option<u32>, target: &str, at_screen: impl Fn(u32, &str) -> Verdict) -> Verdict {
    match uid {
        None => Verdict::Refused,
        Some(u) if privileged(u) => Verdict::Allowed,
        Some(_) if target == crate::service::CONSOLE || target == crate::service::NEXT => Verdict::Refused,
        Some(u) => at_screen(u, target),
    }
}

/// Asks logind: the desktop goes to the user of an active graphical
/// session, tmux to a user with a session, as one over SSH. Without logind
/// nothing tells who is at the screen.
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

fn loginctl(args: &[&str]) -> Option<String> {
    let out = Command::new("loginctl").args(args).stdin(Stdio::null()).stderr(Stdio::null()).output().ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

#[cfg(test)]
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
