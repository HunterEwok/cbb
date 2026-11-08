// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! What differs between the systems the service runs on: the control
//! socket (AF_UNIX, which Windows has too, though Rust's standard library
//! offers it only on Unix), the process's user, the host's name and the
//! clock since boot.

use std::path::Path;
use std::time::Duration;

use crate::error::{Context, Result};

#[cfg(unix)]
pub use std::os::unix::net::{UnixListener, UnixStream};
#[cfg(windows)]
mod uds_windows;
#[cfg(windows)]
pub use uds_windows::{UnixListener, UnixStream};
#[cfg(windows)]
mod acl_windows;
#[cfg(windows)]
pub use acl_windows::listen as listen_windows;
#[cfg(windows)]
pub mod service_windows;

/// Whether the process runs as root, or on Windows as an administrator or
/// the system.
#[cfg(unix)]
pub fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

#[cfg(windows)]
pub fn is_root() -> bool {
    uds_windows::elevated()
}

/// The host's name, as the system gives it; "" when it gives none.
#[cfg(unix)]
pub fn host_name() -> String {
    let mut buf = [0u8; 256];
    // SAFETY: gethostname writes at most len bytes into buf.
    let ok = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) } == 0;
    if !ok {
        return String::new();
    }
    String::from_utf8_lossy(&buf[..buf.iter().position(|&b| b == 0).unwrap_or(0)]).to_string()
}

#[cfg(windows)]
pub fn host_name() -> String {
    std::env::var("COMPUTERNAME").unwrap_or_default()
}

/// The time since boot, counting the time the machine sleeps and never
/// jumping when the wall clock is set: CLOCK_BOOTTIME on Linux,
/// CLOCK_MONOTONIC on the other Unix systems, GetTickCount64 on Windows.
#[cfg(unix)]
pub fn since_boot() -> Duration {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let clock = libc::CLOCK_BOOTTIME;
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let clock = libc::CLOCK_MONOTONIC;
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: clock_gettime writes the timespec it is given.
    unsafe { libc::clock_gettime(clock, &mut ts) };
    Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)
}

#[cfg(windows)]
pub fn since_boot() -> Duration {
    // SAFETY: GetTickCount64 has no preconditions.
    Duration::from_millis(unsafe { windows_sys::Win32::System::SystemInformation::GetTickCount64() })
}

/// Makes dir and its parents, dir itself for this user only: mode 0700 on
/// Unix; on Windows the state's folder takes the access list the
/// installer gave the folder above it.
pub fn mkdir_private(dir: &Path) -> Result<()> {
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(dir).context(format!("cannot make {}", dir.display()))
}

/// Stops the process pid at once.
#[cfg(unix)]
pub fn kill(pid: u32) {
    // SAFETY: kill has no memory preconditions.
    unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
}

#[cfg(windows)]
pub fn kill(pid: u32) {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_TERMINATE, TerminateProcess};
    // SAFETY: the handle is checked and closed after use.
    unsafe {
        let h = OpenProcess(PROCESS_TERMINATE, 0, pid);
        if !h.is_null() {
            TerminateProcess(h, 1);
            CloseHandle(h);
        }
    }
}

/// Where the service keeps its state when nothing names another place, as
/// Go's defaultStateDir; rootless and OpenWrt are decided by the caller.
pub fn default_state() -> std::path::PathBuf {
    if cfg!(windows) {
        program_data().join("cbb").join("state")
    } else if cfg!(target_os = "macos") {
        "/Library/Application Support/cbb/state".into()
    } else if cfg!(target_os = "freebsd") {
        "/var/db/cbb".into()
    } else {
        "/var/lib/cbb".into()
    }
}

/// Where the control socket is when nothing names another place, as Go's
/// control.DefaultSocket: in systemd's runtime folder on Linux, in the
/// folder the init script makes in /var/run on FreeBSD and OpenWrt.
pub fn default_socket(openwrt: bool) -> std::path::PathBuf {
    if cfg!(windows) {
        program_data().join("cbb").join("run").join("control.sock")
    } else if cfg!(target_os = "macos") {
        "/Library/Application Support/cbb/control.sock".into()
    } else if cfg!(target_os = "linux") && !openwrt {
        "/run/cbb/control.sock".into()
    } else {
        "/var/run/cbb/control.sock".into()
    }
}

/// The folder for all users' data, usually C:\ProgramData, asked from the
/// system rather than taken from the environment, so the service and every
/// client agree on it.
#[cfg(windows)]
pub fn program_data() -> std::path::PathBuf {
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::UI::Shell::{FOLDERID_ProgramData, SHGetKnownFolderPath};
    let mut p: *mut u16 = std::ptr::null_mut();
    // SAFETY: p is valid for the call to write, read up to its NUL and freed.
    unsafe {
        if SHGetKnownFolderPath(&FOLDERID_ProgramData, 0, std::ptr::null_mut(), &mut p) == 0 && !p.is_null() {
            let len = (0..).take_while(|&i| *p.add(i) != 0).count();
            let s = String::from_utf16_lossy(std::slice::from_raw_parts(p, len));
            CoTaskMemFree(p.cast());
            return s.into();
        }
    }
    r"C:\ProgramData".into()
}

#[cfg(not(windows))]
fn program_data() -> std::path::PathBuf {
    std::path::PathBuf::new()
}

/// A socket's handle as the system's poll takes it.
#[cfg(unix)]
pub type RawSock = std::os::fd::RawFd;
#[cfg(windows)]
pub type RawSock = std::os::windows::io::RawSocket;

/// The handle of a socket, for [`poll`].
#[cfg(unix)]
pub fn raw<T: std::os::fd::AsRawFd>(s: &T) -> RawSock {
    s.as_raw_fd()
}

/// The handle of a socket, for [`poll`].
#[cfg(windows)]
pub fn raw<T: std::os::windows::io::AsRawSocket>(s: &T) -> RawSock {
    s.as_raw_socket()
}

/// Waits until one of the sockets can be read (the first flag) or written
/// (the second), or the timeout passes; an error counts as the timeout,
/// since the caller looks at every socket again anyway.
#[cfg(unix)]
pub fn poll(socks: &[(RawSock, bool, bool)], timeout: Duration) {
    let mut fds: Vec<libc::pollfd> = socks
        .iter()
        .map(|&(fd, r, w)| libc::pollfd {
            fd,
            events: if r { libc::POLLIN } else { 0 } | if w { libc::POLLOUT } else { 0 },
            revents: 0,
        })
        .collect();
    let ms = timeout.as_millis().min(i32::MAX as u128) as libc::c_int;
    // SAFETY: fds is a valid array of pollfd of the given length.
    unsafe {
        libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, ms);
    }
}

/// Waits until one of the sockets can be read (the first flag) or written
/// (the second), or the timeout passes; an error counts as the timeout,
/// since the caller looks at every socket again anyway.
#[cfg(windows)]
pub fn poll(socks: &[(RawSock, bool, bool)], timeout: Duration) {
    use windows_sys::Win32::Networking::WinSock::{POLLRDNORM, POLLWRNORM, WSAPOLLFD, WSAPoll};
    let mut fds: Vec<WSAPOLLFD> = socks
        .iter()
        .map(|&(fd, r, w)| WSAPOLLFD {
            fd: fd as usize,
            events: if r { POLLRDNORM } else { 0 } | if w { POLLWRNORM } else { 0 },
            revents: 0,
        })
        .collect();
    let ms = timeout.as_millis().min(i32::MAX as u128) as i32;
    // SAFETY: fds is a valid array of WSAPOLLFD of the given length.
    let n = unsafe { WSAPoll(fds.as_mut_ptr(), fds.len() as u32, ms) };
    if n < 0 {
        // WSAPoll fails at once rather than waiting; do not spin.
        std::thread::sleep(timeout.min(Duration::from_millis(10)));
    }
}

/// The process's effective user id; on Windows, where users have no number,
/// 0, which only the tables of /proc compare against.
#[cfg(unix)]
pub fn euid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

/// The process's effective user id; on Windows, where users have no number,
/// 0, which only the tables of /proc compare against.
#[cfg(windows)]
pub fn euid() -> u32 {
    0
}

/// A moment of the local clock, for the log's lines.
pub struct LocalTime {
    pub year: i32,
    pub month: u32,
    pub day: u32,
    pub hour: u32,
    pub minute: u32,
    pub second: u32,
}

/// The local clock's time now.
#[cfg(unix)]
pub fn local_time() -> LocalTime {
    // SAFETY: time with a null pointer only returns the time; localtime_r
    // writes into tm, which is a valid tm.
    unsafe {
        let now = libc::time(std::ptr::null_mut());
        let mut tm: libc::tm = std::mem::zeroed();
        libc::localtime_r(&now, &mut tm);
        LocalTime {
            year: tm.tm_year + 1900,
            month: (tm.tm_mon + 1) as u32,
            day: tm.tm_mday as u32,
            hour: tm.tm_hour as u32,
            minute: tm.tm_min as u32,
            second: tm.tm_sec as u32,
        }
    }
}

/// The local clock's time now.
#[cfg(windows)]
pub fn local_time() -> LocalTime {
    use windows_sys::Win32::System::SystemInformation::GetLocalTime;
    // SAFETY: GetLocalTime writes into st, which is a valid SYSTEMTIME.
    let st = unsafe {
        let mut st = std::mem::zeroed();
        GetLocalTime(&mut st);
        st
    };
    LocalTime {
        year: st.wYear as i32,
        month: st.wMonth as u32,
        day: st.wDay as u32,
        hour: st.wHour as u32,
        minute: st.wMinute as u32,
        second: st.wSecond as u32,
    }
}

/// Makes file the process's standard error, which the children it starts
/// inherit.
#[cfg(unix)]
pub fn set_stderr(file: &std::fs::File) {
    use std::os::fd::AsRawFd;
    // SAFETY: both are open descriptors; dup2 only replaces descriptor 2.
    unsafe {
        libc::dup2(file.as_raw_fd(), 2);
    }
}

/// Makes file the process's standard error, which the children it starts
/// inherit.
#[cfg(windows)]
pub fn set_stderr(file: &std::fs::File) {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::Console::{STD_ERROR_HANDLE, SetStdHandle};
    // The handle stays valid as long as the log keeps its file; the next
    // file replaces it before the old one closes.
    // SAFETY: the handle is an open file's.
    unsafe {
        SetStdHandle(STD_ERROR_HANDLE, file.as_raw_handle());
    }
}

/// Whether the process has a standard error to write to: not when Windows
/// starts it at sign-in without a console.
#[cfg(windows)]
pub fn has_stderr() -> bool {
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::System::Console::{GetStdHandle, STD_ERROR_HANDLE};
    // SAFETY: GetStdHandle has no preconditions.
    let h = unsafe { GetStdHandle(STD_ERROR_HANDLE) };
    !h.is_null() && h != INVALID_HANDLE_VALUE
}
