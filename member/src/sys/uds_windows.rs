// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! AF_UNIX sockets on Windows, which Winsock has had since Windows 10 1803:
//! the control socket the Go clients, the tray app and the agent dial as
//! on the other systems. A connected socket is driven as std's TcpStream,
//! whose reads, writes, timeouts and duplication are Winsock's own calls
//! for any stream socket.

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::os::windows::io::{AsRawSocket, FromRawSocket, RawSocket};
use std::path::Path;
use std::sync::Once;
use std::time::Duration;

use windows_sys::Win32::Networking::WinSock as ws;

fn startup() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        // SAFETY: data is valid for WSAStartup to write; the count it keeps
        // is never released, as std's own start is not either.
        let mut data: ws::WSADATA = unsafe { std::mem::zeroed() };
        unsafe { ws::WSAStartup(0x202, &mut data) };
    });
}

fn last_error() -> io::Error {
    // SAFETY: WSAGetLastError has no preconditions.
    io::Error::from_raw_os_error(unsafe { ws::WSAGetLastError() })
}

/// The address of path: its UTF-8 bytes, ended by a NUL, in sun_path.
fn address(path: &Path) -> io::Result<(ws::SOCKADDR_UN, i32)> {
    let bytes = path
        .to_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "the socket's path is not UTF-8"))?
        .as_bytes();
    let mut a = ws::SOCKADDR_UN { sun_family: ws::AF_UNIX, sun_path: [0; 108] };
    if bytes.len() >= a.sun_path.len() || bytes.contains(&0) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "the socket's path is too long"));
    }
    for (d, s) in a.sun_path.iter_mut().zip(bytes) {
        *d = *s as i8;
    }
    let len = std::mem::size_of::<ws::ADDRESS_FAMILY>() + bytes.len() + 1;
    Ok((a, len as i32))
}

/// A new AF_UNIX stream socket that child processes do not inherit.
fn socket() -> io::Result<ws::SOCKET> {
    startup();
    // SAFETY: no pointers are passed.
    let s = unsafe {
        ws::WSASocketW(
            ws::AF_UNIX as i32,
            ws::SOCK_STREAM,
            0,
            std::ptr::null(),
            0,
            ws::WSA_FLAG_OVERLAPPED | ws::WSA_FLAG_NO_HANDLE_INHERIT,
        )
    };
    if s == ws::INVALID_SOCKET { Err(last_error()) } else { Ok(s) }
}

fn close(s: ws::SOCKET) {
    // SAFETY: s is a socket this module opened and owns.
    unsafe { ws::closesocket(s) };
}

/// A connection on an AF_UNIX socket.
#[derive(Debug)]
pub struct UnixStream(TcpStream);

impl UnixStream {
    pub fn connect(path: impl AsRef<Path>) -> io::Result<UnixStream> {
        let (a, len) = address(path.as_ref())?;
        let s = socket()?;
        // SAFETY: a is a SOCKADDR_UN of len bytes.
        if unsafe { ws::connect(s, (&raw const a).cast(), len) } != 0 {
            let e = last_error();
            close(s);
            return Err(e);
        }
        // SAFETY: s is a connected socket nothing else owns.
        Ok(UnixStream(unsafe { TcpStream::from_raw_socket(s as RawSocket) }))
    }

    pub fn try_clone(&self) -> io::Result<UnixStream> {
        self.0.try_clone().map(UnixStream)
    }

    pub fn set_read_timeout(&self, d: Option<Duration>) -> io::Result<()> {
        self.0.set_read_timeout(d)
    }

    pub fn set_write_timeout(&self, d: Option<Duration>) -> io::Result<()> {
        self.0.set_write_timeout(d)
    }

    pub fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        self.0.shutdown(how)
    }

    /// The process at the other end, from SIO_AF_UNIX_GETPEERPID.
    pub fn peer_pid(&self) -> Option<u32> {
        const SIO_AF_UNIX_GETPEERPID: u32 = 0x5800_0100;
        let (mut pid, mut n) = (0u32, 0u32);
        // SAFETY: pid is valid for 4 bytes, n for the count, and the socket
        // stays open while self lives.
        let r = unsafe {
            ws::WSAIoctl(
                self.0.as_raw_socket() as ws::SOCKET,
                SIO_AF_UNIX_GETPEERPID,
                std::ptr::null(),
                0,
                (&raw mut pid).cast(),
                4,
                &mut n,
                std::ptr::null_mut(),
                None,
            )
        };
        (r == 0 && pid != 0).then_some(pid)
    }
}

impl Read for UnixStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl Read for &UnixStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        (&self.0).read(buf)
    }
}

impl Write for UnixStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Write for &UnixStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        (&self.0).write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A listening AF_UNIX socket.
#[derive(Debug)]
pub struct UnixListener(ws::SOCKET);

impl UnixListener {
    pub fn bind(path: impl AsRef<Path>) -> io::Result<UnixListener> {
        let (a, len) = address(path.as_ref())?;
        let s = socket()?;
        // SAFETY: a is a SOCKADDR_UN of len bytes.
        if unsafe { ws::bind(s, (&raw const a).cast(), len) } != 0
            || unsafe { ws::listen(s, ws::SOMAXCONN as i32) } != 0
        {
            let e = last_error();
            close(s);
            return Err(e);
        }
        Ok(UnixListener(s))
    }

    pub fn accept(&self) -> io::Result<(UnixStream, ())> {
        // SAFETY: no address is asked for.
        let c = unsafe { ws::accept(self.0, std::ptr::null_mut(), std::ptr::null_mut()) };
        if c == ws::INVALID_SOCKET {
            return Err(last_error());
        }
        // SAFETY: c is a connected socket nothing else owns.
        Ok((UnixStream(unsafe { TcpStream::from_raw_socket(c as RawSocket) }), ()))
    }

    pub fn incoming(&self) -> impl Iterator<Item = io::Result<UnixStream>> + '_ {
        std::iter::repeat_with(|| self.accept().map(|(s, _)| s))
    }
}

impl Drop for UnixListener {
    fn drop(&mut self) {
        close(self.0);
    }
}

/// Whether this process runs elevated: as an administrator past UAC, or as
/// the system or a service account in the administrators' group.
pub fn elevated() -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    let mut tok: HANDLE = std::ptr::null_mut();
    // SAFETY: tok is valid for OpenProcessToken to write, e and n for
    // GetTokenInformation, and the token is closed once read.
    unsafe {
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut tok) == 0 {
            return false;
        }
        let mut e = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut n = 0u32;
        let ok = GetTokenInformation(
            tok,
            TokenElevation,
            (&raw mut e).cast(),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut n,
        ) != 0;
        CloseHandle(tok);
        ok && e.TokenIsElevated != 0
    }
}
