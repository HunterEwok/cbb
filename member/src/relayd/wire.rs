// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! What the relay's two kinds of messages share (docs/protocol.md, section
//! 14; their frames are `wire3`'s): the request that starts each
//! connection in a tunnel at the relay's member port and the notes the
//! relay answers with, as the relay's code takes them, and one deadline
//! for all a setup reads and writes.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

/// The most a request or a note takes.
pub const MAX_LINE: usize = 16 << 10;

/// The first message of a connection in a tunnel.
#[derive(Default)]
pub struct Request {
    /// Keep this connection for the notes.
    pub watch: bool,
    /// Join this connection to that of the device of this name (base64).
    pub dial: String,
    /// The ticket of a call this connection answers (base64).
    pub answer: String,
}

/// What the relay tells a device.
#[derive(Clone, Default, Debug, PartialEq)]
pub struct Note {
    /// The other devices of the group on the relay now, by name.
    pub online: Option<Vec<String>>,
    /// The name of a device that dials this one, and the ticket to answer
    /// that call with.
    pub call: String,
    pub ticket: String,
    /// Joined: the member protocol follows.
    pub ok: bool,
    pub error: String,
}

impl Note {
    pub fn error(msg: &str) -> Note {
        Note { error: msg.to_string(), ..Note::default() }
    }
}

/// A connection with one deadline for all it reads and writes, as Go's
/// SetDeadline: each read or write waits only for the time left, so a peer
/// that sends or takes a byte now and then still runs out of time.
pub struct Deadline {
    pub s: TcpStream,
    until: Option<Instant>,
}

impl Deadline {
    pub fn new(s: TcpStream, d: Duration) -> Deadline {
        Deadline { s, until: Some(Instant::now() + d) }
    }

    /// Ends the deadline: the connection waits as long as it needs from now.
    pub fn clear(&mut self) {
        self.until = None;
        let _ = self.s.set_read_timeout(None);
        let _ = self.s.set_write_timeout(None);
    }

    /// The time left, or an error once it is up.
    fn left(&self) -> io::Result<Option<Duration>> {
        let Some(until) = self.until else { return Ok(None) };
        let left = until.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "the deadline passed"));
        }
        Ok(Some(left))
    }
}

impl Read for Deadline {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let left = self.left()?;
        self.s.set_read_timeout(left)?;
        self.s.read(buf)
    }
}

impl Write for Deadline {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let left = self.left()?;
        self.s.set_write_timeout(left)?;
        self.s.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.s.flush()
    }
}
