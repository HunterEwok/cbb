// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The relay's messages (docs/protocol.md, section 14), its side of what
//! member/src/relay.rs sends: the registration's, one frame each, and those
//! inside the tunnel at the relay's member port, where each connection
//! starts with one request and the relay answers with notes.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use cbb_core::authority::Record;
use cbb_core::certs::b64;
use cbb_core::credential::Credential;

use crate::error::{Error, Result};

/// The most a request or a note takes.
pub const MAX_LINE: usize = 64 << 10;
/// The most a claim takes, which carries the group's authority records.
pub const MAX_CLAIM: usize = 1 << 20;

/// The relay's first message of a registration.
#[derive(Serialize)]
pub struct Challenge {
    /// The relay's ephemeral X25519 key.
    #[serde(with = "b64")]
    pub e: Vec<u8>,
    /// Asks a device that registers with credentials for the period
    /// credential and the group's roots: a relay that serves a fixed list of
    /// groups knows them by their roots.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub roots: bool,
}

/// The device's answer: its WireGuard key and the proof that it holds it,
/// with the group's records or its credentials.
#[derive(Deserialize)]
pub struct Claim {
    #[serde(with = "b64", default)]
    pub key: Vec<u8>,
    #[serde(with = "b64", default)]
    pub proof: Vec<u8>,
    #[serde(default)]
    pub records: Vec<Record>,
    #[serde(default)]
    pub credentials: Vec<Credential>,
    #[serde(with = "b64::list", default)]
    pub roots: Vec<Vec<u8>>,
}

/// The relay's last message of a registration: why it refused the device,
/// or its WireGuard key, the device's preshared key and tunnel address.
#[derive(Serialize, Default)]
pub struct Welcome {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub error: String,
    #[serde(with = "b64::opt", skip_serializing_if = "Option::is_none")]
    pub key: Option<Vec<u8>>,
    #[serde(with = "b64::opt", skip_serializing_if = "Option::is_none")]
    pub psk: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub addr: String,
}

/// The first message of a connection in a tunnel.
#[derive(Deserialize, Default)]
pub struct Request {
    /// Keep this connection for the notes.
    #[serde(default)]
    pub watch: bool,
    /// Join this connection to that of the device of this name.
    #[serde(default)]
    pub dial: String,
    /// The ticket of a call this connection answers.
    #[serde(default)]
    pub answer: String,
}

/// What the relay tells a device.
#[derive(Serialize, Clone, Default, Debug, PartialEq)]
pub struct Note {
    /// The other devices of the group on the relay now, by name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub online: Option<Vec<String>>,
    /// The name of a device that dials this one, and the ticket to answer
    /// that call with.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub call: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub ticket: String,
    /// Joined: the member protocol follows.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub ok: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub error: String,
}

impl Note {
    pub fn error(msg: &str) -> Note {
        Note { error: msg.to_string(), ..Note::default() }
    }
}

/// Sends v as one frame, within d.
pub fn write_frame<T: Serialize>(c: &mut impl Write, v: &T, max: usize) -> Result<()> {
    let f = cbb_core::wire::json_frame(v, max)?;
    c.write_all(&f).and_then(|()| c.flush()).map_err(|e| Error::msg(format!("cannot send a frame: {e}")))
}

/// Reads one frame exactly, so that nothing after it is taken from the
/// connection: the member protocol follows an answer.
pub fn read_frame(c: &mut impl Read, max: usize) -> Result<Vec<u8>> {
    let mut head = [0u8; 4];
    c.read_exact(&mut head).map_err(|e| Error::msg(format!("cannot read a frame: {e}")))?;
    let n = cbb_core::wire::frame_len(head, max)?;
    if n == 0 {
        // As Go's readLine: a frame holds a JSON object.
        return Err(Error::msg("an empty frame"));
    }
    let mut body = vec![0u8; n];
    c.read_exact(&mut body).map_err(|e| Error::msg(format!("cannot read a frame: {e}")))?;
    Ok(body)
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

/// Sends a note on a connection in a tunnel, within d.
pub fn send_note(c: &TcpStream, n: &Note, d: Duration) -> Result<()> {
    let mut w = Deadline::new(c.try_clone().map_err(|e| Error::msg(format!("cannot send a frame: {e}")))?, d);
    write_frame(&mut w, n, MAX_LINE)
}

/// Reads the request of a connection in a tunnel, within d.
pub fn read_request(c: &TcpStream, d: Duration) -> Result<Request> {
    let mut r = Deadline::new(c.try_clone().map_err(|e| Error::msg(format!("cannot read a frame: {e}")))?, d);
    let f = read_frame(&mut r, MAX_LINE)?;
    r.clear();
    serde_json::from_slice(&f).map_err(|_| Error::msg("a request that does not decode"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A peer that sends a byte now and then, each well within the time a
    /// read may wait, still runs out of the request's time.
    #[test]
    fn a_request_has_one_deadline() {
        let ln = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut peer = TcpStream::connect(ln.local_addr().unwrap()).unwrap();
        let (c, _) = ln.accept().unwrap();
        let dribble = std::thread::spawn(move || {
            // A frame of 1000 bytes, one byte every 100 ms.
            let _ = peer.write_all(&1000u32.to_be_bytes());
            for _ in 0..30 {
                std::thread::sleep(Duration::from_millis(100));
                if peer.write_all(b" ").is_err() {
                    return;
                }
            }
        });
        let start = Instant::now();
        assert!(read_request(&c, Duration::from_millis(600)).is_err());
        let took = start.elapsed();
        assert!(took < Duration::from_millis(1500), "the request took {took:?}");
        drop(c);
        dribble.join().unwrap();
    }

    /// The notes as Go's encoding/json writes them, which the devices' Go
    /// side in the tests reads: fields left out when empty, but
    /// an empty list of devices kept, which says nobody else is there.
    #[test]
    fn notes_as_go_writes_them() {
        let j = |n: &Note| serde_json::to_string(n).unwrap();
        assert_eq!(j(&Note { online: Some(vec![]), ..Note::default() }), r#"{"online":[]}"#);
        assert_eq!(j(&Note { ok: true, ..Note::default() }), r#"{"ok":true}"#);
        assert_eq!(j(&Note::error("no")), r#"{"error":"no"}"#);
        let c = Challenge { e: vec![1, 2], roots: false };
        assert_eq!(serde_json::to_string(&c).unwrap(), r#"{"e":"AQI="}"#);
        let w = Welcome { error: "full".into(), ..Welcome::default() };
        assert_eq!(serde_json::to_string(&w).unwrap(), r#"{"error":"full"}"#);
        let r: Request = serde_json::from_str(r#"{"dial":"x"}"#).unwrap();
        assert_eq!((r.watch, r.dial.as_str(), r.answer.as_str()), (false, "x", ""));
    }

    #[test]
    fn frames_are_read_exactly() {
        let mut buf = Vec::new();
        write_frame(&mut buf, &Note { ok: true, ..Note::default() }, MAX_LINE).unwrap();
        buf.extend_from_slice(b"after");
        let mut r = &buf[..];
        assert_eq!(read_frame(&mut r, MAX_LINE).unwrap(), br#"{"ok":true}"#);
        assert_eq!(r, b"after");
        let mut big = &(u32::try_from(MAX_LINE + 1).unwrap().to_be_bytes())[..];
        assert!(read_frame(&mut big, MAX_LINE).is_err());
    }

    /// As Go's FuzzRelayWire, over random frames: a frame is never read past
    /// its end, nor taken without its length, cut short, empty or over the
    /// limit; what decodes it is only serde.
    #[test]
    fn random_frames_are_read_exactly() {
        let mut x = 2026u64;
        let mut next = move |n: usize| {
            x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            ((x >> 33) as usize) % n
        };
        let seeds: [&[u8]; 4] = [
            br#"{"watch":true}"#,
            br#"{"dial":"00112233445566778899aabbccddeeff"}"#,
            br#"{"answer":"x"}"#,
            br#"{"e":"AAAA","roots":true}"#,
        ];
        for i in 0..20_000 {
            let mut data = Vec::new();
            let seed = seeds[i % seeds.len()];
            let n = match next(5) {
                0 => seed.len(),
                1 => next(MAX_LINE + 2),
                2 => 0,
                3 => MAX_LINE + 1 + next(1 << 20),
                _ => seed.len() + next(8),
            };
            data.extend_from_slice(&u32::try_from(n).unwrap().to_be_bytes());
            data.extend_from_slice(seed);
            for _ in 0..next(64) {
                data.push(next(256) as u8);
            }
            data.truncate(next(data.len() + 1).max(data.len().min(next(2) * data.len())));
            let mut r = &data[..];
            let got = read_frame(&mut r, MAX_LINE);
            if data.len() < 4 {
                assert!(got.is_err(), "a frame without its length");
                continue;
            }
            if n == 0 || n > MAX_LINE {
                assert!(got.is_err(), "a frame of {n} bytes");
            } else if data.len() < 4 + n {
                assert!(got.is_err(), "a frame cut short");
            } else {
                assert_eq!(got.unwrap(), &data[4..4 + n]);
                assert_eq!(r, &data[4 + n..], "read past the frame");
                let _ = serde_json::from_slice::<Request>(&data[4..4 + n]);
                let _ = serde_json::from_slice::<Claim>(&data[4..4 + n]);
            }
        }
    }
}
