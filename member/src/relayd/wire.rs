// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The relay's messages (docs/protocol.md, section 14), its side of what
//! member/src/relay.rs sends: the registration's, one frame each, and those
//! inside the tunnel at the relay's member port, where each connection
//! starts with one request and the relay answers with notes.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

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
    let mut body = vec![0u8; n];
    c.read_exact(&mut body).map_err(|e| Error::msg(format!("cannot read a frame: {e}")))?;
    Ok(body)
}

/// Sends a note on a connection in a tunnel, within d.
pub fn send_note(c: &TcpStream, n: &Note, d: Duration) -> Result<()> {
    let _ = c.set_write_timeout(Some(d));
    let mut w = c;
    write_frame(&mut w, n, MAX_LINE)
}

/// Reads the request of a connection in a tunnel, waiting at most d.
pub fn read_request(c: &TcpStream, d: Duration) -> Result<Request> {
    let _ = c.set_read_timeout(Some(d));
    let mut r = c;
    let f = read_frame(&mut r, MAX_LINE)?;
    let _ = c.set_read_timeout(None);
    serde_json::from_slice(&f).map_err(|_| Error::msg("a request that does not decode"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The notes as Go's relay writes them: fields left out when empty, but
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
}
