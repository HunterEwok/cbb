// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The least of HTTP/2 (RFC 9113) that the push service needs to post one
//! small request at a time to a platform's push service (APNs speaks only
//! HTTP/2): the preface and settings, one stream after another, flow
//! control both ways, PING and GOAWAY. Headers go out as HPACK literals
//! without indexing and without Huffman coding (RFC 7541, 6.2.2), and the
//! peer is told a header table of 0 bytes, so no table state is ever kept.
//! An answer's status is read from its header block; a status the block
//! codes in a way this reader does not decode (Huffman) is left to the
//! body, which every refusal of APNs carries as JSON.
//!
//! Over any Read + Write: TLS to the platform, or a plain socket to a test's
//! fake.

use std::io::{Read, Write};

use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, StreamOwned};

use crate::error::{Context, Error, Result};

/// A TLS connection to a platform's host.
pub type Tls = StreamOwned<ClientConnection, TcpStream>;

/// Dials `host` on port 443 with TLS that must agree on HTTP/2, and starts
/// the HTTP/2 connection; every read and write waits at most `timeout`.
pub fn dial(cfg: &Arc<ClientConfig>, host: &str, timeout: Duration) -> Result<Conn<Tls>> {
    let addr = (host, 443)
        .to_socket_addrs()
        .context(format!("cannot look up {host}"))?
        .next()
        .ok_or_else(|| Error::msg(format!("{host} has no address")))?;
    let tcp = TcpStream::connect_timeout(&addr, timeout).context(format!("cannot reach {host}"))?;
    let _ = tcp.set_nodelay(true);
    tcp.set_read_timeout(Some(timeout)).context("cannot set a timeout")?;
    tcp.set_write_timeout(Some(timeout)).context("cannot set a timeout")?;
    let name = ServerName::try_from(host.to_string()).map_err(|_| Error::msg("not a host name"))?;
    let conn = ClientConnection::new(cfg.clone(), name).context(format!("cannot start TLS to {host}"))?;
    let mut tls = StreamOwned::new(conn, tcp);
    while tls.conn.is_handshaking() {
        tls.conn.complete_io(&mut tls.sock).context(format!("TLS to {host} failed"))?;
    }
    if tls.conn.alpn_protocol() != Some(b"h2") {
        return Err(Error::msg(format!("{host} does not speak HTTP/2")));
    }
    Conn::start(tls)
}

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

const DATA: u8 = 0;
const HEADERS: u8 = 1;
const RST_STREAM: u8 = 3;
const SETTINGS: u8 = 4;
const PING: u8 = 6;
const GOAWAY: u8 = 7;
const WINDOW_UPDATE: u8 = 8;
const CONTINUATION: u8 = 9;

const END_STREAM: u8 = 0x1;
const ACK: u8 = 0x1;
const END_HEADERS: u8 = 0x4;
const PADDED: u8 = 0x8;
const PRIORITY: u8 = 0x20;

const SETTINGS_HEADER_TABLE_SIZE: u16 = 1;
const SETTINGS_ENABLE_PUSH: u16 = 2;
const SETTINGS_INITIAL_WINDOW_SIZE: u16 = 4;
const SETTINGS_MAX_FRAME_SIZE: u16 = 5;

/// The largest frame this side takes (the protocol's default).
const MAX_FRAME: usize = 16_384;
/// The most of an answer's body kept: refusals are short JSON.
const MAX_BODY: usize = 4096;
/// The window both sides start with.
const DEFAULT_WINDOW: i64 = 65_535;

/// An answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    /// The status, when the header block says it in a form read here.
    pub status: Option<u16>,
    /// The body, at most 4 KiB of it.
    pub body: Vec<u8>,
}

/// One HTTP/2 connection.
pub struct Conn<S: Read + Write> {
    io: S,
    next_stream: u32,
    /// What the peer lets this side send: on the connection, and its
    /// initial window for each new stream.
    send_window: i64,
    stream_initial: i64,
    peer_max_frame: usize,
    gone: bool,
}

fn header(len: usize, kind: u8, flags: u8, stream: u32) -> [u8; 9] {
    let l = (len as u32).to_be_bytes();
    let s = (stream & 0x7fff_ffff).to_be_bytes();
    [l[1], l[2], l[3], kind, flags, s[0], s[1], s[2], s[3]]
}

/// An HPACK integer with an `n`-bit prefix and the first byte's high bits.
fn hpack_int(out: &mut Vec<u8>, first: u8, n: u8, mut v: usize) {
    let max = (1usize << n) - 1;
    if v < max {
        out.push(first | v as u8);
        return;
    }
    out.push(first | max as u8);
    v -= max;
    while v >= 128 {
        out.push((v % 128) as u8 | 0x80);
        v /= 128;
    }
    out.push(v as u8);
}

fn hpack_str(out: &mut Vec<u8>, s: &[u8]) {
    hpack_int(out, 0, 7, s.len());
    out.extend_from_slice(s);
}

/// A header block: `:method POST` and `:scheme https` from the static
/// table, the rest literals without indexing.
pub fn header_block(authority: &str, path: &str, headers: &[(&str, &str)]) -> Vec<u8> {
    let mut b = Vec::new();
    b.push(0x80 | 3); // :method POST
    b.push(0x80 | 7); // :scheme https
    hpack_int(&mut b, 0x00, 4, 4); // :path, name from the static table
    hpack_str(&mut b, path.as_bytes());
    hpack_int(&mut b, 0x00, 4, 1); // :authority
    hpack_str(&mut b, authority.as_bytes());
    for (n, v) in headers {
        b.push(0x00);
        hpack_str(&mut b, n.as_bytes());
        hpack_str(&mut b, v.as_bytes());
    }
    b
}

/// Reads an HPACK integer of an `n`-bit prefix at `b[*i]`.
fn read_int(b: &[u8], i: &mut usize, n: u8) -> Option<usize> {
    let max = (1usize << n) - 1;
    let mut v = (*b.get(*i)? as usize) & max;
    *i += 1;
    if v < max {
        return Some(v);
    }
    let mut shift = 0u32;
    loop {
        let x = *b.get(*i)? as usize;
        *i += 1;
        v = v.checked_add((x & 0x7f).checked_shl(shift)?)?;
        if x & 0x80 == 0 {
            return Some(v);
        }
        shift += 7;
        if shift > 28 {
            return None;
        }
    }
}

/// The status a header block says, if it says it as an indexed field of
/// the static table or as a literal not Huffman-coded.
pub fn status_of(block: &[u8]) -> Option<u16> {
    let mut i = 0;
    while i < block.len() {
        let first = block[i];
        if first & 0x80 != 0 {
            let idx = read_int(block, &mut i, 7)?;
            let s = match idx {
                8 => 200,
                9 => 204,
                10 => 206,
                11 => 304,
                12 => 400,
                13 => 404,
                14 => 500,
                _ => continue,
            };
            return Some(s);
        }
        if first & 0xe0 == 0x20 {
            // A table size update.
            read_int(block, &mut i, 5)?;
            continue;
        }
        let prefix = if first & 0xc0 == 0x40 { 6 } else { 4 };
        let name_idx = read_int(block, &mut i, prefix)?;
        if name_idx == 0 {
            let huff = *block.get(i)? & 0x80 != 0;
            let len = read_int(block, &mut i, 7)?;
            let name = block.get(i..i.checked_add(len)?)?;
            i += len;
            let _ = (huff, name);
        }
        let huff = *block.get(i)? & 0x80 != 0;
        let len = read_int(block, &mut i, 7)?;
        let value = block.get(i..i.checked_add(len)?)?;
        i += len;
        // Indices 8 to 14 all name `:status`.
        if (8..=14).contains(&name_idx) {
            if huff {
                return None;
            }
            return std::str::from_utf8(value).ok()?.parse().ok();
        }
    }
    None
}

impl<S: Read + Write> Conn<S> {
    /// Starts a connection: the preface and this side's settings (no
    /// header table, no server push).
    pub fn start(mut io: S) -> Result<Conn<S>> {
        let mut out = PREFACE.to_vec();
        let settings: [(u16, u32); 2] = [(SETTINGS_HEADER_TABLE_SIZE, 0), (SETTINGS_ENABLE_PUSH, 0)];
        out.extend_from_slice(&header(settings.len() * 6, SETTINGS, 0, 0));
        for (id, v) in settings {
            out.extend_from_slice(&id.to_be_bytes());
            out.extend_from_slice(&v.to_be_bytes());
        }
        io.write_all(&out).map_err(|e| Error::with("cannot start HTTP/2", e))?;
        io.flush().map_err(|e| Error::with("cannot start HTTP/2", e))?;
        Ok(Conn {
            io,
            next_stream: 1,
            send_window: DEFAULT_WINDOW,
            stream_initial: DEFAULT_WINDOW,
            peer_max_frame: MAX_FRAME,
            gone: false,
        })
    }

    /// Whether the peer said it takes no new streams (GOAWAY), or the
    /// connection broke: a new one is needed.
    pub fn gone(&self) -> bool {
        self.gone || self.next_stream > 0x7fff_0000
    }

    fn read_frame(&mut self) -> Result<(u8, u8, u32, Vec<u8>)> {
        let mut h = [0u8; 9];
        self.io.read_exact(&mut h).map_err(|e| {
            self.gone = true;
            Error::with("the push platform closed the connection", e)
        })?;
        let len = u32::from_be_bytes([0, h[0], h[1], h[2]]) as usize;
        if len > MAX_FRAME {
            self.gone = true;
            return Err(Error::msg("the push platform sent a frame over the size agreed"));
        }
        let stream = u32::from_be_bytes([h[5], h[6], h[7], h[8]]) & 0x7fff_ffff;
        let mut p = vec![0u8; len];
        self.io.read_exact(&mut p).map_err(|e| {
            self.gone = true;
            Error::with("the push platform closed the connection", e)
        })?;
        Ok((h[3], h[4], stream, p))
    }

    fn write(&mut self, b: &[u8]) -> Result<()> {
        self.io.write_all(b).and_then(|()| self.io.flush()).map_err(|e| {
            self.gone = true;
            Error::with("cannot write to the push platform", e)
        })
    }

    /// Answers what any frame on the connection asks: settings (acknowledged,
    /// windows and frame size taken), PING, WINDOW_UPDATE, GOAWAY.
    fn control(
        &mut self,
        kind: u8,
        flags: u8,
        stream: u32,
        p: &[u8],
        stream_window: &mut i64,
        ours: u32,
    ) -> Result<()> {
        match kind {
            SETTINGS if flags & ACK == 0 => {
                for s in p.chunks_exact(6) {
                    let id = u16::from_be_bytes([s[0], s[1]]);
                    let v = u32::from_be_bytes([s[2], s[3], s[4], s[5]]);
                    match id {
                        SETTINGS_INITIAL_WINDOW_SIZE => {
                            *stream_window += i64::from(v) - self.stream_initial;
                            self.stream_initial = i64::from(v);
                        }
                        SETTINGS_MAX_FRAME_SIZE => self.peer_max_frame = (v as usize).clamp(MAX_FRAME, 1 << 24),
                        _ => {}
                    }
                }
                self.write(&header(0, SETTINGS, ACK, 0))?;
            }
            PING if flags & ACK == 0 && p.len() == 8 => {
                let mut out = header(8, PING, ACK, 0).to_vec();
                out.extend_from_slice(p);
                self.write(&out)?;
            }
            WINDOW_UPDATE if p.len() == 4 => {
                let inc = i64::from(u32::from_be_bytes([p[0], p[1], p[2], p[3]]) & 0x7fff_ffff);
                if stream == 0 {
                    self.send_window += inc;
                } else if stream == ours {
                    *stream_window += inc;
                }
            }
            GOAWAY => self.gone = true,
            _ => {}
        }
        Ok(())
    }

    /// Posts one request and waits for its answer.
    pub fn post(&mut self, authority: &str, path: &str, headers: &[(&str, &str)], body: &[u8]) -> Result<Answer> {
        if self.gone() {
            return Err(Error::msg("the connection to the push platform is closed"));
        }
        let id = self.next_stream;
        self.next_stream += 2;
        let block = header_block(authority, path, headers);
        if block.len() > self.peer_max_frame || body.len() > self.peer_max_frame {
            return Err(Error::msg("a request too large for one frame"));
        }
        let mut out = header(block.len(), HEADERS, END_HEADERS, id).to_vec();
        out.extend_from_slice(&block);
        self.write(&out)?;
        let mut stream_window = self.stream_initial;
        let need = body.len() as i64;
        // Wait until both windows hold the body.
        while self.send_window < need || stream_window < need {
            let (kind, flags, stream, p) = self.read_frame()?;
            if stream == id && kind == RST_STREAM {
                return Err(Error::msg("the push platform reset the request"));
            }
            self.control(kind, flags, stream, &p, &mut stream_window, id)?;
            if self.gone && kind == GOAWAY {
                return Err(Error::msg("the push platform is closing the connection"));
            }
        }
        let mut out = header(body.len(), DATA, END_STREAM, id).to_vec();
        out.extend_from_slice(body);
        self.write(&out)?;
        self.send_window -= need;
        let mut answer = Answer { status: None, body: Vec::new() };
        let mut block = Vec::new();
        loop {
            let (kind, flags, stream, p) = self.read_frame()?;
            if stream != id {
                self.control(kind, flags, stream, &p, &mut stream_window, id)?;
                if self.gone && kind == GOAWAY {
                    // Streams below its last ID still finish; ours is
                    // answered or reset below if it is one of them.
                    let last = p.get(..4).map_or(0, |b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]) & 0x7fff_ffff);
                    if last < id {
                        return Err(Error::msg("the push platform is closing the connection"));
                    }
                }
                continue;
            }
            match kind {
                HEADERS | CONTINUATION => {
                    let mut p = &p[..];
                    if kind == HEADERS {
                        if flags & PADDED != 0 {
                            let pad = *p.first().unwrap_or(&0) as usize;
                            p = p.get(1..p.len().saturating_sub(pad)).unwrap_or(&[]);
                        }
                        if flags & PRIORITY != 0 {
                            p = p.get(5..).unwrap_or(&[]);
                        }
                    }
                    block.extend_from_slice(p);
                    if flags & END_HEADERS != 0 && answer.status.is_none() {
                        answer.status = status_of(&block);
                        block.clear();
                    }
                }
                DATA => {
                    let mut d = &p[..];
                    if flags & PADDED != 0 {
                        let pad = *d.first().unwrap_or(&0) as usize;
                        d = d.get(1..d.len().saturating_sub(pad)).unwrap_or(&[]);
                    }
                    let room = MAX_BODY.saturating_sub(answer.body.len());
                    answer.body.extend_from_slice(&d[..d.len().min(room)]);
                    // Give the connection's window back (the stream ends
                    // with this answer).
                    if !p.is_empty() {
                        let mut w = header(4, WINDOW_UPDATE, 0, 0).to_vec();
                        w.extend_from_slice(&(p.len() as u32).to_be_bytes());
                        self.write(&w)?;
                    }
                }
                RST_STREAM => return Err(Error::msg("the push platform reset the request")),
                _ => {}
            }
            if flags & END_STREAM != 0 && (kind == HEADERS || kind == DATA) {
                return Ok(answer);
            }
        }
    }
}
