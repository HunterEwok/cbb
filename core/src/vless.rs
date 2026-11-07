// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! VLESS over XHTTP for the lite member's tunnel (docs/protocol.md, section
//! 11, "VLESS"), without I/O: the settings of a hub's offer and their
//! checks, VLESS's request and response headers, its framing of UDP
//! packets, and the shape of XHTTP's `packet-up` requests (Xray-core's
//! splithttp, which the forwarder runs). The lite member (member/src/vless.rs)
//! carries them over TLS and TCP. VLESS adds no security: the boundary stays
//! WireGuard, then the member TLS.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use serde::Deserialize;
use serde_json::Value;

use crate::error::{Error, Result};

/// The most an upload carries, as the forwarder takes it
/// (internal/vless's MaxPostBytes).
pub const MAX_POST: usize = 32 << 10;

/// The VLESS settings of a hub's offer, with XHTTP: REALITY needs a
/// browser's ClientHello, which rustls does not make, so the lite member
/// refuses it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Link {
    /// The web server's address, `ip:port`.
    pub endpoint: String,
    /// The site's name, which its certificate must carry.
    pub server_name: String,
    /// The path the web server passes to the forwarder.
    pub path: String,
    /// The group's VLESS user ID.
    pub id: [u8; 16],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Raw {
    #[serde(default)]
    transport: String,
    endpoint: String,
    #[serde(default)]
    public_key: Option<Value>,
    #[serde(default)]
    short_id: Option<String>,
    server_name: String,
    #[serde(default)]
    path: String,
    id: String,
}

impl Link {
    /// Reads the settings of an offer, refusing what internal/tunnel's
    /// VLESS.Check refuses, and REALITY.
    pub fn from_offer(v: &Value) -> Result<Link> {
        let r: Raw = serde_json::from_value(v.clone())
            .map_err(|e| Error::msg(format!("the hub's VLESS settings do not read: {e}")))?;
        match r.transport.as_str() {
            "xhttp" => {}
            "" => {
                return Err(Error::msg(
                    "the hub's forwarder runs VLESS inside REALITY, which the lite member cannot speak; it needs XHTTP",
                ));
            }
            t => return Err(Error::msg(format!("the hub's VLESS transport {t:?} needs a newer version"))),
        }
        if r.public_key.is_some() || r.short_id.is_some() {
            return Err(Error::msg("the hub's XHTTP settings carry a REALITY key"));
        }
        check_endpoint(&r.endpoint)?;
        check_server_name(&r.server_name)?;
        check_path(&r.path)?;
        Ok(Link { endpoint: r.endpoint, server_name: r.server_name, path: r.path, id: parse_id(&r.id)? })
    }
}

/// `ip:port` with a port that is not 0, IPv4 or IPv6 in brackets.
fn check_endpoint(e: &str) -> Result<()> {
    let bad = || Error::msg(format!("{e:?} is not the forwarder's address, ip:port"));
    let (host, port) = e.rsplit_once(':').ok_or_else(bad)?;
    let port: u16 = port.parse().map_err(|_| bad())?;
    if port == 0 || Some(port.to_string().len()) != e.len().checked_sub(host.len()).and_then(|n| n.checked_sub(1)) {
        return Err(bad());
    }
    let ok = match host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        Some(v6) => v6.parse::<core::net::Ipv6Addr>().is_ok(),
        None => host.parse::<core::net::Ipv4Addr>().is_ok(),
    };
    if ok { Ok(()) } else { Err(bad()) }
}

/// A site's name as internal/tunnel's CheckServerName takes it: labels of
/// lowercase letters, digits and hyphens, a top level of 2 to 63 letters.
pub fn check_server_name(name: &str) -> Result<()> {
    let bad = || Error::msg(format!("{name:?} is not a site's name, such as www.example.com"));
    let labels: Vec<&str> = name.split('.').collect();
    if labels.len() < 2 {
        return Err(bad());
    }
    let (tld, rest) = labels.split_last().ok_or_else(bad)?;
    if !(2..=63).contains(&tld.len()) || !tld.bytes().all(|c| c.is_ascii_lowercase()) {
        return Err(bad());
    }
    for l in rest {
        let ok = (1..=63).contains(&l.len())
            && l.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
            && !l.starts_with('-')
            && !l.ends_with('-');
        if !ok {
            return Err(bad());
        }
    }
    Ok(())
}

fn path_part(p: &str, lo: usize, hi: usize) -> bool {
    (lo..=hi).contains(&p.len()) && p.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
}

/// An XHTTP path as internal/tunnel's CheckVLESSPath takes it: a slash and
/// 8 to 64 of A-Z a-z 0-9 - _, then maybe a slash and the group's own part
/// of 16 to 64.
pub fn check_path(p: &str) -> Result<()> {
    let bad = || Error::msg(format!("{p:?} is not a path such as /AbC-12_xyz0123456"));
    let rest = p.strip_prefix('/').ok_or_else(bad)?;
    let ok = match rest.split_once('/') {
        Some((a, b)) => path_part(a, 8, 64) && path_part(b, 16, 64),
        None => path_part(rest, 8, 64),
    };
    if ok { Ok(()) } else { Err(bad()) }
}

/// A VLESS user ID as internal/tunnel's CheckVLESSID takes it: a UUID of
/// version 4 in lowercase.
pub fn parse_id(s: &str) -> Result<[u8; 16]> {
    let bad = || Error::msg(format!("{s:?} is not a VLESS user ID"));
    let b = s.as_bytes();
    let at = |i: usize| b.get(i).copied();
    if b.len() != 36
        || [8, 13, 18, 23].iter().any(|&i| at(i) != Some(b'-'))
        || at(14) != Some(b'4')
        || !at(19).is_some_and(|c| b"89ab".contains(&c))
    {
        return Err(bad());
    }
    let d = |c: u8| match c {
        b'0'..=b'9' => Some(c.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(c.wrapping_sub(b'a').wrapping_add(10)),
        _ => None,
    };
    let hex: Vec<u8> = b.iter().copied().filter(|&c| c != b'-').collect();
    let mut id = [0u8; 16];
    for (out, pair) in id.iter_mut().zip(hex.chunks_exact(2)) {
        let [h, l] = pair else { return Err(bad()) };
        *out = d(*h).zip(d(*l)).map(|(h, l)| h << 4 | l).ok_or_else(bad)?;
    }
    Ok(id)
}

/// The VLESS request header for UDP: version 0, the user ID, no addons,
/// the command UDP (2) and a target. The forwarder sends every packet to
/// its own UDP port whatever the target, so it names the loopback address
/// and WireGuard's port.
pub fn request_header(id: &[u8; 16]) -> Vec<u8> {
    let mut h = Vec::with_capacity(26);
    h.push(0);
    h.extend_from_slice(id);
    h.push(0); // no addons
    h.push(2); // UDP
    h.extend_from_slice(&51820u16.to_be_bytes());
    h.push(1); // IPv4
    h.extend_from_slice(&[127, 0, 0, 1]);
    h
}

/// One UDP packet as VLESS frames it: its length in two bytes, big-endian,
/// then the packet.
pub fn frame(packet: &[u8]) -> Result<Vec<u8>> {
    let n = u16::try_from(packet.len()).map_err(|_| Error::msg("a packet larger than 64 KiB"))?;
    let mut f = Vec::with_capacity(packet.len().saturating_add(2));
    f.extend_from_slice(&n.to_be_bytes());
    f.extend_from_slice(packet);
    Ok(f)
}

/// Reads the forwarder's answers as they come: VLESS's response header
/// (version 0, then its addons, with their length), then UDP packets
/// framed as `frame` frames them, in pieces of any size.
#[derive(Default)]
pub struct Down {
    buf: Vec<u8>,
    header: bool,
}

/// The most the reader holds of a packet that has not all come.
const MAX_HELD: usize = 64 << 10;

impl Down {
    /// Takes the next bytes of the download and returns the packets they
    /// complete.
    pub fn push(&mut self, data: &[u8]) -> Result<Vec<Vec<u8>>> {
        self.buf.extend_from_slice(data);
        if !self.header {
            let [version, addons, rest @ ..] = self.buf.as_slice() else {
                return Ok(Vec::new());
            };
            if *version != 0 {
                return Err(Error::msg(format!("the forwarder answers in VLESS version {version}")));
            }
            let n = usize::from(*addons);
            if rest.len() < n {
                return Ok(Vec::new());
            }
            self.buf.drain(..n.saturating_add(2));
            self.header = true;
        }
        let mut out = Vec::new();
        let mut rest = self.buf.as_slice();
        while let [hi, lo, tail @ ..] = rest {
            let n = usize::from(u16::from_be_bytes([*hi, *lo]));
            let Some((packet, after)) = tail.split_at_checked(n) else {
                break;
            };
            out.push(packet.to_vec());
            rest = after;
        }
        let used = self.buf.len().saturating_sub(rest.len());
        self.buf.drain(..used);
        if self.buf.len() > MAX_HELD {
            return Err(Error::msg("the forwarder sent a packet that does not end"));
        }
        Ok(out)
    }
}

/// The HTTP/1.1 request of XHTTP's `packet-up` mode: the download
/// (`GET {path}/{session}`, `seq` None) or the upload `seq`
/// (`POST {path}/{session}/{seq}` with the body), each with Xray's padding,
/// a `Referer` whose query `x_padding` is `padding` X's (100 to 1000 by
/// default on the forwarder).
pub fn request(link: &Link, session: &str, seq: Option<u64>, body_len: usize, padding: usize) -> String {
    let target = match seq {
        Some(s) => format!("{}/{session}/{s}", link.path),
        None => format!("{}/{session}", link.path),
    };
    let pad: String = core::iter::repeat_n('X', padding).collect();
    let host = &link.server_name;
    match seq {
        Some(_) => format!(
            "POST {target} HTTP/1.1\r\nHost: {host}\r\nReferer: https://{host}{target}?x_padding={pad}\r\nContent-Length: {body_len}\r\nContent-Type: application/octet-stream\r\nConnection: keep-alive\r\n\r\n"
        ),
        None => format!(
            "GET {target} HTTP/1.1\r\nHost: {host}\r\nReferer: https://{host}{target}?x_padding={pad}\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n"
        ),
    }
}

/// How the body of a response ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Body {
    /// After so many bytes.
    Length(u64),
    /// In HTTP/1.1's chunks (`Chunked` reads them).
    Chunked,
    /// When the server closes the connection.
    Close,
}

/// The head of an HTTP/1.1 response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Head {
    pub status: u16,
    /// The head's length in bytes, with the blank line after it.
    pub len: usize,
    pub body: Body,
    /// The server closes the connection after this response.
    pub close: bool,
}

/// The most a response's head may be.
const MAX_HEAD: usize = 16 << 10;

/// Reads the head of a response at the start of buf: None while it has not
/// all come.
pub fn parse_head(buf: &[u8]) -> Result<Option<Head>> {
    let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
        if buf.len() > MAX_HEAD {
            return Err(Error::msg("the web server's answer has a head that does not end"));
        }
        return Ok(None);
    };
    if end > MAX_HEAD {
        return Err(Error::msg("the web server's answer has a head that does not end"));
    }
    let bad = || Error::msg("the web server does not answer in HTTP/1.1");
    let head = core::str::from_utf8(buf.get(..end).ok_or_else(bad)?).map_err(|_| bad())?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next().ok_or_else(bad)?;
    let rest =
        status_line.strip_prefix("HTTP/1.1 ").or_else(|| status_line.strip_prefix("HTTP/1.0 ")).ok_or_else(bad)?;
    let code = rest.get(..3).ok_or_else(bad)?;
    if !code.bytes().all(|b| b.is_ascii_digit()) || rest.as_bytes().get(3).is_some_and(|&b| b != b' ') {
        return Err(bad());
    }
    let status: u16 = code.parse().map_err(|_| bad())?;
    let mut body = Body::Close;
    let mut length = None;
    let mut close = status_line.starts_with("HTTP/1.0");
    for line in lines {
        let (name, value) = line.split_once(':').ok_or_else(bad)?;
        let value = value.trim();
        if name.eq_ignore_ascii_case("transfer-encoding") {
            if !value.eq_ignore_ascii_case("chunked") {
                return Err(Error::msg(format!("the web server sends its answer in {value:?}")));
            }
            body = Body::Chunked;
        } else if name.eq_ignore_ascii_case("content-length") {
            let n: u64 = value.parse().map_err(|_| bad())?;
            if length.is_some_and(|l| l != n) {
                return Err(bad());
            }
            length = Some(n);
        } else if name.eq_ignore_ascii_case("connection") {
            close = value.split(',').any(|t| t.trim().eq_ignore_ascii_case("close"));
        }
    }
    if body == Body::Chunked {
        if length.is_some() {
            return Err(bad());
        }
    } else if let Some(n) = length {
        body = Body::Length(n);
    } else if status == 204 || status == 304 || (100..200).contains(&status) {
        body = Body::Length(0);
    }
    if body == Body::Close {
        close = true;
    }
    Ok(Some(Head { status, len: end.saturating_add(4), body, close }))
}

/// Reads a body in HTTP/1.1's chunks as it comes, in pieces of any size.
#[derive(Default)]
pub struct Chunked {
    buf: Vec<u8>,
    state: Chunk,
}

#[derive(Default, Clone, Copy, PartialEq, Eq)]
enum Chunk {
    /// The line with the next chunk's size.
    #[default]
    Size,
    /// So many bytes of a chunk still to come.
    Data(usize),
    /// The line end after a chunk.
    DataEnd,
    /// The trailer after the last chunk, up to its blank line.
    Trailer,
    Done,
}

/// The longest line of a chunk's size or of the trailer.
const MAX_LINE: usize = 4 << 10;

impl Chunked {
    /// Takes the next bytes and adds the body's bytes they hold to out.
    pub fn push(&mut self, data: &[u8], out: &mut Vec<u8>) -> Result<()> {
        let bad = || Error::msg("the web server's answer has a bad chunk");
        let mut buf = core::mem::take(&mut self.buf);
        buf.extend_from_slice(data);
        let mut rest = buf.as_slice();
        loop {
            match self.state {
                Chunk::Done => {
                    rest = &[];
                    break;
                }
                Chunk::Data(n) => {
                    let (now, after) = rest.split_at(n.min(rest.len()));
                    out.extend_from_slice(now);
                    rest = after;
                    if now.len() < n {
                        self.state = Chunk::Data(n.saturating_sub(now.len()));
                        break;
                    }
                    self.state = Chunk::DataEnd;
                }
                Chunk::DataEnd => match rest {
                    [b'\r', b'\n', after @ ..] => {
                        rest = after;
                        self.state = Chunk::Size;
                    }
                    [] | [b'\r'] => break,
                    _ => return Err(bad()),
                },
                Chunk::Size | Chunk::Trailer => {
                    let Some(end) = rest.windows(2).position(|w| w == b"\r\n") else {
                        if rest.len() > MAX_LINE {
                            return Err(bad());
                        }
                        break;
                    };
                    if end > MAX_LINE {
                        return Err(bad());
                    }
                    let (line, after) = rest.split_at(end);
                    rest = after.get(2..).unwrap_or_default();
                    if self.state == Chunk::Trailer {
                        if line.is_empty() {
                            self.state = Chunk::Done;
                        }
                        continue;
                    }
                    let size = line.split(|&b| b == b';').next().unwrap_or_default();
                    let size = core::str::from_utf8(size).map_err(|_| bad())?.trim();
                    if size.is_empty() || size.len() > 8 {
                        return Err(bad());
                    }
                    let n = usize::from_str_radix(size, 16).map_err(|_| bad())?;
                    self.state = if n == 0 { Chunk::Trailer } else { Chunk::Data(n) };
                }
            }
        }
        self.buf = rest.to_vec();
        Ok(())
    }

    /// Reports whether the last chunk and the trailer have come.
    pub fn done(&self) -> bool {
        self.state == Chunk::Done
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offer() -> Value {
        serde_json::json!({
            "transport": "xhttp",
            "endpoint": "192.0.2.7:443",
            "server_name": "cbb.example.org",
            "path": "/AbC-12_xyz0123456/a-group-of-its-own",
            "id": "6f1c2b9e-3d4a-4f5b-8c7d-0e1f2a3b4c5d",
        })
    }

    #[test]
    fn reads_an_offer() {
        let l = Link::from_offer(&offer()).unwrap();
        assert_eq!(l.endpoint, "192.0.2.7:443");
        assert_eq!(l.id[0], 0x6f);
        assert_eq!(l.id[15], 0x5d);
        let bad = |k: &str, v: Value| {
            let mut o = offer();
            o[k] = v;
            Link::from_offer(&o).is_err()
        };
        assert!(bad("transport", "".into()), "REALITY");
        assert!(bad("transport", "grpc".into()));
        assert!(bad("endpoint", "192.0.2.7".into()));
        assert!(bad("endpoint", "192.0.2.7:0".into()));
        assert!(bad("endpoint", "192.0.2.7:0443".into()));
        assert!(bad("endpoint", "cbb.example.org:443".into()));
        assert!(
            Link::from_offer(&{
                let mut o = offer();
                o["endpoint"] = "[2001:db8::1]:443".into();
                o
            })
            .is_ok()
        );
        assert!(bad("server_name", "Cbb.example.org".into()));
        assert!(bad("server_name", "localhost".into()));
        assert!(bad("server_name", "-a.example.org".into()));
        assert!(bad("path", "/short".into()));
        assert!(bad("path", "AbC-12_xyz0123456".into()));
        assert!(bad("path", "/AbC-12_xyz0123456/short".into()));
        assert!(bad("id", "6F1C2B9E-3D4A-4F5B-8C7D-0E1F2A3B4C5D".into()));
        assert!(bad("id", "6f1c2b9e-3d4a-3f5b-8c7d-0e1f2a3b4c5d".into()), "version 3");
        assert!(bad("public_key", "AAAA".into()));
        assert!(bad("other", "x".into()));
    }

    #[test]
    fn frames_go_both_ways() {
        let id = parse_id("6f1c2b9e-3d4a-4f5b-8c7d-0e1f2a3b4c5d").unwrap();
        let h = request_header(&id);
        assert_eq!(h.len(), 26);
        assert_eq!((h[0], h[17], h[18]), (0, 0, 2));
        let mut down = Down::default();
        // The response header with an addon of 3 bytes, then two packets,
        // in pieces that cut through all of them.
        let mut stream = alloc::vec![0u8, 3, 9, 9, 9];
        stream.extend(frame(b"one").unwrap());
        stream.extend(frame(b"").unwrap());
        stream.extend(frame(&[7u8; 300]).unwrap());
        let mut got = Vec::new();
        for piece in stream.chunks(4) {
            got.extend(down.push(piece).unwrap());
        }
        assert_eq!(got, alloc::vec![b"one".to_vec(), Vec::new(), alloc::vec![7u8; 300]]);
        assert!(Down::default().push(&[1, 0]).is_err(), "another version");
        assert!(frame(&alloc::vec![0u8; 70_000]).is_err());
    }

    #[test]
    fn requests_have_xrays_shape() {
        let l = Link::from_offer(&offer()).unwrap();
        let get = request(&l, "abc", None, 0, 100);
        assert!(get.starts_with("GET /AbC-12_xyz0123456/a-group-of-its-own/abc HTTP/1.1\r\n"));
        assert!(get.contains(&format!("?x_padding={}\r\n", "X".repeat(100))));
        let post = request(&l, "abc", Some(3), 77, 120);
        assert!(post.starts_with("POST /AbC-12_xyz0123456/a-group-of-its-own/abc/3 HTTP/1.1\r\n"));
        assert!(post.contains("Content-Length: 77\r\n") && post.ends_with("\r\n\r\n"));
    }

    #[test]
    fn reads_responses() {
        let h = parse_head(b"HTTP/1.1 200 OK\r\nX-Padding: XXX\r\nTransfer-Encoding: chunked\r\n\r\nrest")
            .unwrap()
            .unwrap();
        assert_eq!((h.status, h.body, h.close), (200, Body::Chunked, false));
        assert_eq!(h.len, 63);
        let h = parse_head(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nConnection: close\r\n\r\n").unwrap().unwrap();
        assert_eq!((h.body, h.close), (Body::Length(0), true));
        let h = parse_head(b"HTTP/1.1 400 Bad Request\r\n\r\n").unwrap().unwrap();
        assert_eq!((h.status, h.body, h.close), (400, Body::Close, true));
        assert_eq!(parse_head(b"HTTP/1.1 200 OK\r\nA: b\r\n").unwrap(), None);
        assert!(parse_head(b"SSH-2.0-x\r\n\r\n").is_err());
        assert!(parse_head(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n").is_err());
        assert!(parse_head(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n").is_err());
        assert!(parse_head(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n").is_err());
        assert!(parse_head(&alloc::vec![b'a'; MAX_HEAD + 1]).is_err());
    }

    #[test]
    fn reads_chunks_in_any_pieces() {
        let body = b"5;ext=1\r\nhello\r\n1\r\n \r\n6\r\nworld!\r\n0\r\nTrailer: x\r\n\r\n";
        for size in 1..body.len() {
            let mut c = Chunked::default();
            let mut out = Vec::new();
            for piece in body.chunks(size) {
                c.push(piece, &mut out).unwrap();
            }
            assert_eq!(out, b"hello world!", "pieces of {size}");
            assert!(c.done());
        }
        let mut out = Vec::new();
        assert!(Chunked::default().push(b"zz\r\n", &mut out).is_err());
        assert!(Chunked::default().push(b"2\r\nabXX", &mut out).is_err());
        assert!(Chunked::default().push(b"123456789\r\n", &mut out).is_err());
        assert!(Chunked::default().push(&alloc::vec![b'1'; MAX_LINE + 1], &mut out).is_err());
    }
}
