// Copyright (c) 2019, Guillaume Ballet
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Translated to Rust from github.com/gballet/go-libpcsclite (winscard.go,
// msg.go, doc.go); see README.md.

//! A client of pcscd's socket: each message is a little-endian length and
//! command, then its body; the daemon answers with a body of the same
//! layout.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::error::{Error, Result};
use crate::piv::{Card, NO_CARD};

const ESTABLISH_CONTEXT: u32 = 1;
const RELEASE_CONTEXT: u32 = 2;
const CONNECT: u32 = 4;
const DISCONNECT: u32 = 6;
const TRANSMIT: u32 = 9;
const VERSION: u32 = 17;
const GET_READER_STATE: u32 = 18;

const VERSION_MAJOR: u32 = 4;
const VERSION_MINOR: u32 = 3;

const SCOPE_SYSTEM: u32 = 2;
const SHARE_EXCLUSIVE: u32 = 1;
const PROTOCOL_T1: u32 = 2;
const LEAVE_CARD: u32 = 0;

const NAME_LEN: usize = 128;
/// A reader's state as the daemon sends it: its name, then the counters,
/// the ATR (33 bytes, aligned to 36) and its length and protocol.
const READER_STATE_LEN: usize = NAME_LEN + 33 + 5 * 4 + 3;
const MAX_READERS: usize = 16;
/// The most an answer to an APDU may hold (pcsc-lite's
/// MAX_BUFFER_SIZE_EXTENDED).
const MAX_RECV: usize = 4 + 3 + (1 << 16) + 3 + 2;

/// Where pcscd listens, unless PCSCLITE_CSOCK_NAME names another socket.
const SOCKET: &str = "/run/pcscd/pcscd.comm";

/// How long the daemon may take: a signature may wait for a touch.
const TIMEOUT: Duration = Duration::from_secs(60);

struct Client {
    conn: UnixStream,
    ctx: u32,
}

impl Client {
    fn send(&mut self, command: u32, body: &[u8]) -> Result<()> {
        let mut m = Vec::with_capacity(8 + body.len());
        m.extend_from_slice(&(body.len() as u32).to_le_bytes());
        m.extend_from_slice(&command.to_le_bytes());
        m.extend_from_slice(body);
        self.conn.write_all(&m).map_err(|e| Error::with("pcscd stopped answering", e))
    }

    fn read(&mut self, n: usize) -> Result<Vec<u8>> {
        let mut b = vec![0u8; n];
        self.conn.read_exact(&mut b).map_err(|e| Error::with("pcscd stopped answering", e))?;
        Ok(b)
    }
}

fn le(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn code_err(what: &str, code: u32) -> Error {
    Error::msg(format!("pcscd: {what}: PC/SC error {code:#x}"))
}

/// The daemon's context, released once its last card is dropped.
struct Shared(Mutex<Client>);

impl Drop for Shared {
    fn drop(&mut self) {
        let c = self.0.get_mut().unwrap_or_else(|e| e.into_inner());
        let mut body = c.ctx.to_le_bytes().to_vec();
        body.extend_from_slice(&0u32.to_le_bytes());
        if c.send(RELEASE_CONTEXT, &body).is_ok() {
            let _ = c.read(8);
        }
    }
}

fn establish(path: &Path) -> Result<Client> {
    let conn = UnixStream::connect(path).map_err(|e| {
        Error::with(
            "a YubiKey needs pcscd, the PC/SC daemon: install it (the package pcscd or pcsc-lite) and start it",
            e,
        )
    })?;
    conn.set_read_timeout(Some(TIMEOUT)).ok();
    conn.set_write_timeout(Some(TIMEOUT)).ok();
    let mut c = Client { conn, ctx: 0 };
    let mut agreed = false;
    for minor in [VERSION_MINOR, VERSION_MINOR + 1] {
        let body = [VERSION_MAJOR.to_le_bytes(), minor.to_le_bytes(), 0u32.to_le_bytes()].concat();
        c.send(VERSION, &body)?;
        let r = c.read(12)?;
        if le(&r, 8) == 0 && le(&r, 0) == VERSION_MAJOR && le(&r, 4) == minor {
            agreed = true;
            break;
        }
    }
    if !agreed {
        return Err(Error::msg("pcscd speaks a protocol version this program does not"));
    }
    let body = [SCOPE_SYSTEM.to_le_bytes(), 0u32.to_le_bytes(), 0u32.to_le_bytes()].concat();
    c.send(ESTABLISH_CONTEXT, &body)?;
    let r = c.read(12)?;
    if le(&r, 8) != 0 {
        return Err(code_err("SCardEstablishContext", le(&r, 8)));
    }
    c.ctx = le(&r, 4);
    Ok(c)
}

fn readers(c: &mut Client) -> Result<Vec<Vec<u8>>> {
    c.send(GET_READER_STATE, &[])?;
    let r = c.read(READER_STATE_LEN * MAX_READERS)?;
    Ok(r.chunks(READER_STATE_LEN)
        .map(|d| d[..NAME_LEN].split(|b| *b == 0).next().unwrap_or_default().to_vec())
        .take_while(|n| !n.is_empty())
        .collect())
}

struct PcscCard {
    shared: Arc<Shared>,
    handle: u32,
}

impl Card for PcscCard {
    fn transmit(&mut self, apdu: &[u8]) -> Result<Vec<u8>> {
        let mut c = self.shared.0.lock().unwrap_or_else(|e| e.into_inner());
        let req: Vec<u8> = [self.handle, PROTOCOL_T1, 8, apdu.len() as u32, 0, 0, MAX_RECV as u32, 0]
            .iter()
            .flat_map(|v| v.to_le_bytes())
            .collect();
        c.send(TRANSMIT, &req)?;
        c.conn.write_all(apdu).map_err(|e| Error::with("pcscd stopped answering", e))?;
        let r = c.read(32)?;
        if le(&r, 28) != 0 {
            return Err(code_err("SCardTransmit", le(&r, 28)));
        }
        let n = le(&r, 24) as usize;
        if n > MAX_RECV {
            return Err(Error::msg("pcscd sent an answer longer than any card's"));
        }
        c.read(n)
    }
}

impl Drop for PcscCard {
    fn drop(&mut self) {
        let mut c = self.shared.0.lock().unwrap_or_else(|e| e.into_inner());
        let body = [self.handle.to_le_bytes(), LEAVE_CARD.to_le_bytes(), 0u32.to_le_bytes()].concat();
        if c.send(DISCONNECT, &body).is_ok() {
            let _ = c.read(12);
        }
    }
}

/// Every card in the readers pcscd lists, connected for this program alone.
pub fn cards() -> Result<Vec<Box<dyn Card>>> {
    let path = std::env::var_os("PCSCLITE_CSOCK_NAME").unwrap_or_else(|| SOCKET.into());
    cards_at(Path::new(&path))
}

pub(crate) fn cards_at(path: &Path) -> Result<Vec<Box<dyn Card>>> {
    let mut c = establish(path)?;
    let names = readers(&mut c)?;
    let shared = Arc::new(Shared(Mutex::new(c)));
    let mut out: Vec<Box<dyn Card>> = Vec::new();
    for name in names {
        let mut c = shared.0.lock().unwrap_or_else(|e| e.into_inner());
        let mut req = vec![0u8; NAME_LEN + 4 * 6];
        req[..4].copy_from_slice(&c.ctx.to_le_bytes());
        req[4..4 + name.len().min(NAME_LEN - 1)].copy_from_slice(&name[..name.len().min(NAME_LEN - 1)]);
        req[4 + NAME_LEN..8 + NAME_LEN].copy_from_slice(&SHARE_EXCLUSIVE.to_le_bytes());
        req[8 + NAME_LEN..12 + NAME_LEN].copy_from_slice(&PROTOCOL_T1.to_le_bytes());
        c.send(CONNECT, &req)?;
        let r = c.read(NAME_LEN + 4 * 6)?;
        drop(c);
        if le(&r, 148) != 0 {
            continue;
        }
        out.push(Box::new(PcscCard { shared: Arc::clone(&shared), handle: le(&r, 140) }));
    }
    if out.is_empty() {
        return Err(Error::msg(NO_CARD));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixListener;

    use super::*;
    use crate::piv;

    /// Plays pcscd with one reader holding card, until the connection ends.
    fn daemon(conn: &mut UnixStream, card: &mut dyn Card) {
        let read = |conn: &mut UnixStream, n: usize| -> Option<Vec<u8>> {
            let mut b = vec![0u8; n];
            conn.read_exact(&mut b).ok().map(|_| b)
        };
        while let Some(h) = read(conn, 8) {
            let (len, cmd) = (le(&h, 0) as usize, le(&h, 4));
            let Some(body) = read(conn, len) else { return };
            let out: Vec<u8> = match cmd {
                VERSION => body,
                ESTABLISH_CONTEXT => [body[..4].to_vec(), 7u32.to_le_bytes().to_vec(), vec![0; 4]].concat(),
                GET_READER_STATE => {
                    let mut s = vec![0u8; READER_STATE_LEN * MAX_READERS];
                    s[..12].copy_from_slice(b"Fake YubiKey");
                    // A second reader whose card is not there.
                    s[READER_STATE_LEN..READER_STATE_LEN + 5].copy_from_slice(b"Empty");
                    conn.write_all(&s).unwrap();
                    continue;
                }
                CONNECT => {
                    let mut r = body.clone();
                    let name = &body[4..4 + NAME_LEN];
                    if name.starts_with(b"Fake YubiKey\0") {
                        r[140..144].copy_from_slice(&9u32.to_le_bytes());
                    } else {
                        r[148..152].copy_from_slice(&0x8010_000cu32.to_le_bytes());
                    }
                    r
                }
                TRANSMIT => {
                    assert_eq!(le(&body, 0), 9);
                    let Some(apdu) = read(conn, le(&body, 12) as usize) else { return };
                    let ans = card.transmit(&apdu).unwrap();
                    let mut r = body.clone();
                    r[24..28].copy_from_slice(&(ans.len() as u32).to_le_bytes());
                    conn.write_all(&r).unwrap();
                    conn.write_all(&ans).unwrap();
                    continue;
                }
                DISCONNECT | RELEASE_CONTEXT => body,
                _ => return,
            };
            conn.write_all(&out).unwrap();
        }
    }

    #[test]
    fn signs_through_pcscd() {
        let dir = std::env::temp_dir().join(format!("cbb-pcscd-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("pcscd.comm");
        let _ = std::fs::remove_file(&sock);
        let l = UnixListener::bind(&sock).unwrap();
        let card = piv::tests::new_card(21);
        let mut fake = card.clone();
        let t = std::thread::spawn(move || {
            let (mut conn, _) = l.accept().unwrap();
            daemon(&mut conn, &mut fake);
        });
        let (want, public) = {
            let f = card.0.lock().unwrap();
            let (k, c) = &f.slots[&0x84];
            (
                cbb_core::certs::Cert::parse(c.as_ref().unwrap()).unwrap().key_hash(),
                k.verifying_key().to_sec1_point(false).as_bytes().to_vec(),
            )
        };
        let cards = cards_at(&sock).unwrap();
        assert_eq!(cards.len(), 1, "the reader without a card");
        let mut k = piv::find(cards, &want).unwrap();
        piv::verify(k.card.as_mut(), "123456").unwrap();
        let digest = cbb_core::certs::sha256(b"a claim");
        piv::sign(k.card.as_mut(), k.slot, &public, &digest).unwrap();
        drop(k);
        t.join().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn says_when_there_is_no_daemon() {
        let e = cards_at(Path::new("/nonexistent/pcscd.comm")).err().unwrap();
        assert!(e.message().contains("needs pcscd"), "{}", e.message());
    }
}
