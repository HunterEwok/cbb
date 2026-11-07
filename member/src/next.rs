// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The front end for the ZX Spectrum Next (docs/roadmap.md, item 14).
//! On the Accelerated Next, the lite member runs on the Raspberry Pi wired to the
//! Next's second UART, and the Next's `.cbb` dot command types `cbb next
//! ...` at NextPi's shell on that UART. These commands answer in frames the
//! Z80 can read without a parser: lines end in CR, texts are in the Spectrum
//! character set and come with their length and CRC-32, and every answer
//! ends in one status line, `CBBOK` or `CBBERR <message>`. The format is in
//! member/README.md, "ZX Spectrum Next".

use std::io::{Read, Write};

use cbb_core::clip;

use crate::error::{Context, Error, Result};
use crate::{Global, control, request};

const USAGE: &str = "usage: cbb next paste [-max bytes] | copy [-secret] <len> <crc32> | check-list <file> | pair [-name name] [-port port] [-addr host[:port]]... | link -to host:port [-port port] [-serve esp-port:local-port] [-zone +hh:mm] [-join code] [-log file] [-trace]";

/// How long copy waits for the next byte from the Next.
const READ_TIMEOUT_DECISECONDS: u8 = 100;

/// Runs a `next` command and writes its status line; the exit code is 0 on
/// CBBOK and 1 on CBBERR.
pub fn run(g: &Global, args: &[String]) -> i32 {
    let res = match args.first().map(String::as_str) {
        Some("paste") => paste(g, &args[1..]),
        Some("copy") => copy(g, &args[1..]),
        Some("check-list") => check_list(&args[1..], &mut std::io::stdout()),
        Some("pair") => crate::join(g, &args[1..], true),
        // The link answers in frames, not in a status line.
        Some("link") => {
            return match crate::nextlink::link::run(g, &args[1..]) {
                Ok(()) => 0,
                Err(e) => {
                    eprintln!("cbb: {}", e.for_user());
                    1
                }
            };
        }
        _ => Err(Error::msg(USAGE)),
    };
    let mut out = std::io::stdout();
    let line = match res {
        Ok(()) => "CBBOK\r".to_string(),
        Err(e) => format!("CBBERR {}\r", status_text(&e.for_user())),
    };
    out.write_all(line.as_bytes()).ok();
    out.flush().ok();
    if line.starts_with("CBBOK") { 0 } else { 1 }
}

/// The largest file check-list reads: keys.json and zxnext.json.
const MAX_CHECK_LIST: u64 = 16 << 10;

/// `.cbb update`'s check of the site's list for a newer CBB (apps/zxnext,
/// docs/protocol.md section 16, "The ZX Spectrum Next's files"): the file
/// holds keys.json and zxnext.json, a line each, as cbb.tools serves them
/// in SIGNED. This cbb checks them under its pinned release roots and
/// writes the Next's files, `CBBL <name> <size> <crc32> <sha256>` CR each,
/// which the Next takes in place of the site's list. The release must not
/// be older than this cbb.
fn check_list(args: &[String], out: &mut dyn Write) -> Result<()> {
    use cbb_core::release;
    let [path] = args else { return Err(Error::msg(USAGE)) };
    let mut data = Vec::new();
    std::fs::File::open(path)
        .and_then(|f| f.take(MAX_CHECK_LIST + 1).read_to_end(&mut data))
        .context(format!("cannot read {path}"))?;
    if data.len() as u64 > MAX_CHECK_LIST {
        return Err(Error::msg("the signed list is too large"));
    }
    let roots = crate::update::release_roots();
    let roots: Vec<&[u8]> = roots.iter().map(Vec::as_slice).collect();
    let installed =
        if release::parse_version(crate::service::VERSION).is_some() { crate::service::VERSION } else { "" };
    check_signed(&data, &roots, crate::uptime::wall_ms(), installed, out)
}

/// check_list's check of the file's data under roots at now_ms.
fn check_signed(data: &[u8], roots: &[&[u8]], now_ms: i64, installed: &str, out: &mut dyn Write) -> Result<()> {
    use cbb_core::release::{self, File};
    let text = std::str::from_utf8(data).map_err(|_| Error::msg("the signed list is not text"))?;
    let mut lines = text.lines().map(str::trim).filter(|l| !l.is_empty());
    let (Some(keys), Some(list), None) = (lines.next(), lines.next(), lines.next()) else {
        return Err(Error::msg("the signed list is not keys.json and zxnext.json"));
    };
    let file = |s: &str, what: &str| -> Result<File> {
        serde_json::from_str(s).map_err(|e| Error::with(format!("{what} is not a signed file"), e))
    };
    let (keys, list) = (file(keys, "keys.json")?, file(list, "zxnext.json")?);
    if roots.is_empty() {
        return Err(Error::msg("this cbb pins no release keys, so it cannot check the list"));
    }
    let z = release::check_zxnext(&keys, &list, roots, now_ms, installed).map_err(|e| Error::msg(e.message()))?;
    for f in &z.files {
        write!(out, "CBBL {} {} {} {}\r", f.name, f.size, f.crc32, f.sha256).context("cannot write the list")?;
    }
    Ok(())
}

/// An error message on one line of printable ASCII, so the Next can show it.
fn status_text(s: &str) -> String {
    let t = to_spectrum(&s.replace('\n', "; "));
    t.iter().map(|&b| if b == 0x60 || b == 0x7F { '?' } else { b as char }).collect()
}

/// Writes the latest text: `CBB1 <len> <crc32>` CR, len bytes, CR.
fn paste(g: &Global, args: &[String]) -> Result<()> {
    let max = match args {
        [] => usize::MAX,
        [f, n] if crate::flag(f) == Some("max") => n.parse().context("the -max value is a number")?,
        _ => return Err(Error::msg(USAGE)),
    };
    let m =
        request(g, &control::Message::new(control::Header { op: "paste".into(), ..Default::default() }, Vec::new()))?;
    let text = to_spectrum(&String::from_utf8_lossy(&m.payload));
    let text = &text[..text.len().min(max)];
    let mut out = std::io::stdout();
    out.write_all(&frame(text)).context("cannot write the text")?;
    Ok(())
}

/// The frame of a text for the Next.
fn frame(text: &[u8]) -> Vec<u8> {
    let mut f = format!("CBB1 {} {:08x}\r", text.len(), crc32(text)).into_bytes();
    f.extend_from_slice(text);
    f.push(b'\r');
    f
}

/// Reads len bytes in the Spectrum character set from standard input, checks
/// their CRC-32 and sends the text to the group, as a secret with -secret.
fn copy(g: &Global, args: &[String]) -> Result<()> {
    let (secret, args) = match args {
        [f, rest @ ..] if crate::flag(f) == Some("secret") => (true, rest),
        _ => (false, args),
    };
    let [len, crc] = args else { return Err(Error::msg(USAGE)) };
    let len: usize = len.parse().context("the length is a number")?;
    let crc = u32::from_str_radix(crc, 16).context("the CRC-32 is 8 hex digits")?;
    if len > clip::MAX_TEXT {
        return Err(Error::msg("the text is too long"));
    }
    // Fail before the Next sends the text, not after.
    request(g, &control::Message::new(control::Header { op: "status".into(), ..Default::default() }, Vec::new()))?;
    let data = {
        let _raw = RawTerminal::new(READ_TIMEOUT_DECISECONDS, false);
        let mut out = std::io::stdout();
        out.write_all(b"CBBGO\r").and_then(|_| out.flush()).context("cannot answer the Next")?;
        let mut data = vec![0; len];
        let mut got = 0;
        let mut stdin = std::io::stdin();
        while got < len {
            match stdin.read(&mut data[got..]) {
                Ok(0) => return Err(Error::msg(format!("the Next sent {got} of {len} bytes and stopped"))),
                Ok(n) => got += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(Error::with("cannot read the text from the Next", e)),
            }
        }
        data
    };
    if crc32(&data) != crc {
        return Err(Error::msg("the text arrived damaged (CRC-32 mismatch); send it again"));
    }
    let h = control::Header {
        op: "copy".into(),
        kind: if secret { "secret".into() } else { String::new() },
        ..Default::default()
    };
    request(g, &control::Message::new(h, from_spectrum(&data).into_bytes()))?;
    Ok(())
}

/// Writes a QR code for the phone: `CBBQ <size>` CR, then size rows, each of
/// (size + 3) / 4 hex digits, the leftmost module in the high bit of the
/// first digit, a set bit dark.
pub fn qr_frame(text: &str) -> Vec<u8> {
    let Ok(code) = qrcode::QrCode::with_error_correction_level(text, qrcode::EcLevel::L) else {
        return Vec::new();
    };
    let size = code.width();
    let mut f = format!("CBBQ {size}\r").into_bytes();
    for y in 0..size {
        for x0 in (0..size).step_by(4) {
            let mut nibble = 0;
            for x in x0..x0 + 4 {
                nibble <<= 1;
                if x < size && code[(x, y)] == qrcode::Color::Dark {
                    nibble |= 1;
                }
            }
            f.push(b"0123456789abcdef"[nibble]);
        }
        f.push(b'\r');
    }
    f
}

/// UTF-8 to the Spectrum character set: printable ASCII, CR line ends, £ at
/// 0x60 and © at 0x7F, and `?` for every other character (the backtick
/// included, since 0x60 is the pound sign). Cyrillic comes later.
pub fn to_spectrum(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\r' => {}
            '\n' => out.push(0x0D),
            '\t' => out.push(b' '),
            '£' => out.push(0x60),
            '©' => out.push(0x7F),
            ' '..='~' if c != '`' => out.push(c as u8),
            _ => out.push(b'?'),
        }
    }
    out
}

/// The Spectrum character set to UTF-8: CR (or CR LF) is a new line, 0x60
/// the pound sign, 0x7F the copyright sign; block graphics, UDGs and BASIC
/// tokens have no text and become `?`.
pub fn from_spectrum(b: &[u8]) -> String {
    let mut out = String::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            0x0D => {
                out.push('\n');
                if b.get(i + 1) == Some(&0x0A) {
                    i += 1;
                }
            }
            0x0A => out.push('\n'),
            0x60 => out.push('£'),
            0x7F => out.push('©'),
            c @ 0x20..=0x7E => out.push(c as char),
            _ => out.push('?'),
        }
        i += 1;
    }
    out
}

/// CRC-32 (IEEE 802.3, as zlib and PiTools' .crc32 compute it).
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

/// Puts standard input, when it is a terminal (the UART), into raw mode for
/// as long as it lives: no echo, no line editing, no CR to LF, and a read
/// that gives up after the timeout without a byte. It restores the old mode when
/// dropped.
pub(crate) struct RawTerminal(Option<libc::termios>);

impl RawTerminal {
    /// timeout in tenths of a second; binary also turns off the output's
    /// processing (LF to CR LF), for frames.
    pub(crate) fn new(timeout: u8, binary: bool) -> RawTerminal {
        // SAFETY: tcgetattr and tcsetattr only read and write the termios
        // struct passed to them.
        unsafe {
            let mut old: libc::termios = std::mem::zeroed();
            if libc::isatty(0) != 1 || libc::tcgetattr(0, &mut old) != 0 {
                return RawTerminal(None);
            }
            let mut raw = old;
            raw.c_iflag &=
                !(libc::IGNBRK | libc::BRKINT | libc::ICRNL | libc::INLCR | libc::IGNCR | libc::ISTRIP | libc::IXON);
            raw.c_lflag &= !(libc::ECHO | libc::ECHONL | libc::ICANON | libc::ISIG | libc::IEXTEN);
            raw.c_cc[libc::VMIN] = 0;
            raw.c_cc[libc::VTIME] = timeout;
            if binary {
                raw.c_oflag &= !libc::OPOST;
            }
            if libc::tcsetattr(0, libc::TCSANOW, &raw) != 0 {
                return RawTerminal(None);
            }
            if binary {
                // A stray XOFF that came while IXON was on stopped the
                // output, and turning IXON off does not start it again.
                libc::tcflow(0, libc::TCOON);
            }
            RawTerminal(Some(old))
        }
    }
}

impl Drop for RawTerminal {
    fn drop(&mut self) {
        if let Some(old) = &self.0 {
            // SAFETY: as in new.
            unsafe {
                libc::tcsetattr(0, libc::TCSANOW, old);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_check_value() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn charset_round_trip() {
        let s = "Hello, World! £5 © 2026\nline two";
        let b = to_spectrum(s);
        assert_eq!(b[0..5], *b"Hello");
        assert!(b.contains(&0x60) && b.contains(&0x7F) && b.contains(&0x0D));
        assert_eq!(from_spectrum(&b), s);
    }

    #[test]
    fn charset_replaces_what_the_spectrum_lacks() {
        assert_eq!(to_spectrum("a`b\r\nαβγδεζ\tz"), b"a?b\r?????? z".to_vec());
        assert_eq!(from_spectrum(&[b'a', 0x0D, 0x0A, 0x90, 0xF5, b'b', 0x0A]), "a\n??b\n");
    }

    #[test]
    fn frame_has_length_and_crc() {
        assert_eq!(frame(b"123456789"), b"CBB1 9 cbf43926\r123456789\r".to_vec());
        assert_eq!(frame(b""), b"CBB1 0 00000000\r\r".to_vec());
    }

    #[test]
    fn qr_frame_rows() {
        let f = qr_frame("cbb:test");
        let s = String::from_utf8(f).unwrap();
        let mut lines = s.split('\r');
        let size: usize = lines.next().unwrap().strip_prefix("CBBQ ").unwrap().parse().unwrap();
        let rows: Vec<&str> = lines.filter(|l| !l.is_empty()).collect();
        assert_eq!(rows.len(), size);
        assert!(rows.iter().all(|r| r.len() == size.div_ceil(4)));
        // The top-left finder pattern starts with seven dark modules.
        assert!(rows[0].starts_with("fe"));
    }

    /// check-list takes the lists the Go vectors take and writes their
    /// files for the Next; it refuses the others and writes nothing.
    #[test]
    fn check_list_vectors() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata/interop/go-zxnext.json");
        let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        #[derive(serde::Deserialize)]
        struct Der(#[serde(with = "cbb_core::certs::b64")] Vec<u8>);
        let b64 = |x: &serde_json::Value| -> Vec<u8> { serde_json::from_value::<Der>(x.clone()).unwrap().0 };
        let roots: Vec<Vec<u8>> = v["roots"].as_array().unwrap().iter().map(b64).collect();
        let roots: Vec<&[u8]> = roots.iter().map(Vec::as_slice).collect();
        for c in v["vectors"].as_array().unwrap() {
            let data = format!("{}\n{}\n", c["keys"], c["list"]);
            let mut out = Vec::new();
            let got = check_signed(
                data.as_bytes(),
                &roots,
                c["now_ms"].as_i64().unwrap(),
                c["installed"].as_str().unwrap(),
                &mut out,
            );
            let name = c["name"].as_str().unwrap();
            assert_eq!(got.is_ok(), c["ok"].as_bool().unwrap(), "{name}: {got:?}");
            let out = String::from_utf8(out).unwrap();
            if got.is_ok() {
                assert_eq!(out.matches("CBBL ").count(), 4, "{name}: {out}");
                assert!(out.contains(&format!("CBBL cbb 4000 0a0a0a0a {}\r", "d".repeat(64))), "{name}: {out}");
            } else {
                assert!(out.is_empty(), "{name}: {out}");
            }
        }
        let mut out = Vec::new();
        assert!(check_signed(b"{}\n", &roots, 0, "", &mut out).is_err());
        assert!(check_signed(b"{}\n{}\n{}\n", &roots, 0, "", &mut out).is_err());
    }

    #[test]
    fn status_text_is_one_ascii_line() {
        assert_eq!(status_text("bad\nthing «x»"), "bad; thing ?x?");
        assert_eq!(status_text("£1 ©"), "?1 ?");
    }
}
