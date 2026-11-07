// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Images and files on the control socket, as on a full member
//! (docs/protocol.md, section 8): copy-media and copied-media bring a copy's
//! parts in part and data messages after the request, paste-media gives
//! them back the same way, and config sets this device's largest copy at
//! home and away from home (max-copy, max-copy-away).

use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use cbb_core::media::{MAX_ALT_TEXT, MAX_MEDIA, MAX_PARTS, Part};
use serde::{Deserialize, Serialize};

use crate::content::Source;
use crate::control::{self, Header, Message, Reader};
use crate::error::{Context, Error, Result};

/// The file of this device's limits in its state, as Go's.
const LIMITS_FILE: &str = "limits";
const DEFAULT_MAX: i64 = 100 << 20;
const DEFAULT_MAX_AWAY: i64 = 25 << 20;
const MIN_MAX: i64 = 1 << 20;

/// How many bytes of a part go in one data message.
const CHUNK: usize = 1 << 20;

/// This device's largest copy of images or files, in bytes.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    #[serde(rename = "max_copy")]
    pub home: i64,
    #[serde(rename = "max_copy_away")]
    pub away: i64,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits { home: DEFAULT_MAX, away: DEFAULT_MAX_AWAY }
    }
}

impl Limits {
    /// The limits kept in the state folder, or the defaults.
    pub fn load(state_dir: &Path) -> Result<Limits> {
        let data = match std::fs::read(state_dir.join(LIMITS_FILE)) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Limits::default()),
            Err(e) => return Err(Error::with(format!("cannot read {LIMITS_FILE}"), e)),
        };
        let l: Limits = serde_json::from_slice(&data).context(format!("{LIMITS_FILE} is damaged"))?;
        l.check().map_err(|e| e.context(format!("{LIMITS_FILE} holds limits out of range")))?;
        Ok(l)
    }

    fn check(&self) -> Result<()> {
        if self.home < MIN_MAX || self.home > MAX_MEDIA {
            return Err(Error::msg(format!(
                "max-copy must be from {} to {}",
                size_text(MIN_MAX),
                size_text(MAX_MEDIA)
            )));
        }
        if self.away < MIN_MAX || self.away > self.home {
            return Err(Error::msg(format!(
                "max-copy-away must be from {} to max-copy, {}",
                size_text(MIN_MAX),
                size_text(self.home)
            )));
        }
        Ok(())
    }

    /// Sets the setting name to value and keeps the limits; a lower
    /// max-copy lowers max-copy-away with it.
    pub fn set(state_dir: &Path, name: &str, value: &str) -> Result<Limits> {
        let n = parse_size(value)?;
        let mut l = Limits::load(state_dir)?;
        match name {
            "max-copy" => {
                l.home = n;
                l.away = l.away.min(n);
            }
            "max-copy-away" => l.away = n,
            _ => {
                return Err(Error::msg(format!(
                    "there is no setting {name:?}; the settings are max-copy and max-copy-away"
                )));
            }
        }
        l.check()?;
        let mut data = serde_json::to_vec(&l).context("cannot encode the limits")?;
        data.push(b'\n');
        crate::files::write_atomic(&state_dir.join(LIMITS_FILE), &data, 0o600)
            .map_err(|e| e.context("cannot save the setting"))?;
        Ok(l)
    }
}

/// Reads a size such as 100MiB, 100MB, 1GiB or 52428800 (bytes), as Go's
/// parseSize: MB and GB mean MiB and GiB, as most people mean them.
pub fn parse_size(s: &str) -> Result<i64> {
    let t = s.trim().to_ascii_uppercase();
    let mut num = t.as_str();
    let mut mul: i64 = 1;
    for (suffix, m) in [
        ("GIB", 1 << 30),
        ("MIB", 1 << 20),
        ("KIB", 1 << 10),
        ("GB", 1 << 30),
        ("MB", 1 << 20),
        ("KB", 1 << 10),
        ("G", 1 << 30),
        ("M", 1 << 20),
        ("K", 1 << 10),
        ("B", 1),
    ] {
        if let Some(rest) = t.strip_suffix(suffix) {
            num = rest.trim();
            mul = m;
            break;
        }
    }
    match num.parse::<i64>() {
        Ok(n) if n > 0 && n <= MAX_MEDIA / mul + 1 => Ok(n * mul),
        _ => Err(Error::msg(format!("{s:?} is not a size such as 100MiB"))),
    }
}

/// Writes a size for people, as Go's SizeText: 100 MiB, 1 GiB, 512.0 KiB.
pub fn size_text(n: i64) -> String {
    if n >= 1 << 30 && n % (1 << 30) == 0 {
        format!("{} GiB", n >> 30)
    } else if n >= 1 << 20 && n % (1 << 20) == 0 {
        format!("{} MiB", n >> 20)
    } else if n >= 1 << 20 {
        format!("{:.1} MiB", n as f64 / (1 << 20) as f64)
    } else if n >= 1 << 10 {
        format!("{:.1} KiB", n as f64 / (1 << 10) as f64)
    } else {
        format!("{n} bytes")
    }
}

/// A copy's parts as they came on the socket, in files of a folder that
/// goes with it.
pub struct Received {
    pub text: String,
    pub parts: Vec<(Part, Source)>,
    dir: PathBuf,
}

impl Drop for Received {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Reads the parts of copy-media or copied-media, which follow its request
/// whose payload is the plain-text alternative, into files in a new folder
/// under tmp: each part's description, then its bytes in data messages,
/// until a part message with done. A copy larger than limit is refused.
pub fn receive<R: Read>(r: &mut Reader<R>, alt: &[u8], limit: i64, tmp: &Path) -> Result<Received> {
    if alt.len() > MAX_ALT_TEXT {
        return Err(Error::msg("the text that goes with the copy is larger than 256 KiB"));
    }
    let text = String::from_utf8(alt.to_vec()).context("the text that goes with the copy is not UTF-8")?;
    let dir = tmp.join(format!("copy-{}", crate::files::random_name()));
    std::fs::create_dir_all(&dir).context("cannot make a folder for the copy")?;
    let mut got = Received { text, parts: Vec::new(), dir };
    let mut total: i64 = 0;
    loop {
        let m = r.read()?.ok_or_else(|| Error::msg("the copy ended before its last part"))?;
        if m.header.op != "part" {
            return Err(Error::msg(format!("expected a part, got {:?}", m.header.op)));
        }
        if m.header.done {
            break;
        }
        let p = m.header.part.ok_or_else(|| Error::msg("a part without its description"))?;
        if p.size < 0 {
            return Err(Error::msg("a part without its description"));
        }
        if got.parts.len() == MAX_PARTS {
            return Err(Error::msg(format!("a copy has at most {MAX_PARTS} files and folders")));
        }
        total = total.saturating_add(p.size);
        if total > limit {
            return Err(Error::msg(format!(
                "the copy is larger than this device's limit of {}; cbb config max-copy SIZE raises it, up to 1 GiB",
                size_text(limit)
            )));
        }
        let part = Part { kind: p.kind, path: p.path, dir: p.dir, size: p.size, sha256: None };
        if part.dir {
            got.parts.push((part, Source::Dir));
            continue;
        }
        let path = got.dir.join(format!("part-{}", got.parts.len()));
        let mut f = File::create(&path).context("cannot keep a part of the copy")?;
        let mut left = p.size;
        while left > 0 {
            let d = r.read()?.ok_or_else(|| Error::msg("the bytes of a part did not come as said"))?;
            let n = d.payload.len() as i64;
            if d.header.op != "data" || n == 0 || n > left {
                return Err(Error::msg("the bytes of a part did not come as said"));
            }
            f.write_all(&d.payload).context("cannot keep a part of the copy")?;
            left -= n;
        }
        got.parts.push((part, Source::File(path)));
    }
    if got.parts.is_empty() {
        return Err(Error::msg("the copy has no parts"));
    }
    Ok(got)
}

/// Sends a copy's images or files in answer to paste-media: its plain-text
/// alternative with kind media, then each part and its bytes, then done.
pub fn send(out: &mut impl Write, text: &str, parts: &[(Part, PathBuf)]) -> Result<()> {
    let reply = |h: Header, payload: Vec<u8>| Message::new(Header { op: "reply".into(), ..h }, payload);
    control::write(out, &reply(Header { kind: "media".into(), ..Default::default() }, text.as_bytes().to_vec()))?;
    let mut buf = vec![0; CHUNK];
    for (p, path) in parts {
        let part = control::Part { kind: p.kind.clone(), path: p.path.clone(), dir: p.dir, size: p.size };
        control::write(out, &reply(Header { part: Some(part), ..Default::default() }, Vec::new()))?;
        if p.dir {
            continue;
        }
        let mut f = File::open(path).context("a part of the copy is gone")?;
        let mut sent: i64 = 0;
        loop {
            let n = f.read(&mut buf).context("cannot read a part of the copy")?;
            if n == 0 {
                break;
            }
            sent += n as i64;
            control::write(out, &reply(Header::default(), buf[..n].to_vec()))?;
        }
        if sent != p.size {
            return Err(Error::msg("a part of the copy changed its size"));
        }
    }
    control::write(out, &reply(Header { done: true, ..Default::default() }, Vec::new()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes() {
        for (s, n) in [("100MiB", 100 << 20), ("100 mb", 100 << 20), ("1G", 1 << 30), ("52428800", 52_428_800)] {
            assert_eq!(parse_size(s).unwrap(), n, "{s}");
        }
        for s in ["", "0", "-1", "3GiB", "lots", "1.5MiB"] {
            assert!(parse_size(s).is_err(), "{s}");
        }
        assert_eq!(size_text(100 << 20), "100 MiB");
        assert_eq!(size_text(1 << 30), "1 GiB");
        assert_eq!(size_text(1536), "1.5 KiB");
        assert_eq!(size_text(12), "12 bytes");
    }

    #[test]
    fn limits() {
        let dir = std::env::temp_dir().join(format!("cbb-limits-{}", crate::files::random_name()));
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(Limits::load(&dir).unwrap(), Limits::default());
        assert_eq!(Limits::set(&dir, "max-copy", "10MiB").unwrap(), Limits { home: 10 << 20, away: 10 << 20 });
        assert_eq!(Limits::set(&dir, "max-copy-away", "5MiB").unwrap(), Limits { home: 10 << 20, away: 5 << 20 });
        assert_eq!(Limits::load(&dir).unwrap(), Limits { home: 10 << 20, away: 5 << 20 });
        assert!(Limits::set(&dir, "max-copy-away", "20MiB").is_err());
        assert!(Limits::set(&dir, "max-copy", "1KiB").is_err());
        assert!(Limits::set(&dir, "colour", "1MiB").is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The parts read from the socket are what paste-media sends back.
    #[test]
    fn parts_round_trip() {
        let mut wire = Vec::new();
        let part = |p: control::Part| {
            Message::new(Header { op: "part".into(), part: Some(p), ..Default::default() }, Vec::new())
        };
        let data = |b: &[u8]| Message::new(Header { op: "data".into(), ..Default::default() }, b.to_vec());
        for m in [
            part(control::Part { kind: "image/png".into(), size: 5, ..Default::default() }),
            data(b"he"),
            data(b"llo"),
            part(control::Part { path: "trip".into(), dir: true, ..Default::default() }),
            Message::new(Header { op: "part".into(), done: true, ..Default::default() }, Vec::new()),
        ] {
            control::write(&mut wire, &m).unwrap();
        }
        let tmp = std::env::temp_dir();
        let got = receive(&mut Reader::new(wire.as_slice()), b"alt", 1 << 20, &tmp).unwrap();
        assert_eq!(got.text, "alt");
        assert_eq!(got.parts.len(), 2);
        let (p, Source::File(path)) = &got.parts[0] else { panic!("not a file") };
        assert_eq!((p.kind.as_str(), p.size), ("image/png", 5));
        assert_eq!(std::fs::read(path).unwrap(), b"hello");
        assert!(matches!(got.parts[1].1, Source::Dir));

        let mut out = Vec::new();
        let parts = vec![(got.parts[0].0.clone(), path.clone()), (got.parts[1].0.clone(), PathBuf::new())];
        send(&mut out, "alt", &parts).unwrap();
        let mut r = Reader::new(out.as_slice());
        let first = r.read().unwrap().unwrap();
        assert_eq!((first.header.kind.as_str(), first.payload.as_slice()), ("media", &b"alt"[..]));
        assert_eq!(r.read().unwrap().unwrap().header.part.unwrap().size, 5);
        assert_eq!(r.read().unwrap().unwrap().payload, b"hello");
        assert!(r.read().unwrap().unwrap().header.part.unwrap().dir);
        assert!(r.read().unwrap().unwrap().header.done);

        // Bytes that do not match the part, or too large a copy, are refused.
        let dir = got.dir.clone();
        drop(got);
        assert!(!dir.exists());
        let mut bad = Vec::new();
        control::write(&mut bad, &part(control::Part { kind: "image/png".into(), size: 2, ..Default::default() }))
            .unwrap();
        control::write(&mut bad, &data(b"abc")).unwrap();
        assert!(receive(&mut Reader::new(bad.as_slice()), b"", 1 << 20, &tmp).is_err());
        assert!(receive(&mut Reader::new(wire.as_slice()), b"", 4, &tmp).is_err());
    }
}
