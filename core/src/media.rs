// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The manifest of a media event: images or files (docs/protocol.md,
//! section 4, "Media"). The lite member never fetches the content; it takes
//! the event, so that the group converges, and its plain-text alternative.
//! It checks the manifest as Go's package clip does, since it passes the
//! event on.

use alloc::collections::BTreeMap;
use alloc::collections::BTreeSet;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::certs::b64;
use crate::error::{Error, Result};

/// The largest copy, all its parts together, that the group carries.
pub const MAX_MEDIA: i64 = 1 << 30;
/// The most parts of a manifest.
pub const MAX_PARTS: usize = 10000;
/// The most parts of clipboard data, one per type.
pub const MAX_TYPES: usize = 8;
/// The most bytes of all the paths of a manifest.
pub const MAX_PATHS: usize = 512 << 10;
/// The longest path, and the longest name in it.
pub const MAX_PATH: usize = 4096;
pub const MAX_NAME: usize = 255;
/// The largest plain-text alternative of a media event.
pub const MAX_ALT_TEXT: usize = 256 << 10;

const TYPES: [&str; 3] = ["image/png", "image/jpeg", "text/html"];

/// What a media event's content is.
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    #[serde(default)]
    pub size: i64,
    #[serde(default)]
    pub parts: Vec<Part>,
}

/// One item of a manifest: clipboard data of a type, or a file or folder at
/// a path.
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Part {
    #[serde(rename = "type", default, skip_serializing_if = "String::is_empty")]
    pub kind: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub dir: bool,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub size: i64,
    /// Absent for a folder; "" is a hash of no bytes, which no part has.
    #[serde(with = "b64::opt", default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<Vec<u8>>,
}

fn is_false(b: &bool) -> bool {
    !*b
}

fn is_zero(n: &i64) -> bool {
    *n == 0
}

impl Manifest {
    /// What tells two copies of images or files apart, as Go's
    /// Manifest.key: each part's type, path and hash.
    pub fn key(&self) -> Vec<u8> {
        let mut k = b"media\0".to_vec();
        for p in &self.parts {
            k.extend_from_slice(p.kind.as_bytes());
            k.extend_from_slice(p.path.as_bytes());
            k.push(0);
            k.extend_from_slice(p.sha256.as_deref().unwrap_or_default());
        }
        k
    }

    /// Reports whether this is a copy of files, not clipboard data.
    pub fn files(&self) -> bool {
        self.parts.first().is_some_and(|p| !p.path.is_empty())
    }

    /// Reads a manifest received from another member: in the strict form
    /// of signed bodies and in its canonical form, with no member its
    /// table does not name (docs/protocol.md, section 4, "Media"), and
    /// valid.
    pub fn parse(data: &[u8]) -> Result<Manifest> {
        crate::strict::check_canonical(data, &["parts", "size"])
            .map_err(|e| e.context("the manifest is not in the strict form"))?;
        let m: Manifest = serde_json::from_slice(data).map_err(|e| Error::with("the manifest is not valid", e))?;
        m.validate()?;
        Ok(m)
    }

    /// Checks a manifest as every program does (docs/protocol.md, section 7).
    pub fn validate(&self) -> Result<()> {
        if self.parts.is_empty() || self.parts.len() > MAX_PARTS {
            return Err(Error::msg(format!("a manifest has {} parts, not 1 to {MAX_PARTS}", self.parts.len())));
        }
        let files = self.files();
        if !files && self.parts.len() > MAX_TYPES {
            return Err(Error::msg(format!("a manifest has more than {MAX_TYPES} types")));
        }
        let mut size: i64 = 0;
        let mut paths: usize = 0;
        let mut seen = BTreeSet::new();
        for p in &self.parts {
            // Paths compare as a receiver writes them: two that save_path
            // makes one would land in one place.
            let key = if files {
                if p.path.is_empty() || !p.kind.is_empty() {
                    return Err(Error::msg("a manifest mixes files and clipboard data"));
                }
                check_path(&p.path)?;
                paths = paths.saturating_add(p.path.len());
                save_path(&p.path)
            } else {
                if p.kind.is_empty() || p.dir {
                    return Err(Error::msg("a manifest mixes files and clipboard data"));
                }
                if !TYPES.contains(&p.kind.as_str()) {
                    return Err(Error::msg(format!("unknown media type {:?}", p.kind)));
                }
                p.kind.clone()
            };
            if seen.contains(&key) {
                return Err(Error::msg(format!("{key:?} is twice in a manifest, as a receiver writes it")));
            }
            seen.insert(key);
            if p.dir {
                if p.size != 0 || p.sha256.is_some() {
                    return Err(Error::msg("a folder in a manifest has a size or a hash"));
                }
                continue;
            }
            if p.sha256.as_ref().is_none_or(|h| h.len() != 32) {
                return Err(Error::msg("a part of a manifest has no valid SHA-256"));
            }
            if p.size < 0 || p.size > MAX_MEDIA {
                return Err(Error::msg(format!("a part of {} bytes", p.size)));
            }
            size =
                size.checked_add(p.size).ok_or_else(|| Error::msg("the parts of a manifest are too large together"))?;
        }
        if paths > MAX_PATHS {
            return Err(Error::msg(format!("the paths of a manifest have more than {MAX_PATHS} bytes")));
        }
        if size != self.size {
            return Err(Error::msg(format!("a manifest says {} bytes, its parts {size}", self.size)));
        }
        if size > MAX_MEDIA {
            return Err(Error::msg(format!("a copy of {size} bytes is larger than {MAX_MEDIA}")));
        }
        if files {
            check_tree(&self.parts)?;
        }
        Ok(())
    }
}

/// Checks that no file of a copy is also inside a file, by the paths as a
/// receiver writes them (save_path).
fn check_tree(parts: &[Part]) -> Result<()> {
    let saved: Vec<(String, bool)> = parts.iter().map(|p| (save_path(&p.path), p.dir)).collect();
    let kind: BTreeMap<&str, bool> = saved.iter().map(|(path, dir)| (path.as_str(), *dir)).collect();
    for (path, _) in &saved {
        for (i, _) in path.match_indices('/') {
            if kind.get(&path[..i]) == Some(&false) {
                return Err(Error::msg(format!("{:?} is inside the file {:?}", path, &path[..i])));
            }
        }
    }
    Ok(())
}

/// Checks a path of a manifest: names joined by "/", each a clean name, at
/// most MAX_PATH bytes as a receiver writes it (save_path).
pub fn check_path(path: &str) -> Result<()> {
    if path.is_empty() || path.len() > MAX_PATH || save_path(path).len() > MAX_PATH {
        return Err(Error::msg(format!("a path of {} bytes as a receiver writes it", save_path(path).len())));
    }
    for name in path.split('/') {
        check_name(name)?;
    }
    Ok(())
}

/// Checks one name of a path as Go's clip.CheckName does: 1 to 255 bytes,
/// as a receiver writes it too (save_name), not "." or "..", no control characters, separators or characters
/// Windows does not allow, no dot or space at the end, no name Windows
/// reserves.
pub fn check_name(name: &str) -> Result<()> {
    let bad = name.is_empty()
        || name.len() > MAX_NAME
        || save_name(name).len() > MAX_NAME
        || name == "."
        || name == ".."
        || name.contains(['/', '\\', ':', '*', '?', '"', '<', '>', '|'])
        || name.ends_with('.')
        || name.ends_with(' ')
        || reserved(name)
        || name.chars().any(|r| r < ' ' || r == '\u{7f}' || ('\u{80}'..'\u{a0}').contains(&r));
    if bad {
        return Err(Error::msg(format!("the name {name:?} is not allowed in a copy")));
    }
    Ok(())
}

/// Whether name, before its first dot, is a device name of Windows that a
/// manifest may not hold: CON, PRN, AUX, NUL, COM1 to COM9 and LPT1 to
/// LPT9, in any case of ASCII letters, as Go's clip.reserved.
fn reserved(name: &str) -> bool {
    let base = name.split('.').next().unwrap_or("").to_ascii_uppercase();
    match base.as_str() {
        "CON" | "PRN" | "AUX" | "NUL" => true,
        b => {
            b.len() == 4
                && (b.starts_with("COM") || b.starts_with("LPT"))
                && b.as_bytes().get(3).is_some_and(|d| (b'1'..=b'9').contains(d))
        }
    }
}

/// Whether name is a device name of Windows, as Go's clip.device: before
/// its first dot, and without the spaces that end that part, one of CON,
/// PRN, AUX, NUL, CONIN$, CONOUT$, or COM or LPT followed by one digit 0 to
/// 9 or one of the superscripts ¹, ² and ³, in any case of ASCII letters.
fn device(name: &str) -> bool {
    let base = name.split('.').next().unwrap_or("").trim_end_matches(' ').to_ascii_uppercase();
    match base.as_str() {
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$" => true,
        b => match b.strip_prefix("COM").or_else(|| b.strip_prefix("LPT")) {
            Some(n) => {
                matches!(n, "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "\u{b9}" | "\u{b2}" | "\u{b3}")
            }
            None => false,
        },
    }
}

/// save_name for each name of a path, as Go's clip.SavePath.
pub fn save_path(path: &str) -> String {
    path.split('/').map(save_name).collect::<Vec<_>>().join("/")
}

/// The name under which a receiver writes a name that check_name took, as
/// Go's clip.SaveName: a device name of Windows gets "_" after its base,
/// the part before its first dot, and any other name stays as it is.
pub fn save_name(name: &str) -> String {
    if !device(name) {
        return String::from(name);
    }
    match name.split_once('.') {
        Some((base, ext)) => format!("{base}_.{ext}"),
        None => format!("{name}_"),
    }
}
