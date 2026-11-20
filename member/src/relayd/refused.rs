// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The list of groups the operator of an open relay refuses after an abuse
//! report (docs/relay-budget.md, "Abuse reports"), as Go's
//! internal/refused, which the forwarder reads: the relay refuses a new
//! registration of a group on it and drops the devices already registered.
//! Every other group goes on as before; the list never limits who may use
//! the relay.
//!
//! The file has one group tag a line, 16 hex characters as cbb status shows
//! them; a line may also name a period's tag as "period <tag>", for a group
//! that registers with credentials. Blank lines and lines that begin with #
//! are skipped, and so is anything after a tag on its line, such as the
//! date of the report.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;

use crate::error::{Error, Result};

/// The file's cap: a list of reports, never of everyone.
const MAX_FILE: u64 = 1 << 20;

/// What a refused device is told, the same as Go's refused.Message.
pub const MESSAGE: &str =
    "this server's operator refuses this group under the server's terms; use another server or run your own";

/// The list, read from its file.
pub struct List {
    path: PathBuf,
    state: Mutex<Read>,
}

#[derive(Default)]
struct Read {
    tags: HashSet<String>,
    modified: Option<SystemTime>,
    size: u64,
    /// The file was missing at the last reload: one more reload that finds
    /// it missing empties the list, so that an editor saving it by moving
    /// it aside lets no refused group back in meanwhile.
    missing: bool,
}

impl List {
    /// Reads the list at path. A file that does not exist yet is an empty
    /// list, which reload reads once it appears; one that cannot be read
    /// or parsed is an error, so a relay never starts without the list it
    /// was given.
    pub fn load(path: &Path) -> Result<List> {
        if path.as_os_str().is_empty() {
            return Err(Error::msg("refused: no file"));
        }
        let l = List { path: path.to_path_buf(), state: Mutex::new(Read::default()) };
        l.reload()?;
        Ok(l)
    }

    /// Reads the list a relay's flag names: file, or refused-groups in the
    /// directory of the relay's key file when file is empty, or none when
    /// file is "none".
    pub fn open(file: &str, key_file: &Path) -> Result<Option<List>> {
        match file {
            "none" => Ok(None),
            "" => {
                let dir = key_file.parent().unwrap_or_else(|| Path::new("."));
                List::load(&dir.join("refused-groups")).map(Some)
            }
            f => List::load(Path::new(f)).map(Some),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Read> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Whether the group or period tag ("period <tag>") is on the list.
    pub fn refused(&self, tag: &str) -> bool {
        self.lock().tags.contains(tag)
    }

    /// The number of tags on the list.
    pub fn len(&self) -> usize {
        self.lock().tags.len()
    }

    /// Whether the list refuses no group.
    pub fn is_empty(&self) -> bool {
        self.lock().tags.is_empty()
    }

    /// Reads the file again when it changed, and tells whether the list
    /// did. A file that cannot be read or parsed keeps the list as it was:
    /// a typo in the file never lets a refused group back in.
    pub fn reload(&self) -> Result<bool> {
        let meta = match std::fs::metadata(&self.path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let mut r = self.lock();
                if !r.missing && !r.tags.is_empty() {
                    r.missing = true;
                    return Ok(false);
                }
                let changed = !r.tags.is_empty();
                *r = Read { missing: true, ..Read::default() };
                return Ok(changed);
            }
            Err(e) => return Err(Error::msg(format!("refused: {e}"))),
        };
        let modified = meta.modified().ok();
        {
            let mut r = self.lock();
            r.missing = false;
            if modified.is_some() && r.modified == modified && r.size == meta.len() {
                return Ok(false);
            }
        }
        if meta.len() > MAX_FILE {
            return Err(Error::msg(format!("refused: {} is larger than {MAX_FILE} bytes", self.path.display())));
        }
        let b = std::fs::read(&self.path).map_err(|e| Error::msg(format!("refused: {e}")))?;
        let tags = parse(&b).map_err(|e| Error::msg(format!("refused: {}: {e}", self.path.display())))?;
        let mut r = self.lock();
        let changed = tags != r.tags;
        *r = Read { tags, modified, size: meta.len(), missing: false };
        Ok(changed)
    }
}

/// Reads the lines of a list, as Go's refused.Parse.
pub fn parse(b: &[u8]) -> std::result::Result<HashSet<String>, String> {
    let text = std::str::from_utf8(b).map_err(|_| "the file is not UTF-8".to_string())?;
    let mut tags = HashSet::new();
    for (n, line) in text.lines().enumerate() {
        let n = n + 1;
        let mut f = line.split_whitespace();
        let Some(first) = f.next() else { continue };
        if first.starts_with('#') {
            continue;
        }
        let tag = if first == "period" {
            match f.next() {
                Some(t) if is_tag(t) => format!("period {t}"),
                _ => return Err(format!("line {n}: \"period\" without a tag of 16 hex characters")),
            }
        } else if is_tag(first) {
            first.to_string()
        } else {
            return Err(format!("line {n}: {first:?} is not a group tag of 16 hex characters"));
        };
        tags.insert(tag);
    }
    Ok(tags)
}

fn is_tag(s: &str) -> bool {
    s.len() == 16 && s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "0123456789abcdef";
    const B: &str = "fedcba9876543210";

    fn dir() -> PathBuf {
        let d = std::env::temp_dir().join(format!("cbb-refused-{}", cbb_core::certs::random_id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Writes the file with a time of its own, as an editor's save would
    /// have.
    fn write(path: &Path, s: &str, age_secs: u64) {
        std::fs::write(path, s).unwrap();
        let t = SystemTime::now() - std::time::Duration::from_secs(age_secs);
        std::fs::File::options().write(true).open(path).unwrap().set_modified(t).unwrap();
    }

    /// The lines as Go's TestParse reads them.
    #[test]
    fn parses_as_go() {
        let tags = parse(format!("# reports\n\n{A} 2026-11-09 abuse@ report\nperiod {B}\n  {B}\n").as_bytes()).unwrap();
        assert_eq!(tags.len(), 3);
        assert!(tags.contains(A) && tags.contains(B) && tags.contains(&format!("period {B}")));
        for bad in [
            "0123456789ABCDEF\n",
            "0123456789abcde\n",
            "0123456789abcdef0\n",
            "period\n",
            "period xyz\n",
            &format!("group {A}\n"),
        ] {
            assert!(parse(bad.as_bytes()).is_err(), "parse took {bad:?}");
        }
    }

    /// As Go's TestReload: the list follows the file, a broken file keeps
    /// the one before, and a file too large is refused; a missing file
    /// empties the list only once it stays missing.
    #[test]
    fn reloads() {
        let d = dir();
        let path = d.join("refused");
        assert!(List::load(Path::new("")).is_err());
        let l = List::load(&path).unwrap();
        assert!(!l.refused(A));
        write(&path, &format!("{A}\n"), 180);
        assert!(l.reload().unwrap());
        assert!(l.refused(A) && !l.refused(B) && l.len() == 1);
        assert!(!l.reload().unwrap(), "an unchanged file");

        write(&path, &format!("{A}\nnot a tag\n"), 120);
        assert!(l.reload().is_err());
        assert!(l.refused(A), "a broken file let a refused group back in");

        write(&path, &format!("{B}\n"), 60);
        assert!(l.reload().unwrap());
        assert!(!l.refused(A) && l.refused(B));

        std::fs::remove_file(&path).unwrap();
        assert!(!l.reload().unwrap(), "a file moved aside for a moment");
        assert!(l.refused(B), "a file moved aside let a refused group back in");
        assert!(l.reload().unwrap(), "a removed file");
        assert!(!l.refused(B), "a removed file still refuses");

        write(&path, &"\n".repeat(MAX_FILE as usize + 1), 0);
        assert!(l.reload().is_err(), "a file too large");
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn opens_beside_the_key() {
        let d = dir();
        let key = d.join("relay.pem");
        assert!(List::open("none", &key).unwrap().is_none());
        std::fs::write(d.join("refused-groups"), format!("{A}\n")).unwrap();
        assert!(List::open("", &key).unwrap().unwrap().refused(A));
        let other = d.join("other");
        std::fs::write(&other, "broken\n").unwrap();
        assert!(List::open(other.to_str().unwrap(), &key).is_err(), "a relay must not start without its list");
        let _ = std::fs::remove_dir_all(d);
    }
}
