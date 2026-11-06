// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The signed list of the project's entry points (docs/protocol.md, section
//! 16, "Entry points"). The lite member is no hub and reaches no forwarder
//! itself, so it only takes the list from its peers, keeps the newest that
//! checks out and passes it on, as the full members do.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use cbb_core::release::{self, File, Seen};
use serde::Deserialize;
use serde_json::Value;

use crate::error::{Error, Result};
use crate::files::write_atomic;

/// The file it is kept in, in the state directory, as the full member's.
pub const FILE: &str = "entries.json";

/// The largest list taken: a keys.json and an entries.json are a few KB.
const MAX: usize = 64 << 10;

#[derive(Deserialize)]
struct Set {
    keys: File,
    entries: File,
}

struct Held {
    set: Value,
    seen: Seen,
    expires_ms: i64,
}

/// The entry points this member holds.
pub struct Entries {
    path: PathBuf,
    roots: Vec<Vec<u8>>,
    held: Mutex<Option<Held>>,
}

/// Reports whether the order (keys.json seq, entries.json seq) a is newer
/// than b: a newer keys.json, or the same one and a newer list.
pub fn newer(a: (u64, u64), b: (u64, u64)) -> bool {
    a.0 > b.0 || (a.0 == b.0 && a.1 > b.1)
}

impl Entries {
    /// Opens the list kept in dir, checked again under roots; a list that
    /// no longer checks out is dropped, and logged.
    pub fn open(dir: &Path, roots: Vec<Vec<u8>>, now_ms: i64, log: &dyn Fn(&str)) -> Entries {
        let e = Entries { path: dir.join(FILE), roots, held: Mutex::new(None) };
        match std::fs::read(&e.path) {
            Ok(data) => match serde_json::from_slice::<Value>(&data).map_err(|_| Error::msg("it does not decode")) {
                Ok(v) => match e.check(&v, now_ms, &Seen::default()) {
                    Ok(h) => *e.held.lock().unwrap() = Some(h),
                    Err(err) => log(&format!("cbb: the entry points kept in {FILE}: {}", err.for_log())),
                },
                Err(err) => log(&format!("cbb: the entry points kept in {FILE}: {}", err.for_log())),
            },
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => log(&format!("cbb: cannot read {}: {err}", e.path.display())),
        }
        e
    }

    fn check(&self, v: &Value, now_ms: i64, seen: &Seen) -> Result<Held> {
        if self.roots.is_empty() {
            return Err(Error::msg("this build pins no release keys"));
        }
        let set: Set = serde_json::from_value(v.clone()).map_err(|_| Error::msg("the entry points do not decode"))?;
        let roots: Vec<&[u8]> = self.roots.iter().map(Vec::as_slice).collect();
        let (e, next) = release::check_entries(&set.keys, &set.entries, &roots, now_ms, seen)?;
        Ok(Held { set: v.clone(), seen: next, expires_ms: e.expires_ms })
    }

    /// The keys.json and entries.json seqs of the list held, which a hello
    /// names; (0, 0) for none, or once it has expired.
    pub fn order(&self, now_ms: i64) -> (u64, u64) {
        match self.held.lock().unwrap().as_ref() {
            Some(h) if now_ms < h.expires_ms => (h.seen.entries_keys_seq, h.seen.entries_seq),
            _ => (0, 0),
        }
    }

    /// The list held, `{keys, entries}`, while it has not expired.
    pub fn current(&self, now_ms: i64) -> Option<Value> {
        self.held.lock().unwrap().as_ref().filter(|h| now_ms < h.expires_ms).map(|h| h.set.clone())
    }

    /// Takes a list a peer sent when it checks out and is newer than the one
    /// held, keeps it in the file and reports whether it did.
    pub fn take(&self, v: &Value, now_ms: i64) -> Result<bool> {
        if serde_json::to_vec(v).map_or(true, |d| d.len() > MAX) {
            return Err(Error::msg("the entry points are too large"));
        }
        let mut held = self.held.lock().unwrap();
        let live = held.as_ref().filter(|h| now_ms < h.expires_ms);
        let seen = live.map(|h| h.seen.clone()).unwrap_or_default();
        let have = live.map_or((0, 0), |h| (h.seen.entries_keys_seq, h.seen.entries_seq));
        let h = self.check(v, now_ms, &seen)?;
        if !newer((h.seen.entries_keys_seq, h.seen.entries_seq), have) {
            return Ok(false);
        }
        let data = serde_json::to_vec(v).map_err(|_| Error::msg("cannot encode the entry points"))?;
        write_atomic(&self.path, &data, 0o644)?;
        *held = Some(h);
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vectors() -> Value {
        let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata/interop/go-entries.json");
        serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap()
    }

    fn roots(v: &Value) -> Vec<Vec<u8>> {
        #[derive(Deserialize)]
        struct Der(#[serde(with = "cbb_core::certs::b64")] Vec<u8>);
        v["roots"].as_array().unwrap().iter().map(|r| serde_json::from_value::<Der>(r.clone()).unwrap().0).collect()
    }

    fn case(v: &Value, name: &str) -> Value {
        let c = v["vectors"].as_array().unwrap().iter().find(|c| c["name"] == name).unwrap();
        serde_json::json!({"keys": c["keys"], "entries": c["entries"]})
    }

    #[test]
    fn takes_keeps_and_reopens() {
        let v = vectors();
        let now = v["now_ms"].as_i64().unwrap();
        let dir = std::env::temp_dir().join(format!("cbb-entries-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let log = |_: &str| {};
        let e = Entries::open(&dir, roots(&v), now, &log);
        assert_eq!(e.order(now), (0, 0));
        assert!(e.current(now).is_none());
        // A list under another key is refused, the valid one taken once.
        assert!(e.take(&case(&v, "signed by another key"), now).is_err());
        assert!(e.take(&case(&v, "valid"), now).unwrap());
        assert!(!e.take(&case(&v, "valid"), now).unwrap());
        assert_eq!(e.order(now), (3, 5));
        assert!(e.current(now).is_some());
        // It is kept across a restart, and not used once it has expired.
        let again = Entries::open(&dir, roots(&v), now, &log);
        assert_eq!(again.order(now), (3, 5));
        assert_eq!(again.order(i64::MAX), (0, 0));
        // Without roots nothing is taken.
        assert!(Entries::open(&dir, Vec::new(), now, &log).take(&case(&v, "valid"), now).is_err());
        let _ = std::fs::remove_dir_all(&dir);
        assert!(newer((4, 1), (3, 9)) && newer((3, 6), (3, 5)) && !newer((3, 5), (3, 5)) && !newer((2, 9), (3, 1)));
    }
}
