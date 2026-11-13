// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The signed list of the project's entry points (docs/protocol.md, section
//! 16, "Entry points"). A member that is no hub reaches no forwarder
//! itself, so it only takes the list from its peers, keeps the newest that
//! checks out and passes it on, as the full members do.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use cbb_core::release::{self, File, Seen};
use serde::Deserialize;
use serde_json::value::RawValue;

use crate::error::{Error, Result};
use crate::files::write_atomic;

/// The file it is kept in, in the state directory, as the full member's.
pub const FILE: &str = "entries.json";

/// The largest set taken: its two files, each at most as large as any
/// reader takes a release file, and the JSON around them.
pub const MAX: usize = 2 * release::MAX_FILE + 64;

#[derive(Deserialize)]
struct Set {
    keys: File,
    entries: File,
}

struct Held {
    set: Box<RawValue>,
    seen: Seen,
    expires_ms: i64,
}

/// The entry points this member holds.
pub struct Entries {
    path: PathBuf,
    roots: Vec<cbb_core::release::Key>,
    held: Mutex<Option<Held>>,
}

/// Reads a set `{keys, entries}` from the bytes that came, so that each
/// file is read as it was signed and sent (docs/protocol.md, section 16,
/// "Two signatures").
fn decode(v: &RawValue) -> Result<Set> {
    serde_json::from_str(v.get()).map_err(|_| Error::msg("the entry points do not decode"))
}

/// A set of signed files, `{"NAME": FILE, ...}`, of the bytes of each file
/// as fetched, which must each be one JSON value; the readers check them.
pub fn set_of(files: &[(&str, &[u8])]) -> Result<Box<RawValue>> {
    let mut out = String::from("{");
    for (i, (name, data)) in files.iter().enumerate() {
        let text = std::str::from_utf8(data).map_err(|_| Error::msg(format!("{name} is not UTF-8")))?;
        let one: &RawValue = serde_json::from_str(text).map_err(|_| Error::msg(format!("{name} does not decode")))?;
        if i > 0 {
            out.push(',');
        }
        out.push_str(&serde_json::to_string(name).map_err(|_| Error::msg("cannot encode a name"))?);
        out.push(':');
        out.push_str(one.get());
    }
    out.push('}');
    RawValue::from_string(out).map_err(|_| Error::msg("cannot encode the signed files"))
}

/// Reports whether the order (keys.json seq, entries.json seq) a is newer
/// than b: a newer keys.json, or the same one and a newer list.
pub fn newer(a: (u64, u64), b: (u64, u64)) -> bool {
    a.0 > b.0 || (a.0 == b.0 && a.1 > b.1)
}

impl Entries {
    /// Opens the list kept in dir, checked again under roots; a list that
    /// no longer checks out is dropped, and logged.
    pub fn open(dir: &Path, roots: Vec<cbb_core::release::Key>, now_ms: i64, log: &dyn Fn(&str)) -> Entries {
        let e = Entries { path: dir.join(FILE), roots, held: Mutex::new(None) };
        match std::fs::read(&e.path) {
            Ok(data) => {
                match serde_json::from_slice::<Box<RawValue>>(&data).map_err(|_| Error::msg("it does not decode")) {
                    Ok(v) => match e.check(&v, now_ms, &Seen::default()) {
                        Ok(h) => *e.held.lock().unwrap() = Some(h),
                        Err(err) => log(&format!("cbb: the entry points kept in {FILE}: {}", err.for_log())),
                    },
                    Err(err) => log(&format!("cbb: the entry points kept in {FILE}: {}", err.for_log())),
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => log(&format!("cbb: cannot read {}: {err}", e.path.display())),
        }
        e
    }

    fn check(&self, v: &RawValue, now_ms: i64, seen: &Seen) -> Result<Held> {
        if self.roots.is_empty() {
            return Err(Error::msg("this build pins no release keys"));
        }
        let set = decode(v)?;
        let roots = &self.roots;
        let (e, next) = release::check_entries(&set.keys, &set.entries, roots, now_ms, seen)?;
        Ok(Held { set: v.to_owned(), seen: next, expires_ms: e.expires_ms })
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
    pub fn current(&self, now_ms: i64) -> Option<Box<RawValue>> {
        self.held.lock().unwrap().as_ref().filter(|h| now_ms < h.expires_ms).map(|h| h.set.clone())
    }

    /// The keys keys.json of the list held names for the project's relay
    /// `name` (each a SubjectPublicKeyInfo, DER), while the list has not
    /// expired; none when it names none.
    pub fn relay_keys(&self, name: &str, now_ms: i64) -> Vec<Vec<u8>> {
        let Some(set) = self.current(now_ms) else { return Vec::new() };
        let Ok(set) = decode(&set) else { return Vec::new() };
        let roots = &self.roots;
        let Ok(keys) = release::verify_keys(&set.keys, roots, now_ms, &Seen::default()) else { return Vec::new() };
        keys.relays(name)
    }

    /// Where the list held says the project's relay `name` is reached now,
    /// host:port, while the list has not expired; none when it names none.
    pub fn relay_endpoints(&self, name: &str, now_ms: i64) -> Vec<String> {
        let Some(set) = self.current(now_ms) else { return Vec::new() };
        let Ok(set) = decode(&set) else { return Vec::new() };
        let roots = &self.roots;
        match release::check_entries(&set.keys, &set.entries, roots, now_ms, &Seen::default()) {
            Ok((e, _)) => e.relays.into_iter().find(|r| r.name == name).map(|r| r.endpoints).unwrap_or_default(),
            Err(_) => Vec::new(),
        }
    }

    /// Takes a list a peer sent when it checks out and is newer than the one
    /// held, keeps it in the file and reports whether it did.
    pub fn take(&self, v: &RawValue, now_ms: i64) -> Result<bool> {
        if v.get().len() > MAX {
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
        write_atomic(&self.path, v.get().as_bytes(), 0o644)?;
        *held = Some(h);
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn vectors() -> Value {
        let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata/interop/go-entries.json");
        serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap()
    }

    fn roots(v: &Value) -> Vec<cbb_core::release::Key> {
        serde_json::from_value(v["roots"].clone()).unwrap()
    }

    fn case(v: &Value, name: &str) -> Box<RawValue> {
        let c = v["vectors"].as_array().unwrap().iter().find(|c| c["name"] == name).unwrap();
        serde_json::value::to_raw_value(&serde_json::json!({"keys": c["keys"], "entries": c["entries"]})).unwrap()
    }

    // The valid list with its keys.json written another way: the same body
    // and signatures, in an envelope that no reader takes.
    fn reworded(v: &Value, how: fn(&str, &str) -> String) -> Box<RawValue> {
        let c = v["vectors"].as_array().unwrap().iter().find(|c| c["name"] == "valid").unwrap();
        let keys = how(c["keys"]["body"].as_str().unwrap(), &c["keys"]["sigs"].to_string());
        let entries = c["entries"].to_string();
        set_of(&[("keys", keys.as_bytes()), ("entries", entries.as_bytes())]).unwrap()
    }

    #[test]
    fn takes_only_the_canonical_envelope() {
        let v = vectors();
        let now = v["now_ms"].as_i64().unwrap();
        let dir = std::env::temp_dir().join(format!("cbb-entries-canonical-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let e = Entries::open(&dir, roots(&v), now, &|_| {});
        let spaced = reworded(&v, |b, s| format!(r#"{{ "body" : "{b}" , "sigs" : {s} }}"#));
        let reordered = reworded(&v, |b, s| format!(r#"{{"sigs":{s},"body":"{b}"}}"#));
        assert!(e.take(&spaced, now).is_err());
        assert!(e.take(&reordered, now).is_err());
        assert_eq!(e.order(now), (0, 0));
        // Written as signed, with the space around it that readers pass
        // over, the same list is taken, and kept as it came.
        let same = reworded(&v, |b, s| format!("\n{{\"body\":\"{b}\",\"sigs\":{s}}}\r\n"));
        assert!(e.take(&same, now).unwrap());
        assert_eq!(std::fs::read(dir.join(FILE)).unwrap(), same.get().as_bytes());
        assert!(set_of(&[("keys", b"{} {}")]).is_err());
        let _ = std::fs::remove_dir_all(&dir);
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
