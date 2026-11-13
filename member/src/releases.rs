// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The newest signed release the group passes around (docs/protocol.md,
//! section 16, "In the group"), as Go's releaseStore: a member keeps the
//! newest that checks out for the stable channel, passes it on, says in
//! cbb status when it is above this build, and keeps the archives of it
//! that cbb update installed, which it serves to its peers.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use cbb_core::release::{self, Asset, File, Seen};
use serde::Deserialize;
use serde_json::value::RawValue;

use crate::error::{Error, Result};
use crate::files::write_atomic;

/// The file it is kept in, in the state directory, as the full member's.
pub const FILE: &str = "release.json";

/// The folder of the held release's archives, named by their SHA-256.
pub const FILES_DIR: &str = "release-files";

/// The largest release taken: its three files, each at most as large as
/// any reader takes a release file, and the JSON around them.
const MAX: usize = 3 * release::MAX_FILE + 64;

#[derive(Deserialize)]
struct Set {
    keys: File,
    channel: File,
    release: File,
}

struct Held {
    set: Box<RawValue>,
    seen: Seen,
    version: String,
    files: Vec<Asset>,
    expires_ms: i64,
}

/// The release this member holds.
pub struct Releases {
    dir: PathBuf,
    roots: Vec<cbb_core::release::Key>,
    held: Mutex<Option<Held>>,
}

/// Reports whether the order (keys.json seq, channel seq) a is newer than
/// b: a release under a newer keys.json is newer whatever its channel
/// file's seq.
pub fn newer(a: (u64, u64), b: (u64, u64)) -> bool {
    a.0 > b.0 || (a.0 == b.0 && a.1 > b.1)
}

impl Releases {
    /// Opens the release kept in dir, checked again under roots, which may
    /// be others since; one that no longer checks out is dropped, and
    /// logged.
    pub fn open(dir: &Path, roots: Vec<cbb_core::release::Key>, now_ms: i64, log: &dyn Fn(&str)) -> Releases {
        let r = Releases { dir: dir.to_path_buf(), roots, held: Mutex::new(None) };
        match std::fs::read(dir.join(FILE)) {
            Ok(data) => {
                match serde_json::from_slice::<Box<RawValue>>(&data).map_err(|_| Error::msg("it does not decode")) {
                    Ok(v) => match r.check(&v, now_ms, &Seen::default()) {
                        Ok(h) => *r.held.lock().unwrap() = Some(h),
                        Err(err) => log(&format!("cbb: the release kept in {FILE}: {}", err.for_log())),
                    },
                    Err(err) => log(&format!("cbb: the release kept in {FILE}: {}", err.for_log())),
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => log(&format!("cbb: cannot read {}: {err}", dir.join(FILE).display())),
        }
        r
    }

    fn check(&self, v: &RawValue, now_ms: i64, seen: &Seen) -> Result<Held> {
        if self.roots.is_empty() {
            return Err(Error::msg("this build pins no release keys"));
        }
        // The set in the strict form of signed bodies, each file read from
        // the bytes that came, as it was signed.
        cbb_core::strict::check(v.get().as_bytes(), &["keys", "channel", "release"])
            .map_err(|e| Error::msg(format!("the release: {}", e.message())))?;
        let set: Set = serde_json::from_str(v.get()).map_err(|_| Error::msg("the release does not decode"))?;
        let roots = &self.roots;
        let seen = Seen { version: String::new(), ..seen.clone() };
        let (r, next) =
            release::check(&set.keys, &set.channel, &set.release, roots, crate::update::CHANNEL, now_ms, &seen)?;
        let c = release::decode_channel(&set.channel.body)?;
        Ok(Held { set: v.to_owned(), seen: next, version: r.version, files: r.files, expires_ms: c.expires_ms })
    }

    /// The keys.json and channel seqs of the release held, which a hello
    /// names; (0, 0) for none, or once its channel file has expired.
    pub fn order(&self, now_ms: i64) -> (u64, u64) {
        match self.held.lock().unwrap().as_ref() {
            Some(h) if now_ms < h.expires_ms => (h.seen.keys_seq, h.seen.channel_seq),
            _ => (0, 0),
        }
    }

    /// The release held, `{keys, channel, release}`, while its channel file
    /// has not expired.
    pub fn current(&self, now_ms: i64) -> Option<Box<RawValue>> {
        self.held.lock().unwrap().as_ref().filter(|h| now_ms < h.expires_ms).map(|h| h.set.clone())
    }

    /// The version of the release held, while it has not expired.
    pub fn version(&self, now_ms: i64) -> Option<String> {
        self.held.lock().unwrap().as_ref().filter(|h| now_ms < h.expires_ms).map(|h| h.version.clone())
    }

    /// The archive of the release held whose SHA-256 is sha, hex.
    pub fn file(&self, sha: &str, now_ms: i64) -> Option<Asset> {
        let held = self.held.lock().unwrap();
        held.as_ref().filter(|h| now_ms < h.expires_ms)?.files.iter().find(|f| f.sha256 == sha).cloned()
    }

    /// The archives of the release held, while it has not expired.
    pub fn files(&self, now_ms: i64) -> Vec<Asset> {
        self.held
            .lock()
            .unwrap()
            .as_ref()
            .filter(|h| now_ms < h.expires_ms)
            .map(|h| h.files.clone())
            .unwrap_or_default()
    }

    /// Where the archive with the SHA-256 sha is kept once held whole.
    pub fn path_of(&self, sha: &str) -> PathBuf {
        self.dir.join(FILES_DIR).join(sha)
    }

    /// The size of the archive sha of the release held when this member
    /// holds it whole; only those are served.
    pub fn held(&self, sha: &str, now_ms: i64) -> Option<u64> {
        let a = self.file(sha, now_ms)?;
        let size = u64::try_from(a.size).ok()?;
        std::fs::metadata(self.path_of(sha)).ok().filter(|m| m.is_file() && m.len() == size).map(|_| size)
    }

    /// Reads up to len bytes of the archive whose SHA-256 is sum from
    /// offset, for a peer; None when it is not held whole.
    pub fn read(&self, sum: &[u8], offset: u64, len: usize, now_ms: i64) -> Option<Vec<u8>> {
        use std::io::{Read, Seek, SeekFrom};
        let sha = hex(sum);
        let size = self.held(&sha, now_ms)?;
        if offset >= size {
            return Some(Vec::new());
        }
        let mut f = std::fs::File::open(self.path_of(&sha)).ok()?;
        f.seek(SeekFrom::Start(offset)).ok()?;
        let mut out = vec![0u8; len.min(usize::try_from(size - offset).unwrap_or(usize::MAX))];
        f.read_exact(&mut out).ok()?;
        Some(out)
    }

    /// Takes the archive at tmp, whole, as the archive sha of the release
    /// held: it must be listed, of the listed size and match the hash.
    pub fn keep_file(&self, sha: &str, tmp: &Path, now_ms: i64) -> Result<()> {
        let a = self.file(sha, now_ms).ok_or_else(|| Error::msg("the release this device holds lists no such file"))?;
        let (size, sum) = crate::content::file_sum(tmp).map_err(|e| e.context("cannot read the archive"))?;
        if i64::try_from(size).ok() != Some(a.size) {
            return Err(Error::msg(format!("{} is {size} bytes, not as said", a.name)));
        }
        if hex(&sum) != sha {
            return Err(Error::msg(format!("{} does not match the signed release.json", a.name)));
        }
        std::fs::rename(tmp, self.path_of(sha)).map_err(|e| Error::with("cannot keep the archive", e))
    }

    /// The folder of the archives, made when it is not there.
    pub fn files_dir(&self) -> Result<PathBuf> {
        let dir = self.dir.join(FILES_DIR);
        std::fs::create_dir_all(&dir)
            .map_err(|e| Error::with("cannot make the folder of the release's archives", e))?;
        Ok(dir)
    }

    /// Takes a release when it checks out and is newer than the one held,
    /// keeps it in the file and reports whether it did; the archives of
    /// the older one go.
    pub fn take(&self, v: &RawValue, now_ms: i64) -> Result<bool> {
        if v.get().len() > MAX {
            return Err(Error::msg("the release is too large"));
        }
        let mut held = self.held.lock().unwrap();
        let live = held.as_ref().filter(|h| now_ms < h.expires_ms);
        let seen = live.map(|h| h.seen.clone()).unwrap_or_default();
        let have = live.map_or((0, 0), |h| (h.seen.keys_seq, h.seen.channel_seq));
        let h = self.check(v, now_ms, &seen)?;
        if !newer((h.seen.keys_seq, h.seen.channel_seq), have) {
            return Ok(false);
        }
        write_atomic(&self.dir.join(FILE), v.get().as_bytes(), 0o600)?;
        let keep: Vec<String> = h.files.iter().map(|f| f.sha256.clone()).collect();
        *held = Some(h);
        drop(held);
        self.prune(&keep);
        Ok(true)
    }

    /// Deletes the archives that the release held does not list.
    fn prune(&self, keep: &[String]) {
        let Ok(rd) = std::fs::read_dir(self.dir.join(FILES_DIR)) else { return };
        for e in rd.flatten() {
            if !keep.iter().any(|k| e.file_name().to_str() == Some(k.as_str())) {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
}

/// sum in lowercase hex.
pub fn hex(sum: &[u8]) -> String {
    sum.iter().map(|b| format!("{b:02x}")).collect()
}

/// The bytes of s in hex, lowercase or not; None when it is not hex.
pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.is_ascii() {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

/// Whether this device should install the release v: it is above this
/// build's version. A development build is offered nothing, as cbb update
/// installs over releases only.
pub fn offered(v: &str) -> bool {
    let own = crate::service::VERSION.trim_start_matches('v');
    own != "dev" && release::compare(v, own) == std::cmp::Ordering::Greater
}

#[cfg(test)]
mod tests {
    use super::*;

    // The release is read from the bytes that came: the valid one of the
    // Go vectors is taken as signed, and the same files with release.json
    // in an envelope no reader takes, or a set not in the strict form, are
    // refused.
    #[test]
    fn takes_only_the_canonical_envelope() {
        let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata/interop/go-release.json");
        let v: serde_json::Value = serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap();
        let now = v["now_ms"].as_i64().unwrap();
        let roots: Vec<cbb_core::release::Key> = serde_json::from_value(v["roots"].clone()).unwrap();
        let c = &v["vectors"][0];
        assert_eq!(c["name"], "valid");
        let file = |n: &str| v["files"][c[n].as_u64().unwrap() as usize].clone();
        let (keys, channel, rel) = (file("keys").to_string(), file("channel").to_string(), file("release"));
        let set = |rel: &str| {
            crate::entries::set_of(&[
                ("keys", keys.as_bytes()),
                ("channel", channel.as_bytes()),
                ("release", rel.as_bytes()),
            ])
            .unwrap()
        };
        let dir = std::env::temp_dir().join(format!("cbb-releases-canonical-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let r = Releases::open(&dir, roots, now, &|_| {});
        let (body, sigs) = (rel["body"].as_str().unwrap(), rel["sigs"].to_string());
        for bad in [format!(r#"{{"sigs":{sigs},"body":"{body}"}}"#), format!(r#"{{ "body":"{body}","sigs":{sigs}}}"#)] {
            assert!(r.take(&set(&bad), now).is_err(), "{bad:.40}");
        }
        let escaped = format!(r#"{{"k\u0065ys":{keys},"channel":{channel},"release":{rel}}}"#);
        assert!(r.take(&RawValue::from_string(escaped).unwrap(), now).is_err());
        assert_eq!(r.order(now), (0, 0));
        let good = set(&rel.to_string());
        assert!(r.take(&good, now).unwrap());
        assert_eq!(std::fs::read(dir.join(FILE)).unwrap(), good.get().as_bytes());
        assert_eq!(r.version(now).as_deref(), Some("0.6.0"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
