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
use serde_json::Value;

use crate::error::{Error, Result};
use crate::files::write_atomic;

/// The file it is kept in, in the state directory, as the full member's.
pub const FILE: &str = "release.json";

/// The folder of the held release's archives, named by their SHA-256.
pub const FILES_DIR: &str = "release-files";

/// The largest release taken: three signed files of a few KB.
const MAX: usize = 256 << 10;

#[derive(Deserialize)]
struct Set {
    keys: File,
    channel: File,
    release: File,
}

struct Held {
    set: Value,
    seen: Seen,
    version: String,
    files: Vec<Asset>,
    expires_ms: i64,
}

/// The release this member holds.
pub struct Releases {
    dir: PathBuf,
    roots: Vec<Vec<u8>>,
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
    pub fn open(dir: &Path, roots: Vec<Vec<u8>>, now_ms: i64, log: &dyn Fn(&str)) -> Releases {
        let r = Releases { dir: dir.to_path_buf(), roots, held: Mutex::new(None) };
        match std::fs::read(dir.join(FILE)) {
            Ok(data) => match serde_json::from_slice::<Value>(&data).map_err(|_| Error::msg("it does not decode")) {
                Ok(v) => match r.check(&v, now_ms, &Seen::default()) {
                    Ok(h) => *r.held.lock().unwrap() = Some(h),
                    Err(err) => log(&format!("cbb: the release kept in {FILE}: {}", err.for_log())),
                },
                Err(err) => log(&format!("cbb: the release kept in {FILE}: {}", err.for_log())),
            },
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => log(&format!("cbb: cannot read {}: {err}", dir.join(FILE).display())),
        }
        r
    }

    fn check(&self, v: &Value, now_ms: i64, seen: &Seen) -> Result<Held> {
        if self.roots.is_empty() {
            return Err(Error::msg("this build pins no release keys"));
        }
        let set: Set = serde_json::from_value(v.clone()).map_err(|_| Error::msg("the release does not decode"))?;
        let roots: Vec<&[u8]> = self.roots.iter().map(Vec::as_slice).collect();
        let seen = Seen { version: String::new(), ..seen.clone() };
        let (r, next) =
            release::check(&set.keys, &set.channel, &set.release, &roots, crate::update::CHANNEL, now_ms, &seen)?;
        let c = release::decode_channel(&set.channel.body)?;
        Ok(Held { set: v.clone(), seen: next, version: r.version, files: r.files, expires_ms: c.expires_ms })
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
    pub fn current(&self, now_ms: i64) -> Option<Value> {
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

    /// Takes a release when it checks out and is newer than the one held,
    /// keeps it in the file and reports whether it did; the archives of
    /// the older one go.
    pub fn take(&self, v: &Value, now_ms: i64) -> Result<bool> {
        if serde_json::to_vec(v).map_or(true, |d| d.len() > MAX) {
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
        let data = serde_json::to_vec(v).map_err(|_| Error::msg("cannot encode the release"))?;
        write_atomic(&self.dir.join(FILE), &data, 0o600)?;
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

/// Whether this device should install the release v: it is above this
/// build's version. A development build is offered nothing, as cbb update
/// installs over releases only.
pub fn offered(v: &str) -> bool {
    let own = crate::service::VERSION.trim_start_matches('v');
    own != "dev" && release::compare(v, own) == std::cmp::Ordering::Greater
}
