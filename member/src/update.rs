// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! cbb update (docs/guide/install.md, "Updating"):
//! it checks keys.json, stable.json and release.json against the release
//! roots, downloads the archive for this device, checks it and
//! the program in it, runs the archive's own installer, and puts the
//! previous program back when the service does not report the new version
//! within a minute. The downloads go through curl, wget or uclient-fetch,
//! whichever the system has, so cbb carries no HTTPS client of
//! its own; the signatures make the transport untrusted.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use cbb_core::certs::{hex, sha256};
use cbb_core::release::{self, File, Release, Seen};
use serde::{Deserialize, Serialize};

use crate::error::{Context, Error, Result};
use crate::files::write_atomic;

pub const CHANNEL: &str = "stable";
const GITHUB: &str = "https://github.com/HunterEwok/cbb/releases";
pub const MIRROR: &str = "https://dl.cbb.tools";
/// Where GitHub keeps the current keys.json and channel file: the branch
/// channel, since a published release takes no new files and these are
/// signed again while it is current (docs/protocol.md, section 16).
const CHANNEL_FILES: &str = "https://raw.githubusercontent.com/HunterEwok/cbb/channel";
const MAX_MANIFEST: u64 = cbb_core::release::MAX_FILE as u64;
const MAX_ARCHIVE: u64 = 256 << 20;
pub const HEALTH: Duration = Duration::from_secs(60);
/// A timer checks again only a day after the last check, less a margin for
/// its random time of day.
const CHECK_EVERY_MS: i64 = 20 * 3600 * 1000;
const STATE_FILE: &str = "update.json";
const NO_ROOTS: &str =
    "this build pins no release keys yet, so it cannot check a release; install a newer one with get.sh";

/// What the updater keeps in update.json, as the full member's does.
#[derive(Default, Serialize, Deserialize, PartialEq, Debug)]
pub struct State {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto: Option<bool>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub mirror: String,
    #[serde(default)]
    pub seen: Seen,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failed: Vec<String>,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub checked_ms: i64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub available: String,
}

fn is_zero(n: &i64) -> bool {
    *n == 0
}

/// The updater's folder, which only root may change, and where it
/// downloads (update_os::paths).
pub fn paths() -> (PathBuf, PathBuf) {
    crate::update_os::paths()
}

pub fn load_state(dir: &Path) -> Result<State> {
    let path = dir.join(STATE_FILE);
    match fs::read(&path) {
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(State::default()),
        Err(e) => Err(Error::with(format!("cannot read {}", path.display()), e)),
        Ok(data) => serde_json::from_slice(&data).context(format!("{} is damaged", path.display())),
    }
}

pub fn save_state(dir: &Path, st: &State) -> Result<()> {
    mkdir_private(dir)?;
    let data = serde_json::to_vec_pretty(st).context("cannot encode the update state")?;
    write_atomic(&dir.join(STATE_FILE), &data, 0o600)
}

fn mkdir_private(dir: &Path) -> Result<()> {
    crate::sys::mkdir_private(dir)
}

/// Reports whether a timer should check now.
pub fn due(st: &State, now_ms: i64) -> bool {
    st.auto == Some(true) && now_ms - st.checked_ms >= CHECK_EVERY_MS
}

pub fn now_ms() -> i64 {
    crate::uptime::wall_ms()
}

/// The release's archive for this device
/// (update_os::archive_name); None for a system it does not build for.
pub fn archive_name() -> Option<String> {
    crate::update_os::archive_name()
}

/// Where the release files come from: a server, or a folder for tests.
pub enum Source {
    Http { base: String, github: bool },
    Dir(PathBuf),
}

impl Source {
    /// GitHub, then dl.cbb.tools; or only the mirror the user set.
    pub fn defaults(mirror: &str) -> Result<Vec<Source>> {
        if !mirror.is_empty() {
            return Ok(vec![Source::mirror(mirror)?]);
        }
        Ok(vec![
            Source::Http { base: GITHUB.into(), github: true },
            Source::Http { base: MIRROR.into(), github: false },
        ])
    }

    pub fn mirror(url: &str) -> Result<Source> {
        if !url.starts_with("https://") || url.len() <= "https://".len() || url.contains(['?', '#', ' ']) {
            return Err(Error::msg(format!("a mirror is an https:// address without a query, not {url:?}")));
        }
        Ok(Source::Http { base: url.trim_end_matches('/').into(), github: false })
    }

    /// The address of name in the release version, or the latest one.
    fn url(&self, name: &str, version: &str) -> String {
        match self {
            Source::Http { github: true, .. }
                if version.is_empty() && (name == "keys.json" || name == format!("{CHANNEL}.json")) =>
            {
                format!("{CHANNEL_FILES}/{name}")
            }
            Source::Http { base, github: true } if version.is_empty() => format!("{base}/latest/download/{name}"),
            Source::Http { base, github: true } => format!("{base}/download/v{version}/{name}"),
            Source::Http { base, .. } if version.is_empty() => format!("{base}/{name}"),
            Source::Http { base, .. } => format!("{base}/v{version}/{name}"),
            Source::Dir(d) => d.join(name).display().to_string(),
        }
    }

    /// Writes name to path, refusing more than max bytes.
    fn fetch_to(&self, name: &str, version: &str, path: &Path, max: u64) -> Result<()> {
        let _ = fs::remove_file(path);
        match self {
            Source::Dir(d) => {
                fs::copy(d.join(name), path).context(format!("cannot copy {name} from {}", d.display()))?;
            }
            Source::Http { .. } => fetch(&self.url(name, version), path, max)?,
        }
        let len = fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        if len > max {
            let _ = fs::remove_file(path);
            return Err(Error::msg(format!("{name} is larger than {max} bytes")));
        }
        Ok(())
    }

    fn fetch(&self, name: &str, version: &str, work: &Path, max: u64) -> Result<Vec<u8>> {
        let path = work.join(format!(".{name}.part"));
        self.fetch_to(name, version, &path, max)?;
        let data = fs::read(&path).context(format!("cannot read the downloaded {name}"));
        let _ = fs::remove_file(&path);
        data
    }

    fn file(&self, name: &str, version: &str, work: &Path) -> Result<File> {
        let data = self.fetch(name, version, work, MAX_MANIFEST)?;
        serde_json::from_slice(&data).context(format!("{name} does not decode"))
    }
}

impl std::fmt::Display for Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Source::Http { base, .. } => f.write_str(base),
            Source::Dir(d) => write!(f, "{}", d.display()),
        }
    }
}

/// Downloads url to path with the first of curl, wget and uclient-fetch
/// that the system has: https only, also after a redirect where the tool
/// can be told, with the User-Agent cbb and nothing about this device. The
/// tool writes to a pipe, so that no more than max bytes reach the disk
/// (the RAM on OpenWrt), and it is stopped after FETCH_TIME.
fn fetch(url: &str, path: &Path, max: u64) -> Result<()> {
    fetch_via(url, path, max, None, FETCH_TIME)
}

/// As fetch, within time; with resolve (`host:443:address`) only curl,
/// which can be told to reach the host at that address.
fn fetch_via(url: &str, path: &Path, max: u64, resolve: Option<&str>, time: Duration) -> Result<()> {
    let max_s = max.to_string();
    let time_s = time.as_secs().to_string();
    let mut curl = vec![
        "-fsSL",
        "-g",
        "--proto",
        "=https",
        "--proto-redir",
        "=https",
        "--max-filesize",
        &max_s,
        "--max-time",
        &time_s,
        "-A",
        "cbb",
    ];
    if let Some(r) = resolve {
        curl.extend(["--resolve", r]);
    }
    curl.push(url);
    let mut tools: Vec<(&str, Vec<&str>)> = vec![("curl", curl)];
    if resolve.is_none() {
        tools.push(("wget", vec!["-q", "-U", "cbb", "-O", "-", url]));
        tools.push(("uclient-fetch", vec!["-q", "-O", "-", url]));
    }
    for (tool, args) in tools {
        let child =
            Command::new(tool).args(&args).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn();
        match child {
            Err(e) if e.kind() == ErrorKind::NotFound => continue,
            Err(e) => return Err(Error::with(format!("cannot run {tool}"), e)),
            Ok(child) => return fetch_with(tool, url, child, path, max),
        }
    }
    if resolve.is_some() {
        return Err(Error::msg(
            "fetching the signed lists from the relay's server needs curl, which this system has not",
        ));
    }
    Err(Error::msg("downloading needs curl, wget or uclient-fetch, and this system has none"))
}

/// Fetches keys.json and entries.json from the mirror reached at the
/// address at, the project's relay's server, where the mirror is too, as
/// Go's fetchProjectLists: `{keys, entries}`, which the node checks.
#[cfg(feature = "tunnel")]
pub fn fetch_lists_at(at: std::net::IpAddr, work: &Path) -> Result<serde_json::Value> {
    let host = MIRROR.trim_start_matches("https://");
    let ip = match at {
        std::net::IpAddr::V6(v6) => format!("[{v6}]"),
        v4 => v4.to_string(),
    };
    let resolve = format!("{host}:443:{ip}");
    let mut set = serde_json::Map::new();
    for (key, name) in [("keys", "keys.json"), ("entries", "entries.json")] {
        let path = work.join(format!(".{name}.relay.part"));
        let got = fetch_via(&format!("{MIRROR}/{name}"), &path, MAX_MANIFEST, Some(&resolve), LISTS_TIME)
            .and_then(|()| fs::read(&path).context(format!("cannot read the downloaded {name}")));
        let _ = fs::remove_file(&path);
        let v: serde_json::Value = serde_json::from_slice(&got?).context(format!("{name} does not decode"))?;
        set.insert(key.into(), v);
    }
    Ok(serde_json::Value::Object(set))
}

/// The longest fetching the signed lists from the relay's server may take.
#[cfg(feature = "tunnel")]
const LISTS_TIME: Duration = Duration::from_secs(60);

/// The longest a download may take.
const FETCH_TIME: Duration = Duration::from_secs(30 * 60);

/// Copies what child writes to path, at most max bytes, and stops it when
/// it writes more or takes longer than FETCH_TIME.
fn fetch_with(tool: &str, url: &str, mut child: std::process::Child, path: &Path, max: u64) -> Result<()> {
    use std::io::Read;
    let mut out = child.stdout.take().expect("piped");
    let mut err = child.stderr.take().expect("piped");
    let errs = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = err.by_ref().take(64 << 10).read_to_end(&mut b);
        b
    });
    let pid = child.id();
    let (done, stop) = std::sync::mpsc::channel::<()>();
    let watch = std::thread::spawn(move || {
        // Only the time running out stops the tool: done is dropped once
        // its output has ended, and a tool may still be finishing then.
        if let Err(std::sync::mpsc::RecvTimeoutError::Timeout) = stop.recv_timeout(FETCH_TIME) {
            // The child is waited for only after this thread is joined,
            // so pid is still its.
            crate::sys::kill(pid);
        }
    });
    let copied = (|| -> std::io::Result<u64> {
        let mut f = fs::File::create(path)?;
        std::io::copy(&mut out.by_ref().take(max + 1), &mut f)
    })();
    if !matches!(copied, Ok(n) if n <= max) {
        let _ = child.kill();
    }
    drop(out);
    drop(done);
    let _ = watch.join();
    let status = child.wait();
    let stderr = errs.join().unwrap_or_default();
    let res = match (copied, status) {
        (Err(e), _) => Err(Error::with(format!("cannot write the download of {url}"), e)),
        (Ok(n), _) if n > max => Err(Error::msg(format!("{url} is larger than {max} bytes"))),
        (Ok(_), Ok(s)) if s.success() => Ok(()),
        (Ok(_), Ok(_)) => {
            Err(Error::msg(format!("{tool} could not download {url}: {}", String::from_utf8_lossy(&stderr).trim())))
        }
        (Ok(_), Err(e)) => Err(Error::with(format!("cannot run {tool}"), e)),
    };
    if res.is_err() {
        let _ = fs::remove_file(path);
    }
    res
}

/// The service, which passes the signed release and its archives through
/// the group (docs/protocol.md, section 16, "In the group"), as Go's cbb
/// update asks it.
pub trait Group {
    /// Hands the service the release, `{keys, channel, release}`, that a
    /// server gave, for the group.
    fn share(&self, set: &serde_json::Value);
    /// The release the service holds, for when no server answers.
    fn held(&self) -> Result<serde_json::Value>;
    /// Writes the archive with the SHA-256 sha and size bytes to path, from
    /// the service, which holds it or fetches it from its peers.
    fn get(&self, sha: &str, size: i64, path: &Path) -> Result<()>;
    /// Hands the service the archive at path, now installed, to serve.
    fn keep(&self, sha: &str, size: i64, path: &Path);
    /// On a hub, the archives the group's members update from that the
    /// service does not hold.
    fn want(&self) -> Vec<String>;
}

/// Found::source of a release the service held.
pub const FROM_GROUP: usize = usize::MAX;

/// The release a check found.
pub struct Found {
    pub release: Release,
    /// Above the installed version.
    pub newer: bool,
    /// It did not become healthy here before.
    pub failed: bool,
    pub seen: Seen,
    /// The index of the source it came from, which the archive comes from;
    /// FROM_GROUP for the service's.
    pub source: usize,
}

pub type Installer<'a> = dyn Fn(&Path, &Path) -> Result<()> + 'a;
pub type Health<'a> = dyn Fn(&str, Duration) -> Result<()> + 'a;

pub struct Updater<'a> {
    pub work: PathBuf,
    pub roots: Vec<cbb_core::release::Key>,
    pub sources: Vec<Source>,
    pub installed: String,
    pub archive: String,
    /// The installed programs, which the archive's replace and which go
    /// back together when the new release fails: cbb first, then those
    /// beside it (update_os::programs).
    pub programs: Vec<PathBuf>,
    pub now_ms: i64,
    pub install: &'a Installer<'a>,
    pub healthy: &'a Health<'a>,
    pub log: &'a dyn Fn(&str),
    /// The service, when one runs.
    pub group: Option<&'a dyn Group>,
}

impl Updater<'_> {
    /// Fetches and checks the channel's current release from the first
    /// source that answers; a file that does not verify stops it, so that
    /// another server gets no say.
    pub fn check(&self, st: &State) -> Result<Found> {
        if self.roots.is_empty() {
            return Err(Error::msg(NO_ROOTS));
        }
        let roots = &self.roots;
        mkdir_private(&self.work)?;
        let mut errs = Vec::new();
        for (i, src) in self.sources.iter().enumerate() {
            let files = (|| -> Result<(File, File, File)> {
                let keys = src.file("keys.json", "", &self.work)?;
                let ch = src.file(&format!("{CHANNEL}.json"), "", &self.work)?;
                #[derive(Deserialize)]
                struct Names {
                    #[serde(default)]
                    release: String,
                }
                let names: Names = serde_json::from_slice(&ch.body).unwrap_or(Names { release: String::new() });
                if names.release.is_empty() {
                    return Err(Error::msg(format!("{CHANNEL}.json names no release")));
                }
                // The name goes into the release's address before the
                // channel file is checked, so it must be a version.
                if release::parse_version(&names.release).is_none() {
                    return Err(Error::msg(format!("{CHANNEL}.json names a release that is not a version")));
                }
                let rel = src.file("release.json", &names.release, &self.work)?;
                Ok((keys, ch, rel))
            })();
            let (keys, ch, rel) = match files {
                Ok(f) => f,
                Err(e) => {
                    errs.push(format!("{src}: {}", e.message()));
                    continue;
                }
            };
            // A signature that fails or a rollback is an answer, not a
            // server that is out of date: another server must not get a
            // say. Any other refusal, such as a channel file that expired,
            // leaves the next server to answer, as in Go's Updater.Check.
            let (r, seen) = match release::check(&keys, &ch, &rel, roots, CHANNEL, self.now_ms, &st.seen) {
                Ok(v) => v,
                Err(e) if e.is_answer() => return Err(e),
                Err(e) => {
                    errs.push(format!("{src}: {}", e.for_log()));
                    continue;
                }
            };
            if let Some(g) = self.group {
                g.share(&serde_json::json!({"keys": keys, "channel": ch, "release": rel}));
            }
            return Ok(self.found(st, r, seen, i));
        }
        // The release the group passed around, when no server answers.
        if let Some(g) = self.group {
            let held = g.held().and_then(|v| {
                #[derive(Deserialize)]
                struct Set {
                    keys: File,
                    channel: File,
                    release: File,
                }
                let set: Set = serde_json::from_value(v).context("the service's release does not decode")?;
                release::check(&set.keys, &set.channel, &set.release, roots, CHANNEL, self.now_ms, &st.seen)
            });
            match held {
                Ok((r, seen)) => {
                    (self.log)("No update server answered; the release comes from the group.");
                    return Ok(self.found(st, r, seen, FROM_GROUP));
                }
                Err(e) if e.is_answer() => return Err(e),
                Err(e) => errs.push(format!("the group: {}", e.message())),
            }
        }
        Err(Error::msg(format!("no update server answered: {}", errs.join("; "))))
    }

    fn found(&self, st: &State, r: Release, seen: Seen, source: usize) -> Found {
        Found {
            newer: release::compare(&r.version, &self.installed).is_gt(),
            failed: st.failed.contains(&r.version),
            release: r,
            seen,
            source,
        }
    }

    /// On a hub, downloads the archives of r that the group's members
    /// update from and the service lacks, from the source the release came
    /// from, and hands them to the service, so that devices on networks
    /// that block the update servers get them through the group (Go's
    /// archivesForGroup).
    pub fn archives_for_group(&self, source: usize, r: &Release) {
        let (Some(g), Some(src)) = (self.group, self.sources.get(source)) else { return };
        for name in g.want() {
            let Some(a) = r.files.iter().find(|a| a.name == name) else { continue };
            let file = self.work.join(format!(".group-{name}"));
            let res = mkdir_private(&self.work)
                .and_then(|()| src.fetch_to(&a.name, &r.version, &file, MAX_ARCHIVE.min(a.size.max(0) as u64)))
                .and_then(|()| r.check_file(&a.name, &fs::read(&file).context("cannot read the downloaded archive")?));
            match res {
                Ok(()) => g.keep(&a.sha256, a.size, &file),
                Err(e) => (self.log)(&format!("Not every archive for the group came: {}", e.message())),
            }
            let _ = fs::remove_file(&file);
        }
    }

    /// Downloads the archive, checks it and the program in it, installs it
    /// with its own installer and waits for the service to report the new
    /// version; otherwise it installs the previous program again and adds
    /// the version to st.failed.
    pub fn apply(&self, source: usize, st: &mut State, r: &Release) -> Result<()> {
        if !r.direct(&self.installed) {
            return Err(Error::msg(format!(
                "{} updates only from {} or later; install {} first with get.sh",
                r.version, r.min_from, r.min_from
            )));
        }
        let asset = r
            .files
            .iter()
            .find(|a| a.name == self.archive)
            .ok_or_else(|| Error::msg(format!("{} has no {} for this device", r.version, self.archive)))?;
        let prog = asset
            .binaries
            .iter()
            .find(|b| matches!(b.name.rsplit('/').next(), Some("cbb" | "cbb.exe")))
            .ok_or_else(|| Error::msg(format!("release.json lists no cbb in {}", asset.name)))?;
        mkdir_private(&self.work)?;
        let new = self.work.join("new");
        let _ = fs::remove_dir_all(&new);
        mkdir_private(&new)?;
        (self.log)(&format!("Downloading {} ({})...", asset.name, r.version));
        let file = self.work.join(&asset.name);
        let max = MAX_ARCHIVE.min(asset.size.max(0) as u64);
        match (source, self.group) {
            (FROM_GROUP, Some(g)) => g.get(&asset.sha256, asset.size, &file)?,
            (FROM_GROUP, None) => return Err(Error::msg("the release came from the group, which no longer answers")),
            _ => self.sources[source].fetch_to(&asset.name, &r.version, &file, max)?,
        }
        let data = fs::read(&file).context("cannot read the downloaded archive")?;
        r.check_file(&asset.name, &data)?;
        drop(data);
        // The archive's hash is the signed one, so its names are the
        // project's; tar unpacks it into a folder of its own.
        let out = crate::update_os::unpack(&file, &new).inspect_err(|_| {
            let _ = fs::remove_file(&file);
        })?;
        // The archive stays until the install ends, for the service to
        // serve to the group then.
        let _gone = Remove(&file);
        if !out.status.success() {
            return Err(Error::msg(format!(
                "cannot unpack {}: {}",
                asset.name,
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        for b in &asset.binaries {
            let p = new.join(&b.name);
            let ok = fs::symlink_metadata(&p).map(|m| m.is_file()).unwrap_or(false)
                && fs::read(&p).map(|d| hex(&sha256(&d)) == b.sha256).unwrap_or(false);
            if !ok {
                return Err(Error::msg(format!("{} in {} does not match release.json", b.name, asset.name)));
            }
        }
        let bin = new.join(&prog.name);
        let root = bin.parent().unwrap_or(&new).to_path_buf();
        // Each installed program and the archive's that replaces it.
        let (olds, news): (Vec<PathBuf>, Vec<PathBuf>) = std::iter::once((self.programs[0].clone(), bin.clone()))
            .chain(self.programs.iter().skip(1).filter_map(|p| {
                let new = root.join(p.file_name()?);
                new.is_file().then(|| (p.clone(), new))
            }))
            .unzip();
        crate::update_os::verify_signer(&olds, &news)?;
        // The installed programs go to a folder of their own, where the
        // installer finds those beside cbb when it puts them back.
        let prev = self.work.join("previous");
        let _ = fs::remove_dir_all(&prev);
        mkdir_private(&prev)?;
        let mut saved = PathBuf::new();
        for (i, p) in self.programs.iter().enumerate() {
            let name = if i == 0 {
                format!("cbb{}", std::env::consts::EXE_SUFFIX).into()
            } else {
                p.file_name().unwrap_or_default().to_os_string()
            };
            let to = prev.join(name);
            fs::copy(p, &to).context(format!("cannot keep a copy of {}", p.display()))?;
            if i == 0 {
                saved = to;
            }
        }

        (self.log)(&format!("Installing {}...", r.version));
        let mut res = (self.install)(&root, &bin);
        if res.is_ok() {
            res = (self.healthy)(&r.version, HEALTH).map_err(|e| {
                prefixed(e, &format!("the service did not report {} within {}s", r.version, HEALTH.as_secs()))
            });
        }
        let err = match res {
            Ok(()) => {
                st.failed.retain(|v| v != &r.version);
                st.available.clear();
                (self.log)(&format!("CBB {} is installed.", r.version));
                if let Some(g) = self.group {
                    g.keep(&asset.sha256, asset.size, &file);
                }
                return Ok(());
            }
            Err(e) => e,
        };
        if !st.failed.contains(&r.version) {
            st.failed.push(r.version.clone());
        }
        st.available.clear();
        let why = err.message().to_string();
        (self.log)(&format!("Putting {} back: {why}", self.installed));
        if let Err(e) = (self.install)(&root, &saved) {
            return Err(err.context(format!("{why}; and putting {} back failed too: {}", self.installed, e.message())));
        }
        if let Err(e) = (self.healthy)(&self.installed, HEALTH) {
            return Err(err.context(format!(
                "{why}; {} is back, but its service does not answer either: {}",
                self.installed,
                e.message()
            )));
        }
        Err(err.context(format!("{why}; {} is back, and automatic updates skip {}", self.installed, r.version)))
    }
}

/// Deletes its file when dropped.
struct Remove<'a>(&'a Path);

impl Drop for Remove<'_> {
    fn drop(&mut self) {
        let _ = fs::remove_file(self.0);
    }
}

/// Puts p before an error's message, keeping the error as the cause, which
/// -debug shows.
pub fn prefixed(e: Error, p: &str) -> Error {
    let m = format!("{p}: {}", e.message());
    e.context(m)
}

/// Runs the installer of this system in an unpacked archive on bin
/// (update_os::install).
pub fn install(root: &Path, bin: &Path) -> Result<()> {
    crate::update_os::install(root, bin)
}

/// Polls status until it reports version, or the time is up.
pub fn wait_healthy(status: &dyn Fn() -> Result<String>, version: &str, within: Duration) -> Result<()> {
    let start = Instant::now();
    loop {
        let last = match status() {
            Ok(v) if v == version => return Ok(()),
            Ok(v) => Error::msg(format!("it runs {v}")),
            // Not the hint to start the service: the previous version goes
            // back in and starts. The cause stays for -debug.
            Err(e) => e.context(format!(
                "it does not answer; {} -u cbb (logread on OpenWrt) tells why",
                crate::rootless::journalctl()
            )),
        };
        if start.elapsed() >= within {
            return Err(last);
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

/// The release roots: those of the PEM file CBB_RELEASE_ROOTS names, for
/// tests, else the pinned ones.
pub fn release_roots() -> Vec<release::Key> {
    if let Some(f) = std::env::var_os("CBB_RELEASE_ROOTS")
        && let Ok(r) = read_roots(Path::new(&f))
    {
        return r;
    }
    release::pinned_roots()
}

/// Reads the root keys of a PEM file, for tests (CBB_RELEASE_ROOTS).
pub fn read_roots(path: &Path) -> Result<Vec<release::Key>> {
    let text = fs::read_to_string(path).context(format!("cannot read {}", path.display()))?;
    release::parse_roots(&text).map_err(|e| Error::msg(format!("{}: {}", path.display(), e.message())))
}

const SYSTEMD_SERVICE: &str = "/etc/systemd/system/cbb-update.service";
const SYSTEMD_TIMER: &str = "/etc/systemd/system/cbb-update.timer";
const CRON_OPENWRT: &str = "/etc/crontabs/root";
const CRON_MARK: &str = "# cbb-update";

/// Adds the daily timer that runs exe update -timer, or removes it: a
/// systemd timer, or cron on OpenWrt, as the full member's; on the other
/// systems update_os's.
pub fn set_timer(on: bool, exe: &Path) -> Result<()> {
    if let Some(r) = crate::update_os::set_timer(on, exe) {
        return r;
    }
    if crate::openwrt() {
        return cron_timer(on, exe);
    }
    // A rootless install's timer is one of the user's own units.
    let user = crate::rootless::is();
    let (service_file, timer_file) = if user {
        let d = crate::rootless::unit_dir();
        (d.join("cbb-update.service"), d.join("cbb-update.timer"))
    } else {
        (PathBuf::from(SYSTEMD_SERVICE), PathBuf::from(SYSTEMD_TIMER))
    };
    let systemctl = |args: &[&str]| {
        let mut c = Command::new("systemctl");
        if user {
            c.arg("--user");
        }
        c.args(args);
        c
    };
    let run = |args: &[&str]| -> Result<()> {
        let o = systemctl(args).output().context("cannot run systemctl")?;
        if o.status.success() {
            Ok(())
        } else {
            Err(Error::msg(format!("systemctl {}: {}", args.join(" "), String::from_utf8_lossy(&o.stderr).trim())))
        }
    };
    if !on {
        let _ = systemctl(&["disable", "--now", "cbb-update.timer"]).output();
        for p in [&timer_file, &service_file] {
            match fs::remove_file(p) {
                Err(e) if e.kind() != ErrorKind::NotFound => {
                    return Err(Error::with(format!("cannot remove {}", p.display()), e));
                }
                _ => {}
            }
        }
        return run(&["daemon-reload"]);
    }
    let service = format!(
        "# Written by cbb update -auto on; cbb update -auto off removes it.\n[Unit]\nDescription=CBB automatic update\n\
         Wants=network-online.target\nAfter=network-online.target\n\n[Service]\nType=oneshot\n\
         # No sandbox: it runs the new release's install.sh, which changes the\n# system as installing does.\n\
         ExecStart={} update -timer\n",
        exe.display()
    );
    let timer = "# Written by cbb update -auto on; cbb update -auto off removes it.\n[Unit]\nDescription=Check for a CBB update once a day\n\n\
                 [Timer]\nOnCalendar=daily\nRandomizedDelaySec=6h\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n";
    if user {
        fs::create_dir_all(timer_file.parent().unwrap()).context("cannot make the user's unit folder")?;
    }
    write_atomic(&service_file, service.as_bytes(), 0o644)?;
    write_atomic(&timer_file, timer.as_bytes(), 0o644)?;
    run(&["daemon-reload"])?;
    run(&["enable", "--now", "cbb-update.timer"])
}

fn cron_timer(on: bool, exe: &Path) -> Result<()> {
    let old = fs::read_to_string(CRON_OPENWRT).unwrap_or_default();
    let mut lines: Vec<String> =
        old.lines().filter(|l| !l.is_empty() && !l.ends_with(CRON_MARK)).map(String::from).collect();
    if on {
        // cron has no random delay: a time of day of this device's own.
        let r = cbb_core::certs::random_bytes::<2>();
        let (hour, minute) = (1 + r[0] % 6, r[1] % 60);
        lines.push(format!("{minute} {hour} * * * {} update -timer {CRON_MARK}", exe.display()));
    }
    let mut out = lines.join("\n");
    if !out.is_empty() {
        out.push('\n');
    }
    fs::create_dir_all("/etc/crontabs").context("cannot make /etc/crontabs")?;
    write_atomic(Path::new(CRON_OPENWRT), out.as_bytes(), 0o600)?;
    if on {
        let _ = Command::new("/etc/init.d/cron").arg("enable").output();
    }
    let o = Command::new("/etc/init.d/cron").arg("restart").output().context("cannot restart cron")?;
    if !o.status.success() {
        return Err(Error::msg(format!("/etc/init.d/cron restart: {}", String::from_utf8_lossy(&o.stderr).trim())));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cbb_core::certs::b64;
    use cbb_core::release::testing::TestKey;
    use std::cell::RefCell;

    const NOW: i64 = 1_800_000_000_000;
    const ARCHIVE: &str = "cbb-linux-test.tar.gz";

    fn key(n: u8) -> TestKey {
        TestKey::new(n)
    }

    fn sign(body: serde_json::Value, k: &TestKey) -> File {
        k.sign(&serde_json::to_vec(&body).unwrap())
    }

    fn write(dir: &Path, name: &str, f: &File) {
        fs::write(dir.join(name), serde_json::to_vec(f).unwrap()).unwrap();
    }

    /// A release of version with an archive, whose cbb is
    /// "cbb VERSION", signed under root 1; prog overrides the hash
    /// release.json lists for it.
    fn publish(dir: &Path, version: &str, seq: u64, prog: Option<&str>) {
        let tree = dir.join("tree");
        let _ = fs::remove_dir_all(&tree);
        fs::create_dir_all(tree.join("cbb/packaging/linux")).unwrap();
        let body = format!("cbb {version}");
        fs::write(tree.join("cbb/cbb"), &body).unwrap();
        fs::write(tree.join("cbb/packaging/linux/install.sh"), "#!/bin/sh\n").unwrap();
        let st =
            Command::new("tar").arg("-czf").arg(dir.join(ARCHIVE)).arg("-C").arg(&tree).arg("cbb").status().unwrap();
        assert!(st.success());
        let data = fs::read(dir.join(ARCHIVE)).unwrap();
        let (root, rel) = (key(1), key(2));
        let at = NOW - 1000;
        let keys = sign(
            serde_json::json!({"v": 1, "type": "keys", "seq": 1, "time_ms": at, "expires_ms": at + 86_400_000,
                "keys": rel.keys("test", "")}),
            &root,
        );
        let r = sign(
            serde_json::json!({"v": 1, "type": "release", "version": version, "channel": CHANNEL, "time_ms": at,
                "files": [{"name": ARCHIVE, "size": data.len(), "sha256": hex(&sha256(&data)),
                    "binaries": [{"name": "cbb/cbb",
                        "sha256": prog.map(String::from).unwrap_or_else(|| hex(&sha256(body.as_bytes())))}]}]}),
            &rel,
        );
        let ch = sign(
            serde_json::json!({"v": 1, "type": "channel", "channel": CHANNEL, "seq": seq, "time_ms": at,
                "expires_ms": at + 86_400_000, "release": version, "release_sha256": hex(&r.hash())}),
            &rel,
        );
        write(dir, "keys.json", &keys);
        write(dir, "release.json", &r);
        write(dir, "stable.json", &ch);
    }

    fn base64(b: &[u8]) -> String {
        #[derive(Serialize)]
        struct B<'a>(#[serde(with = "b64")] &'a [u8]);
        serde_json::to_value(B(b)).unwrap().as_str().unwrap().to_string()
    }

    struct Fake {
        running: RefCell<String>,
        installs: RefCell<Vec<String>>,
        /// A version whose service never starts.
        broken: String,
    }

    fn run(dir: &Path, installed: &str, broken: &str, st: &mut State) -> (Result<()>, Vec<String>, String) {
        let work = dir.join("work");
        let program = dir.join("bin/cbb");
        fs::create_dir_all(program.parent().unwrap()).unwrap();
        fs::write(&program, format!("cbb {installed}")).unwrap();
        let fake =
            Fake { running: RefCell::new(installed.into()), installs: RefCell::new(Vec::new()), broken: broken.into() };
        let install = |root: &Path, bin: &Path| -> Result<()> {
            assert!(root.join("packaging/linux/install.sh").exists());
            let v = fs::read_to_string(bin).unwrap().trim_start_matches("cbb ").to_string();
            fake.installs.borrow_mut().push(v.clone());
            *fake.running.borrow_mut() = v;
            Ok(())
        };
        let healthy = |v: &str, _: Duration| -> Result<()> {
            let r = fake.running.borrow().clone();
            if r == v && r != fake.broken { Ok(()) } else { Err(Error::msg("it does not answer")) }
        };
        let u = Updater {
            work,
            roots: key(1).root("root-1"),
            sources: vec![Source::Dir(dir.to_path_buf())],
            installed: installed.into(),
            archive: ARCHIVE.into(),
            programs: vec![program],
            now_ms: NOW,
            install: &install,
            healthy: &healthy,
            log: &|_| {},
            group: None,
        };
        let res = u.check(st).and_then(|f| {
            assert!(f.newer);
            st.seen = f.seen;
            u.apply(f.source, st, &f.release)
        });
        let installs = fake.installs.borrow().clone();
        let running = fake.running.borrow().clone();
        (res, installs, running)
    }

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("cbb-update-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    /// The service in the tests: it holds the release in dir and its
    /// archive, and notes what cbb update hands it.
    struct FakeGroup {
        dir: PathBuf,
        shared: RefCell<Vec<serde_json::Value>>,
        kept: RefCell<Vec<(String, i64)>>,
        want: Vec<String>,
    }

    impl Group for FakeGroup {
        fn share(&self, set: &serde_json::Value) {
            self.shared.borrow_mut().push(set.clone());
        }
        fn held(&self) -> Result<serde_json::Value> {
            let read =
                |n: &str| serde_json::from_slice::<serde_json::Value>(&fs::read(self.dir.join(n)).unwrap()).unwrap();
            Ok(
                serde_json::json!({"keys": read("keys.json"), "channel": read("stable.json"), "release": read("release.json")}),
            )
        }
        fn get(&self, _: &str, _: i64, path: &Path) -> Result<()> {
            fs::copy(self.dir.join(ARCHIVE), path).map(|_| ()).context("no archive")
        }
        fn keep(&self, sha: &str, size: i64, path: &Path) {
            assert_eq!(hex(&sha256(&fs::read(path).unwrap())), sha);
            self.kept.borrow_mut().push((sha.into(), size));
        }
        fn want(&self) -> Vec<String> {
            self.want.clone()
        }
    }

    /// cbb update hands the service the release a server gave and the
    /// archive it installed, downloads for a hub the archives the group
    /// wants, and installs from the group when no server answers.
    #[test]
    fn the_group_passes_it() {
        for servers in [true, false] {
            let dir = tmp(if servers { "group-servers" } else { "group-only" });
            publish(&dir, "0.6.1", 1, None);
            let empty = dir.join("empty");
            fs::create_dir_all(&empty).unwrap();
            let program = dir.join("bin/cbb");
            fs::create_dir_all(program.parent().unwrap()).unwrap();
            fs::write(&program, "cbb 0.6.0").unwrap();
            let g = FakeGroup {
                dir: dir.clone(),
                shared: RefCell::new(Vec::new()),
                kept: RefCell::new(Vec::new()),
                want: vec![ARCHIVE.into(), "cbb-plan9-amd64.tar.gz".into()],
            };
            let installed = RefCell::new(String::new());
            let install = |_: &Path, bin: &Path| -> Result<()> {
                *installed.borrow_mut() = fs::read_to_string(bin).unwrap();
                Ok(())
            };
            let u = Updater {
                work: dir.join("work"),
                roots: key(1).root("root-1"),
                sources: vec![Source::Dir(if servers { dir.clone() } else { empty.clone() })],
                installed: "0.6.0".into(),
                archive: ARCHIVE.into(),
                programs: vec![program],
                now_ms: NOW,
                install: &install,
                healthy: &|_, _| Ok(()),
                log: &|_| {},
                group: Some(&g),
            };
            let mut st = State::default();
            let f = u.check(&st).unwrap();
            assert_eq!(f.source == FROM_GROUP, !servers);
            assert_eq!(g.shared.borrow().len(), usize::from(servers));
            if servers {
                u.archives_for_group(f.source, &f.release);
                assert_eq!(g.kept.borrow().len(), 1, "the archive for the group");
            }
            u.apply(f.source, &mut st, &f.release).unwrap();
            assert_eq!(installed.borrow().as_str(), "cbb 0.6.1");
            let sha = &f.release.files.iter().find(|a| a.name == ARCHIVE).unwrap().sha256;
            assert_eq!(g.kept.borrow().last().map(|k| &k.0), Some(sha), "the archive installed");
            assert!(!dir.join("work").join(ARCHIVE).exists(), "the archive stays after the install");
        }
    }

    #[test]
    fn updates_and_rolls_back() {
        let dir = tmp("ok");
        publish(&dir, "0.6.1", 1, None);
        let mut st = State::default();
        let (res, installs, running) = run(&dir, "0.6.0", "", &mut st);
        assert!(res.is_ok(), "{:?}", res.err().map(|e| e.for_user()));
        assert_eq!((installs, running.as_str()), (vec!["0.6.1".to_string()], "0.6.1"));
        assert_eq!(st.seen.channel_seq, 1);

        let dir = tmp("broken");
        publish(&dir, "0.6.1", 1, None);
        let mut st = State { available: "0.6.1".into(), ..State::default() };
        let (res, installs, running) = run(&dir, "0.6.0", "0.6.1", &mut st);
        let msg = res.unwrap_err().for_user();
        assert!(msg.contains("0.6.0 is back"), "{msg}");
        assert_eq!((installs, running.as_str()), (vec!["0.6.1".to_string(), "0.6.0".to_string()], "0.6.0"));
        assert_eq!((st.failed.clone(), st.available.as_str()), (vec!["0.6.1".to_string()], ""));
    }

    #[test]
    fn refuses() {
        // A program that is not the one release.json lists.
        let dir = tmp("prog");
        publish(&dir, "0.6.1", 1, Some(&"0".repeat(64)));
        let (res, installs, _) = run(&dir, "0.6.0", "", &mut State::default());
        assert!(res.unwrap_err().for_user().contains("does not match release.json"));
        assert!(installs.is_empty());
        // An archive changed after signing.
        let dir = tmp("archive");
        publish(&dir, "0.6.1", 1, None);
        fs::write(dir.join(ARCHIVE), b"not the archive").unwrap();
        let (res, installs, _) = run(&dir, "0.6.0", "", &mut State::default());
        assert!(res.is_err() && installs.is_empty());
        // An older channel file than one seen.
        let dir = tmp("older");
        publish(&dir, "0.6.1", 1, None);
        let mut st = State { seen: Seen { keys_seq: 1, channel_seq: 2, ..Seen::default() }, ..State::default() };
        let (res, installs, _) = run(&dir, "0.6.0", "", &mut st);
        assert!(res.is_err() && installs.is_empty());
        // A signature that fails.
        let dir = tmp("sig");
        publish(&dir, "0.6.1", 1, None);
        let mut data: serde_json::Value = serde_json::from_slice(&fs::read(dir.join("release.json")).unwrap()).unwrap();
        data["sigs"][0]["sig"] = serde_json::Value::String(base64(&[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]));
        fs::write(dir.join("release.json"), serde_json::to_vec(&data).unwrap()).unwrap();
        let (res, installs, _) = run(&dir, "0.6.0", "", &mut State::default());
        assert!(res.is_err() && installs.is_empty());
        // A channel that names something else than a version, refused
        // before the name makes an address.
        let dir = tmp("name");
        publish(&dir, "0.6.1", 1, None);
        let body = serde_json::to_vec(&serde_json::json!({"release": "0.6.1/../x"})).unwrap();
        write(
            &dir,
            &format!("{CHANNEL}.json"),
            &File { body, sigs: vec![cbb_core::release::Sig { alg: 1, key: vec![1], sig: vec![1] }] },
        );
        let (res, installs, _) = run(&dir, "0.6.0", "", &mut State::default());
        assert!(res.unwrap_err().for_user().contains("not a version"));
        assert!(installs.is_empty());
    }

    /// Writes dir's channel file again, naming its release.json, with seq
    /// and expiring at expires_ms.
    fn rechannel(dir: &Path, seq: u64, expires_ms: i64) {
        #[derive(Deserialize)]
        struct In {
            #[serde(with = "b64")]
            body: Vec<u8>,
        }
        let rel: In = serde_json::from_slice(&fs::read(dir.join("release.json")).unwrap()).unwrap();
        let at = NOW - 1000;
        let ch = sign(
            serde_json::json!({"v": 1, "type": "channel", "channel": CHANNEL, "seq": seq, "time_ms": at,
                "expires_ms": expires_ms, "release": "0.6.1", "release_sha256": hex(&sha256(&rel.body))}),
            &key(2),
        );
        write(dir, "stable.json", &ch);
    }

    /// Checks for an update from the sources dirs, in order.
    fn check_from(dirs: &[&Path], st: &State) -> Result<Found> {
        let healthy = |_: &str, _: Duration| Ok(());
        let install = |_: &Path, _: &Path| Ok(());
        let u = Updater {
            work: dirs[0].join("work"),
            roots: key(1).root("root-1"),
            sources: dirs.iter().map(|d| Source::Dir(d.to_path_buf())).collect(),
            installed: "0.6.0".into(),
            archive: ARCHIVE.into(),
            programs: vec![PathBuf::from("/nonexistent")],
            now_ms: NOW,
            install: &install,
            healthy: &healthy,
            log: &|_| {},
            group: None,
        };
        u.check(st)
    }

    /// As in Go, a source whose files are refused for any other reason than
    /// a signature or a rollback leaves the next source to answer; a
    /// signature that fails or a rollback ends the check.
    #[test]
    fn next_source_unless_an_answer() {
        let (first, second) = (tmp("first"), tmp("second"));
        publish(&first, "0.6.1", 1, None);
        publish(&second, "0.6.1", 2, None);
        // An expired channel file on the first: the second answers.
        rechannel(&first, 1, NOW - 1);
        let f = check_from(&[&first, &second], &State::default());
        let f = f.unwrap_or_else(|e| panic!("{}", e.for_user()));
        assert_eq!((f.source, f.seen.channel_seq), (1, 2));
        // A channel file older than one seen on the first: the check ends.
        publish(&first, "0.6.1", 1, None);
        let st = State { seen: Seen { keys_seq: 1, channel_seq: 2, ..Seen::default() }, ..State::default() };
        publish(&second, "0.6.1", 3, None);
        let err = check_from(&[&first, &second], &st).err().expect("a rollback was passed over");
        assert!(err.is_answer() && err.for_log().contains("older"), "{}", err.for_log());
        // A signature that fails on the first: the check ends.
        let mut data: serde_json::Value =
            serde_json::from_slice(&fs::read(first.join("release.json")).unwrap()).unwrap();
        data["sigs"][0]["sig"] = serde_json::Value::String(base64(&[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]));
        fs::write(first.join("release.json"), serde_json::to_vec(&data).unwrap()).unwrap();
        let err = check_from(&[&first, &second], &State::default()).err().expect("a bad signature was passed over");
        assert!(err.is_answer() && err.for_log().contains("signature"), "{}", err.for_log());
    }

    /// A download stops at its limit and leaves no more on the disk.
    #[test]
    fn fetch_is_bounded() {
        let dir = tmp("fetch");
        let path = dir.join("out");
        let child = Command::new("sh")
            .args(["-c", "head -c 100000 /dev/zero"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let err = fetch_with("sh", "test", child, &path, 1000).unwrap_err();
        assert!(err.for_user().contains("larger than 1000"), "{}", err.for_user());
        assert!(!path.exists(), "the part of a refused download stays");
        let child = Command::new("sh")
            .args(["-c", "printf abc"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        fetch_with("sh", "test", child, &path, 1000).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"abc");
        // No more than the limit reaches the disk while the tool goes on:
        // the tool measures the file before it ends.
        let size = dir.join("size");
        let script = format!("head -c 100000 /dev/zero; sleep 1; wc -c < {} > {}", path.display(), size.display());
        let child =
            Command::new("sh").args(["-c", &script]).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        assert!(fetch_with("sh", "test", child, &path, 1000).is_err());
        std::thread::sleep(Duration::from_millis(1500));
        if let Ok(n) = fs::read_to_string(&size) {
            assert!(n.trim().parse::<u64>().unwrap() <= 1001, "{} bytes on the disk", n.trim());
        }
    }

    /// A tool that closes its output and then finishes is not stopped: its
    /// download stands.
    #[test]
    fn fetch_lets_the_tool_finish() {
        let dir = tmp("fetch-finish");
        let path = dir.join("out");
        let child = Command::new("sh")
            .args(["-c", "printf abc; exec 1>&-; sleep 0.5; exit 0"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        fetch_with("sh", "test", child, &path, 1000).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"abc");
    }

    #[test]
    fn no_roots_and_names() {
        let healthy = |_: &str, _: Duration| Ok(());
        let install = |_: &Path, _: &Path| Ok(());
        let u = Updater {
            work: tmp("roots"),
            roots: Vec::new(),
            sources: Vec::new(),
            installed: "0.6.0".into(),
            archive: ARCHIVE.into(),
            programs: vec![PathBuf::from("/nonexistent")],
            now_ms: NOW,
            install: &install,
            healthy: &healthy,
            log: &|_| {},
            group: None,
        };
        assert_eq!(u.check(&State::default()).err().unwrap().for_user(), NO_ROOTS);
        let gh = Source::Http { base: GITHUB.into(), github: true };
        assert_eq!(gh.url("stable.json", ""), format!("{CHANNEL_FILES}/stable.json"));
        assert_eq!(gh.url("keys.json", ""), format!("{CHANNEL_FILES}/keys.json"));
        assert_eq!(gh.url("release.json", ""), format!("{GITHUB}/latest/download/release.json"));
        assert_eq!(gh.url("release.json", "0.6.1"), format!("{GITHUB}/download/v0.6.1/release.json"));
        let m = Source::mirror("https://example.org/cbb/").unwrap();
        assert_eq!(m.url("release.json", "0.6.1"), "https://example.org/cbb/v0.6.1/release.json");
        assert!(Source::mirror("http://example.org").is_err() && Source::mirror("https://x/?a").is_err());
        assert!(archive_name().is_some());
    }

    #[test]
    fn state_and_due() {
        let dir = tmp("state");
        let st = State { auto: Some(true), checked_ms: NOW, failed: vec!["0.6.2".into()], ..State::default() };
        save_state(&dir, &st).unwrap();
        assert_eq!(load_state(&dir).unwrap(), st);
        assert!(!due(&st, NOW + 3_600_000) && due(&st, NOW + CHECK_EVERY_MS));
        assert!(!due(&State::default(), NOW));
        // The full member's file reads the same.
        fs::write(
            dir.join(STATE_FILE),
            br#"{"method":"get","auto":false,"seen":{"keys_seq":3,"channel_seq":7,"version":"0.6.0"}}"#,
        )
        .unwrap();
        let st = load_state(&dir).unwrap();
        assert_eq!((st.method.as_str(), st.auto, st.seen.channel_seq), ("get", Some(false), 7));
    }

    #[test]
    fn roots_from_pem() {
        let dir = tmp("pem");
        fs::write(dir.join("r.pem"), key(1).pem("root-1")).unwrap();
        assert_eq!(read_roots(&dir.join("r.pem")).unwrap(), key(1).root("root-1"));
        fs::write(dir.join("e.pem"), "nothing").unwrap();
        assert!(read_roots(&dir.join("e.pem")).is_err());
        let one = key(1).pem("root-1").replace("Name: root-1\n", "");
        fs::write(dir.join("n.pem"), one).unwrap();
        assert!(read_roots(&dir.join("n.pem")).is_err(), "a root without a name");
        // Two roots, by name, whether roots.pem holds their P-256 halves only
        // or both halves of each.
        let names: std::collections::BTreeSet<_> = release::pinned_roots().into_iter().map(|r| r.name).collect();
        assert_eq!(names.len(), 2, "the pinned roots read");
    }
}
