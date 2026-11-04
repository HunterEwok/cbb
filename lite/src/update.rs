// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! cbb update for the lite member on Linux and OpenWrt, as the full
//! member's internal/update does it (docs/guide/install.md, "Updating"):
//! it checks keys.json, stable.json and release.json against the release
//! roots, downloads the lite member's archive for this device, checks it and
//! the program in it, runs the archive's own installer, and puts the
//! previous program back when the service does not report the new version
//! within a minute. The downloads go through curl, wget or uclient-fetch,
//! whichever the system has, so the lite member carries no HTTPS client of
//! its own; the signatures make the transport untrusted.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use cbb_core::certs::{hex, sha256};
use cbb_core::release::{self, File, Release, Seen};
use serde::{Deserialize, Serialize};

use crate::error::{Context, Error, Result};
use crate::files::write_atomic;

/// The release root keys, SubjectPublicKeyInfos in DER, as Go's
/// release.Roots (internal/release/roots/roots.pem): two YubiKeys.
pub const ROOTS: &[&[u8]] = &[
    &[
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48,
        0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xf6, 0xc2, 0xdf, 0xad, 0xc1, 0x81, 0x8b, 0x6d, 0xd7,
        0xbd, 0xe4, 0x0d, 0xf1, 0xd2, 0xbc, 0x67, 0xe9, 0x5b, 0x12, 0xec, 0x53, 0x2c, 0xe8, 0x27, 0x43, 0xdb, 0x3f,
        0x83, 0x3a, 0x7f, 0x93, 0xbc, 0x71, 0xf3, 0xc2, 0x05, 0xbe, 0x47, 0x4c, 0xbb, 0x2a, 0x0b, 0xd8, 0xae, 0xe3,
        0xd6, 0x77, 0x9c, 0x40, 0x66, 0x0b, 0x9a, 0xad, 0xe2, 0x7e, 0x27, 0xbd, 0xc0, 0x3a, 0xc5, 0xeb, 0xd0, 0x0e,
        0xfc,
    ],
    &[
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48,
        0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xc4, 0x66, 0xc0, 0xab, 0x9e, 0x57, 0x19, 0x78, 0xa9,
        0xdc, 0x3b, 0x6a, 0xea, 0x3b, 0x0c, 0xd9, 0xb3, 0x98, 0x51, 0xea, 0x18, 0x7c, 0x3c, 0x6c, 0x82, 0x05, 0xcb,
        0x8a, 0xc8, 0xf0, 0xa0, 0x24, 0x28, 0x0c, 0xcd, 0xbc, 0xa4, 0x26, 0x24, 0x22, 0x86, 0x40, 0x7d, 0xc8, 0xf0,
        0x47, 0x76, 0x80, 0x18, 0xe0, 0x14, 0x59, 0x95, 0xfe, 0x2f, 0x9d, 0xe8, 0x83, 0xbf, 0xd3, 0x2c, 0xba, 0x67,
        0x7e,
    ],
];
pub const CHANNEL: &str = "stable";
const GITHUB: &str = "https://github.com/HunterEwok/cbb/releases";
pub const MIRROR: &str = "https://dl.cbb.tools";
/// Where GitHub keeps the current keys.json and channel file: the branch
/// channel, since a published release takes no new files and these are
/// signed again while it is current (docs/protocol.md, section 16).
const CHANNEL_FILES: &str = "https://raw.githubusercontent.com/HunterEwok/cbb/channel";
const MAX_MANIFEST: u64 = 1 << 20;
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
/// downloads: on OpenWrt /etc, which survives a sysupgrade, and RAM.
pub fn paths() -> (PathBuf, PathBuf) {
    if crate::rootless::is() {
        let d = crate::rootless::update_dir();
        (d.clone(), d)
    } else if crate::openwrt() {
        (PathBuf::from("/etc/cbb-update"), PathBuf::from("/tmp/cbb-update"))
    } else {
        (PathBuf::from("/var/lib/cbb-update"), PathBuf::from("/var/lib/cbb-update"))
    }
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
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().recursive(true).mode(0o700).create(dir).context(format!("cannot make {}", dir.display()))
}

/// Reports whether a timer should check now.
pub fn due(st: &State, now_ms: i64) -> bool {
    st.auto == Some(true) && now_ms - st.checked_ms >= CHECK_EVERY_MS
}

pub fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

/// The lite member's archive for this device, as the release workflow
/// names it; None for a system it does not build for.
pub fn archive_name() -> Option<String> {
    let arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        // The ARMv6 build runs on ARMv7 too.
        "arm" => "armv6",
        "mips" if cfg!(target_endian = "little") => "mipsle",
        "mips" => "mips",
        _ => return None,
    };
    Some(format!("cbb-lite-linux-{arch}.tar.gz"))
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
    let max_s = max.to_string();
    let time = FETCH_TIME.as_secs().to_string();
    let tools: [(&str, Vec<&str>); 3] = [
        (
            "curl",
            vec![
                "-fsSL",
                "-g",
                "--proto",
                "=https",
                "--proto-redir",
                "=https",
                "--max-filesize",
                &max_s,
                "--max-time",
                &time,
                "-A",
                "cbb",
                url,
            ],
        ),
        ("wget", vec!["-q", "-U", "cbb", "-O", "-", url]),
        ("uclient-fetch", vec!["-q", "-O", "-", url]),
    ];
    for (tool, args) in tools {
        let child =
            Command::new(tool).args(&args).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn();
        match child {
            Err(e) if e.kind() == ErrorKind::NotFound => continue,
            Err(e) => return Err(Error::with(format!("cannot run {tool}"), e)),
            Ok(child) => return fetch_with(tool, url, child, path, max),
        }
    }
    Err(Error::msg("downloading needs curl, wget or uclient-fetch, and this system has none"))
}

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
            // SAFETY: kill has no memory preconditions, and the child is
            // waited for only after this thread is joined, so pid is
            // still its.
            unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
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

/// The release a check found.
pub struct Found {
    pub release: Release,
    /// Above the installed version.
    pub newer: bool,
    /// It did not become healthy here before.
    pub failed: bool,
    pub seen: Seen,
    /// The index of the source it came from, which the archive comes from.
    pub source: usize,
}

pub type Installer<'a> = dyn Fn(&Path, &Path) -> Result<()> + 'a;
pub type Health<'a> = dyn Fn(&str, Duration) -> Result<()> + 'a;

pub struct Updater<'a> {
    pub work: PathBuf,
    pub roots: Vec<Vec<u8>>,
    pub sources: Vec<Source>,
    pub installed: String,
    pub archive: String,
    /// The installed program, which the archive's replaces.
    pub program: PathBuf,
    pub now_ms: i64,
    pub install: &'a Installer<'a>,
    pub healthy: &'a Health<'a>,
    pub log: &'a dyn Fn(&str),
}

impl Updater<'_> {
    /// Fetches and checks the channel's current release from the first
    /// source that answers; a file that does not verify stops it, so that
    /// another server gets no say.
    pub fn check(&self, st: &State) -> Result<Found> {
        if self.roots.is_empty() {
            return Err(Error::msg(NO_ROOTS));
        }
        let roots: Vec<&[u8]> = self.roots.iter().map(Vec::as_slice).collect();
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
            let (r, seen) = match release::check(&keys, &ch, &rel, &roots, CHANNEL, self.now_ms, &st.seen) {
                Ok(v) => v,
                Err(e) if e.is_answer() => return Err(e),
                Err(e) => {
                    errs.push(format!("{src}: {}", e.for_log()));
                    continue;
                }
            };
            return Ok(Found {
                newer: release::compare(&r.version, &self.installed).is_gt(),
                failed: st.failed.contains(&r.version),
                release: r,
                seen,
                source: i,
            });
        }
        Err(Error::msg(format!("no update server answered: {}", errs.join("; "))))
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
            .find(|b| b.name.rsplit('/').next() == Some("cbb"))
            .ok_or_else(|| Error::msg(format!("release.json lists no cbb in {}", asset.name)))?;
        mkdir_private(&self.work)?;
        let new = self.work.join("new");
        let _ = fs::remove_dir_all(&new);
        mkdir_private(&new)?;
        (self.log)(&format!("Downloading {} ({})...", asset.name, r.version));
        let file = self.work.join(&asset.name);
        self.sources[source].fetch_to(&asset.name, &r.version, &file, MAX_ARCHIVE.min(asset.size.max(0) as u64))?;
        let data = fs::read(&file).context("cannot read the downloaded archive")?;
        r.check_file(&asset.name, &data)?;
        drop(data);
        // The archive's hash is the signed one, so its names are the
        // project's; tar unpacks it into a folder of its own.
        let out = Command::new("tar").arg("-xzf").arg(&file).arg("-C").arg(&new).output().context("cannot run tar")?;
        let _ = fs::remove_file(&file);
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
        let prev = self.work.join("previous");
        let _ = fs::remove_dir_all(&prev);
        mkdir_private(&prev)?;
        let saved = prev.join("cbb");
        fs::copy(&self.program, &saved).context(format!("cannot keep a copy of {}", self.program.display()))?;

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

/// Puts p before an error's message, keeping the error as the cause, which
/// -debug shows.
pub fn prefixed(e: Error, p: &str) -> Error {
    let m = format!("{p}: {}", e.message());
    e.context(m)
}

/// Runs the installer of an unpacked archive on bin, as an update: it asks
/// nothing and keeps the settings.
pub fn install(root: &Path, bin: &Path) -> Result<()> {
    let script = if crate::openwrt() { "packaging/openwrt/install.sh" } else { "packaging/linux/install.sh" };
    let mut cmd = Command::new("sh");
    cmd.arg(root.join(script));
    if crate::rootless::is() {
        cmd.arg("--rootless");
    }
    let out = cmd.arg(bin).env("CBB_UPDATING", "1").output().context("cannot run install.sh")?;
    if out.status.success() {
        return Ok(());
    }
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    Err(Error::msg(format!("install.sh failed: {}", failure(&text))))
}

/// The installer's own line about what failed, or its last lines.
fn failure(out: &str) -> String {
    let lines: Vec<&str> = out.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    if let Some(l) = lines.iter().rev().find(|l| l.starts_with("install.sh: ")) {
        return l.trim_start_matches("install.sh: ").to_string();
    }
    lines[lines.len().saturating_sub(3)..].join(" / ")
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
pub fn release_roots() -> Vec<Vec<u8>> {
    if let Some(f) = std::env::var_os("CBB_RELEASE_ROOTS")
        && let Ok(r) = read_roots(Path::new(&f))
    {
        return r;
    }
    ROOTS.iter().map(|r| r.to_vec()).collect()
}

/// Reads the public keys of a PEM file, for tests (CBB_RELEASE_ROOTS).
pub fn read_roots(path: &Path) -> Result<Vec<Vec<u8>>> {
    #[derive(Deserialize)]
    struct Der(#[serde(with = "cbb_core::certs::b64")] Vec<u8>);
    let text = fs::read_to_string(path).context(format!("cannot read {}", path.display()))?;
    let mut roots = Vec::new();
    let mut body: Option<String> = None;
    for line in text.lines().map(str::trim) {
        match line {
            "-----BEGIN PUBLIC KEY-----" => body = Some(String::new()),
            "-----END PUBLIC KEY-----" => {
                if let Some(b) = body.take() {
                    let Der(der) = serde_json::from_str(&format!("\"{b}\"")).context("a PUBLIC KEY is not base64")?;
                    roots.push(der);
                }
            }
            l => {
                if let Some(b) = body.as_mut() {
                    b.push_str(l);
                }
            }
        }
    }
    if roots.is_empty() {
        return Err(Error::msg(format!("{} holds no PUBLIC KEY", path.display())));
    }
    Ok(roots)
}

const SYSTEMD_SERVICE: &str = "/etc/systemd/system/cbb-update.service";
const SYSTEMD_TIMER: &str = "/etc/systemd/system/cbb-update.timer";
const CRON_OPENWRT: &str = "/etc/crontabs/root";
const CRON_MARK: &str = "# cbb-update";

/// Adds the daily timer that runs exe update -timer, or removes it: a
/// systemd timer, or cron on OpenWrt, as the full member's.
pub fn set_timer(on: bool, exe: &Path) -> Result<()> {
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
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{Signature, SigningKey};
    use p256::pkcs8::EncodePublicKey;
    use std::cell::RefCell;

    const NOW: i64 = 1_800_000_000_000;
    const ARCHIVE: &str = "cbb-lite-linux-test.tar.gz";

    fn key(n: u8) -> SigningKey {
        SigningKey::from_slice(&[n; 32]).unwrap()
    }

    fn spki(k: &SigningKey) -> Vec<u8> {
        k.verifying_key().to_public_key_der().unwrap().as_bytes().to_vec()
    }

    fn sign(body: serde_json::Value, k: &SigningKey) -> File {
        let body = serde_json::to_vec(&body).unwrap();
        let sig: Signature = k.sign(&body);
        File { body, sig: sig.to_der().as_bytes().to_vec(), key: sha256(&spki(k)).to_vec() }
    }

    fn write(dir: &Path, name: &str, f: &File) {
        #[derive(Serialize)]
        struct Out<'a> {
            #[serde(with = "b64")]
            body: &'a [u8],
            #[serde(with = "b64")]
            sig: &'a [u8],
            #[serde(with = "b64")]
            key: &'a [u8],
        }
        let data = serde_json::to_vec(&Out { body: &f.body, sig: &f.sig, key: &f.key }).unwrap();
        fs::write(dir.join(name), data).unwrap();
    }

    /// A release of version with the lite member's archive, whose cbb is
    /// "cbb VERSION", signed under root 1; prog overrides the hash
    /// release.json lists for it.
    fn publish(dir: &Path, version: &str, seq: u64, prog: Option<&str>) {
        let tree = dir.join("tree");
        let _ = fs::remove_dir_all(&tree);
        fs::create_dir_all(tree.join("cbb-lite/packaging/linux")).unwrap();
        let body = format!("cbb {version}");
        fs::write(tree.join("cbb-lite/cbb"), &body).unwrap();
        fs::write(tree.join("cbb-lite/packaging/linux/install.sh"), "#!/bin/sh\n").unwrap();
        let st = Command::new("tar")
            .arg("-czf")
            .arg(dir.join(ARCHIVE))
            .arg("-C")
            .arg(&tree)
            .arg("cbb-lite")
            .status()
            .unwrap();
        assert!(st.success());
        let data = fs::read(dir.join(ARCHIVE)).unwrap();
        let (root, rel) = (key(1), key(2));
        let at = NOW - 1000;
        let keys = sign(
            serde_json::json!({"v": 1, "type": "keys", "seq": 1, "time_ms": at, "expires_ms": at + 86_400_000,
                "keys": [{"key": base64(&spki(&rel)), "name": "test"}]}),
            &root,
        );
        let r = sign(
            serde_json::json!({"v": 1, "type": "release", "version": version, "channel": CHANNEL, "time_ms": at,
                "files": [{"name": ARCHIVE, "size": data.len(), "sha256": hex(&sha256(&data)),
                    "binaries": [{"name": "cbb-lite/cbb",
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
            roots: vec![spki(&key(1))],
            sources: vec![Source::Dir(dir.to_path_buf())],
            installed: installed.into(),
            archive: ARCHIVE.into(),
            program,
            now_ms: NOW,
            install: &install,
            healthy: &healthy,
            log: &|_| {},
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
        data["sig"] = serde_json::Value::String(base64(&[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]));
        fs::write(dir.join("release.json"), serde_json::to_vec(&data).unwrap()).unwrap();
        let (res, installs, _) = run(&dir, "0.6.0", "", &mut State::default());
        assert!(res.is_err() && installs.is_empty());
        // A channel that names something else than a version, refused
        // before the name makes an address.
        let dir = tmp("name");
        publish(&dir, "0.6.1", 1, None);
        let body = serde_json::to_vec(&serde_json::json!({"release": "0.6.1/../x"})).unwrap();
        write(&dir, &format!("{CHANNEL}.json"), &File { body, sig: vec![1], key: vec![1] });
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
            roots: vec![spki(&key(1))],
            sources: dirs.iter().map(|d| Source::Dir(d.to_path_buf())).collect(),
            installed: "0.6.0".into(),
            archive: ARCHIVE.into(),
            program: PathBuf::from("/nonexistent"),
            now_ms: NOW,
            install: &install,
            healthy: &healthy,
            log: &|_| {},
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
        data["sig"] = serde_json::Value::String(base64(&[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]));
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
            program: PathBuf::from("/nonexistent"),
            now_ms: NOW,
            install: &install,
            healthy: &healthy,
            log: &|_| {},
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
        assert_eq!(failure("a\ninstall.sh: copying failed: no space\nmore\n"), "copying failed: no space");
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
        let der = spki(&key(1));
        let pem = format!("-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n", base64(&der));
        fs::write(dir.join("r.pem"), pem).unwrap();
        assert_eq!(read_roots(&dir.join("r.pem")).unwrap(), vec![der]);
        fs::write(dir.join("e.pem"), "nothing").unwrap();
        assert!(read_roots(&dir.join("e.pem")).is_err());
    }
}
