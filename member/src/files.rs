// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Writing state files in one step.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// Writes data to path with the given mode, through a temporary file in the
/// same directory and a rename, so a crash leaves either the old file or the
/// new one. The temporary file has a random name and must be new, so that
/// nothing already at a name it could have, such as a link, is written.
pub fn write_atomic(path: &Path, data: &[u8], mode: u32) -> Result<()> {
    let fail = |e| Error::with(format!("cannot write {}", path.display()), e);
    let dir = path.parent().unwrap_or(Path::new("."));
    let rnd = random_name();
    let tmp = dir.join(format!(".{}.{rnd}.tmp", path.file_name().and_then(|n| n.to_str()).unwrap_or("file")));
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    let mut f = opts.open(&tmp).map_err(fail)?;
    let written = f.write_all(data).and_then(|()| f.sync_all());
    drop(f);
    if let Err(e) = written.and_then(|()| fs::rename(&tmp, path)) {
        let _ = fs::remove_file(&tmp);
        return Err(fail(e));
    }
    if let Ok(d) = fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

/// The path with its links followed, as a program that is not Rust takes
/// it: on Windows without the prefix \\?\ that fs::canonicalize puts
/// before it, which PowerShell's -File and Join-Path refuse. The path
/// itself when it cannot be followed.
pub fn real_path(path: &Path) -> PathBuf {
    let Ok(real) = fs::canonicalize(path) else { return path.to_path_buf() };
    plain(real)
}

/// A Windows path without the prefix \\?\ (\\?\UNC\ as \\), where
/// the rest is a path without it; others as they are.
fn plain(p: PathBuf) -> PathBuf {
    let Some(s) = p.to_str() else { return p };
    if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
        return PathBuf::from(format!(r"\\{rest}"));
    }
    match s.strip_prefix(r"\\?\") {
        Some(rest) if rest.as_bytes().get(1) == Some(&b':') && rest.len() < 260 => PathBuf::from(rest),
        _ => p,
    }
}

/// Sixteen random hex digits for a new file's or folder's name. Without the
/// system's randomness it falls back to the process and the time, which still
/// tells apart the names one process makes.
pub fn random_name() -> String {
    let mut rnd = [0u8; 8];
    if getrandom::fill(&mut rnd).is_err() {
        let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
        rnd = ((t as u64) ^ (u64::from(std::process::id()) << 32)).to_le_bytes();
    }
    rnd.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_paths() {
        assert_eq!(
            plain(PathBuf::from(r"\\?\C:\Program Files\cbb\cbb.exe")),
            PathBuf::from(r"C:\Program Files\cbb\cbb.exe")
        );
        assert_eq!(plain(PathBuf::from(r"\\?\UNC\host\share\cbb.exe")), PathBuf::from(r"\\host\share\cbb.exe"));
        assert_eq!(plain(PathBuf::from("/usr/local/bin/cbb")), PathBuf::from("/usr/local/bin/cbb"));
    }

    #[test]
    fn writes_through_a_new_file() {
        let dir = std::env::temp_dir().join(format!("cbb-files-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.json");
        let other = dir.join("other");
        fs::write(&other, b"keep").unwrap();
        // A link where a temporary file of a fixed name would go.
        #[cfg(unix)]
        std::os::unix::fs::symlink(&other, dir.join(".state.json.tmp")).unwrap();
        write_atomic(&path, b"new", 0o600).unwrap();
        write_atomic(&path, b"newer", 0o600).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"newer");
        assert_eq!(fs::read(&other).unwrap(), b"keep");
        let left: Vec<_> = fs::read_dir(&dir).unwrap().filter_map(|e| e.ok()?.file_name().into_string().ok()).collect();
        assert_eq!(left.len(), 3, "{left:?}");
        fs::remove_dir_all(&dir).unwrap();
    }
}

/// Marks a file received from another device as downloaded, so that the
/// system checks it before it first opens, as Go's mediafile.markDownload:
/// on a Mac the quarantine attribute (Gatekeeper), on Windows the Mark of
/// the Web in the Zone.Identifier stream, zone 3 (SmartScreen, Office's
/// Protected View). Elsewhere nothing; a file system without the attribute
/// or the stream keeps the file unmarked.
pub fn mark_download(path: &Path) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::ffi::OsStrExt;
        let fail = |e| Error::with(format!("cannot mark {} as downloaded", path.display()), e);
        let c = std::ffi::CString::new(path.as_os_str().as_bytes())
            .map_err(|_| Error::msg(format!("{} holds a NUL", path.display())))?;
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
        let value = quarantine_value(now);
        // SAFETY: both strings are NUL-terminated and value is read within
        // its length, all for the call.
        let r = unsafe {
            libc::setxattr(c.as_ptr(), c"com.apple.quarantine".as_ptr(), value.as_ptr().cast(), value.len(), 0, 0)
        };
        if r != 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() != Some(libc::ENOTSUP) {
                return Err(fail(e));
            }
        }
    }
    #[cfg(windows)]
    {
        let mut stream = path.as_os_str().to_owned();
        stream.push(":Zone.Identifier");
        // A file system without streams (FAT) keeps the file unmarked.
        if let Ok(mut f) = fs::File::create(&stream) {
            f.write_all(ZONE_IDENTIFIER.as_bytes())
                .map_err(|e| Error::with(format!("cannot mark {} as downloaded", path.display()), e))?;
        }
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    let _ = path;
    Ok(())
}

/// The quarantine attribute of a file CBB received at `now` (Unix
/// seconds), as Go's: the flags, the time in hexadecimal, the agent.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn quarantine_value(now: u64) -> String {
    format!("0083;{now:x};CBB;")
}

/// The Mark of the Web of a file from another device: the Internet zone.
#[cfg_attr(not(windows), allow(dead_code))]
const ZONE_IDENTIFIER: &str = "[ZoneTransfer]\r\nZoneId=3\r\n";

#[cfg(test)]
mod mark_tests {
    use super::*;

    /// The marks are Go's, byte for byte (internal/mediafile).
    #[test]
    fn marks_as_go() {
        assert_eq!(quarantine_value(0x6543_21ab), "0083;654321ab;CBB;");
        assert_eq!(ZONE_IDENTIFIER, "[ZoneTransfer]\r\nZoneId=3\r\n");
        let dir = std::env::temp_dir().join(format!("cbb-mark-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let f = dir.join("a.txt");
        fs::write(&f, b"x").unwrap();
        mark_download(&f).unwrap();
        #[cfg(target_os = "macos")]
        {
            let out =
                std::process::Command::new("xattr").arg("-p").arg("com.apple.quarantine").arg(&f).output().unwrap();
            assert!(String::from_utf8_lossy(&out.stdout).starts_with("0083;"));
        }
        #[cfg(windows)]
        {
            let mut s = f.as_os_str().to_owned();
            s.push(":Zone.Identifier");
            assert_eq!(fs::read_to_string(s).unwrap(), ZONE_IDENTIFIER);
        }
        fs::remove_dir_all(&dir).unwrap();
    }
}
