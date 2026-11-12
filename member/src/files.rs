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
    #[cfg(test)]
    let cut = faults::take();
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
    #[cfg(test)]
    if let Some(c) = cut {
        return faults::cut(c, f, &tmp, path, data).map_err(fail);
    }
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

/// A file written in pieces that appears at its path only whole: the
/// pieces go to a new temporary file beside it, and [`Atomic::commit`]
/// syncs and renames it; dropped without a commit, as when a download
/// breaks, it removes the temporary file and leaves what was at the path.
/// A crash leaves only the temporary file, which [`sweep`] removes.
pub struct Atomic {
    file: Option<fs::File>,
    tmp: PathBuf,
    path: PathBuf,
}

impl Atomic {
    pub fn create(path: &Path, mode: u32) -> Result<Atomic> {
        let fail = |e| Error::with(format!("cannot write {}", path.display()), e);
        let dir = path.parent().unwrap_or(Path::new("."));
        let tmp =
            dir.join(format!(".{}.{}.tmp", path.file_name().and_then(|n| n.to_str()).unwrap_or("file"), random_name()));
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(mode);
        }
        #[cfg(not(unix))]
        let _ = mode;
        let file = opts.open(&tmp).map_err(fail)?;
        Ok(Atomic { file: Some(file), tmp, path: path.to_path_buf() })
    }

    /// Syncs the file and puts it at its path.
    pub fn commit(mut self) -> Result<()> {
        let fail = |e| Error::with(format!("cannot write {}", self.path.display()), e);
        let Some(f) = self.file.take() else { return Err(Error::msg("the file was committed")) };
        let synced = f.sync_all();
        drop(f);
        synced.and_then(|()| fs::rename(&self.tmp, &self.path)).map_err(fail)?;
        if let Some(d) = self.path.parent().and_then(|d| fs::File::open(d).ok()) {
            let _ = d.sync_all();
        }
        Ok(())
    }
}

impl Write for Atomic {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.file.as_mut().ok_or_else(|| std::io::Error::other("committed"))?.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.as_mut().map_or(Ok(()), Write::flush)
    }
}

impl Drop for Atomic {
    fn drop(&mut self) {
        if self.file.take().is_some() {
            let _ = fs::remove_file(&self.tmp);
        }
    }
}

/// How old a temporary file of write_atomic must be before [`sweep`]
/// removes it: older than any write in progress, by another process too.
const LEFT_OVER: std::time::Duration = std::time::Duration::from_secs(3600);

/// Removes the temporary files that a write cut short by a crash or a
/// power cut left in dir: `.NAME.<16 hex digits>.tmp`, older than an hour.
/// The file a write was for is whole, the old one or the new one; only its
/// temporary file is left. Returns how many it removed.
pub fn sweep(dir: &Path) -> usize {
    let Ok(entries) = fs::read_dir(dir) else { return 0 };
    let mut removed = 0;
    for e in entries.flatten() {
        let name = e.file_name();
        let Some(name) = name.to_str() else { continue };
        if !is_left_over(name) {
            continue;
        }
        let old = e
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
            .is_some_and(|age| age >= LEFT_OVER);
        if old && e.file_type().is_ok_and(|t| t.is_file()) && fs::remove_file(e.path()).is_ok() {
            removed += 1;
        }
    }
    removed
}

/// Whether name is a temporary file's of write_atomic.
fn is_left_over(name: &str) -> bool {
    let Some(rest) = name.strip_prefix('.').and_then(|n| n.strip_suffix(".tmp")) else { return false };
    let Some((file, rnd)) = rest.rsplit_once('.') else { return false };
    !file.is_empty() && rnd.len() == 16 && rnd.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Cuts in write_atomic for the tests of a power cut (docs/testing.md,
/// "Power loss"): the next write on this thread stops at a step, either as
/// a process that dies there (nothing more happens, the temporary file
/// stays) or as an error of the system (write_atomic cleans up as it does).
/// Steps 0 to len: that many bytes of the data written; len + 1: written,
/// not yet synced; len + 2: synced, not yet renamed; len + 3: renamed.
#[cfg(test)]
pub mod faults {
    use std::cell::Cell;
    use std::fs;
    use std::io::Write;
    use std::path::Path;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum How {
        Dies,
        Fails,
    }

    thread_local! {
        static NEXT: Cell<Option<(usize, How)>> = const { Cell::new(None) };
    }

    /// Cuts the next write_atomic on this thread at step.
    pub fn at(step: usize, how: How) {
        NEXT.with(|n| n.set(Some((step, how))));
    }

    pub(super) fn take() -> Option<(usize, How)> {
        NEXT.with(Cell::take)
    }

    pub(super) fn cut(c: (usize, How), mut f: fs::File, tmp: &Path, path: &Path, data: &[u8]) -> std::io::Result<()> {
        let (step, how) = c;
        let stop = || std::io::Error::other(format!("cut at step {step} ({how:?})"));
        let end = |r: std::io::Error| {
            if how == How::Fails {
                let _ = fs::remove_file(tmp);
            }
            Err(r)
        };
        f.write_all(&data[..step.min(data.len())])?;
        if step <= data.len() {
            return end(stop());
        }
        if step == data.len() + 1 {
            return end(stop());
        }
        f.sync_all()?;
        drop(f);
        if step == data.len() + 2 {
            return end(stop());
        }
        fs::rename(tmp, path)?;
        // Renamed: the write is done, whatever comes after.
        Ok(())
    }
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

    /// A write cut at every step, as a process that dies or as an error:
    /// the file is the old one or the new one, never a mix; a leftover
    /// temporary file is swept once old, and the next write succeeds.
    #[test]
    fn a_write_cut_at_every_step_leaves_the_old_file_or_the_new() {
        use faults::How;
        let dir = std::env::temp_dir().join(format!("cbb-cut-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("records.json");
        let (old, new) = (br#"{"v":3,"records":["a"]}"#.to_vec(), br#"{"v":3,"records":["a","b","c"]}"#.to_vec());
        let mut cuts = 0;
        for how in [How::Dies, How::Fails] {
            for step in 0..=new.len() + 3 {
                write_atomic(&path, &old, 0o600).unwrap();
                faults::at(step, how);
                let r = write_atomic(&path, &new, 0o600);
                let got = fs::read(&path).unwrap();
                if step == new.len() + 3 {
                    assert!(r.is_ok());
                    assert_eq!(got, new);
                } else {
                    assert!(r.is_err(), "step {step}");
                    assert_eq!(got, old, "step {step} ({how:?}): the file is torn");
                }
                let left: Vec<String> = fs::read_dir(&dir)
                    .unwrap()
                    .filter_map(|e| e.ok()?.file_name().into_string().ok())
                    .filter(|n| is_left_over(n))
                    .collect();
                match how {
                    How::Fails => assert!(left.is_empty(), "step {step}: {left:?}"),
                    How::Dies if step < new.len() + 3 => assert_eq!(left.len(), 1, "step {step}"),
                    How::Dies => assert!(left.is_empty()),
                }
                // A young leftover may be a write in progress: kept.
                assert_eq!(sweep(&dir), 0);
                for n in &left {
                    let f = fs::File::options().write(true).open(dir.join(n)).unwrap();
                    f.set_modified(std::time::SystemTime::UNIX_EPOCH).unwrap();
                }
                assert_eq!(sweep(&dir), left.len());
                cuts += 1;
            }
        }
        assert!(cuts > 60);
        assert!(path.exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    /// A file written in pieces: a break in the middle leaves the old
    /// file, a crash only a temporary file that is swept, a commit the new.
    #[test]
    fn a_file_in_pieces_appears_only_whole() {
        let dir = std::env::temp_dir().join(format!("cbb-pieces-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cbb.tar.gz");
        fs::write(&path, b"old").unwrap();
        let data: Vec<u8> = (0..=255u8).collect();
        let left = || {
            fs::read_dir(&dir)
                .unwrap()
                .filter_map(|e| e.ok()?.file_name().into_string().ok())
                .filter(|n| is_left_over(n))
                .collect::<Vec<_>>()
        };
        for cut in 0..data.len() {
            // A break: dropped without a commit.
            let mut a = Atomic::create(&path, 0o644).unwrap();
            a.write_all(&data[..cut]).unwrap();
            drop(a);
            assert_eq!(fs::read(&path).unwrap(), b"old");
            assert!(left().is_empty(), "cut {cut}");
        }
        // A crash: the process is gone, its temporary file stays.
        let mut a = Atomic::create(&path, 0o644).unwrap();
        a.write_all(&data[..100]).unwrap();
        std::mem::forget(a);
        assert_eq!(fs::read(&path).unwrap(), b"old");
        let l = left();
        assert_eq!(l.len(), 1);
        fs::File::options()
            .write(true)
            .open(dir.join(&l[0]))
            .unwrap()
            .set_modified(std::time::SystemTime::UNIX_EPOCH)
            .unwrap();
        assert_eq!(sweep(&dir), 1);
        let mut a = Atomic::create(&path, 0o644).unwrap();
        a.write_all(&data).unwrap();
        a.commit().unwrap();
        assert_eq!(fs::read(&path).unwrap(), data);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn only_write_atomic_leftovers_are_swept() {
        assert!(is_left_over(".records.json.0123456789abcdef.tmp"));
        assert!(!is_left_over("records.json"));
        assert!(!is_left_over(".records.json.tmp"));
        assert!(!is_left_over(".records.json.0123456789abcdeg.tmp"));
        assert!(!is_left_over("..0123456789abcdef.tmp"));
    }

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
