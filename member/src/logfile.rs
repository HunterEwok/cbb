// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The service's log where the system keeps none of its output: on
//! Windows, where the service manager gives it no standard error, and on a
//! Mac, where launchd only appends to a file. Every line starts with the
//! local time, and at MAX_LOG bytes the file moves to its ".1" name and
//! starts again, so a log keeps at most twice that, as in the Go service.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::error::{Context, Result};
use crate::sys;

/// The size at which a log file moves to its ".1" name.
const MAX_LOG: u64 = 1 << 20;

struct Log {
    path: PathBuf,
    file: File,
    size: u64,
}

static LOG: Mutex<Option<Log>> = Mutex::new(None);

/// Opens the log at path for the rest of the process: the service's lines
/// go there from now on, and so does what its children write to standard
/// error.
#[cfg_attr(not(any(windows, target_os = "macos")), allow(dead_code))]
pub fn set(path: &Path) -> Result<()> {
    if let Some(dir) = path.parent() {
        sys::mkdir_private(dir)?;
    }
    let log = open(path)?;
    *LOG.lock().unwrap_or_else(|e| e.into_inner()) = Some(log);
    Ok(())
}

fn open(path: &Path) -> Result<Log> {
    let mut o = OpenOptions::new();
    o.append(true).create(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
    let file = o.open(path).context(format!("cannot open the log {}", path.display()))?;
    let size = file.metadata().map(|m| m.len()).unwrap_or(0);
    sys::set_stderr(&file);
    Ok(Log { path: path.to_path_buf(), file, size })
}

/// Writes one line to the log, after the time; without a log, to standard
/// error. Reports whether a log took it.
pub fn line(s: &str) -> bool {
    let mut guard = LOG.lock().unwrap_or_else(|e| e.into_inner());
    let Some(log) = guard.as_mut() else { return false };
    if log.size >= MAX_LOG {
        let old = PathBuf::from(format!("{}.1", log.path.display()));
        let _ = std::fs::remove_file(&old);
        let _ = std::fs::rename(&log.path, &old);
        match open(&log.path) {
            Ok(l) => *log = l,
            Err(_) => return false,
        }
    }
    let text = stamped(&sys::local_time(), s);
    if log.file.write_all(text.as_bytes()).is_ok() {
        log.size += text.len() as u64;
    }
    true
}

/// The lines of s, each after the time, as "2006-01-02 15:04:05 ".
fn stamped(t: &sys::LocalTime, s: &str) -> String {
    let stamp = format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02} ", t.year, t.month, t.day, t.hour, t.minute, t.second);
    let mut out = String::with_capacity(s.len() + stamp.len() + 1);
    for l in s.lines() {
        out.push_str(&stamp);
        out.push_str(l);
        out.push('\n');
    }
    if out.is_empty() {
        out.push_str(&stamp);
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_line_has_the_time() {
        let t = sys::LocalTime { year: 2026, month: 11, day: 8, hour: 3, minute: 4, second: 5 };
        assert_eq!(stamped(&t, "one\ntwo"), "2026-11-08 03:04:05 one\n2026-11-08 03:04:05 two\n");
        assert_eq!(stamped(&t, ""), "2026-11-08 03:04:05 \n");
        let now = sys::local_time();
        assert!(now.year >= 2026 && (1..=12).contains(&now.month), "{:?}", now.year);
    }
}
