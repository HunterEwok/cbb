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
    opened: fn(&File),
}

static LOG: Mutex<Option<Log>> = Mutex::new(None);

/// Opens the log at path for the rest of the process: the service's lines
/// go there from now on, and so does what its children write to standard
/// error.
pub fn set(path: &Path) -> Result<()> {
    if let Some(dir) = path.parent() {
        sys::mkdir_private(dir)?;
    }
    let log = open(path)?;
    *LOG.lock().unwrap_or_else(|e| e.into_inner()) = Some(log);
    Ok(())
}

fn open(path: &Path) -> Result<Log> {
    open_then(path, sys::set_stderr)
}

/// Opens the log at path and hands its file to opened: the service makes
/// each file its standard error, also after a move to ".1".
fn open_then(path: &Path, opened: fn(&File)) -> Result<Log> {
    let mut o = OpenOptions::new();
    o.append(true).create(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
    let file = o.open(path).context(format!("cannot open the log {}", path.display()))?;
    let size = file.metadata().map(|m| m.len()).unwrap_or(0);
    opened(&file);
    Ok(Log { path: path.to_path_buf(), file, size, opened })
}

/// Writes one line to the log, after the time; without a log, to standard
/// error. Reports whether a log took it.
pub fn line(s: &str) -> bool {
    let mut guard = LOG.lock().unwrap_or_else(|e| e.into_inner());
    let Some(log) = guard.as_mut() else { return false };
    log.write(&stamped(&sys::local_time(), s))
}

impl Log {
    /// Writes text, after moving a full log to its ".1" name; false when
    /// the new file does not open.
    fn write(&mut self, text: &str) -> bool {
        if self.size >= MAX_LOG {
            let old = PathBuf::from(format!("{}.1", self.path.display()));
            let _ = std::fs::remove_file(&old);
            let _ = std::fs::rename(&self.path, &old);
            match open_then(&self.path, self.opened) {
                Ok(l) => *self = l,
                Err(_) => return false,
            }
        }
        if self.file.write_all(text.as_bytes()).is_ok() {
            self.size += text.len() as u64;
        }
        true
    }
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

    static OPENED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    /// A full log moves aside and the new one starts empty; each file the
    /// log opens, also after the move, is handed on, as the service makes it
    /// its standard error.
    #[test]
    fn a_full_log_moves_aside() {
        let dir = std::env::temp_dir().join(format!("cbb-log-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("service.log");
        let mut log = open_then(&path, |_| {
            OPENED.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        })
        .unwrap();
        let line = format!("{}\n", "x".repeat(1000));
        while log.size < MAX_LOG {
            assert!(log.write(&line));
        }
        assert!(log.write("after\n"));
        let old = std::fs::metadata(dir.join("service.log.1")).unwrap();
        assert!(old.len() >= MAX_LOG, "the old log holds {}", old.len());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "after\n");
        assert_eq!(OPENED.load(std::sync::atomic::Ordering::SeqCst), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
