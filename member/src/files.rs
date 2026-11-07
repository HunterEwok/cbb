// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Writing state files in one step.

use std::fs;
use std::io::Write;
use std::path::Path;

use crate::error::{Error, Result};

/// Writes data to path with the given mode, through a temporary file in the
/// same directory and a rename, so a crash leaves either the old file or the
/// new one. The temporary file has a random name and must be new, so that
/// nothing already at a name it could have, such as a link, is written.
pub fn write_atomic(path: &Path, data: &[u8], mode: u32) -> Result<()> {
    let fail = |e| Error::with(format!("cannot write {}", path.display()), e);
    let dir = path.parent().unwrap_or(Path::new("."));
    let mut rnd = [0u8; 8];
    getrandom::fill(&mut rnd).map_err(|_| Error::msg("cannot write a file: the system has no randomness"))?;
    let rnd: String = rnd.iter().map(|b| format!("{b:02x}")).collect();
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

#[cfg(test)]
mod tests {
    use super::*;

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
