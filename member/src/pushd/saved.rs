// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! cbb-push's state: the secret of the keyed hashes and the tokens'
//! bindings, so that a restart keeps them. It holds no token and no
//! address: each binding is filed under the token's keyed hash, with the
//! keyed hash of whoever first paid for it.
//!
//! Two files. The state file is a snapshot, written whole every few
//! seconds when something changed and at a stop:
//! `cbb-push state 2\n`, the 32-byte secret, the change number the snapshot
//! holds as 8 bytes, then entries. Its journal (the same name with `.log`)
//! gets each change to a binding appended, and synced, before the send
//! that made it is answered: `cbb-push log 2\n`, then per change its number
//! (8 bytes), then an entry. A start reads the snapshot and then the
//! journal's changes numbered after it; a change cut off at the end (a
//! crash while writing it) was never answered, and is dropped.
//!
//! An entry: the token's keyed hash (32), the payer's (16), the binding's
//! length (2; 0 when the binding was dropped), the binding. A binding: a
//! byte that is 1 when a key is confirmed, then that key's hash (32); the
//! time of its last send (8); the count of slots (1) and per slot the key's
//! hash (32), the slot (16) and seq (8); the count of open challenges (1)
//! and per challenge the key's hash (32), the challenge (16) and when it
//! was made (8). Numbers big-endian.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use super::binding::{Binding, Pending, Slot};
use super::shares::Payer;
use crate::error::{Error, Result};

const MAGIC: &[u8] = b"cbb-push state 2\n";
const MAGIC_LOG: &[u8] = b"cbb-push log 2\n";

/// The bindings by the tokens' keyed hashes, with their payers.
pub(super) type Bindings = HashMap<[u8; 32], (Binding, Payer)>;

/// What a start reads: the secret, the last change number and the
/// bindings.
#[derive(Debug, PartialEq)]
pub(super) struct Loaded {
    pub secret: [u8; 32],
    pub ver: u64,
    pub bindings: Bindings,
}

pub(super) fn log_path(state: &Path) -> PathBuf {
    let mut p = state.as_os_str().to_owned();
    p.push(".log");
    PathBuf::from(p)
}

fn binding_bytes(b: &Binding) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 32 + 8 + 2 + b.slots.len() * 56 + b.pending.len() * 56);
    match &b.key {
        Some(k) => {
            out.push(1);
            out.extend_from_slice(k);
        }
        None => out.push(0),
    }
    out.extend_from_slice(&b.used_ms.to_be_bytes());
    out.push(b.slots.len() as u8);
    for s in &b.slots {
        out.extend_from_slice(&s.key);
        out.extend_from_slice(&s.slot);
        out.extend_from_slice(&s.seq.to_be_bytes());
    }
    out.push(b.pending.len() as u8);
    for p in &b.pending {
        out.extend_from_slice(&p.key);
        out.extend_from_slice(&p.value);
        out.extend_from_slice(&p.made_ms.to_be_bytes());
    }
    out
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Some(a)
    }
    fn arr<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.take(N)?.try_into().ok()
    }
    fn u64(&mut self) -> Option<u64> {
        self.arr::<8>().map(u64::from_be_bytes)
    }
    fn u8(&mut self) -> Option<u8> {
        self.arr::<1>().map(|b| b[0])
    }
}

fn read_binding(b: &[u8]) -> Option<Binding> {
    let mut r = Reader(b);
    let key = match r.u8()? {
        0 => None,
        1 => Some(r.arr::<32>()?),
        _ => return None,
    };
    let used_ms = r.u64()?;
    let mut slots = Vec::new();
    for _ in 0..r.u8()? {
        slots.push(Slot { key: r.arr()?, slot: r.arr()?, seq: r.u64()? });
    }
    let mut pending = Vec::new();
    for _ in 0..r.u8()? {
        pending.push(Pending { key: r.arr()?, value: r.arr()?, made_ms: r.u64()? });
    }
    if !r.0.is_empty() || slots.len() > super::binding::SLOTS_MAX || pending.len() > super::binding::PENDING_MAX {
        return None;
    }
    Some(Binding { key, slots, pending, used_ms })
}

/// One entry; `b` None when the binding was dropped.
pub(super) fn entry(tok: &[u8; 32], payer: &Payer, b: Option<&Binding>) -> Vec<u8> {
    let body = b.map(binding_bytes).unwrap_or_default();
    let mut out = Vec::with_capacity(50 + body.len());
    out.extend_from_slice(tok);
    out.extend_from_slice(payer);
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(&body);
    out
}

/// Reads one entry: None at a cut-off end, Err for one that does not read.
#[allow(clippy::type_complexity)]
fn read_entry(r: &mut Reader<'_>) -> std::result::Result<Option<([u8; 32], Payer, Option<Binding>)>, ()> {
    let (Some(tok), Some(payer), Some(len)) = (r.arr::<32>(), r.arr::<16>(), r.arr::<2>()) else { return Ok(None) };
    let len = u16::from_be_bytes(len) as usize;
    let Some(body) = r.take(len) else { return Ok(None) };
    if len == 0 {
        return Ok(Some((tok, payer, None)));
    }
    read_binding(body).map(|b| Some((tok, payer, Some(b)))).ok_or(())
}

/// The snapshot's bytes.
pub(super) fn snapshot(secret: &[u8; 32], ver: u64, bindings: &[(&[u8; 32], &Binding, Payer)]) -> Vec<u8> {
    let mut out = Vec::with_capacity(MAGIC.len() + 40 + bindings.len() * 120);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(secret);
    out.extend_from_slice(&ver.to_be_bytes());
    for (tok, b, payer) in bindings {
        out.extend_from_slice(&entry(tok, payer, Some(b)));
    }
    out
}

/// A journal's change: its number, then the entry.
pub(super) fn change(ver: u64, tok: &[u8; 32], payer: &Payer, b: Option<&Binding>) -> Vec<u8> {
    let mut out = ver.to_be_bytes().to_vec();
    out.extend_from_slice(&entry(tok, payer, b));
    out
}

fn read_snapshot(bytes: &[u8]) -> Option<Loaded> {
    let mut r = Reader(bytes.strip_prefix(MAGIC)?);
    let secret = r.arr::<32>()?;
    let ver = r.u64()?;
    let mut bindings = HashMap::new();
    while !r.0.is_empty() {
        let (tok, payer, b) = read_entry(&mut r).ok()??;
        bindings.insert(tok, (b?, payer));
    }
    Some(Loaded { secret, ver, bindings })
}

/// Applies a journal's changes numbered after the snapshot's.
fn replay(l: &mut Loaded, log: &[u8]) -> Option<()> {
    let mut r = Reader(log.strip_prefix(MAGIC_LOG)?);
    while !r.0.is_empty() {
        let Some(ver) = r.u64() else { break };
        match read_entry(&mut r) {
            Err(()) => return None,
            // Cut off while it was written: never answered.
            Ok(None) => break,
            Ok(Some((tok, payer, b))) => {
                if ver <= l.ver {
                    continue;
                }
                l.ver = ver;
                match b {
                    Some(b) => {
                        l.bindings.insert(tok, (b, payer));
                    }
                    None => {
                        l.bindings.remove(&tok);
                    }
                }
            }
        }
    }
    Some(())
}

/// The state at path and its journal. A file that does not read is an
/// error, and so is a missing one unless `new` says this is the first
/// start: without its bindings the service would let any key bind a token
/// anew.
pub(super) fn load(path: &Path, new: bool) -> Result<Loaded> {
    let mut l = match std::fs::read(path) {
        Ok(b) => read_snapshot(&b).ok_or_else(|| Error::msg(format!("{} is not cbb-push's state", path.display())))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && new => {
            Loaded { secret: cbb_core::certs::random_bytes(), ver: 0, bindings: HashMap::new() }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(Error::msg(format!(
                "{} is missing: cbb-push keeps the tokens' bindings there, and without them it does not start; restore it from a backup, or pass -new-state on the very first start only",
                path.display()
            )));
        }
        Err(e) => return Err(Error::with(format!("cannot read {}", path.display()), e)),
    };
    let log = log_path(path);
    match std::fs::read(&log) {
        Ok(b) => {
            replay(&mut l, &b).ok_or_else(|| Error::msg(format!("{} is not cbb-push's journal", log.display())))?
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(Error::with(format!("cannot read {}", log.display()), e)),
    }
    Ok(l)
}

/// The journal, opened to append.
pub(super) struct Journal {
    path: PathBuf,
    file: File,
    len: u64,
}

impl Journal {
    /// Starts the journal anew, holding `tail` (changes made after the
    /// snapshot that was just written).
    pub(super) fn start(state: &Path, tail: &[u8]) -> Result<Journal> {
        let path = log_path(state);
        let mut data = MAGIC_LOG.to_vec();
        data.extend_from_slice(tail);
        crate::files::write_atomic(&path, &data, 0o600)?;
        let file = OpenOptions::new()
            .append(true)
            .open(&path)
            .map_err(|e| Error::with(format!("cannot open {}", path.display()), e))?;
        Ok(Journal { path, file, len: data.len() as u64 })
    }

    /// Appends a change and syncs it.
    pub(super) fn append(&mut self, c: &[u8]) -> Result<()> {
        self.file
            .write_all(c)
            .and_then(|()| self.file.sync_data())
            .map_err(|e| Error::with(format!("cannot write {}", self.path.display()), e))?;
        self.len += c.len() as u64;
        Ok(())
    }

    pub(super) fn len(&self) -> u64 {
        self.len
    }

    /// The changes appended since the journal was `at` long.
    pub(super) fn since(&self, at: u64) -> Result<Vec<u8>> {
        let all =
            std::fs::read(&self.path).map_err(|e| Error::with(format!("cannot read {}", self.path.display()), e))?;
        Ok(all.get(at as usize..).unwrap_or_default().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b(seq: u64, confirmed: bool) -> Binding {
        Binding {
            key: confirmed.then_some([2; 32]),
            slots: vec![Slot { key: [2; 32], slot: [3; 16], seq }],
            pending: vec![Pending { key: [4; 32], value: [5; 16], made_ms: 6 }],
            used_ms: 7,
        }
    }

    #[test]
    fn the_snapshot_and_its_journal_read_back_and_damage_does_not() {
        let dir = std::env::temp_dir().join(format!("cbb-push-saved-{}", cbb_core::certs::random_id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("push.state");
        // Missing: an error unless this is the first start.
        assert!(load(&path, false).unwrap_err().to_string().contains("-new-state"));
        let first = load(&path, true).unwrap();
        assert!(first.bindings.is_empty());

        let (one, two) = (b(1, false), b(u64::MAX, true));
        let snap = snapshot(&[9; 32], 5, &[(&[1; 32], &one, [8; 16]), (&[2; 32], &two, [8; 16])]);
        std::fs::write(&path, &snap).unwrap();
        let mut j = Journal::start(&path, &[]).unwrap();
        // A change older than the snapshot is skipped; later ones apply in
        // order; a drop removes.
        j.append(&change(4, &[3; 32], &[8; 16], Some(&b(9, false)))).unwrap();
        j.append(&change(6, &[1; 32], &[8; 16], Some(&b(2, true)))).unwrap();
        j.append(&change(7, &[2; 32], &[8; 16], None)).unwrap();
        // A change cut off at the end was never answered: dropped.
        let cut = change(8, &[4; 32], &[8; 16], Some(&b(1, false)));
        j.append(&cut[..cut.len() - 3]).unwrap();
        let l = load(&path, false).unwrap();
        assert_eq!(l.secret, [9; 32]);
        assert_eq!(l.ver, 7);
        assert_eq!(l.bindings.len(), 1);
        assert_eq!(l.bindings[&[1; 32]].0, b(2, true));

        // A snapshot cut short, or longer, does not read.
        for bad in [&snap[..snap.len() - 1], &snap[1..]] {
            std::fs::write(&path, bad).unwrap();
            assert!(load(&path, false).is_err());
        }
        let mut longer = snap.clone();
        longer.push(0);
        std::fs::write(&path, &longer).unwrap();
        assert!(load(&path, false).is_err());
        // A journal whose middle does not read is an error, not a cut-off.
        std::fs::write(&path, &snap).unwrap();
        let mut bad = MAGIC_LOG.to_vec();
        let mut c = change(9, &[1; 32], &[8; 16], Some(&b(2, true)));
        c[8 + 48 + 2] = 7;
        bad.extend_from_slice(&c);
        bad.extend_from_slice(&change(10, &[1; 32], &[8; 16], None));
        std::fs::write(log_path(&path), &bad).unwrap();
        assert!(load(&path, false).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
