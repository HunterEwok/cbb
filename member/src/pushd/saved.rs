// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! cbb-push's state: the secret of the keyed hashes and the tokens'
//! bindings, so that a restart keeps them. The secret also makes the
//! challenges (`binding.rs`), so a challenge made before a restart still
//! confirms after it. It holds no token and no address: each binding is
//! filed under the token's keyed hash, with the keyed hash of whoever first
//! paid for it.
//!
//! Two files. The state file is a snapshot, written whole every few
//! seconds when something changed and at a stop:
//! `cbb-push state 3\n`, the 32-byte secret, the change number the snapshot
//! holds as 8 bytes, then entries. Its journal (the same name with `.log`)
//! gets each change to a binding appended, and synced, before the send
//! that made it is answered: `cbb-push log 3\n`, then per change its length
//! (2 bytes, of what follows up to the check), its number (8 bytes), an
//! entry, and a check (the first 8 bytes of SHA-256 of the number and the
//! entry). A start reads the snapshot and then the journal's changes
//! numbered after it. A change cut off at the end (a crash while writing
//! it) was never answered, and is dropped; any other change that does not
//! read or check stops the start, with where it is. An append that fails
//! is cut off again at once, so a later change never follows a torn one.
//!
//! An entry: the token's keyed hash (32), the payer's (16), the binding's
//! length (2; 0 when the binding was dropped), the binding. A binding: a
//! byte that is 1 when a key is confirmed, then that key's hash (32); the
//! generation (4); the time of its last send (8); the count of slots (1)
//! and per slot the key's hash (32), the slot (16) and seq (8). Numbers
//! big-endian.
//!
//! Version 2's files (bindings with open challenges and no generation, a
//! journal without lengths and checks) still read: their challenges are
//! dropped, and the phone gets a new one with its next push.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use super::binding::{Binding, Slot};
use super::shares::Payer;
use crate::error::{Error, Result};

const MAGIC: &[u8] = b"cbb-push state 3\n";
const MAGIC_LOG: &[u8] = b"cbb-push log 3\n";
const MAGIC_2: &[u8] = b"cbb-push state 2\n";
const MAGIC_LOG_2: &[u8] = b"cbb-push log 2\n";
/// Version 2's open challenges per binding at most.
const PENDING_MAX_2: usize = 4;

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
    let mut out = Vec::with_capacity(1 + 32 + 4 + 8 + 1 + b.slots.len() * 56);
    match &b.key {
        Some(k) => {
            out.push(1);
            out.extend_from_slice(k);
        }
        None => out.push(0),
    }
    out.extend_from_slice(&b.generation.to_be_bytes());
    out.extend_from_slice(&b.used_ms.to_be_bytes());
    out.push(b.slots.len() as u8);
    for s in &b.slots {
        out.extend_from_slice(&s.key);
        out.extend_from_slice(&s.slot);
        out.extend_from_slice(&s.seq.to_be_bytes());
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

/// Reads a binding of version 3, or of version 2 when `v2`.
fn read_binding(b: &[u8], v2: bool) -> Option<Binding> {
    let mut r = Reader(b);
    let key = match r.u8()? {
        0 => None,
        1 => Some(r.arr::<32>()?),
        _ => return None,
    };
    let generation = if v2 { 0 } else { u32::from_be_bytes(r.arr()?) };
    let used_ms = r.u64()?;
    let mut slots = Vec::new();
    for _ in 0..r.u8()? {
        slots.push(Slot { key: r.arr()?, slot: r.arr()?, seq: r.u64()? });
    }
    if v2 {
        // Open challenges: dropped.
        let n = r.u8()? as usize;
        if n > PENDING_MAX_2 {
            return None;
        }
        r.take(n * 56)?;
    }
    if !r.0.is_empty() || slots.len() > super::binding::SLOTS_MAX {
        return None;
    }
    Some(Binding { key, generation, slots, used_ms })
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

type Entry = ([u8; 32], Payer, Option<Binding>);

/// Reads one entry: None at a cut-off end, Err for one that does not read.
fn read_entry(r: &mut Reader<'_>, v2: bool) -> std::result::Result<Option<Entry>, ()> {
    let (Some(tok), Some(payer), Some(len)) = (r.arr::<32>(), r.arr::<16>(), r.arr::<2>()) else { return Ok(None) };
    let len = u16::from_be_bytes(len) as usize;
    let Some(body) = r.take(len) else { return Ok(None) };
    if len == 0 {
        return Ok(Some((tok, payer, None)));
    }
    read_binding(body, v2).map(|b| Some((tok, payer, Some(b)))).ok_or(())
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

fn check(numbered: &[u8]) -> [u8; 8] {
    let h = Sha256::digest(numbered);
    let mut out = [0u8; 8];
    out.copy_from_slice(&h[..8]);
    out
}

/// A journal's change: its length, its number and the entry, the check.
pub(super) fn change(ver: u64, tok: &[u8; 32], payer: &Payer, b: Option<&Binding>) -> Vec<u8> {
    let mut numbered = ver.to_be_bytes().to_vec();
    numbered.extend_from_slice(&entry(tok, payer, b));
    let mut out = (numbered.len() as u16).to_be_bytes().to_vec();
    out.extend_from_slice(&numbered);
    out.extend_from_slice(&check(&numbered));
    out
}

fn read_snapshot(bytes: &[u8]) -> Option<Loaded> {
    let (rest, v2) = match bytes.strip_prefix(MAGIC) {
        Some(r) => (r, false),
        None => (bytes.strip_prefix(MAGIC_2)?, true),
    };
    let mut r = Reader(rest);
    let secret = r.arr::<32>()?;
    let ver = r.u64()?;
    let mut bindings = HashMap::new();
    while !r.0.is_empty() {
        let (tok, payer, b) = read_entry(&mut r, v2).ok()??;
        bindings.insert(tok, (b?, payer));
    }
    Some(Loaded { secret, ver, bindings })
}

fn apply(l: &mut Loaded, ver: u64, (tok, payer, b): Entry) {
    if ver <= l.ver {
        return;
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

/// Applies a journal's changes numbered after the snapshot's; the offset
/// of a change that does not read.
fn replay(l: &mut Loaded, log: &[u8]) -> std::result::Result<(), usize> {
    if let Some(rest) = log.strip_prefix(MAGIC_LOG_2) {
        let mut r = Reader(rest);
        while !r.0.is_empty() {
            let at = log.len() - r.0.len();
            let Some(ver) = r.u64() else { break };
            match read_entry(&mut r, true) {
                Err(()) => return Err(at),
                Ok(None) => break,
                Ok(Some(e)) => apply(l, ver, e),
            }
        }
        return Ok(());
    }
    let rest = log.strip_prefix(MAGIC_LOG).ok_or(0usize)?;
    let mut r = Reader(rest);
    while !r.0.is_empty() {
        let at = log.len() - r.0.len();
        let Some(len) = r.arr::<2>().map(u16::from_be_bytes) else { break };
        let (Some(numbered), Some(sum)) = (r.take(len as usize), r.arr::<8>()) else {
            // Cut off while it was written: never answered.
            break;
        };
        if sum != check(numbered) {
            return Err(at);
        }
        let mut n = Reader(numbered);
        let ver = n.u64().ok_or(at)?;
        match read_entry(&mut n, false) {
            Ok(Some(e)) if n.0.is_empty() => apply(l, ver, e),
            _ => return Err(at),
        }
    }
    Ok(())
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
        Ok(b) => replay(&mut l, &b).map_err(|at| {
            Error::msg(format!(
                "{} is not cbb-push's journal: the change at byte {at} does not read; keep a copy, then cut the file there to start with the changes before it",
                log.display()
            ))
        })?,
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
    /// For the tests: an append writes this many bytes, then fails.
    #[cfg(test)]
    pub(super) tear_at: Option<usize>,
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
        Ok(Journal {
            path,
            file,
            len: data.len() as u64,
            #[cfg(test)]
            tear_at: None,
        })
    }

    fn write(&mut self, c: &[u8]) -> std::io::Result<()> {
        #[cfg(test)]
        if let Some(n) = self.tear_at {
            self.file.write_all(&c[..n.min(c.len())])?;
            return Err(std::io::Error::other("torn on purpose"));
        }
        self.file.write_all(c)?;
        self.file.sync_data()
    }

    /// Appends a change and syncs it. When that fails, the file is cut
    /// back to where it was, so the next change does not follow a torn one.
    pub(super) fn append(&mut self, c: &[u8]) -> Result<()> {
        if let Err(e) = self.write(c) {
            let undone = self.file.set_len(self.len).and_then(|()| self.file.sync_data());
            let what = match undone {
                Ok(()) => format!("cannot write {}", self.path.display()),
                Err(_) => format!("cannot write {}, nor cut it back", self.path.display()),
            };
            return Err(Error::with(what, e));
        }
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
        Ok(all.get(at as usize..self.len as usize).unwrap_or_default().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b(seq: u64, confirmed: bool) -> Binding {
        Binding {
            key: confirmed.then_some([2; 32]),
            generation: 3,
            slots: vec![Slot { key: [2; 32], slot: [3; 16], seq }],
            used_ms: 7,
        }
    }

    fn dir() -> PathBuf {
        let d = std::env::temp_dir().join(format!("cbb-push-saved-{}", cbb_core::certs::random_id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn the_snapshot_and_its_journal_read_back_and_damage_does_not() {
        let dir = dir();
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
        std::fs::OpenOptions::new()
            .append(true)
            .open(log_path(&path))
            .unwrap()
            .write_all(&cut[..cut.len() - 3])
            .unwrap();
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
        // A change in the middle that does not check stops the start, and
        // the message says where.
        std::fs::write(&path, &snap).unwrap();
        let mut bad = MAGIC_LOG.to_vec();
        let mut c = change(9, &[1; 32], &[8; 16], Some(&b(2, true)));
        c[2 + 8 + 50] ^= 1;
        bad.extend_from_slice(&c);
        bad.extend_from_slice(&change(10, &[1; 32], &[8; 16], None));
        std::fs::write(log_path(&path), &bad).unwrap();
        let e = load(&path, false).unwrap_err().to_string();
        assert!(e.contains(&format!("byte {}", MAGIC_LOG.len())), "{e}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A write that fails part-way leaves nothing behind it: the changes
    /// after it read back, all of them, and the next journal starts at a
    /// change.
    #[test]
    fn a_write_torn_part_way_is_cut_back() {
        let dir = dir();
        let path = dir.join("push.state");
        std::fs::write(&path, snapshot(&[9; 32], 0, &[])).unwrap();
        for torn in [1usize, 5, 9, 30, 58, 107] {
            let mut j = Journal::start(&path, &[]).unwrap();
            j.append(&change(1, &[1; 32], &[8; 16], Some(&b(1, true)))).unwrap();
            let mark = j.len();
            j.tear_at = Some(torn);
            assert!(j.append(&change(2, &[2; 32], &[8; 16], Some(&b(2, true)))).is_err());
            j.tear_at = None;
            assert_eq!(std::fs::metadata(log_path(&path)).unwrap().len(), mark, "{torn}: cut back");
            j.append(&change(3, &[3; 32], &[8; 16], Some(&b(3, true)))).unwrap();
            j.append(&change(4, &[4; 32], &[8; 16], Some(&b(4, true)))).unwrap();
            let l = load(&path, false).unwrap();
            assert_eq!(l.ver, 4, "{torn}");
            let mut toks: Vec<u8> = l.bindings.keys().map(|k| k[0]).collect();
            toks.sort();
            assert_eq!(toks, [1, 3, 4], "{torn}");
            // What a new journal would start with is whole changes.
            let tail = j.since(mark).unwrap();
            let mut probe = Loaded { secret: [0; 32], ver: 0, bindings: HashMap::new() };
            let mut log = MAGIC_LOG.to_vec();
            log.extend_from_slice(&tail);
            replay(&mut probe, &log).unwrap();
            assert_eq!(probe.bindings.len(), 2, "{torn}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Version 2's files read: open challenges are dropped, never a failed
    /// start.
    #[test]
    fn version_2_reads_and_its_challenges_are_dropped() {
        fn v2_binding(seq: u64, pending: u8) -> Vec<u8> {
            let mut out = vec![1];
            out.extend_from_slice(&[2; 32]);
            out.extend_from_slice(&7u64.to_be_bytes());
            out.push(1);
            out.extend_from_slice(&[2; 32]);
            out.extend_from_slice(&[3; 16]);
            out.extend_from_slice(&seq.to_be_bytes());
            out.push(pending);
            for _ in 0..pending {
                out.extend_from_slice(&[4; 32]);
                out.extend_from_slice(&[5; 16]);
                out.extend_from_slice(&6u64.to_be_bytes());
            }
            out
        }
        fn v2_entry(tok: u8, body: &[u8]) -> Vec<u8> {
            let mut out = vec![tok; 32];
            out.extend_from_slice(&[8; 16]);
            out.extend_from_slice(&(body.len() as u16).to_be_bytes());
            out.extend_from_slice(body);
            out
        }
        let dir = dir();
        let path = dir.join("push.state");
        let mut snap = MAGIC_2.to_vec();
        snap.extend_from_slice(&[9; 32]);
        snap.extend_from_slice(&1u64.to_be_bytes());
        snap.extend_from_slice(&v2_entry(1, &v2_binding(5, 4)));
        std::fs::write(&path, &snap).unwrap();
        let mut log = MAGIC_LOG_2.to_vec();
        log.extend_from_slice(&2u64.to_be_bytes());
        log.extend_from_slice(&v2_entry(2, &v2_binding(6, 2)));
        std::fs::write(log_path(&path), &log).unwrap();
        let l = load(&path, false).unwrap();
        assert_eq!(l.ver, 2);
        let want = Binding {
            key: Some([2; 32]),
            generation: 0,
            slots: vec![Slot { key: [2; 32], slot: [3; 16], seq: 5 }],
            used_ms: 7,
        };
        assert_eq!(l.bindings[&[1; 32]].0, want);
        assert_eq!(l.bindings[&[2; 32]].0.slots[0].seq, 6);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
