// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The sealed blobs of copies with images or files, as a phone's member
//! keeps them (docs/protocol.md, section 4, "The blob" and "Content"): it
//! seals the parts the app hands it into a blob, keeps the blobs it made or
//! fetched whole and checked, serves them to the members that ask, and
//! opens a fetched one into the app's folder, each part checked against
//! its hash in the manifest.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use cbb_core::copy::{self, Blob, KEY_SIZE, SEALED_SEGMENT, SEGMENT};
use cbb_core::media::{self, MAX_MEDIA, Manifest, Part};
use sha2::{Digest, Sha256};

use crate::error::{Context, Error, Result};

/// How many blobs are kept: the group's current copy and a few before it,
/// which a member that reconnects may still fetch.
const KEEP: usize = 8;

/// What a part of a copy the app hands in holds.
pub enum Source {
    /// Clipboard data, such as an image, in memory.
    Bytes(Vec<u8>),
    /// A file on the phone.
    File(PathBuf),
    /// A folder, which holds no bytes.
    Dir,
}

/// The blobs in a folder of the member's state.
pub struct Store {
    dir: PathBuf,
    /// How far the peers read each blob, by its SHA-256: a phone's share
    /// stays until a computer fetched what it shared.
    served: Mutex<HashMap<Vec<u8>, u64>>,
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl Store {
    pub fn open(state_dir: &Path) -> Store {
        Store { dir: state_dir.join("content"), served: Mutex::new(HashMap::new()) }
    }

    fn path(&self, sum: &[u8]) -> PathBuf {
        self.dir.join(hex(sum))
    }

    /// Where a fetch of the blob sum keeps what it has so far.
    pub fn partial(&self, sum: &[u8]) -> PathBuf {
        self.dir.join(format!("{}.part", hex(sum)))
    }

    /// The size of the blob sum when it is held whole and checked; only
    /// those are served.
    pub fn held(&self, sum: &[u8]) -> Option<u64> {
        if sum.len() != 32 {
            return None;
        }
        fs::metadata(self.path(sum)).ok().filter(|m| m.is_file()).map(|m| m.len())
    }

    /// Reads up to len bytes of the blob sum from offset; None when it is
    /// not held or cannot be read.
    pub fn read(&self, sum: &[u8], offset: u64, len: usize) -> Option<Vec<u8>> {
        let size = self.held(sum)?;
        if offset >= size {
            return Some(Vec::new());
        }
        let mut f = File::open(self.path(sum)).ok()?;
        f.seek(SeekFrom::Start(offset)).ok()?;
        let mut out = vec![0u8; len.min((size - offset) as usize)];
        f.read_exact(&mut out).ok()?;
        let end = offset.saturating_add(out.len() as u64);
        let mut served = self.served.lock().unwrap();
        // The member keeps the last eight blobs; a few more are counted.
        if served.len() >= 64 && !served.contains_key(sum) {
            served.clear();
        }
        let at = served.entry(sum.to_vec()).or_insert(0);
        *at = (*at).max(end);
        Some(out)
    }

    /// How far the peers read the blob sum, in bytes.
    pub fn served(&self, sum: &[u8]) -> u64 {
        self.served.lock().unwrap().get(sum).copied().unwrap_or(0)
    }

    /// Keeps the fetched blob in partial as the blob sum, once its size is
    /// size and its SHA-256 is sum; otherwise drops it.
    pub fn finish(&self, sum: &[u8], size: u64) -> Result<()> {
        let part = self.partial(sum);
        let ok = file_sum(&part).ok().is_some_and(|(n, s)| n == size && s.as_slice() == sum);
        if !ok {
            let _ = fs::remove_file(&part);
            return Err(Error::msg("the fetched blob does not match its hash"));
        }
        fs::rename(&part, self.path(sum)).context("keep the fetched blob")?;
        self.prune();
        Ok(())
    }

    /// Seals the parts into a blob under key and keeps it: returns the
    /// manifest, with each part's size and hash, and the blob, None when no
    /// part holds bytes.
    pub fn seal(&self, parts: Vec<(Part, Source)>, key: &[u8; KEY_SIZE]) -> Result<(Manifest, Option<Blob>)> {
        fs::create_dir_all(&self.dir).context("make the folder of the copies' content")?;
        // The parts' sizes and hashes first, so the manifest is whole.
        let mut manifest = Manifest { size: 0, parts: Vec::with_capacity(parts.len()) };
        for (mut p, src) in parts.iter().map(|(p, s)| (p.clone(), s)) {
            match src {
                Source::Dir => {
                    p.dir = true;
                    p.size = 0;
                    p.sha256 = None;
                }
                Source::Bytes(b) => {
                    p.size = b.len() as i64;
                    p.sha256 = Some(Sha256::digest(b).to_vec());
                }
                Source::File(path) => {
                    let (n, s) = file_sum(path)?;
                    p.size = i64::try_from(n).map_err(|_| Error::msg("a file too large"))?;
                    p.sha256 = Some(s.to_vec());
                }
            }
            manifest.size = manifest.size.saturating_add(p.size);
            manifest.parts.push(p);
        }
        if manifest.size > MAX_MEDIA {
            return Err(Error::msg("the images or files are larger than 1 GiB"));
        }
        manifest.validate()?;
        let total = manifest.size as u64;
        if total == 0 {
            return Ok((manifest, None));
        }
        // Then the blob: the parts' bytes one after another, sealed a
        // segment at a time.
        let tmp = self.dir.join(format!("{}.new", hex(&copy::new_key()[..8])));
        let res = (|| -> Result<Blob> {
            let mut out = io::BufWriter::new(File::create(&tmp).context("write the blob")?);
            let segments = total.div_ceil(SEGMENT as u64);
            let mut w =
                Segments { key, out: &mut out, buf: Vec::with_capacity(SEGMENT), i: 0, segments, hash: Sha256::new() };
            for (p, src) in &parts {
                match src {
                    Source::Dir => {}
                    Source::Bytes(b) => w.write(b)?,
                    Source::File(path) => {
                        let mut f = File::open(path).context(format!("read {}", path.display()))?;
                        let mut buf = vec![0u8; 1 << 16];
                        let mut left = manifest_size(&manifest, &p.path, &p.kind);
                        loop {
                            let n = f.read(&mut buf).context("read a file")?;
                            if n == 0 {
                                break;
                            }
                            left = left.saturating_sub(n as u64);
                            w.write(&buf[..n])?;
                        }
                        if left != 0 {
                            return Err(Error::msg(format!("{} changed while it was sealed", path.display())));
                        }
                    }
                }
            }
            let hash = w.finish()?;
            out.flush().context("write the blob")?;
            Ok(Blob { size: copy::blob_size(total) as i64, sha256: hash.to_vec() })
        })();
        let blob = match res {
            Ok(b) => b,
            Err(e) => {
                let _ = fs::remove_file(&tmp);
                return Err(e);
            }
        };
        fs::rename(&tmp, self.path(&blob.sha256)).context("keep the blob")?;
        self.prune();
        Ok((manifest, Some(blob)))
    }

    /// Opens the held blob sum of a copy with manifest under key into the
    /// new folder out: clipboard data as `part-<n>` files, files and folders
    /// at their paths as the receiver writes them. Each part is checked
    /// against its hash; on any error out is removed. Returns each part
    /// with where it is.
    pub fn open_into(
        &self,
        sum: Option<&[u8]>,
        manifest: &Manifest,
        key: &[u8; KEY_SIZE],
        out: &Path,
    ) -> Result<Vec<(Part, PathBuf)>> {
        fs::create_dir(out).context(format!("make {}", out.display()))?;
        let res = self.open_parts(sum, manifest, key, out);
        if res.is_err() {
            let _ = fs::remove_dir_all(out);
        }
        res
    }

    fn open_parts(
        &self,
        sum: Option<&[u8]>,
        manifest: &Manifest,
        key: &[u8; KEY_SIZE],
        out: &Path,
    ) -> Result<Vec<(Part, PathBuf)>> {
        let total = manifest.size.max(0) as u64;
        let mut plain = match (sum, total) {
            (_, 0) => None,
            (Some(sum), _) => {
                let f = File::open(self.path(sum)).context("the copy's blob is not here")?;
                Some(Opened { f, key, i: 0, segments: total.div_ceil(SEGMENT as u64), buf: Vec::new(), at: 0 })
            }
            (None, _) => return Err(Error::msg("the copy has no blob")),
        };
        let mut placed = Vec::with_capacity(manifest.parts.len());
        for (n, p) in manifest.parts.iter().enumerate() {
            let at =
                if p.path.is_empty() { out.join(format!("part-{n}")) } else { out.join(media::save_path(&p.path)) };
            if p.dir {
                fs::create_dir_all(&at).context("make a folder of the copy")?;
                placed.push((p.clone(), at));
                continue;
            }
            if let Some(parent) = at.parent() {
                fs::create_dir_all(parent).context("make a folder of the copy")?;
            }
            // A new file only: the folder is new, so nothing there may be a
            // link to follow.
            let mut f =
                OpenOptions::new().write(true).create_new(true).open(&at).context("write a part of the copy")?;
            let mut h = Sha256::new();
            let mut left = p.size.max(0) as u64;
            while left > 0 {
                let src = plain.as_mut().ok_or_else(|| Error::msg("the copy has no blob"))?;
                let b = src.take(left)?;
                left -= b.len() as u64;
                h.update(&b);
                f.write_all(&b).context("write a part of the copy")?;
            }
            if p.sha256.as_deref() != Some(h.finalize().as_slice()) {
                return Err(Error::msg("a part of the copy does not match its hash"));
            }
            placed.push((p.clone(), at));
        }
        Ok(placed)
    }

    /// Drops all but the KEEP newest blobs, and leftovers of fetches and
    /// seals older than a day.
    fn prune(&self) {
        let Ok(rd) = fs::read_dir(&self.dir) else { return };
        let mut whole = Vec::new();
        for e in rd.flatten() {
            let Ok(m) = e.metadata() else { continue };
            let age = m.modified().ok().and_then(|t| t.elapsed().ok()).unwrap_or_default();
            let name = e.file_name().to_string_lossy().into_owned();
            if name.contains('.') {
                if age.as_secs() > 86_400 {
                    let _ = fs::remove_file(e.path());
                }
            } else {
                whole.push((age, e.path()));
            }
        }
        whole.sort();
        for (_, p) in whole.into_iter().skip(KEEP) {
            let _ = fs::remove_file(p);
        }
    }
}

fn manifest_size(m: &Manifest, path: &str, kind: &str) -> u64 {
    m.parts.iter().find(|p| p.path == path && p.kind == kind).map_or(0, |p| p.size.max(0) as u64)
}

/// A file's size and SHA-256.
fn file_sum(path: &Path) -> Result<(u64, [u8; 32])> {
    let mut f = File::open(path).context(format!("read {}", path.display()))?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    let mut n = 0u64;
    loop {
        let got = f.read(&mut buf).context(format!("read {}", path.display()))?;
        if got == 0 {
            break;
        }
        h.update(&buf[..got]);
        n += got as u64;
    }
    Ok((n, h.finalize().into()))
}

/// Seals plain bytes a segment at a time into out, hashing what it writes.
struct Segments<'a, W: Write> {
    key: &'a [u8; KEY_SIZE],
    out: &'a mut W,
    buf: Vec<u8>,
    i: u64,
    segments: u64,
    hash: Sha256,
}

impl<W: Write> Segments<'_, W> {
    fn write(&mut self, mut b: &[u8]) -> Result<()> {
        while !b.is_empty() {
            let room = SEGMENT - self.buf.len();
            let n = room.min(b.len());
            self.buf.extend_from_slice(&b[..n]);
            b = &b[n..];
            if self.buf.len() == SEGMENT {
                self.flush_segment()?;
            }
        }
        Ok(())
    }

    fn flush_segment(&mut self) -> Result<()> {
        if self.i >= self.segments {
            return Err(Error::msg("the parts hold more bytes than their sizes say"));
        }
        let last = self.i + 1 == self.segments;
        let sealed = copy::seal_segment(self.key, self.i, last, &self.buf)?;
        self.hash.update(&sealed);
        self.out.write_all(&sealed).context("write the blob")?;
        self.buf.clear();
        self.i += 1;
        Ok(())
    }

    fn finish(mut self) -> Result<[u8; 32]> {
        if !self.buf.is_empty() {
            self.flush_segment()?;
        }
        if self.i != self.segments {
            return Err(Error::msg("the parts hold fewer bytes than their sizes say"));
        }
        Ok(self.hash.finalize().into())
    }
}

/// Opens a sealed blob a segment at a time.
struct Opened<'a> {
    f: File,
    key: &'a [u8; KEY_SIZE],
    i: u64,
    segments: u64,
    buf: Vec<u8>,
    at: usize,
}

impl Opened<'_> {
    /// Up to want plain bytes, at least one.
    fn take(&mut self, want: u64) -> Result<Vec<u8>> {
        if self.at == self.buf.len() {
            if self.i >= self.segments {
                return Err(Error::msg("the copy's blob is shorter than its parts"));
            }
            let mut sealed = vec![0u8; SEALED_SEGMENT];
            self.f.read_exact(&mut sealed).context("the copy's blob is cut short")?;
            self.buf = copy::open_segment(self.key, self.i, self.i + 1 == self.segments, &sealed)?;
            self.at = 0;
            self.i += 1;
        }
        let n = (self.buf.len() - self.at).min(usize::try_from(want).unwrap_or(usize::MAX));
        let out = self.buf[self.at..self.at + n].to_vec();
        self.at += n;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use cbb_core::copy::new_key;
    use cbb_core::media::Part;

    use super::{Source, Store};

    #[test]
    fn seals_and_opens_files() {
        let dir = std::env::temp_dir().join(format!("cbb-content-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let big: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        std::fs::write(dir.join("big.bin"), &big).unwrap();
        let store = Store::open(&dir);
        let key = new_key();
        let parts = vec![
            (Part { path: "trip".into(), ..Part::default() }, Source::Dir),
            (Part { path: "trip/big.bin".into(), ..Part::default() }, Source::File(dir.join("big.bin"))),
            (Part { path: "trip/note.txt".into(), ..Part::default() }, Source::Bytes(b"hello".to_vec())),
        ];
        let (m, blob) = store.seal(parts, &key).unwrap();
        let blob = blob.unwrap();
        assert_eq!(m.size, 200_005);
        assert_eq!(blob.size as u64, cbb_core::copy::blob_size(200_005));
        assert_eq!(store.held(&blob.sha256), Some(blob.size as u64));
        let out = dir.join("out");
        let placed = store.open_into(Some(&blob.sha256), &m, &key, &out).unwrap();
        assert_eq!(placed.len(), 3);
        assert_eq!(std::fs::read(out.join("trip/big.bin")).unwrap(), big);
        assert_eq!(std::fs::read(out.join("trip/note.txt")).unwrap(), b"hello");
        // Under another key nothing opens, and the folder is gone.
        assert!(store.open_into(Some(&blob.sha256), &m, &new_key(), &dir.join("bad")).is_err());
        assert!(!dir.join("bad").exists());
        // A range of it reads as served.
        let all = std::fs::read(dir.join("content").join(super::hex(&blob.sha256))).unwrap();
        assert_eq!(store.read(&blob.sha256, 10, 100).unwrap(), all[10..110]);
        // How far the peers read it counts up to the end of each read.
        assert_eq!(store.served(&blob.sha256), 110);
        assert!(store.read(&blob.sha256, 0, all.len() + 10).is_some());
        assert_eq!(store.served(&blob.sha256), all.len() as u64);
        assert_eq!(store.served(&[0u8; 32]), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_image_in_memory() {
        let dir = std::env::temp_dir().join(format!("cbb-content-img-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::open(&dir);
        let key = new_key();
        let png = vec![0x89u8; 70_000];
        let (m, blob) = store
            .seal(vec![(Part { kind: "image/png".into(), ..Part::default() }, Source::Bytes(png.clone()))], &key)
            .unwrap();
        let placed = store.open_into(blob.as_ref().map(|b| b.sha256.as_slice()), &m, &key, &dir.join("o")).unwrap();
        assert_eq!(std::fs::read(&placed[0].1).unwrap(), png);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
