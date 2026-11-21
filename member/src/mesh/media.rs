// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Copies with images or files on the member connection of 0.6: the
//! origin seals the parts' bytes into a blob under the copy's blob key and
//! keeps it; a reader fetches the sealed blob from a member that holds it,
//! a range at a time (`get`, answered by binary chunk frames or `missing`),
//! checks it whole against the header's size and SHA-256 and opens it.
//! Members fetch, keep and serve only sealed blobs, and the archives of
//! the signed release they hold (docs/protocol.md, section 16, "In the
//! group"), which the same `get` names by their SHA-256.

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::Duration;

use cbb_core::content::Content;
use cbb_core::copies;
use cbb_core::format::cbor::Value;
use cbb_core::format::copy::blob_key;
use cbb_core::format::frame;
use cbb_core::media::{Manifest, Part};
use cbb_core::msg::member as m;
use cbb_core::records::DeviceId;

use super::{Conn, Mesh, hex};
use crate::content::{BlobKey, Source};
use crate::error::{Context, Error, Result};
use crate::sealed::{self, Blob, SealedBlob};
use crate::wire::{self, Chunk};

/// How much one `get` asks for: the most a get may.
const FETCH_AHEAD: u64 = 1 << 20;
/// How long a fetch waits for the next chunk.
const CHUNK_WAIT: Duration = Duration::from_secs(15);

/// What a fetch hears of its blob.
pub(super) enum Got {
    Chunk(Chunk),
    Missing,
}

/// A copy with images or files this member sealed: its manifest, its
/// blob (none when it has no bytes), which this member keeps and opens,
/// and whether it went to the group (false: not to be sent, or the group
/// has no reader for it).
#[derive(Clone, Debug)]
pub struct SentMedia {
    pub manifest: Manifest,
    pub blob: Option<Blob>,
    pub sent: bool,
    /// The copy's ID, once it went to the group.
    pub id: Option<[u8; 16]>,
}

/// A frame as it arrives: a message, or a chunk of a blob.
pub(super) enum In {
    Msg(Vec<u8>),
    Chunk(Chunk),
}

/// Reads one frame of the member protocol, or a chunk frame, whose length
/// word has its top bit set.
pub(super) fn read_any(r: &mut impl Read) -> Result<In> {
    let mut head = [0u8; 4];
    r.read_exact(&mut head).map_err(|e| Error::with("cannot read a frame", e))?;
    if head[0] & 0x80 != 0 {
        let n = (u32::from_be_bytes(head) & 0x7fff_ffff) as usize;
        if n > wire::MAX_CHUNK_FRAME {
            return Err(Error::msg("a chunk frame is too large"));
        }
        let mut b = vec![0u8; n];
        r.read_exact(&mut b).map_err(|e| Error::with("the connection broke in the middle of a chunk", e))?;
        return Ok(In::Chunk(wire::decode_chunk(&b)?));
    }
    let n = frame::length(head, frame::LIMIT_MEMBER).map_err(|rule| Error::msg(format!("a frame breaks {rule}")))?;
    let mut body = vec![0u8; n];
    r.read_exact(&mut body).map_err(|e| Error::with("cannot read a frame", e))?;
    frame::message(&body).map_err(|rule| Error::msg(format!("a frame breaks {rule}")))?;
    Ok(In::Msg(body))
}

/// Message `get` (t 13) or `missing` (t 14): a range of the blob `sum`;
/// no length cancels a get.
fn range(t: u64, sum: &[u8; 32], offset: u64, length: u64) -> Vec<u8> {
    let mut f = vec![(frame::FIELD_T, Value::Uint(t)), (2, Value::Bytes(sum))];
    if offset != 0 {
        f.push((3, Value::Uint(offset)));
    }
    if length != 0 {
        f.push((4, Value::Uint(length)));
    }
    frame::write(&Value::Map(f))
}

/// A get's or a missing's blob, offset and length.
fn read_range(msg: &[u8]) -> Option<([u8; 32], u64, u64)> {
    let (_, v, _) = cbb_core::msg::read_noted(msg).ok()?;
    let sum = v.get(2)?.as_bytes()?.try_into().ok()?;
    let at = |n| v.get(n).and_then(Value::as_uint).unwrap_or(0);
    Some((sum, at(3), at(4)))
}

/// Takes a fetch's place in the map while it runs.
struct Fetching<'a> {
    mesh: &'a Mesh,
    sum: [u8; 32],
}

impl Drop for Fetching<'_> {
    fn drop(&mut self) {
        self.mesh.fetches.lock().unwrap().remove(&self.sum);
    }
}

impl Mesh {
    /// Seals a copy with images or files: the parts' bytes into a blob
    /// under the copy's blob key, kept to serve, and, when `send`, the copy
    /// to the group. `content` is of type media or files; its manifest is
    /// made from the parts.
    pub fn copy_media(&self, content: &Content, parts: Vec<(Part, Source)>, send: bool) -> Result<SentMedia> {
        let k = copies::new_key()?;
        let key = blob_key(&k);
        let (manifest, blob) = self.content.seal(parts, BlobKey::Blob(&key))?;
        let content = Content { manifest: Some(manifest.clone()), ..content.clone() };
        let blob = match blob {
            Some(b) => Some(SealedBlob {
                k,
                size: u64::try_from(b.size).map_err(|_| Error::msg("the blob's size is not a size"))?,
                sha256: b.sha256.as_slice().try_into().map_err(|_| Error::msg("the blob's hash is not 32 bytes"))?,
            }),
            None => None,
        };
        let held = blob.as_ref().map(|b| Blob { size: b.size, sha256: b.sha256, key });
        let mut out = SentMedia { manifest, blob: held, sent: false, id: None };
        if !send {
            return Ok(out);
        }
        let state = self.state();
        let now = crate::uptime::wall_ms().max(0) as u64;
        let made_time = self.clock.now();
        let made = sealed::make_with(
            &*self.own.member,
            &state,
            &self.statements.lock().unwrap(),
            &content,
            made_time,
            Some(now),
            blob,
        )?;
        let Some((frame, kept)) = made else { return Ok(out) };
        let id = kept.made.id;
        self.see(&id);
        out.id = Some(id);
        self.kept.lock().unwrap().insert(id, kept);
        if !content.is_secret() {
            self.set_current(made_time, id, &frame);
        }
        self.broadcast(&frame, None);
        out.sent = true;
        Ok(out)
    }

    /// Fetches a copy's sealed blob, of at most `max` bytes, from `from`
    /// (the member it came from) or, failing that, any other member
    /// connected, and keeps it once it is whole and checked.
    pub fn fetch(&self, blob: &Blob, from: &DeviceId, max: u64) -> Result<()> {
        if self.content.held(&blob.sha256) == Some(blob.size) {
            return Ok(());
        }
        if blob.size > max {
            return Err(Error::msg(format!("the images or files are larger than this device takes ({max} bytes)")));
        }
        if copies::blob::segments(blob.size).is_none() {
            return Err(Error::msg("the copy's blob has no size a blob has"));
        }
        let (tx, rx) = mpsc::sync_channel(64);
        {
            let mut f = self.fetches.lock().unwrap();
            if f.contains_key(&blob.sha256) {
                return Err(Error::msg("this blob is being fetched already"));
            }
            f.insert(blob.sha256, tx);
        }
        let _place = Fetching { mesh: self, sum: blob.sha256 };
        let mut peers = vec![*from];
        peers.extend(self.connected().into_iter().filter(|p| p != from));
        let mut last = Error::msg("no member that may hold the blob is connected");
        let part = self.content.partial(&blob.sha256);
        for p in peers {
            match self.fetch_from(&p, &blob.sha256, blob.size, &part, &rx) {
                Ok(()) => return self.content.finish(&blob.sha256, blob.size),
                Err(e) => {
                    self.logf(&format!("fetching a blob from {} failed: {}", hex(&p.0[..4]), e.details()));
                    last = e;
                }
            }
        }
        Err(last)
    }

    /// Fetches the blob or archive `sum` of `size` bytes from `peer` into
    /// the partial file `part`, continuing what an earlier fetch left.
    fn fetch_from(
        &self,
        peer: &DeviceId,
        sum: &[u8; 32],
        size: u64,
        part: &Path,
        rx: &mpsc::Receiver<Got>,
    ) -> Result<()> {
        if let Some(dir) = part.parent() {
            fs::create_dir_all(dir).context("make the folder of the copies' content")?;
        }
        let mut f = OpenOptions::new().create(true).append(true).open(part).context("keep the blob being fetched")?;
        // What an earlier fetch left is continued.
        let mut offset = f.metadata().map(|m| m.len()).unwrap_or(0).min(size);
        while offset < size {
            let len = FETCH_AHEAD.min(size - offset);
            if !self.send_to(peer, range(m::T_GET, sum, offset, len)) {
                return Err(Error::msg("the member is not connected"));
            }
            let end = offset + len;
            while offset < end {
                match rx.recv_timeout(CHUNK_WAIT) {
                    Ok(Got::Chunk(c)) if c.offset == offset && !c.data.is_empty() => {
                        let n = (c.data.len() as u64).min(end - offset);
                        f.write_all(&c.data[..n as usize]).context("keep the blob being fetched")?;
                        offset += n;
                    }
                    // Left from a fetch that was cancelled.
                    Ok(Got::Chunk(_)) => {}
                    Ok(Got::Missing) => return Err(Error::msg("the member does not hold the blob")),
                    Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => {
                        let _ = self.send_to(peer, range(m::T_GET, sum, 0, 0));
                        return Err(Error::msg(format!("no chunk came for {} s", CHUNK_WAIT.as_secs())));
                    }
                }
            }
        }
        f.flush().context("keep the blob being fetched")?;
        Ok(())
    }

    /// Fetches the archive of the release held whose SHA-256 is `sha` (in
    /// hex) from a member connected that holds it, for cbb update, and
    /// keeps it once it is whole and matches `release.json`; nothing when
    /// it is held here already.
    pub fn fetch_release_file(&self, sha: &str) -> Result<()> {
        let r = self.releases().ok_or_else(|| Error::msg("this device keeps no release"))?;
        let now = crate::uptime::wall_ms();
        let a = r.file(sha, now).ok_or_else(|| Error::msg("the release this device holds lists no such file"))?;
        if r.held(sha, now).is_some() {
            return Ok(());
        }
        let sum: [u8; 32] = crate::releases::unhex(sha)
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| Error::msg(format!("{sha:?} is not a SHA-256")))?;
        let size = u64::try_from(a.size).map_err(|_| Error::msg("the archive has no size"))?;
        let (tx, rx) = mpsc::sync_channel(64);
        {
            let mut f = self.fetches.lock().unwrap();
            if f.contains_key(&sum) {
                return Err(Error::msg("this archive is being fetched already"));
            }
            f.insert(sum, tx);
        }
        let _place = Fetching { mesh: self, sum };
        let part = r.files_dir()?.join(format!(".part-{sha}"));
        let mut last = Error::msg("no member that serves files is connected");
        let hellos = self.hellos();
        let serving = |p: &DeviceId| hellos.get(p).is_some_and(|h| h.features & crate::hello::FEATURE_MEDIA != 0);
        for p in self.connected().into_iter().filter(serving) {
            let _ = fs::remove_file(&part);
            match self.fetch_from(&p, &sum, size, &part, &rx).and_then(|()| r.keep_file(sha, &part, now)) {
                Ok(()) => {
                    let name = hellos.get(&p).map(|h| h.name.clone()).unwrap_or_default();
                    self.logf(&format!("fetched {} from {name} for cbb update", a.name));
                    return Ok(());
                }
                Err(e) => last = e.context(format!("from {}", hex(&p.0[..4]))),
            }
        }
        let _ = fs::remove_file(&part);
        Err(last)
    }

    /// Opens a copy's blob, held whole, into the new folder `out`: each
    /// part where the manifest puts it, checked against its hash.
    pub fn open_media(&self, blob: Option<&Blob>, manifest: &Manifest, out: &Path) -> Result<Vec<(Part, PathBuf)>> {
        let key = blob.map_or([0; 32], |b| b.key);
        self.content.open_into(blob.map(|b| b.sha256.as_slice()), manifest, BlobKey::Blob(&key), out)
    }

    /// A chunk of a blob from a peer: to the fetch that waits for it.
    pub(super) fn take_chunk(&self, c: Chunk) {
        let tx = self.fetches.lock().unwrap().get(&c.sha256).cloned();
        if let Some(tx) = tx {
            let _ = tx.try_send(Got::Chunk(c));
        }
    }

    /// A peer's `get`: the range in chunk frames when this member holds
    /// the blob whole, `missing` when it does not. A cancel needs nothing:
    /// every range is sent at once.
    pub(super) fn take_get(&self, conn: &Conn, msg: &[u8]) -> Result<()> {
        let Some((sum, offset, length)) = read_range(msg) else { return Ok(()) };
        if length == 0 {
            return Ok(());
        }
        let length = length.min(FETCH_AHEAD);
        // A sealed blob, else an archive of the release held whole.
        let now = crate::uptime::wall_ms();
        let releases = self.releases();
        let blob = self.content.held(&sum);
        // Through the group's tunnel only a blob within this member's
        // limit away from home: a hub's limit caps its whole star.
        if blob.is_some() && conn.tunneled() && !self.content.serves_away(&sum) {
            let _ = conn.tx.try_send(range(m::T_MISSING, &sum, offset, length));
            return Ok(());
        }
        let Some(size) = blob.or_else(|| releases.as_ref()?.held(&crate::releases::hex(&sum), now)) else {
            let _ = conn.tx.try_send(range(m::T_MISSING, &sum, offset, length));
            return Ok(());
        };
        let read = |at: u64, n: usize| match blob {
            Some(_) => self.content.read(&sum, at, n),
            None => releases.as_ref()?.read(&sum, at, n, now),
        };
        let end = offset.saturating_add(length).min(size);
        let mut at = offset;
        while at < end {
            let n = usize::try_from(end - at).unwrap_or(usize::MAX).min(wire::MAX_CHUNK_DATA);
            let Some(data) = read(at, n) else {
                let _ = conn.tx.try_send(range(m::T_MISSING, &sum, at, end - at));
                return Ok(());
            };
            if data.is_empty() {
                break;
            }
            let got = data.len() as u64;
            let f = wire::chunk_frame(&Chunk { sha256: sum, offset: at, data })?;
            // The writer drains the queue; waiting on it holds this reader
            // back rather than dropping a chunk.
            if conn.tx.send(f).is_err() {
                return Err(Error::msg("the connection is closing"));
            }
            at += got;
        }
        Ok(())
    }

    /// A peer's `missing`: the fetch of that blob tries elsewhere.
    pub(super) fn take_missing(&self, msg: &[u8]) {
        let Some((sum, _, _)) = read_range(msg) else { return };
        let tx = self.fetches.lock().unwrap().get(&sum).cloned();
        if let Some(tx) = tx {
            let _ = tx.try_send(Got::Missing);
        }
    }
}
