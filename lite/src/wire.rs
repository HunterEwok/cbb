// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The frames of the member protocol over a stream (cbb_core::wire has the
//! messages).

use std::io::Read;

pub use cbb_core::wire::*;

use crate::error::{Context, Error, Result};

/// Reads one frame of at most max bytes and returns its JSON.
pub fn read_frame(r: &mut (impl Read + ?Sized), max: usize) -> Result<Vec<u8>> {
    let mut n = [0u8; 4];
    r.read_exact(&mut n).context("the connection broke")?;
    let size = frame_len(n, max)?;
    // Read the body as it arrives rather than trusting the length.
    let mut data = Vec::new();
    r.take(size as u64).read_to_end(&mut data).context("the connection broke")?;
    if data.len() != size {
        return Err(Error::msg("the connection broke in the middle of a frame"));
    }
    Ok(data)
}

/// What a chunk's length pads to.
const CHUNK_PAD: usize = 16 << 10;

/// A chunk of a blob as it travels ("Content" in section 4).
#[derive(Debug, Clone, PartialEq)]
pub struct Chunk {
    pub sha256: [u8; 32],
    pub offset: u64,
    pub data: Vec<u8>,
}

/// The chunk frame of c: its length word with the top bit set, the blob's
/// SHA-256, the offset, the data's length and the data, padded with zeros
/// to a multiple of 16 KiB.
pub fn chunk_frame(c: &Chunk) -> Result<Vec<u8>> {
    if c.data.len() > MAX_CHUNK_DATA {
        return Err(Error::msg("a chunk of more than 256 KiB"));
    }
    let body = 32 + 8 + 4 + c.data.len();
    let padded = body.div_ceil(CHUNK_PAD) * CHUNK_PAD;
    let mut f = Vec::with_capacity(4 + padded);
    f.extend_from_slice(&((padded as u32) | 0x8000_0000).to_be_bytes());
    f.extend_from_slice(&c.sha256);
    f.extend_from_slice(&c.offset.to_be_bytes());
    f.extend_from_slice(&(c.data.len() as u32).to_be_bytes());
    f.extend_from_slice(&c.data);
    f.resize(4 + padded, 0);
    Ok(f)
}

/// Reads the body of a chunk frame, what follows its length word.
pub fn decode_chunk(b: &[u8]) -> Result<Chunk> {
    let bad = || Error::msg("a chunk frame that does not decode");
    if b.len() < 44 || b.len() > MAX_CHUNK_FRAME {
        return Err(bad());
    }
    let mut sha256 = [0u8; 32];
    sha256.copy_from_slice(&b[..32]);
    let offset = u64::from_be_bytes(b[32..40].try_into().map_err(|_| bad())?);
    let n = u32::from_be_bytes(b[40..44].try_into().map_err(|_| bad())?) as usize;
    if n > MAX_CHUNK_DATA || 44 + n > b.len() {
        return Err(bad());
    }
    Ok(Chunk { sha256, offset, data: b[44..44 + n].to_vec() })
}
