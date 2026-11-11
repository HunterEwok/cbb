// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Frames (format section 9.1): a 4-byte big-endian length `L`, then `L`
//! bytes of one message, a map in the profile with its type in field 0.
//! `L` is on the grid (64, 256, 1024, 4096, 16384, or a multiple of 16384);
//! a message that is not that long by itself carries zeros in `pad` (field
//! 1), just enough for the smallest grid size it can reach. So every
//! message has one frame, and a frame's size tells only its step.
//!
//! The binary `chunk` frames (length with its top bit set) are not messages
//! and are read before these rules.

use alloc::vec::Vec;

use super::Rule;
use super::cbor::{self, Value, head_len};

/// A message's type.
pub const FIELD_T: u16 = 0;
/// A message's padding.
pub const FIELD_PAD: u16 = 1;

/// The largest frame of the member protocol: 7 MiB, 448 · 16384.
pub const LIMIT_MEMBER: usize = 7 * 1024 * 1024;
/// The largest frame of pairing.
pub const LIMIT_PAIRING: usize = 64 * 1024;
/// The largest frame a leaf takes.
pub const LIMIT_LEAF: usize = 16 * 1024;

/// The grid's steps below the multiples of 16384.
pub const GRID: [usize; 5] = [64, 256, 1024, 4096, 16384];
const STEP: usize = 16384;

/// Reports whether a message of n bytes is on the grid.
pub fn on_grid(n: usize) -> bool {
    GRID.contains(&n) || (n > STEP && n.is_multiple_of(STEP))
}

/// The smallest grid size of at least n.
fn grid_at_least(n: usize) -> Option<usize> {
    if let Some(g) = GRID.iter().find(|g| **g >= n) {
        return Some(*g);
    }
    n.div_ceil(STEP).checked_mul(STEP)
}

/// The length of the zeros a message of `base` bytes and `entries` map
/// entries, without `pad`, needs to reach its grid size, and that size;
/// None when it is on the grid already.
pub fn pad_length(base: usize, entries: usize) -> Option<(usize, usize)> {
    if on_grid(base) {
        return None;
    }
    pad_to(base, entries, grid_at_least)
}

/// The zeros a map of `base` bytes and `entries` entries needs in a `pad`
/// field of key 1 so that its encoding is exactly a size that `at_least`
/// gives (the smallest allowed size of at least its argument), and that
/// size. A size the map cannot reach exactly (its padding's head grows past
/// it) is skipped for the next.
pub fn pad_to(base: usize, entries: usize, at_least: fn(usize) -> Option<usize>) -> Option<(usize, usize)> {
    // Adding `pad` adds one entry (perhaps a longer map head), the key 1 in
    // one byte, the bytes' head and the zeros.
    let grow = head_len(entries.saturating_add(1) as u64).saturating_sub(head_len(entries as u64));
    let fixed = base.saturating_add(grow).saturating_add(1);
    let mut target = at_least(fixed.saturating_add(1))?;
    loop {
        for hl in [1usize, 2, 3, 5, 9] {
            if let Some(plen) = target.checked_sub(fixed).and_then(|r| r.checked_sub(hl))
                && head_len(plen as u64) == hl
            {
                return Some((plen, target));
            }
        }
        target = at_least(target.saturating_add(1))?;
    }
}

/// Checks that a map's `pad` (field 1), if any, is zeros and the one
/// padding that pad_length (for frames) or pad_to gives; `size` is the
/// map's encoding's length, `pad` the zeros and `entries` the entries
/// counting `pad`. Returns false on a broken rule.
pub fn pad_is_exact(
    size: usize,
    zeros: &[u8],
    entries: usize,
    fits: fn(usize, usize) -> Option<(usize, usize)>,
) -> bool {
    if zeros.iter().any(|z| *z != 0) {
        return false;
    }
    let rest = entries.saturating_sub(1);
    let shrink = head_len(entries as u64).saturating_sub(head_len(rest as u64));
    let taken = head_len(zeros.len() as u64).saturating_add(zeros.len()).saturating_add(shrink).saturating_add(1);
    let Some(base) = size.checked_sub(taken) else {
        return false;
    };
    matches!(fits(base, rest), Some((plen, total)) if plen == zeros.len() && total == size)
}

/// A message read from a frame.
#[derive(Clone, Debug)]
pub struct Message<'a> {
    /// The message type (field 0).
    pub t: u64,
    /// The whole message, padding included.
    pub map: Value<'a>,
}

impl<'a> Message<'a> {
    /// A field of the message.
    pub fn get(&self, key: u16) -> Option<&Value<'a>> {
        self.map.get(key)
    }
}

/// Reads the 4-byte length of a frame and checks it against the grid and
/// limit: the length of the message that follows.
pub fn length(header: [u8; 4], limit: usize) -> Result<usize, Rule> {
    let n = usize::try_from(u32::from_be_bytes(header)).map_err(|_| Rule::FRAME_GRID)?;
    if n == 0 || n > limit || !on_grid(n) {
        return Err(Rule::FRAME_GRID);
    }
    Ok(n)
}

/// Reads exactly one frame: its length, then the message, padded as the
/// one form of section 9.1 has it.
pub fn read(frame: &[u8], limit: usize) -> Result<Message<'_>, Rule> {
    let (Some(head), Some(body)) = (frame.get(..4), frame.get(4..)) else {
        return Err(Rule::TRUNCATED);
    };
    let mut h = [0u8; 4];
    h.copy_from_slice(head);
    let n = length(h, limit)?;
    match body.len().cmp(&n) {
        core::cmp::Ordering::Less => return Err(Rule::TRUNCATED),
        core::cmp::Ordering::Greater => return Err(Rule::TRAILING),
        core::cmp::Ordering::Equal => {}
    }
    message(body)
}

/// Reads a message of a frame whose length was already checked.
pub fn message(b: &[u8]) -> Result<Message<'_>, Rule> {
    let map = cbor::decode(b)?;
    let entries = map.as_map().ok_or(Rule::FRAME_MESSAGE)?;
    let t = map.get(FIELD_T).and_then(Value::as_uint).ok_or(Rule::FRAME_MESSAGE)?;
    if let Some(pad) = map.get(FIELD_PAD) {
        let zeros = pad.as_bytes().ok_or(Rule::FRAME_PAD)?;
        if !pad_is_exact(b.len(), zeros, entries.len(), pad_length) {
            return Err(Rule::FRAME_PAD);
        }
    }
    Ok(Message { t, map })
}

/// Pads a message (a map with field 0 and without field 1) to the grid and
/// writes its frame.
pub fn write(msg: &Value<'_>) -> Vec<u8> {
    let entries: Vec<(u16, Value<'_>)> =
        msg.as_map().unwrap_or(&[]).iter().filter(|(k, _)| *k != FIELD_PAD).cloned().collect();
    let base = Value::Map(entries.clone()).encode();
    let mut out = Vec::new();
    let body = match pad_length(base.len(), entries.len()) {
        None => base,
        Some((plen, _)) => {
            let zeros = alloc::vec![0u8; plen];
            let mut all = entries;
            all.push((FIELD_PAD, Value::Bytes(&zeros)));
            Value::Map(all).encode()
        }
    };
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    out
}
