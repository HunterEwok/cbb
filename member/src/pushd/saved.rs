// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! cbb-push's state file: the secret of the keyed hashes and the tokens'
//! bindings to their send keys, so that a restart keeps them. It holds no
//! token: each binding is filed under the token's keyed hash.
//!
//! The file: `cbb-push state 1\n`, the 32-byte secret, the count as 4 bytes
//! big-endian, then per binding the keyed hash (32), the send key's hash
//! (32), seq (8) and the time it was last used (8), big-endian.

use std::collections::HashMap;
use std::path::Path;

use super::Binding;
use crate::error::{Error, Result};

const MAGIC: &[u8] = b"cbb-push state 1\n";
const ENTRY: usize = 32 + 32 + 8 + 8;

/// The secret and the bindings by the tokens' keyed hashes.
pub(super) type State = ([u8; 32], HashMap<[u8; 32], Binding>);

pub(super) fn write(secret: &[u8; 32], bindings: &HashMap<[u8; 32], Binding>) -> Vec<u8> {
    let mut out = Vec::with_capacity(MAGIC.len() + 36 + bindings.len() * ENTRY);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(secret);
    out.extend_from_slice(&(bindings.len() as u32).to_be_bytes());
    for (tok, b) in bindings {
        out.extend_from_slice(tok);
        out.extend_from_slice(&b.key);
        out.extend_from_slice(&b.seq.to_be_bytes());
        out.extend_from_slice(&b.used_ms.to_be_bytes());
    }
    out
}

pub(super) fn read(bytes: &[u8]) -> Option<State> {
    let rest = bytes.strip_prefix(MAGIC)?;
    let secret: [u8; 32] = rest.get(..32)?.try_into().ok()?;
    let n = u32::from_be_bytes(rest.get(32..36)?.try_into().ok()?) as usize;
    let entries = rest.get(36..)?;
    if entries.len() != n.checked_mul(ENTRY)? {
        return None;
    }
    let mut out = HashMap::with_capacity(n);
    for e in entries.chunks_exact(ENTRY) {
        let tok: [u8; 32] = e[..32].try_into().ok()?;
        let key: [u8; 32] = e[32..64].try_into().ok()?;
        let seq = u64::from_be_bytes(e[64..72].try_into().ok()?);
        let used_ms = u64::from_be_bytes(e[72..80].try_into().ok()?);
        out.insert(tok, Binding { key, seq, used_ms });
    }
    Some((secret, out))
}

/// The secret and the bindings at path; a new secret and none when the
/// file is not there yet. A file that does not read is an error: starting
/// without the bindings would let any member bind a token anew.
pub(super) fn load(path: &Path) -> Result<State> {
    match std::fs::read(path) {
        Ok(b) => read(&b).ok_or_else(|| Error::msg(format!("{} is not cbb-push's state", path.display()))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok((cbb_core::certs::random_bytes(), HashMap::new())),
        Err(e) => Err(Error::with(format!("cannot read {}", path.display()), e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_state_reads_back_and_a_damaged_one_does_not() {
        let mut m = HashMap::new();
        m.insert([1; 32], Binding { key: [2; 32], seq: 3, used_ms: 4 });
        m.insert([5; 32], Binding { key: [6; 32], seq: u64::MAX, used_ms: 7 });
        let b = write(&[9; 32], &m);
        assert_eq!(read(&b), Some(([9; 32], m)));
        assert_eq!(read(&b[..b.len() - 1]), None);
        assert_eq!(read(&b[1..]), None);
        let mut longer = b.clone();
        longer.push(0);
        assert_eq!(read(&longer), None);
        assert_eq!(read(&write(&[0; 32], &HashMap::new())).map(|(_, m)| m.len()), Some(0));
    }
}
