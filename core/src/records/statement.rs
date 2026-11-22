// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The keys statement (format-0.6 section 5): a device's own statement of
//! the key copies are sealed to it with, signed by its member key, which
//! no admin and no root can sign in its place (rule 4).

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use super::Rule;
use super::eval::State;
use super::key::{self, ALG_XWING, DeviceId, GroupId, Key, KeyHash, RecordId, XWING_PUBLIC};
use crate::certs::sha256;
use crate::format::cbor::Value;
use crate::identity::ExternalKey;

/// The label statements are signed under.
pub const LABEL_KEYS: &str = "cbb keys v1";
/// The ceiling on a statement's body: room for the seal keys of later
/// algorithms beside X-Wing's 1216 bytes ([`FIELD_SEALS`]).
pub const MAX_STATEMENT_BODY: usize = 32 << 10;

/// Field 10, `seal`: the X-Wing key every 0.6 sender seals to; a later
/// version keeps writing it there.
pub const FIELD_SEAL: u16 = 10;

/// Field 256, `seals`, in the optional zone: further seal keys of later
/// algorithms, which a 0.6 device skips. A sender seals to the first key it
/// knows of field 10 and then this list.
pub const FIELD_SEALS: u16 = 256;

/// A statement's body.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Body {
    pub group: GroupId,
    /// The key hash of the device's member key.
    pub signer: KeyHash,
    pub epoch: u64,
    pub time_ms: u64,
    pub seal: Key,
    /// A critical field this version does not know: kept and passed on,
    /// not applied.
    pub held: bool,
}

impl Body {
    pub fn check(&self) -> Result<(), Rule> {
        if self.epoch == 0 || self.epoch > i64::MAX as u64 {
            return Err(Rule::field("keys", "epoch"));
        }
        if self.seal.alg() != ALG_XWING || self.seal.public().len() != XWING_PUBLIC {
            return Err(Rule::field("keys", "seal"));
        }
        Ok(())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut m: Vec<(u16, Value<'_>)> = alloc::vec![
            (1, Value::Uint(1)),
            (2, Value::Bytes(&self.group.0)),
            (3, Value::Bytes(&self.signer.0)),
            (4, Value::Uint(self.epoch)),
        ];
        if self.time_ms != 0 {
            m.push((6, Value::Uint(self.time_ms)));
        }
        m.push((FIELD_SEAL, self.seal.to_value()));
        if self.held {
            m.push((250, Value::Uint(1)));
        }
        Value::Map(m).encode()
    }
}

/// A signed statement.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Statement {
    bytes: Vec<u8>,
    sig: Vec<u8>,
    /// A second signature of a later version (its body names `signer2`):
    /// the statement is applied on the first alone, which covers this
    /// one's SHA-256, and passed on with it.
    sig2: Option<Vec<u8>>,
    body: Body,
    id: RecordId,
}

impl Statement {
    /// Signs body with the device's member key.
    pub fn sign(body: Body, key: &dyn ExternalKey) -> crate::error::Result<Statement> {
        body.check().map_err(|r| crate::error::Error::msg(alloc::format!("the statement breaks {r}")))?;
        if body.held || Key::es256(key.public()).hash() != body.signer {
            return Err(crate::error::Error::msg("a statement is signed by its own device's member key"));
        }
        let bytes = body.encode();
        let sig = key::sign_es256(key, LABEL_KEYS, &bytes)?.to_vec();
        Ok(Statement { id: RecordId(sha256(&bytes)), bytes, sig, sig2: None, body })
    }

    /// A statement from what a reader found; the value must encode to the
    /// bytes until the codec reads them itself.
    pub fn from_parts(bytes: Vec<u8>, sig: Vec<u8>, body: Body) -> Result<Statement, Rule> {
        if body.encode() != bytes {
            return Err(Rule::new("cbor/encoding"));
        }
        Ok(Statement { id: RecordId(sha256(&bytes)), bytes, sig, sig2: None, body })
    }

    /// A statement from a reader that checked the bytes itself and found
    /// body in them (`crate::keystore::read_statement`): fields of the
    /// optional zone it skipped stay in the bytes and the signature.
    pub(crate) fn from_read(bytes: Vec<u8>, sig: Vec<u8>, sig2: Option<Vec<u8>>, body: Body) -> Statement {
        Statement { id: RecordId(sha256(&bytes)), bytes, sig, sig2, body }
    }

    pub fn body(&self) -> &Body {
        &self.body
    }

    pub fn id(&self) -> RecordId {
        self.id
    }

    /// The envelope `[body, sig]`, or `[body, sig, sig2]`, as message `keys`
    /// carries it.
    pub fn envelope(&self) -> Vec<u8> {
        crate::format::envelope::write(&self.bytes, &self.sig, self.sig2.as_deref())
    }

    /// Checks the statement against the device's member key.
    pub fn verify(&self, member: &Key) -> Result<(), Rule> {
        if self.bytes.len() > MAX_STATEMENT_BODY {
            return Err(Rule::new("keys/size"));
        }
        self.body.check()?;
        if member.hash() != self.body.signer {
            return Err(Rule::new("sig/verify"));
        }
        match &self.sig2 {
            None => key::verify_es256(member, LABEL_KEYS, &self.bytes, &self.sig),
            // The first signature covers the second's SHA-256: a second
            // signature swapped or cut on the way is a damaged copy.
            Some(s2) => match key::verify_es256(
                member,
                LABEL_KEYS,
                &crate::format::envelope::signed_data(&self.bytes, Some(s2)),
                &self.sig,
            ) {
                Err(r) if r.is("sig/verify") => Err(Rule::new("env/damaged")),
                other => other,
            },
        }
    }
}

/// The statement that counts for a device, and whether another of the
/// same epoch competes with it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Sealing {
    pub statement: Statement,
    pub conflict: bool,
}

/// Of the statements given, the one that counts for each device of the
/// state: of those that verify with the device's member key and are of its
/// group, the highest epoch; of two of one epoch, the smaller ID, with the
/// device shown in conflict. A statement counts only while its device has
/// a counting record; a held one never counts.
pub fn choose<'a>(state: &State, statements: impl IntoIterator<Item = &'a Statement>) -> BTreeMap<DeviceId, Sealing> {
    let mut out: BTreeMap<DeviceId, Sealing> = BTreeMap::new();
    for s in statements {
        let Some(d) = state.device_by_key(&s.body.signer) else { continue };
        if s.body.held || s.body.group != state.group || s.verify(&d.key).is_err() {
            continue;
        }
        match out.get_mut(&d.id) {
            None => {
                out.insert(d.id, Sealing { statement: s.clone(), conflict: false });
            }
            Some(old) => {
                let (e, oe) = (s.body.epoch, old.statement.body.epoch);
                if e > oe {
                    *old = Sealing { statement: s.clone(), conflict: false };
                } else if e == oe && s.id != old.statement.id {
                    if s.id < old.statement.id {
                        old.statement = s.clone();
                    }
                    old.conflict = true;
                }
            }
        }
    }
    out
}

/// The most statements one message `keys` carries (field 2).
pub const KEYS_PER_MESSAGE: usize = 256;

/// Splits statements' envelopes, in the order they are sent, into messages
/// `keys` of at most [`KEYS_PER_MESSAGE`] each that fit a frame: 256
/// statements at their widest (a 32 KiB body and a second signature) are
/// over 10 MiB, more than one frame holds.
pub fn keys_messages<'a>(envelopes: &[&'a [u8]]) -> Vec<Vec<&'a [u8]>> {
    let mut out: Vec<Vec<&'a [u8]>> = Vec::new();
    let mut cur: Vec<&'a [u8]> = Vec::new();
    let mut used = 0usize;
    for &e in envelopes {
        let item = e.len().saturating_add(9);
        if !cur.is_empty()
            && (cur.len() >= KEYS_PER_MESSAGE || used.saturating_add(item) > crate::records::sync::PART_BYTES)
        {
            out.push(core::mem::take(&mut cur));
            used = 0;
        }
        cur.push(e);
        used = used.saturating_add(item);
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 256 statements at their widest go in two messages, each inside a
    /// frame; 300 small ones in two of at most 256.
    #[test]
    fn statements_are_split_into_messages_that_fit_a_frame() {
        let wide = alloc::vec![0u8; MAX_STATEMENT_BODY + 8192 + 128];
        let all: Vec<&[u8]> = (0..256).map(|_| wide.as_slice()).collect();
        let msgs = keys_messages(&all);
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs.iter().map(Vec::len).sum::<usize>(), 256);
        for m in &msgs {
            assert!(m.iter().map(|e| e.len() + 9).sum::<usize>() <= crate::records::sync::PART_BYTES);
        }
        let small = [0u8; 100];
        let all: Vec<&[u8]> = (0..300).map(|_| small.as_slice()).collect();
        let msgs = keys_messages(&all);
        assert_eq!(msgs.iter().map(Vec::len).collect::<Vec<_>>(), [256, 44]);
        assert!(keys_messages(&[]).is_empty());
    }
}
