// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Records v3: the group's records in the 0.6 format and the rules that
//! turn a set of them into the group's state.
//!
//! The rules (plans: design-records-v3, format-0.6 sections 3–5 and 13):
//!
//! 1. A record is `[body, sig]`; its ID is SHA-256 over the body, and a set
//!    holds each record once, by ID. A signature has one form (64 bytes,
//!    low S) and is checked before the record is stored, so a copy that
//!    does not verify never takes a good one's place.
//! 2. A device's ID is the first 16 bytes of its member key's hash; the key
//!    never changes. Two counting records with two keys and one ID: neither
//!    counts.
//! 3. An admin with `admit` signs only the first record of a device, with
//!    base rights (read, send; secrets only when its own device has them);
//!    later records need `manage` and never widen. Only a root widens.
//!    The root's first record for a device fixes whether it is a leaf (an
//!    admin's earlier record does not bind the root), and a guarded leaf
//!    stays guarded for its ID.
//! 4. The sealing key is in the device's own keys statement (`statement`).
//! 5. Unknown critical fields hold a record (kept, passed on, not applied);
//!    `min_rules` in the settings stops older devices from secrets.
//! 6. The kept set and the state depend on the set alone, never on the
//!    order its records came in; its ceilings are the format's, with no
//!    working limits under them.
//! 7. No rule reads a clock.
//! 8. A root's own records count during a stop, and only a root resolves
//!    a conflict between admins.
//! 9. A root's removal counts for good while it is kept: a resolve never
//!    voids a root's record, and the root's checkpoint leaves a removal out
//!    only with the admissions of the keys it names, so no old record
//!    brings the device back; only a new record admits it again. A root's
//!    resolve may void an admin's revoke; the device then counts again
//!    with its key and ID. Two histories of the current root stop the
//!    group until the recovery key changes the root.
//! 10. The root changes only by a takeover the group's recovery key
//!     signs, at once: no delay, no cancel, no objection, and no admin
//!     takes the group over (rule 33). The recovery chain, walked from the
//!     recovery key the device was given with the group, gives the path of
//!     roots before anything else; no root's or admin's record changes it,
//!     whatever order the records came in.
//! 11. A device's member key and its admin key go together: a removal or
//!     freeze that names one names both.
//! 12. A recovery record hands the chain to the next recovery key, whose
//!     records start again at seq 1; the key that handed over signs
//!     nothing more that counts. Two records at one step of the chain stop
//!     the group for good. Whether a peer counts another owner comes from
//!     the peers' paths of roots (`State::disagrees`), never from records.
//! 13. A takeover lists what stays of the root it follows (`keep`): those
//!     records count by themselves, at once, with no chain below them; the
//!     rest of that root counts nothing and is not stored.
//!
//! The bytes are the format's (`crate::format`): a record is read from its
//! envelope with [`Record::decode`] and written with [`Record::envelope`].

/// The bytes a record is counted for beyond its body: the envelope's
/// array head, the heads of body and sig, and the 64-byte signature.
pub const ENVELOPE_ALLOWANCE: usize = 1 + 9 + 9 + 64;

/// The bytes counted for a second signature, whatever its length: nine
/// units, which hold the largest one the format takes
/// (`format::envelope::MAX_SIG2`) with its head. The count still depends
/// on the body alone.
pub const SIG2_ALLOWANCE: usize = 9 * keep::UNIT;

const _: () = assert!(SIG2_ALLOWANCE >= crate::format::envelope::MAX_SIG2 + 9);

/// The bytes counted for a recovery head's second signature, K2's
/// (`format::envelope::MAX_SIG2_HEAD` with its head). Heads are kept
/// outside the rooms (rule 33); this counts them in the set's bytes.
pub const HEAD_SIG2_ALLOWANCE: usize = 65 * keep::UNIT;

const _: () = assert!(HEAD_SIG2_ALLOWANCE >= crate::format::envelope::MAX_SIG2_HEAD + 9);

pub mod body;
pub mod eval;
pub mod keep;
pub mod key;
pub mod pq;
pub mod set;
pub mod statement;

#[cfg(test)]
mod tests;

use alloc::vec::Vec;
use core::fmt;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

pub use body::{Body, Kind, List};
pub use eval::{Input, State, evaluate};
pub use key::{DeviceId, GroupId, Key, KeyHash, RecordId, Recovery, group_id};
pub use set::{RecordSet, Stuck};

use crate::certs::sha256;
use crate::identity::ExternalKey;

/// The label records are signed under.
pub const LABEL_RECORD: &str = "cbb record v3";

/// The label the recovery key signs a fetch proof under (rule 33): what a
/// writer that is not a member shows to fetch the group's records. Its own
/// label, so that nothing signed for a fetch reads as a record and no
/// record as a fetch proof; the fetch protocol itself is not built yet.
pub const LABEL_RECOVERY_FETCH: &str = "cbb recovery fetch v3";

/// The data a first signature covers beside a second one (audit Q-1):
/// the signed bytes, then the SHA-256 of the second signature, so a second
/// signature cannot be swapped on the way.
pub fn with_sig2(data: &[u8], sig2: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(data.len().saturating_add(32));
    m.extend_from_slice(data);
    m.extend_from_slice(&sha256(sig2));
    m
}

/// The recovery key's fetch proof over data (rule 33, E-6): K2 signs first,
/// over data under [`pq::CONTEXT_FETCH`]; K1 signs data and the SHA-256 of
/// K2's signature under [`LABEL_RECOVERY_FETCH`]. It returns
/// `(sig, sig2)`.
pub fn sign_fetch(k1: &dyn ExternalKey, k2: &pq::PqKey, data: &[u8]) -> crate::error::Result<([u8; 64], Vec<u8>)> {
    let sig2 = k2.sign(data, pq::CONTEXT_FETCH)?;
    let sig = key::sign_es256(k1, LABEL_RECOVERY_FETCH, &with_sig2(data, &sig2))?;
    Ok((sig, sig2))
}

/// Checks a fetch proof: both signatures of the group's recovery key, as
/// [`sign_fetch`] makes them. Both are checked every time, K1's first.
pub fn verify_fetch(recovery: &Recovery, data: &[u8], sig: &[u8], sig2: &[u8]) -> Result<(), Rule> {
    let first = key::verify_es256(&recovery.k1, LABEL_RECOVERY_FETCH, &with_sig2(data, sig2), sig);
    let second = pq::verify(&recovery.k2, data, sig2, pq::CONTEXT_FETCH);
    first?;
    if !second {
        return Err(Rule::new("sig/verify"));
    }
    Ok(())
}

/// The label of a record's mark (`Record::mark`).
pub const LABEL_MARK: &str = "cbb record mark v3";

/// A device's mark on a record it verified, stored beside it in its own
/// store: HMAC-SHA-256 under a 32-byte key the device keeps to itself, over
/// the label, a zero byte and the record's envelope. Loading checks the
/// mark instead of the signature (design-records-v3 section 7, rule 29).
pub type Mark = [u8; 32];
/// The label of the pinned keys' mark (`pin_mark`).
pub const LABEL_PIN: &str = "cbb pin v3";

/// The mark a device keeps beside the group's first root key and recovery
/// key in its own store (rule 29): HMAC-SHA-256 under its own local key
/// over the label, a zero byte and the encodings of the root key and both
/// halves of the recovery key. A store whose pinned keys were changed does
/// not load (`RecordSet::pinned`).
#[allow(clippy::expect_used, reason = "HMAC takes a key of any length, so this never fails")]
pub fn pin_mark(local: &[u8; 32], root: &Key, recovery: &Recovery) -> Mark {
    let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(local).expect("HMAC takes a key of any length");
    m.update(LABEL_PIN.as_bytes());
    m.update(&[0]);
    m.update(&root.encode());
    m.update(&recovery.k1.encode());
    m.update(&recovery.k2.encode());
    let mut out = [0u8; 32];
    out.copy_from_slice(&m.finalize().into_bytes());
    out
}

/// The label of the set digest.
pub const LABEL_SET: &str = "cbb set v3";

/// The rules version this code implements (section 3.3).
pub const RULES_VERSION: u64 = 1;

/// The highest seq.
pub const MAX_SEQ: u64 = (1 << 31) - 1;
/// The most entries of a `seen` list.
pub const MAX_SEEN: usize = 1024;

// The ceilings frozen in the format (section 13).

/// A record body, and a checkpoint's. A recovery record is small: its list
/// rides beside it.
pub const MAX_BODY: usize = 16 << 10;
/// A checkpoint names records of a full set: at most one head per key that
/// signs (the roots on the path and 256 admin keys, about 76 bytes each)
/// and the other records it keeps, one per seq of a key, all of them in
/// the set's 4096 records or among the first checkpoints outside the
/// rooms, 34 bytes each: 321 * 76 + (4096 + 65 - 321) * 34 + the fixed
/// fields is about 155 000 bytes. The new root's first checkpoint, which
/// keeps the whole list besides what the old root's checkpoint kept, is
/// such a checkpoint too.
pub const MAX_CHECKPOINT_BODY: usize = 160 << 10;
/// Records of one root key.
pub const MAX_ROOT_RECORDS: usize = 1024;
/// Records of one admin key.
pub const MAX_ADMIN_RECORDS: usize = 256;
/// Records in a set, and their bytes.
pub const MAX_RECORDS: usize = 4096;
pub const MAX_SET_BYTES: usize = 2 << 20;
/// Devices with a device record.
pub const MAX_DEVICES: usize = 256;
/// Roots on the path: the first and one for each recovery record.
pub const MAX_PATH: usize = 1 + body::MAX_RECOVERY as usize;
/// Held records a state lists.
pub const MAX_NEWER: usize = 16;
/// Notices a set keeps of removals the newest list dropped, and of
/// notices dismissed (`RecordSet::notices`).
pub const MAX_NOTICES: usize = 256;

/// Why an object is refused: the name of the rule it breaks, as the
/// vectors cite it ("sig/low-s", "records/device/name").
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Rule {
    kind: &'static str,
    field: &'static str,
}

impl Rule {
    pub const fn new(name: &'static str) -> Rule {
        Rule { kind: name, field: "" }
    }

    /// The rule of one field of a record type: `records/<type>/<field>`.
    pub const fn field(kind: &'static str, field: &'static str) -> Rule {
        Rule { kind, field }
    }

    /// Reports whether this is the rule named name.
    pub fn is(&self, name: &str) -> bool {
        if self.field.is_empty() {
            return self.kind == name;
        }
        let mut parts = name.splitn(3, '/');
        parts.next() == Some("records") && parts.next() == Some(self.kind) && parts.next() == Some(self.field)
    }
}

impl From<crate::format::Rule> for Rule {
    fn from(r: crate::format::Rule) -> Rule {
        Rule::new(r.name())
    }
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.field.is_empty() { f.write_str(self.kind) } else { write!(f, "records/{}/{}", self.kind, self.field) }
    }
}

/// A record: its body's bytes, its signature, and the body they read as.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Record {
    bytes: Vec<u8>,
    sig: Vec<u8>,
    sig2: Option<Vec<u8>>,
    body: Body,
    id: RecordId,
}

impl Record {
    /// Signs body with key, whose hash must be the body's signer. A held
    /// body is not signed, and the types every version must apply are
    /// written with the fields of 0.6 only (section 3.3).
    pub fn sign(body: Body, key: &dyn ExternalKey) -> crate::error::Result<Record> {
        if body.held {
            return Err(crate::error::Error::msg("a record with a field this version does not know is not signed"));
        }
        if body.check().map_err(|r| crate::error::Error::msg(alloc::format!("the record breaks {r}")))? {
            return Err(crate::error::Error::msg("a record naming a key of an unknown algorithm is not signed"));
        }
        if Key::es256(key.public()).hash() != body.signer {
            return Err(crate::error::Error::msg("the record's signer is not the key that signs it"));
        }
        if matches!(body.kind, Kind::Recovery { .. }) {
            return Err(crate::error::Error::msg("a recovery head is signed by both halves of the recovery key"));
        }
        let bytes = body.encode();
        let max = if matches!(body.kind, Kind::Checkpoint { .. }) { MAX_CHECKPOINT_BODY } else { MAX_BODY };
        if bytes.len() > max {
            return Err(crate::error::Error::msg(alloc::format!(
                "a record body of {} bytes is over its ceiling of {max}",
                bytes.len()
            )));
        }
        let sig = key::sign_es256(key, LABEL_RECORD, &bytes)?.to_vec();
        let id = RecordId(sha256(&bytes));
        Ok(Record { bytes, sig, sig2: None, body, id })
    }

    /// Signs a recovery head with both halves of the recovery key (E-6):
    /// K2 first, over the body under [`pq::CONTEXT_RECORD`]; then K1 over
    /// the body and the SHA-256 of K2's signature under [`LABEL_RECORD`]
    /// (audit Q-1). The body's signer is K1's hash, its `signer2` K2's.
    pub fn sign_head(body: Body, k1: &dyn ExternalKey, k2: &pq::PqKey) -> crate::error::Result<Record> {
        use crate::error::Error;
        let Kind::Recovery { signer2, .. } = &body.kind else {
            return Err(Error::msg("only a recovery head carries two signatures in 0.6"));
        };
        if Key::es256(k1.public()).hash() != body.signer || k2.key().hash() != *signer2 {
            return Err(Error::msg("the head's signers are not the keys that sign it"));
        }
        if body.held || body.check().map_err(|r| Error::msg(alloc::format!("the record breaks {r}")))? {
            return Err(Error::msg("a record naming a key of an unknown algorithm is not signed"));
        }
        let bytes = body.encode();
        let sig2 = k2.sign(&bytes, pq::CONTEXT_RECORD)?;
        let sig = key::sign_es256(k1, LABEL_RECORD, &with_sig2(&bytes, &sig2))?.to_vec();
        let id = RecordId(sha256(&bytes));
        Ok(Record { bytes, sig, sig2: Some(sig2), body, id })
    }

    /// A record from the parts a reader found: the body's bytes, the
    /// signatures, and the body's value. Until the codec reads the bytes
    /// itself, the value must encode to exactly those bytes (one value has
    /// one encoding in the profile). Nothing is verified here.
    pub fn from_parts(bytes: Vec<u8>, sig: Vec<u8>, sig2: Option<Vec<u8>>, body: Body) -> Result<Record, Rule> {
        if body.encode() != bytes {
            return Err(Rule::new("cbor/encoding"));
        }
        if sig2.is_some() && !(body.held || matches!(body.kind, Kind::Recovery { .. })) {
            return Err(Rule::new("env/shape"));
        }
        let id = RecordId(sha256(&bytes));
        Ok(Record { bytes, sig, sig2, body, id })
    }

    /// Reads a record from its envelope's bytes, checking all that can be
    /// checked without its signer's key: the envelope's size and shape, the
    /// profile, the body's fields against their rows, and the signature's
    /// form (64 bytes, in range, low S). The signature itself is checked
    /// when the record is put into a set (`RecordSet::insert`), which knows
    /// the signer's key; the group is the set's too. A body with a
    /// critical field or a type this version does not know reads as held.
    pub fn decode(envelope: &[u8]) -> Result<Record, Rule> {
        let e = crate::format::Envelope::parse_limited(envelope, MAX_CHECKPOINT_BODY)?;
        let body = Body::from_value(&e.map)?;
        let max = if matches!(body.kind, Kind::Checkpoint { .. }) { MAX_CHECKPOINT_BODY } else { MAX_BODY };
        if e.body.len() > max {
            return Err(crate::format::Rule::ENV_SIZE.into());
        }
        crate::format::sig::check_form(e.sig)?;
        body.check()?;
        let id = RecordId(sha256(e.body));
        Ok(Record { bytes: e.body.to_vec(), sig: e.sig.to_vec(), sig2: e.sig2.map(<[u8]>::to_vec), body, id })
    }

    pub fn id(&self) -> RecordId {
        self.id
    }

    pub fn body(&self) -> &Body {
        &self.body
    }

    pub fn body_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn sig(&self) -> &[u8] {
        &self.sig
    }

    /// The envelope's bytes: `[body, sig]`, or with sig2.
    pub fn envelope(&self) -> Vec<u8> {
        crate::format::envelope::write(&self.bytes, &self.sig, self.sig2.as_deref())
    }

    /// The bytes the record is counted for in a set: its body's and one
    /// fixed allowance for the rest of its envelope ([`ENVELOPE_ALLOWANCE`],
    /// and [`SIG2_ALLOWANCE`] when the body names `signer2`, or
    /// [`HEAD_SIG2_ALLOWANCE`] for a recovery head). The count depends on
    /// the body alone, so every envelope of one record ID counts the same.
    pub fn size(&self) -> usize {
        let rest = match (&self.body.kind, self.sig2.is_some()) {
            (Kind::Recovery { .. }, true) => ENVELOPE_ALLOWANCE + HEAD_SIG2_ALLOWANCE,
            (_, true) => ENVELOPE_ALLOWANCE + SIG2_ALLOWANCE,
            _ => ENVELOPE_ALLOWANCE,
        };
        self.bytes.len().saturating_add(rest)
    }

    /// The ceiling on its body: a checkpoint's is larger.
    fn max_body(&self) -> usize {
        if matches!(self.body.kind, Kind::Checkpoint { .. }) { MAX_CHECKPOINT_BODY } else { MAX_BODY }
    }

    /// Checks what can be checked without the set: the body's size and
    /// fields, and its signature with key. It returns whether the record is
    /// held.
    pub fn verify(&self, key: &Key) -> Result<bool, Rule> {
        if self.bytes.len() > self.max_body() {
            return Err(Rule::new("records/size"));
        }
        let held = self.body.check()?;
        // A recovery head is the recovery key's two signatures: `verify_head`.
        if !held && matches!(self.body.kind, Kind::Recovery { .. }) {
            return Err(Rule::new("sig/verify"));
        }
        #[cfg(test)]
        VERIFIED.with(|n| n.set(n.get().saturating_add(1)));
        key::verify_es256(key, LABEL_RECORD, &self.bytes, &self.sig)?;
        Ok(held)
    }

    /// Checks a record the recovery key signed, as [`verify`](Self::verify)
    /// does with one key: a head this version applies must carry both
    /// signatures, `signer2` must be the group's K2, and both must hold.
    /// Both are checked every time, K1's first and K2's second, whatever
    /// the first gave, so the time taken does not tell which failed. K1's
    /// signature covers the SHA-256 of K2's (Q-1): a K2 signature swapped
    /// on the way breaks K1's (`records/recovery/damaged`), and the copy is
    /// dropped like any that does not verify. A held record of the recovery
    /// key carries both signatures and is checked as a head: K1 alone never
    /// stands for the key.
    pub fn verify_head(&self, recovery: &Recovery) -> Result<bool, Rule> {
        if self.bytes.len() > self.max_body() {
            return Err(Rule::new("records/size"));
        }
        let held = self.body.check()?;
        // Every record of the recovery key carries both signatures, one
        // this version holds too: K1 alone never stands for the key, so a
        // held record that a later version reads was checked as a head.
        if !held {
            let Kind::Recovery { signer2, .. } = &self.body.kind else { return Err(Rule::new("records/recovery")) };
            if *signer2 != recovery.hash2() {
                return Err(Rule::field("recovery", "signer2"));
            }
        }
        let Some(sig2) = self.sig2.as_deref() else { return Err(Rule::new("env/shape")) };
        #[cfg(test)]
        VERIFIED.with(|n| n.set(n.get().saturating_add(1)));
        let first = key::verify_es256(&recovery.k1, LABEL_RECORD, &with_sig2(&self.bytes, sig2), &self.sig);
        let second = pq::verify(&recovery.k2, &self.bytes, sig2, pq::CONTEXT_RECORD);
        if first.is_err() {
            return Err(Rule::field("recovery", "damaged"));
        }
        if !second {
            return Err(Rule::new("sig/verify"));
        }
        Ok(held)
    }

    /// `verify_head` for a record from the device's own store, as
    /// [`verify_marked`](Self::verify_marked).
    pub(crate) fn verify_head_marked(
        &self,
        recovery: &Recovery,
        mark: Option<(&[u8; 32], &Mark)>,
    ) -> Result<bool, Rule> {
        match mark {
            Some((local, mark)) if self.mark_holds(local, mark) => {
                if self.bytes.len() > self.max_body() {
                    return Err(Rule::new("records/size"));
                }
                self.body.check()
            }
            _ => self.verify_head(recovery),
        }
    }

    /// The second signature, when the envelope has one.
    pub fn sig2(&self) -> Option<&[u8]> {
        self.sig2.as_deref()
    }

    /// The mark of the record under the device's own key local. The core
    /// never makes or stores that key; its caller keeps it.
    pub fn mark(&self, local: &[u8; 32]) -> Mark {
        let mut out = [0u8; 32];
        out.copy_from_slice(&self.marker(local).finalize().into_bytes());
        out
    }

    #[allow(clippy::expect_used, reason = "HMAC takes a key of any length, so this never fails")]
    fn marker(&self, local: &[u8; 32]) -> Hmac<Sha256> {
        let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(local).expect("HMAC takes a key of any length");
        m.update(LABEL_MARK.as_bytes());
        m.update(&[0]);
        m.update(&self.envelope());
        m
    }

    /// Whether mark is the record's mark under local, compared in constant
    /// time (hmac's own verify).
    pub(crate) fn mark_holds(&self, local: &[u8; 32], mark: &Mark) -> bool {
        self.marker(local).verify_slice(mark).is_ok()
    }

    /// verify for a record from the device's own store: with its mark under
    /// local, the checks without the signature; with a missing or wrong
    /// mark, verify.
    pub(crate) fn verify_marked(&self, key: &Key, mark: Option<(&[u8; 32], &Mark)>) -> Result<bool, Rule> {
        match mark {
            Some((local, mark)) if self.mark_holds(local, mark) => {
                if self.bytes.len() > self.max_body() {
                    return Err(Rule::new("records/size"));
                }
                self.body.check()
            }
            _ => self.verify(key),
        }
    }
}

#[cfg(test)]
std::thread_local! {
    /// The signatures this thread verified, for the tests that count them.
    pub(crate) static VERIFIED: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

/// The set digest: SHA-256 over the label, a zero byte and the sorted IDs.
pub fn digest<'a>(ids: impl IntoIterator<Item = &'a RecordId>) -> [u8; 32] {
    let mut ids: Vec<&RecordId> = ids.into_iter().collect();
    ids.sort();
    ids.dedup();
    let mut m = Vec::with_capacity(LABEL_SET.len().saturating_add(1).saturating_add(ids.len().saturating_mul(32)));
    m.extend_from_slice(LABEL_SET.as_bytes());
    m.push(0);
    for id in ids {
        m.extend_from_slice(&id.0);
    }
    sha256(&m)
}
