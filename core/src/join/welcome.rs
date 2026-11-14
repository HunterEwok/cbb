// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The Welcome (format 11.2): what an admitter sends the joiner once CPace
//! confirmed, and the joiner's checks of it (design-no-certificates
//! section 4). No certificate: the group's first root key and its recovery
//! key, which give the Group ID together (rule 33), and the group's records.
//!
//! The records travel one of two ways (plans/second-builder/
//! welcome-in-parts.md). A set that fits the Welcome's budget rides in it
//! (field 2, the newest list in field 10): zero parts, as before. A wider
//! one, which second signatures make up to about 84 MiB, rides whole in
//! `records` messages after it (`parts`, field 13), in the order
//! `RecordSet::parts_for_peer` gives; nothing is cut either way. Either
//! way field 12 carries the digest of the set the admitter sends (its IDs
//! and its lists' hashes, [`digest_of`]), and message 67's `Tw` (field 4,
//! [`tag`]) is a MAC from CPace's ISK over the Welcome's bytes, so the
//! digest, the count of parts and every other field are bound to the
//! confirmed session; the parts are bound to the Welcome by the digest. A
//! leaf's Welcome has neither digest nor parts.
//!
//! The joiner checks `Tw` before it reads the Welcome, holds the parts
//! without evaluating or keeping anything ([`Assembly`]), then takes them
//! all into a set, refuses unless every record it was sent is held and the
//! digest is the Welcome's, and only then checks: the Group ID from the
//! code exchange is the one the two keys give, so no admitter can pin a
//! false recovery key; the records verify up to those keys; its own record
//! carries its own key; the admitter's key from TLS stands in the records
//! and the key that signed the joiner's record is the root's or that
//! admitter's admin key with `admit`; the path of roots comes from the
//! recovery records, never from the admitter's word.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use crate::format::{Alg, GroupId, Rule, Value, cbor};
use crate::records::body::{Kind, POWER_ADMIT};
use crate::records::set::RecordSet;
use crate::records::{Key, KeyHash, Record, RecordId, Recovery, State, group_id};

/// What a Welcome's keys statements and credentials may take of message
/// 67 together (fields 4 and 7): the admitter's and the joiner's own first,
/// then the others while they fit; the rest come with the joiner's first
/// sync (they are also synced, `crate::msg::later`'s rows say so). 256
/// statements at their widest are 8 MiB, so not all of them can be
/// promised in one frame.
pub const STATEMENTS_BUDGET: usize = 2 << 20;

/// What a Welcome may take of its frame (the member limit, 7 MiB, which
/// message 67 alone of pairing takes, after the confirm) for its records
/// and its list when the set rides in it, counted by the bytes they take
/// in it (the envelopes): the rest is left for the statements, the grant,
/// the tags and the map. A set that does not fit goes in parts.
pub const RECORDS_BUDGET: usize = crate::format::frame::LIMIT_MEMBER - STATEMENTS_BUDGET - 64 * 1024;

/// The parts a Welcome announces at most (field 13). The range is frozen
/// with 0.6 and leaves room: [`MAX_PARTS_BYTES`] is the real bound, which
/// the widest set reaches in about 12 parts.
pub const MAX_PARTS: u64 = 64;

/// What the parts of one Welcome may take together, their messages' bytes:
/// what `RecordSet::for_peer` gives a device at the widest, that is the
/// set's rooms, the records that wait for a new root's list (within one
/// root's room), each of those records with the widest second signature
/// and its head, every list, every head and every first checkpoint, and a
/// MiB for the arrays' heads and the messages' maps: 101.0 MB (about
/// 96.4 MiB) at table A's ceilings. The records kept aside for a later
/// checkpoint and the settled ones are never sent, so this stays below the
/// set's own bound on second signatures. A joiner refuses as soon as the
/// parts pass it.
pub const MAX_PARTS_BYTES: usize = {
    use crate::format::envelope::MAX_SIG2;
    use crate::records::{
        ENVELOPE_ALLOWANCE, LIST_MAX, MAX_CHECKPOINT_BODY, MAX_RECORDS, MAX_ROOT_RECORDS, MAX_SET_BYTES,
    };
    let waiting = MAX_ROOT_RECORDS * crate::records::keep::UNIT;
    let sig2s = (MAX_RECORDS + MAX_ROOT_RECORDS) * (MAX_SIG2 + 9);
    let lists = crate::records::body::MAX_RECOVERY as usize * (4 + 34 * LIST_MAX);
    let heads = super::intro::MAX_HEADS * super::intro::HEAD_BYTES;
    let firsts = super::intro::MAX_HEADS * (MAX_CHECKPOINT_BODY + ENVELOPE_ALLOWANCE + MAX_SIG2);
    MAX_SET_BYTES + waiting + sig2s + lists + heads + firsts + (1 << 20)
};
// The second signatures a Welcome carries are among those the set holds.
const _: () = assert!(
    (crate::records::MAX_RECORDS + crate::records::MAX_ROOT_RECORDS) * (crate::format::envelope::MAX_SIG2 + 9)
        <= crate::records::MAX_SET_SIG2_BYTES
);
// The parts' bytes fit the parts' count, each part a frame.
const _: () = assert!(MAX_PARTS_BYTES <= MAX_PARTS as usize * crate::records::sync::PART_BYTES);
const _: () = assert!(RECORDS_BUDGET + STATEMENTS_BUDGET + 64 * 1024 <= crate::format::frame::LIMIT_MEMBER);

/// The longest a joiner waits for the next part after message 67 or the
/// part before: a 7 MiB part in 120 s is 0.49 Mbit/s, a phone's mobile link
/// through the relay at its worst that still joins. The core's ceiling; a
/// service may wait less.
pub const PART_MS: u64 = 120_000;

/// The longest a joiner waits for every part after message 67: the
/// [`MAX_PARTS_BYTES`] of the widest set in 25 minutes is 0.54 Mbit/s,
/// near a single part's slowest ([`PART_MS`]).
pub const PARTS_MS: u64 = 1_500_000;
// The widest parts arrive in time at 0.6 Mbit/s.
const _: () = assert!(MAX_PARTS_BYTES as u64 * 8 * 1000 / 600_000 <= PARTS_MS);

/// The label of the Welcome's digest ([`digest_of`]).
pub const LABEL_DIGEST: &str = "cbb welcome digest v1";
/// The label of the key of the Welcome's tag, from CPace's ISK ([`tag`]);
/// nothing else uses it.
pub const LABEL_TAG_KEY: &str = "cbb welcome key v1";
/// The label of the Welcome's tag ([`tag`]).
pub const LABEL_TAG: &str = "cbb welcome v1";

/// The parts a Welcome would need pass [`MAX_PARTS`]: no Welcome is
/// built. A set inside the format's ceilings never does.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TooLarge;

pub const RULE_SHAPE: Rule = Rule::field("welcome/shape");
pub const RULE_ROOT: Rule = Rule::field("welcome/root");
pub const RULE_RECOVERY: Rule = Rule::field("welcome/recovery");
/// The recovery key's second half is missing or not a 32-byte SLH-DSA key.
pub const RULE_RECOVERY2: Rule = Rule::field("welcome/recovery2");
pub const RULE_LIST: Rule = Rule::field("welcome/list");
/// A record of the Welcome that does not read (`Record::decode`).
pub const RULE_RECORD: Rule = Rule::field("welcome/record");
/// Fields 3 (claim ages) and 8 (counted claims) of earlier drafts.
pub const RULE_RETIRED: Rule = Rule::field("welcome/retired");
/// A non-leaf's Welcome without a digest, or a leaf's with one; or a set
/// whose digest is not the Welcome's.
pub const RULE_DIGEST: Rule = Rule::field("welcome/digest");
/// The parts break their rules: a count beside field 2 or a list, a leaf's
/// parts, a part after the last or before message 67, a message of another
/// type while parts are due, more bytes than [`MAX_PARTS_BYTES`], or a part
/// that is missing at the end.
pub const RULE_PARTS: Rule = Rule::field("welcome/parts");
/// A part came later than [`PART_MS`] after the one before, or the parts
/// took longer than [`PARTS_MS`].
pub const RULE_LATE: Rule = Rule::field("welcome/late");
/// Message 67 without its tag `Tw`, or with one that is not the Welcome's
/// under this session's ISK.
pub const RULE_TAG: Rule = Rule::field("pair/welcome/tw");

/// The Welcome.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Welcome {
    /// The group's first root key, its point.
    pub root: Vec<u8>,
    pub records: Vec<Record>,
    /// Statements of the group's devices, as envelopes.
    pub keys: Vec<Vec<u8>>,
    /// The admitter's clock, for a joiner without one (A-47).
    pub time_ms: u64,
    /// A leaf's first grant: the map of message `grant`'s fields 2–5, as
    /// its encoding.
    pub grant: Option<Vec<u8>>,
    /// The current period's server credentials, as envelopes.
    pub credentials: Vec<Vec<u8>>,
    /// The group's recovery key: K1's point.
    pub recovery: Vec<u8>,
    /// The recovery key's second half, K2: its 32 bytes (E-6).
    pub recovery2: Vec<u8>,
    /// The newest recovery record's list, as its encoding, when the set
    /// rides in the Welcome.
    pub list: Option<Vec<u8>>,
    /// The digest of the set the admitter sends ([`digest_of`]): every
    /// Welcome but a leaf's.
    pub digest: Option<[u8; 32]>,
    /// How many `records` messages follow (field 13): 0 when the set rides
    /// in the Welcome.
    pub parts: u64,
    /// The lists the parts carried, after [`Assembly::finish`]; never
    /// encoded (the parts carry them).
    pub lists: Vec<Vec<u8>>,
}

/// How the joiner took its Welcome.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Joining {
    Ordinary,
    /// A guarded leaf (A-50): it takes only a record the root signed
    /// itself.
    Guarded,
}

/// What binds the member to the joiner in this pairing, which the joiner
/// shows to take a Welcome.
#[derive(Debug)]
pub enum Way<'a> {
    /// An invitation: its secret, CPace's password, binds the member. One
    /// with the ID of none is no invitation.
    Invited(&'a super::invitation::Invitation),
    /// At home without an invitation nothing secret binds the member: only
    /// the person's "they match" at the joiner, in this session
    /// (`invitation::JoinerAttempts::answered`). Without it, or after "they
    /// do not match", there is no Welcome to take, and the session ends.
    /// `exporter` is the TLS exporter of the session the Welcome came on:
    /// an answer given in another session, or to another member than the
    /// admitter, takes nothing. The answer is taken by value: one answer,
    /// one Welcome.
    Home { matched: super::invitation::Matched, exporter: &'a [u8] },
}

/// Why the joiner does not take a Welcome.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Refusal {
    /// The two keys' Group ID is not the one the code exchange gave.
    OtherGroup,
    /// The records do not hold the joiner's own record with its own key.
    NotAdmitted,
    /// The admitter's key is not a device of the group, or the key that
    /// signed the joiner's record is neither the root's nor the admitter's
    /// admin key with `admit`.
    NotAdmitter,
    /// The Welcome is damaged.
    Damaged,
    /// At home without an invitation, the person's "they match" is of
    /// another session than this one, of another member than the
    /// admitter, or of another key than the joiner's own; or the
    /// invitation shown has the ID of none.
    Unconfirmed,
    /// The group is stopped (`State::stopped`): two recovery records at
    /// one seq, one this version cannot read, or two histories of the
    /// current root. An admitter in such a group does not admit, and a
    /// joiner does not join it.
    Stopped,
    /// The set the joiner took is not the one the admitter sent: a record
    /// it was sent that it does not hold (it does not verify, or its second
    /// signature is not the one its first covers), or a digest that is not
    /// the Welcome's.
    Digest,
}

/// The Welcome's digest of a set: of the IDs it holds (its digest, which
/// counts the records kept aside for a root whose change waits) and of the
/// hashes of its lists, sorted:
/// SHA-256(`cbb welcome digest v1` ‖ 0x00 ‖ digest ‖ count of lists, 4 bytes
/// big-endian ‖ each list's hash). Every part has a fixed length or a count
/// before it, so two sets never give the same bytes. A list is canonical
/// (its IDs sorted, once each), and the lists' order among themselves
/// means nothing (a recovery record finds its list by hash).
pub fn digest_of(set: &RecordSet) -> [u8; 32] {
    digest_from(&set.digest(), set.lists())
}

/// [`digest_of`] from a set's digest and its lists' bytes.
pub fn digest_from<'a>(set_digest: &[u8; 32], lists: impl IntoIterator<Item = &'a [u8]>) -> [u8; 32] {
    let mut hashes: Vec<[u8; 32]> = lists.into_iter().map(crate::records::body::list_hash).collect();
    hashes.sort_unstable();
    let count = u32::try_from(hashes.len()).unwrap_or(u32::MAX);
    let mut m = crate::format::sig::message(LABEL_DIGEST, set_digest);
    m.extend_from_slice(&count.to_be_bytes());
    for h in &hashes {
        m.extend_from_slice(h);
    }
    crate::certs::sha256(&m)
}

/// The Welcome's tag `Tw` (message 67, field 4): HMAC-SHA-512 under
/// K_w = HMAC-SHA-512(ISK, `cbb welcome key v1` ‖ 0x00) over
/// `cbb welcome v1` ‖ 0x00 ‖ the Welcome's bytes as they travel. The ISK is
/// what CPace's `finish` gave this session (CPACE-X25519-SHA512, whose Ta
/// and Tb are HMAC-SHA-512 too); K_w is its only other use.
pub fn tag(isk: &[u8], welcome: &[u8]) -> Option<[u8; 64]> {
    use hmac::{KeyInit, Mac};
    type H = hmac::Hmac<sha2::Sha512>;
    // HMAC takes a key of any length: neither call fails.
    let mut k = <H as KeyInit>::new_from_slice(isk).ok()?;
    k.update(&crate::format::sig::message(LABEL_TAG_KEY, &[]));
    let kw = zeroize::Zeroizing::new(k.finalize().into_bytes());
    let mut t = <H as KeyInit>::new_from_slice(&kw).ok()?;
    t.update(&crate::format::sig::message(LABEL_TAG, welcome));
    let mut out = [0u8; 64];
    out.copy_from_slice(&t.finalize().into_bytes());
    Some(out)
}

/// Message 67 as an admitter sends it: CPace's Tb, the Welcome's bytes and
/// their tag under the session's ISK, framed.
pub fn message(tb: &[u8], welcome: &[u8], isk: &[u8]) -> Result<Vec<u8>, Rule> {
    let tw = tag(isk, welcome).ok_or(RULE_TAG)?;
    let w = cbor::decode(welcome)?;
    let m = Value::Map(alloc::vec![
        (0, Value::Uint(super::T_WELCOME)),
        (2, Value::Bytes(tb)),
        (3, w),
        (4, Value::Bytes(&tw)),
    ]);
    Ok(crate::format::frame::write(&m))
}

/// The Welcome's bytes from message 67 (the message read by
/// `read_pairing`, `body` its bytes), once its tag holds under the
/// session's ISK. The tag is checked over field 3's bytes exactly as they
/// came, in constant time, before anything in them is read past the
/// profile's heads; a message without it, or with another, is refused and
/// nothing of it is kept. The caller still checks Tb (CPace's `verify`).
pub fn open<'a>(body: &'a [u8], isk: &[u8]) -> Result<&'a [u8], Rule> {
    let welcome = cbor::raw_field(body, 3)?.ok_or(RULE_SHAPE)?;
    let tw = cbor::raw_field(body, 4)?.ok_or(RULE_TAG)?;
    let tw = match cbor::decode(tw) {
        Ok(Value::Bytes(b)) => b,
        _ => return Err(RULE_TAG),
    };
    // Load-bearing: the Tamarin lemmas `parts_exact` and `parts_ids_exact`
    // (audit-0.6/formal-join/parts) fall without Tw over the digest and the
    // count of parts, both inside field 3. Do not narrow what it covers.
    if !tag(isk, welcome).is_some_and(|t| crate::secret::ct_eq(tw, &t)) {
        return Err(RULE_TAG);
    }
    Ok(welcome)
}

/// The rules between a Welcome's fields, each in range: with parts
/// (field 13) neither the records (2) nor a list (10) ride in it; without,
/// the records do; a leaf's (with a grant, 6) has neither digest (12) nor
/// parts; every other has a digest.
pub fn between(v: &Value<'_>) -> Result<(), Rule> {
    let parts = v.get(13).is_some();
    if parts && (v.get(2).is_some() || v.get(10).is_some()) {
        return Err(RULE_PARTS);
    }
    if !parts && v.get(2).is_none() {
        return Err(RULE_SHAPE);
    }
    let leaf = v.get(6).is_some();
    if leaf && parts {
        return Err(RULE_PARTS);
    }
    if leaf == v.get(12).is_some() {
        return Err(RULE_DIGEST);
    }
    Ok(())
}

impl Welcome {
    /// The Welcome an admitter sends a joiner that holds a set, and the
    /// parts that follow it: its set already holds the joiner's record.
    /// `admitter` and `joiner` are the member keys' hashes. What the joiner
    /// gets is `RecordSet::parts_for_peer`'s, all of the set for a device of
    /// the group; when it is one part with at most the newest list and fits
    /// [`RECORDS_BUDGET`], it rides in the Welcome and no part follows.
    pub fn build<'a>(
        set: &'a RecordSet,
        state: &State,
        admitter: &KeyHash,
        joiner: &KeyHash,
        time_ms: u64,
    ) -> Result<(Welcome, Vec<crate::records::sync::Part<'a>>), TooLarge> {
        Self::build_within(set, state, admitter, joiner, time_ms, RECORDS_BUDGET)
    }

    /// build with budget bytes for the records and the list that ride in
    /// the Welcome.
    pub(crate) fn build_within<'a>(
        set: &'a RecordSet,
        state: &State,
        _admitter: &KeyHash,
        joiner: &KeyHash,
        time_ms: u64,
        budget: usize,
    ) -> Result<(Welcome, Vec<crate::records::sync::Part<'a>>), TooLarge> {
        let mut parts = set.parts_for_peer(state, joiner);
        let mut w = Welcome {
            root: set.root().public().to_vec(),
            records: Vec::new(),
            keys: Vec::new(),
            time_ms,
            grant: None,
            credentials: Vec::new(),
            recovery: set.recovery().k1.public().to_vec(),
            recovery2: set.recovery().k2.public().to_vec(),
            list: None,
            digest: Some(digest_of(set)),
            parts: 0,
            lists: Vec::new(),
        };
        let inline = match parts.as_slice() {
            [] => true,
            [p] => p.lists.len() <= 1 && p.bytes() <= budget,
            _ => false,
        };
        if inline {
            if let Some(p) = parts.pop() {
                w.records = p.records.into_iter().cloned().collect();
                w.list = p.lists.first().map(|l| l.to_vec());
            }
            return Ok((w, Vec::new()));
        }
        w.parts = u64::try_from(parts.len()).map_err(|_| TooLarge)?;
        if w.parts > MAX_PARTS {
            return Err(TooLarge);
        }
        Ok((w, parts))
    }

    /// The statements of message 67 (fields 4 and 7): `keys` then
    /// `credentials`, each already in the order to send (the admitter's and
    /// the joiner's own first), each taken in that order while it still
    /// fits [`STATEMENTS_BUDGET`] with those before; the rest come with the
    /// first sync.
    pub fn add_statements(&mut self, keys: &[Vec<u8>], credentials: &[Vec<u8>]) {
        let mut used = 0usize;
        let mut fits = |e: &Vec<u8>| {
            let n = used.saturating_add(e.len());
            let ok = n <= STATEMENTS_BUDGET;
            if ok {
                used = n;
            }
            ok
        };
        self.keys = keys.iter().filter(|e| fits(e)).cloned().collect();
        self.credentials = credentials.iter().filter(|e| fits(e)).cloned().collect();
    }

    /// The Welcome's encoding (the map of format 11.2).
    pub fn encode(&self) -> Vec<u8> {
        let envs: Vec<Vec<u8>> = self.records.iter().map(Record::envelope).collect();
        fn values(v: &[Vec<u8>]) -> Option<Vec<Value<'_>>> {
            v.iter().map(|e| cbor::decode(e).ok()).collect()
        }
        let es256 = |p: &[u8]| -> Vec<u8> {
            Value::Array(alloc::vec![Value::Uint(Alg::Es256.number()), Value::Bytes(p)]).encode()
        };
        let (root, recovery) = (es256(&self.root), es256(&self.recovery));
        let mut m: Vec<(u16, Value<'_>)> = Vec::new();
        m.push((1, cbor::decode(&root).unwrap_or(Value::Uint(0))));
        if self.parts == 0 {
            m.push((2, Value::Array(values(&envs).unwrap_or_default())));
        }
        if !self.keys.is_empty() {
            m.push((4, Value::Array(values(&self.keys).unwrap_or_default())));
        }
        m.push((5, Value::Uint(self.time_ms)));
        let grant = self.grant.as_ref().and_then(|g| cbor::decode(g).ok());
        if let Some(g) = grant {
            m.push((6, g));
        }
        if !self.credentials.is_empty() {
            m.push((7, Value::Array(values(&self.credentials).unwrap_or_default())));
        }
        m.push((9, cbor::decode(&recovery).unwrap_or(Value::Uint(0))));
        if let Some(l) = &self.list {
            m.push((10, Value::Bytes(l)));
        }
        m.push((11, Value::Array(alloc::vec![Value::Uint(Alg::SlhDsa.number()), Value::Bytes(&self.recovery2)])));
        if let Some(d) = &self.digest {
            m.push((12, Value::Bytes(d)));
        }
        if self.parts > 0 {
            m.push((13, Value::Uint(self.parts)));
        }
        Value::Map(m).encode()
    }

    /// An encoded Welcome read against its table as a reader of this
    /// version does (`crate::msg::read_map`).
    fn read(b: &[u8]) -> Result<Value<'_>, Rule> {
        crate::msg::read_map(&crate::msg::tables::WELCOME, &cbor::decode(b)?)
    }

    /// The parts of an encoded Welcome before each record is read: the
    /// root's point, the record envelopes, the time, the recovery key's
    /// point and its second half's 32 bytes.
    #[allow(clippy::type_complexity, reason = "the parts as they come")]
    pub fn parts(b: &[u8]) -> Result<(Vec<u8>, Vec<Vec<u8>>, u64, Vec<u8>, Vec<u8>), Rule> {
        let v = Welcome::read(b)?;
        let key = |n: u16, alg: Alg, rule: Rule| -> Result<Vec<u8>, Rule> {
            let k = crate::format::Key::from_value(v.get(n).ok_or(rule)?).map_err(|_| rule)?;
            if k.alg != alg || k.check().is_err() {
                return Err(rule);
            }
            Ok(k.public.to_vec())
        };
        let root = key(1, Alg::Es256, RULE_ROOT)?;
        let recovery = key(9, Alg::Es256, RULE_RECOVERY)?;
        if root == recovery {
            return Err(RULE_RECOVERY);
        }
        let recovery2 = key(11, Alg::SlhDsa, RULE_RECOVERY2)?;
        // Absent with parts (the table's rules between fields, `between`,
        // were checked by the reader): the records come in them.
        let envs = match v.get(2) {
            None => Vec::new(),
            Some(a) => a.as_array().ok_or(RULE_SHAPE)?.iter().map(Value::encode).collect(),
        };
        let time = v.get(5).and_then(Value::as_uint).ok_or(RULE_SHAPE)?;
        Ok((root, envs, time, recovery, recovery2))
    }

    /// Reads a Welcome: its fields, each record read with the records'
    /// reader (signatures are checked by [`Welcome::check`]).
    pub fn decode(b: &[u8]) -> Result<Welcome, Rule> {
        let (root, envs, time_ms, recovery, recovery2) = Welcome::parts(b)?;
        let records = envs.iter().map(|e| Record::decode(e).map_err(|_| RULE_RECORD)).collect::<Result<Vec<_>, _>>()?;
        let v = Welcome::read(b)?;
        let list_of = |k: u16| -> Result<Vec<Vec<u8>>, Rule> {
            match v.get(k) {
                None => Ok(Vec::new()),
                Some(a) => Ok(a.as_array().ok_or(RULE_SHAPE)?.iter().map(Value::encode).collect()),
            }
        };
        let grant = match v.get(6) {
            None => None,
            Some(g) if g.as_map().is_some() => Some(g.encode()),
            Some(_) => return Err(RULE_SHAPE),
        };
        let list = match v.get(10) {
            None => None,
            // Its hash is checked against the recovery record that names it.
            Some(l) => Some(l.as_bytes().ok_or(RULE_LIST)?.to_vec()),
        };
        let digest = match v.get(12).and_then(Value::as_bytes) {
            None => None,
            Some(d) => Some(<[u8; 32]>::try_from(d).map_err(|_| RULE_DIGEST)?),
        };
        Ok(Welcome {
            root,
            records,
            keys: list_of(4)?,
            time_ms,
            grant,
            credentials: list_of(7)?,
            recovery,
            recovery2,
            list,
            digest,
            parts: v.get(13).and_then(Value::as_uint).unwrap_or(0),
            lists: Vec::new(),
        })
    }

    /// The joiner's checks. `group` is the group ID the code exchange gave
    /// (`ADb` 1), `admitter` the key the TLS handshake proved, `own` the
    /// joiner's member key, `way` what binds the member to the joiner.
    /// Returns the joiner's record set and its state. A guarded leaf
    /// (A-50) takes only a record the root signed itself.
    pub fn check(
        &self,
        group: &GroupId,
        admitter: &[u8; 65],
        own: &[u8; 65],
        joining: Joining,
        way: Way<'_>,
    ) -> Result<(RecordSet, State), Refusal> {
        let confirmed = match &way {
            Way::Invited(i) => i.id != super::NO_INVITATION,
            Way::Home { matched, exporter } => {
                matched.local() == Key::es256(own.to_vec()).device_id() && matched.of(exporter) && matched.to(admitter)
            }
        };
        if !confirmed {
            return Err(Refusal::Unconfirmed);
        }
        let root = Key::es256(self.root.clone());
        let k2 = Key::new(crate::records::key::ALG_SLH_DSA, self.recovery2.clone());
        let Some(recovery) = Recovery::new(Key::es256(self.recovery.clone()), k2) else {
            return Err(Refusal::Damaged);
        };
        if root.check().is_err() {
            return Err(Refusal::Damaged);
        }
        if group_id(&root, &recovery).0 != group.0 {
            return Err(Refusal::OtherGroup);
        }
        let mut set = RecordSet::new(root, recovery);
        // The heads and their lists first, so that the new root's records
        // count when they come; then everything, as a part is taken, twice,
        // since a part may wait for a later one's records.
        set.insert_all(self.records.iter().filter(|r| matches!(r.body().kind, Kind::Recovery { .. })).cloned());
        let lists: Vec<&[u8]> = self.list.iter().chain(&self.lists).map(Vec::as_slice).collect();
        for l in &lists {
            if set.insert_list(l).is_err() && self.digest.is_none() {
                return Err(Refusal::Damaged);
            }
        }
        set.take_part(&self.records, &lists);
        set.take_part(&self.records, &lists);
        // The set is the one the admitter sent: its IDs and lists.
        // Load-bearing with the tag: `parts_ids_exact` and `parts_exact`
        // (audit-0.6/formal-join/parts) fall without it.
        if let Some(d) = &self.digest
            && !crate::secret::ct_eq(&digest_of(&set), d)
        {
            return Err(Refusal::Digest);
        }
        let state = set.state();
        if state.stopped() {
            return Err(Refusal::Stopped);
        }
        if self.digest.is_some() {
            // Every record and list it was sent is held: a record that does
            // not verify, or whose second signature is not the one its first
            // covers, is not, and its ID alone would not change the digest.
            // (A stopped group keeps only the recovery key's records, and is
            // refused above.) Nothing is kept on a refusal.
            // Load-bearing: `parts_exact` (audit-0.6/formal-join/parts)
            // falls without it, to a swapped second signature.
            let held: BTreeSet<&RecordId> = set.ids().collect();
            let lists: BTreeSet<&[u8]> = set.lists().collect();
            let all_lists = self.list.iter().chain(&self.lists).all(|l| lists.contains(l.as_slice()));
            if !all_lists || !self.records.iter().all(|r| held.contains(&r.id())) {
                return Err(Refusal::Digest);
            }
        }
        let own_key = Key::es256(own.to_vec());
        let me = own_key.hash();
        if state.device_by_key(&me).is_none() {
            return Err(Refusal::NotAdmitted);
        }
        // The key that signed my counting record.
        let signer = set
            .in_dependency_order()
            .into_iter()
            .filter(|r| state.counting.contains(&r.id()))
            .find_map(|r| match &r.body().kind {
                Kind::Device(d) if d.key.hash() == me => Some(r.body().signer),
                _ => None,
            })
            .ok_or(Refusal::NotAdmitted)?;
        let adm = state.device_by_key(&Key::es256(admitter.to_vec()).hash()).ok_or(Refusal::NotAdmitter)?;
        if adm.frozen {
            return Err(Refusal::NotAdmitter);
        }
        let by_root = state.is_root(&signer) && state.root_device == Some(adm.id);
        let by_admin = adm.admin == Some(signer) && adm.powers & POWER_ADMIT != 0;
        if !(by_root || by_admin) || (joining == Joining::Guarded && !by_root) {
            return Err(Refusal::NotAdmitter);
        }
        Ok((set, state))
    }
}

/// The joiner's Welcome while its parts come (a Welcome with field 13):
/// it holds each part's records and lists as read, evaluates nothing and
/// keeps nothing, and gives the whole Welcome to check only once every
/// part is in. Any error ends the pairing; the caller drops the assembly,
/// and with it everything it held.
#[derive(Debug)]
pub struct Assembly {
    welcome: Welcome,
    due: u64,
    bytes: usize,
    started_ms: u64,
    last_ms: u64,
}

impl Assembly {
    /// Starts with the Welcome of message 67, read at now_ms. A Welcome
    /// without parts is whole already: [`Assembly::finish`] gives it back.
    pub fn new(welcome: Welcome, now_ms: u64) -> Result<Assembly, Rule> {
        if welcome.parts > MAX_PARTS {
            return Err(RULE_PARTS);
        }
        let due = welcome.parts;
        Ok(Assembly { welcome, due, bytes: 0, started_ms: now_ms, last_ms: now_ms })
    }

    /// The parts still due.
    pub fn due(&self) -> u64 {
        self.due
    }

    /// Whether the parts are late at now_ms: the next is due within
    /// [`PART_MS`] of the one before (or of message 67), all of them within
    /// [`PARTS_MS`] of message 67. The driver asks it while it waits.
    pub fn late(&self, now_ms: u64) -> bool {
        self.due > 0
            && (now_ms.saturating_sub(self.last_ms) > PART_MS || now_ms.saturating_sub(self.started_ms) > PARTS_MS)
    }

    /// Takes the next frame of the pairing while parts are due: a `records`
    /// message within the member limit, which comes in time and keeps the
    /// parts' bytes within [`MAX_PARTS_BYTES`]. Each record must read
    /// (`Record::decode`, the envelope and its second signature's hash);
    /// its signature is checked when the parts are taken, in
    /// [`Welcome::check`], where a record not held ends the pairing.
    pub fn take(&mut self, frame: &[u8], now_ms: u64) -> Result<(), Rule> {
        if self.due == 0 {
            return Err(RULE_PARTS);
        }
        if self.late(now_ms) {
            return Err(RULE_LATE);
        }
        let m = crate::format::frame::read(frame, crate::format::frame::LIMIT_MEMBER)?;
        if m.t != T_RECORDS {
            return Err(RULE_PARTS);
        }
        self.bytes = self.bytes.saturating_add(frame.len());
        if self.bytes > MAX_PARTS_BYTES {
            return Err(RULE_PARTS);
        }
        let v = crate::msg::read_map(&crate::msg::tables::RECORDS, &m.map)?;
        let (records, lists) = read_part(&v)?;
        self.welcome.records.extend(records);
        self.welcome.lists.extend(lists);
        self.due = self.due.saturating_sub(1);
        self.last_ms = now_ms;
        Ok(())
    }

    /// The whole Welcome, every part in, for [`Welcome::check`].
    pub fn finish(self) -> Result<Welcome, Rule> {
        if self.due > 0 {
            return Err(RULE_PARTS);
        }
        Ok(self.welcome)
    }
}

/// Message `records` (format 9.2).
pub const T_RECORDS: u64 = 5;

/// The records and lists of a `records` message read against its table:
/// at least one of the two (the table's reader checks it), each record read
/// by the records' reader.
pub fn read_part(v: &Value<'_>) -> Result<(Vec<Record>, Vec<Vec<u8>>), Rule> {
    const RULE_RECORDS: Rule = Rule::field("records/records");
    let records = match v.get(2).and_then(Value::as_array) {
        None => Vec::new(),
        Some(a) => a.iter().map(|e| Record::decode(&e.encode()).map_err(|_| RULE_RECORDS)).collect::<Result<_, _>>()?,
    };
    let lists = match v.get(3).and_then(Value::as_array) {
        None => Vec::new(),
        Some(a) => a.iter().filter_map(Value::as_bytes).map(<[u8]>::to_vec).collect(),
    };
    Ok((records, lists))
}

/// A part as message `records`, framed: what an admitter sends after
/// message 67 for each of [`Welcome::build`]'s parts.
pub fn part_message(part: &crate::records::sync::Part<'_>) -> Vec<u8> {
    let envs: Vec<Vec<u8>> = part.records.iter().map(|r| r.envelope()).collect();
    let mut m: Vec<(u16, Value<'_>)> = alloc::vec![(0, Value::Uint(T_RECORDS))];
    if !envs.is_empty() {
        m.push((2, Value::Array(envs.iter().filter_map(|e| cbor::decode(e).ok()).collect())));
    }
    if !part.lists.is_empty() {
        m.push((3, Value::Array(part.lists.iter().map(|l| Value::Bytes(l)).collect())));
    }
    crate::format::frame::write(&Value::Map(m))
}
