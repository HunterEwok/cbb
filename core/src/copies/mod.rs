// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Copies sealed end to end in the 0.6 format (format section 10), on the
//! records v3 (`crate::records`) and the keys statements: who a copy is
//! sealed to, sealing it, checking it on the way, opening it, the reduced
//! copy for a leaf, a secret's mark, and sealing it again for a reader that
//! slept through a key change.
//!
//! - The origin picks a copy key K for each copy and binds it to the
//!   header: `commit` in the header is derived from K, and the payload and
//!   blob keys are derived from K under the header's hash `h` (A-5, A-75).
//!   So a K used twice still gives other keys under another header, and a
//!   reader refuses a copy whose `commit` does not match the K it opened.
//! - K is sealed to each reader's sealing key of the epoch the header names,
//!   taken from that device's own keys statement. Root and admin keys open
//!   nothing: a copy is sealed to device keys only.
//! - Every member checks the origin's signature before it passes a copy on
//!   (`check`); a reader then opens its own wrap (`open`).
//! - A reader whose wrap is for an epoch it no longer holds asks the origin
//!   to seal the copy again (message `reseal`), and the origin does so for
//!   a device that was one of the copy's readers and still is (`reseal`).
//!
//! Whether a reader writes what it opened is decided from signed fields
//! only: see [`fresh`].
//!
//! This is the new path beside the old one (`crate::copy`); the service and
//! the phones switch to it in wave 5.

pub mod fresh;

#[cfg(test)]
mod tests;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};

use crate::content::Content;
use crate::error::Error;
use crate::format::cbor::{self, Value};
use crate::format::copy::{self as fcopy, Copy};
use crate::format::frame;
use crate::format::{Rule, sha256, sig};
use crate::hlc::Timestamp;
use crate::identity::ExternalKey;
use crate::keystore::KeyStore;
use crate::records::body::{RIGHT_READ, RIGHT_SECRETS, RIGHT_SEND, ROLE_LEAF, ROLE_WATCH};
use crate::records::eval::{DeviceState, State};
use crate::records::key::{self as rkey, DeviceId};
use crate::records::statement::Sealing;

/// The message type of a copy.
pub const T_COPY: u64 = 2;
/// The message type of a request to seal a copy again.
pub const T_RESEAL: u64 = crate::msg::wave4::T_RESEAL;

/// A copy from a device the records do not name (yet): it waits for the
/// records and is not passed on.
pub const RULE_ORIGIN: Rule = Rule::field("copy/origin");
/// A copy from a device the records name, but without the right to send.
pub const RULE_SEND: Rule = Rule::field("copy/send");
/// A wrap that does not open with the reader's key of its epoch.
pub const RULE_WRAP: Rule = Rule::field("copy/wrap");
/// A payload that does not open with the key derived from K under `h`.
pub const RULE_PAYLOAD: Rule = Rule::field("copy/payload");
/// A copy to a leaf whose frame would be larger than the leaf's.
pub const RULE_LEAF_FRAME: Rule = Rule::field("copy/leaf-frame");
/// A copy's time no clock reaches (past `hlc::MAX_WALL`).
pub const RULE_TIME: Rule = Rule::field("copy/time");
/// A request to seal again from a device that was not a reader of the copy.
pub const RULE_RESEAL_READER: Rule = Rule::field("reseal/reader");
/// A request to seal again to an epoch that is not the asker's current one.
pub const RULE_RESEAL_EPOCH: Rule = Rule::field("reseal/not-current");
/// A copy past its lifetime, or a secret asked of an origin without a
/// clock: it is not sealed again.
pub const RULE_RESEAL_EXPIRED: Rule = Rule::field("reseal/expired");
/// The asker already had this copy sealed again [`MAX_RESEALS`] times.
pub const RULE_RESEAL_LIMIT: Rule = Rule::field("reseal/limit");
/// A request to seal again while the group is stopped (`State::stopped`).
pub const RULE_RESEAL_HALTED: Rule = Rule::field("reseal/halted");

/// How many times the origin seals one copy again for one asker.
pub const MAX_RESEALS: u8 = 2;

/// A reader of a copy: its device ID, the epoch of its statement, and that
/// statement's sealing key.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Reader {
    pub id: DeviceId,
    pub epoch: u64,
    pub seal: Vec<u8>,
}

/// What a copy says about itself outside the content: its ID, its time on
/// the origin's hybrid clock, and its blob's size and hash when it has one.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Made {
    pub id: [u8; 16],
    pub time: Timestamp,
    pub blob: Option<(u64, [u8; 32])>,
}

/// How old a keys statement may be, by its time on the sender's clock,
/// and still be sealed to: 35 days. A device whose newest statement is
/// older is asleep; it asks for the copy sealed again when it is back.
pub const STATEMENT_MAX_AGE_MS: u64 = 35 * 86_400_000;

/// The devices a copy of this content is sealed to: each device of the
/// state that reads (and, for a secret, takes secrets, while the group's
/// rules allow secrets here), does not skip the content's type, is not a
/// watch (it reads through its phone) and not a leaf, and has a keys
/// statement that counts and, on a sender with a clock (`now_ms`), is not
/// older than [`STATEMENT_MAX_AGE_MS`] (a statement without a time, from a
/// device without a clock, has no age); the origin itself is left out. A
/// leaf is a reader only when the origin names it in `leaves` (the leaves
/// whose grants name the origin). At most 256, in the order of their IDs.
/// None while the group is stopped (`State::stopped`).
pub fn readers(
    state: &State,
    sealing: &BTreeMap<DeviceId, Sealing>,
    content: &Content,
    origin: &DeviceId,
    leaves: &[DeviceId],
    now_ms: Option<u64>,
) -> Vec<Reader> {
    let secret = content.is_secret();
    let skip_bit = content.kind.checked_sub(1).filter(|b| *b < 64).map_or(0, |b| 1u64 << b);
    let mut out = Vec::new();
    if state.stopped() {
        return out;
    }
    for d in &state.devices {
        let leaf = d.role == ROLE_LEAF;
        if d.id == *origin
            || d.frozen
            || d.rights & RIGHT_READ == 0
            || d.skip & skip_bit != 0
            || d.role == ROLE_WATCH
            || (leaf && !leaves.contains(&d.id))
            || state.nothing_to.contains(&d.id)
            || (secret && (d.rights & RIGHT_SECRETS == 0 || state.too_old || state.no_secrets_to.contains(&d.id)))
        {
            continue;
        }
        let Some(s) = sealing.get(&d.id) else { continue };
        let body = s.statement.body();
        if body.time_ms != 0 && now_ms.is_some_and(|now| now.saturating_sub(body.time_ms) > STATEMENT_MAX_AGE_MS) {
            continue;
        }
        out.push(Reader { id: d.id, epoch: body.epoch, seal: body.seal.public().to_vec() });
        if out.len() == fcopy::MAX_READERS {
            break;
        }
    }
    out
}

fn random<const N: usize>() -> Result<[u8; N], Error> {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).map_err(|_| Error::msg("copies: the system has no randomness"))?;
    Ok(b)
}

fn aead(key: &[u8; 32]) -> ChaCha20Poly1305 {
    ChaCha20Poly1305::new(key.into())
}

/// Seals content for readers and signs it with the origin's member key:
/// the copy's map, as message `copy` carries it in field 2.
pub fn seal(origin: &dyn ExternalKey, readers: &[Reader], made: &Made, content: &Content) -> Result<Vec<u8>, Error> {
    let mut seeds = Vec::with_capacity(readers.len());
    for _ in readers {
        seeds.push(random::<32>()?);
    }
    seal_with(origin, readers, made, content, &random::<32>()?, &seeds)
}

/// [`seal`] with K and the seals' randomness given: for the tests only.
#[doc(hidden)]
pub fn seal_with(
    origin: &dyn ExternalKey,
    readers: &[Reader],
    made: &Made,
    content: &Content,
    k: &[u8; 32],
    seeds: &[[u8; 32]],
) -> Result<Vec<u8>, Error> {
    if readers.is_empty() || readers.len() > fcopy::MAX_READERS || seeds.len() != readers.len() {
        return Err(Error::msg("a copy has 1 to 256 readers"));
    }
    if readers.windows(2).any(|w| matches!(w, [a, b] if a.id >= b.id)) {
        return Err(Error::msg("a copy's readers are sorted by ID, each once"));
    }
    let plain = content.write().ok_or_else(|| Error::msg("the content breaks its rows or is over 4 MiB"))?;
    seal_bytes(origin, readers, made, &plain, k, seeds)
}

/// [`seal_with`] of a content already encoded: for the tests only, which
/// seal content of a later version.
#[doc(hidden)]
pub fn seal_bytes(
    origin: &dyn ExternalKey,
    readers: &[Reader],
    made: &Made,
    plain: &[u8],
    k: &[u8; 32],
    seeds: &[[u8; 32]],
) -> Result<Vec<u8>, Error> {
    if made.time.wall <= 0 || !made.time.valid() {
        return Err(Error::msg("a copy's time is not on the clock"));
    }
    let origin_id = rkey::Key::es256(origin.public()).device_id();
    let entries: Vec<Value<'_>> =
        readers.iter().map(|r| Value::Array(alloc::vec![Value::Bytes(&r.id.0), Value::Uint(r.epoch)])).collect();
    let commit = fcopy::commit(k);
    let wall = u64::try_from(made.time.wall).map_err(|_| Error::msg("a copy's time is not on the clock"))?;
    let mut hm: Vec<(u16, Value<'_>)> = alloc::vec![
        (1, Value::Bytes(&made.id)),
        (2, Value::Bytes(&origin_id.0)),
        (3, Value::Array(alloc::vec![Value::Uint(wall), Value::Uint(u64::from(made.time.logical))])),
        (4, Value::Array(entries)),
    ];
    if let Some((size, hash)) = &made.blob {
        hm.push((5, Value::Array(alloc::vec![Value::Uint(*size), Value::Bytes(hash)])));
    }
    hm.push((6, Value::Bytes(&commit)));
    let hdr = Value::Map(hm).encode();
    let h = fcopy::header_hash(&hdr);
    let payload = aead(&fcopy::payload_key(k, &h))
        .encrypt(&Nonce::default(), Payload { msg: plain, aad: &h })
        .map_err(|_| Error::msg("copies: cannot seal the payload"))?;
    let mut wraps = Vec::with_capacity(readers.len());
    for (r, seed) in readers.iter().zip(seeds) {
        wraps.push(crate::seal::seal_with_seed(&r.seal, &h, k, *seed)?);
    }
    let hashes: Vec<[u8; 32]> = wraps.iter().map(|w| sha256(&[w])).collect();
    let signed = fcopy::signed(&h, &fcopy::wraps_digest(&hashes), &sha256(&[&payload]));
    let sig = rkey::sign_es256(origin, sig::LABEL_COPY_SIG, &signed)?;
    let copy = Value::Map(alloc::vec![
        (fcopy::FIELD_HDR, Value::Bytes(&hdr)),
        (fcopy::FIELD_WRAPS, Value::Array(wraps.iter().map(|w| Value::Bytes(w)).collect())),
        (fcopy::FIELD_PAYLOAD, Value::Bytes(&payload)),
        (fcopy::FIELD_SIG, Value::Bytes(&sig)),
    ]);
    Ok(copy.encode())
}

/// A copy checked on the way: its form, its origin a device of the records
/// with the right to send, and the origin's signature.
#[derive(Clone, Debug)]
pub struct Checked<'a> {
    pub copy: Copy<'a>,
    /// The copy's ID.
    pub id: [u8; 16],
    pub origin: DeviceId,
    /// Its time on the origin's hybrid clock, inside the signature.
    pub time: Timestamp,
    /// Its readers, `[device ID, epoch]`, in the header's order.
    pub readers: Vec<(DeviceId, u64)>,
}

/// What checking a copy needs of its origin: its member key, its rights
/// and whether it is frozen.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Origin<'a> {
    pub key: &'a rkey::Key,
    pub rights: u64,
    pub frozen: bool,
}

/// Finds a copy's origin by its device ID. The records' state is one; a
/// leaf, which builds no state, fills an [`OriginMap`] from its grant.
pub trait Origins {
    fn origin(&self, id: &DeviceId) -> Option<Origin<'_>>;
}

impl Origins for State {
    fn origin(&self, id: &DeviceId) -> Option<Origin<'_>> {
        self.device(id).map(|d| Origin { key: &d.key, rights: d.rights, frozen: d.frozen })
    }
}

/// The origins a leaf knows, by device ID (the first 16 bytes of the key's
/// hash).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OriginMap(BTreeMap<DeviceId, (rkey::Key, u64, bool)>);

impl OriginMap {
    /// Adds a device by its member key, with its rights and whether it is
    /// frozen.
    pub fn insert(&mut self, key: rkey::Key, rights: u64, frozen: bool) {
        self.0.insert(key.device_id(), (key, rights, frozen));
    }
}

impl Origins for OriginMap {
    fn origin(&self, id: &DeviceId) -> Option<Origin<'_>> {
        self.0.get(id).map(|(key, rights, frozen)| Origin { key, rights: *rights, frozen: *frozen })
    }
}

/// Checks a copy as every member does before it passes it on, a hub that
/// does not read included: the format's rows, the origin a device the
/// origins name that may send, and the signature by that device's member
/// key. A copy from a device they do not name is [`RULE_ORIGIN`]: it waits
/// for the records.
pub fn check<'a>(v: &Value<'a>, origins: &dyn Origins) -> Result<Checked<'a>, Rule> {
    let copy = Copy::from_value(v)?;
    let h = &copy.header;
    let bytes = |f| h.get(f).and_then(Value::as_bytes);
    let id: [u8; 16] = bytes(1).and_then(|b| b.try_into().ok()).ok_or(fcopy::RULE_SHAPE)?;
    let origin = bytes(2).and_then(DeviceId::from_slice).ok_or(fcopy::RULE_SHAPE)?;
    let time = match h.get(3).and_then(Value::as_array) {
        Some([Value::Uint(w), Value::Uint(l)]) => Timestamp {
            wall: i64::try_from(*w).map_err(|_| fcopy::RULE_SHAPE)?,
            logical: u32::try_from(*l).map_err(|_| fcopy::RULE_SHAPE)?,
        },
        _ => return Err(fcopy::RULE_SHAPE),
    };
    if !time.valid() {
        return Err(RULE_TIME);
    }
    let readers = h
        .get(fcopy::HDR_READERS)
        .and_then(Value::as_array)
        .unwrap_or(&[])
        .iter()
        .filter_map(|r| match r.as_array() {
            Some([Value::Bytes(id), Value::Uint(e)]) => DeviceId::from_slice(id).map(|d| (d, *e)),
            _ => None,
        })
        .collect();
    let d = origins.origin(&origin).ok_or(RULE_ORIGIN)?;
    if d.rights & RIGHT_SEND == 0 || d.frozen {
        return Err(RULE_SEND);
    }
    copy.verify(d.key.public())?;
    Ok(Checked { copy, id, origin, time, readers })
}

/// What a reader found in a copy.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Opened {
    /// The content, and the blob key when the copy has a blob.
    Content { content: Content, blob_key: Option<[u8; 32]> },
    /// The copy is not sealed to this device: it is passed on, never
    /// written.
    NotForMe,
    /// Sealed to an epoch this device no longer holds: it asks the origin
    /// to seal it again ([`reseal_request`]).
    Reseal { epoch: u64 },
    /// A mark or a reduced copy without the payload: the reader fetches it.
    NoPayload,
    /// A secret while this device's rules are too old for the group
    /// (format 3.3): opened only to learn that, then dropped.
    TooOld,
    /// The group is stopped here (`State::stopped`): no copy is opened.
    Halted,
}

/// Opens a checked copy as the reader me: its own wrap with the sealing
/// secret of the wrap's epoch, then `commit` against K before anything
/// else, then the payload under `h`, then the content's rows. A secret is
/// never given while the state says this device's rules are too old, and
/// nothing is opened while the group is stopped.
pub fn open(c: &Checked<'_>, me: &DeviceId, store: &dyn KeyStore, state: &State) -> Result<Opened, Rule> {
    if state.stopped() {
        return Ok(Opened::Halted);
    }
    let Some(i) = c.readers.iter().position(|(d, _)| d == me) else { return Ok(Opened::NotForMe) };
    let (_, epoch) = c.readers.get(i).copied().ok_or(fcopy::RULE_SHAPE)?;
    let wrap = c.copy.wraps.get(i).copied().ok_or(fcopy::RULE_SHAPE)?;
    if wrap.len() != fcopy::WRAP_SIZE {
        return Err(fcopy::RULE_SHAPE);
    }
    let Some(secret) = store.sealing(epoch) else { return Ok(Opened::Reseal { epoch }) };
    let k: [u8; 32] =
        crate::seal::open(&secret, &c.copy.h, wrap).ok().and_then(|k| k.try_into().ok()).ok_or(RULE_WRAP)?;
    c.copy.check_commit(&k)?;
    let Some(payload) = c.copy.payload else { return Ok(Opened::NoPayload) };
    let plain = aead(&fcopy::payload_key(&k, &c.copy.h))
        .decrypt(&Nonce::default(), Payload { msg: payload, aad: &c.copy.h })
        .map_err(|_| RULE_PAYLOAD)?;
    let content = Content::read(&plain)?;
    if content.is_secret() && state.too_old {
        return Ok(Opened::TooOld);
    }
    let blob_key = c.copy.header.get(5).map(|_| fcopy::blob_key(&k, &c.copy.h));
    Ok(Opened::Content { content, blob_key })
}

fn rewrite(c: &Copy<'_>, wraps: Vec<Value<'_>>, payload: Option<&[u8]>, age_ms: u64) -> Vec<u8> {
    let mut m: Vec<(u16, Value<'_>)> = alloc::vec![(fcopy::FIELD_HDR, Value::Bytes(c.hdr))];
    if age_ms != 0 {
        m.push((fcopy::FIELD_AGE, Value::Uint(age_ms)));
    }
    m.push((fcopy::FIELD_WRAPS, Value::Array(wraps)));
    match payload {
        Some(p) => m.push((fcopy::FIELD_PAYLOAD, Value::Bytes(p))),
        None => m.push((fcopy::FIELD_PAYLOAD_HASH, Value::Bytes(&c.p))),
    }
    m.push((fcopy::FIELD_SIG, Value::Bytes(c.sig)));
    Value::Map(m).encode()
}

/// A secret's mark: the copy with the payload's hash in place of the
/// payload. The signature still verifies; a reader that has seen the copy's
/// ID ignores it.
pub fn mark(c: &Copy<'_>) -> Vec<u8> {
    rewrite(c, c.wraps.iter().map(|w| Value::Bytes(w)).collect(), None, c.age_ms)
}

/// The frame of message `copy` carrying copy.
pub fn message(copy: &[u8]) -> Result<Vec<u8>, Rule> {
    let v = cbor::decode(copy)?;
    Ok(frame::write(&Value::Map(alloc::vec![(frame::FIELD_T, Value::Uint(T_COPY)), (2, v)])))
}

/// The largest frame a peer sends to device d: 16 KiB to a leaf (A-4), which
/// a peer learns from the leaf's record and never exceeds, 7 MiB to any
/// other member.
pub fn frame_limit(d: &DeviceState) -> usize {
    if d.role == ROLE_LEAF { frame::LIMIT_LEAF } else { frame::LIMIT_MEMBER }
}

/// The reduced copy for a leaf (A-4): its own wrap whole, the other readers'
/// wraps as their hashes, and the payload whole only when message `copy`
/// then fits the leaf's 16 KiB frame (else its hash, and the leaf fetches
/// it). The leaf checks the signature from this copy alone. A copy whose
/// reduced message is still over 16 KiB, or that is not sealed to the leaf,
/// is not sent to it.
pub fn reduce(c: &Copy<'_>, readers: &[(DeviceId, u64)], leaf: &DeviceId) -> Result<Vec<u8>, Rule> {
    if !readers.iter().any(|(d, _)| d == leaf) {
        return Err(RULE_LEAF_FRAME);
    }
    let wraps: Vec<[u8; 32]> =
        c.wraps.iter().map(|w| if w.len() == 32 { (*w).try_into().unwrap_or([0; 32]) } else { sha256(&[w]) }).collect();
    let mut values = Vec::with_capacity(c.wraps.len());
    for ((d, _), (w, hash)) in readers.iter().zip(c.wraps.iter().zip(&wraps)) {
        values.push(if d == leaf { Value::Bytes(w) } else { Value::Bytes(hash) });
    }
    let whole = rewrite(c, values.clone(), c.payload, c.age_ms);
    let fits = |b: &[u8]| message(b).is_ok_and(|f| f.len() <= frame::LIMIT_LEAF);
    if c.payload.is_some() && fits(&whole) {
        return Ok(whole);
    }
    let hashed = rewrite(c, values, None, c.age_ms);
    if fits(&hashed) { Ok(hashed) } else { Err(RULE_LEAF_FRAME) }
}

/// Message `reseal` (t 23): "seal copy `id` to me again, at my current
/// epoch".
pub fn reseal_request(id: &[u8; 16], epoch: u64) -> Vec<u8> {
    frame::write(&Value::Map(alloc::vec![
        (frame::FIELD_T, Value::Uint(T_RESEAL)),
        (2, Value::Bytes(id)),
        (3, Value::Uint(epoch)),
    ]))
}

/// What the origin keeps of a copy it made, to seal it again on request.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Kept {
    pub made: Made,
    pub content: Content,
    /// The devices it was sealed to.
    pub readers: Vec<DeviceId>,
    /// How many times it was sealed again for each asker.
    pub resealed: BTreeMap<DeviceId, u8>,
}

impl Kept {
    /// What the origin keeps of a copy it just sealed to readers.
    pub fn new(made: Made, content: Content, readers: &[Reader]) -> Kept {
        Kept { made, content, readers: readers.iter().map(|r| r.id).collect(), resealed: BTreeMap::new() }
    }

    /// The copy's lifetime: its own `ttl`, or for a secret the group's.
    /// None: a copy that lives as long as the group keeps copies.
    pub fn life_ms(&self, group_ttl_ms: u64) -> Option<u64> {
        self.content.ttl_ms().or(self.content.is_secret().then_some(group_ttl_ms))
    }
}

/// A request to seal a copy again, as the origin sees it.
#[derive(Clone, Copy, Debug)]
pub struct Ask<'a> {
    /// The device that asked.
    pub asker: DeviceId,
    /// The epoch it asked at.
    pub epoch: u64,
    /// The leaves the origin seals to, as for [`readers`].
    pub leaves: &'a [DeviceId],
    /// The origin's clock, None without one.
    pub now_ms: Option<u64>,
    /// The group's lifetime of a secret without its own `ttl`.
    pub group_ttl_ms: u64,
}

/// Seals a kept copy again for the asker at its epoch (message `reseal`),
/// never while the group is stopped ([`RULE_RESEAL_HALTED`]):
/// only for a device that was one of the copy's readers
/// ([`RULE_RESEAL_READER`]), whose statement that counts is of that epoch
/// ([`RULE_RESEAL_EPOCH`]), and that would still be sealed this copy by the
/// state now; never a copy past its lifetime, and never a copy with a
/// lifetime on an origin without a clock ([`RULE_RESEAL_EXPIRED`]); at most
/// [`MAX_RESEALS`] times for one asker ([`RULE_RESEAL_LIMIT`]). The new
/// copy has the same ID, origin and time, the asker as its one reader, and
/// a new K. A member that holds the first copy keeps it for its other
/// readers and passes this one on to the asker ([`second`]).
pub fn reseal(
    origin: &dyn ExternalKey,
    kept: &mut Kept,
    state: &State,
    sealing: &BTreeMap<DeviceId, Sealing>,
    ask: &Ask<'_>,
) -> Result<Vec<u8>, Rule> {
    if state.stopped() {
        return Err(RULE_RESEAL_HALTED);
    }
    if !kept.readers.contains(&ask.asker) {
        return Err(RULE_RESEAL_READER);
    }
    if let Some(life) = kept.life_ms(ask.group_ttl_ms) {
        let now = ask.now_ms.ok_or(RULE_RESEAL_EXPIRED)?;
        let made = u64::try_from(kept.made.time.wall).unwrap_or(0);
        if now.saturating_sub(made) >= life {
            return Err(RULE_RESEAL_EXPIRED);
        }
    }
    let done = kept.resealed.get(&ask.asker).copied().unwrap_or(0);
    if done >= MAX_RESEALS {
        return Err(RULE_RESEAL_LIMIT);
    }
    let me = rkey::Key::es256(origin.public()).device_id();
    let now = readers(state, sealing, &kept.content, &me, ask.leaves, ask.now_ms);
    let r = now.into_iter().find(|r| r.id == ask.asker).ok_or(RULE_RESEAL_READER)?;
    if r.epoch != ask.epoch {
        return Err(RULE_RESEAL_EPOCH);
    }
    let sealed = seal(origin, &[r], &kept.made, &kept.content).map_err(|_| fcopy::RULE_SHAPE)?;
    kept.resealed.insert(ask.asker, done.saturating_add(1));
    Ok(sealed)
}

/// What a member that holds a copy does with a second one of the same ID.
/// A copy is known by its origin and ID: a copy of another origin with
/// that ID is another copy, held on its own.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Second {
    /// Another origin's copy: not this one, held and judged on its own.
    Another,
    /// The same copy again, or one that claims its origin and ID at another
    /// time: dropped. The first stays as it is.
    Drop,
    /// The copy sealed again for these readers: passed on to them, and
    /// never written over the first, which stays for its other readers.
    Pass { to: Vec<DeviceId> },
}

/// Judges a second checked copy with the ID of a first one held here. Both
/// passed [`check`], so both are signed by their origin.
pub fn second(first: &Checked<'_>, again: &Checked<'_>) -> Second {
    if first.origin != again.origin || first.id != again.id {
        return Second::Another;
    }
    if first.time != again.time || first.copy.hdr == again.copy.hdr {
        return Second::Drop;
    }
    Second::Pass { to: again.readers.iter().map(|(d, _)| *d).collect() }
}
