// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The records' exchange on a member connection of 0.6 (docs/protocol.md,
//! section 9.2, and section 10, "Sync"), without I/O: the caller reads
//! frames from the connection, hands each message to [`Exchange::take`]
//! with the device's set, sends the frames it gets back and saves the set
//! when it changed. The steps are the ones the core's simulator runs:
//!
//! - Each side opens with a `hello` that carries its set digest, and sends
//!   one again after every change of its set ([`hello`]), so two connected
//!   members whose sets differ go on until the digests are equal, never
//!   stopping because nothing was asked.
//! - A side whose digest differs from the peer's hello answers with `have`:
//!   the IDs it gives that peer (`RecordSet::for_peer`).
//! - On every hello it also asks with `want` for what its own records name
//!   and it lacks (`RecordSet::missing`) and for the list a change of root
//!   waits for (`RecordSet::missing_list`); on a `have`, for the IDs it
//!   lacks.
//! - A `want` is answered with `records`, built only from
//!   `RecordSet::for_peer_by_id` and `RecordSet::lists_for_peer`.
//! - The records taken are inserted part by part (`RecordSet::take_part`);
//!   a peer that gets only a root fork's proof gives only that
//!   (`RecordSet::insert_proof`).
//!
//! A connection answers at most [`MAX_ROUNDS`] hellos whose digest differs;
//! past that it stops and says so once ([`Out::stuck`]), so a fault in the
//! rules shows in the log with both digests instead of a loop.

use cbb_core::format::cbor::Value;
use cbb_core::format::frame;
use cbb_core::join::welcome;
use cbb_core::msg::member as m;
use cbb_core::peer::{Standing, standing};
use cbb_core::records::body::List;
use cbb_core::records::sync::{self, HAVE_IDS};
use cbb_core::records::{KeyHash, Record, RecordId, RecordSet};

use crate::error::{Error, Result};

/// How many hellos whose digest differs one connection answers.
pub const MAX_ROUNDS: u32 = 64;

/// What a message gave: the frames to send back, whether the set changed
/// (save it, then send [`hello`] on every connection), and the type of a
/// message this exchange does not read, for the caller.
#[derive(Debug, Default)]
pub struct Out {
    pub send: Vec<Vec<u8>>,
    pub changed: bool,
    pub other: Option<u64>,
    /// The round bound was passed on this message: the peer's digest and
    /// ours, for the log.
    pub stuck: Option<([u8; 32], [u8; 32])>,
}

/// One connection's side of the exchange.
pub struct Exchange {
    own: KeyHash,
    peer: [u8; 65],
    peer_hash: KeyHash,
    rounds: u32,
    stuck: bool,
}

/// The frame of a message of type t with fields.
fn write(t: u64, mut fields: Vec<(u16, Value<'_>)>) -> Vec<u8> {
    fields.insert(0, (frame::FIELD_T, Value::Uint(t)));
    frame::write(&Value::Map(fields))
}

/// The hello's fields this exchange fills: the set digest and the count of
/// records. The caller adds the rest of section 9.3 with [`hello_with`].
pub fn hello(set: &RecordSet) -> Vec<u8> {
    hello_with(set, Vec::new())
}

/// The hello with the set's fields and the caller's (keys above 8, in
/// order).
pub fn hello_with(set: &RecordSet, extra: Vec<(u16, Value<'_>)>) -> Vec<u8> {
    let digest = set.digest();
    let mut fields = vec![(7, Value::Bytes(&digest))];
    if !set.is_empty() {
        fields.push((8, Value::Uint(set.len() as u64)));
    }
    fields.extend(extra);
    write(m::T_HELLO, fields)
}

impl Exchange {
    /// The exchange with the peer whose member key TLS showed, for the
    /// device whose key hash is own.
    pub fn new(own: KeyHash, peer: [u8; 65]) -> Exchange {
        let peer_hash = cbb_core::records::Key::es256(peer.to_vec()).hash();
        Exchange { own, peer, peer_hash, rounds: 0, stuck: false }
    }

    /// Takes one message (a frame's message, as `frame::read` gives it).
    pub fn take(&mut self, set: &mut RecordSet, msg: &[u8]) -> Result<Out> {
        let (t, v, _) = cbb_core::msg::read_noted(msg).map_err(|r| Error::msg(format!("a message breaks {r}")))?;
        let mut out = Out::default();
        match t {
            m::T_HELLO => self.on_hello(set, &v, &mut out),
            m::T_HAVE => {
                let ids: Vec<RecordId> = ids_of(v.get(2));
                let lacking: Vec<RecordId> = ids.into_iter().filter(|id| !set.contains(id)).collect();
                want(&lacking, None, &mut out);
            }
            m::T_WANT => {
                let ids = ids_of(v.get(2));
                let list = v.get(3).and_then(Value::as_bytes).and_then(|b| <[u8; 32]>::try_from(b).ok());
                self.answer(set, &ids, list, &mut out);
            }
            welcome::T_RECORDS => {
                let (records, lists) = welcome::read_part(&v).map_err(|r| Error::msg(format!("records break {r}")))?;
                out.changed = self.insert(set, records, &lists);
            }
            other => out.other = Some(other),
        }
        Ok(out)
    }

    fn standing(&self, set: &RecordSet) -> Standing {
        standing(&set.state(), &self.own, &self.peer)
    }

    fn on_hello(&mut self, set: &mut RecordSet, v: &Value<'_>, out: &mut Out) {
        let ours = set.digest();
        let theirs = v.get(7).and_then(Value::as_bytes).and_then(|b| <[u8; 32]>::try_from(b).ok());
        let state = set.state();
        if theirs.is_some_and(|d| d != ours) {
            if self.rounds >= MAX_ROUNDS {
                if !self.stuck {
                    self.stuck = true;
                    out.stuck = theirs.map(|d| (d, ours));
                }
                return;
            }
            self.rounds = self.rounds.saturating_add(1);
            let given: Vec<RecordId> = set.for_peer(&state, &self.peer_hash).iter().map(|r| r.id()).collect();
            for part in sync::have_parts(given.iter()) {
                let ids: Vec<Value<'_>> = part.iter().map(|id| Value::Bytes(&id.0)).collect();
                if !ids.is_empty() {
                    out.send.push(write(m::T_HAVE, vec![(2, Value::Array(sorted(ids)))]));
                }
            }
        }
        // Equal digests say nothing of what both lack: what its records
        // name and the list it waits for, it still asks.
        let lacking = set.missing(&state);
        want(&lacking, set.missing_list(), out);
    }

    fn answer(&self, set: &RecordSet, ids: &[RecordId], list: Option<[u8; 32]>, out: &mut Out) {
        let state = set.state();
        let records: Vec<&Record> =
            ids.iter().filter_map(|id| set.for_peer_by_id(&state, &self.peer_hash, id)).collect();
        let lists: Vec<&[u8]> = match list {
            Some(h) => set
                .lists_for_peer(&state, &self.peer_hash)
                .into_iter()
                .filter(|l| List::of(l, &h).is_some())
                .take(1)
                .collect(),
            None => Vec::new(),
        };
        for part in sync::split(&records, &lists, sync::PART_RECORDS, sync::PART_BYTES) {
            out.send.push(welcome::part_message(&part));
        }
    }

    fn insert(&self, set: &mut RecordSet, records: Vec<Record>, lists: &[Vec<u8>]) -> bool {
        let before = set.digest();
        if self.standing(set) == Standing::ForkProof {
            for r in records {
                let _ = set.insert_proof(r);
            }
        } else {
            let lists: Vec<&[u8]> = lists.iter().map(Vec::as_slice).collect();
            set.take_part(&records, &lists);
        }
        set.digest() != before
    }
}

/// The record IDs of a set field, as a reader took it.
fn ids_of(v: Option<&Value<'_>>) -> Vec<RecordId> {
    v.and_then(Value::as_array)
        .unwrap_or(&[])
        .iter()
        .filter_map(|x| x.as_bytes().and_then(|b| <[u8; 32]>::try_from(b).ok()).map(RecordId))
        .collect()
}

/// IDs sorted by their bytes, each once, as a set field is written.
fn sorted(mut ids: Vec<Value<'_>>) -> Vec<Value<'_>> {
    ids.sort_by(|a, b| a.as_bytes().cmp(&b.as_bytes()));
    ids.dedup_by(|a, b| a.as_bytes() == b.as_bytes());
    ids
}

/// Asks for ids and list, in messages of at most HAVE_IDS IDs each.
fn want(ids: &[RecordId], list: Option<[u8; 32]>, out: &mut Out) {
    let mut chunks: Vec<&[RecordId]> = ids.chunks(HAVE_IDS).collect();
    if chunks.is_empty() && list.is_some() {
        chunks.push(&[]);
    }
    for (i, chunk) in chunks.iter().enumerate() {
        let mut fields = Vec::new();
        if !chunk.is_empty() {
            fields.push((2, Value::Array(sorted(chunk.iter().map(|id| Value::Bytes(&id.0)).collect()))));
        }
        if i == 0
            && let Some(h) = &list
        {
            fields.push((3, Value::Bytes(h)));
        }
        out.send.push(write(m::T_WANT, fields));
    }
}

#[cfg(test)]
mod tests;
