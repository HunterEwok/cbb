// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The glue between the simulated members: what one member sends another
//! in a round of sync, and how the other takes it. It stands in for the
//! member protocol's sync until wave 5 gives the core a sans-I/O
//! connection; the simulator calls only `offer` and `take`, so that the
//! real exchange replaces this module and nothing else.
//!
//! A sender gives a peer what `RecordSet::for_peer` gives it (all of its
//! records to a device of the group, only the removals that name it to a
//! removed one, nothing to a stranger), the lists of the changes of root
//! and the keys statements to a device, and the copies it holds to a
//! device that is not removed. A receiver takes records from anyone, as
//! they are signed: records, then lists, then records again, so that the
//! records a change of root's list keeps are taken once the list is.

use alloc::vec::Vec;

use crate::records::eval::State;
use crate::records::{KeyHash, Record, RecordSet};

/// One message of sync from one member to another.
#[derive(Clone, Debug, Default)]
pub struct Offer {
    /// Record envelopes, in the order of their dependencies.
    pub records: Vec<Vec<u8>>,
    /// The lists of the changes of root, as they came.
    pub lists: Vec<Vec<u8>>,
    /// Keys statement envelopes.
    pub statements: Vec<Vec<u8>>,
    /// Copies, each a copy's map as message `copy` carries it.
    pub copies: Vec<Vec<u8>>,
}

/// What a sender with this set and state gives the peer whose member key
/// is peer; statements and copies are the sender's to give.
pub fn offer(set: &RecordSet, state: &State, peer: &KeyHash, statements: &[Vec<u8>], copies: &[Vec<u8>]) -> Offer {
    let records = set.for_peer(state, peer).into_iter().map(Record::envelope).collect();
    let device = state.device_by_key(peer).is_some();
    if !device {
        return Offer { records, ..Offer::default() };
    }
    Offer {
        records,
        lists: set.lists().map(<[u8]>::to_vec).collect(),
        statements: statements.to_vec(),
        copies: copies.to_vec(),
    }
}

/// What taking an offer did to the set.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Took {
    /// Records that were new.
    pub records: usize,
    /// Lists that were new.
    pub lists: usize,
}

/// Takes an offer's records and lists into set: records, lists, records.
/// A record that does not decode, or that the set refuses, is left out,
/// as a member drops it; the simulator's checks find what that costs.
pub fn take(set: &mut RecordSet, offer: &Offer) -> Took {
    let records: Vec<Record> = offer.records.iter().filter_map(|e| Record::decode(e).ok()).collect();
    let before = set.len();
    let mut took = Took::default();
    set.insert_all(records.iter().cloned());
    for l in &offer.lists {
        if set.insert_list(l) == Ok(true) {
            took.lists += 1;
        }
    }
    set.insert_all(records);
    took.records = set.len().saturating_sub(before);
    took
}
