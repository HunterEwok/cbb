// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! What servers (the forwarder and the relay) see of a group in 0.6: only
//! blind credentials (A-71, design-no-certificates section 6). A server
//! never sees the root, the records or a device ID: it sees a period's tag
//! and keys and the hashes of server keys. There is no way by records.
//!
//! - `credential`: the server credentials (format section 8): `period`
//!   (the root gives a period key and tag), `server` (a device's server key
//!   for the period), `hubs` and `members` (the period key lists the
//!   server keys a server takes).
//! - `card`: a server card (A-54), which an operator signs so that a
//!   server not of the project changes its keys and addresses without
//!   anyone typing them.
//! - `alias`: a group shows each server another tag and period key (A-55),
//!   so that two operators cannot tell they serve one group.

pub mod alias;
pub mod card;
pub mod credential;

#[cfg(test)]
mod tests;
