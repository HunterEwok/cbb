// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The blind relay (docs/design.md, "Blind relay"; docs/protocol.md,
//! section 14), the Rust twin of Go's internal/relay: a meeting point for a
//! group that has no computer to be its hub, on a server the user runs. It
//! holds none of the group's keys. cbb-relay runs it as a service of its
//! own, apart from cbb and the keys of cbb-helper.

pub mod budget;
pub mod command;
pub mod keys;
pub mod limits;
pub mod records;
pub mod register;
pub mod server;
pub mod wire;

pub use server::{Config, Relay};
