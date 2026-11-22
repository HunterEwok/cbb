// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The group's records in the state directory, in records.json.

pub use cbb_core::authority::Record;
pub use cbb_core::command::{Command, valid_name};
pub use cbb_core::group::*;

/// The name of the records file in the state directory.
pub const FILE_NAME: &str = "records.json";
