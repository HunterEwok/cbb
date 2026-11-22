// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The body of a command (orders between members) and its device names,
//! and the name of the records file a group made before 0.6 left in the
//! state directory, which the service moves aside (D-126).

pub use cbb_core::command::{Command, valid_name};

/// The name of the records file in the state directory.
pub const FILE_NAME: &str = "records.json";
