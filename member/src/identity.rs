// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The device's keys as the core holds them (cbb_core::identity), and the
//! name of the identity file of a group made before 0.6, which marks such a
//! group until the device leaves it (D-126).

pub use cbb_core::identity::*;

/// The name of the identity file in the state directory.
pub const FILE_NAME: &str = "identity.json";
