// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! What the service carries out of a paste or an action order that another
//! member signed (docs/format.md, section 6), and the name of the records
//! file a group made before 0.6 left in the state directory, which the
//! service moves aside (D-126).

/// A paste or an action order as the service carries it out.
#[derive(Clone, Debug, Default)]
pub struct Command {
    /// The command's ID, in hex.
    pub id: String,
    /// The signer's device ID, for showing.
    pub by: String,
    /// In a paste: `paste` or `type`.
    pub mode: String,
    /// In a paste: press Enter after the text.
    pub enter: bool,
    /// In a paste: `text`, `secret` or `media`.
    pub paste_kind: String,
    /// In a paste: the text; in one of kind `media`, the ID of the group's
    /// copy of images or files it pastes, in hex.
    pub text: String,
    /// In an action: the name of the action, which the receiver defines.
    pub action: String,
}

/// The name of the records file in the state directory.
pub const FILE_NAME: &str = "records.json";
