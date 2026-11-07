// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The identity in the state directory, in identity.json (the format of the
//! Go member's file, see cbb_core::identity).

use std::path::Path;

pub use cbb_core::identity::*;

use crate::error::{Error, Result, Wrap};
use crate::files;

/// The name of the identity file in the state directory.
pub const FILE_NAME: &str = "identity.json";

/// Reading and writing the identity file.
pub trait Stored: Sized {
    /// Writes the identity to dir/identity.json, readable only by its
    /// owner, replacing the file in one step.
    fn save(&self, dir: &Path) -> Result<()>;
    /// Reads the identity from dir/identity.json; None if there is none.
    fn load(dir: &Path) -> Result<Option<Self>>;
}

impl Stored for Identity {
    fn save(&self, dir: &Path) -> Result<()> {
        files::write_atomic(&dir.join(FILE_NAME), &self.to_file()?, 0o600)
    }

    fn load(dir: &Path) -> Result<Option<Identity>> {
        let path = dir.join(FILE_NAME);
        let data = match std::fs::read(&path) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(Error::with(format!("cannot read {}", path.display()), e)),
        };
        let id = Identity::from_file(&data).wrap(format!("{} is damaged", path.display()))?;
        Ok(Some(id))
    }
}
