// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The identity in the state directory, in identity.json (the format of the
//! Go member's file, see cbb_core::identity). A device key in the TPM or the
//! Secure Enclave opens through cbb-helper (keys.rs). The parts only an
//! admin holds (the group CA key on the computer that made the group, an
//! admin key and its CA, a claim) stay in the file as Go writes them: the
//! core's identity leaves them out, and admin.rs reads them.

use std::path::Path;

pub use cbb_core::identity::*;

use crate::error::{Error, Result, Wrap};

/// The name of the identity file in the state directory.
pub const FILE_NAME: &str = "identity.json";

/// Reading and writing the identity file.
pub trait Stored: Sized {
    /// Reads the identity from dir/identity.json; None if there is none.
    fn load(dir: &Path) -> Result<Option<Self>>;
}

impl Stored for Identity {
    fn load(dir: &Path) -> Result<Option<Identity>> {
        let path = dir.join(FILE_NAME);
        let data = match std::fs::read(&path) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(Error::with(format!("cannot read {}", path.display()), e)),
        };
        let id = Identity::from_file_with(&data, &crate::keys::open).wrap(format!("{} is damaged", path.display()))?;
        Ok(Some(id))
    }
}
