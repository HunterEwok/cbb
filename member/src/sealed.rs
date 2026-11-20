// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Copies of 0.6 on a member (format section 10, `cbb_core::copies`): the
//! keys statements it holds of the group's devices and passes on in
//! message `keys`, a copy sealed to the group's readers, and a copy that
//! arrives checked, passed on, opened and judged. Every rule is the
//! core's: who reads, the seal, the signature, the wrap and the freshness
//! of what opened. What the clipboard then does with new content
//! (`cbb_core::rule::incoming`) stays with the caller.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use cbb_core::content::Content;
use cbb_core::copies::{self, Made, Opened, fresh};
use cbb_core::format::cbor::Value;
use cbb_core::format::frame;
use cbb_core::hlc::Timestamp;
use cbb_core::identity::ExternalKey;
use cbb_core::keystore::{KeyStore, ReadStatement, read_statement};
use cbb_core::msg::wave4::T_KEYS;
use cbb_core::records::statement::{self, Sealing, Statement};
use cbb_core::records::{DeviceId, State};
use serde::{Deserialize, Serialize};

use crate::error::{Context, Error, Result};
use crate::files;

/// The statements file's name in the state directory.
pub const FILE_NAME: &str = "statements.json";

/// The most statements kept: two epochs of each of 256 devices, and room
/// for statements held for a later version.
pub const MAX_KEPT: usize = 1024;

/// The keys statements a member holds of the group's devices, its own
/// among them, by ID.
pub struct Statements {
    path: PathBuf,
    taken: BTreeMap<[u8; 32], Statement>,
    /// Statements of a later version, kept and passed on, never counted.
    held: BTreeMap<[u8; 32], Vec<u8>>,
}

#[derive(Serialize, Deserialize)]
struct File {
    v: u32,
    statements: Vec<String>,
}

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

impl Statements {
    /// The statements kept in dir; none when the file is not there.
    pub fn load(dir: &Path) -> Result<Statements> {
        let mut s = Statements { path: dir.join(FILE_NAME), taken: BTreeMap::new(), held: BTreeMap::new() };
        let data = match std::fs::read(&s.path) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(s),
            Err(e) => return Err(Error::with(format!("cannot read {}", s.path.display()), e)),
        };
        let f: File = serde_json::from_slice(&data).context(format!("{} is damaged", s.path.display()))?;
        if f.v != 1 {
            return Err(Error::msg(format!("{} is of unknown version {}", s.path.display(), f.v)));
        }
        for e in f.statements {
            let env = b64().decode(&e).context(format!("{} is damaged", s.path.display()))?;
            // A statement the file holds was read once; one that no longer
            // reads is left out rather than stopping the device.
            let _ = s.add(&env);
        }
        Ok(s)
    }

    /// Keeps the statements in their file.
    pub fn save(&self) -> Result<()> {
        let statements = self.envelopes().iter().map(|e| b64().encode(e)).collect();
        let data = serde_json::to_vec_pretty(&File { v: 1, statements }).context("cannot encode the statements")?;
        files::write_atomic(&self.path, &data, 0o600)
    }

    /// Adds one statement by its envelope: true when it is new here. Its
    /// signature is checked against its device when it is counted
    /// (`statement::choose`), since the device may arrive after it.
    pub fn add(&mut self, envelope: &[u8]) -> Result<bool> {
        if self.taken.len() + self.held.len() >= MAX_KEPT {
            return Err(Error::msg("too many keys statements are kept"));
        }
        match read_statement(envelope).map_err(|r| Error::msg(format!("a keys statement breaks {r}")))? {
            ReadStatement::Take(s) => Ok(self.taken.insert(s.id().0, s).is_none()),
            ReadStatement::Held { id, envelope } => Ok(self.held.insert(id, envelope).is_none()),
        }
    }

    /// Takes message `keys` (its body): how many statements were new.
    pub fn take_message(&mut self, msg: &[u8]) -> Result<usize> {
        let (t, v, _) = cbb_core::msg::read_noted(msg).map_err(|r| Error::msg(format!("message keys breaks {r}")))?;
        if t != T_KEYS {
            return Err(Error::msg("not message keys"));
        }
        let mut new = 0;
        for e in v.get(2).and_then(Value::as_array).unwrap_or(&[]) {
            // Each statement rides as its envelope's value, `[body, sig]`.
            if self.add(&e.encode())? {
                new += 1;
            }
        }
        Ok(new)
    }

    /// The statement that counts for each device of the state.
    pub fn sealing(&self, state: &State) -> BTreeMap<DeviceId, Sealing> {
        statement::choose(state, self.taken.values())
    }

    /// Drops what no longer counts: a statement of a device that is gone,
    /// or of an epoch below the one that counts for its device. Held
    /// statements stay.
    pub fn prune(&mut self, state: &State) {
        let counting = self.sealing(state);
        self.taken.retain(|_, s| {
            state.device_by_key(&s.body().signer).is_some_and(|d| {
                counting.get(&d.id).is_some_and(|c| s.body().epoch >= c.statement.body().epoch.saturating_sub(1))
            })
        });
    }

    fn envelopes(&self) -> Vec<Vec<u8>> {
        self.taken.values().map(Statement::envelope).chain(self.held.values().cloned()).collect()
    }

    /// The frames of message `keys` carrying every statement kept, to send
    /// to a peer when a connection opens and after a new one arrives.
    pub fn messages(&self) -> Vec<Vec<u8>> {
        let envs = self.envelopes();
        let refs: Vec<&[u8]> = envs.iter().map(Vec::as_slice).collect();
        statement::keys_messages(&refs)
            .into_iter()
            .map(|part| {
                let list = part.into_iter().filter_map(|e| cbb_core::format::cbor::decode(e).ok()).collect();
                frame::write(&Value::Map(vec![(frame::FIELD_T, Value::Uint(T_KEYS)), (2, Value::Array(list))]))
            })
            .collect()
    }
}

/// A copy this device makes of content, sealed to the group's readers and
/// signed with its member key: the frame of message `copy`, and what the
/// device keeps to seal it again on request. None when the group has no
/// reader for it.
pub fn make(
    member: &dyn ExternalKey,
    state: &State,
    statements: &Statements,
    content: &Content,
    time: Timestamp,
    now_ms: Option<u64>,
) -> Result<Option<(Vec<u8>, copies::Kept)>> {
    let me = cbb_core::records::Key::es256(member.public()).device_id();
    let sealing = statements.sealing(state);
    let readers = copies::readers(state, &sealing, content, &me, &[], now_ms);
    if readers.is_empty() {
        return Ok(None);
    }
    let mut id = [0u8; 16];
    getrandom::fill(&mut id).map_err(|_| Error::msg("the system has no randomness"))?;
    let made = Made { id, time, blob: None };
    let copy = copies::seal(member, &readers, &made, content).map_err(|e| e.context("cannot seal the copy"))?;
    let frame = copies::message(&copy).map_err(|r| Error::msg(format!("the copy breaks {r}")))?;
    Ok(Some((frame, copies::Kept::new(made, content.clone(), &readers))))
}

/// The lifetimes a copy is judged by: the group's lifetime of secrets and
/// its window for incoming copies.
#[derive(Clone, Copy, Debug)]
pub struct Lifetimes {
    pub secret_ms: u64,
    pub incoming_ms: u64,
}

/// What became of a copy that arrived.
#[derive(Debug)]
pub enum Taken {
    /// New content for this device: the caller applies the rule of
    /// incoming copies with its age, then calls `Marks::wrote` when it
    /// writes it.
    New { content: Content, origin: DeviceId, signed: Timestamp, age_ms: u64 },
    /// Opened, but not newer than what was written here, a secret seen
    /// before, or signed ahead of this clock.
    Old(fresh::Fresh),
    /// Not sealed to this device, a mark, or nothing to open here: passed
    /// on only.
    PassedOn,
    /// Sealed to an epoch this device no longer holds: send this frame of
    /// message `reseal` to the origin.
    Reseal(Vec<u8>),
    /// A secret while this device's rules are too old, or a group stopped
    /// here: dropped.
    Dropped,
}

/// Takes message `copy` (its body): checks it as every member does,
/// opens this device's wrap and judges what opened. A copy that does not
/// check is an error and is not passed on; one from a device the records
/// do not name yet is an error too, and the caller may keep it until they
/// do.
pub fn take(
    msg: &[u8],
    me: &DeviceId,
    state: &State,
    store: &dyn KeyStore,
    marks: &mut fresh::Marks,
    lifetimes: Lifetimes,
    now_ms: Option<u64>,
) -> Result<Taken> {
    let (t, v, _) = cbb_core::msg::read_noted(msg).map_err(|r| Error::msg(format!("message copy breaks {r}")))?;
    if t != copies::T_COPY {
        return Err(Error::msg("not message copy"));
    }
    let copy = v.get(2).ok_or_else(|| Error::msg("message copy has no copy"))?;
    let c = copies::check(copy, state).map_err(|r| Error::msg(format!("the copy breaks {r}")))?;
    let opened = copies::open(&c, me, store, state).map_err(|r| Error::msg(format!("the copy breaks {r}")))?;
    Ok(match opened {
        Opened::Content { content, .. } => {
            let seen = fresh::Seen::of(&c, &content, lifetimes.secret_ms, lifetimes.incoming_ms);
            match marks.judge(&seen, now_ms, state) {
                fresh::Fresh::New { age_ms } => Taken::New { content, origin: c.origin, signed: c.time, age_ms },
                old => Taken::Old(old),
            }
        }
        Opened::NotForMe | Opened::NoPayload => Taken::PassedOn,
        Opened::Reseal { .. } => {
            let epoch = store.epochs().iter().map(|e| e.epoch).max().unwrap_or(0);
            Taken::Reseal(copies::reseal_request(&c.id, epoch))
        }
        Opened::TooOld | Opened::Halted => Taken::Dropped,
    })
}

#[cfg(test)]
mod tests;
