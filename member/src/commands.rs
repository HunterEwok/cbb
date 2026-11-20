// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Commands of 0.6 on a member (format section 6, `cbb_core::commands`):
//! sending one with its orders sealed to the receiver, and taking one
//! addressed here. Who may command whom, the lifetime, the counter and the
//! seal are the core's; this keeps the counters across restarts in
//! `commands.cbor` (the last counter of each signer taken here, and the
//! last this device gave its own commands), and hands the opened orders to
//! the caller, which carries them out.

use std::path::{Path, PathBuf};

use cbb_core::commands::{self, Command, Counters, Draft, Keys, Member, Refusal};
use cbb_core::format::cbor::{self, Value};
use cbb_core::identity::ExternalKey;
use cbb_core::keystore::KeyStore;
use cbb_core::records::{DeviceId, State};

use crate::error::{Error, Result};
use crate::files;
use crate::sealed::Statements;

/// The file's name in the state directory.
pub const FILE_NAME: &str = "commands.cbor";

/// The counters a member keeps.
pub struct Book {
    path: PathBuf,
    /// The last counter of each signer whose command was taken here.
    pub taken: Counters,
    /// The last counter this device gave a command of its own.
    pub sent: u64,
}

impl Book {
    /// The counters kept in dir; none yet without the file.
    pub fn load(dir: &Path) -> Result<Book> {
        let path = dir.join(FILE_NAME);
        let mut b = Book { path, taken: Counters::default(), sent: 0 };
        let data = match std::fs::read(&b.path) {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(b),
            Err(e) => return Err(Error::with(format!("cannot read {}", b.path.display()), e)),
        };
        let damaged = |r| Error::msg(format!("{} is damaged: {r}", b.path.display()));
        let v = cbor::decode(&data).map_err(damaged)?;
        if v.get(1).and_then(Value::as_uint) != Some(1) {
            return Err(Error::msg(format!("{} is of an unknown version", b.path.display())));
        }
        if let Some(t) = v.get(2) {
            b.taken = Counters::decode(&t.encode()).map_err(damaged)?;
        }
        b.sent = v.get(3).and_then(Value::as_uint).unwrap_or(0);
        Ok(b)
    }

    fn save(&self) -> Result<()> {
        let taken = self.taken.encode();
        let taken = cbor::decode(&taken).map_err(|r| Error::msg(format!("cannot encode the counters: {r}")))?;
        let data = Value::Map(vec![(1, Value::Uint(1)), (2, taken), (3, Value::Uint(self.sent))]).encode();
        files::write_atomic(&self.path, &data, 0o600)
    }

    /// A command of this device's to device `to`, signed by `signer` (the
    /// root's key or an admin key the device holds): orders, when the type
    /// has them, sealed to the receiver's current statement. The counter
    /// is taken and kept before the frame of message `command` is given.
    #[allow(clippy::too_many_arguments)]
    pub fn send(
        &mut self,
        signer: &dyn ExternalKey,
        state: &State,
        statements: &Statements,
        to: DeviceId,
        kind: u64,
        orders: Option<&[u8]>,
        time_ms: u64,
    ) -> Result<Vec<u8>> {
        let sealing = statements.sealing(state);
        let seal = match orders {
            Some(_) => {
                let s = sealing
                    .get(&to)
                    .ok_or_else(|| Error::msg("the device has no keys statement here yet: it cannot be commanded"))?;
                let b = s.statement.body();
                Some((b.epoch, b.seal.public().to_vec()))
            }
            None => None,
        };
        // A counter is never given twice, even across a clock set back:
        // the next above the last one, or the time when that is higher.
        let n = self.sent.saturating_add(1).max(time_ms);
        self.sent = n;
        self.save()?;
        let d = Draft {
            kind,
            group: state.group,
            to,
            n,
            time_ms,
            nonce: None,
            orders,
            seal_to: seal.as_ref().map(|(e, k)| (*e, k.as_slice())),
        };
        let env = commands::make(&d, signer).map_err(|e| e.context("cannot write the command"))?;
        commands::message(&env).map_err(|r| Error::msg(format!("the command breaks {r}")))
    }

    /// Takes message `command` (its body) addressed to this member: the
    /// command's type and its opened orders, with the counter kept; or the
    /// refusal and, after a valid signature, the frame of message `result`
    /// to answer its sender with.
    pub fn take(
        &mut self,
        msg: &[u8],
        me: DeviceId,
        state: &State,
        keys: &Keys,
        store: &dyn KeyStore,
        now_ms: Option<u64>,
    ) -> std::result::Result<Taken, Refused> {
        let silent = || Refused { refusal: Refusal::SILENT, answer: None, fault: None };
        let (t, v, _) = cbb_core::msg::read_noted(msg).map_err(|_| silent())?;
        if t != commands::T_COMMAND {
            return Err(silent());
        }
        let env = v.get(2).map(Value::encode).ok_or_else(silent)?;
        let c = Command::read(&env).map_err(|_| silent())?;
        let at = Member { me, state, keys, now_ms };
        let before = self.taken.clone();
        match commands::accept_member(&c, &at, &mut self.taken, store) {
            Ok(orders) => {
                if let Err(e) = self.save() {
                    // Not kept: not taken, so a restart cannot take it again.
                    self.taken = before;
                    return Err(Refused { fault: Some(e), ..silent() });
                }
                Ok(Taken { kind: c.kind, id: c.id, signer: c.signer, orders })
            }
            Err(r) => Err(Refused { refusal: r, answer: commands::refusal(&c.id, &me, r), fault: None }),
        }
    }
}

/// A command taken: its type, ID, signer and opened orders.
#[derive(Debug)]
pub struct Taken {
    pub kind: u64,
    pub id: [u8; 16],
    pub signer: cbb_core::records::KeyHash,
    pub orders: Option<Vec<u8>>,
}

/// A command refused: why, the answer to send when there is one, and,
/// for a command that passed but could not be kept, the error to log.
#[derive(Debug)]
pub struct Refused {
    pub refusal: Refusal,
    pub answer: Option<Vec<u8>>,
    pub fault: Option<Error>,
}

#[cfg(test)]
mod tests;
