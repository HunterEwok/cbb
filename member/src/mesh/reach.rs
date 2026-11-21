// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Reach (docs/protocol.md, section 4, "Reach"): a computer tells each
//! phone connected to it which other members it is connected to now, so
//! that a phone away from home, connected only to a hub, shows the members
//! behind it as online; and a phone keeps what each connection told it
//! until that connection ends.

use cbb_core::format::cbor::Value;
use cbb_core::format::frame;
use cbb_core::msg::member as m;
use cbb_core::records::DeviceId;
use cbb_core::records::body::{ROLE_MEMBER, ROLE_PHONE};

use super::Mesh;

/// The most device IDs a reach message names.
pub const MAX_REACH: usize = 256;

impl Mesh {
    /// On a computer, tells each phone connected now the other members it
    /// is connected to, sorted, at most [`MAX_REACH`], whenever that set
    /// changed for the phone since it was last told.
    pub(super) fn send_reach(&self) {
        let state = self.state();
        if state.device(&self.device()).map(|d| d.role) != Some(ROLE_MEMBER) {
            return;
        }
        let conns: Vec<(DeviceId, std::sync::Arc<super::Conn>)> =
            self.conns.lock().unwrap().iter().map(|(id, c)| (*id, c.clone())).collect();
        // A device the records refuse (removed, frozen) is neither told
        // nor named.
        let counts = |id: &DeviceId| state.device(id).is_some_and(|d| !d.frozen);
        let conns: Vec<_> = conns.into_iter().filter(|(id, _)| counts(id)).collect();
        let mut all: Vec<DeviceId> = conns.iter().map(|(id, _)| *id).collect();
        all.sort();
        let mut sent = self.reach_out.lock().unwrap();
        sent.retain(|id, _| all.contains(id));
        for (id, c) in &conns {
            if state.device(id).map(|d| d.role) != Some(ROLE_PHONE) {
                continue;
            }
            let reach: Vec<DeviceId> = all.iter().filter(|x| *x != id).take(MAX_REACH).copied().collect();
            if sent.get(id) == Some(&reach) {
                continue;
            }
            let ids: Vec<Value<'_>> = reach.iter().map(|d| Value::Bytes(&d.0)).collect();
            let mut fields = vec![(frame::FIELD_T, Value::Uint(m::T_REACH))];
            if !ids.is_empty() {
                fields.push((2, Value::Array(ids)));
            }
            if c.tx.try_send(frame::write(&Value::Map(fields))).is_ok() {
                sent.insert(*id, reach);
            }
        }
    }

    /// Keeps what a reach message from peer says, in place of the last
    /// one: the IDs the group's records name, other than this device's.
    /// The list is shown, never trusted.
    pub(super) fn take_reach(&self, peer: &DeviceId, msg: &[u8]) -> crate::error::Result<()> {
        let v = cbb_core::format::cbor::decode(msg)
            .map_err(|_| crate::error::Error::msg("a reach message that does not decode"))?;
        let state = self.state();
        let me = self.device();
        let reach: Vec<DeviceId> = v
            .get(2)
            .and_then(Value::as_array)
            .unwrap_or_default()
            .iter()
            .take(MAX_REACH)
            .filter_map(|x| x.as_bytes().and_then(|b| <[u8; 16]>::try_from(b).ok()).map(DeviceId))
            .filter(|id| *id != me && state.device(id).is_some())
            .collect();
        self.reach_in.lock().unwrap().insert(*peer, reach);
        Ok(())
    }

    /// The other members the connected member peer says it reaches now
    /// (docs/protocol.md, section 4, "Reach"); none once it is gone.
    pub fn reach_of(&self, peer: &DeviceId) -> Vec<DeviceId> {
        self.reach_in.lock().unwrap().get(peer).cloned().unwrap_or_default()
    }

    /// A connection ended: what it told goes with it, and the phones
    /// still connected learn the change.
    pub(super) fn reach_gone(&self, peer: &DeviceId) {
        self.reach_in.lock().unwrap().remove(peer);
        self.reach_out.lock().unwrap().remove(peer);
        self.send_reach();
    }
}
