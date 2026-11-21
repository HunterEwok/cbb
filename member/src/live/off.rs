// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Sync away from home on the records of 0.6 in a build without the tunnel,
//! as for MIPS, where GotaTun lacks the 64-bit atomics it needs: never on.
//! The device meets no hub and no relay, serves no invitation and syncs at
//! home only; cbb global says why.

use std::sync::Arc;
use std::time::Duration;

use cbb_core::records::DeviceId;

use super::Live;
use super::invite::Opened;
use crate::away::Away;
use crate::error::{Error, Result};

/// Why sync away from home and the invitations from afar are off.
pub(super) const NO_TUNNEL: &str = "this build of cbb has no tunnel for sync away from home (MIPS); it syncs at home only, and joins at home with cbb pair";

impl Live {
    pub fn with_away(self: &Arc<Self>, _away: Arc<Away>) {}

    pub fn is_standing_by(&self) -> bool {
        false
    }

    pub fn away(&self) -> Option<&Arc<Away>> {
        None
    }

    pub fn tunnel_to_hubs(&self) {}

    pub fn away_off(&self, _after: Duration) -> Result<()> {
        Ok(())
    }

    pub fn stop_being_hub(&self) -> Result<()> {
        Err(Error::msg("this device is no hub of the group"))
    }

    pub fn hand_hub_to(self: &Arc<Self>, _to: DeviceId) -> Result<()> {
        Err(Error::msg("this device is no hub of the group"))
    }

    pub(crate) fn relay_status(&self) -> Option<crate::control::Relay> {
        None
    }

    pub fn open_guest(self: &Arc<Self>, _key: [u8; 32], _public: [u8; 32], _psk: [u8; 32]) -> Result<Opened> {
        Err(Error::msg(NO_TUNNEL))
    }

    pub fn guest_ended(self: &Arc<Self>, _public: &[u8; 32], _admitted: Option<DeviceId>) {}

    pub fn open_through(
        self: &Arc<Self>,
        _hub: Option<DeviceId>,
        _keys: ([u8; 32], [u8; 32], [u8; 32]),
        _expires_ms: u64,
        _invite: [u8; 16],
    ) -> Result<(Opened, DeviceId)> {
        Err(Error::msg(NO_TUNNEL))
    }

    pub fn through_ended(&self, _public: &[u8; 32], _admitted: Option<DeviceId>) {}
}
