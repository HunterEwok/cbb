// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Sync away from home in a build without the tunnel, as for MIPS, where
//! GotaTun lacks the 64-bit atomics it needs: always off, and cbb global
//! on says why. The device syncs at home only.

use std::path::PathBuf;
use std::sync::Arc;

use crate::certs::DeviceId;
use crate::control::{self, Header};
use crate::error::{Error, Result};

/// Sync away from home on this device: never on in this build.
pub struct Away;

impl Away {
    pub fn new(_dir: PathBuf, _group: String, _me: DeviceId, _log: Arc<dyn Fn(&str) + Send + Sync>) -> Away {
        Away
    }

    pub fn via(self, _via: Option<std::net::SocketAddr>) -> Away {
        self
    }

    pub fn key(&self) -> Option<(Vec<u8>, Vec<u8>)> {
        None
    }

    pub fn turn_on(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        Err(off())
    }

    pub fn turn_off(&self) -> Result<()> {
        Ok(())
    }

    pub fn offered(
        &self,
        _from: &DeviceId,
        _v: &serde_json::Value,
        _may_host: &dyn Fn(&str) -> bool,
    ) -> Option<DeviceId> {
        None
    }

    pub fn make_hub(&self, _h: &Header) -> Result<(Vec<u8>, Vec<u8>)> {
        self.turn_on()
    }

    pub fn is_hub(&self) -> bool {
        false
    }

    pub fn is_hub_now(&self) -> bool {
        false
    }

    pub fn is_on(&self) -> bool {
        false
    }

    pub fn held_hubs(&self) -> Vec<String> {
        Vec::new()
    }

    pub fn drop_held_gone(&self, _is_device: &dyn Fn(&cbb_core::records::DeviceId) -> bool) {}

    pub fn live_status(&self) -> Option<control::Away> {
        None
    }

    pub fn live_status_as(&self, _standby: bool, _order: &[String]) -> Option<control::Away> {
        None
    }

    pub fn live_forwarder(&self, _entries_held: bool) -> Option<control::Forwarder> {
        None
    }

    pub fn own_forwarder(&self) -> Option<(String, [u8; 32])> {
        None
    }

    pub fn hub_settings(&self) -> Option<([u8; 32], Option<serde_json::Value>, u16)> {
        None
    }
}

/// A forwarder a hub command names: this build reaches none.
pub fn forwarder_named(fwd: &str, _key: &str) -> Result<Option<(String, [u8; 32])>> {
    if fwd.is_empty() { Ok(None) } else { Err(off()) }
}

/// Why sync away from home is off in this build.
fn off() -> Error {
    Error::msg("this build of cbb has no tunnel for sync away from home (MIPS); it syncs at home only")
}
