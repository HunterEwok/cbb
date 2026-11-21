// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Sync away from home in a build without the tunnel, as for MIPS, where
//! GotaTun lacks the 64-bit atomics it needs: always off, and cbb global
//! on says why. The device syncs at home only.

use std::path::PathBuf;
use std::sync::Arc;

use cbb_core::certs::Cert;
use cbb_core::wire::Message;

use crate::certs::DeviceId;
use crate::control::{self, Header};
use crate::error::{Error, Result};
use crate::node::{Node, Peer};

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

    pub fn retry(&self, _node: &Node, _hub: &DeviceId) {}

    pub fn status(&self, _node: &Node) -> Option<control::Away> {
        None
    }

    pub fn make_hub(&self, _h: &Header) -> Result<(Vec<u8>, Vec<u8>)> {
        self.turn_on()
    }

    pub fn serve_if_first(&self, _node: &std::sync::Arc<Node>) {}

    pub fn stop_hub(&self, _node: &Node, _anyway: bool) -> Result<()> {
        Err(Error::msg("this device is no hub of the group"))
    }

    pub fn hello(&self, _node: &Node, _from: &DeviceId, _peer: &Peer, _chain: &[Cert]) -> Vec<Message> {
        Vec::new()
    }

    pub fn prune(&self, _node: &Node) {}

    pub fn set_credentials(&self, _c: Arc<crate::credentials::Credentials>) {}

    pub fn meet_at(&self, _node: &Node, _h: &Header) -> Result<(Vec<u8>, Vec<u8>)> {
        self.turn_on()
    }

    pub fn open_own(
        self: &Arc<Self>,
        _keys: &crate::inviter::GuestKeys,
        _w: &Arc<crate::window::Window>,
    ) -> Result<crate::inviter::Opened> {
        Err(off())
    }

    pub fn is_hub(&self) -> bool {
        false
    }

    pub fn guest_message(self: &Arc<Self>, _node: &Node, _from: &DeviceId, _chain: &[Cert], _g: crate::wire::Guest) {}

    pub fn hubs_shared(self: &Arc<Self>, _node: &Arc<Node>, _from: &DeviceId, _chain: &[Cert], _v: &serde_json::Value) {
    }

    pub fn run(self: Arc<Self>, _node: Arc<Node>) {}

    pub fn is_hub_now(&self) -> bool {
        false
    }

    pub fn live_status(&self) -> Option<control::Away> {
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

/// A build without the tunnel keeps no invitation: it cannot join by one.
pub fn keep_guest(_dir: &std::path::Path, _text: &str) -> Result<()> {
    Err(off())
}

/// A build without the tunnel has no guest tunnel.
pub struct GuestTunnel;

impl GuestTunnel {
    pub fn start(_inv: &cbb_core::invite::Invitation, _log: Arc<dyn Fn(&str) + Send + Sync>) -> Result<GuestTunnel> {
        Err(off())
    }

    pub fn port(&self) -> u16 {
        0
    }

    pub fn answered(&self) -> bool {
        false
    }
}
