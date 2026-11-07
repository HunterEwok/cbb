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
        Err(Error::msg(
            "this build of the lite member has no tunnel for sync away from home (MIPS); it syncs at home only",
        ))
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

    pub fn stop_hub(&self, _node: &Node, _anyway: bool) -> Result<()> {
        Err(Error::msg("this device is no hub of the group"))
    }

    pub fn hello(&self, _node: &Node, _from: &DeviceId, _peer: &Peer, _chain: &[Cert]) -> Vec<Message> {
        Vec::new()
    }

    pub fn prune(&self, _node: &Node) {}

    pub fn hubs_shared(self: &Arc<Self>, _node: &Arc<Node>, _from: &DeviceId, _chain: &[Cert], _v: &serde_json::Value) {
    }

    pub fn run(self: Arc<Self>, _node: Arc<Node>) {}
}
