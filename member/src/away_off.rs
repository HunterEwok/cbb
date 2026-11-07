// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Sync away from home in a build without the tunnel, as for MIPS, where
//! GotaTun lacks the 64-bit atomics it needs: always off, and cbb global
//! on says why. The device syncs at home only.

use std::path::PathBuf;
use std::sync::Arc;

use cbb_core::certs::Cert;
use cbb_core::wire::{Message, TunnelOffer};

use crate::admin::Admin;
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

    pub fn is_hub(&self) -> bool {
        false
    }

    pub fn take_hub(&self, _node: &Arc<Node>, _by: &str, _order: &serde_json::Value) -> Result<TunnelOffer> {
        Err(Error::msg("sync away from home is off on this computer; this build has no tunnel"))
    }

    pub fn make_hub_on(
        &self,
        _a: &Admin,
        _target: &str,
        _addrs: &[String],
        _fwd: (&str, &str),
        _fo: bool,
    ) -> Result<()> {
        self.turn_on().map(|_| ())
    }

    pub fn move_hub(&self, _a: &Admin, _target: &str, _addrs: &[String], _fwd: (&str, &str)) -> Result<()> {
        Err(Error::msg("this device is not the group's hub; cbb global hub makes it the hub"))
    }

    pub fn stop_hub_on(&self, _a: &Admin, _target: &str, _anyway: bool) -> Result<()> {
        self.turn_on().map(|_| ())
    }

    pub fn hubs_shared(self: &Arc<Self>, _node: &Arc<Node>, _from: &DeviceId, _chain: &[Cert], _v: &serde_json::Value) {
    }

    pub fn run(self: Arc<Self>, _node: Arc<Node>) {}
}

/// Whether a hub order is a stop order: this build is never a hub.
pub fn is_stop(_order: &serde_json::Value) -> bool {
    false
}
