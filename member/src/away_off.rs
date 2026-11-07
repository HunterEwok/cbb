// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Sync away from home in a build without the tunnel, as for MIPS, where
//! GotaTun lacks the 64-bit atomics it needs: always off, and cbb global
//! on says why. The device syncs at home only.

use std::path::PathBuf;
use std::sync::Arc;

use crate::certs::DeviceId;
use crate::control;
use crate::error::{Error, Result};
use crate::node::Node;

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

    pub fn run(self: Arc<Self>, _node: Arc<Node>) {}
}
