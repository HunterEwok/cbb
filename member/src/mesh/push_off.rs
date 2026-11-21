// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The push sender in a build without the tunnel, as for MIPS, which has no
//! TLS client for the project's push service: it keeps no registration and
//! wakes no phone. The member syncs as in any other build.

use std::path::Path;
use std::sync::{Arc, Weak};

use cbb_core::format::cbor::Value;
use cbb_core::records::eval::State;
use cbb_core::records::key::{DeviceId, GroupId};

use super::Mesh;

/// Why this device sends a copy; in this build it never does.
#[derive(Clone, Copy)]
pub(super) enum Role {
    Origin,
    Neither,
}

/// The push sender: it sends nothing.
pub(super) struct Sender;

impl Sender {
    pub(super) fn start(
        _f: Arc<PushFaces>,
        _s: Arc<PushSaved>,
        _l: Vec<()>,
        _log: Arc<dyn Fn(&str) + Send + Sync>,
    ) -> Sender {
        Sender
    }

    pub(super) fn connected(&self, _device: &DeviceId) {}

    pub(super) fn left(&self, _device: &DeviceId) {}

    pub(super) fn renewals(&self, _device: &DeviceId) -> Vec<(GroupId, Vec<u8>)> {
        Vec::new()
    }

    pub(super) fn stop(&self) {}
}

pub(super) struct PushFaces;

impl PushFaces {
    pub(super) fn new(_mesh: Weak<Mesh>) -> PushFaces {
        PushFaces
    }

    pub(super) fn look(&self, _mesh: &Mesh, _state: &State) {}
}

pub(super) struct PushSaved;

impl PushSaved {
    pub(super) fn open(_dir: &Path, _group: GroupId, _log: Arc<dyn Fn(&str) + Send + Sync>) -> (PushSaved, Vec<()>) {
        (PushSaved, Vec::new())
    }
}

pub(super) struct Applied;

impl Applied {
    pub(super) fn of(_state: &State) -> Applied {
        Applied
    }
}

impl Mesh {
    pub(super) fn take_push(&self, _peer: &DeviceId, _msg: &[u8]) {}

    pub(super) fn prune_push(&self, _state: &State) {}

    pub(super) fn push_copy(&self, _msg: &Value<'_>, _role: Role) {}

    pub(super) fn push_role_received(&self) -> Role {
        Role::Neither
    }

    pub(super) fn push_events(&self, _set: &cbb_core::records::RecordSet) {}
}
