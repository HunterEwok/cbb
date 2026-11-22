// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Remote invitations that an admin that is not the group's hub makes
//! through the hub (docs/protocol.md, section 12, "Through the hub"): the
//! admin makes the guest key, the preshared key and the secret, asks the hub
//! for a guest tunnel with a guest message, and runs the invitation's
//! pairing window itself. The hub passes the bytes of each pairing
//! connection that comes through the guest tunnel to the admin over their
//! member connection, without reading them: the pairing's TLS runs between
//! the joiner and the admin's window, and the hub holds no key that admits.
//! Here each connection the hub passes on becomes a loopback connection to
//! this node, served as a guest's (Node::accept_guest), so the window runs
//! as it does on a hub.

use std::time::Duration;

use crate::error::{Error, Result};

/// The most invitations an admin keeps open through hubs at once, as a hub
/// carries for one admin.
pub const MAX_OPEN: usize = 4;

/// How long an invitation is valid unless the admin asks otherwise, and at
/// most, as Go's invite.DefaultLifetime and MaxLifetime.
pub const DEFAULT_LIFETIME: Duration = Duration::from_secs(3600);
pub const MAX_LIFETIME: Duration = Duration::from_secs(24 * 3600);

/// The keys of an invitation's guest: its WireGuard private key, which the
/// invitation carries, its public key, which the hub admits, and the
/// preshared key.
pub struct GuestKeys {
    pub key: [u8; 32],
    pub public: [u8; 32],
    pub psk: [u8; 32],
}

impl GuestKeys {
    /// New keys for a guest.
    pub fn new() -> Result<GuestKeys> {
        let key = random32()?;
        Ok(GuestKeys { key, public: cbb_core::invite::guest_public(&key), psk: random32()? })
    }
}

fn random32() -> Result<[u8; 32]> {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).map_err(|_| Error::msg("cannot make a key: the system has no randomness"))?;
    Ok(b)
}
