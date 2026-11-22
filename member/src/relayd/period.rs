// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! What the relay keeps of a group, in memory only: the period of its
//! server credentials, by the period's tag (docs/relay-budget.md).

use std::sync::Arc;

use cbb_core::certs::KeyHash;

use super::server::{Inner, Member, State};

/// What the relay holds of a group that registered with credentials: the
/// period key it first saw for the period's tag, the newest versions of its
/// credentials, and the members the newest members' credential lists.
pub struct Period {
    pub signer: KeyHash,
    pub hubs: u64,
    pub members_version: u64,
    pub members: Option<Vec<KeyHash>>,
}

/// What a registration's credentials show of their period: the key that signed the hubs' credential (the period key),
/// the hubs' credential's version, and the members' credential's version
/// with the server keys it lists.
pub struct Shown {
    pub signer: KeyHash,
    pub hubs: u64,
    pub members: Option<(u64, Vec<KeyHash>)>,
}

impl Inner {
    /// Checks the credentials p against what the relay holds for their
    /// period: they are of the key that registered it first, and no older
    /// than the ones it saw. It changes nothing; take_period_locked does.
    pub fn check_period_locked(st: &State, tag: &str, p: &Shown) -> Option<String> {
        let cur = st.periods.get(tag)?;
        let members = p.members.as_ref().map_or(0, |m| m.0);
        if cur.signer != p.signer {
            return Some("another key registered this group's period first".into());
        }
        if p.hubs < cur.hubs || members < cur.members_version {
            return Some("the group's credentials are older than ones this relay saw".into());
        }
        None
    }

    /// The devices of the period tag that the credentials p would leave out
    /// when taken.
    pub fn leaving_locked(st: &State, tag: &str, p: &Shown) -> Option<Vec<KeyHash>> {
        let (version, members) = p.members.as_ref()?;
        if let Some(cur) = st.periods.get(tag)
            && cur.members.is_some()
            && *version <= cur.members_version
        {
            return None;
        }
        Some(members.clone())
    }

    /// Takes the credentials p, which check_period_locked let through, for
    /// their period; the devices a newer members' credential no longer
    /// lists go.
    pub fn take_period_locked(&self, st: &mut State, tag: &str, p: &Shown) {
        let (version, listed) = p.members.clone().unwrap_or_default();
        let cur = st.periods.entry(tag.to_string()).or_insert(Period {
            signer: p.signer,
            hubs: 0,
            members_version: 0,
            members: None,
        });
        cur.hubs = p.hubs;
        if version > cur.members_version || cur.members.is_none() {
            cur.members_version = version;
            cur.members = Some(listed.clone());
            let gone: Vec<Arc<Member>> = st
                .groups
                .get(tag)
                .map(|g| g.values().filter(|o| !listed.contains(&o.leaf)).cloned().collect())
                .unwrap_or_default();
            for o in gone {
                self.drop_locked(st, &o);
            }
        }
    }
}
