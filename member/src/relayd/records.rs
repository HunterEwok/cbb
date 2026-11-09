// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! What the relay keeps of a group, in memory only: its authority records,
//! verified once and bounded on an open relay, and the period of a group
//! that registered with credentials (docs/relay-budget.md).

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, Condvar, Mutex};

use cbb_core::authority::Record;
use cbb_core::certs::{Cert, KeyHash};
use cbb_core::credential::Presented;
use cbb_core::group::{Records, Refusal};

use super::server::{Inner, Member, State, drop_records_locked};

/// A group's authority records as the relay keeps them: the set that has
/// verified them, the bytes they take, which an open relay bounds for each
/// group, and what each source that brought them paid, which it bounds for
/// each source and in all.
pub struct RecordSet {
    pub set: Records,
    pub bytes: usize,
    pub paid: HashMap<Option<IpAddr>, usize>,
}

/// What a record takes in memory, as far as the limits count.
pub fn record_size(r: &Record) -> usize {
    r.body.len() + r.sig.len() + r.chain.iter().map(Vec::len).sum::<usize>()
}

/// Keeps the registrations of one group one at a time while they check its
/// records, which the set does not allow at once; it exists only while
/// some registration holds or waits for it.
#[derive(Default)]
pub struct TagLock {
    busy: Mutex<bool>,
    free: Condvar,
    waiting: Mutex<usize>,
}

/// What the relay holds of a group that registered with credentials: the
/// period key it first saw for the period's tag, the newest versions of its
/// credentials, and the members the newest members' credential lists.
pub struct Period {
    pub signer: KeyHash,
    pub hubs: u64,
    pub members_version: u64,
    pub members: Option<Vec<KeyHash>>,
}

/// Why the relay refuses a device of a group: what the records refuse,
/// except a stop of the exchange, under which the group's devices still
/// exchange records through the relay.
pub fn refused_here(set: &Records, chain: &[Cert]) -> Option<String> {
    match set.refused(chain) {
        None | Some(Refusal::Stopped) => None,
        Some(r) => Some(r.why().to_string()),
    }
}

impl Inner {
    /// Waits for the turn of a registration of the group tag; the guard
    /// ends it.
    pub fn lock_tag(self: &Arc<Self>, tag: &str) -> TagTurn {
        let l = {
            let mut st = self.lock();
            let l = st.tag_locks.entry(tag.to_string()).or_default().clone();
            if let Ok(mut w) = l.waiting.lock() {
                *w += 1;
            }
            l
        };
        let mut busy = l.busy.lock().unwrap_or_else(|e| e.into_inner());
        while *busy {
            busy = l.free.wait(busy).unwrap_or_else(|e| e.into_inner());
        }
        *busy = true;
        drop(busy);
        TagTurn { inner: self.clone(), tag: tag.to_string(), lock: l }
    }

    /// Adds the records of a claim to what the relay keeps for the group
    /// tag, whose first root is root, and returns the group's set (None
    /// when the relay keeps none and the claim has none) and whether the
    /// claim brought records that were new. The caller holds the group's
    /// turn. Each record is verified once, when first sent: the records the
    /// relay already keeps cost nothing, and the new ones are charged to
    /// the address they come from. On an open relay, what it keeps for a
    /// group, and in all, is bounded.
    pub fn check_records(
        &self,
        tag: &str,
        root: &Cert,
        from: Option<IpAddr>,
        recs: &[Record],
    ) -> (Option<Arc<Mutex<RecordSet>>>, bool, Option<String>) {
        let mut st = self.lock();
        let existing = st.records.get(tag).cloned();
        if existing.is_none() && recs.is_empty() {
            return (None, false, None);
        }
        let created = existing.is_none();
        let rs = existing.unwrap_or_else(|| {
            Arc::new(Mutex::new(RecordSet { set: Records::new(root), bytes: 0, paid: HashMap::new() }))
        });
        let mut missing = Vec::new();
        let mut size = 0;
        {
            let set = rs.lock().unwrap_or_else(|e| e.into_inner());
            // A body may come under several signers, each a record of its
            // own.
            let mut seen = HashSet::new();
            for r in recs {
                if !seen.insert((cbb_core::certs::sha256(&r.body), r.sig.clone())) || set.set.has(r) {
                    continue;
                }
                missing.push(r.clone());
                size += record_size(r);
            }
        }
        let have = rs.lock().map(|r| r.bytes).unwrap_or(0);
        let now = st.now();
        let err = if missing.is_empty() {
            None
        } else if !st.allow.take(from, missing.len() as f64, now) {
            Some("too many records from this network; try again later")
        } else if self.cfg.open && have + size > self.limits.group_record_bytes {
            Some("the relay keeps as many records of this group as it can")
        } else if self.cfg.open && st.record_bytes.full(from, size).is_some() {
            Some("the relay keeps as many records from this network as it can; try again later")
        } else {
            None
        };
        if let Some(e) = err {
            return (Some(rs), false, Some(e.to_string()));
        }
        if created {
            st.records.insert(tag.to_string(), rs.clone());
        }
        if let Ok(mut r) = rs.lock() {
            r.bytes += size;
            *r.paid.entry(from).or_default() += size;
        }
        st.record_bytes.add(from, size);
        drop(st);
        // The signatures take time, so they are checked outside the lock,
        // with the group's other registrations waiting.
        let fresh = {
            let mut r = rs.lock().unwrap_or_else(|e| e.into_inner());
            r.set.add_all(&missing).0
        };
        if fresh.len() < missing.len() {
            // What did not verify is not kept.
            let kept: usize = fresh.iter().map(record_size).sum();
            let mut st = self.lock();
            if let Ok(mut r) = rs.lock() {
                r.bytes -= size - kept;
                let p = r.paid.entry(from).or_default();
                *p = p.saturating_sub(size - kept);
                if *p == 0 {
                    r.paid.remove(&from);
                }
            }
            st.record_bytes.remove(from, size - kept);
        }
        (Some(rs), !fresh.is_empty(), None)
    }

    /// Ends a registration that failed: a group that the relay holds no
    /// device of, and whose records its own registration brought, does not
    /// keep them. The caller holds the group's turn.
    pub fn forget_records(&self, tag: &str) {
        let mut st = self.lock();
        if self.cfg.open && st.groups.get(tag).is_none_or(|g| g.is_empty()) {
            drop_records_locked(&mut st, tag);
        }
    }

    /// Checks the credentials p against what the relay holds for their
    /// period: they are of the key that registered it first, and no older
    /// than the ones it saw. It changes nothing; take_period_locked does.
    pub fn check_period_locked(st: &State, tag: &str, p: &Presented) -> Option<String> {
        let cur = st.periods.get(tag)?;
        let members = p.members.as_ref().map_or(0, |m| m.version);
        if cur.signer != p.signer {
            return Some("another key registered this group's period first".into());
        }
        if p.hubs.version < cur.hubs || members < cur.members_version {
            return Some("the group's credentials are older than ones this relay saw".into());
        }
        None
    }

    /// The devices of the period tag that the credentials p would leave out
    /// when taken.
    pub fn leaving_locked(st: &State, tag: &str, p: &Presented) -> Option<Vec<KeyHash>> {
        let members = p.members.as_ref()?;
        if let Some(cur) = st.periods.get(tag)
            && cur.members.is_some()
            && members.version <= cur.members_version
        {
            return None;
        }
        Some(members.members.clone())
    }

    /// Takes the credentials p, which check_period_locked let through, for
    /// their period; the devices a newer members' credential no longer
    /// lists go.
    pub fn take_period_locked(&self, st: &mut State, tag: &str, p: &Presented) {
        let (version, listed) = p.members.as_ref().map_or((0, Vec::new()), |m| (m.version, m.members.clone()));
        let cur = st.periods.entry(tag.to_string()).or_insert(Period {
            signer: p.signer,
            hubs: 0,
            members_version: 0,
            members: None,
        });
        cur.hubs = p.hubs.version;
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

/// A registration's turn among those of its group.
pub struct TagTurn {
    inner: Arc<Inner>,
    tag: String,
    lock: Arc<TagLock>,
}

impl Drop for TagTurn {
    fn drop(&mut self) {
        {
            let mut busy = self.lock.busy.lock().unwrap_or_else(|e| e.into_inner());
            *busy = false;
        }
        self.lock.free.notify_one();
        let mut st = self.inner.lock();
        let left = self.lock.waiting.lock().map_or(1, |mut w| {
            *w -= 1;
            *w
        });
        if left == 0 {
            st.tag_locks.remove(&self.tag);
        }
    }
}
