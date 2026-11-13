// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! A table the service shares among everyone who sends to it, bounded so
//! that no one payer (an address, an IPv6 /64) can fill it for the others:
//! when it is full, the oldest entry of the payer with the most entries
//! gives way (one it may lose first, when it has one: an unconfirmed
//! binding before a confirmed one). It never refuses everyone.

use std::collections::{HashMap, VecDeque};

/// Who pays: a keyed hash of the address (its /64 for IPv6), so that the
/// state file holds no address.
pub(super) type Payer = [u8; 16];

struct Entry<V> {
    v: V,
    payer: Payer,
    serial: u64,
}

pub(super) struct Shared<V> {
    map: HashMap<[u8; 32], Entry<V>>,
    /// Each payer's keys, oldest first; an entry removed or filed again
    /// stays behind until it reaches the front (its serial tells).
    order: HashMap<Payer, VecDeque<([u8; 32], u64)>>,
    counts: HashMap<Payer, usize>,
    cap: usize,
    serial: u64,
}

impl<V> Shared<V> {
    pub(super) fn new(cap: usize) -> Shared<V> {
        Shared { map: HashMap::new(), order: HashMap::new(), counts: HashMap::new(), cap, serial: 0 }
    }

    pub(super) fn len(&self) -> usize {
        self.map.len()
    }

    pub(super) fn get(&self, k: &[u8; 32]) -> Option<&V> {
        self.map.get(k).map(|e| &e.v)
    }

    pub(super) fn get_mut(&mut self, k: &[u8; 32]) -> Option<&mut V> {
        self.map.get_mut(k).map(|e| &mut e.v)
    }

    /// The entries with their payers.
    pub(super) fn iter(&self) -> impl Iterator<Item = (&[u8; 32], &V, Payer)> {
        self.map.iter().map(|(k, e)| (k, &e.v, e.payer))
    }

    /// Who pays for the entry under `k`.
    pub(super) fn payer(&self, k: &[u8; 32]) -> Option<Payer> {
        self.map.get(k).map(|e| e.payer)
    }

    pub(super) fn remove(&mut self, k: &[u8; 32]) -> Option<V> {
        let e = self.map.remove(k)?;
        self.uncount(e.payer);
        Some(e.v)
    }

    fn uncount(&mut self, payer: Payer) {
        if let Some(n) = self.counts.get_mut(&payer) {
            *n -= 1;
            if *n == 0 {
                self.counts.remove(&payer);
                self.order.remove(&payer);
            }
        }
    }

    /// Drops the entries `stale` says are past their life, when the table
    /// is full.
    pub(super) fn prune(&mut self, stale: impl Fn(&V) -> bool) -> Vec<([u8; 32], V)> {
        let gone: Vec<[u8; 32]> = self.map.iter().filter(|(_, e)| stale(&e.v)).map(|(k, _)| *k).collect();
        gone.into_iter().filter_map(|k| self.remove(&k).map(|v| (k, v))).collect()
    }

    /// Files `v` under `k`: an entry already there keeps its payer; a new
    /// one in a full table first makes room (after `stale` had its say).
    pub(super) fn insert(&mut self, k: [u8; 32], v: V, payer: Payer, stale: impl Fn(&V) -> bool) {
        self.insert_keeping(k, v, payer, stale, |_| false, |_| 0);
    }

    /// As `insert`, and when room is made the payer that gives way loses
    /// an entry `keep` does not hold to before one it does (its oldest),
    /// and of those it holds to, the one `used` says was used longest ago.
    /// Returns the entries dropped to make room.
    pub(super) fn insert_keeping(
        &mut self,
        k: [u8; 32],
        v: V,
        payer: Payer,
        stale: impl Fn(&V) -> bool,
        keep: impl Fn(&V) -> bool,
        used: impl Fn(&V) -> u64,
    ) -> Vec<([u8; 32], V)> {
        let mut dropped = Vec::new();
        if let Some(e) = self.map.get_mut(&k) {
            e.v = v;
            return dropped;
        }
        if self.map.len() >= self.cap {
            dropped = self.prune(stale);
        }
        while self.map.len() >= self.cap.max(1) {
            if !self.evict_one(&keep, &used, &mut dropped) {
                break;
            }
        }
        self.serial += 1;
        self.map.insert(k, Entry { v, payer, serial: self.serial });
        *self.counts.entry(payer).or_default() += 1;
        let q = self.order.entry(payer).or_default();
        q.push_back((k, self.serial));
        // Keys left behind by removals never make a queue more than twice
        // the payer's entries.
        if q.len() > 2 * self.counts[&payer] + 16 {
            let map = &self.map;
            q.retain(|(k, s)| map.get(k).is_some_and(|e| e.serial == *s));
        }
        dropped
    }

    /// Drops an entry of the payer with the most entries: its oldest that
    /// `keep` does not hold to, else the one `used` says was used longest
    /// ago (the oldest among equals).
    fn evict_one(
        &mut self,
        keep: &dyn Fn(&V) -> bool,
        used: &dyn Fn(&V) -> u64,
        dropped: &mut Vec<([u8; 32], V)>,
    ) -> bool {
        let Some(payer) = self.counts.iter().max_by_key(|(p, n)| (**n, **p)).map(|(p, _)| *p) else { return false };
        let loose = self.order.get(&payer).and_then(|q| {
            q.iter()
                .find(|(k, s)| self.map.get(k).is_some_and(|e| e.serial == *s && e.payer == payer && !keep(&e.v)))
                .map(|(k, _)| *k)
        });
        if let Some(k) = loose {
            dropped.extend(self.remove(&k).map(|v| (k, v)));
            return true;
        }
        let idle = self.order.get(&payer).and_then(|q| {
            q.iter()
                .filter_map(|(k, s)| {
                    self.map.get(k).filter(|e| e.serial == *s && e.payer == payer).map(|e| (used(&e.v), e.serial, *k))
                })
                .min()
                .map(|(_, _, k)| k)
        });
        if let Some(k) = idle {
            dropped.extend(self.remove(&k).map(|v| (k, v)));
            return true;
        }
        while let Some((k, s)) = self.order.get_mut(&payer).and_then(VecDeque::pop_front) {
            if self.map.get(&k).is_some_and(|e| e.serial == s && e.payer == payer) {
                dropped.extend(self.remove(&k).map(|v| (k, v)));
                return true;
            }
        }
        // Its queue held only keys left behind: the count is wrong, which
        // never happens; start the payer over rather than loop.
        self.counts.remove(&payer);
        self.order.remove(&payer);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(i: u32) -> [u8; 32] {
        let mut k = [0; 32];
        k[..4].copy_from_slice(&i.to_be_bytes());
        k
    }

    #[test]
    fn the_fullest_payer_gives_way_and_no_one_else() {
        let (honest, flood): (Payer, Payer) = ([1; 16], [2; 16]);
        let mut t = Shared::new(100);
        for i in 0..10 {
            t.insert(k(i), i, honest, |_| false);
        }
        for i in 1000..5000 {
            t.insert(k(i), i, flood, |_| false);
        }
        assert_eq!(t.len(), 100);
        for i in 0..10 {
            assert_eq!(t.get(&k(i)), Some(&i), "the honest payer's entry {i}");
        }
        // The flood keeps its newest.
        assert!(t.get(&k(4999)).is_some() && t.get(&k(1000)).is_none());
        // Removing and filing again keeps the counts right.
        t.remove(&k(3));
        t.insert(k(3), 3, honest, |_| false);
        t.insert(k(3), 33, flood, |_| false);
        assert_eq!(t.get(&k(3)), Some(&33));
        assert_eq!(t.counts[&honest], 10);
        assert_eq!(t.counts.values().sum::<usize>(), t.len());
    }

    #[test]
    fn stale_entries_go_first() {
        let (a, b): (Payer, Payer) = ([1; 16], [2; 16]);
        let mut t = Shared::new(3);
        t.insert(k(1), 1, a, |_| false);
        t.insert(k(2), 2, a, |_| false);
        t.insert(k(3), 3, b, |_| false);
        t.insert(k(4), 4, b, |v| *v == 3);
        assert_eq!((t.get(&k(1)), t.get(&k(3)), t.get(&k(4))), (Some(&1), None, Some(&4)));
    }

    #[test]
    fn the_payer_that_gives_way_loses_what_it_may_lose_first() {
        let (home, other): (Payer, Payer) = ([1; 16], [2; 16]);
        let mut t: Shared<bool> = Shared::new(8);
        // The home's one confirmed entry, oldest of all.
        t.insert_keeping(k(0), true, home, |_| false, |v| *v, |_| 0);
        for i in 1..4 {
            t.insert_keeping(k(i), true, other, |_| false, |v| *v, |_| 0);
        }
        // More from the home, unconfirmed, until it is the fullest payer.
        for i in 10..20 {
            t.insert_keeping(k(i), false, home, |_| false, |v| *v, |_| 0);
        }
        assert_eq!(t.get(&k(0)), Some(&true), "the confirmed entry stays while there are others to lose");
        assert_eq!((1..4).filter(|i| t.get(&k(*i)).is_some()).count(), 3);
        assert_eq!(t.len(), 8);
    }

    #[test]
    fn of_the_entries_it_holds_to_the_payer_loses_the_one_used_longest_ago() {
        let mut t: Shared<(bool, u64)> = Shared::new(4);
        let p = [1; 16];
        // The phone's binding filed first and still used now; three others
        // filed after it and not used since.
        t.insert_keeping(k(0), (true, 1000), p, |_| false, |v| v.0, |v| v.1);
        for i in 1..4 {
            t.insert_keeping(k(i), (true, i as u64), p, |_| false, |v| v.0, |v| v.1);
        }
        t.insert_keeping(k(9), (true, 2000), p, |_| false, |v| v.0, |v| v.1);
        assert!(t.get(&k(0)).is_some(), "the one in use stays");
        assert!(t.get(&k(1)).is_none(), "the one idle longest goes");
    }
}
