// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! A token's binding to the phone's send key (format section 20.4).
//!
//! - While no key is confirmed, a send under any key passes, and the
//!   service hands the key a challenge, which goes to the token with the
//!   send (the phone's alert pushes carry it).
//! - The challenge is not kept: it is a keyed function of the service's
//!   secret, the token, the send key, the binding's generation and the
//!   14-day period ([`CHALLENGE_PERIOD_MS`]), and an answer is checked by
//!   computing it again, for the current period and the one before. So
//!   any number of keys may be challenged and none pushes another's out,
//!   and a challenge serves 14 to 28 days.
//! - A key is confirmed by a send whose signature covers its challenge:
//!   only the token's holder saw it. A confirmation raises the generation,
//!   so every challenge made before it, for any key, confirms nothing more
//!   (a challenge serves once); one made for another key or another token
//!   never does.
//! - Once a key is confirmed, only that key sends. Another key gets its
//!   challenge on its own (a push with no body, within its group's budget
//!   for them) and takes the binding only by confirming it; never by time.
//! - The highest seq is kept per (key, slot): each of the phone's groups
//!   registers under a slot of its own, so one group's registration never
//!   silences another's. A seq more than a day ahead of the service's
//!   clock is refused: seq is a clock by rule.

use cbb_core::push;

/// The period a challenge is made for; the previous period's is taken
/// too.
pub const CHALLENGE_PERIOD_MS: u64 = 14 * 24 * 3600 * 1000;
/// Slots kept per token at most: a phone in more groups than this loses
/// the oldest slot's seq, never a binding.
pub const SLOTS_MAX: usize = 16;
/// How long an unconfirmed binding outlives its last send when the table
/// is full.
pub const UNCONFIRMED_LIFE_MS: u64 = 30 * 24 * 3600 * 1000;

/// The highest seq accepted under one key and slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Slot {
    pub key: [u8; 32],
    pub slot: [u8; 16],
    pub seq: u64,
}

/// One token's binding, filed under the token's keyed hash.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Binding {
    /// The hash of the confirmed send key's encoding.
    pub key: Option<[u8; 32]>,
    /// Raised by each confirmation: the challenges of an earlier
    /// generation confirm nothing.
    pub generation: u32,
    pub slots: Vec<Slot>,
    /// When a send last passed (Unix milliseconds), never later than the
    /// clock that read it.
    pub used_ms: u64,
}

/// A send to judge: the hash of its send key, its slot and seq, and the
/// challenge its signature covers (the signature itself already checked).
#[derive(Clone, Copy, Debug)]
pub struct Ask {
    pub key: [u8; 32],
    pub slot: [u8; 16],
    pub seq: u64,
    pub challenge: Option<[u8; 16]>,
}

/// What the binding says of a send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The send goes, with this challenge for its key when the token is
    /// unconfirmed; `confirms` when it confirms its key; `then` is the
    /// binding once the platform took it.
    Pass { challenge: Option<[u8; 16]>, confirms: bool, then: Binding },
    /// Refused (`stale`).
    Stale,
    /// Refused (`stale`), and the token may be sent this challenge on its
    /// own, for the send's key; the binding does not change.
    Challenge { value: [u8; 16] },
}

/// Makes the challenge for a key, a generation and a period: the
/// service's keyed function of them and the token.
pub type Mint<'a> = &'a dyn Fn(&[u8; 32], u32, u64) -> [u8; 16];

/// The period of `now_ms`.
pub fn period(now_ms: u64) -> u64 {
    now_ms / CHALLENGE_PERIOD_MS
}

/// Compares two challenges in time that does not depend on where they
/// differ.
fn same(a: &[u8; 16], b: &[u8; 16]) -> bool {
    a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

impl Binding {
    fn seq(&self, key: &[u8; 32], slot: &[u8; 16]) -> Option<u64> {
        self.slots.iter().find(|s| &s.key == key && &s.slot == slot).map(|s| s.seq)
    }

    fn raise(&mut self, key: [u8; 32], slot: [u8; 16], seq: u64) {
        match self.slots.iter_mut().find(|s| s.key == key && s.slot == slot) {
            Some(s) => s.seq = s.seq.max(seq),
            None => {
                if self.slots.len() >= SLOTS_MAX {
                    // The key with the most slots gives its oldest (seq is a
                    // clock: the lowest), so many keys of a stranger's never
                    // push out the slots of a key with few.
                    let mut most: Option<([u8; 32], usize)> = None;
                    for s in &self.slots {
                        let n = self.slots.iter().filter(|t| t.key == s.key).count();
                        if most.is_none_or(|(_, m)| n > m) {
                            most = Some((s.key, n));
                        }
                    }
                    if let Some((k, _)) = most
                        && let Some(i) = self
                            .slots
                            .iter()
                            .enumerate()
                            .filter(|(_, s)| s.key == k)
                            .min_by_key(|(_, s)| s.seq)
                            .map(|(i, _)| i)
                    {
                        self.slots.remove(i);
                    }
                }
                self.slots.push(Slot { key, slot, seq });
            }
        }
    }

    /// Whether the binding is confirmed.
    pub fn confirmed(&self) -> bool {
        self.key.is_some()
    }

    /// Reads a time from a clock that may have been ahead as no later
    /// than now (on load and before each judgement).
    pub fn clamp(&mut self, now_ms: u64) {
        self.used_ms = self.used_ms.min(now_ms);
    }
}

/// Judges a send against the token's binding at `now_ms`; `mint` makes
/// the token's challenges.
pub fn judge(old: Option<&Binding>, a: &Ask, now_ms: u64, mint: Mint<'_>) -> Verdict {
    if !push::seq_in_time(a.seq, now_ms) {
        return Verdict::Stale;
    }
    let mut b = old.cloned().unwrap_or_default();
    b.clamp(now_ms);
    let p = period(now_ms);
    // The challenge made for this token, this key and this generation, in
    // this period or the one before, carried back under the key's
    // signature: the token's holder confirms the key.
    let proved = a.challenge.is_some_and(|c| {
        same(&c, &mint(&a.key, b.generation, p)) || (p > 0 && same(&c, &mint(&a.key, b.generation, p - 1)))
    });
    let stale = b.seq(&a.key, &a.slot).is_some_and(|s| a.seq < s);
    match b.key {
        Some(k) if k == a.key => {
            if stale {
                return Verdict::Stale;
            }
            b.raise(a.key, a.slot, a.seq);
            b.used_ms = now_ms;
            Verdict::Pass { challenge: None, confirms: false, then: b }
        }
        _ if proved => {
            if stale {
                return Verdict::Stale;
            }
            // Confirmed: the key's own slots stay, the others' go, and every
            // challenge made so far is dead.
            b.key = Some(a.key);
            b.generation = b.generation.wrapping_add(1);
            b.slots.retain(|s| s.key == a.key);
            b.raise(a.key, a.slot, a.seq);
            b.used_ms = now_ms;
            Verdict::Pass { challenge: None, confirms: true, then: b }
        }
        Some(_) => Verdict::Challenge { value: mint(&a.key, b.generation, p) },
        None => {
            if stale {
                return Verdict::Stale;
            }
            let c = mint(&a.key, b.generation, p);
            b.raise(a.key, a.slot, a.seq);
            b.used_ms = now_ms;
            Verdict::Pass { challenge: Some(c), confirms: false, then: b }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: u64 = 1_800_000_000_000;
    const PHONE: [u8; 32] = [1; 32];
    const STRANGER: [u8; 32] = [2; 32];
    const A: [u8; 16] = [10; 16];
    const B: [u8; 16] = [11; 16];

    /// A stand-in for the service's keyed function: distinct per key,
    /// generation and period.
    fn mint(k: &[u8; 32], g: u32, p: u64) -> [u8; 16] {
        let mut o = [0u8; 16];
        o[..2].copy_from_slice(&k[..2]);
        o[2..6].copy_from_slice(&g.to_be_bytes());
        o[6..14].copy_from_slice(&p.to_be_bytes());
        o
    }

    fn ask(key: [u8; 32], slot: [u8; 16], seq: u64, challenge: Option<[u8; 16]>) -> Ask {
        Ask { key, slot, seq, challenge }
    }

    fn j(old: Option<&Binding>, a: &Ask, now: u64) -> Verdict {
        judge(old, a, now, &mint)
    }

    fn pass(v: Verdict) -> (Option<[u8; 16]>, Binding) {
        match v {
            Verdict::Pass { challenge, then, .. } => (challenge, then),
            other => panic!("refused: {other:?}"),
        }
    }

    #[test]
    fn a_stranger_first_then_the_phone_the_phone_is_never_refused() {
        // A stranger's key binds nothing: its send passes with a challenge
        // for its own key, which only the token's holder sees.
        let (c1, b) = pass(j(None, &ask(STRANGER, A, T, None), T));
        assert!(c1.is_some() && !b.confirmed());
        // The phone's key: passes, with a challenge for the phone's key.
        let (c2, b) = pass(j(Some(&b), &ask(PHONE, A, T, None), T));
        assert_ne!(c1, c2);
        // The phone registers again over its challenge: confirmed.
        let v = j(Some(&b), &ask(PHONE, A, T + 1, c2), T + 1);
        assert!(matches!(v, Verdict::Pass { confirms: true, .. }));
        let (_, b) = pass(v);
        assert_eq!(b.key, Some(PHONE));
        assert!(b.slots.iter().all(|s| s.key == PHONE));
        // From now the stranger is refused, and the phone's sends pass.
        assert!(matches!(j(Some(&b), &ask(STRANGER, A, T + 2, None), T + 2), Verdict::Challenge { .. }));
        assert!(matches!(j(Some(&b), &ask(PHONE, A, T + 1, None), T + 2), Verdict::Pass { .. }));
    }

    #[test]
    fn no_number_of_other_keys_pushes_the_phones_challenge_out() {
        let (c, mut b) = pass(j(None, &ask(PHONE, A, T, None), T));
        // A thousand sends under a thousand keys of someone else's, each
        // with its own challenge: nothing is kept per key.
        for i in 0..1000u32 {
            let mut k = [3u8; 32];
            k[..4].copy_from_slice(&i.to_be_bytes());
            b = pass(j(Some(&b), &ask(k, [i as u8; 16], T + 1, None), T + 1)).1;
        }
        let (_, b) = pass(j(Some(&b), &ask(PHONE, A, T + 2, c), T + 2));
        assert_eq!(b.key, Some(PHONE));
    }

    #[test]
    fn a_challenge_made_before_a_confirmation_is_dead_after_it_for_every_key() {
        let (cp, b) = pass(j(None, &ask(PHONE, A, T, None), T));
        let (cs, b) = pass(j(Some(&b), &ask(STRANGER, B, T, None), T));
        let (_, b) = pass(j(Some(&b), &ask(PHONE, A, T + 1, cp), T + 1));
        assert_eq!(b.generation, 1);
        // The stranger's challenge (had it seen it) confirms nothing now.
        assert!(matches!(j(Some(&b), &ask(STRANGER, B, T + 2, cs), T + 2), Verdict::Challenge { .. }));
        // The phone reinstalls with a new key, which takes the binding by
        // its own new challenge; after that the old key's is dead too.
        let new = [4u8; 32];
        let Verdict::Challenge { value } = j(Some(&b), &ask(new, A, T + 3, None), T + 3) else { panic!() };
        let (_, b2) = pass(j(Some(&b), &ask(new, A, T + 4, Some(value)), T + 4));
        assert_eq!((b2.key, b2.generation), (Some(new), 2));
        // Every challenge of the phone's old key made before, of either
        // generation, is dead under the new binding.
        for old in [cp.unwrap(), mint(&PHONE, 1, period(T))] {
            assert!(matches!(j(Some(&b2), &ask(PHONE, A, T + 5, Some(old)), T + 5), Verdict::Challenge { .. }));
        }
    }

    #[test]
    fn a_challenge_serves_this_period_and_the_one_before_with_its_generation() {
        let start = (period(T) + 1) * CHALLENGE_PERIOD_MS - 1; // the last ms of a period
        let (c, b) = pass(j(None, &ask(PHONE, A, start, None), start));
        // In the next period: taken.
        let next = start + 2;
        let v = j(Some(&b), &ask(PHONE, A, next, c), next);
        assert!(matches!(v, Verdict::Pass { confirms: true, .. }));
        // Two periods on: dead, a new one is handed out.
        let late = start + CHALLENGE_PERIOD_MS + 2;
        let (c2, b2) = pass(j(Some(&b), &ask(PHONE, A, late, c), late));
        assert!(!b2.confirmed());
        assert_ne!(c, c2);
        // The previous period's under another generation confirms nothing.
        let mut other = b.clone();
        other.generation = 7;
        let v = j(Some(&other), &ask(PHONE, A, next, c), next);
        assert!(matches!(v, Verdict::Pass { confirms: false, .. }));
    }

    #[test]
    fn a_seq_more_than_a_day_ahead_is_refused() {
        assert_eq!(j(None, &ask(PHONE, A, T + push::MAX_SEQ_AHEAD_MS + 1, None), T), Verdict::Stale);
        assert!(matches!(j(None, &ask(PHONE, A, T + push::MAX_SEQ_AHEAD_MS, None), T), Verdict::Pass { .. }));
    }

    #[test]
    fn two_groups_of_one_phone_keep_their_own_numbers() {
        let (c, b) = pass(j(None, &ask(PHONE, A, T, None), T));
        let (_, b) = pass(j(Some(&b), &ask(PHONE, A, T, c), T));
        // Group B registered five minutes later; group A's sends still pass.
        let (_, b) = pass(j(Some(&b), &ask(PHONE, B, T + 300_000, None), T + 300_000));
        let (_, b) = pass(j(Some(&b), &ask(PHONE, A, T, None), T + 300_001));
        let (_, b) = pass(j(Some(&b), &ask(PHONE, B, T + 300_000, None), T + 300_002));
        // A registers again: A's old number is stale, B's still passes.
        let (_, b) = pass(j(Some(&b), &ask(PHONE, A, T + 600_000, None), T + 600_000));
        assert_eq!(j(Some(&b), &ask(PHONE, A, T, None), T + 600_001), Verdict::Stale);
        assert!(matches!(j(Some(&b), &ask(PHONE, B, T + 300_000, None), T + 600_001), Verdict::Pass { .. }));
    }

    #[test]
    fn a_confirmed_key_moves_only_by_a_confirmed_challenge_never_by_time() {
        let (c, b) = pass(j(None, &ask(PHONE, A, T, None), T));
        let (_, b) = pass(j(Some(&b), &ask(PHONE, A, T, c), T));
        // Years without a send: still bound to the phone's key.
        let later = T + 3000 * 24 * 3600 * 1000;
        let Verdict::Challenge { value } = j(Some(&b), &ask(STRANGER, A, later, None), later) else {
            panic!("a stranger took the binding by time")
        };
        // Guessing, or another key's challenge, fails.
        assert!(matches!(j(Some(&b), &ask(STRANGER, A, later, Some([0; 16])), later), Verdict::Challenge { .. }));
        let new = [3u8; 32];
        let Verdict::Challenge { value: v2 } = j(Some(&b), &ask(new, A, later, None), later) else { panic!() };
        assert_ne!(value, v2);
        assert!(matches!(j(Some(&b), &ask(new, A, later, Some(value)), later), Verdict::Challenge { .. }));
        let (_, b) = pass(j(Some(&b), &ask(new, A, later, Some(v2)), later));
        assert_eq!(b.key, Some(new));
        // The first challenge serves no more.
        assert!(matches!(j(Some(&b), &ask(PHONE, A, later, c), later), Verdict::Challenge { .. }));
    }

    #[test]
    fn a_clock_that_was_ahead_is_read_as_now() {
        let (c, mut b) = pass(j(None, &ask(PHONE, A, T, None), T + 3650 * 24 * 3600 * 1000));
        b.clamp(T);
        assert_eq!(b.used_ms, T);
        // That challenge was made for a period far ahead: dead now, a new one
        // is handed out and serves.
        let (c2, b) = pass(j(Some(&b), &ask(PHONE, A, T, c), T));
        assert!(!b.confirmed());
        assert!(pass(j(Some(&b), &ask(PHONE, A, T, c2), T)).1.confirmed());
    }

    #[test]
    fn slots_are_bounded_and_many_keys_do_not_push_out_a_key_with_few() {
        let (_, mut b) = pass(j(None, &ask(PHONE, A, T, None), T));
        for i in 0..40u8 {
            b = pass(j(Some(&b), &ask(STRANGER, [i; 16], T + 1 + u64::from(i), None), T + 100)).1;
        }
        assert_eq!(b.slots.len(), SLOTS_MAX);
        assert!(b.slots.iter().any(|s| s.key == PHONE && s.slot == A), "the phone's one slot stays");
        assert!(b.slots.iter().any(|s| s.seq == T + 40), "the newest stay");
    }
}
