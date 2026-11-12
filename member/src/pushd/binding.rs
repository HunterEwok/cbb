// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! A token's binding to the phone's send key (format section 20.4).
//!
//! - While no key is confirmed, a send under any key passes, and the
//!   service hands each key that shows up a challenge, which goes to the
//!   token with the send (the phone's alert pushes carry it).
//! - A key is confirmed by a send whose signature covers the challenge the
//!   service made for that token and that key, within [`CHALLENGE_LIFE_MS`]:
//!   only the token's holder saw it. A challenge serves once; one made for
//!   another key, or another token, or past its life confirms nothing.
//! - Once a key is confirmed, only that key sends. Another key gets a
//!   challenge on its own (a push with no body, within the token's budget
//!   for them) and takes the binding only by confirming it; never by time.
//! - The highest seq is kept per (key, slot): each of the phone's groups
//!   registers under a slot of its own, so one group's registration never
//!   silences another's. A seq more than a day ahead of the service's
//!   clock is refused: seq is a clock by rule.

use cbb_core::push;

/// How long a challenge serves.
pub const CHALLENGE_LIFE_MS: u64 = 14 * 24 * 3600 * 1000;
/// Slots and open challenges kept per token at most: a phone in more
/// groups than this loses the oldest slot's seq, never a binding.
pub const SLOTS_MAX: usize = 16;
pub const PENDING_MAX: usize = 4;
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

/// A challenge the service made for one key of this token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pending {
    pub key: [u8; 32],
    pub value: [u8; 16],
    pub made_ms: u64,
}

/// One token's binding, filed under the token's keyed hash.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Binding {
    /// The hash of the confirmed send key's encoding.
    pub key: Option<[u8; 32]>,
    pub slots: Vec<Slot>,
    pub pending: Vec<Pending>,
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
    /// The send goes, with this challenge for its key when there is one;
    /// `then` is the binding once the platform took it.
    Pass { challenge: Option<[u8; 16]>, then: Binding },
    /// Refused (`stale`).
    Stale,
    /// Refused (`stale`), and the token may be sent this challenge on its
    /// own, for the send's key: `then` holds it once the platform took it.
    Challenge { value: [u8; 16], then: Binding },
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
                    // seq is a clock: the lowest is the oldest registration.
                    if let Some(i) = self.slots.iter().enumerate().min_by_key(|(_, s)| s.seq).map(|(i, _)| i) {
                        self.slots.remove(i);
                    }
                }
                self.slots.push(Slot { key, slot, seq });
            }
        }
    }

    /// The live challenge for `key`, made now with `draw` when there is
    /// none.
    fn challenge_for(&mut self, key: [u8; 32], now_ms: u64, draw: &mut dyn FnMut() -> [u8; 16]) -> [u8; 16] {
        self.pending.retain(|p| live(p, now_ms));
        if let Some(p) = self.pending.iter().find(|p| p.key == key) {
            return p.value;
        }
        if self.pending.len() >= PENDING_MAX {
            self.pending.remove(0);
        }
        let value = draw();
        self.pending.push(Pending { key, value, made_ms: now_ms });
        value
    }

    /// Whether the binding is confirmed.
    pub fn confirmed(&self) -> bool {
        self.key.is_some()
    }

    /// Reads a time from a clock that may have been ahead as no later
    /// than now (on load and before each judgement).
    pub fn clamp(&mut self, now_ms: u64) {
        self.used_ms = self.used_ms.min(now_ms);
        for p in &mut self.pending {
            p.made_ms = p.made_ms.min(now_ms);
        }
    }
}

fn live(p: &Pending, now_ms: u64) -> bool {
    now_ms.saturating_sub(p.made_ms) <= CHALLENGE_LIFE_MS
}

/// Judges a send against the token's binding at `now_ms`; `draw` makes a
/// new challenge.
pub fn judge(old: Option<&Binding>, a: &Ask, now_ms: u64, draw: &mut dyn FnMut() -> [u8; 16]) -> Verdict {
    if !push::seq_in_time(a.seq, now_ms) {
        return Verdict::Stale;
    }
    let mut b = old.cloned().unwrap_or_default();
    b.clamp(now_ms);
    // The challenge made for this token and this key, carried back under
    // the key's signature: the token's holder confirms the key.
    let proved =
        a.challenge.is_some_and(|c| b.pending.iter().any(|p| p.key == a.key && p.value == c && live(p, now_ms)));
    let stale = b.seq(&a.key, &a.slot).is_some_and(|s| a.seq < s);
    match b.key {
        Some(k) if k == a.key => {
            if stale {
                return Verdict::Stale;
            }
            b.raise(a.key, a.slot, a.seq);
            b.used_ms = now_ms;
            Verdict::Pass { challenge: None, then: b }
        }
        _ if proved => {
            if stale {
                return Verdict::Stale;
            }
            // Confirmed: the key's own slots stay, the others' and the open
            // challenges go (the one just used serves no more).
            b.key = Some(a.key);
            b.slots.retain(|s| s.key == a.key);
            b.pending.clear();
            b.raise(a.key, a.slot, a.seq);
            b.used_ms = now_ms;
            Verdict::Pass { challenge: None, then: b }
        }
        Some(_) => {
            let value = b.challenge_for(a.key, now_ms, draw);
            Verdict::Challenge { value, then: b }
        }
        None => {
            if stale {
                return Verdict::Stale;
            }
            let c = b.challenge_for(a.key, now_ms, draw);
            b.raise(a.key, a.slot, a.seq);
            b.used_ms = now_ms;
            Verdict::Pass { challenge: Some(c), then: b }
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

    fn draws() -> impl FnMut() -> [u8; 16] {
        let mut n = 0u8;
        move || {
            n += 1;
            [n; 16]
        }
    }

    fn ask(key: [u8; 32], slot: [u8; 16], seq: u64, challenge: Option<[u8; 16]>) -> Ask {
        Ask { key, slot, seq, challenge }
    }

    fn pass(v: Verdict) -> (Option<[u8; 16]>, Binding) {
        match v {
            Verdict::Pass { challenge, then } => (challenge, then),
            other => panic!("refused: {other:?}"),
        }
    }

    #[test]
    fn a_stranger_first_then_the_phone_the_phone_is_never_refused() {
        let mut d = draws();
        // A stranger's key binds nothing: its send passes with a challenge
        // for its own key, which only the token's holder sees.
        let (c1, b) = pass(judge(None, &ask(STRANGER, A, T, None), T, &mut d));
        assert!(c1.is_some() && !b.confirmed());
        // The phone's key: passes, with a challenge for the phone's key.
        let (c2, b) = pass(judge(Some(&b), &ask(PHONE, A, T, None), T, &mut d));
        assert_ne!(c1, c2);
        // The phone registers again over its challenge: confirmed.
        let (_, b) = pass(judge(Some(&b), &ask(PHONE, A, T + 1, c2), T + 1, &mut d));
        assert_eq!(b.key, Some(PHONE));
        assert!(b.pending.is_empty() && b.slots.iter().all(|s| s.key == PHONE));
        // From now the stranger is refused, and the phone's sends pass.
        assert!(matches!(judge(Some(&b), &ask(STRANGER, A, T + 2, None), T + 2, &mut d), Verdict::Challenge { .. }));
        assert!(matches!(judge(Some(&b), &ask(PHONE, A, T + 1, None), T + 2, &mut d), Verdict::Pass { .. }));
    }

    #[test]
    fn a_seq_more_than_a_day_ahead_is_refused() {
        let mut d = draws();
        assert_eq!(judge(None, &ask(PHONE, A, T + push::MAX_SEQ_AHEAD_MS + 1, None), T, &mut d), Verdict::Stale);
        assert!(matches!(
            judge(None, &ask(PHONE, A, T + push::MAX_SEQ_AHEAD_MS, None), T, &mut d),
            Verdict::Pass { .. }
        ));
    }

    #[test]
    fn two_groups_of_one_phone_keep_their_own_numbers() {
        let mut d = draws();
        let (c, b) = pass(judge(None, &ask(PHONE, A, T, None), T, &mut d));
        let (_, b) = pass(judge(Some(&b), &ask(PHONE, A, T, c), T, &mut d));
        // Group B registered five minutes later; group A's sends still pass.
        let (_, b) = pass(judge(Some(&b), &ask(PHONE, B, T + 300_000, None), T + 300_000, &mut d));
        let (_, b) = pass(judge(Some(&b), &ask(PHONE, A, T, None), T + 300_001, &mut d));
        let (_, b) = pass(judge(Some(&b), &ask(PHONE, B, T + 300_000, None), T + 300_002, &mut d));
        // A registers again: A's old number is stale, B's still passes.
        let (_, b) = pass(judge(Some(&b), &ask(PHONE, A, T + 600_000, None), T + 600_000, &mut d));
        assert_eq!(judge(Some(&b), &ask(PHONE, A, T, None), T + 600_001, &mut d), Verdict::Stale);
        assert!(matches!(
            judge(Some(&b), &ask(PHONE, B, T + 300_000, None), T + 600_001, &mut d),
            Verdict::Pass { .. }
        ));
    }

    #[test]
    fn a_confirmed_key_moves_only_by_a_new_confirmed_challenge() {
        let mut d = draws();
        let (c, b) = pass(judge(None, &ask(PHONE, A, T, None), T, &mut d));
        let (_, b) = pass(judge(Some(&b), &ask(PHONE, A, T, c), T, &mut d));
        // Years without a send: still bound to the phone's key.
        let later = T + 3000 * 24 * 3600 * 1000;
        let Verdict::Challenge { value, then } = judge(Some(&b), &ask(STRANGER, A, later, None), later, &mut d) else {
            panic!("a stranger took the binding by time")
        };
        // The stranger's challenge went to the token; the stranger never
        // sees it. Guessing, or replaying another key's challenge, fails.
        assert!(matches!(
            judge(Some(&then), &ask(STRANGER, A, later, Some([0; 16])), later, &mut d),
            Verdict::Challenge { .. }
        ));
        // The phone reinstalled with a new send key, which saw the challenge
        // through the platform: it takes the binding.
        let new = [3u8; 32];
        let Verdict::Challenge { value: v2, then } = judge(Some(&then), &ask(new, A, later, None), later, &mut d)
        else {
            panic!()
        };
        assert_ne!(value, v2);
        // The phone's new key cannot use the stranger's challenge.
        assert!(matches!(
            judge(Some(&then), &ask(new, A, later, Some(value)), later, &mut d),
            Verdict::Challenge { .. }
        ));
        let (_, b) = pass(judge(Some(&then), &ask(new, A, later, Some(v2)), later, &mut d));
        assert_eq!(b.key, Some(new));
        // A challenge serves once: the old key with an old one stays out.
        assert!(matches!(judge(Some(&b), &ask(PHONE, A, later, c), later, &mut d), Verdict::Challenge { .. }));
    }

    #[test]
    fn a_challenge_past_its_life_confirms_nothing() {
        let mut d = draws();
        let (c, b) = pass(judge(None, &ask(PHONE, A, T, None), T, &mut d));
        let late = T + CHALLENGE_LIFE_MS + 1;
        let (c2, b2) = pass(judge(Some(&b), &ask(PHONE, A, late, c), late, &mut d));
        assert!(!b2.confirmed());
        assert_ne!(c, c2);
    }

    #[test]
    fn a_clock_that_was_ahead_is_read_as_now() {
        let mut d = draws();
        let (c, mut b) = pass(judge(None, &ask(PHONE, A, T, None), T + 3650 * 24 * 3600 * 1000, &mut d));
        b.clamp(T);
        assert_eq!(b.used_ms, T);
        assert!(b.pending.iter().all(|p| p.made_ms == T));
        assert!(pass(judge(Some(&b), &ask(PHONE, A, T, c), T, &mut d)).1.confirmed());
    }

    #[test]
    fn slots_and_challenges_are_bounded() {
        let mut d = draws();
        let mut b = Binding::default();
        for i in 0..40u8 {
            b = pass(judge(Some(&b), &ask([i; 32], [i; 16], T + u64::from(i), None), T + 100, &mut d)).1;
        }
        assert_eq!(b.slots.len(), SLOTS_MAX);
        assert_eq!(b.pending.len(), PENDING_MAX);
        // The newest stay.
        assert!(b.slots.iter().any(|s| s.seq == T + 39));
    }
}
