// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The hybrid logical clock (docs/protocol.md, section 5), as Go's package
//! hlc implements it.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use core::fmt;

use crate::sync::Mutex;

/// The largest wall time a timestamp may carry: the last millisecond of the
/// year 9999.
pub const MAX_WALL: i64 = 253402300799999;

/// How far a received timestamp may be ahead of this clock, in
/// milliseconds: one further ahead is refused (Clock::ahead), so that no
/// member can move the group's clocks to MAX_WALL for good.
pub const MAX_AHEAD: i64 = 7 * 24 * 3600 * 1000;

/// A wall time before which the clock does not trust itself to refuse
/// timestamps for being ahead: a device without a real-time clock that has
/// not set its time yet (2026-01-01).
const PLAUSIBLE: i64 = 1767225600000;

/// Where a restarted clock starts: the mark it saved, unless the wall clock
/// reads 2026 or later and the mark is more than MAX_AHEAD ahead of it.
/// Such a mark comes from a clock that was set far ahead and then right:
/// every member with a right clock refused its timestamps, so keeping it
/// would leave the device's copies refused until real time caught up. Then
/// it returns the zero timestamp and true.
pub fn floor(mark: Timestamp, now: i64) -> (Timestamp, bool) {
    if now >= PLAUSIBLE && mark.wall > now.saturating_add(MAX_AHEAD) {
        return (Timestamp::default(), true);
    }
    (mark, false)
}

/// How far ahead of the clock the saved mark is set, in milliseconds.
const MARK_STEP: i64 = 10_000;

/// A point on the hybrid clock, ordered by wall time and then the logical
/// counter. The zero timestamp sorts first.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Debug, Hash)]
pub struct Timestamp {
    pub wall: i64,
    pub logical: u32,
}

impl Timestamp {
    pub fn is_zero(&self) -> bool {
        *self == Timestamp::default()
    }

    pub fn valid(&self) -> bool {
        (0..=MAX_WALL).contains(&self.wall)
    }

    /// Parses exactly the form "wall.logical" with a wall time of at most
    /// MAX_WALL.
    pub fn parse(s: &str) -> Option<Timestamp> {
        let (w, l) = s.split_once('.')?;
        let digits = |s: &str| !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit());
        if !digits(w) || !digits(l) {
            return None;
        }
        let wall: i64 = w.parse().ok()?;
        if wall > MAX_WALL {
            return None;
        }
        Some(Timestamp { wall, logical: l.parse().ok()? })
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.wall, self.logical)
    }
}

impl serde::Serialize for Timestamp {
    fn serialize<S: serde::Serializer>(&self, s: S) -> core::result::Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for Timestamp {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Timestamp::parse(&s).ok_or_else(|| serde::de::Error::custom(format!("timestamp {s:?} is not wall.logical")))
    }
}

type Save = Box<dyn FnMut(Timestamp) -> bool + Send>;

struct State {
    last: Timestamp,
    mark: Timestamp,
}

/// A hybrid logical clock. When it reaches the last mark it saved, it saves
/// a new one 10 seconds ahead, so a restart that passes the saved mark as
/// the floor never issues a timestamp below one issued before.
pub struct Clock {
    now: Box<dyn Fn() -> i64 + Send + Sync>,
    state: Mutex<State>,
    save: Mutex<Option<Save>>,
}

impl Clock {
    /// A clock that reads the wall time in milliseconds from now and never
    /// goes back before floor; save, if given, keeps the mark and reports
    /// whether it did.
    pub fn new(now: Box<dyn Fn() -> i64 + Send + Sync>, floor: Timestamp, save: Option<Save>) -> Clock {
        Clock { now, state: Mutex::new(State { last: floor, mark: floor }), save: Mutex::new(save) }
    }

    /// A timestamp for a local event, greater than every one returned or
    /// observed before, until MAX_WALL.
    pub fn now(&self) -> Timestamp {
        let mut st = self.state.lock();
        let pt = (self.now)().min(MAX_WALL);
        if pt > st.last.wall {
            st.last = Timestamp { wall: pt, logical: 0 };
        } else {
            tick(&mut st.last);
        }
        self.keep_mark(&mut st);
        st.last
    }

    /// Whether remote is more than MAX_AHEAD ahead of this clock's wall
    /// time, as Go's Ahead: the timestamps it issued or observed do not move
    /// that limit. A clock that reads before 2026 refuses nothing.
    pub fn ahead(&self, remote: Timestamp) -> bool {
        let reference = (self.now)();
        reference >= PLAUSIBLE && remote.wall > reference.saturating_add(MAX_AHEAD)
    }

    /// Moves the clock past a timestamp from another device.
    pub fn observe(&self, remote: Timestamp) {
        if !remote.valid() {
            return;
        }
        let mut st = self.state.lock();
        let pt = (self.now)().min(MAX_WALL);
        let wall = st.last.wall.max(remote.wall).max(pt);
        if wall == st.last.wall && wall == remote.wall {
            st.last.logical = st.last.logical.max(remote.logical);
            tick(&mut st.last);
        } else if wall == st.last.wall {
            tick(&mut st.last);
        } else if wall == remote.wall {
            st.last = remote;
            tick(&mut st.last);
        } else {
            st.last = Timestamp { wall, logical: 0 };
        }
        self.keep_mark(&mut st);
    }

    fn keep_mark(&self, st: &mut State) {
        let mut save = self.save.lock();
        let Some(save) = save.as_mut() else { return };
        if st.last < st.mark {
            return;
        }
        let mut next = Timestamp { wall: st.last.wall.saturating_add(MARK_STEP), logical: 0 };
        if st.last.wall > MAX_WALL - MARK_STEP {
            next = Timestamp {
                wall: MAX_WALL,
                logical: (st.last.logical as u64).saturating_add(MARK_STEP as u64).min(u32::MAX as u64) as u32,
            };
        }
        if next <= st.mark {
            return; // saturated
        }
        if save(next) {
            st.mark = next;
        }
    }
}

/// Advances the logical counter, moving to the next millisecond when it is
/// exhausted, and stopping at MAX_WALL.
fn tick(t: &mut Timestamp) {
    if t.logical < u32::MAX {
        t.logical = t.logical.saturating_add(1);
    } else if t.wall < MAX_WALL {
        *t = Timestamp { wall: t.wall.saturating_add(1), logical: 0 };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicI64, Ordering};

    fn clock(at: Arc<AtomicI64>) -> Clock {
        Clock::new(Box::new(move || at.load(Ordering::SeqCst)), Timestamp::default(), None)
    }

    #[test]
    fn now_and_observe() {
        let at = Arc::new(AtomicI64::new(1000));
        let c = clock(at.clone());
        assert_eq!(c.now(), Timestamp { wall: 1000, logical: 0 });
        assert_eq!(c.now(), Timestamp { wall: 1000, logical: 1 });
        c.observe(Timestamp { wall: 5000, logical: 7 });
        assert_eq!(c.now(), Timestamp { wall: 5000, logical: 9 });
        at.store(6000, Ordering::SeqCst);
        assert_eq!(c.now(), Timestamp { wall: 6000, logical: 0 });
        c.observe(Timestamp { wall: 6000, logical: 4 });
        assert_eq!(c.now(), Timestamp { wall: 6000, logical: 6 });
    }

    #[test]
    fn marks() {
        let saved = Arc::new(AtomicI64::new(0));
        let s = saved.clone();
        let c = Clock::new(
            Box::new(|| 1000),
            Timestamp::default(),
            Some(Box::new(move |t| {
                s.store(t.wall, Ordering::SeqCst);
                true
            })),
        );
        c.now();
        assert_eq!(saved.load(Ordering::SeqCst), 11000);
    }

    #[test]
    fn ahead() {
        let now = 1792886400000; // 2026-10-25
        let c = Clock::new(Box::new(move || now), Timestamp::default(), None);
        assert!(c.ahead(Timestamp { wall: MAX_WALL, logical: 0 }));
        assert!(!c.ahead(Timestamp { wall: now + MAX_AHEAD, logical: 0 }));
        let early = Clock::new(Box::new(|| 1000), Timestamp::default(), None);
        assert!(!early.ahead(Timestamp { wall: MAX_WALL, logical: 0 }));
    }

    #[test]
    fn floor_after_clock_ahead() {
        let now = 1792886400000; // 2026-10-25
        let day = 24 * 3600 * 1000;
        let behind = Timestamp { wall: now - day, logical: 3 };
        assert_eq!(floor(behind, now), (behind, false));
        let six = Timestamp { wall: now + 6 * day, logical: 0 };
        assert_eq!(floor(six, now), (six, false));
        let year = Timestamp { wall: now + 365 * day, logical: 0 };
        assert_eq!(floor(year, now), (Timestamp::default(), true));
        // A board without a real-time clock keeps its mark.
        assert_eq!(floor(year, 5), (year, false));
    }
}
