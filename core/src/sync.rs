// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! A mutex for the core: the standard library's with the std feature, a
//! spin lock without it.

/// A mutual exclusion lock whose lock never fails: a thread that panicked
/// while holding it leaves the data as it was.
pub struct Mutex<T> {
    #[cfg(feature = "std")]
    inner: std::sync::Mutex<T>,
    #[cfg(not(feature = "std"))]
    inner: spin::Mutex<T>,
}

#[cfg(feature = "std")]
pub type Guard<'a, T> = std::sync::MutexGuard<'a, T>;
#[cfg(not(feature = "std"))]
pub type Guard<'a, T> = spin::MutexGuard<'a, T>;

impl<T> Mutex<T> {
    pub const fn new(v: T) -> Mutex<T> {
        #[cfg(feature = "std")]
        return Mutex { inner: std::sync::Mutex::new(v) };
        #[cfg(not(feature = "std"))]
        return Mutex { inner: spin::Mutex::new(v) };
    }

    pub fn lock(&self) -> Guard<'_, T> {
        #[cfg(feature = "std")]
        return self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        #[cfg(not(feature = "std"))]
        return self.inner.lock();
    }
}
