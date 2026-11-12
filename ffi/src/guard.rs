// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! A panic stops at the C functions (docs/core-api.md, "Panics"). The
//! apps' library is built with unwinding (the profile `app`), so a panic in
//! a call becomes that call's answer, code 5 `panic`, whose details say
//! what broke and where, and a panic in one of the member's threads becomes
//! a `panic` event to the app, which shows it and starts the member again.
//! Built with `panic = "abort"`, as the computers' `cbb` is, nothing
//! unwinds: the hook still records what broke, then the process ends and
//! the system's service manager starts it again.

use std::panic::{self, AssertUnwindSafe, PanicHookInfo};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, Once, PoisonError};

/// Where a panic's description goes besides the answer: a running member's
/// events.
pub type Sink = Box<dyn Fn(&str) + Send + Sync>;

static HOOK: Once = Once::new();
static LAST: Mutex<Option<String>> = Mutex::new(None);
static SINKS: Mutex<Vec<(u64, Sink)>> = Mutex::new(Vec::new());
static NEXT: AtomicU64 = AtomicU64::new(1);

/// What broke and where, as the answer's details and the event carry it:
/// the panic's message, its file, line and column, and the thread.
fn describe(info: &PanicHookInfo<'_>) -> String {
    let payload = info.payload();
    let what = payload
        .downcast_ref::<&str>()
        .map(|s| (*s).to_string())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "a panic without a message".to_string());
    let at = info.location().map(|l| format!(" at {}:{}:{}", l.file(), l.line(), l.column())).unwrap_or_default();
    let thread = std::thread::current();
    let name = thread.name().map(|n| format!(" in thread {n}")).unwrap_or_default();
    format!("panic: {what}{at}{name}")
}

/// Puts the hook in place once, before anything this library runs can
/// panic; the hook it replaces still runs after it.
pub fn install() {
    HOOK.call_once(|| {
        let earlier = panic::take_hook();
        panic::set_hook(Box::new(move |info| {
            let d = describe(info);
            *LAST.lock().unwrap_or_else(PoisonError::into_inner) = Some(d.clone());
            for (_, sink) in SINKS.lock().unwrap_or_else(PoisonError::into_inner).iter() {
                sink(&d);
            }
            earlier(info);
        }));
    });
}

/// The description of the last panic, empty when none was recorded.
fn last() -> String {
    LAST.lock().unwrap_or_else(PoisonError::into_inner).clone().unwrap_or_default()
}

/// The answer of a call that panicked.
pub fn panicked() -> Vec<u8> {
    cbb_core::api::panic_answer(&last())
}

/// Runs f, or gives what `fallback` makes when f panics.
pub fn or<T>(fallback: impl FnOnce() -> T, f: impl FnOnce() -> T) -> T {
    install();
    panic::catch_unwind(AssertUnwindSafe(f)).unwrap_or_else(|_| fallback())
}

/// Runs f, which gives an answer, or answers code 5 when it panics.
pub fn answer(f: impl FnOnce() -> Vec<u8>) -> Vec<u8> {
    or(panicked, f)
}

/// Sends each later panic's description to sink as well, until `unwatch`
/// with the number it gives.
pub fn watch(sink: Sink) -> u64 {
    install();
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    SINKS.lock().unwrap_or_else(PoisonError::into_inner).push((id, sink));
    id
}

/// Stops sending panics to the sink `watch` gave the number id.
pub fn unwatch(id: u64) {
    SINKS.lock().unwrap_or_else(PoisonError::into_inner).retain(|(i, _)| *i != id);
}

/// The answer of the last panic, for a function that could answer only
/// null; None when nothing panicked.
pub fn last_answer() -> Option<Vec<u8>> {
    LAST.lock().unwrap_or_else(PoisonError::into_inner).as_ref().map(|d| cbb_core::api::panic_answer(d))
}

/// Panics, inside the guard: the wrappers' tests check that the answer is
/// code 5 and that the app goes on (`cbb_test_panic`).
pub fn test_panic() -> Vec<u8> {
    answer(|| {
        #[allow(clippy::panic, reason = "the wrappers' tests need one panic to catch")]
        {
            panic!("cbb_test_panic: a panic the wrappers' tests ask for")
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_panic_is_an_answer_and_an_event() {
        let seen = std::sync::Arc::new(Mutex::new(Vec::<String>::new()));
        let s = seen.clone();
        let id = watch(Box::new(move |d| s.lock().unwrap().push(d.to_string())));
        let a: serde_json::Value = serde_json::from_slice(&test_panic()).unwrap();
        assert_eq!(a["error"]["code"], 5, "{a}");
        assert_eq!(a["error"]["name"], "panic");
        let details = a["error"]["details"].as_str().unwrap();
        assert!(details.starts_with("panic: cbb_test_panic:") && details.contains("guard.rs:"), "{details}");
        // A thread's panic reaches the sink, and the answer function
        // after it still answers.
        let t = std::thread::Builder::new()
            .name("node".into())
            .spawn(|| {
                #[allow(clippy::panic)]
                {
                    panic!("a thread broke")
                }
            })
            .unwrap();
        assert!(t.join().is_err());
        unwatch(id);
        let seen = seen.lock().unwrap();
        assert!(seen.iter().any(|d| d.contains("a thread broke") && d.ends_with("in thread node")), "{seen:?}");
        assert_eq!(answer(|| b"{}".to_vec()), b"{}");
        assert!(last_answer().is_some());
    }
}
