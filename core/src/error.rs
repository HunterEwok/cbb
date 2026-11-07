// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Errors with a message for the user and the cause behind it.
//!
//! Every error carries a short message that says what failed in words a
//! user understands, and the chain of underlying errors. The message is
//! always shown; the details (each cause with its type) are shown under it
//! in debug mode, and always written to the log. Debug mode follows the
//! build (on in a debug build, off in a release build); the program
//! overrides it with set_show_details (the lite member from `CBB_DEBUG` or the
//! `-debug` flag), so the details of an error in a release build can be
//! seen when needed.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::{String, ToString};
use core::fmt;
use core::sync::atomic::{AtomicU8, Ordering};

/// A failure: a message for the user, and the error that caused it.
pub struct Error {
    msg: String,
    cause: Option<Box<dyn core::error::Error + Send + Sync + 'static>>,
    cause_type: &'static str,
    // answer marks a refusal that is an answer, not a failure to get one:
    // a signature that does not verify, or a file older than one seen.
    answer: bool,
}

pub type Result<T, E = Error> = core::result::Result<T, E>;

impl Error {
    /// An error with a message and no underlying cause.
    pub fn msg(msg: impl Into<String>) -> Error {
        Error { msg: msg.into(), cause: None, cause_type: "", answer: false }
    }

    /// An error with a message, caused by err.
    pub fn with<E: core::error::Error + Send + Sync + 'static>(msg: impl Into<String>, err: E) -> Error {
        Error { msg: msg.into(), cause: Some(Box::new(err)), cause_type: core::any::type_name::<E>(), answer: false }
    }

    /// Wraps this error under a new message, keeping this one as the cause.
    pub fn context(self, msg: impl Into<String>) -> Error {
        let answer = self.answer;
        Error { msg: msg.into(), cause_type: "cbb_core::error::Error", cause: Some(Box::new(Cause(self))), answer }
    }

    /// Marks this error as an answer rather than a failure to get one, as
    /// Go's release.ErrSignature and release.ErrRollback: whoever asks
    /// several sources stops at it instead of asking the next. A context
    /// over it keeps the mark.
    pub fn answer(mut self) -> Error {
        self.answer = true;
        self
    }

    /// Whether this error, or the one under its contexts, is an answer.
    pub fn is_answer(&self) -> bool {
        self.answer
    }

    /// The message for the user.
    pub fn message(&self) -> &str {
        &self.msg
    }

    /// The underlying causes, one per line, each with its type where known.
    pub fn details(&self) -> String {
        let mut out = String::new();
        let mut cur: Option<&(dyn core::error::Error + 'static)> = self.cause.as_deref().map(|e| e as _);
        let mut ty = self.cause_type;
        while let Some(e) = cur {
            if let Some(Cause(inner)) = e.downcast_ref::<Cause>() {
                out.push_str(&format!("{}\n", inner.msg));
                cur = inner.cause.as_deref().map(|e| e as _);
                ty = inner.cause_type;
                continue;
            }
            if ty.is_empty() {
                out.push_str(&format!("{e} ({e:?})\n"));
            } else {
                out.push_str(&format!("{e} ({ty}: {e:?})\n"));
            }
            cur = e.source();
            ty = "";
        }
        out.trim_end().to_string()
    }

    /// The message and, in debug mode, the details under it.
    pub fn for_user(&self) -> String {
        let details = self.details();
        if show_details() && !details.is_empty() {
            format!("{}\n  details: {}", self.msg, details.replace('\n', "\n           "))
        } else {
            self.msg.clone()
        }
    }

    /// The message and the details on one line, for the log.
    pub fn for_log(&self) -> String {
        let details = self.details();
        if details.is_empty() { self.msg.clone() } else { format!("{}: {}", self.msg, details.replace('\n', ": ")) }
    }
}

/// An Error kept as the cause of another.
struct Cause(Error);

impl fmt::Debug for Cause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.msg)
    }
}

impl fmt::Display for Cause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.msg)
    }
}

impl core::error::Error for Cause {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.msg)
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.for_log())
    }
}

/// Adds a message for the user to the error of a Result.
pub trait Context<T> {
    fn context(self, msg: impl Into<String>) -> Result<T>;
}

impl<T, E: core::error::Error + Send + Sync + 'static> Context<T> for core::result::Result<T, E> {
    fn context(self, msg: impl Into<String>) -> Result<T> {
        self.map_err(|e| Error::with(msg, e))
    }
}

/// Adds a message to an Error, keeping it as the cause.
pub trait Wrap<T> {
    fn wrap(self, msg: impl Into<String>) -> Result<T>;
}

impl<T> Wrap<T> for Result<T> {
    fn wrap(self, msg: impl Into<String>) -> Result<T> {
        self.map_err(|e| e.context(msg))
    }
}

// 0: follow the build; 1: show; 2: hide.
static MODE: AtomicU8 = AtomicU8::new(0);

/// Turns the details on or off, overriding the build and CBB_DEBUG.
pub fn set_show_details(show: bool) {
    MODE.store(if show { 1 } else { 2 }, Ordering::Relaxed);
}

/// Reports whether errors show their details: as set_show_details set it,
/// else as the build.
pub fn show_details() -> bool {
    match MODE.load(Ordering::Relaxed) {
        1 => true,
        2 => false,
        _ => cfg!(debug_assertions),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn details_name_the_causes() {
        let io = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        let e = Error::with("cannot read the identity", io).context("cannot start");
        assert_eq!(e.message(), "cannot start");
        let d = e.details();
        // The type's path differs between Rust versions (std:: or core::).
        assert!(d.starts_with("cannot read the identity\ndenied ("), "{d}");
        assert!(d.contains("io::error::Error: "), "{d}");
        assert!(e.for_log().starts_with("cannot start: cannot read the identity: denied"), "{}", e.for_log());

        set_show_details(false);
        assert_eq!(e.for_user(), "cannot start");
        set_show_details(true);
        assert!(e.for_user().contains("details: cannot read the identity"));
        assert!(e.for_user().contains("PermissionDenied"));
    }
}
