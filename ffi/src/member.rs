// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The member inside a phone's app (the Aurora, HarmonyOS, iPhone and
//! Android apps): cbb's member of 0.6 (`live::Phone`, on `cbb_member::Live`)
//! with the app's key, which stays where the app keeps it and signs through
//! the callback the join takes too. The member runs on threads of its own
//! and calls the app back with each event (`Event`). The app asks it
//! everything else through one call, `cbb_member_call`, a JSON request
//! `{op, args}` and its answer, as `cbb_call` asks the core
//! (docs/core-api.md, "The member"). A group made before 0.6 runs no member
//! (D-126).

use std::sync::Mutex;

use cbb_core::certs;
use cbb_core::error::{Error, Result};
use cbb_core::media::Part;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::join::{SignFn, answer};

pub(crate) mod live;

/// Gets an event as JSON bytes, on one of the member's threads.
pub use crate::join::EventFn;

/// The app's keys for the servers, which `cbb_member_servers` takes: the
/// member of 0.6 keeps the group's server credentials itself and calls it
/// no more. It stays until the Harmony app, the call's last caller, drops
/// it.
pub type KeysFn = unsafe extern "C" fn(
    ctx: *mut core::ffi::c_void,
    op: i32,
    name: *const u8,
    name_len: usize,
    digest: *const u8,
    out: *mut u8,
    out_len: *mut usize,
) -> i32;

fn yes() -> bool {
    true
}

/// A request of cbb_member_call.
#[derive(Deserialize)]
struct Request {
    op: String,
    #[serde(default)]
    args: Value,
}

/// A part of images or files the app hands in: clipboard data (`type`)
/// with its bytes in `data`, or a file or folder (`path`) with the file on
/// the phone in `file`.
#[derive(Deserialize)]
struct PartArgs {
    #[serde(rename = "type", default)]
    kind: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    dir: bool,
    #[serde(with = "certs::b64::opt", default)]
    data: Option<Vec<u8>>,
    #[serde(default)]
    file: Option<String>,
}

#[derive(Deserialize)]
struct MediaArgs {
    #[serde(default)]
    text: String,
    parts: Vec<PartArgs>,
}

#[derive(Deserialize)]
struct FetchArgs {
    id: String,
    /// The most bytes of the sealed blob the phone fetches.
    max: u64,
    /// A new folder to open the copy into.
    out: String,
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum Event<'a> {
    /// A text for the phone's clipboard; ttl_ms bounds how long a secret
    /// may stay there.
    Write {
        text: &'a str,
        kind: &'a str,
        ttl_ms: Option<u64>,
    },
    Log {
        line: &'a str,
    },
    /// Something in the member broke (a panic in one of its threads,
    /// docs/core-api.md "Panics"): what and where. The app shows it and
    /// starts the member again.
    Panic {
        details: &'a str,
    },
    /// A copy that became the group's current one from another member.
    Copy {
        copy: Value,
    },
    /// An admin muted the phone, or ended its mute: for_ms is how long it
    /// lasts, 0 for until an admin unmutes it.
    Mute {
        muted: bool,
        for_ms: i64,
        by: &'a str,
    },
    /// An admin turned the phone's sync off or on (a group of 0.6): the
    /// member did it; the app shows it.
    Sync {
        off: bool,
        by: &'a str,
    },
}

#[derive(Deserialize)]
struct SyncArgs {
    on: bool,
    #[serde(default)]
    for_ms: i64,
}

fn part_json(p: &Part, at: &std::path::Path) -> Value {
    json!({
        "type": p.kind,
        "path": p.path,
        "dir": p.dir,
        "size": p.size,
        "file": at.to_string_lossy(),
    })
}

#[cfg(test)]
fn b64(b: &[u8]) -> Value {
    #[derive(Serialize)]
    struct B<'a>(#[serde(with = "certs::b64")] &'a [u8]);
    serde_json::to_value(B(b)).unwrap_or(Value::Null)
}

fn args<T: for<'de> Deserialize<'de>>(v: Value) -> Result<T> {
    serde_json::from_value(v).map_err(|e| Error::msg(format!("the request's arguments do not decode: {e}")))
}

/// The app's callback and its context, called from the member's threads.
#[derive(Clone, Copy)]
struct Events {
    f: EventFn,
    ctx: usize,
}

impl Events {
    fn send(&self, e: &Event<'_>) {
        if let Ok(b) = serde_json::to_vec(e) {
            // SAFETY: the app gave a callback that stays valid, and may be
            // called from any thread, until cbb_member_stop returns.
            unsafe { (self.f)(self.ctx as *mut core::ffi::c_void, b.as_ptr(), b.len()) }
        }
    }
}

/// The lock's value, also after a thread panicked holding it.
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The phone's member of 0.6 (`live::Phone`), which runs when the app's
/// folder holds the group's `group.cbor`. A group made before 0.6 runs no
/// member (D-126): the app says to make a new one.
pub struct Member(Box<live::Phone>);

/// What `cbb_member_start` answers for an app folder without a group of
/// 0.6: a group made before 0.6, which the apps tell the person to replace
/// with a new one (D-126).
pub const BEFORE_06: &str = "this group was made before 0.6, which this version no longer runs: make a new group";

impl Member {
    /// Starts the member the app's folder holds a group of 0.6 for.
    pub fn start(request: &[u8], sign: SignFn, events: EventFn, ctx: usize) -> (Option<Member>, Vec<u8>) {
        if !live::on_06(request) {
            return (None, answer::<()>(Err(Error::msg(BEFORE_06))));
        }
        match live::Phone::start(request, sign, events, ctx) {
            Ok(p) => (Some(Member(Box::new(p))), answer(Ok(json!({})))),
            Err(e) => (None, answer::<()>(Err(e))),
        }
    }

    pub fn call(&self, request: &[u8]) -> Vec<u8> {
        self.0.call(request)
    }

    /// The member of 0.6 keeps the group's server credentials itself:
    /// this answers that it serves none for the app (until the Harmony app,
    /// its last caller, drops the call).
    pub fn servers(&self, keys: KeysFn, ctx: usize) -> Vec<u8> {
        self.0.servers(keys, ctx)
    }

    pub fn stop(&self) {
        self.0.stop()
    }

    pub fn manage(&self, request: &[u8], sign: SignFn, ctx: usize) -> Vec<u8> {
        self.0.manage(request, sign, ctx)
    }

    pub fn manage_watch(&self) -> Vec<u8> {
        self.0.manage_watch()
    }

    /// A pairing window on the records of 0.6.
    pub fn window(&self, request: &[u8], sign: SignFn, ctx: usize) -> (Option<crate::window::Window>, Vec<u8>) {
        self.0.window(request, sign, ctx)
    }

    /// A remote invitation: the member's (`Live::open_invitation`).
    pub fn invite(&self, request: &[u8], sign: SignFn, ctx: usize) -> (Option<crate::invite::Invite>, Vec<u8>) {
        crate::invite::Invite::new_live(self.0.live(), request, sign, ctx)
    }
}
