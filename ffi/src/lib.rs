// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The Rust core's one entry point as C functions (docs/core-api.md), for
//! every program that links the core: `cbb_call`, `cbb_free` and `cbb_abi`,
//! declared in `include/cbb_core.h`. Go links them through cgo, the Swift
//! kit through that header and the Kotlin kit through JNA, so the phones
//! do not write the group's rules again and none of them needs generated
//! bindings. A request and its answer are JSON bytes, so the binding stays
//! one function wide and each caller decodes with its own JSON reader.

// As in the core: nothing outside the tests may panic, since a panic here is
// a crash of the phone's app. The C functions are the only unsafe code.
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented
    )
)]

/// Answers one request of the core (docs/core-api.md). It never fails: a
/// refusal is an answer with an error code, a message for the user and
/// the details under it, which the apps show in debug mode and always log.
pub fn call(request: Vec<u8>) -> Vec<u8> {
    cbb_core::api::call(&request)
}

/// The version of the request and answer shapes this library speaks.
pub fn abi() -> u32 {
    cbb_core::api::ABI
}

/// The C form of `abi`.
#[unsafe(no_mangle)]
pub extern "C" fn cbb_abi() -> u32 {
    cbb_core::api::ABI
}

/// The C form of `call`: answers the `len` bytes at `request` with bytes
/// the caller owns and gives back with `cbb_free`, their length written to
/// `answer_len`. A null `request` with `len` 0 is an empty request. It
/// returns null only when `answer_len` is null or `request` is null with a
/// length.
///
/// # Safety
///
/// `request` must point to `len` readable bytes (or be null with `len`
/// 0) and `answer_len` to a writable `size_t`, for the time of the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cbb_call(request: *const u8, len: usize, answer_len: *mut usize) -> *mut u8 {
    if answer_len.is_null() || (request.is_null() && len != 0) {
        return core::ptr::null_mut();
    }
    let req: &[u8] = if len == 0 {
        &[]
    } else {
        // SAFETY: the caller gives len readable bytes at request, not null.
        unsafe { core::slice::from_raw_parts(request, len) }
    };
    let answer = cbb_core::api::call(req).into_boxed_slice();
    // SAFETY: the caller gives a writable size_t at answer_len, not null.
    unsafe { answer_len.write(answer.len()) };
    Box::into_raw(answer).cast::<u8>()
}

/// Gives back an answer of `cbb_call`, with the length it wrote. Null does
/// nothing.
///
/// # Safety
///
/// `answer` must be null or what `cbb_call` returned, with its length, and
/// not given back before.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cbb_free(answer: *mut u8, len: usize) {
    if answer.is_null() {
        return;
    }
    // SAFETY: answer and len are a boxed slice cbb_call let go of.
    drop(unsafe { Box::from_raw(core::ptr::slice_from_raw_parts_mut(answer, len)) });
}

#[cfg(feature = "member")]
pub mod admit;
#[cfg(feature = "join")]
pub mod join;
#[cfg(feature = "member")]
pub mod member;
#[cfg(feature = "join")]
pub mod qr;
#[cfg(feature = "tunnel")]
pub mod tunnel;

/// Hands an answer to C: its bytes, which the caller gives back with
/// `cbb_free`, their length written to `answer_len` when not null.
#[cfg(feature = "join")]
fn to_c(answer: Vec<u8>, answer_len: *mut usize) -> *mut u8 {
    if answer_len.is_null() {
        return core::ptr::null_mut();
    }
    let answer = answer.into_boxed_slice();
    // SAFETY: the caller gives a writable size_t at answer_len, not null.
    unsafe { answer_len.write(answer.len()) };
    Box::into_raw(answer).cast::<u8>()
}

/// The texts of the QR codes in a grey frame (src/qr.rs): `gray` holds
/// `height` rows of `width` bytes, `stride` bytes apart. The answer is
/// `{"texts": [...]}`; null only when `answer_len` is null or `gray` is.
///
/// # Safety
///
/// `gray` must point to `stride * (height - 1) + width` readable bytes and
/// `answer_len` to a writable `size_t`, for the time of the call.
#[cfg(feature = "join")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cbb_qr_read(
    gray: *const u8,
    width: usize,
    height: usize,
    stride: usize,
    answer_len: *mut usize,
) -> *mut u8 {
    if gray.is_null() {
        return core::ptr::null_mut();
    }
    let len = stride.saturating_mul(height.saturating_sub(1)).saturating_add(width);
    // SAFETY: the caller gives that many readable bytes at gray.
    let frame = unsafe { core::slice::from_raw_parts(gray, len) };
    to_c(qr::read(frame, width, height, stride), answer_len)
}

/// Makes a group with the app's root key (src/join.rs, new_group):
/// `request` is its JSON, `sign` the root key's callback with `ctx`, called
/// during this call only. The answer has a join's fields.
///
/// # Safety
///
/// `request` must point to `len` readable bytes and `answer_len` to a
/// writable `size_t`, for the time of the call.
#[cfg(feature = "join")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cbb_group_new(
    request: *const u8,
    len: usize,
    sign: join::SignFn,
    ctx: *mut core::ffi::c_void,
    answer_len: *mut usize,
) -> *mut u8 {
    if request.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: the caller gives len readable bytes at request.
    let req = unsafe { core::slice::from_raw_parts(request, len) };
    to_c(join::new_group(req, sign, ctx as usize), answer_len)
}

/// A joiner that listens with the app's key (src/join.rs): `request` is
/// its JSON, `sign` the key's callback with `ctx`, which must stay valid
/// until `cbb_join_free`. Writes the answer to `answer` and `answer_len`
/// and returns the joiner, or null when the answer is an error.
///
/// # Safety
///
/// `request` must point to `len` readable bytes, `answer` and `answer_len`
/// to writable pointers, for the time of the call.
#[cfg(feature = "join")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cbb_join_new(
    request: *const u8,
    len: usize,
    sign: join::SignFn,
    ctx: *mut core::ffi::c_void,
    answer: *mut *mut u8,
    answer_len: *mut usize,
) -> *mut join::Join {
    if request.is_null() || answer.is_null() || answer_len.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: the caller gives len readable bytes at request.
    let req = unsafe { core::slice::from_raw_parts(request, len) };
    let (j, ans) = join::Join::new(req, sign, ctx as usize, None);
    // SAFETY: the caller gives a writable pointer at answer.
    unsafe { answer.write(to_c(ans, answer_len)) };
    j.map_or(core::ptr::null_mut(), |j| Box::into_raw(Box::new(j)))
}

/// As `cbb_join_new`, for a phone that asks to be an admin: the request
/// names `admin_public`, the admin key's public point, and `admin_sign`
/// with `admin_ctx` signs with that key, as `sign` does with the device
/// key. The joined answer carries `admin_ca` when the member made the phone
/// an admin.
///
/// # Safety
///
/// As `cbb_join_new`; `admin_sign` and `admin_ctx` stay valid as `sign`
/// and `ctx` do.
#[cfg(feature = "join")]
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments, reason = "a C function takes each callback and its context")]
pub unsafe extern "C" fn cbb_join_new_admin(
    request: *const u8,
    len: usize,
    sign: join::SignFn,
    ctx: *mut core::ffi::c_void,
    admin_sign: join::SignFn,
    admin_ctx: *mut core::ffi::c_void,
    answer: *mut *mut u8,
    answer_len: *mut usize,
) -> *mut join::Join {
    if request.is_null() || answer.is_null() || answer_len.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: the caller gives len readable bytes at request.
    let req = unsafe { core::slice::from_raw_parts(request, len) };
    let (j, ans) = join::Join::new(req, sign, ctx as usize, Some((admin_sign, admin_ctx as usize)));
    // SAFETY: the caller gives a writable pointer at answer.
    unsafe { answer.write(to_c(ans, answer_len)) };
    j.map_or(core::ptr::null_mut(), |j| Box::into_raw(Box::new(j)))
}

/// Starts an attempt for a connection the app accepted.
///
/// # Safety
///
/// `j` must be a joiner of `cbb_join_new`, not freed, used by one thread
/// at a time; `answer_len` writable.
#[cfg(feature = "join")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cbb_join_accept(j: *mut join::Join, answer_len: *mut usize) -> *mut u8 {
    // SAFETY: as the function's contract says.
    let Some(j) = (unsafe { j.as_mut() }) else { return core::ptr::null_mut() };
    to_c(j.accept(), answer_len)
}

/// Passes the `len` bytes at `data` that arrived on the attempt's
/// connection; `now_ms` is the wall clock in Unix milliseconds, or 0 for
/// the system's.
///
/// # Safety
///
/// As `cbb_join_accept`, and `data` must point to `len` readable bytes (or
/// be null with `len` 0).
#[cfg(feature = "join")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cbb_join_feed(
    j: *mut join::Join,
    data: *const u8,
    len: usize,
    now_ms: i64,
    answer_len: *mut usize,
) -> *mut u8 {
    // SAFETY: as the function's contract says.
    let Some(j) = (unsafe { j.as_mut() }) else { return core::ptr::null_mut() };
    if data.is_null() && len != 0 {
        return core::ptr::null_mut();
    }
    let input: &[u8] = if len == 0 {
        &[]
    } else {
        // SAFETY: the caller gives len readable bytes at data.
        unsafe { core::slice::from_raw_parts(data, len) }
    };
    to_c(j.feed(input, now_ms), answer_len)
}

/// Ends a joined attempt: `saved` nonzero when the app stored the result.
///
/// # Safety
///
/// As `cbb_join_accept`.
#[cfg(feature = "join")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cbb_join_finish(j: *mut join::Join, saved: i32, answer_len: *mut usize) -> *mut u8 {
    // SAFETY: as the function's contract says.
    let Some(j) = (unsafe { j.as_mut() }) else { return core::ptr::null_mut() };
    to_c(j.finish(saved != 0), answer_len)
}

/// Frees a joiner; null does nothing.
///
/// # Safety
///
/// `j` must be null or a joiner of `cbb_join_new`, not freed before.
#[cfg(feature = "join")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cbb_join_free(j: *mut join::Join) {
    if !j.is_null() {
        // SAFETY: j is a box cbb_join_new let go of.
        drop(unsafe { Box::from_raw(j) });
    }
}

/// Starts the member inside the app (src/member.rs): `request` is its
/// JSON, `sign` the key's callback and `event` the callback for its events,
/// both with `ctx`, which must stay valid, and callable from any thread,
/// for the rest of the process: a thread of the member may still be in a
/// call when `cbb_member_stop` returns. Writes the answer to `answer` and
/// `answer_len` and returns the member, or null when the answer is an
/// error.
///
/// # Safety
///
/// As `cbb_join_new`.
#[cfg(feature = "member")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cbb_member_start(
    request: *const u8,
    len: usize,
    sign: join::SignFn,
    event: member::EventFn,
    ctx: *mut core::ffi::c_void,
    answer: *mut *mut u8,
    answer_len: *mut usize,
) -> *mut member::Member {
    if request.is_null() || answer.is_null() || answer_len.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: the caller gives len readable bytes at request.
    let req = unsafe { core::slice::from_raw_parts(request, len) };
    let (m, ans) = member::Member::start(req, sign, event, ctx as usize);
    // SAFETY: the caller gives a writable pointer at answer.
    unsafe { answer.write(to_c(ans, answer_len)) };
    m.map_or(core::ptr::null_mut(), |m| Box::into_raw(Box::new(m)))
}

/// Asks the member: `request` is `{"op", "args"}` (src/member.rs,
/// docs/core-api.md, "The member"), the answer `{"ok"}` or `{"error"}`.
/// It may block: `fetch`, `command` and `wait` wait for the network, so the
/// app calls them off its main thread.
///
/// # Safety
///
/// `m` must be a member of `cbb_member_start`, not stopped; `request` must
/// point to `len` readable bytes and `answer_len` be writable.
#[cfg(feature = "member")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cbb_member_call(
    m: *const member::Member,
    request: *const u8,
    len: usize,
    answer_len: *mut usize,
) -> *mut u8 {
    // SAFETY: as the function's contract says.
    let Some(m) = (unsafe { m.as_ref() }) else { return core::ptr::null_mut() };
    if request.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: the caller gives len readable bytes at request.
    let req = unsafe { core::slice::from_raw_parts(request, len) };
    to_c(m.call(req), answer_len)
}

/// Signs an admin's change to a device of the group, or a command for it
/// (src/member.rs, manage): `request` is `{"action", "device", "name",
/// "for_ms", "public", "admin_ca", "timeout_ms"}` and `sign` with `ctx`
/// signs with the key `public` names, during this call only. A command
/// waits for its result, so the app calls it off its main thread.
///
/// # Safety
///
/// `m` must be a member of `cbb_member_start`, not stopped; `request` must
/// point to `len` readable bytes, `answer_len` be writable, and `sign`
/// work with `ctx` until the call returns.
#[cfg(feature = "member")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cbb_member_manage(
    m: *const member::Member,
    request: *const u8,
    len: usize,
    sign: join::SignFn,
    ctx: *mut core::ffi::c_void,
    answer_len: *mut usize,
) -> *mut u8 {
    // SAFETY: as the function's contract says.
    let Some(m) = (unsafe { m.as_ref() }) else { return core::ptr::null_mut() };
    if request.is_null() || answer_len.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: the caller gives len readable bytes at request.
    let req = unsafe { core::slice::from_raw_parts(request, len) };
    to_c(m.manage(req, sign, ctx as usize), answer_len)
}

/// Starts admitting a device by its QR code, as an admin of the group
/// (src/admit.rs): `request` is `{"qr", "public", "admin_ca", "make_admin"}`
/// and `sign` with `ctx` signs with the key `public` names, the phone's
/// admin key or the root's, until `cbb_admit_free`. Writes the answer,
/// `{"addrs"}` to dial, to `answer` and `answer_len` and returns the
/// admission, or null when the answer is an error.
///
/// # Safety
///
/// `m` must be a running member of `cbb_member_start`, which stays running
/// until `cbb_admit_free`; the rest as `cbb_join_new`.
#[cfg(feature = "member")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cbb_admit_new(
    m: *const member::Member,
    request: *const u8,
    len: usize,
    sign: join::SignFn,
    ctx: *mut core::ffi::c_void,
    answer: *mut *mut u8,
    answer_len: *mut usize,
) -> *mut admit::Admit {
    if request.is_null() || answer.is_null() || answer_len.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: as the function's contract says.
    let Some(m) = (unsafe { m.as_ref() }) else { return core::ptr::null_mut() };
    // SAFETY: the caller gives len readable bytes at request.
    let req = unsafe { core::slice::from_raw_parts(request, len) };
    let (a, ans) = m.admit(req, sign, ctx as usize);
    // SAFETY: the caller gives a writable pointer at answer.
    unsafe { answer.write(to_c(ans, answer_len)) };
    a.map_or(core::ptr::null_mut(), |a| Box::into_raw(Box::new(a)))
}

/// Starts on a connection the app is dialing to one of the addresses,
/// ending the one before: the answer is as `cbb_admit_feed` gives it, its
/// `send` the first bytes to send.
///
/// # Safety
///
/// `a` must be an admission of `cbb_admit_new`, not freed, used by one
/// thread at a time; `answer_len` writable.
#[cfg(feature = "member")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cbb_admit_dial(a: *mut admit::Admit, answer_len: *mut usize) -> *mut u8 {
    // SAFETY: as the function's contract says.
    let Some(a) = (unsafe { a.as_mut() }) else { return core::ptr::null_mut() };
    to_c(a.dial(), answer_len)
}

/// Passes the `len` bytes at `data` that arrived on the connection; `now_ms`
/// is the wall clock in Unix milliseconds, or 0 for the system's. The
/// answer is `{"send", "state", "wrong_code", "device", "confirmed",
/// "error"}`, state pending, admitted (the device is in the group now),
/// done or failed.
///
/// # Safety
///
/// As `cbb_admit_dial`, and `data` must point to `len` readable bytes (or
/// be null with `len` 0).
#[cfg(feature = "member")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cbb_admit_feed(
    a: *mut admit::Admit,
    data: *const u8,
    len: usize,
    now_ms: i64,
    answer_len: *mut usize,
) -> *mut u8 {
    // SAFETY: as the function's contract says.
    let Some(a) = (unsafe { a.as_mut() }) else { return core::ptr::null_mut() };
    if data.is_null() && len != 0 {
        return core::ptr::null_mut();
    }
    let input: &[u8] = if len == 0 {
        &[]
    } else {
        // SAFETY: the caller gives len readable bytes at data.
        unsafe { core::slice::from_raw_parts(data, len) }
    };
    to_c(a.feed(input, now_ms), answer_len)
}

/// Frees an admission; null does nothing.
///
/// # Safety
///
/// `a` must be null or an admission of `cbb_admit_new`, not freed before.
#[cfg(feature = "member")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cbb_admit_free(a: *mut admit::Admit) {
    if !a.is_null() {
        // SAFETY: a is a box cbb_admit_new let go of.
        drop(unsafe { Box::from_raw(a) });
    }
}

/// Stops the member; null does nothing. The member stays valid for the rest
/// of the process, as its callbacks' context does: another thread of the
/// app may be in `cbb_member_call` with it right now, or about to be (an
/// event's handler, as the member restarts), and a call after the stop
/// answers that the member stopped. Freeing it here let such a call read
/// freed memory, and the Android app crashed on a restart. Its callbacks may
/// still run for a moment on threads that were in the middle of a call. The
/// secret for sealed messages stays the first member's for the process.
///
/// # Safety
///
/// `m` must be null or a member of `cbb_member_start`; stopping it again
/// does nothing.
#[cfg(feature = "member")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cbb_member_stop(m: *mut member::Member) {
    if !m.is_null() {
        // SAFETY: m is a box cbb_member_start let go of and nothing frees.
        let m = unsafe { &*m };
        m.stop();
    }
}

/// The phones' tunnel to the hub (src/tunnel.rs lists the requests): answers
/// the `len` bytes at `request` with bytes the caller gives back with
/// `cbb_free`, their length written to `answer_len`. Null only when
/// `answer_len` or `request` is null.
///
/// # Safety
///
/// `request` must point to `len` readable bytes and `answer_len` to a
/// writable `size_t`, for the time of the call.
#[cfg(feature = "tunnel")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cbb_tunnel(request: *const u8, len: usize, answer_len: *mut usize) -> *mut u8 {
    if request.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: the caller gives len readable bytes at request, not null.
    let req = unsafe { core::slice::from_raw_parts(request, len) };
    to_c(tunnel::call(req), answer_len)
}

/// Registers a hub of `cbb_tunnel` with the group's forwarder (src/tunnel.rs
/// tells the request), signing its TLS with the app's member key through
/// `sign` and `ctx`, as `cbb_member_start` does; the answer is as
/// `cbb_tunnel`'s.
///
/// # Safety
///
/// As `cbb_tunnel`; `sign` must stay callable with `ctx`, from any thread,
/// until the hub stops or registers again.
#[cfg(feature = "tunnel")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cbb_tunnel_register(
    request: *const u8,
    len: usize,
    sign: join::SignFn,
    ctx: *mut core::ffi::c_void,
    answer_len: *mut usize,
) -> *mut u8 {
    if request.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: the caller gives len readable bytes at request, not null.
    let req = unsafe { core::slice::from_raw_parts(request, len) };
    to_c(tunnel::register(req, sign, ctx as usize), answer_len)
}

/// Links the phone to the group's blind relay (src/tunnel.rs tells the
/// request and the events), signing its TLS with the member key through
/// `sign` and telling the app through `event`, both with `ctx`; the answer
/// is as `cbb_tunnel`'s, `{"id"}` for the `relay_...` requests.
///
/// # Safety
///
/// As `cbb_tunnel`; `sign` and `event` must stay callable with `ctx`, from
/// any thread, until `relay_stop` returns.
#[cfg(feature = "tunnel")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cbb_tunnel_relay(
    request: *const u8,
    len: usize,
    sign: join::SignFn,
    event: join::EventFn,
    ctx: *mut core::ffi::c_void,
    answer_len: *mut usize,
) -> *mut u8 {
    if request.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: the caller gives len readable bytes at request, not null.
    let req = unsafe { core::slice::from_raw_parts(request, len) };
    to_c(tunnel::relay_start(req, sign, event, ctx as usize), answer_len)
}

/// Makes a relay link of `cbb_tunnel_relay` register with the group's
/// server credentials (src/tunnel.rs tells the request), signing with the
/// period's server key through `sign` and `ctx`; the answer is as
/// `cbb_tunnel`'s.
///
/// # Safety
///
/// As `cbb_tunnel`; `sign` must stay callable with `ctx`, from any thread,
/// until the link stops or is given other credentials.
#[cfg(feature = "tunnel")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cbb_tunnel_relay_credentials(
    request: *const u8,
    len: usize,
    sign: join::SignFn,
    ctx: *mut core::ffi::c_void,
    answer_len: *mut usize,
) -> *mut u8 {
    if request.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: the caller gives len readable bytes at request, not null.
    let req = unsafe { core::slice::from_raw_parts(request, len) };
    to_c(tunnel::relay_credentials(req, sign, ctx as usize), answer_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The library answers as the core does.
    #[test]
    fn answers_as_the_core() {
        let req = format!(r#"{{"abi":{},"op":"version"}}"#, abi());
        let answer: serde_json::Value = serde_json::from_slice(&call(req.into_bytes())).unwrap();
        assert_eq!(answer["ok"]["abi"], abi());
        let answer: serde_json::Value = serde_json::from_slice(&call(b"nonsense".to_vec())).unwrap();
        assert_eq!(answer["error"]["name"], "request");
    }

    /// The C functions answer as the core does, give the answer back, and
    /// refuse null pointers without reading them.
    #[test]
    fn answers_through_c() {
        assert_eq!(cbb_abi(), abi());
        let req = format!(r#"{{"abi":{},"op":"version"}}"#, abi()).into_bytes();
        let mut n = 0usize;
        // SAFETY: req and n live for the call; the answer is freed once.
        let got = unsafe {
            let p = cbb_call(req.as_ptr(), req.len(), &mut n);
            assert!(!p.is_null());
            let got = core::slice::from_raw_parts(p, n).to_vec();
            cbb_free(p, n);
            got
        };
        assert_eq!(got, call(req.clone()));
        // SAFETY: null pointers are refused or read as an empty request.
        unsafe {
            assert!(cbb_call(req.as_ptr(), 0, core::ptr::null_mut()).is_null());
            assert!(cbb_call(core::ptr::null(), 3, &mut n).is_null());
            let p = cbb_call(core::ptr::null(), 0, &mut n);
            let answer: serde_json::Value = serde_json::from_slice(core::slice::from_raw_parts(p, n)).unwrap();
            assert_eq!(answer["error"]["name"], "request");
            cbb_free(p, n);
            cbb_free(core::ptr::null_mut(), 0);
        }
    }

    /// include/cbb_core.h declares the C functions this library exports.
    #[test]
    fn the_header_declares_them() {
        let h = include_str!("../include/cbb_core.h");
        for decl in [
            "uint32_t cbb_abi(void);",
            "uint8_t *cbb_call(const uint8_t *request, size_t len, size_t *answer_len);",
            "void cbb_free(uint8_t *answer, size_t len);",
        ] {
            assert!(h.contains(decl), "{decl}");
        }
    }
}
