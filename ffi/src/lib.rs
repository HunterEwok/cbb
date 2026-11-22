// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The Rust core's one entry point as C functions (docs/core-api.md), for
//! every program that links the core: `cbb_call`, `cbb_free` and `cbb_abi`,
//! declared in `include/cbb_core.h`. The Swift kit links them through that
//! header and the Kotlin kit through JNA, so the phones do not write the
//! group's rules again and none of them needs generated bindings. A request and its answer are JSON bytes, so the binding stays
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
    let answer = boxed(guard::answer(|| cbb_core::api::call(req)));
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
    let mut answer = unsafe { Box::from_raw(core::ptr::slice_from_raw_parts_mut(answer, len)) };
    // An answer may hold a secret (a new key, a copy's key and text): it is
    // wiped before its memory goes back.
    cbb_core::secret::Zeroize::zeroize(&mut answer[..]);
}

/// An answer as the boxed slice C gets, of its exact length: a Vec with
/// room to spare is copied, and the bytes it leaves behind wiped, so that
/// shrinking it leaves no copy of a secret in freed memory.
fn boxed(mut answer: Vec<u8>) -> Box<[u8]> {
    if answer.len() == answer.capacity() {
        return answer.into_boxed_slice();
    }
    let out: Box<[u8]> = answer.as_slice().into();
    cbb_core::secret::Zeroize::zeroize(&mut answer);
    out
}

pub mod guard;

/// The answer of the last panic this library caught, for a function that
/// could only answer null (docs/core-api.md, "Panics"), given back with
/// `cbb_free`; null when nothing panicked or `answer_len` is null.
///
/// # Safety
///
/// `answer_len` must be null or point to a writable `size_t`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cbb_last_panic(answer_len: *mut usize) -> *mut u8 {
    match guard::last_answer() {
        Some(a) if !answer_len.is_null() => {
            let a = a.into_boxed_slice();
            // SAFETY: the caller gives a writable size_t at answer_len, not null.
            unsafe { answer_len.write(a.len()) };
            Box::into_raw(a).cast::<u8>()
        }
        _ => core::ptr::null_mut(),
    }
}

/// Panics inside the guard and answers it, code 5, given back with
/// `cbb_free`: the wrappers' tests check that a panic is an answer and the
/// app goes on.
///
/// # Safety
///
/// `answer_len` must point to a writable `size_t`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cbb_test_panic(answer_len: *mut usize) -> *mut u8 {
    if answer_len.is_null() {
        return core::ptr::null_mut();
    }
    let a = guard::test_panic().into_boxed_slice();
    // SAFETY: the caller gives a writable size_t at answer_len, not null.
    unsafe { answer_len.write(a.len()) };
    Box::into_raw(a).cast::<u8>()
}

#[cfg(feature = "member")]
pub(crate) mod found;
#[cfg(feature = "member")]
pub mod invite;
#[cfg(feature = "join")]
pub mod join;
#[cfg(feature = "member")]
pub mod joiner;
#[cfg(feature = "member")]
pub mod member;
#[cfg(feature = "member")]
pub(crate) mod pair06;
#[cfg(feature = "member")]
pub mod piv;
#[cfg(feature = "join")]
pub mod qr;
#[cfg(feature = "member")]
pub mod watch;
#[cfg(feature = "member")]
pub mod window;

/// Hands an answer to C: its bytes, which the caller gives back with
/// `cbb_free`, their length written to `answer_len` when not null.
#[cfg(feature = "join")]
fn to_c(answer: Vec<u8>, answer_len: *mut usize) -> *mut u8 {
    if answer_len.is_null() {
        return core::ptr::null_mut();
    }
    let answer = boxed(answer);
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
    // The length is checked before a slice is made of gray: one that
    // overflows, or passes what a slice can hold, is refused here.
    let Some(len) = qr::frame_len(width, height, stride) else {
        return to_c(guard::answer(qr::refused), answer_len);
    };
    // SAFETY: the caller gives that many readable bytes at gray.
    let frame = unsafe { core::slice::from_raw_parts(gray, len) };
    to_c(guard::answer(|| qr::read(frame, width, height, stride)), answer_len)
}

/// What `cbb_group_new` answers for a request without the app's folder.
#[cfg(feature = "join")]
const NEW_GROUP_NEEDS_DIR: &str = "a new group needs the app's folder (dir): groups are 0.6 only";

/// Makes a group of 0.6 with the app's root key (src/found.rs): `request`
/// names the app's `dir`, where the set is kept, and the answer is the
/// group's and the phone's IDs and the recovery sheet. A request without
/// `dir` is refused: groups are 0.6 only (D-126). `sign` is the root key's
/// callback with `ctx`, called during this call only.
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
    #[cfg(feature = "member")]
    if found::on_06(req) {
        return to_c(guard::answer(|| found::new_group(req, sign, ctx as usize)), answer_len);
    }
    let _ = (req, sign, ctx);
    let refused: Result<(), cbb_core::error::Error> = Err(cbb_core::error::Error::msg(NEW_GROUP_NEEDS_DIR));
    to_c(guard::answer(|| join::answer(refused)), answer_len)
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
/// `request` must point to `len` readable bytes; `answer` and `answer_len`
/// writable; `ctx` valid for both callbacks as said.
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
    let (m, ans) = guard::or(|| (None, guard::panicked()), || member::Member::start(req, sign, event, ctx as usize));
    // SAFETY: the caller gives a writable pointer at answer.
    unsafe { answer.write(to_c(ans, answer_len)) };
    m.map_or(core::ptr::null_mut(), |m| Box::into_raw(Box::new(m)))
}

/// Runs one step with the group's recovery key on a YubiKey (src/piv.rs):
/// `request` is `{"op", ...}` (seal or open) and `transmit`
/// with `ctx` carries each APDU to the card during this call only. Returns
/// the answer, `{"ok"}` or `{"error"}`, with its length in `answer_len`.
///
/// # Safety
///
/// `request` must point to `len` readable bytes, `answer_len` must be
/// writable, and `transmit` must be callable with `ctx` until it returns.
#[cfg(feature = "member")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cbb_piv(
    request: *const u8,
    len: usize,
    transmit: piv::TransmitFn,
    ctx: *mut core::ffi::c_void,
    answer_len: *mut usize,
) -> *mut u8 {
    if request.is_null() || answer_len.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: the caller gives len readable bytes at request.
    let req = unsafe { core::slice::from_raw_parts(request, len) };
    to_c(guard::answer(|| piv::run(req, transmit, ctx as usize)), answer_len)
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
    to_c(guard::answer(|| m.call(req)), answer_len)
}

/// Signs an admin's change to a device of the group, or a command for it
/// (src/member.rs, manage): `request` is `{"action", "device", "name",
/// "for_ms", "text", "mode", "kind", "enter", "public", "admin_ca",
/// "timeout_ms"}` and `sign` with `ctx`
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
    to_c(guard::answer(|| m.manage(req, sign, ctx as usize)), answer_len)
}

/// Does what the app's watch asked from the wrist (src/watch.rs): as
/// `cbb_member_manage`, signed by the watch's admin key, which `sign_body`
/// with `ctx` reaches over the app's link to the watch and which is shown
/// each record or command whole. `request` is
/// `{"action","device","watch","public","admin_ca","name"}`.
///
/// # Safety
///
/// As `cbb_member_manage`, with `sign_body` callable with `ctx` until the
/// call returns.
#[cfg(feature = "member")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cbb_member_manage_watch(
    m: *const member::Member,
    request: *const u8,
    len: usize,
    sign_body: watch::SignBodyFn,
    ctx: *mut core::ffi::c_void,
    answer_len: *mut usize,
) -> *mut u8 {
    // SAFETY: as the function's contract says.
    let Some(m) = (unsafe { m.as_ref() }) else { return core::ptr::null_mut() };
    if request.is_null() || answer_len.is_null() {
        return core::ptr::null_mut();
    }
    // The watch signs nothing in 0.6: the member refuses every action,
    // so neither the request nor sign_body is read.
    let _ = (len, sign_body, ctx);
    to_c(guard::answer(|| m.manage_watch()), answer_len)
}

/// Makes a remote invitation as an admin of the group (src/invite.rs):
/// `request` is `{"public", "admin_ca", "expires", "hub", "kind"}` and
/// `sign` with `ctx` signs with the key `public` names until
/// `cbb_invite_free`; a member of 0.6 needs no `admin_ca` and invites a
/// `kind` of device, "computer" (or empty) or "phone". Writes
/// the answer, `{"invite", "expires", "modules"}`, to `answer` and
/// `answer_len` and returns the invitation, or null when the answer is an
/// error. It waits for the hub's answer, so the app calls it off its main
/// thread.
///
/// # Safety
///
/// `m` is a running member, `request` holds `len` readable bytes, `answer`
/// and `answer_len` are writable; `sign` stays callable with `ctx` until
/// `cbb_invite_free`.
#[cfg(feature = "member")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cbb_invite_new(
    m: *const member::Member,
    request: *const u8,
    len: usize,
    sign: join::SignFn,
    ctx: *mut core::ffi::c_void,
    answer: *mut *mut u8,
    answer_len: *mut usize,
) -> *mut invite::Invite {
    if request.is_null() || answer.is_null() || answer_len.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: as the function's contract says.
    let Some(m) = (unsafe { m.as_ref() }) else { return core::ptr::null_mut() };
    // SAFETY: the caller gives len readable bytes at request.
    let req = unsafe { core::slice::from_raw_parts(request, len) };
    let (i, ans) = guard::or(|| (None, guard::panicked()), || m.invite(req, sign, ctx as usize));
    // SAFETY: the caller gives a writable pointer at answer.
    unsafe { answer.write(to_c(ans, answer_len)) };
    i.map_or(core::ptr::null_mut(), |i| Box::into_raw(Box::new(i)))
}

/// Waits up to `timeout_ms` for the invitation's state to pass `version`
/// and answers it: `{"version", "state", "joining", "name", "device",
/// "error"}`, state open, joining (ask the user about `joining`: device,
/// name, os, fingerprint), done or failed. It blocks, so the app calls it
/// off its main thread.
///
/// # Safety
///
/// `i` must be an invitation of `cbb_invite_new`, not freed; `answer_len`
/// writable.
#[cfg(feature = "member")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cbb_invite_next(
    i: *const invite::Invite,
    version: u64,
    timeout_ms: u64,
    answer_len: *mut usize,
) -> *mut u8 {
    // SAFETY: as the function's contract says.
    let Some(i) = (unsafe { i.as_ref() }) else { return core::ptr::null_mut() };
    to_c(guard::answer(|| i.next(version, timeout_ms)), answer_len)
}

/// Answers whether to admit the device the state's `joining` names: `yes`
/// non-zero admits it.
///
/// # Safety
///
/// As `cbb_invite_next`.
#[cfg(feature = "member")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cbb_invite_answer(i: *const invite::Invite, yes: i32) {
    // SAFETY: as the function's contract says.
    if let Some(i) = unsafe { i.as_ref() } {
        guard::or(|| (), || i.answer(yes != 0));
    }
}

/// Ends an invitation and frees it, once its window ended (a second at
/// most, or until an admission that has started finishes); null does
/// nothing.
///
/// # Safety
///
/// `i` must be null or an invitation of `cbb_invite_new`, not freed before,
/// with no other call on it running.
#[cfg(feature = "member")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cbb_invite_free(i: *mut invite::Invite) {
    if !i.is_null() {
        // SAFETY: i is a box cbb_invite_new let go of.
        guard::or(|| (), || drop(unsafe { Box::from_raw(i) }));
    }
}

/// Opens a home window on a member of 0.6 (src/window.rs): `request` is
/// `{"public", "addrs", "expires", "mdns"}`, `public` the admitting key (the
/// phone's admin key or the root's), which `sign` with `ctx` signs with
/// until `cbb_window_free`; `addrs` the phone's home addresses without a
/// port. The member port must listen (the member's `listen`). Writes the
/// answer, `{"qr", "digits", "id", "fingerprint", "expires", "modules"}`, to `answer` and
/// `answer_len` and returns the window, or null when the answer is an
/// error.
///
/// # Safety
///
/// `m` is a running member, `request` holds `len` readable bytes, `answer`
/// and `answer_len` are writable; `sign` stays callable with `ctx` until
/// `cbb_window_free`.
#[cfg(feature = "member")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cbb_window_new(
    m: *const member::Member,
    request: *const u8,
    len: usize,
    sign: join::SignFn,
    ctx: *mut core::ffi::c_void,
    answer: *mut *mut u8,
    answer_len: *mut usize,
) -> *mut window::Window {
    if request.is_null() || answer.is_null() || answer_len.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: as the function's contract says.
    let Some(m) = (unsafe { m.as_ref() }) else { return core::ptr::null_mut() };
    // SAFETY: the caller gives len readable bytes at request.
    let req = unsafe { core::slice::from_raw_parts(request, len) };
    let (w, ans) = guard::or(|| (None, guard::panicked()), || m.window(req, sign, ctx as usize));
    // SAFETY: the caller gives a writable pointer at answer.
    unsafe { answer.write(to_c(ans, answer_len)) };
    w.map_or(core::ptr::null_mut(), |w| Box::into_raw(Box::new(w)))
}

/// Waits up to `timeout_ms` for the window's state to pass `version` and
/// answers it: `{"version", "state", "joining", "name", "device",
/// "error"}`, state open, joining (ask the person whether `joining.code`
/// matches the device's screen; `joining` also names its device, name and
/// os), done (a device joined), failed (that attempt failed; the window
/// stays open) or closed (its time is up). It blocks, so the app calls it
/// off its main thread.
///
/// # Safety
///
/// `w` must be a window of `cbb_window_new`, not freed; `answer_len`
/// writable.
#[cfg(feature = "member")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cbb_window_next(
    w: *const window::Window,
    version: u64,
    timeout_ms: u64,
    answer_len: *mut usize,
) -> *mut u8 {
    // SAFETY: as the function's contract says.
    let Some(w) = (unsafe { w.as_ref() }) else { return core::ptr::null_mut() };
    to_c(guard::answer(|| w.next(version, timeout_ms)), answer_len)
}

/// Closes a window and frees it. Null does nothing.
///
/// # Safety
///
/// `w` must be null or a window of `cbb_window_new`, not freed before, with
/// no other call on it running.
#[cfg(feature = "member")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cbb_window_free(w: *mut window::Window) {
    if !w.is_null() {
        // SAFETY: w is a box cbb_window_new let go of.
        guard::or(|| (), || drop(unsafe { Box::from_raw(w) }));
    }
}

/// Joins a group of 0.6 by a home window (src/joiner.rs): `request` is
/// `{"dir", "qr", "digits", "name", "os", "public"}` (`qr` empty: `digits`,
/// the six the person typed, with the one window announced by mDNS), `public` the
/// phone's member key, which `sign` with `ctx` signs with until
/// `cbb_joiner_free`. It dials on a thread of its own; the answer is the
/// first state, as `cbb_joiner_next` gives it. Returns the joiner, or null
/// when the answer is an error (a phone in a group already, a QR code that
/// is not a window's, digits that are not six).
///
/// # Safety
///
/// `request` must point to `len` readable bytes; `answer` and `answer_len`
/// writable; `ctx` valid for `sign` until `cbb_joiner_free`.
#[cfg(feature = "member")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cbb_joiner_new(
    request: *const u8,
    len: usize,
    sign: join::SignFn,
    ctx: *mut core::ffi::c_void,
    answer: *mut *mut u8,
    answer_len: *mut usize,
) -> *mut joiner::Joiner {
    if request.is_null() || answer.is_null() || answer_len.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: the caller gives len readable bytes at request.
    let req = unsafe { core::slice::from_raw_parts(request, len) };
    let (j, ans) = guard::or(|| (None, guard::panicked()), || joiner::Joiner::new(req, sign, ctx as usize, None));
    // SAFETY: the caller gives a writable pointer at answer.
    unsafe { answer.write(to_c(ans, answer_len)) };
    j.map_or(core::ptr::null_mut(), |j| Box::into_raw(Box::new(j)))
}

/// As `cbb_joiner_new`, for a phone that offers its admin key: the request
/// names `admin_public`, the admin key's public point, and `admin_sign`
/// with `admin_ctx` signs the key's proof over the session with it. The
/// group's root keeps the key and makes the phone an admin with it later.
///
/// # Safety
///
/// As `cbb_joiner_new`; `admin_ctx` valid for `admin_sign` as `ctx` is for
/// `sign`.
#[cfg(feature = "member")]
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn cbb_joiner_new_admin(
    request: *const u8,
    len: usize,
    sign: join::SignFn,
    ctx: *mut core::ffi::c_void,
    admin_sign: join::SignFn,
    admin_ctx: *mut core::ffi::c_void,
    answer: *mut *mut u8,
    answer_len: *mut usize,
) -> *mut joiner::Joiner {
    if request.is_null() || answer.is_null() || answer_len.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: the caller gives len readable bytes at request.
    let req = unsafe { core::slice::from_raw_parts(request, len) };
    let admin = Some((admin_sign, admin_ctx as usize));
    let (j, ans) = guard::or(|| (None, guard::panicked()), || joiner::Joiner::new(req, sign, ctx as usize, admin));
    // SAFETY: the caller gives a writable pointer at answer.
    unsafe { answer.write(to_c(ans, answer_len)) };
    j.map_or(core::ptr::null_mut(), |j| Box::into_raw(Box::new(j)))
}

/// Waits up to `timeout_ms` for the joiner's state to pass `version` and
/// answers it: `{"version", "state", "group", "device", "name",
/// "error"}`, state dialing, done (the set is kept in `dir`: start the
/// member on it; `name` is the member that let the phone in) or failed. It blocks, so the app calls it off its main thread.
///
/// # Safety
///
/// `j` must be a joiner of `cbb_joiner_new`, not freed; `answer_len`
/// writable.
#[cfg(feature = "member")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cbb_joiner_next(
    j: *const joiner::Joiner,
    version: u64,
    timeout_ms: u64,
    answer_len: *mut usize,
) -> *mut u8 {
    // SAFETY: as the function's contract says.
    let Some(j) = (unsafe { j.as_ref() }) else { return core::ptr::null_mut() };
    to_c(guard::answer(|| j.next(version, timeout_ms)), answer_len)
}

/// Ends joining and frees the joiner. Null does nothing.
///
/// # Safety
///
/// `j` must be null or a joiner of `cbb_joiner_new`, not freed before, with
/// no other call on it running.
#[cfg(feature = "member")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cbb_joiner_free(j: *mut joiner::Joiner) {
    if !j.is_null() {
        // SAFETY: j is a box cbb_joiner_new let go of.
        guard::or(|| (), || drop(unsafe { Box::from_raw(j) }));
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
        guard::or(|| (), || m.stop());
    }
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

    /// The C functions of a joiner and the QR reader read no byte past
    /// what they are given, refuse null pointers, and hand back answers
    /// that free cleanly; Miri runs this (docs/testing.md, "Unsafe code").
    #[cfg(feature = "join")]
    #[test]
    fn joiner_and_qr_through_c() {
        #[cfg(feature = "member")]
        unsafe extern "C" fn no_sign(_: *mut core::ffi::c_void, _: *const u8, _: *mut u8, _: *mut usize) -> i32 {
            -1
        }
        let error = |p: *mut u8, n: usize| -> serde_json::Value {
            assert!(!p.is_null());
            // SAFETY: p is an answer of n bytes, freed once here.
            unsafe {
                let v = serde_json::from_slice(core::slice::from_raw_parts(p, n)).unwrap();
                cbb_free(p, n);
                v
            }
        };
        let mut n = 0usize;
        // A frame of exactly stride * (height - 1) + width bytes, in a box
        // of that size, so that a read past it is an error under Miri.
        let (w, h, stride) = (4usize, 3usize, 6usize);
        let frame = vec![255u8; stride * (h - 1) + w].into_boxed_slice();
        // SAFETY: frame holds the bytes the size names; n is writable.
        unsafe {
            let got = error(cbb_qr_read(frame.as_ptr(), w, h, stride, &mut n), n);
            assert!(got.get("ok").is_some() || got.get("error").is_some(), "{got}");
            assert!(cbb_qr_read(core::ptr::null(), w, h, stride, &mut n).is_null());
            assert!(cbb_qr_read(frame.as_ptr(), w, h, stride, core::ptr::null_mut()).is_null());
            // A stride narrower than the width is refused, not read.
            let got = error(cbb_qr_read(frame.as_ptr(), w, 1, w - 1, &mut n), n);
            assert!(got.get("error").is_some(), "{got}");
            // A size whose length overflows is refused before a slice is
            // made of the pointer, so no byte of it is read.
            let got = error(cbb_qr_read(frame.as_ptr(), w, h, usize::MAX, &mut n), n);
            assert!(got.get("error").is_some(), "{got}");
            let got = error(cbb_qr_read(frame.as_ptr(), w, 2, isize::MAX as usize, &mut n), n);
            assert!(got.get("error").is_some(), "{got}");
        }
        // SAFETY: req, ans and n live for each call; null joiners do nothing.
        unsafe {
            #[cfg(feature = "member")]
            {
                let req = b"{not json";
                let mut ans: *mut u8 = core::ptr::null_mut();
                let j = cbb_joiner_new(req.as_ptr(), req.len(), no_sign, core::ptr::null_mut(), &mut ans, &mut n);
                assert!(j.is_null());
                assert!(error(ans, n).get("error").is_some());
                assert!(
                    cbb_joiner_new(core::ptr::null(), 0, no_sign, core::ptr::null_mut(), &mut ans, &mut n).is_null()
                );
                assert!(
                    cbb_joiner_new(
                        req.as_ptr(),
                        req.len(),
                        no_sign,
                        core::ptr::null_mut(),
                        core::ptr::null_mut(),
                        &mut n
                    )
                    .is_null()
                );
                assert!(cbb_joiner_next(core::ptr::null(), 0, 0, &mut n).is_null());
                cbb_joiner_free(core::ptr::null_mut());
            }
            assert!(to_c(Vec::new(), core::ptr::null_mut()).is_null());
            let p = to_c(b"{}".to_vec(), &mut n);
            assert_eq!((core::slice::from_raw_parts(p, n), n), (&b"{}"[..], 2));
            cbb_free(p, n);
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
