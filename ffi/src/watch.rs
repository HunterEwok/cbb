// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The phone's watch as an admin of the group (docs/protocol.md, section
//! 10, "Watches"): the watch's admin key signs on the watch, which is shown
//! each record or command whole and checks it before it signs, so the
//! phone hands it the bytes, not a digest. The app carries them over its
//! link to the watch with the callback here. The member of 0.6 signs
//! nothing on the wrist yet: `cbb_member_manage_watch` refuses, and the
//! callback stays for the watch apps of 0.7.

/// The app's link to its watch: sends the body (len bytes) to sign to the
/// watch and writes its ECDSA P-256 signature over the body's SHA-256,
/// DER, to sig (72 bytes of room) with its length in sig_len; 0 when the
/// watch signed, another value when it refused or went away.
pub type SignBodyFn = unsafe extern "C" fn(
    ctx: *mut core::ffi::c_void,
    body: *const u8,
    len: usize,
    sig: *mut u8,
    sig_len: *mut usize,
) -> i32;
