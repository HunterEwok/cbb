// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The Rust core's one entry point (docs/core-api.md) as a WebAssembly
//! module, for the Go builds that do not link C: Windows, macOS and FreeBSD
//! run it under wazero (internal/core). Built with
//!
//! ```sh
//! cargo build --locked --release -p cbb-wasm --target wasm32-unknown-unknown
//! ```
//!
//! The module exports `cbb_abi`, `cbb_alloc`, `cbb_call` and `cbb_free`,
//! and imports one function, `env.cbb_random`, which fills a buffer with the
//! host's randomness. The host writes a request into memory it got from
//! `cbb_alloc`; `cbb_call` takes that memory and returns the answer's
//! address and length in one u64, and the host gives the answer back with
//! `cbb_free`.

#![cfg(target_arch = "wasm32")]
// As in the core: nothing may panic; a panic would trap the host's call.
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::unreachable,
    clippy::todo,
    clippy::unimplemented
)]

#[link(wasm_import_module = "env")]
unsafe extern "C" {
    /// Fills len bytes at buf with the host's randomness; 0 when it did.
    fn cbb_random(buf: *mut u8, len: usize) -> i32;
}

/// getrandom's source, and so of every key and nonce of the core: the
/// host's (Go's crypto/rand).
///
/// # Safety
///
/// getrandom passes len writable bytes at dest.
#[unsafe(no_mangle)]
unsafe extern "Rust" fn __getrandom_v03_custom(dest: *mut u8, len: usize) -> Result<(), getrandom::Error> {
    // SAFETY: the host writes exactly len bytes at dest, which getrandom
    // gives writable.
    if unsafe { cbb_random(dest, len) } == 0 { Ok(()) } else { Err(getrandom::Error::new_custom(1)) }
}

/// The version of the request and answer shapes the module speaks.
#[unsafe(no_mangle)]
pub extern "C" fn cbb_abi() -> u32 {
    cbb_core::api::ABI
}

/// Memory of len bytes for a request, which `cbb_call` takes.
#[unsafe(no_mangle)]
pub extern "C" fn cbb_alloc(len: usize) -> *mut u8 {
    Box::into_raw(vec![0u8; len].into_boxed_slice()).cast::<u8>()
}

/// Answers the request of len bytes at request, which it takes, and
/// returns the answer's address in the high 32 bits and its length in the
/// low.
///
/// # Safety
///
/// request must be what `cbb_alloc(len)` returned, filled, and not used
/// again.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cbb_call(request: *mut u8, len: usize) -> u64 {
    // SAFETY: request is cbb_alloc's boxed slice of len bytes.
    let req = unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(request, len)) };
    let answer = cbb_core::api::call(&req).into_boxed_slice();
    drop(req);
    let n = answer.len() as u64;
    let p = Box::into_raw(answer).cast::<u8>() as usize as u64;
    (p << 32) | n
}

/// Gives back an answer of `cbb_call`, or a request never sent.
///
/// # Safety
///
/// p and len must be an answer of `cbb_call` or memory of `cbb_alloc`, not
/// given back before.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cbb_free(p: *mut u8, len: usize) {
    if p.is_null() {
        return;
    }
    // SAFETY: p and len are a boxed slice this module let go of.
    drop(unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(p, len)) });
}
