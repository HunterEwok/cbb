// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! The protocol core of the cbb lite member (docs/protocol.md):
//! certificates and their checks, the signed records, the hybrid clock, the
//! sync engine, the frames of the member protocol and the joiner's side of
//! the pairing, and the format of the saved state for a board without a file
//! system. It does no I/O and needs no operating system, only an
//! allocator and a source of randomness, so the same code runs in the lite
//! member on Linux and on a microcontroller such as the ESP32.
//!
//! With the tls feature it has the members' TLS as well (rustls without
//! the standard library, a RustCrypto provider and a session without I/O).
//!
//! Randomness comes from the getrandom crate: on Linux from the kernel, on a
//! microcontroller from the function the firmware registers as getrandom's
//! custom backend. Without the std feature the locks are spin locks.

#![cfg_attr(not(any(test, feature = "std")), no_std)]
// The core reads what peers send and runs inside the phones' apps and the
// Go service, so a panic there is a crash or a hang. It has no unsafe code,
// and outside its tests nothing may panic: no unwrap or expect, no indexing
// that can fail and no arithmetic that can overflow. The few places that
// cannot fail say why where they allow it.
#![forbid(unsafe_code)]
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

extern crate alloc;

#[cfg(feature = "tls")]
pub mod admit;
pub mod api;
pub mod authority;
pub mod certs;
pub mod clip;
pub mod command;
pub mod copy;
pub mod credential;
pub mod error;
#[cfg(feature = "fuzzing")]
#[allow(clippy::expect_used, clippy::panic, reason = "a fuzz target reports a broken promise by panicking")]
pub mod fuzzing;
pub mod group;
pub mod hlc;
pub mod identity;
pub mod invite;
pub mod issue;
pub mod keyboard;
pub mod manage;
pub mod media;
pub mod pair;
#[cfg(feature = "tls")]
pub mod pair_session;
pub mod recovery;
pub mod release;
pub mod rule;
pub mod seal;
pub mod store;
pub mod strict;
pub mod sync;
pub mod third_party {
    // Copied code, kept close to its source: its field arithmetic wraps on
    // purpose (u128 limbs, reduced modulo p), and its indexes and unwraps
    // are on fixed-size arrays.
    #[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects, clippy::unwrap_used, clippy::expect_used)]
    pub mod cpace;
}
#[cfg(feature = "tls")]
pub mod tls;
#[cfg(test)]
mod vectors;
pub mod vless;
pub mod wire;
