// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! One program per part of the core for a small device without an operating
//! system (riscv32imac-unknown-none-elf, as the ESP32-C6), chosen by
//! features: the parts are called with input the linker cannot see through,
//! so each keeps all the code it needs, and the difference between two
//! programs' sizes is what a part costs. It is never run; size.sh builds and
//! measures it. On the host it is an empty program, so that the workspace's
//! builds and tests pass over it.

#![cfg_attr(target_os = "none", no_std, no_main)]

#[cfg(not(target_os = "none"))]
fn main() {}

#[cfg(target_os = "none")]
mod parts;

#[cfg(target_os = "none")]
mod bare {
    extern crate alloc;

    use core::alloc::{GlobalAlloc, Layout};
    use core::sync::atomic::{AtomicUsize, Ordering};

    /// A bump allocator over a fixed area: the program is measured, not run.
    struct Bump;

    const HEAP: usize = 64 << 10;
    static mut AREA: [u8; HEAP] = [0; HEAP];
    static NEXT: AtomicUsize = AtomicUsize::new(0);

    unsafe impl GlobalAlloc for Bump {
        unsafe fn alloc(&self, l: Layout) -> *mut u8 {
            let start = (NEXT.load(Ordering::Relaxed) + l.align() - 1) & !(l.align() - 1);
            if start + l.size() > HEAP {
                return core::ptr::null_mut();
            }
            NEXT.store(start + l.size(), Ordering::Relaxed);
            // SAFETY: start + size is within AREA.
            unsafe { (&raw mut AREA).cast::<u8>().add(start) }
        }
        unsafe fn dealloc(&self, _: *mut u8, _: Layout) {}
    }

    #[global_allocator]
    static ALLOC: Bump = Bump;

    #[panic_handler]
    fn panic(_: &core::panic::PanicInfo) -> ! {
        loop {
            core::hint::spin_loop();
        }
    }

    /// The firmware's randomness, as the ESP32's chip gives it.
    #[unsafe(no_mangle)]
    unsafe extern "Rust" fn __getrandom_v03_custom(dest: *mut u8, len: usize) -> Result<(), getrandom::Error> {
        // SAFETY: getrandom passes a buffer of len bytes.
        unsafe { core::ptr::write_bytes(dest, core::hint::black_box(7), len) };
        Ok(())
    }

    #[unsafe(no_mangle)]
    extern "C" fn _start() -> ! {
        super::parts::run();
        loop {
            core::hint::spin_loop();
        }
    }
}
