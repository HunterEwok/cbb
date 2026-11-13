// Long fuzzing of the 0.6 readers (not for the repository as is).
#![no_main]
#[path = "alloc_guard.rs"]
mod alloc_guard;
#[global_allocator]
static A: alloc_guard::Counting = alloc_guard::Counting;

libfuzzer_sys::fuzz_target!(|data: &[u8]| alloc_guard::bounded(data, cbb_core::format::fuzz::one_form));
