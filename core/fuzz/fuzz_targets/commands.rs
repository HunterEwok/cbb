// Long fuzzing of the 0.6 readers (not for the repository as is).
#![no_main]
#[path = "alloc_guard.rs"]
mod alloc_guard;
#[global_allocator]
static A: alloc_guard::Counting = alloc_guard::Counting;
use cbb_core::commands::{self, orders, Command, Counters};

fn one(data: &[u8]) {
    if let Ok(c) = Command::read(data) {
        let e = &c.envelope;
        assert_eq!(cbb_core::format::envelope::write(e.body, e.sig, e.sig2), data, "a command does not write back");
        let _ = commands::message(data);
    }
    if let Ok(c) = Counters::decode(data) {
        assert_eq!(c.encode(), data, "counters do not encode back");
    }
    for t in 0..=11u64 {
        let _ = orders::check(t, data);
    }
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| alloc_guard::bounded(data, one));

