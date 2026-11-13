// Long fuzzing of the 0.6 readers (not for the repository as is).
#![no_main]
#[path = "alloc_guard.rs"]
mod alloc_guard;
#[global_allocator]
static A: alloc_guard::Counting = alloc_guard::Counting;
use cbb_core::beacon;

fn one(data: &[u8]) {
    if let Ok((b, e)) = beacon::read(data) {
        assert_eq!(cbb_core::format::envelope::write(e.body, e.sig, e.sig2), data, "a beacon does not write back");
        let st = cbb_core::records::eval::State::default();
        let _ = beacon::check(data, &st);
        let mut f = beacon::Beacons::default();
        let _ = f.take(b.clone(), None);
        let _ = f.take(b, Some(1_800_000_000_000));
        let _ = beacon::message(data);
    }
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| alloc_guard::bounded(data, one));

