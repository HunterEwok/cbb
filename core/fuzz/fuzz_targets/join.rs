// Long fuzzing of the 0.6 readers (not for the repository as is).
#![no_main]
#[path = "alloc_guard.rs"]
mod alloc_guard;
#[global_allocator]
static A: alloc_guard::Counting = alloc_guard::Counting;
use cbb_core::join::{info::Info, intro::Intro, invitation::Invitation, waiting, welcome::Welcome};

fn one(data: &[u8]) {
    if let Ok(i) = Info::decode(data) {
        // Unknown fields are skipped by design: the model reads one way.
        assert_eq!(Info::decode(&i.encode()).as_ref(), Ok(&i), "an info encodes to another");
        let _ = i.admin_key();
    }
    if let Ok(w) = Welcome::decode(data) {
        assert_eq!(Welcome::decode(&w.encode()).as_ref(), Ok(&w), "a welcome encodes to another");
        use cbb_core::join::welcome::Joining;
        use cbb_core::records::Key;
        // The group the two keys make, so the joiner's checks go past the
        // Group ID (fields 1 and 9), and another group.
        let g = cbb_core::records::key::group_id(&Key::es256(w.root.clone()), &cbb_core::records::Recovery { k1: Key::es256(w.recovery.clone()), k2: Key { alg: cbb_core::records::key::ALG_SLH_DSA, public: w.recovery2.clone() } });
        let admitter: [u8; 65] = w.root.clone().try_into().unwrap_or([4; 65]);
        for j in [Joining::Ordinary, Joining::Guarded] {
            let _ = w.check(&g, &admitter, &[4; 65], j);
        }
        let _ = w.check(&cbb_core::format::DeviceId([0; 16]), &[4; 65], &[4; 65], Joining::Ordinary);
    }
    let _ = Welcome::parts(data);
    let _ = Intro::envelopes(data);
    if let Ok(i) = Intro::read(data) {
        assert_eq!(Intro::read(&i.message()).as_ref(), Ok(&i), "an intro writes another");
    }
    if let Ok(inv) = Invitation::decode(data) {
        assert_eq!(Invitation::decode(&inv.encode()).as_ref(), Ok(&inv), "an invitation encodes to another");
        let t = inv.text();
        assert_eq!(Invitation::parse(&t).as_ref(), Ok(&inv), "an invitation's text reads another");
    }
    if let Ok(s) = core::str::from_utf8(data) {
        if let Ok(inv) = Invitation::parse(s) {
            assert_eq!(Invitation::parse(&inv.text()).as_ref(), Ok(&inv), "an invitation text writes another");
        }
    }
    let _ = waiting::read(data);
    if let Ok((inv, key)) = waiting::read_dismiss(data) {
        let again = waiting::read_dismiss(&waiting::dismiss_message(&inv, key.as_ref()));
        assert_eq!(again, Ok((inv, key)), "a dismiss writes another");
    }
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| alloc_guard::bounded(data, one));

