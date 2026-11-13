// Long fuzzing of the 0.6 readers (not for the repository as is).
#![no_main]
#[path = "alloc_guard.rs"]
mod alloc_guard;
#[global_allocator]
static A: alloc_guard::Counting = alloc_guard::Counting;
use cbb_core::format::cbor;
use cbb_core::records::{body::Body, Record};

fn v_high(b: &[u8]) -> bool {
    cbor::decode(b).ok().and_then(|v| v.as_map().map(|m| m.iter().any(|(k, _)| *k >= 256))).unwrap_or(true)
}

fn one(data: &[u8]) {
    // A recovery head's list (rule 33): one form.
    if let Ok(l) = cbb_core::records::body::List::decode(data) {
        assert_eq!(l.encode(), data, "a list does not encode back");
    }
    if let Ok(r) = Record::decode(data) {
        assert_eq!(r.envelope(), data, "a record's envelope does not write back");
        // A held body (a later type or critical field) keeps its bytes; its
        // model does not carry what this version does not know.
        // Fields from 256 up are not critical and not in the model either.
        let high = v_high(r.body_bytes());
        if !r.body().held && !high {
            assert_eq!(r.body().encode(), r.body_bytes(), "a record's body does not encode back");
        }
        let v = cbor::decode(r.body_bytes()).expect("a taken body is not CBOR");
        let again = Body::from_value(&v).expect("a taken body does not read again");
        assert_eq!(&again, r.body(), "a body reads two ways");
        let again = Record::from_parts(r.body_bytes().to_vec(), r.sig().to_vec(), None, r.body().clone());
        let _ = again;
        let _ = r.size();
        // A set whose root is some key: the signature fails, the reader must not.
        let root = cbb_core::records::key::Key::es256({
            let mut p = vec![0x04u8];
            p.extend_from_slice(&[0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2,
                0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
                0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16,
                0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5]);
            p
        });
        let mut set = cbb_core::records::set::RecordSet::new(root.clone(), cbb_core::records::Recovery { k1: root, k2: cbb_core::records::Key::new(cbb_core::records::key::ALG_SLH_DSA, vec![0x5a; 32]) });
        let _ = set.insert(r);
        let st = set.state();
        drop(st);
    }
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| alloc_guard::bounded(data, one));

