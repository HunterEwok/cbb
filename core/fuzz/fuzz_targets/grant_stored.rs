// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! A leaf's stored state (`grant::Stored`) from arbitrary bytes: the
//! reader never panics; what it takes writes back to the same bytes and
//! reads again the same; bytes it refuses give a state that obeys nobody
//! and takes no grant; a state it takes that obeys anyone is one a writer
//! makes: a grant's hash with its commanders, no fork, no wait, and the
//! head at or above the grant's seq.

#![no_main]

use cbb_core::format::grant::{self, Stored};
use cbb_core::format::{Alg, Key};

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let s = Stored::load(Some(data));
    let (kept, rec) = s.start();
    match Stored::decode(data) {
        Ok(d) => {
            assert_eq!(d, s, "load and decode differ");
            assert_eq!(d.encode(), data, "took a state that does not write back");
            assert_eq!(Stored::decode(&d.encode()).as_ref(), Ok(&d), "a written state reads otherwise");
            if !kept.commanders.is_empty() && !kept.forked && !kept.needs_rebind(rec) {
                assert!(kept.grant_hash != [0; 32], "obeys commanders without a grant");
                assert!(kept.rebind.is_none(), "obeys commanders while it waits");
                assert!(kept.commanders.len() <= grant::MAX_COMMANDERS, "too many commanders");
                assert!(kept.commanders.windows(2).all(|w| w[0].0 < w[1].0), "commanders not sorted");
                for (h, p) in &kept.commanders {
                    assert_eq!(Key { alg: Alg::Es256, public: p }.hash(), *h, "a commander's hash is not its key's");
                }
                assert!(s.head().is_none_or(|(_, h)| h >= kept.recovery), "a head below the grant's seq");
            }
            assert!(rec <= grant::MAX_RECOVERY, "a recovery seq above the limit");
        }
        Err(_) => {
            assert!(kept.commanders.is_empty() && kept.forked && kept.guarded, "refused bytes give a state that obeys someone");
            assert_eq!(rec, grant::MAX_RECOVERY, "refused bytes do not lock out every root");
        }
    }
});
