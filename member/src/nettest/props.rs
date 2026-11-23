// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Properties of the service's copies over random inputs: the rule of
//! incoming copies keeps its promises.

use proptest::prelude::*;

use cbb_core::clip::Kind;
use cbb_core::rule::{self, Incoming, Verdict};

proptest! {
    #![proptest_config(ProptestConfig { cases: 200, failure_persistence: None, ..ProptestConfig::default() })]

    /// The rule of incoming copies: what never writes, and that a copy
    /// written at one age is written at every younger one.
    #[test]
    fn the_rule_keeps_its_promises(
        flags in any::<[bool; 8]>(),
        kind in prop_oneof![Just(Kind::Text), Just(Kind::Secret), Just(Kind::Media)],
        age in 0i64..400_000,
        younger in 0i64..400_000,
        window in 1i64..300_000,
        ttl in 1i64..300_000,
    ) {
        let i = Incoming {
            receives: flags[0], kind, mark: flags[1], unread: flags[2], has_text: flags[3],
            has_media: flags[4], takes_media: flags[5], held: flags[6], before_start: flags[7],
            age_ms: age, window_ms: window, secret_ttl_ms: ttl,
        };
        let v = rule::incoming(&i);
        if v == Verdict::Write {
            prop_assert!(i.receives && !i.mark && !i.unread && !i.held && !i.before_start && age < window);
            prop_assert!(i.has_text || (i.takes_media && i.has_media));
            prop_assert!(kind != Kind::Secret || age < ttl);
            let y = Incoming { age_ms: younger.min(age), ..i.clone() };
            prop_assert_eq!(rule::incoming(&y), Verdict::Write);
        }
        if v == Verdict::Old {
            let o = Incoming { age_ms: age.max(younger), ..i.clone() };
            prop_assert_ne!(rule::incoming(&o), Verdict::Write);
        }
        if !i.receives {
            prop_assert_eq!(v, Verdict::Mode);
        }
    }
}
