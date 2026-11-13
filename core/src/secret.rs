// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

//! Secrets in memory and in time: the one comparison the core uses for
//! anything a secret decides (a mark, a confirmation tag, a commitment),
//! and the redacted form a secret takes in `Debug`. Secrets the core holds
//! are wiped when dropped with `zeroize`; docs/core-api.md, "Secrets",
//! lists them.

use core::fmt;

use subtle::ConstantTimeEq;
/// zeroize's types, for the core's callers to keep the secrets the core
/// hands them the same way.
pub use zeroize::{Zeroize, Zeroizing};

/// Whether a and b are equal, in a time that depends only on their
/// lengths. Use it for every comparison one of whose sides is a secret or
/// an authenticator; public values (key hashes, IDs, tags a server sees)
/// may use `==`.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

/// Writes a secret field in `Debug` as its length only.
pub struct Redacted(pub usize);

impl fmt::Debug for Redacted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<{} secret bytes>", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ct_eq_is_equality() {
        assert!(ct_eq(b"", b""));
        assert!(ct_eq(&[7; 32], &[7; 32]));
        assert!(!ct_eq(&[7; 32], &[7; 31]));
        let mut b = [7u8; 32];
        for i in 0..32 {
            b[i] ^= 1;
            assert!(!ct_eq(&[7; 32], &b), "{i}");
            b[i] ^= 1;
        }
    }

    #[test]
    fn redacted_shows_no_bytes() {
        assert_eq!(alloc::format!("{:?}", Redacted(32)), "<32 secret bytes>");
    }
}

/// Timing tests in the manner of dudect (Reparaz, Balasch, Verbauwhede,
/// "Dude, is my code constant time?", 2017): two classes of wrong inputs,
/// one that differs from the right value only in its last byte and one
/// that differs in its first, measured in random order; Welch's t-test
/// over the times, the slowest tenth cut off, must not tell the classes
/// apart. They are ignored by default, being slow and sensitive to a busy
/// machine: `cargo test -p cbb-core --release -- --ignored timing --test-threads=1`.
#[cfg(test)]
mod timing {
    use alloc::vec::Vec;
    use std::time::Instant;

    use crate::records::{RecordSet, pin_mark};
    use crate::testkit::{G, k};
    use crate::third_party::cpace;

    /// Measurements per class.
    const N: usize = 100_000;
    /// The largest |t| taken as no leak. dudect flags 4.5 with far more
    /// measurements; 10 leaves room for a shared machine's noise, and a
    /// comparison that stops at the first different byte gives far more.
    const MAX_T: f64 = 10.0;

    /// The bits of a small generator (SplitMix64), so that the classes'
    /// order is random but each run the same.
    struct Mix(u64);

    impl Mix {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        }
    }

    /// Welch's t over the two classes' times, the slowest tenth of each cut.
    fn welch(mut a: Vec<f64>, mut b: Vec<f64>) -> f64 {
        let crop = |v: &mut Vec<f64>| {
            v.sort_by(f64::total_cmp);
            v.truncate(v.len() * 9 / 10);
        };
        crop(&mut a);
        crop(&mut b);
        let stats = |v: &[f64]| {
            let n = v.len() as f64;
            let mean = v.iter().sum::<f64>() / n;
            let var = v.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n - 1.0);
            (mean, var, n)
        };
        let ((ma, va, na), (mb, vb, nb)) = (stats(&a), stats(&b));
        (ma - mb) / (va / na + vb / nb).sqrt()
    }

    /// Times check on the two classes of inputs that wrong makes from the
    /// right value, in random order, and returns Welch's t.
    fn t_of(right: &[u8], check: impl Fn(&[u8]) -> bool) -> f64 {
        let (mut last, mut first) = (right.to_vec(), right.to_vec());
        *last.last_mut().unwrap() ^= 1;
        first[0] ^= 1;
        let (mut a, mut b) = (Vec::with_capacity(N), Vec::with_capacity(N));
        let mut mix = Mix(0x5eed);
        // Warm the caches and the branch predictor first.
        for _ in 0..1000 {
            assert!(!check(&last) && !check(&first));
        }
        while a.len() < N || b.len() < N {
            let class_a = mix.next() & 1 == 0;
            if (class_a && a.len() == N) || (!class_a && b.len() == N) {
                continue;
            }
            let input = if class_a { &last } else { &first };
            let t = Instant::now();
            let ok = core::hint::black_box(check(core::hint::black_box(input)));
            let d = t.elapsed().as_nanos() as f64;
            assert!(!ok);
            if class_a { a.push(d) } else { b.push(d) }
        }
        let t = welch(a, b);
        std::eprintln!("t = {t:.2}");
        t
    }

    /// The control: a comparison that stops at the first different byte,
    /// over inputs long enough for the difference to show, is caught.
    #[test]
    #[ignore = "a timing measurement; run with --ignored timing"]
    fn timing_control_catches_an_early_exit() {
        let right = alloc::vec![7u8; 4096];
        let t = t_of(&right, |x| core::hint::black_box(x) == core::hint::black_box(&right[..]));
        assert!(t.abs() > MAX_T, "t = {t:.1}: the test would not see a leak");
    }

    #[test]
    #[ignore = "a timing measurement; run with --ignored timing"]
    fn timing_record_mark() {
        let mut g = G::new();
        g.device("laptop", crate::records::body::ROLE_MEMBER, 0, |_| {});
        let r = g.checkpoint(crate::testkit::T0);
        let local = [9u8; 32];
        let mark = r.mark(&local);
        let t = t_of(&mark, |m| r.mark_holds(&local, m.try_into().unwrap()));
        assert!(t.abs() < MAX_T, "t = {t:.1}");
    }

    #[test]
    #[ignore = "a timing measurement; run with --ignored timing"]
    fn timing_pin_mark() {
        let (root, recovery) = (k("root").key, k("recovery").key);
        let local = [9u8; 32];
        let mark = pin_mark(&local, &root, &recovery);
        let t =
            t_of(&mark, |m| RecordSet::pinned(root.clone(), recovery.clone(), &local, m.try_into().unwrap()).is_some());
        assert!(t.abs() < MAX_T, "t = {t:.1}");
    }

    #[test]
    #[ignore = "a timing measurement; run with --ignored timing"]
    fn timing_pairing_confirmation() {
        let cfg = |role, ad: &'static [u8]| cpace::Config {
            role,
            password: b"123456",
            channel_id: b"channel",
            session_id: b"session",
            ad,
        };
        let (mut a, ma) = cpace::start(&cfg(cpace::Role::Initiator, b"a")).unwrap();
        let (mut b, mb) = cpace::start(&cfg(cpace::Role::Responder, b"b")).unwrap();
        a.finish(&mb, b"b").unwrap();
        b.finish(&ma, b"a").unwrap();
        let tag = b.tag().unwrap();
        a.verify(&tag).unwrap();
        let t = t_of(&tag, |x| a.verify(x).is_ok());
        assert!(t.abs() < MAX_T, "t = {t:.1}");
    }
}
