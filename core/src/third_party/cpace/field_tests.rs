// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Translated to Rust from internal/cpace/ of rsc.io/cmd/mote v0.1.3, file field_test.go; see
// README.md. The Go tests compare with math/big as they run; these compare
// with its results, written out in field_vectors.rs.

use super::field::*;
use super::field_vectors::{PAIRS, SINGLE, VALUES};

fn fe(s: &str) -> Fe {
    let b: Vec<u8> = (0..64).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect();
    from_bytes(&b.try_into().unwrap())
}

fn values() -> Vec<Fe> {
    VALUES.iter().map(|s| fe(s)).collect()
}

/// Every value is below p, so that equal values have equal limbs.
fn reduced(x: &Fe) -> bool {
    to_bytes(x) == to_bytes(&from_bytes(&to_bytes(x))) && x.0[3] >> 63 == 0
}

#[test]
fn field_arith() {
    let xs = values();
    let mut i = 0;
    for x in &xs {
        for y in &xs {
            let [s, d, m] = PAIRS[i];
            for (name, got, want) in [("add", add(x, y), s), ("sub", sub(x, y), d), ("mul", mul(x, y), m)] {
                assert_eq!(got, fe(want), "{name}({x:?}, {y:?})");
                assert!(reduced(&got), "{name}({x:?}, {y:?}) is not reduced");
            }
            i += 1;
        }
    }
    assert_eq!(i, PAIRS.len());
}

#[test]
fn field_square() {
    for x in values() {
        assert_eq!(square(&x), mul(&x, &x), "square({x:?})");
    }
}

#[test]
fn field_invert_chi_elligator2() {
    for (x, [inv, legendre, ell]) in values().iter().zip(SINGLE) {
        // 1/0 is defined as 0, and the Legendre symbol -1 is p-1.
        assert_eq!(invert(x), fe(inv), "invert({x:?})");
        assert_eq!(chi(x), fe(legendre), "chi({x:?})");
        assert_eq!(elligator2(x), to_bytes(&fe(ell)), "elligator2({x:?})");
    }
}

#[test]
fn field_bytes() {
    // from_bytes ignores bit 255 and reduces modulo p.
    for x in values() {
        let mut b = to_bytes(&x);
        assert_eq!(from_bytes(&b), x);
        b[31] |= 0x80;
        assert_eq!(from_bytes(&b), x, "bit 255 of {b:?} is not ignored");
    }
    // Values between p and 2^255 are reduced: p + 7 is 7.
    let mut b = [0xff; 32];
    b[0] = 0xed + 7;
    b[31] = 0x7f;
    assert_eq!(from_bytes(&b), Fe([7, 0, 0, 0]));
}
