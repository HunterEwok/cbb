// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Translated to Rust from internal/third_party/cpace/field.go and
// elligator.go; see README.md.

//! Arithmetic in GF(2^255-19) and the Elligator 2 map to Curve25519.

/// An element of the field GF(2^255-19), represented as four 64-bit limbs
/// in little-endian order holding a value less than p = 2^255-19.
///
/// All operations run in time independent of the values being operated on,
/// except that exponents, which are fixed constants, are used bit by bit.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub(crate) struct Fe(pub(crate) [u64; 4]);

const FE_ZERO: Fe = Fe([0, 0, 0, 0]);
const FE_ONE: Fe = Fe([1, 0, 0, 0]);

/// The field modulus p = 2^255-19.
const FE_P: Fe = Fe([0xffffffffffffffed, 0xffffffffffffffff, 0xffffffffffffffff, 0x7fffffffffffffff]);

/// p-2 = 2^255-21, the exponent used for inversion.
const FE_INV_EXP: Fe = Fe([0xffffffffffffffeb, 0xffffffffffffffff, 0xffffffffffffffff, 0x7fffffffffffffff]);

/// (p-1)/2 = 2^254-10, the exponent used for the Legendre symbol.
const FE_CHI_EXP: Fe = Fe([0xfffffffffffffff6, 0xffffffffffffffff, 0xffffffffffffffff, 0x3fffffffffffffff]);

/// The Curve25519 parameter A, and A/2.
const FE_A: Fe = Fe([486662, 0, 0, 0]);
const FE_A_HALF: Fe = Fe([243331, 0, 0, 0]);

#[inline]
fn add64(x: u64, y: u64, carry: u64) -> (u64, u64) {
    let s = x as u128 + y as u128 + carry as u128;
    (s as u64, (s >> 64) as u64)
}

#[inline]
fn sub64(x: u64, y: u64, borrow: u64) -> (u64, u64) {
    let d = (x as u128).wrapping_sub(y as u128).wrapping_sub(borrow as u128);
    (d as u64, ((d >> 64) as u64) & 1)
}

#[inline]
fn mul64(x: u64, y: u64) -> (u64, u64) {
    let p = x as u128 * y as u128;
    ((p >> 64) as u64, p as u64)
}

/// Returns x mod p, assuming x < 2p.
fn reduce(x: &Fe) -> Fe {
    // t = x - p. If that borrows, x < p and we keep x instead.
    let x = &x.0;
    let mut t = [0u64; 4];
    let mut b;
    (t[0], b) = sub64(x[0], FE_P.0[0], 0);
    (t[1], b) = sub64(x[1], FE_P.0[1], b);
    (t[2], b) = sub64(x[2], FE_P.0[2], b);
    (t[3], b) = sub64(x[3], FE_P.0[3], b);
    let m = b.wrapping_neg(); // all ones if x < p, all zeros otherwise
    Fe([t[0] ^ (m & (t[0] ^ x[0])), t[1] ^ (m & (t[1] ^ x[1])), t[2] ^ (m & (t[2] ^ x[2])), t[3] ^ (m & (t[3] ^ x[3]))])
}

/// Returns x + y.
pub(crate) fn add(x: &Fe, y: &Fe) -> Fe {
    // x + y < 2p < 2^256, so the sum cannot overflow four limbs.
    let mut t = [0u64; 4];
    let mut c;
    (t[0], c) = add64(x.0[0], y.0[0], 0);
    (t[1], c) = add64(x.0[1], y.0[1], c);
    (t[2], c) = add64(x.0[2], y.0[2], c);
    (t[3], _) = add64(x.0[3], y.0[3], c);
    reduce(&Fe(t))
}

/// Returns x - y.
pub(crate) fn sub(x: &Fe, y: &Fe) -> Fe {
    let mut t = [0u64; 4];
    let mut b;
    (t[0], b) = sub64(x.0[0], y.0[0], 0);
    (t[1], b) = sub64(x.0[1], y.0[1], b);
    (t[2], b) = sub64(x.0[2], y.0[2], b);
    (t[3], b) = sub64(x.0[3], y.0[3], b);

    // If the subtraction borrowed, add p back.
    let m = b.wrapping_neg();
    let mut z = [0u64; 4];
    let mut c;
    (z[0], c) = add64(t[0], FE_P.0[0] & m, 0);
    (z[1], c) = add64(t[1], FE_P.0[1] & m, c);
    (z[2], c) = add64(t[2], FE_P.0[2] & m, c);
    (z[3], _) = add64(t[3], FE_P.0[3] & m, c);
    Fe(z)
}

/// Returns x * y.
pub(crate) fn mul(x: &Fe, y: &Fe) -> Fe {
    // Schoolbook multiplication into the eight limbs of r.
    let mut r = [0u64; 8];
    for i in 0..4 {
        let mut carry = 0u64;
        for j in 0..4 {
            let (mut hi, mut lo) = mul64(x.0[i], y.0[j]);
            let mut c;
            (lo, c) = add64(lo, r[i + j], 0);
            hi += c;
            (lo, c) = add64(lo, carry, 0);
            hi += c;
            r[i + j] = lo;
            carry = hi;
        }
        r[i + 4] = carry;
    }

    // Fold the upper half down: 2^256 = 38 mod p.
    let mut h = [0u64; 5];
    let mut carry = 0u64;
    for i in 0..4 {
        let (mut hi, mut lo) = mul64(r[4 + i], 38);
        let c;
        (lo, c) = add64(lo, carry, 0);
        hi += c;
        h[i] = lo;
        carry = hi;
    }
    h[4] = carry;

    let mut t = [0u64; 4];
    let mut c;
    (t[0], c) = add64(r[0], h[0], 0);
    (t[1], c) = add64(r[1], h[1], c);
    (t[2], c) = add64(r[2], h[2], c);
    (t[3], c) = add64(r[3], h[3], c);

    // Fold the overflow down again. It is at most 38+1, so 38*top fits
    // in a single limb, and the addition can overflow at most once more.
    let top = h[4] + c;
    (t[0], c) = add64(t[0], top * 38, 0);
    (t[1], c) = add64(t[1], 0, c);
    (t[2], c) = add64(t[2], 0, c);
    (t[3], c) = add64(t[3], 0, c);
    (t[0], c) = add64(t[0], c * 38, 0);
    (t[1], c) = add64(t[1], 0, c);
    (t[2], c) = add64(t[2], 0, c);
    (t[3], _) = add64(t[3], 0, c);

    // Fold bit 255 down: 2^255 = 19 mod p. Now t < 2^255+19 < 2p.
    let b = t[3] >> 63;
    t[3] &= !(1 << 63);
    (t[0], c) = add64(t[0], b * 19, 0);
    (t[1], c) = add64(t[1], 0, c);
    (t[2], c) = add64(t[2], 0, c);
    (t[3], _) = add64(t[3], 0, c);

    reduce(&Fe(t))
}

/// Returns x * x.
pub(crate) fn square(x: &Fe) -> Fe {
    mul(x, x)
}

/// Returns x**e, for a public exponent e.
fn pow(x: &Fe, e: &Fe) -> Fe {
    let mut r = FE_ONE;
    for i in (0..4).rev() {
        for j in (0..64).rev() {
            r = square(&r);
            if (e.0[i] >> j) & 1 == 1 {
                r = mul(&r, x);
            }
        }
    }
    r
}

/// Returns 1/x, or 0 if x = 0.
pub(crate) fn invert(x: &Fe) -> Fe {
    pow(x, &FE_INV_EXP)
}

/// Returns the Legendre symbol of x: 1 if x is a non-zero square, -1 if x
/// is not a square, and 0 if x is zero.
pub(crate) fn chi(x: &Fe) -> Fe {
    pow(x, &FE_CHI_EXP)
}

/// Returns the field element encoded by the 32 bytes of b, which are
/// interpreted as a little-endian integer with bit 255 ignored, as in the
/// decodeUCoordinate function of RFC 7748.
pub(crate) fn from_bytes(b: &[u8; 32]) -> Fe {
    let mut t = [0u64; 4];
    for (i, limb) in t.iter_mut().enumerate() {
        *limb = u64::from_le_bytes(b[8 * i..8 * i + 8].try_into().unwrap());
    }
    t[3] &= !(1 << 63); // ignore bit 255, leaving t < 2^255 < 2p
    reduce(&Fe(t))
}

/// Returns the 32-byte little-endian encoding of x, as in the
/// encodeUCoordinate function of RFC 7748.
pub(crate) fn to_bytes(x: &Fe) -> [u8; 32] {
    let mut b = [0u8; 32];
    for (i, v) in x.0.iter().enumerate() {
        b[8 * i..8 * i + 8].copy_from_slice(&v.to_le_bytes());
    }
    b
}

/// Maps the field element r to the u-coordinate of a point on Curve25519,
/// using the Elligator 2 map with the non-square Z = 2, as specified in
/// draft-irtf-cfrg-cpace-21, Appendix A.5:
///
/// ```text
/// v = -A / (1 + Z*r^2)
/// epsilon = (v^3 + A*v^2 + B*v)^((q-1)/2)
/// u = epsilon*v - (1 - epsilon) * A/2
/// ```
///
/// The curve parameter B is 1, and epsilon is the Legendre symbol of the
/// curve equation evaluated at v, so it is 1 if v is the u-coordinate of a
/// curve point and -1 if it is not. In the latter case -v-A is used
/// instead, which then is a u-coordinate on the curve.
pub(crate) fn elligator2(r: &Fe) -> [u8; 32] {
    let neg_a = sub(&FE_ZERO, &FE_A);

    // v = -A / (1 + 2*r^2)
    let mut t = square(r);
    t = add(&t, &t);
    t = add(&t, &FE_ONE);
    t = invert(&t);
    let v = mul(&neg_a, &t);

    // w = v^3 + A*v^2 + v = v * (v^2 + A*v + 1)
    let mut w = square(&v);
    t = mul(&FE_A, &v);
    w = add(&w, &t);
    w = add(&w, &FE_ONE);
    w = mul(&w, &v);

    // epsilon = w^((p-1)/2)
    let eps = chi(&w);

    // u = epsilon*v - (1 - epsilon) * A/2
    let mut u = mul(&eps, &v);
    t = sub(&FE_ONE, &eps);
    t = mul(&t, &FE_A_HALF);
    u = sub(&u, &t);

    to_bytes(&u)
}
