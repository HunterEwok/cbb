// SPDX-License-Identifier: AGPL-3.0-only
//
// A port of internal/third_party/cpace/field.go, Copyright 2026 The Go
// Authors, under the BSD-style license in internal/third_party/cpace/LICENSE.

/// An element of the field GF(2^255-19), as four 64-bit limbs in
/// little-endian order holding a value less than p = 2^255-19.
///
/// The operations run in time independent of the values, except that the
/// exponents, which are fixed constants, are used bit by bit.
struct FieldElement: Equatable {
    var l: (UInt64, UInt64, UInt64, UInt64)

    init(_ l0: UInt64, _ l1: UInt64, _ l2: UInt64, _ l3: UInt64) { l = (l0, l1, l2, l3) }

    static func == (a: FieldElement, b: FieldElement) -> Bool {
        a.l.0 == b.l.0 && a.l.1 == b.l.1 && a.l.2 == b.l.2 && a.l.3 == b.l.3
    }

    static let zero = FieldElement(0, 0, 0, 0)
    static let one = FieldElement(1, 0, 0, 0)
    static let p = FieldElement(0xffff_ffff_ffff_ffed, .max, .max, 0x7fff_ffff_ffff_ffff)
    /// p-2, the exponent for inversion.
    static let invExp = FieldElement(0xffff_ffff_ffff_ffeb, .max, .max, 0x7fff_ffff_ffff_ffff)
    /// (p-1)/2, the exponent for the Legendre symbol.
    static let chiExp = FieldElement(0xffff_ffff_ffff_fff6, .max, .max, 0x3fff_ffff_ffff_ffff)

    var limbs: [UInt64] { [l.0, l.1, l.2, l.3] }
    init(limbs t: [UInt64]) { l = (t[0], t[1], t[2], t[3]) }

    /// Returns x mod p, assuming x < 2p.
    static func reduce(_ x: [UInt64]) -> FieldElement {
        let pl = p.limbs
        var t = [UInt64](repeating: 0, count: 4)
        var borrow: UInt64 = 0
        for i in 0..<4 { (t[i], borrow) = sub(x[i], pl[i], borrow) }
        let m = 0 &- borrow // all ones if x < p
        for i in 0..<4 { t[i] ^= m & (t[i] ^ x[i]) }
        return FieldElement(limbs: t)
    }

    static func + (x: FieldElement, y: FieldElement) -> FieldElement {
        let a = x.limbs, b = y.limbs
        var t = [UInt64](repeating: 0, count: 4)
        var c: UInt64 = 0
        for i in 0..<4 { (t[i], c) = add(a[i], b[i], c) }
        return reduce(t)
    }

    static func - (x: FieldElement, y: FieldElement) -> FieldElement {
        let a = x.limbs, b = y.limbs, pl = p.limbs
        var t = [UInt64](repeating: 0, count: 4)
        var borrow: UInt64 = 0
        for i in 0..<4 { (t[i], borrow) = sub(a[i], b[i], borrow) }
        let m = 0 &- borrow
        var c: UInt64 = 0
        for i in 0..<4 { (t[i], c) = add(t[i], pl[i] & m, c) }
        return FieldElement(limbs: t)
    }

    static func * (x: FieldElement, y: FieldElement) -> FieldElement {
        let a = x.limbs, b = y.limbs
        // Schoolbook multiplication into eight limbs.
        var r = [UInt64](repeating: 0, count: 8)
        for i in 0..<4 {
            var carry: UInt64 = 0
            for j in 0..<4 {
                var (hi, lo) = a[i].multipliedFullWidth(by: b[j])
                var c: UInt64
                (lo, c) = add(lo, r[i + j], 0)
                hi &+= c
                (lo, c) = add(lo, carry, 0)
                hi &+= c
                r[i + j] = lo
                carry = hi
            }
            r[i + 4] = carry
        }
        // Fold the upper half down: 2^256 = 38 mod p.
        var h = [UInt64](repeating: 0, count: 5)
        var carry: UInt64 = 0
        for i in 0..<4 {
            var (hi, lo) = r[4 + i].multipliedFullWidth(by: 38)
            var c: UInt64
            (lo, c) = add(lo, carry, 0)
            hi &+= c
            h[i] = lo
            carry = hi
        }
        h[4] = carry
        var t = [UInt64](repeating: 0, count: 4)
        var c: UInt64 = 0
        for i in 0..<4 { (t[i], c) = add(r[i], h[i], c) }
        // Fold the overflow down again; it is small, so twice suffices.
        let top = h[4] &+ c
        (t[0], c) = add(t[0], top &* 38, 0)
        for i in 1..<4 { (t[i], c) = add(t[i], 0, c) }
        (t[0], c) = add(t[0], c &* 38, 0)
        for i in 1..<4 { (t[i], c) = add(t[i], 0, c) }
        // Fold bit 255 down: 2^255 = 19 mod p. Now t < 2p.
        let bit = t[3] >> 63
        t[3] &= ~(UInt64(1) << 63)
        (t[0], c) = add(t[0], bit &* 19, 0)
        for i in 1..<4 { (t[i], c) = add(t[i], 0, c) }
        return reduce(t)
    }

    var squared: FieldElement { self * self }

    /// Returns self**e for a public exponent e.
    func pow(_ e: FieldElement) -> FieldElement {
        var r = FieldElement.one
        let el = e.limbs
        for i in stride(from: 3, through: 0, by: -1) {
            for j in stride(from: 63, through: 0, by: -1) {
                r = r.squared
                if (el[i] >> UInt64(j)) & 1 == 1 { r = r * self }
            }
        }
        return r
    }

    /// 1/self, or 0 for 0.
    var inverted: FieldElement { pow(.invExp) }

    /// The Legendre symbol: 1 for a non-zero square, -1 for a non-square, 0 for 0.
    var chi: FieldElement { pow(.chiExp) }

    /// The element encoded by 32 little-endian bytes, bit 255 ignored, as
    /// decodeUCoordinate in RFC 7748.
    init(bytes b: [UInt8]) {
        precondition(b.count == 32)
        var t = [UInt64](repeating: 0, count: 4)
        for i in 0..<4 {
            for k in 0..<8 { t[i] |= UInt64(b[8 * i + k]) << UInt64(8 * k) }
        }
        t[3] &= ~(UInt64(1) << 63)
        self = FieldElement.reduce(t)
    }

    /// The 32-byte little-endian encoding, as encodeUCoordinate in RFC 7748.
    var bytes: [UInt8] {
        var b = [UInt8](repeating: 0, count: 32)
        for (i, v) in limbs.enumerated() {
            for k in 0..<8 { b[8 * i + k] = UInt8(truncatingIfNeeded: v >> UInt64(8 * k)) }
        }
        return b
    }

    private static func add(_ x: UInt64, _ y: UInt64, _ carry: UInt64) -> (UInt64, UInt64) {
        let (s1, o1) = x.addingReportingOverflow(y)
        let (s2, o2) = s1.addingReportingOverflow(carry)
        return (s2, (o1 ? 1 : 0) + (o2 ? 1 : 0))
    }

    private static func sub(_ x: UInt64, _ y: UInt64, _ borrow: UInt64) -> (UInt64, UInt64) {
        let (d1, o1) = x.subtractingReportingOverflow(y)
        let (d2, o2) = d1.subtractingReportingOverflow(borrow)
        return (d2, (o1 ? 1 : 0) + (o2 ? 1 : 0))
    }
}

/// The Elligator 2 map with Z = 2 to the u-coordinate of a point on
/// Curve25519, as in draft-irtf-cfrg-cpace-21, Appendix A.5.
func elligator2(_ r: FieldElement) -> [UInt8] {
    let a = FieldElement(486_662, 0, 0, 0)
    let aHalf = FieldElement(243_331, 0, 0, 0)
    // v = -A / (1 + 2*r^2)
    let v = (FieldElement.zero - a) * (r.squared + r.squared + .one).inverted
    // w = v * (v^2 + A*v + 1)
    let w = (v.squared + a * v + .one) * v
    let eps = w.chi
    // u = eps*v - (1 - eps) * A/2
    let u = eps * v - (.one - eps) * aHalf
    return u.bytes
}
