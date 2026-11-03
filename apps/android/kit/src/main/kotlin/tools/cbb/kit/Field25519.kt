// SPDX-License-Identifier: AGPL-3.0-only
//
// A port of internal/third_party/cpace/field.go, Copyright 2026 The Go
// Authors, under the BSD-style license in internal/third_party/cpace/LICENSE.

package tools.cbb.kit

/**
 * An element of the field GF(2^255-19), as four 64-bit limbs in
 * little-endian order holding a value less than p = 2^255-19.
 *
 * The operations run in time independent of the values, except that the
 * exponents, which are fixed constants, are used bit by bit.
 */
internal class FieldElement private constructor(private val l: ULongArray) {
    constructor(l0: ULong, l1: ULong, l2: ULong, l3: ULong) : this(ulongArrayOf(l0, l1, l2, l3))

    override fun equals(other: Any?): Boolean = other is FieldElement && l.contentEquals(other.l)

    override fun hashCode(): Int = l.contentHashCode()

    operator fun plus(y: FieldElement): FieldElement {
        val t = ULongArray(4)
        var c = 0uL
        for (i in 0 until 4) {
            val (s, o) = add(l[i], y.l[i], c)
            t[i] = s
            c = o
        }
        return reduce(t)
    }

    operator fun minus(y: FieldElement): FieldElement {
        val t = ULongArray(4)
        var borrow = 0uL
        for (i in 0 until 4) {
            val (d, o) = sub(l[i], y.l[i], borrow)
            t[i] = d
            borrow = o
        }
        val m = 0uL - borrow
        var c = 0uL
        for (i in 0 until 4) {
            val (s, o) = add(t[i], P.l[i] and m, c)
            t[i] = s
            c = o
        }
        return FieldElement(t)
    }

    operator fun times(y: FieldElement): FieldElement {
        // Schoolbook multiplication into eight limbs.
        val r = ULongArray(8)
        for (i in 0 until 4) {
            var carry = 0uL
            for (j in 0 until 4) {
                var hi = mulHigh(l[i], y.l[j])
                var lo = l[i] * y.l[j]
                var (s, c) = add(lo, r[i + j], 0uL)
                lo = s
                hi += c
                val (s2, c2) = add(lo, carry, 0uL)
                lo = s2
                hi += c2
                r[i + j] = lo
                carry = hi
            }
            r[i + 4] = carry
        }
        // Fold the upper half down: 2^256 = 38 mod p.
        val h = ULongArray(5)
        var carry = 0uL
        for (i in 0 until 4) {
            var hi = mulHigh(r[4 + i], 38uL)
            val (lo, c) = add(r[4 + i] * 38uL, carry, 0uL)
            hi += c
            h[i] = lo
            carry = hi
        }
        h[4] = carry
        val t = ULongArray(4)
        var c = 0uL
        for (i in 0 until 4) {
            val (s, o) = add(r[i], h[i], c)
            t[i] = s
            c = o
        }
        // Fold the overflow down again; it is small, so twice suffices.
        val top = h[4] + c
        c = foldInto(t, top * 38uL)
        foldInto(t, c * 38uL)
        // Fold bit 255 down: 2^255 = 19 mod p. Now t < 2p.
        val bit = t[3] shr 63
        t[3] = t[3] and (1uL shl 63).inv()
        foldInto(t, bit * 19uL)
        return reduce(t)
    }

    val squared: FieldElement get() = this * this

    /** Returns this**e for a public exponent e. */
    fun pow(e: FieldElement): FieldElement {
        var r = ONE
        for (i in 3 downTo 0) {
            for (j in 63 downTo 0) {
                r = r.squared
                if ((e.l[i] shr j) and 1uL == 1uL) r *= this
            }
        }
        return r
    }

    /** 1/this, or 0 for 0. */
    val inverted: FieldElement get() = pow(INV_EXP)

    /** The Legendre symbol: 1 for a non-zero square, -1 for a non-square, 0 for 0. */
    val chi: FieldElement get() = pow(CHI_EXP)

    /** The 32-byte little-endian encoding, as encodeUCoordinate in RFC 7748. */
    val bytes: ByteArray
        get() {
            val b = ByteArray(32)
            for (i in 0 until 4) for (k in 0 until 8) b[8 * i + k] = (l[i] shr (8 * k)).toByte()
            return b
        }

    /** Swaps a and b's limbs when swap is 1, in constant time. */
    fun copy(): FieldElement = FieldElement(l.copyOf())

    companion object {
        val ZERO = FieldElement(0uL, 0uL, 0uL, 0uL)
        val ONE = FieldElement(1uL, 0uL, 0uL, 0uL)
        val P = FieldElement(0xffff_ffff_ffff_ffeduL, ULong.MAX_VALUE, ULong.MAX_VALUE, 0x7fff_ffff_ffff_ffffuL)

        /** p-2, the exponent for inversion. */
        private val INV_EXP = FieldElement(0xffff_ffff_ffff_ffebuL, ULong.MAX_VALUE, ULong.MAX_VALUE, 0x7fff_ffff_ffff_ffffuL)

        /** (p-1)/2, the exponent for the Legendre symbol. */
        private val CHI_EXP = FieldElement(0xffff_ffff_ffff_fff6uL, ULong.MAX_VALUE, ULong.MAX_VALUE, 0x3fff_ffff_ffff_ffffuL)

        /**
         * The element encoded by 32 little-endian bytes, bit 255 ignored, as
         * decodeUCoordinate in RFC 7748.
         */
        fun fromBytes(b: ByteArray): FieldElement {
            require(b.size == 32)
            val t = ULongArray(4)
            for (i in 0 until 4) for (k in 0 until 8) t[i] = t[i] or ((b[8 * i + k].toULong() and 0xffuL) shl (8 * k))
            t[3] = t[3] and (1uL shl 63).inv()
            return reduce(t)
        }

        /** Returns x mod p, assuming x < 2p. */
        private fun reduce(x: ULongArray): FieldElement {
            val t = ULongArray(4)
            var borrow = 0uL
            for (i in 0 until 4) {
                val (d, o) = sub(x[i], P.l[i], borrow)
                t[i] = d
                borrow = o
            }
            val m = 0uL - borrow // all ones if x < p
            for (i in 0 until 4) t[i] = t[i] xor (m and (t[i] xor x[i]))
            return FieldElement(t)
        }

        /** Adds v to t, carrying up through the limbs; returns the carry out. */
        private fun foldInto(t: ULongArray, v: ULong): ULong {
            var (s, c) = add(t[0], v, 0uL)
            t[0] = s
            for (i in 1 until 4) {
                val (s2, c2) = add(t[i], 0uL, c)
                t[i] = s2
                c = c2
            }
            return c
        }

        /** Exchanges a and b when bit is 1, in constant time. */
        fun cswap(a: FieldElement, b: FieldElement, bit: ULong) {
            val m = 0uL - bit
            for (i in 0 until 4) {
                val d = m and (a.l[i] xor b.l[i])
                a.l[i] = a.l[i] xor d
                b.l[i] = b.l[i] xor d
            }
        }

        private fun add(x: ULong, y: ULong, carry: ULong): Pair<ULong, ULong> {
            val s1 = x + y
            val o1 = if (s1 < x) 1uL else 0uL
            val s2 = s1 + carry
            val o2 = if (s2 < s1) 1uL else 0uL
            return s2 to (o1 + o2)
        }

        private fun sub(x: ULong, y: ULong, borrow: ULong): Pair<ULong, ULong> {
            val d1 = x - y
            val o1 = if (x < y) 1uL else 0uL
            val d2 = d1 - borrow
            val o2 = if (d1 < borrow) 1uL else 0uL
            return d2 to (o1 + o2)
        }

        /** The upper 64 bits of the 128-bit product x*y. */
        private fun mulHigh(x: ULong, y: ULong): ULong {
            val x0 = x and 0xffff_ffffuL
            val x1 = x shr 32
            val y0 = y and 0xffff_ffffuL
            val y1 = y shr 32
            val p00 = x0 * y0
            val p01 = x0 * y1
            val p10 = x1 * y0
            val p11 = x1 * y1
            val mid = (p00 shr 32) + (p01 and 0xffff_ffffuL) + (p10 and 0xffff_ffffuL)
            return p11 + (p01 shr 32) + (p10 shr 32) + (mid shr 32)
        }
    }
}

/**
 * The Elligator 2 map with Z = 2 to the u-coordinate of a point on
 * Curve25519, as in draft-irtf-cfrg-cpace-21, Appendix A.5.
 */
internal fun elligator2(r: FieldElement): ByteArray {
    val a = FieldElement(486_662uL, 0uL, 0uL, 0uL)
    val aHalf = FieldElement(243_331uL, 0uL, 0uL, 0uL)
    // v = -A / (1 + 2*r^2)
    val v = (FieldElement.ZERO - a) * (r.squared + r.squared + FieldElement.ONE).inverted
    // w = v * (v^2 + A*v + 1)
    val w = (v.squared + a * v + FieldElement.ONE) * v
    val eps = w.chi
    // u = eps*v - (1 - eps) * A/2
    val u = eps * v - (FieldElement.ONE - eps) * aHalf
    return u.bytes
}

/**
 * X25519(scalar, u) of RFC 7748: the Montgomery ladder over the
 * u-coordinate, with the scalar clamped.
 */
internal fun x25519(scalar: ByteArray, u: ByteArray): ByteArray {
    require(scalar.size == 32 && u.size == 32)
    val k = scalar.copyOf()
    k[0] = (k[0].toInt() and 248).toByte()
    k[31] = ((k[31].toInt() and 127) or 64).toByte()
    val x1 = FieldElement.fromBytes(u)
    val a24 = FieldElement(121_665uL, 0uL, 0uL, 0uL)
    var x2 = FieldElement.ONE.copy()
    var z2 = FieldElement.ZERO.copy()
    var x3 = x1.copy()
    var z3 = FieldElement.ONE.copy()
    var swap = 0uL
    for (t in 254 downTo 0) {
        val bit = ((k[t / 8].toInt() shr (t % 8)) and 1).toULong()
        swap = swap xor bit
        FieldElement.cswap(x2, x3, swap)
        FieldElement.cswap(z2, z3, swap)
        swap = bit
        val a = x2 + z2
        val aa = a.squared
        val b = x2 - z2
        val bb = b.squared
        val e = aa - bb
        val c = x3 + z3
        val d = x3 - z3
        val da = d * a
        val cb = c * b
        x3 = (da + cb).squared.copy()
        z3 = (x1 * (da - cb).squared).copy()
        x2 = (aa * bb).copy()
        z2 = (e * (aa + a24 * e)).copy()
    }
    FieldElement.cswap(x2, x3, swap)
    FieldElement.cswap(z2, z3, swap)
    return (x2 * z2.inverted).bytes
}
