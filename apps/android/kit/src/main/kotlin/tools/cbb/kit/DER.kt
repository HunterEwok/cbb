// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.time.format.DateTimeFormatterBuilder
import java.time.temporal.ChronoField

/** The few DER encodings an X.509 certificate needs. */
internal object DER {
    fun tlv(tag: Int, content: ByteArray): ByteArray = byteArrayOf(tag.toByte()) + length(content.size) + content

    fun length(n: Int): ByteArray {
        if (n < 0x80) return byteArrayOf(n.toByte())
        val bytes = mutableListOf<Byte>()
        var v = n
        while (v > 0) {
            bytes.add(0, (v and 0xff).toByte())
            v = v ushr 8
        }
        return byteArrayOf((0x80 or bytes.size).toByte()) + bytes.toByteArray()
    }

    private fun cat(parts: List<ByteArray>): ByteArray = parts.fold(ByteArray(0)) { a, b -> a + b }

    fun sequence(vararg parts: ByteArray): ByteArray = tlv(0x30, cat(parts.toList()))
    fun sequence(parts: List<ByteArray>): ByteArray = tlv(0x30, cat(parts))
    fun set(vararg parts: ByteArray): ByteArray = tlv(0x31, cat(parts.toList()))
    fun bool(v: Boolean): ByteArray = tlv(0x01, byteArrayOf(if (v) 0xff.toByte() else 0))
    fun octetString(v: ByteArray): ByteArray = tlv(0x04, v)
    fun utf8String(s: String): ByteArray = tlv(0x0c, s.toByteArray())

    /** A context-specific tag: constructed (explicit) or primitive (implicit). */
    fun context(n: Int, constructed: Boolean, content: ByteArray): ByteArray =
        tlv((if (constructed) 0xa0 else 0x80) or n, content)

    /** A BIT STRING with the given number of unused bits in its last byte. */
    fun bitString(bytes: ByteArray, unused: Int = 0): ByteArray = tlv(0x03, byteArrayOf(unused.toByte()) + bytes)

    /** A non-negative INTEGER from big-endian bytes, in its minimal form. */
    fun integerUnsigned(bytes: ByteArray): ByteArray {
        var b = bytes.dropWhile { it == 0.toByte() }.toByteArray()
        if (b.isEmpty()) b = byteArrayOf(0)
        if (b[0].toInt() and 0x80 != 0) b = byteArrayOf(0) + b
        return tlv(0x02, b)
    }

    fun integer(v: Long): ByteArray {
        require(v >= 0)
        val bytes = mutableListOf<Byte>()
        var x = v
        do {
            bytes.add(0, (x and 0xff).toByte())
            x = x ushr 8
        } while (x > 0)
        return integerUnsigned(bytes.toByteArray())
    }

    /** An OBJECT IDENTIFIER from its dotted form. */
    fun oid(dotted: String): ByteArray {
        val arcs = dotted.split(".").map { it.toLong() }
        val out = mutableListOf((arcs[0] * 40 + arcs[1]).toByte())
        for (arc in arcs.drop(2)) {
            val chunk = mutableListOf((arc and 0x7f).toByte())
            var v = arc ushr 7
            while (v > 0) {
                chunk.add(0, ((v and 0x7f) or 0x80).toByte())
                v = v ushr 7
            }
            out += chunk
        }
        return tlv(0x06, out.toByteArray())
    }

    private val utcTime = DateTimeFormatter.ofPattern("yyMMddHHmmss'Z'").withZone(ZoneOffset.UTC)
    private val generalizedTime = DateTimeFormatter.ofPattern("yyyyMMddHHmmss'Z'").withZone(ZoneOffset.UTC)

    /** UTCTime for the years 1950 to 2049, GeneralizedTime otherwise, as RFC 5280 requires. */
    fun time(d: Instant): ByteArray {
        val year = d.atZone(ZoneOffset.UTC).year
        return if (year in 1950..2049) {
            tlv(0x17, utcTime.format(d).toByteArray())
        } else {
            tlv(0x18, generalizedTime.format(d).toByteArray())
        }
    }

    // yy from 50 on is 19yy, as RFC 5280 says.
    val utcTimeParser: DateTimeFormatter = DateTimeFormatterBuilder()
        .appendValueReduced(ChronoField.YEAR, 2, 2, 1950)
        .appendPattern("MMddHHmmss'Z'")
        .toFormatter()
        .withZone(ZoneOffset.UTC)
    val generalizedTimeParser: DateTimeFormatter = generalizedTime
}

class MalformedException(message: String = "malformed DER") : Exception(message)

/** A minimal DER reader over a byte range. */
internal class DERReader(val bytes: ByteArray) {
    var pos = 0

    val peek: Int? get() = if (pos < bytes.size) bytes[pos].toInt() and 0xff else null

    /** Reads one element; returns its content, or the whole element with raw. */
    fun readAny(raw: Boolean = false): DERReader {
        if (pos + 2 > bytes.size) throw MalformedException()
        val start = pos
        pos += 1
        var n = bytes[pos].toInt() and 0xff
        pos += 1
        if (n and 0x80 != 0) {
            val k = n and 0x7f
            if (k == 0 || k > 4 || pos + k > bytes.size) throw MalformedException()
            n = 0
            for (i in 0 until k) n = (n shl 8) or (bytes[pos + i].toInt() and 0xff)
            pos += k
            if (n < 0) throw MalformedException()
        }
        if (n > bytes.size - pos) throw MalformedException() // pos + n could overflow
        val out = DERReader(bytes.copyOfRange(if (raw) start else pos, pos + n))
        pos += n
        return out
    }

    fun read(tag: Int): DERReader {
        if (peek != tag) throw MalformedException()
        return readAny()
    }

    fun readTime(): Instant {
        val tag = peek
        val s = String(readAny().bytes)
        val f = when (tag) {
            0x17 -> DER.utcTimeParser
            0x18 -> DER.generalizedTimeParser
            else -> throw MalformedException()
        }
        return try {
            Instant.from(f.parse(s))
        } catch (e: java.time.DateTimeException) {
            throw MalformedException(e.message ?: "bad time")
        }
    }
}
