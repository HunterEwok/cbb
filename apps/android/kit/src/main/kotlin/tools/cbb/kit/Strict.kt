// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.util.Base64

/**
 * The strict form of signed bodies (docs/protocol.md, section 1, "Signed
 * bodies"), which every member reads alike, as Go's checkStrict.
 */
internal object Strict {
    /** How deeply a signed body nests arrays and objects at most. */
    private const val MAX_DEPTH = 16

    class Invalid(message: String) : Exception(message)

    /**
     * Checks that b is one JSON object in valid UTF-8; member names of 1 to
     * 64 of a-z, 0-9 and _, without escapes, none twice in one object; no
     * null; integers only, without fraction or exponent, in the range of a
     * Long; a surrogate escape only as one half of a pair. Each name in
     * required must be a member of the object.
     */
    fun check(b: ByteArray, vararg required: String) {
        try {
            Charsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(b))
        } catch (e: CharacterCodingException) {
            throw Invalid("a signed body is not valid UTF-8")
        }
        val p = Parser(b)
        p.space()
        if (p.peek() != '{'.code) throw Invalid("a signed body is not a JSON object")
        val names = try {
            p.obj(0)
        } catch (e: Invalid) {
            throw Invalid("a signed body: ${e.message}")
        }
        p.space()
        if (p.i != b.size) throw Invalid("a signed body has more after its object")
        for (n in required) if (n !in names) throw Invalid("a signed body has no $n")
    }

    /** Whether b is a body that [check] takes. */
    fun ok(b: ByteArray, vararg required: String): Boolean = runCatching { check(b, *required) }.isSuccess

    /**
     * Whether every number in b, outside its strings, is an integer as
     * [check] takes it: never "-0", a fraction or an exponent. Readers differ
     * on those (Go takes "-0" for 0, the lite member's reader for a float),
     * so the member protocol's frames pass this first, members a reader does
     * not know included. It only scans: whether b is JSON is for the decoder.
     */
    fun integersOnly(b: ByteArray): Boolean {
        var i = 0
        while (i < b.size) {
            val c = b[i].toInt()
            if (c == '"'.code) {
                i++
                while (i < b.size && b[i] != '"'.code.toByte()) i += if (b[i] == '\\'.code.toByte()) 2 else 1
                i++
            } else if (c == '-'.code || c in '0'.code..'9'.code) {
                val p = Parser(b)
                p.i = i
                try {
                    p.integer()
                } catch (e: Invalid) {
                    return false
                }
                i = p.i
            } else {
                i++
            }
        }
        return true
    }

    /** Decodes s, standard base64 with padding, only when s is the one encoding of its bytes. */
    fun base64(s: String): ByteArray? {
        val b = try {
            Base64.getDecoder().decode(s)
        } catch (e: IllegalArgumentException) {
            return null
        }
        return b.takeIf { Base64.getEncoder().encodeToString(it) == s }
    }

    private class Parser(val b: ByteArray) {
        var i = 0

        fun peek(): Int = if (i < b.size) b[i].toInt() and 0xff else -1

        fun space() {
            while (peek() == ' '.code || peek() == '\t'.code || peek() == '\n'.code || peek() == '\r'.code) i++
        }

        fun value(depth: Int) {
            space()
            when (val c = peek()) {
                -1 -> throw Invalid("it ends early")
                '{'.code, '['.code -> {
                    if (depth >= MAX_DEPTH) throw Invalid("it nests too deeply")
                    if (c == '{'.code) obj(depth + 1) else array(depth + 1)
                }
                '"'.code -> string()
                't'.code -> literal("true")
                'f'.code -> literal("false")
                'n'.code -> throw Invalid("it has a null")
                else -> if (c == '-'.code || c in '0'.code..'9'.code) integer() else throw Invalid("an unexpected character")
            }
        }

        fun obj(depth: Int): Set<String> {
            i++ // {
            val names = mutableSetOf<String>()
            space()
            if (peek() == '}'.code) {
                i++
                return names
            }
            while (true) {
                space()
                if (!names.add(name())) throw Invalid("a member is there twice")
                space()
                if (peek() != ':'.code) throw Invalid("a member has no value")
                i++
                value(depth)
                space()
                when (peek()) {
                    ','.code -> i++
                    '}'.code -> {
                        i++
                        return names
                    }
                    -1 -> throw Invalid("it ends early")
                    else -> throw Invalid("an unexpected character in an object")
                }
            }
        }

        /** A member name: 1 to 64 of a-z, 0-9 and _ in quotes. */
        fun name(): String {
            if (peek() != '"'.code) throw Invalid("a member has no name")
            val start = ++i
            while (true) {
                when (val c = peek()) {
                    -1 -> throw Invalid("it ends early")
                    '"'.code -> break
                    else -> if (c in 'a'.code..'z'.code || c in '0'.code..'9'.code || c == '_'.code) i++ else throw Invalid("a member name is not of a-z, 0-9 and _")
                }
            }
            val name = String(b, start, i - start, Charsets.US_ASCII)
            i++
            if (name.isEmpty() || name.length > 64) throw Invalid("a member name is not 1 to 64 characters")
            return name
        }

        fun array(depth: Int) {
            i++ // [
            space()
            if (peek() == ']'.code) {
                i++
                return
            }
            while (true) {
                value(depth)
                space()
                when (peek()) {
                    ','.code -> i++
                    ']'.code -> {
                        i++
                        return
                    }
                    -1 -> throw Invalid("it ends early")
                    else -> throw Invalid("an unexpected character in an array")
                }
            }
        }

        fun string() {
            i++ // "
            while (true) {
                val c = peek()
                when {
                    c == -1 -> throw Invalid("it ends early")
                    c == '"'.code -> {
                        i++
                        return
                    }
                    c < 0x20 -> throw Invalid("a string holds a control character")
                    c != '\\'.code -> {
                        i++
                        continue
                    }
                }
                i++
                when (peek()) {
                    -1 -> throw Invalid("it ends early")
                    '"'.code, '\\'.code, '/'.code, 'b'.code, 'f'.code, 'n'.code, 'r'.code, 't'.code -> i++
                    'u'.code -> {
                        val r = hex4()
                        if (r in 0xd800 until 0xdc00) {
                            if (i + 1 >= b.size || b[i] != '\\'.code.toByte() || b[i + 1] != 'u'.code.toByte()) throw Invalid("a string has half a surrogate pair")
                            i++
                            if (hex4() !in 0xdc00..0xdfff) throw Invalid("a string has half a surrogate pair")
                        } else if (r in 0xdc00..0xdfff) {
                            throw Invalid("a string has half a surrogate pair")
                        }
                    }
                    else -> throw Invalid("a string has an unknown escape")
                }
            }
        }

        /** The u and four hex digits of a \u escape. */
        fun hex4(): Int {
            if (i + 5 > b.size) throw Invalid("it ends early")
            var v = 0
            for (k in i + 1 until i + 5) {
                val d = Character.digit(b[k].toInt() and 0xff, 16)
                if (d < 0) throw Invalid("a string has a wrong \\u escape")
                v = v * 16 + d
            }
            i += 5
            return v
        }

        fun literal(s: String) {
            if (i + s.length > b.size || String(b, i, s.length, Charsets.US_ASCII) != s) throw Invalid("an unknown literal")
            i += s.length
        }

        /** -?[1-9][0-9]*|0, in the range of a Long; "-0" is refused. */
        fun integer() {
            val start = i
            if (peek() == '-'.code) i++
            val digits = i
            while (peek() in '0'.code..'9'.code) i++
            if (i == digits) throw Invalid("a number has no digits")
            if (b[digits] == '0'.code.toByte() && i > digits + 1) throw Invalid("a number has a leading zero")
            if (b[digits] == '0'.code.toByte() && digits > start) throw Invalid("a number is a negative zero")
            if (peek() == '.'.code || peek() == 'e'.code || peek() == 'E'.code) throw Invalid("a number is not an integer")
            String(b, start, i - start, Charsets.US_ASCII).toLongOrNull() ?: throw Invalid("a number is out of range")
        }
    }
}
