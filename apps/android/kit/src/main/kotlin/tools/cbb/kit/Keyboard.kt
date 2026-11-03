// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive

/**
 * Typing a text as a Bluetooth keyboard (docs/roadmap.md, item 25): the
 * keys of a layout and the HID boot keyboard's reports that press them,
 * as the lite member's cbb_core::keyboard has them for the Nano ESP32.
 * Both are checked against testdata/interop/keyboard.json.
 *
 * A keyboard sends the position of a key, not a character: the host's
 * layout turns the position into one. So the phone needs the layout that
 * is active on the host, and a character that layout cannot type is
 * refused rather than typed as something else.
 */
object Keyboard {
    /** Shift, of the modifier bits in a report's first byte. */
    const val LEFT_SHIFT = 0x02

    /** The usages of the keys a text needs besides its characters. */
    const val ENTER = 0x28
    const val TAB = 0x2b
    const val SPACE = 0x2c

    /** A key of the HID keyboard page and the modifiers held with it. */
    data class Key(val usage: Int, val modifiers: Int = 0) {
        /** The boot keyboard's report that holds this key down: the modifiers, a reserved byte and up to six keys. */
        fun report(): ByteArray = byteArrayOf(modifiers.toByte(), 0, usage.toByte(), 0, 0, 0, 0, 0)
    }

    /** The report with every key up. */
    val RELEASE: ByteArray get() = ByteArray(8)

    /**
     * The HID report descriptor of a boot keyboard: eight modifier bits, a
     * reserved byte and six keys, with the five LEDs the host sets. A
     * Bluetooth host reads it from the phone when they pair.
     */
    val DESCRIPTOR: ByteArray = byteArrayOf(
        0x05, 0x01, // usage page: generic desktop
        0x09, 0x06, // usage: keyboard
        0xa1.toByte(), 0x01, // collection: application
        0x05, 0x07, //   usage page: keyboard
        0x19, 0xe0.toByte(), //   usage minimum: left control
        0x29, 0xe7.toByte(), //   usage maximum: right GUI
        0x15, 0x00, //   logical minimum 0
        0x25, 0x01, //   logical maximum 1
        0x75, 0x01, //   report size 1
        0x95.toByte(), 0x08, //   report count 8
        0x81.toByte(), 0x02, //   input: the modifiers
        0x95.toByte(), 0x01, //   report count 1
        0x75, 0x08, //   report size 8
        0x81.toByte(), 0x01, //   input: the reserved byte
        0x95.toByte(), 0x05, //   report count 5
        0x75, 0x01, //   report size 1
        0x05, 0x08, //   usage page: LEDs
        0x19, 0x01, //   usage minimum: num lock
        0x29, 0x05, //   usage maximum: kana
        0x91.toByte(), 0x02, //   output: the LEDs
        0x95.toByte(), 0x01, //   report count 1
        0x75, 0x03, //   report size 3
        0x91.toByte(), 0x01, //   output: padding
        0x95.toByte(), 0x06, //   report count 6
        0x75, 0x08, //   report size 8
        0x15, 0x00, //   logical minimum 0
        0x25, 0x65, //   logical maximum 101
        0x05, 0x07, //   usage page: keyboard
        0x19, 0x00, //   usage minimum 0
        0x29, 0x65, //   usage maximum 101
        0x81.toByte(), 0x00, //   input: the keys
        0xc0.toByte(), // end collection
    )

    /** A layout active on the host, by the name a user sets it with. */
    enum class Layout(val key: String) {
        /** English (US), the default of most TVs and computers. */
        US("us"),

        /** Russian (the JCUKEN layout), as Windows, macOS's "Russian - PC" and XKB's ru have it. */
        RU("ru"),
        ;

        /** The key that types the character c (a code point), if this layout has one. A new line presses Enter and a tab Tab. */
        fun key(c: Int): Key? = when (c) {
            '\n'.code -> Key(ENTER)
            '\t'.code -> Key(TAB)
            ' '.code -> Key(SPACE)
            else -> when (this) {
                US -> us(c)
                RU -> ru(c)
            }
        }

        /** The characters of text, each once and in the order they first come, that this layout cannot type. */
        fun untypeable(text: String): List<String> {
            val out = LinkedHashSet<String>()
            text.codePoints().forEach { c ->
                if (c != '\r'.code && key(c) == null) out += String(Character.toChars(c))
            }
            return out.toList()
        }

        /**
         * The reports that type text: each key down and then all keys up,
         * so that the same key twice in a row is two presses. A carriage
         * return types nothing, so a CRLF line end is one Enter. Null when
         * the layout cannot type a character of it (untypeable says which).
         */
        fun reports(text: String): List<ByteArray>? {
            val out = ArrayList<ByteArray>(text.length * 2)
            for (c in text.codePoints().toArray()) {
                if (c == '\r'.code) continue
                out += (key(c) ?: return null).report()
                out += RELEASE
            }
            return out
        }

        companion object {
            fun of(key: String?): Layout? = entries.firstOrNull { it.key.equals(key, ignoreCase = true) }
        }
    }

    /** The slowest, fastest and usual typing, in characters a second, as the Nano's rate. */
    const val MIN_RATE = 5
    const val MAX_RATE = 60
    const val DEFAULT_RATE = 20

    /**
     * What the phone's user set for its Bluetooth keyboard: whether it is
     * on, the host by its Bluetooth address, the layout active on the host,
     * characters a second, and whether remote pastes go to the host rather
     * than into this phone's focused field.
     */
    data class Settings(
        val on: Boolean = false,
        val host: String? = null,
        val layout: Layout = Layout.US,
        val rate: Int = DEFAULT_RATE,
        val pastes: Boolean = false,
    ) {
        fun encode(): ByteArray {
            val fields = mutableListOf<Pair<String, JsonElement?>>(
                "on" to JsonPrimitive(on),
                "layout" to Wire.str(layout.key),
                "rate" to Wire.num(rate.toLong()),
            )
            host?.let { fields += "host" to Wire.str(it) }
            if (pastes) fields += "pastes" to JsonPrimitive(true)
            return Wire.encode(Wire.obj(*fields.toTypedArray()))
        }

        companion object {
            private val ADDRESS = Regex("[0-9A-F]{2}(:[0-9A-F]{2}){5}")

            /** The settings in data; the defaults for what it does not say, or says wrong. */
            fun decode(data: ByteArray): Settings {
                val o = Wire.parse(data) ?: return Settings()
                return try {
                    Settings(
                        on = o.optBool("on") == true,
                        host = o.optString("host")?.takeIf { ADDRESS.matches(it) },
                        layout = Layout.of(o.optString("layout")) ?: Layout.US,
                        rate = (o.optLong("rate") ?: DEFAULT_RATE.toLong()).coerceIn(MIN_RATE.toLong(), MAX_RATE.toLong()).toInt(),
                        pastes = o.optBool("pastes") == true,
                    )
                } catch (e: WireTypeException) {
                    Settings()
                }
            }
        }
    }

    /** The digits' row and the keys right of it, which most layouts share. */
    private fun digit(c: Int): Key? = when (c) {
        in '1'.code..'9'.code -> Key(0x1e + c - '1'.code)
        '0'.code -> Key(0x27)
        '-'.code -> Key(0x2d)
        '='.code -> Key(0x2e)
        else -> null
    }

    private val US_SHIFTED = mapOf(
        '!' to 0x1e, '@' to 0x1f, '#' to 0x20, '$' to 0x21, '%' to 0x22, '^' to 0x23, '&' to 0x24,
        '*' to 0x25, '(' to 0x26, ')' to 0x27, '_' to 0x2d, '+' to 0x2e, '{' to 0x2f, '}' to 0x30,
        '|' to 0x31, ':' to 0x33, '"' to 0x34, '~' to 0x35, '<' to 0x36, '>' to 0x37, '?' to 0x38,
    )

    private val US_PLAIN = mapOf(
        '[' to 0x2f, ']' to 0x30, '\\' to 0x31, ';' to 0x33, '\'' to 0x34, '`' to 0x35, ',' to 0x36,
        '.' to 0x37, '/' to 0x38,
    )

    private fun us(c: Int): Key? {
        digit(c)?.let { return it }
        return when (c) {
            in 'a'.code..'z'.code -> Key(0x04 + c - 'a'.code)
            in 'A'.code..'Z'.code -> Key(0x04 + c - 'A'.code, LEFT_SHIFT)
            else -> {
                if (c > 0xffff) return null
                US_SHIFTED[c.toChar()]?.let { Key(it, LEFT_SHIFT) } ?: US_PLAIN[c.toChar()]?.let { Key(it) }
            }
        }
    }

    /** The Russian letters on the keys of the US letters q to /, in the US keys' order: the row of q, of a and of z. */
    private val RU_LETTERS = mapOf(
        '\u0439' to 0x14, // short i
        '\u0446' to 0x1a, // tse
        '\u0443' to 0x08, // u
        '\u043a' to 0x15, // ka
        '\u0435' to 0x17, // ie
        '\u043d' to 0x1c, // en
        '\u0433' to 0x18, // ghe
        '\u0448' to 0x0c, // sha
        '\u0449' to 0x12, // shcha
        '\u0437' to 0x13, // ze
        '\u0445' to 0x2f, // ha
        '\u044a' to 0x30, // hard sign
        '\u0444' to 0x04, // ef
        '\u044b' to 0x16, // yeru
        '\u0432' to 0x07, // ve
        '\u0430' to 0x09, // a
        '\u043f' to 0x0a, // pe
        '\u0440' to 0x0b, // er
        '\u043e' to 0x0d, // o
        '\u043b' to 0x0e, // el
        '\u0434' to 0x0f, // de
        '\u0436' to 0x33, // zhe
        '\u044d' to 0x34, // e
        '\u044f' to 0x1d, // ya
        '\u0447' to 0x1b, // che
        '\u0441' to 0x06, // es
        '\u043c' to 0x19, // em
        '\u0438' to 0x05, // i
        '\u0442' to 0x11, // te
        '\u044c' to 0x10, // soft sign
        '\u0431' to 0x36, // be
        '\u044e' to 0x37, // yu
        '\u0451' to 0x35, // io
    )

    private val RU_SHIFTED = mapOf(
        '!' to 0x1e, '"' to 0x1f, '\u2116' to 0x20 /* the numero sign */, ';' to 0x21, '%' to 0x22, ':' to 0x23,
        '?' to 0x24, '*' to 0x25, '(' to 0x26, ')' to 0x27, '_' to 0x2d, '+' to 0x2e, '/' to 0x31, ',' to 0x38,
    )

    private val RU_PLAIN = mapOf('\\' to 0x31, '.' to 0x38)

    private fun ru(c: Int): Key? {
        digit(c)?.let { return it }
        if (c > 0xffff) return null
        val ch = c.toChar()
        RU_LETTERS[ch]?.let { return Key(it) }
        // A capital: the small letter's key with Shift.
        val lower = ch.lowercaseChar()
        if (lower != ch) RU_LETTERS[lower]?.let { return Key(it, LEFT_SHIFT) }
        return RU_SHIFTED[ch]?.let { Key(it, LEFT_SHIFT) } ?: RU_PLAIN[ch]?.let { Key(it) }
    }
}
