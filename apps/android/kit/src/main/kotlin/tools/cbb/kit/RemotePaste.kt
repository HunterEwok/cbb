// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * What a phone keeps for remote paste as a target (docs/design.md, "Remote
 * paste"), as Go's internal/remotepaste: the switches its own user sets, the
 * cleaning of a text before it goes in, the limits per sender and the log of
 * the last pastes.
 */
object RemotePaste {
    /** The switches only the phone's own user turns on: on lets the group's admins paste, enter lets a paste press Enter. */
    data class Settings(val on: Boolean = false, val enter: Boolean = false) {
        fun encode(): ByteArray {
            val s = if (on) this else Settings()
            val fields = mutableListOf("on" to JsonPrimitive(s.on))
            if (s.enter) fields += "enter" to JsonPrimitive(true)
            return Wire.encode(Wire.obj(*fields.toTypedArray()))
        }

        companion object {
            /** The settings in data; all off when it says nothing. */
            fun decode(data: ByteArray): Settings {
                val o = Wire.parse(data) ?: return Settings()
                return try {
                    val on = o.optBool("on") == true
                    Settings(on, on && o.optBool("enter") == true)
                } catch (e: WireTypeException) {
                    Settings()
                }
            }
        }
    }

    /**
     * The text as it may go in: newlines and tabs, without other control
     * characters and without terminal escape sequences, so that a paste
     * cannot move a terminal's cursor or run what the user does not see. CR
     * LF and a lone CR become LF; a lone surrogate goes.
     */
    fun clean(text: String): String {
        val b = StringBuilder(text.length)
        var i = 0
        while (i < text.length) {
            val c = text[i]
            var n = 1
            when {
                c == '\r' -> {
                    b.append('\n')
                    if (i + 1 < text.length && text[i + 1] == '\n') n++
                }
                c == '\u001b' -> n = escapeLen(text, i)
                c == '\u009b' -> n += csiLen(text, i + 1)
                c == '\n' || c == '\t' -> b.append(c)
                c < ' ' || c == '\u007f' || c in '\u0080'..'\u009f' -> {}
                c.isHighSurrogate() && i + 1 < text.length && text[i + 1].isLowSurrogate() -> {
                    b.append(c).append(text[i + 1])
                    n = 2
                }
                c.isSurrogate() -> {}
                else -> b.append(c)
            }
            i += n
        }
        return b.toString()
    }

    /** The length of the escape sequence at s[i], which is ESC: CSI up to its final byte, OSC, DCS and the like up to BEL or ESC \, or ESC and one character. */
    private fun escapeLen(s: String, i: Int): Int {
        if (i + 1 >= s.length) return s.length - i
        return when (s[i + 1]) {
            '[' -> 2 + csiLen(s, i + 2)
            ']', 'P', 'X', '^', '_' -> {
                var j = i + 2
                while (j < s.length) {
                    if (s[j] == '\u0007') return j + 1 - i
                    if (s[j] == '\u001b' && j + 1 < s.length && s[j + 1] == '\\') return j + 2 - i
                    j++
                }
                s.length - i
            }
            else -> if (s[i + 1].isHighSurrogate() && i + 2 < s.length && s[i + 2].isLowSurrogate()) 3 else 2
        }
    }

    /** The length of a CSI sequence's parameters and final byte at s[i]. */
    private fun csiLen(s: String, i: Int): Int {
        var j = i
        while (j < s.length) {
            val c = s[j]
            if (c in '@'..'~') return j + 1 - i
            if (c < ' ' || c > '~') return j - i
            j++
        }
        return s.length - i
    }

    /** The limits per sender: at most one paste a second and BURST a minute. */
    const val EVERY_MS = 1_000L
    const val BURST = 30

    /** Counts each sender's pastes. */
    class Limiter {
        private val sent = HashMap<String, ArrayDeque<Long>>()

        /** Whether sender may paste at nowMS; it counts the paste if so. */
        @Synchronized
        fun allow(sender: String, nowMS: Long): Boolean {
            val it = sent.entries.iterator()
            while (it.hasNext()) {
                val ts = it.next().value
                while (ts.isNotEmpty() && nowMS - ts.first() >= 60_000) ts.removeFirst()
                if (ts.isEmpty()) it.remove()
            }
            val ts = sent.getOrPut(sender) { ArrayDeque() }
            if (ts.size >= BURST || (ts.isNotEmpty() && nowMS - ts.last() < EVERY_MS)) {
                if (ts.isEmpty()) sent.remove(sender)
                return false
            }
            ts.addLast(nowMS)
            return true
        }
    }

    /** One paste in the log: who sent it, when, how long it was and how it ended, never its text. */
    data class Entry(
        val timeMS: Long,
        val by: String,
        val name: String?,
        val len: Int,
        val method: String,
        val enter: Boolean,
        val result: String,
        val reason: String?,
        /** The records do not show that the device by names signed; by is then only the signer's word. */
        val unverified: Boolean = false,
    )

    /** How many pastes the log keeps. */
    const val LOG_SIZE = 100

    /** The log with e added, the last LOG_SIZE kept. */
    fun appended(log: List<Entry>, e: Entry): List<Entry> = (log + e).takeLast(LOG_SIZE)

    fun encodeLog(log: List<Entry>): ByteArray = Wire.encode(
        JsonArray(
            log.map { e ->
                val fields = mutableListOf<Pair<String, JsonElement?>>(
                    "time_ms" to Wire.num(e.timeMS),
                    "by" to Wire.str(e.by),
                    "len" to Wire.num(e.len.toLong()),
                    "method" to Wire.str(e.method),
                    "result" to Wire.str(e.result),
                )
                e.name?.let { fields += "name" to Wire.str(it) }
                if (e.enter) fields += "enter" to JsonPrimitive(true)
                e.reason?.let { fields += "reason" to Wire.str(it) }
                if (e.unverified) fields += "unverified" to JsonPrimitive(true)
                Wire.obj(*fields.toTypedArray())
            },
        ),
    )

    /** The log in data; entries it cannot read are left out, and all of it when it is not a log. */
    fun decodeLog(data: ByteArray): List<Entry> {
        val a = try {
            Json.parseToJsonElement(String(data, Charsets.UTF_8)) as? JsonArray
        } catch (e: SerializationException) {
            null
        } catch (e: IllegalArgumentException) {
            null
        } ?: return emptyList()
        return a.mapNotNull { el ->
            val o = el as? JsonObject ?: return@mapNotNull null
            try {
                Entry(
                    o.optLong("time_ms") ?: return@mapNotNull null,
                    o.optString("by") ?: return@mapNotNull null,
                    o.optString("name"),
                    (o.optLong("len") ?: 0).toInt(),
                    o.optString("method") ?: "paste",
                    o.optBool("enter") == true,
                    o.optString("result") ?: return@mapNotNull null,
                    o.optString("reason"),
                    o.optBool("unverified") == true,
                )
            } catch (e: WireTypeException) {
                null
            }
        }
    }
}
