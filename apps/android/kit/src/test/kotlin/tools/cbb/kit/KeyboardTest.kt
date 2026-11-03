// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNull

class KeyboardTest {
    /** testdata/interop/keyboard.json, from the lite member's keyboard tests: the Nano and the phone type alike. */
    @Test
    fun vectors() {
        val v = Interop.read("keyboard.json").jsonObject
        val candidates = v.str("candidates")
        val layouts = v.getValue("layouts").jsonObject
        assertEquals(Keyboard.Layout.entries.map { it.key }.toSet(), layouts.keys)
        for (l in Keyboard.Layout.entries) {
            val keys = layouts.getValue(l.key).jsonObject
            candidates.codePoints().forEach { c ->
                val s = String(Character.toChars(c))
                val want = keys[s]?.jsonArray?.let { Keyboard.Key(it[1].jsonPrimitive.int, it[0].jsonPrimitive.int) }
                assertEquals(want, l.key(c), "${l.key} U+%04X".format(c))
            }
        }
        for (t in v.getValue("texts").jsonArray) {
            t as JsonObject
            val l = Keyboard.Layout.of(t.str("layout"))!!
            val text = t.str("text")
            val reports = t["reports"] as JsonArray?
            if (reports != null) {
                val got = l.reports(text)!!.map { r -> r.joinToString("") { "%02x".format(it) } }
                assertEquals(reports.map { it.jsonPrimitive.content }, got, text)
                assertEquals(emptyList(), l.untypeable(text))
            } else {
                assertNull(l.reports(text), text)
                assertEquals(t.getValue("untypeable").jsonArray.map { it.jsonPrimitive.content }, l.untypeable(text))
            }
        }
    }

    @Test
    fun reports() {
        val r = Keyboard.Layout.US.reports("aA\r\n")!!
        assertEquals(6, r.size)
        assertContentEquals(byteArrayOf(Keyboard.LEFT_SHIFT.toByte(), 0, 0x04, 0, 0, 0, 0, 0), r[2])
        assertContentEquals(Keyboard.RELEASE, r[5])
        // A character outside the BMP is one character, and untypeable.
        assertEquals(listOf("\uD83D\uDE00"), Keyboard.Layout.US.untypeable("ok \uD83D\uDE00\uD83D\uDE00"))
        assertEquals(Keyboard.Layout.RU, Keyboard.Layout.of("RU"))
        assertNull(Keyboard.Layout.of("de"))
    }

    @Test
    fun settings() {
        val s = Keyboard.Settings(on = true, host = "AA:BB:CC:00:11:22", layout = Keyboard.Layout.RU, rate = 40, pastes = true)
        assertEquals(s, Keyboard.Settings.decode(s.encode()))
        assertEquals(Keyboard.Settings(), Keyboard.Settings.decode("not json".toByteArray()))
        // A wrong address goes, a rate is kept within the limits, an unknown layout is US.
        assertEquals(
            Keyboard.Settings(on = true, rate = Keyboard.MAX_RATE),
            Keyboard.Settings.decode("""{"on":true,"host":"aa:bb","rate":1000,"layout":"de"}""".toByteArray()),
        )
        assertEquals(Keyboard.Settings(), Keyboard.Settings.decode("""{"on":"yes"}""".toByteArray()))
    }
}
