// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class RemotePasteTest {
    /** The cases of Go's TestClean that a Kotlin string can hold, with the same results. */
    @Test
    fun clean() {
        val cases = mapOf(
            "ls -l\n" to "ls -l\n",
            "a\tb\r\nc\rd" to "a\tb\nc\nd",
            "Grüße, 世界 🙂" to "Grüße, 世界 🙂",
            "red \u001b[31mtext\u001b[0m" to "red text",
            "title \u001b]0;pwned\u0007ok" to "title ok",
            "osc \u001b]8;;x\u001b\\link" to "osc link",
            "csi \u009b2Jclear" to "csi clear",
            "bell\u0007 nul\u0000 del\u007f" to "bell nul del",
            "bad \ud800 surrogate" to "bad  surrogate",
            "esc at the end \u001b" to "esc at the end ",
            "keypad \u001b=on" to "keypad on",
        )
        for ((input, want) in cases) assertEquals(want, RemotePaste.clean(input), input)
    }

    @Test
    fun limiter() {
        val l = RemotePaste.Limiter()
        val now = 1_761_400_000_000L
        assertTrue(l.allow("a", now))
        assertFalse(l.allow("a", now + 500), "not one a second")
        assertTrue(l.allow("b", now), "another sender waits for the first")
        for (i in 1 until RemotePaste.BURST) assertTrue(l.allow("a", now + i * 1_000L))
        assertFalse(l.allow("a", now + RemotePaste.BURST * 1_000L), "more than a minute's burst")
        assertTrue(l.allow("a", now + 61_000L), "the oldest left the minute")
    }

    @Test
    fun settingsAndLog() {
        assertEquals(RemotePaste.Settings(), RemotePaste.Settings.decode(RemotePaste.Settings(on = false, enter = true).encode()))
        assertEquals(RemotePaste.Settings(true, true), RemotePaste.Settings.decode(RemotePaste.Settings(true, true).encode()))
        assertEquals(RemotePaste.Settings(), RemotePaste.Settings.decode("{\"on\":\"yes\"}".toByteArray()))
        val e = RemotePaste.Entry(5, "ab", "deck", 3, "type", true, "refused", "locked")
        var log = emptyList<RemotePaste.Entry>()
        repeat(RemotePaste.LOG_SIZE + 5) { log = RemotePaste.appended(log, e.copy(timeMS = it.toLong(), unverified = it % 2 == 0)) }
        assertEquals(RemotePaste.LOG_SIZE, log.size)
        assertEquals(5L, log.first().timeMS)
        assertEquals(log, RemotePaste.decodeLog(RemotePaste.encodeLog(log)))
        assertEquals(emptyList(), RemotePaste.decodeLog("not json".toByteArray()))
    }
}
