// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ClockTest {
    /** The timestamps a clock took do not move how far ahead it takes the next one (hlc-ahead.json, as Go's TestAheadVectors writes it). */
    @Test
    fun aheadVectors() {
        val v = Interop.read("hlc-ahead.json").jsonObject
        assertEquals(HybridClock.MAX_AHEAD_MS, v.getValue("max_ahead").jsonPrimitive.long)
        val now = v.getValue("now").jsonPrimitive.long
        val c = HybridClock(wallMS = { now })
        for (w in v.getValue("accepted").jsonArray.map { it.jsonPrimitive.long }) {
            val ts = Member.Timestamp(w, 0)
            assertFalse(c.ahead(ts), "$w refused")
            c.observe(ts)
        }
        assertTrue(c.ahead(Member.Timestamp(v.getValue("refused").jsonPrimitive.long, 0)), "taken after a chain of timestamps ahead")
    }
}
