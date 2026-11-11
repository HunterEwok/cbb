// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class BugReportsTest {
    @Test
    fun keepsTheStateThroughAReport() {
        var saved: String? = null
        val posted = mutableListOf<String>()
        val bugs = BugReports({ saved }, { saved = it }, { url, _ -> posted.add(url); """{"fixed_in":"0.6.1"}""" }, { 1_762_646_400_000 })
        val o = bugs.offer(
            BugReports.Input(
                kind = "panic", code = 5, name = "panic", message = "Something in CBB broke.",
                details = "panic: boom at member/src/x.rs:1:2", app = "android", version = "0.6.0",
                log = listOf("dialed 192.168.0.2:8764 for Pixel"), names = listOf("Pixel"),
            ),
        )
        assertEquals("member/src/x.rs:1:2", o.report.getValue("where").jsonPrimitive.content)
        val line = o.report.getValue("log").toString()
        assertFalse(line.contains("192.168.0.2") || line.contains("Pixel"), line)
        assertEquals(BugReports.URL, o.url)
        assertFalse(o.offerAlways)
        // This build has no robot key yet: nothing is posted.
        if (o.post.isEmpty()) {
            assertEquals("skip", o.action)
            assertNull(bugs.send(o))
            assertTrue(posted.isEmpty())
        } else {
            assertEquals("ask", o.action)
            assertEquals("0.6.1", bugs.send(o))
        }
        bugs.allow(false)
        bugs.allow(false)
        assertEquals(2, Json.parseToJsonElement(saved!!).jsonObject.getValue("allowed").jsonPrimitive.int)
        assertEquals(0, bugs.resend())
    }
}
