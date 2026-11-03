// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class CoreTest {
    /**
     * Evaluates every case of testdata/interop/v2-records.json in the linked
     * core, which must give its state byte for byte, as Go's
     * internal/authority does.
     */
    @Test
    fun vectors() {
        val cases = Interop.read("v2-records.json").jsonObject.getValue("cases").jsonArray
        assertTrue(cases.isNotEmpty())
        for (c in cases) {
            val o = c as JsonObject
            val request = """{"abi":1,"op":"evaluate","args":$o}"""
            val answer = Core.call(request.toByteArray()).decodeToString()
            assertEquals("""{"abi":1,"ok":${o.str("state")}}""", answer, o.str("name"))
        }
    }

    /** Asks the version, and sees a refusal come back as a Refusal. */
    @Test
    fun run() {
        val v = Core.version()
        assertEquals(Core.ABI, v.abi)
        assertTrue(v.core.isNotEmpty())
        assertTrue(v.line.startsWith("core ${v.core}, abi 1, source "), v.line)
        val e = assertFailsWith<Core.Refusal> { Core.run("no such op") }
        assertEquals("op", e.name)
        assertEquals(3, e.code)
        assertTrue(Core.call(ByteArray(0)).decodeToString().contains(""""name":"request""""))
    }

    /** Calls the core from many threads at once, as the member's connections do. */
    @Test
    fun concurrent() {
        val pool = Executors.newFixedThreadPool(16)
        val calls = (1..16).map { pool.submit<Int> { (1..20).sumOf { Core.version().abi } } }
        calls.forEach { assertEquals(20 * Core.ABI, it.get(30, TimeUnit.SECONDS)) }
        pool.shutdown()
    }
}
