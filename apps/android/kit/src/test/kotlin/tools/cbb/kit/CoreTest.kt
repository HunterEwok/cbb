// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class CoreTest {
    /** Asks the version, and sees a refusal come back as a Refusal. */
    /** A panic in the core's library is an answer, code 5 with what broke and where, and the core answers again after it. */
    @Test
    fun panicIsAnAnswer() {
        val e = Core.testPanic()
        assertEquals(5, e.code)
        assertEquals("panic", e.name)
        assertTrue(e.details.orEmpty().contains("cbb_test_panic"), e.toString())
        assertNotNull(Core.lastPanic())
        assertEquals(Core.ABI, Core.version().abi)
        // A panic in one of the member's threads is an event the app restarts the member on.
        val ev = CoreMember.decode("""{"type":"panic","details":"panic: boom at member/src/x.rs:1:2"}""".toByteArray())
        assertEquals("panic: boom at member/src/x.rs:1:2", (ev as CoreMember.Event.Panic).details)
    }

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
