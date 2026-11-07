// SPDX-License-Identifier: AGPL-3.0-only

package tools.cbb.kit

import java.time.Instant
import java.util.Collections
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class EngineTest {
    @Test
    fun offerChecksAsGo() {
        val (k, p) = ByteArray(32) { 2 } to ByteArray(32) { 3 }
        assertTrue(Member.TunnelOffer(k, p, listOf("192.0.2.1:8764", "[2001:db8::1]:65535")).isValid)
        assertFalse(Member.TunnelOffer(ByteArray(32), p).isValid, "a hub key of zeros")
        assertFalse(Member.TunnelOffer(k, ByteArray(32)).isValid, "a preshared key of zeros")
        for (e in listOf("192.0.2.1:0", "192.0.2.1", "192.0.2.1:65536", "192.0.2.1:+1", ":8764x", "[2001:db8::1]")) {
            assertFalse(Member.TunnelOffer(k, p, listOf(e)).isValid, e)
        }
    }

    @Test
    fun clock() {
        var wall = 1000L
        val c = HybridClock(wallMS = { wall })
        assertEquals(Member.Timestamp(1000, 0), c.now())
        assertEquals(Member.Timestamp(1000, 1), c.now())
        wall = 999 // the wall clock went back
        assertEquals(Member.Timestamp(1000, 2), c.now())
        c.observe(Member.Timestamp(5000, 7)) // a peer ahead
        assertEquals(Member.Timestamp(5000, 8), c.latest)
        c.observe(Member.Timestamp(5000, 3))
        assertEquals(Member.Timestamp(5000, 9), c.latest)
        wall = 9000
        c.observe(Member.Timestamp(10, 0))
        assertEquals(Member.Timestamp(9000, 0), c.latest)
        val floored = HybridClock(Member.Timestamp(20000, 4)) { 100 }
        assertEquals(Member.Timestamp(20000, 5), floored.now())
    }

    private fun event(id: String, wall: Long, kind: Member.Kind = Member.Kind.TEXT, text: String = "x", age: Long = 0) =
        Member.Event(id, "0123456789abcdef0123456789abcdef", Member.Via.COPY, Member.Timestamp(wall, 0), age, kind, text)

    @Test
    fun aheadRefused() {
        val now = 1_792_886_400_000L // 2026-10-25
        val e = SyncEngine("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", HybridClock { now }) { 100_000L }
        val far = event("d0000000000000000000000000000000", Member.Timestamp.MAX_WALL)
        assertEquals(SyncEngine.Result(null, false), e.received(far))
        assertEquals(SyncEngine.Result(null, false), e.reconcile(Member.Hello(now, far)))
        val near = event("e0000000000000000000000000000000", now + 6 * 24 * 3600 * 1000L)
        assertEquals(SyncEngine.Result(near, true), e.received(near))
    }

    @Test
    fun engine() {
        var up = 100_000L
        val e = SyncEngine("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", HybridClock { 1000 }) { up }
        val a = event("a0000000000000000000000000000000", 2000, text = "first")
        assertEquals(SyncEngine.Result(a, true), e.received(a))
        assertEquals(SyncEngine.Result(null, false), e.received(a)) // seen
        // An older event is forwarded but does not become current.
        val old = event("b0000000000000000000000000000000", 1500, text = "older")
        assertEquals(SyncEngine.Result(old, false), e.received(old))
        assertEquals("first", e.usable?.first)
        // A local event is later than everything seen.
        val mine = e.local("from the phone", Member.Kind.TEXT, Member.Via.PHONE)
        assertTrue(mine.isLater(a))
        assertEquals("from the phone", e.usable?.first)
        // An invalid event changes nothing.
        assertEquals(SyncEngine.Result(null, false), e.received(event("short", 9999)))

        // A secret arrives first as a mark, then with its text.
        val secret = event("c0000000000000000000000000000000", 9000, Member.Kind.SECRET, "hunter2", 1000)
        assertTrue(e.reconcile(Member.Hello(0, secret.mark)).changed)
        assertNull(e.usable) // a mark has no text
        assertEquals("", e.hello(null).current?.text)
        assertEquals(SyncEngine.Result(secret, true), e.received(secret))
        assertEquals("hunter2", e.usable?.first)
        assertEquals("", e.hello("Pixel").current?.text, "a hello never carries a secret's text")
        up += 58_000 // 59 s after the copy, which was a second before it arrived
        assertNotNull(e.usable)
        up += 1000
        assertNull(e.usable)
        assertEquals(60_000L, e.currentEvent?.ageMS)

        assertFailsWith<SyncEngine.HelloException> {
            e.reconcile(Member.Hello(0, event("d0000000000000000000000000000000", 1, Member.Kind.SECRET, "leak")))
        }
        assertFailsWith<SyncEngine.HelloException> { e.reconcile(Member.Hello(0, event("bad", 1))) }
    }
}
