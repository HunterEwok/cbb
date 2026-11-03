// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb

import tools.cbb.kit.CredentialStore
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/** The phone at a blind relay: its settings, the link it starts, and whose each call is. */
class RelayOnPhoneTest {
    private val phone = "8".repeat(32)
    private val pc = "1".repeat(32)
    private val tv = "f".repeat(32)
    private val pin = "A".repeat(43) + "="

    private class FakeLink(val args: List<String>, val memberPort: Int, var shown: String) : RelayLink {
        @Volatile var closed = false
        /** The creds of each SetCredentials, "" back to the member certificate. */
        val credentials = mutableListOf<String>()
        override fun setRecords(records: String) {
            shown = records
        }
        override fun setCredentials(serverKey: ByteArray, sign: (ByteArray) -> ByteArray, creds: String, roots: String, names: String) {
            credentials.add(creds)
        }
        override fun close() {
            closed = true
        }
    }

    private class FakeLinks : RelayLinks {
        val started = mutableListOf<FakeLink>()
        override fun newKey(): ByteArray = ByteArray(32) { 1 }
        override fun start(
            private: ByteArray, device: String, endpoint: String, pin: String, chain: String,
            sign: (ByteArray) -> ByteArray, records: String, memberPort: Int, events: RelayLinkEvents,
        ): RelayLink = FakeLink(listOf(private[0].toString(), device, endpoint, pin), memberPort, records).also { started.add(it) }
    }

    private fun group() = HubOnPhone.Group(4242, listOf(byteArrayOf(1, 1, 1)), { it }, emptyList())

    private fun relay(links: FakeLinks, saved: MutableList<RelaySettings?>, near: Set<String> = emptySet(), initial: RelaySettings? = null) =
        RelayOnPhone(phone, links, { initial }, { saved.add(it) }, { _, _ -> error("no dial in this test") }, { _, _ -> }, { it in near })

    @Test
    fun settingsRoundTrip() {
        val s = RelaySettings(ByteArray(32) { 1 }, HubState.Forwarder("203.0.113.9:8764", pin))
        assertEquals(s, RelaySettings.decode(s.encode()))
        assertNull(RelaySettings.decode("{}".toByteArray()))
        assertNull(RelaySettings.decode(s.copy(relay = HubState.Forwarder("203.0.113.9:8764", "nope")).encode()))
    }

    @Test
    fun startsOnlyWhenOn() {
        val links = FakeLinks()
        val saved = mutableListOf<RelaySettings?>()
        val r = relay(links, saved)
        r.start(group())
        assertTrue("off: no link", links.started.isEmpty())
        assertEquals(RelayOnPhone.Status.OFF, r.status(false).first)
        assertThrows(IllegalArgumentException::class.java) { r.turnOn("203.0.113.9:8764", "short") }
        assertTrue(saved.isEmpty())

        r.turnOn("203.0.113.9:8764", pin)
        assertEquals(RelayOnPhone.Status.PAUSED, r.status(true).first)
        r.start(group())
        r.start(group())
        assertEquals("a running link is not started again", 1, links.started.size)
        val l = links.started[0]
        assertEquals(listOf("1", phone, "203.0.113.9:8764", pin), l.args)
        assertEquals(4242, l.memberPort)
        assertEquals(RelayOnPhone.Status.CONNECTING, r.status(false).first)

        // Another relay keeps the key and starts again.
        r.turnOn("198.51.100.7:8764", pin)
        assertTrue(l.closed)
        assertEquals(saved[0]!!.key.toList(), saved[1]!!.key.toList())
        r.start(group())
        assertEquals(2, links.started.size)

        r.turnOff()
        assertNull(saved.last())
        assertTrue(links.started[1].closed)
        assertEquals(RelayOnPhone.Status.OFF, r.status(false).first)
    }

    @Test
    fun reports() {
        val r = relay(FakeLinks(), mutableListOf(), initial = RelaySettings(ByteArray(32) { 1 }, HubState.Forwarder("203.0.113.9:8764", pin)))
        r.start(group())
        r.changed("""{"connected":true,"online":["$pc"],"through":1}""")
        val (st, rp, _) = r.status(false)
        assertEquals(RelayOnPhone.Status.CONNECTED, st)
        assertEquals(RelayOnPhone.Report(true, listOf(pc), 1), rp)
        r.changed("""{"connected":false,"online":[],"through":0,"error":"the relay refused: too many groups"}""")
        val (st2, _, why) = r.status(false)
        assertEquals(RelayOnPhone.Status.FAILED, st2)
        assertEquals("the relay refused: too many groups", why)
        r.changed("not json") // logged, the last report stays
        assertEquals(RelayOnPhone.Status.FAILED, r.status(false).first)
    }

    @Test
    fun credentialsGoToTheLinkOnce() {
        val links = FakeLinks()
        val r = relay(links, mutableListOf(), initial = RelaySettings(ByteArray(32) { 1 }, HubState.Forwarder("203.0.113.9:8764", pin)))
        val reg = CredentialStore.Registration(emptyList(), listOf(byteArrayOf(1)), mapOf("ab" to pc))
        r.setCredentials(RelayOnPhone.Credentials(byteArrayOf(2), { it }, reg))
        r.start(group())
        val l = links.started.single()
        assertEquals("kept for the link when it starts", listOf("[]"), l.credentials)
        r.setCredentials(RelayOnPhone.Credentials(byteArrayOf(2), { it }, reg))
        assertEquals("the same again: no new registration", 1, l.credentials.size)
        r.setCredentials(null)
        assertEquals(listOf("[]", ""), l.credentials)
        r.stop()
        r.start(group())
        assertTrue("back with the member certificate: nothing to hand over", links.started[1].credentials.isEmpty())
    }

    @Test
    fun callersAreTakenOnce() {
        val r = relay(FakeLinks(), mutableListOf(), near = setOf(pc))
        assertFalse("found at home: dialed directly", r.wanted(pc))
        assertTrue(r.wanted(tv))
        r.calling(pc, 50_001)
        r.calling(tv, 50_002)
        assertNull("a connection the relay did not announce", r.caller(50_003))
        assertEquals(tv, r.caller(50_002))
        assertNull("taken once", r.caller(50_002))
        assertEquals(pc, r.caller(50_001))
        // The oldest go when many never come.
        for (p in 0 until RelayOnPhone.MAX_CALLS + 5) r.calling(pc, 40_000 + p)
        assertNull(r.caller(40_000))
        assertEquals(pc, r.caller(40_000 + RelayOnPhone.MAX_CALLS + 4))
    }
}
