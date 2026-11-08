// SPDX-License-Identifier: AGPL-3.0-only

package tools.cbb.kit

import kotlinx.serialization.json.JsonArray
import java.time.Instant
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The phone as the group's hub: admitting clients by their tunnel keys, and the offers over member TLS. */
class PhoneHubTest {
    /** The phone as the hub answers a client's tunnel key, as its hello offers it, with its own offer under the client's preshared key. */
    @Test
    fun answersTheTunnelKeyOverTLS() = CoreGroup().use { t ->
        val (phone, client) = t.phones
        val hub = PhoneHub(key(1))
        hub.endpoints = listOf("203.0.113.1:8764")
        client.member.setTunnelKey(key(2) to key(7))
        t.connect(1, 0)
        val p = phone.peer(client.device)
        for (o in hub.offers(p.device, p.tunnelKey!!, p.tunnelPSK, emptyList())) phone.member.sendTunnel(p.device, o)
        val offer = client.next("the hub's offer") { (it as? CoreMember.Event.Tunnel)?.offer }
        assertTrue(offer.psk.contentEquals(key(7)), "the client's own preshared key")
        assertTrue(offer.hubKey.contentEquals(key(1)))
        assertEquals(listOf("203.0.113.1:8764"), offer.endpoints)
        assertEquals(listOf(client.device), hub.clients.map { it.device })
    }

    /** A device of another group does not get through the hub's port. */
    @Test
    fun refusesAStranger() = CoreGroup().use { t ->
        CoreGroup().use { other ->
            val hub = t.root
            val port = hub.member.listen(CoreMember.Listen.HOME)
            other.phones[1].member.found("stranger", listOf("127.0.0.1:$port"), hub.device)
            Thread.sleep(2_000)
            assertTrue(hub.member.peers().isEmpty(), "a device of another group got in")
            assertTrue(other.phones[1].member.peers().isEmpty())
        }
    }

    /** The relay's port serves a call only when the app names its caller and its certificate names the same device. */
    @Test
    fun servesOnlyTheAnnouncedCaller() = CoreGroup().use { t ->
        val (a, b) = t.phones
        val port = b.member.listen(CoreMember.Listen.RELAY)
        a.member.found("relay", listOf("127.0.0.1:$port"), b.device)
        val first = b.next("the first call") { it as? CoreMember.Event.Caller }
        assertEquals(a.device, first.device)
        b.member.caller(first.token, SyncEngine.newID())
        val second = b.next("the second call") { (it as? CoreMember.Event.Caller)?.takeIf { c -> c.token != first.token } }
        assertTrue(b.member.peers().isEmpty(), "a call named wrong was served")
        b.member.caller(second.token, a.device)
        b.until("the announced caller connected") { b.connected() == setOf(a.device) }
    }

    private val now = Instant.now()

    private fun key(b: Int) = ByteArray(32) { b.toByte() }

    @Test
    fun admitsAsAComputersHub() {
        val hub = PhoneHub(key(1))
        val a = SyncEngine.newID()
        val b = SyncEngine.newID()
        val (first, changed) = hub.admit(a, key(2))
        assertTrue(changed)
        assertEquals(32, first.psk.size)

        // The same key keeps its preshared key; a new key gets a new one.
        val (same, unchanged) = hub.admit(a, key(2))
        assertFalse(unchanged)
        assertContentEquals(first.psk, same.psk)
        val (renewed, _) = hub.admit(a, key(3))
        assertFalse(renewed.psk.contentEquals(first.psk))
        assertEquals(1, hub.clients.size)

        // Another device's key, the hub's own, no key, and a bad device are refused.
        assertFailsWith<PhoneHub.Refused> { hub.admit(b, key(3)) }
        assertFailsWith<PhoneHub.Refused> { hub.admit(b, key(1)) }
        assertFailsWith<PhoneHub.Refused> { hub.admit(b, key(0)) }
        assertFailsWith<PhoneHub.Refused> { hub.admit(b, ByteArray(31)) }
        assertFailsWith<PhoneHub.Refused> { hub.admit("B", key(4)) }

        // The clients go to the tunnel as JSON and come back from it.
        hub.admit(b, key(4))
        val back = PhoneHub.clientsFromJson(hub.clientsJson)
        assertEquals(listOf(a, b), back.map { it.device })
        assertContentEquals(hub.clients[1].psk, back[1].psk)
        assertTrue(PhoneHub.clientsFromJson("").isEmpty())
        assertFailsWith<IllegalArgumentException> { PhoneHub.clientsFromJson("{}") }
        assertFailsWith<IllegalArgumentException> { PhoneHub.clientsFromJson("""[{"device":"x"}]""") }

        assertEquals(listOf(a), hub.prune { it.device != a })
        assertEquals(listOf(b), hub.clients.map { it.device })
    }

    /** The client's own preshared key, the clients other hubs share, and their offers passed on (section 11, "Several hubs"). */
    @Test
    fun sharesWithTheOtherHubs() {
        val hub = PhoneHub(key(1))
        hub.endpoints = listOf("203.0.113.1:8764")
        val a = SyncEngine.newID()
        val b = SyncEngine.newID()
        val other = SyncEngine.newID()

        // A client's own preshared key; an older one's stays when it offers none.
        val (c, _) = hub.admit(a, key(2), key(3))
        assertContentEquals(key(3), c.psk)
        assertFalse(hub.admit(a, key(2)).second)
        assertTrue(hub.admit(a, key(2), key(4)).second)
        assertContentEquals(key(4), hub.clients.single().psk)

        // A shared client is taken, and takes new keys, but one met here stays.
        assertTrue(hub.take(PhoneHub.Client(b, key(5), key(6))))
        assertFalse(hub.take(PhoneHub.Client(b, key(5), key(6))))
        assertTrue(hub.take(PhoneHub.Client(b, key(7), key(6))))
        assertFalse(hub.take(PhoneHub.Client(a, key(9), key(9))))
        assertFailsWith<PhoneHub.Refused> { hub.take(PhoneHub.Client(other, key(7), key(6))) }
        assertFailsWith<PhoneHub.Refused> { hub.take(PhoneHub.Client(other, key(1), key(6))) }
        assertTrue(hub.admit(b, key(7), key(6)).second, "met now")
        assertTrue(hub.clients.all { it.met })
        assertEquals(hub.clients.map { it.met }, PhoneHub.clientsFromJson(JsonArray(hub.clients.map { it.toJson(keep = true) }).toString()).map { it.met })
        assertFalse(PhoneHub.clientsFromJson(hub.clientsJson).any { it.met }, "the tunnel gets no met")

        // Another hub's offer goes to the clients with their own preshared keys.
        hub.setOther(other, Member.TunnelOffer(key(10), ByteArray(0), listOf("198.51.100.1:8764")))
        val offers = hub.offers(hub.clients.first { it.device == a })
        assertEquals(2, offers.size)
        assertNull(offers[0].hub)
        assertEquals(other, offers[1].hub)
        assertContentEquals(key(4), offers[1].psk)
        assertTrue(offers.all { it.isValid })
        hub.setOther(other, null)
        assertEquals(1, hub.offers(hub.clients.first()).size)

        // What it shares goes through a frame and back.
        val share = assertNotNull(hub.share())
        val e = Member.encode(Member.Message.Hubs(share))
        assertEquals(Member.Message.Hubs(share), Member.decode(e.copyOfRange(4, e.size)))
        val go = """{"t":"hubs","hubs":{"serving":true,"offer":{"hub_key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","psk":null},""" +
            """"clients":[{"device":"$a","key":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=","psk":"AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM="}]}}"""
        val got = (Member.decode(go.toByteArray()) as Member.Message.Hubs).share
        assertTrue(got.serving)
        assertContentEquals(key(3), got.clients.single().psk)
    }

    @Test
    fun keepsAtMost256Clients() {
        val hub = PhoneHub(key(1))
        repeat(PhoneHub.MAX_CLIENTS) { i -> hub.admit(SyncEngine.newID(), key(7).also { it[0] = i.toByte(); it[1] = (i shr 8).toByte() }) }
        assertFailsWith<PhoneHub.Refused> { hub.admit(SyncEngine.newID(), key(9)) }
    }

    @Test
    fun offersWaitForVLESS() {
        val hub = PhoneHub(key(1))
        hub.endpoints = listOf("203.0.113.1:8764")
        val c = hub.admit(SyncEngine.newID(), key(2)).first
        val o = assertNotNull(hub.offer(c))
        assertTrue(o.isValid)
        assertEquals(listOf("203.0.113.1:8764"), o.endpoints)
        hub.vlessOnly = true
        assertNull(hub.offer(c))
        hub.vless = """{"endpoint":"203.0.113.1:443"}"""
        assertEquals(hub.vless, hub.offer(c)?.vless)
    }

}
