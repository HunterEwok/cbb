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

        // The clients go to cbbtun as JSON and come back from it.
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
        assertFalse(PhoneHub.clientsFromJson(hub.clientsJson).any { it.met }, "cbbtun gets no met")

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

    /**
     * A computer dials the phone's member listener with a tunnel key in its
     * hello and gets the hub's offer; the hub ignores an offer it gets.
     */
    @Test
    fun answersTheTunnelKeyOverTLS() {
        val caKey = SoftwareSigner()
        val ca = GroupCertificates.groupCA(caKey, now, pathLength = 1)
        fun member(): Triple<String, SoftwareSigner, ByteArray> {
            val id = SyncEngine.newID()
            val k = SoftwareSigner()
            return Triple(id, k, GroupCertificates.member(id, k.publicKeyDER, ca, caKey, now))
        }
        val (phoneID, phoneKey, phoneCert) = member()
        val (pcID, pcKey, pcCert) = member()
        val hub = PhoneHub(key(1))
        hub.endpoints = listOf("203.0.113.1:8764")
        val saved = LinkedBlockingQueue<List<PhoneHub.Client>>()
        val phone = MemberNode(
            SyncEngine(phoneID, HybridClock()), "Pixel",
            tunnelKey = { key(5) to key(6) },
            onTunnel = { _, _ -> error("the hub took an offer") },
            hub = { device, k, psk, _ -> hub.offers(device, k, psk, emptyList(), changed = { saved.add(it) }) },
            hubShare = { _, _ -> hub.share() },
        )
        val errors = LinkedBlockingQueue<Exception>()
        val listener = MemberListener(phone, phoneKey.keyPair.private, listOf(phoneCert), { listOf(ca) }, onError = { errors.add(it) })
        val offers = LinkedBlockingQueue<Pair<String?, Member.TunnelOffer>>()
        val shares = LinkedBlockingQueue<Member.HubShare>()
        val pc = MemberNode(
            SyncEngine(pcID, HybridClock()), "PC", role = Member.Role.FULL, tunnelKey = { key(2) to key(8) },
            onTunnel = { p, o -> offers.add(p to o) }, onHubs = { _, _, h -> shares.add(h) },
        )
        try {
            val t = TLSTransport.dial("127.0.0.1", listener.port, Member.ALPN, pcKey.keyPair.private, listOf(pcCert)) {
                runCatching { GroupCertificates.verifyMember(it, listOf(ca), now) }.getOrNull() == phoneID
            }
            val dialled = Background { pc.serve(t, phoneID) }
            val (from, offer) = assertNotNull(offers.poll(10, TimeUnit.SECONDS))
            assertEquals(phoneID, from)
            assertContentEquals(key(1), offer.hubKey)
            assertEquals(listOf("203.0.113.1:8764"), offer.endpoints)
            val client = assertNotNull(saved.poll(1, TimeUnit.SECONDS)).single()
            assertEquals(pcID, client.device)
            assertContentEquals(client.psk, offer.psk)
            assertContentEquals(key(8), offer.psk, "the client's own preshared key")
            val share = assertNotNull(shares.poll(10, TimeUnit.SECONDS))
            assertTrue(share.serving)
            assertEquals(listOf(pcID), share.clients.map { it.device })
            assertEquals(0, share.offer?.psk?.size)
            waitUntil { phone.connected == setOf(pcID) }
            pc.closeAll()
            dialled.join()
        } finally {
            listener.stop()
        }
        assertTrue(errors.isEmpty(), "the listener failed: ${errors.peek()}")
    }

    /** A peer whose certificate is not the group's gets no connection. */
    @Test
    fun refusesAStranger() {
        val caKey = SoftwareSigner()
        val ca = GroupCertificates.groupCA(caKey, now, pathLength = 1)
        val otherKey = SoftwareSigner()
        val other = GroupCertificates.groupCA(otherKey, now, pathLength = 1)
        val phoneKey = SoftwareSigner()
        val phoneID = SyncEngine.newID()
        val phoneCert = GroupCertificates.member(phoneID, phoneKey.publicKeyDER, ca, caKey, now)
        val strangerKey = SoftwareSigner()
        val strangerCert = GroupCertificates.member(SyncEngine.newID(), strangerKey.publicKeyDER, other, otherKey, now)
        val phone = MemberNode(SyncEngine(phoneID, HybridClock()), "Pixel")
        val listener = MemberListener(phone, phoneKey.keyPair.private, listOf(phoneCert), { listOf(ca) })
        try {
            assertFailsWith<java.io.IOException> {
                val t = TLSTransport.dial("127.0.0.1", listener.port, Member.ALPN, strangerKey.keyPair.private, listOf(strangerCert)) { true }
                // TLS 1.3 may finish on the client before the server refuses it.
                t.read(4)
            }
            assertEquals(0, phone.peers)
        } finally {
            listener.stop()
        }
    }

    /** A relay's call is served only when the certificate names the device the relay announced for its port. */
    @Test
    fun servesOnlyTheAnnouncedCaller() {
        val caKey = SoftwareSigner()
        val ca = GroupCertificates.groupCA(caKey, now, pathLength = 1)
        val phoneKey = SoftwareSigner()
        val phoneID = SyncEngine.newID()
        val phoneCert = GroupCertificates.member(phoneID, phoneKey.publicKeyDER, ca, caKey, now)
        val pcKey = SoftwareSigner()
        val pcID = SyncEngine.newID()
        val pcCert = GroupCertificates.member(pcID, pcKey.publicKeyDER, ca, caKey, now)
        val phone = MemberNode(SyncEngine(phoneID, HybridClock()), "Pixel")
        val errors = LinkedBlockingQueue<Exception>()
        val ports = LinkedBlockingQueue<Int>()
        val announced = AtomicReference<String?>(SyncEngine.newID())
        val listener = MemberListener(phone, phoneKey.keyPair.private, listOf(phoneCert), { listOf(ca) }, onError = { errors.add(it) },
            caller = { port -> ports.add(port); announced.get() })
        val pc = MemberNode(SyncEngine(pcID, HybridClock()), "PC", role = Member.Role.FULL)
        try {
            // Another device was announced: the connection closes.
            val t = TLSTransport.dial("127.0.0.1", listener.port, Member.ALPN, pcKey.keyPair.private, listOf(pcCert)) { true }
            assertFailsWith<java.io.IOException> { t.read(4) }
            assertIs<MemberListener.NotTheCaller>(assertNotNull(errors.poll(10, TimeUnit.SECONDS)))
            assertTrue(assertNotNull(ports.poll(1, TimeUnit.SECONDS)) > 0)
            assertEquals(0, phone.peers)

            announced.set(pcID)
            val t2 = TLSTransport.dial("127.0.0.1", listener.port, Member.ALPN, pcKey.keyPair.private, listOf(pcCert)) {
                runCatching { GroupCertificates.verifyMember(it, listOf(ca), now) }.getOrNull() == phoneID
            }
            val dialled = Background { pc.serve(t2, phoneID) }
            waitUntil { phone.connected == setOf(pcID) }
            pc.closeAll()
            dialled.join()
        } finally {
            listener.stop()
        }
    }
}
