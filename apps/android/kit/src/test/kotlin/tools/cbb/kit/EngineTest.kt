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
    /** b gets a's current copy from its hello, then a later one, through the members in the Rust core. */
    @Test
    fun nodesSync() = CoreGroup().use { t ->
        val (a, b) = t.phones
        a.member.copy("before")
        t.connect(1, 0)
        b.copy("before")
        a.member.copy("after")
        b.copy("after")
        assertEquals(listOf(a.device), b.member.peers().map { it.device })
        assertEquals("after", b.member.current()?.text)
    }

    /** Records the root's key signs go to the connected peers at once, and a peer's app reads them from its member. */
    @Test
    fun nodesExchangeRecords() = CoreGroup().use { t ->
        val (phone, peer) = t.phones
        t.connect(1, 0)
        val r = t.g.rename(peer.device, "Kitchen phone", t.ca, java.time.Instant.now())
        phone.member.addRecords(listOf(r))
        peer.until("the new record") { peer.member.records().any { it.body.contentEquals(r.body) } }
        assertEquals(listOf(peer.device), phone.member.peers().map { it.device })
    }

    /** An admin phone renews a peer's certificate from the chain its hello carries and sends a device its admin CA; the peer's app gets both. */
    @Test
    fun nodeRenewsAndSendsTheAdminCA() = CoreGroup().use { t ->
        val (phone, peer) = t.phones
        t.connect(1, 0)
        val p = phone.peer(peer.device)
        assertTrue(p.chain.first().contentEquals(peer.cert), "the hello event carries the peer's chain")
        // A certificate for the same key, as a renewal issues it once one is due.
        val renewed = GroupCertificates.member(peer.device, peer.key.publicKeyDER, t.g.groupCA, t.ca, java.time.Instant.now().plusSeconds(3600))
        assertTrue(phone.member.sendCert(peer.device, renewed, null))
        peer.next("the renewed certificate") { (it as? CoreMember.Event.Identity)?.takeIf { e -> e.cert.contentEquals(renewed) } }
        assertTrue(phone.member.sendAdminCA(peer.device, byteArrayOf(7, 7)))
        val admin = peer.next("the admin CA") { (it as? CoreMember.Event.Message)?.message as? Member.Message.Admin }
        assertTrue(admin.adminCA.contentEquals(byteArrayOf(7, 7)))
    }

    /** The phone's hello offers the tunnel key the app set, and the root's offer for it reaches the app; one turned off is offered no more. */
    @Test
    fun nodeOffersTheTunnelKeyAndKeepsTheOffer() = CoreGroup().use { t ->
        val (hub, phone) = t.phones
        val key = ByteArray(32) { 1 }
        val psk = ByteArray(32) { 4 }
        phone.member.setTunnelKey(key to psk)
        t.connect(1, 0)
        val p = hub.peer(phone.device)
        assertTrue(p.tunnelKey!!.contentEquals(key))
        assertTrue(p.tunnelPSK!!.contentEquals(psk))
        val good = Member.TunnelOffer(ByteArray(32) { 2 }, ByteArray(32) { 3 }, listOf("192.0.2.1:8764"))
        assertTrue(hub.member.sendTunnel(phone.device, good))
        val got = phone.next("the offer") { it as? CoreMember.Event.Tunnel }
        assertEquals(hub.device, got.from)
        assertTrue(got.offer.hubKey.contentEquals(good.hubKey))
        assertEquals(good.endpoints, got.offer.endpoints)
        phone.member.setTunnelKey(null)
        phone.member.disconnect(hub.device)
        hub.until("a hello without the key") { hub.member.peers().any { it.device == phone.device && it.tunnelKey == null } }
    }

    /** The credentials go to the one peer named, and the ones a peer sends reach the app, which passes new ones on to the others. */
    @Test
    fun nodeSendsAndTakesCredentials() = CoreGroup(3).use { t ->
        val (root, b, c) = t.phones
        t.connect(1, 0)
        t.connect(2, 0)
        val signer = SoftwareSigner()
        fun cred(v: Long) = ServerCredentials.sign(
            ServerCredentials.Body(type = ServerCredentials.HUBS, group = "0123456789abcdef", version = v, expiresMS = 1, hubs = ServerCredentials.pad(emptyList())),
            signer,
        )
        val kept = cred(1)
        assertEquals(listOf(b.device), root.member.sendCredentials(listOf(kept), to = b.device))
        val got = b.next("the credentials") { ((it as? CoreMember.Event.Message)?.message as? Member.Message.Credentials)?.credentials }
        assertEquals(listOf(kept), got)
        // New ones go to every other member, not back to the one that sent them.
        assertEquals(listOf(c.device), root.member.sendCredentials(listOf(cred(2)), except = b.device))
        c.next("the new credentials") { ((it as? CoreMember.Event.Message)?.message as? Member.Message.Credentials)?.credentials }
        assertEquals(1, b.all { (it as? CoreMember.Event.Message)?.message as? Member.Message.Credentials }.size)
    }

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
