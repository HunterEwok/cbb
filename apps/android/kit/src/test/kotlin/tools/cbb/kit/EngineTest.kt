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

    @Test
    fun nodesSync() {
        val (pa, pb) = Pipe.pair()
        val changes = Collections.synchronizedList(mutableListOf<String>())
        val a = MemberNode(SyncEngine("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", HybridClock()), "Pixel")
        val b = MemberNode(SyncEngine("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", HybridClock()), "pi", Member.Role.FULL, onChange = { changes.add(it.text) })
        a.send("before", Member.Kind.TEXT)
        val ta = Background { a.serve(pa) }
        val tb = Background { b.serve(pb) }
        // b gets a's current event from its hello, then a later event.
        waitUntil { "before" in changes }
        a.send("after", Member.Kind.TEXT)
        waitUntil { "after" in changes }
        assertEquals(1, b.peers)
        a.closeAll()
        ta.join()
        tb.join() // a goodbye ends it without an error
        assertEquals("after", b.usable?.first)
    }

    @Test
    fun noSecretsSendsTheMark() {
        // While the records stop secrets to a peer, it gets the mark of a
        // secret, never its text (docs/protocol.md, section 10, "Stopping the exchange").
        val noSecrets = object : RecordStore {
            override val digest: String? = null
            override val all: List<Member.Record> = emptyList()
            override fun add(records: List<Member.Record>): List<Member.Record> = emptyList()
            override fun noSecrets(device: String?): Boolean = true
        }
        val (pa, pb) = Pipe.pair()
        val changes = Collections.synchronizedList(mutableListOf<String>())
        val a = MemberNode(SyncEngine("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", HybridClock()), "Pixel", records = noSecrets)
        val b = MemberNode(SyncEngine("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", HybridClock()), "pi", Member.Role.FULL, onChange = { changes.add(it.text) })
        val ta = Background { a.serve(pa) }
        val tb = Background { b.serve(pb) }
        a.send("plain", Member.Kind.TEXT)
        waitUntil { "plain" in changes }
        a.send("hunter2", Member.Kind.SECRET)
        waitUntil { "" in changes }
        assertFalse("hunter2" in changes)
        a.closeAll()
        ta.join()
        tb.join()
    }

    @Test
    fun nodesExchangeRecords() {
        val rootKey = SoftwareSigner()
        val g = PhoneGroup.create(rootKey, SoftwareSigner().publicKeyDER, Instant.now())
        val pc = SyncEngine.newID()
        val cert = GroupCertificates.member(pc, SoftwareSigner().publicKeyDER, g.groupCA, rootKey, Instant.now())
        g.record(pc, "pi", "full", Records.keyHashOfCert(cert), rootKey, Instant.now())
        val phoneStore = Store(g.groupCA, g.records)
        val peerStore = Store(g.groupCA, RecordSet())
        val phone = MemberNode(SyncEngine(g.device, HybridClock()), "Pixel", records = phoneStore)
        val peer = MemberNode(SyncEngine(pc, HybridClock()), "pi", Member.Role.FULL, records = peerStore)
        val (a, b) = Pipe.pair()
        val ta = Background { phone.serve(a, pc) }
        val tb = Background { peer.serve(b) }
        // The hello's digest differs, so the phone sends its records.
        waitUntil { peerStore.digest == phoneStore.digest }
        // A revocation made later is sent at once.
        val r = synchronized(phoneStore) { g.revoke(pc, rootKey, Instant.now()) }
        phone.sendRecords(listOf(r))
        waitUntil { synchronized(peerStore) { peerStore.set.revoked.size == 1 } }
        assertEquals(setOf(pc), phone.connected)
        phone.close(pc)
        ta.join()
        tb.join()
    }

    @Test
    fun nodeRenewsAndSendsTheAdminCA() {
        val key = SoftwareSigner().publicKeyDER
        val ca = byteArrayOf(7, 7)
        val renewed = byteArrayOf(9)
        val phone = MemberNode(
            SyncEngine(SyncEngine.newID(), HybridClock()), "Pixel",
            renew = { MemberNode.Renewal(renewed) },
            adminCA = { if (it.contentEquals(key)) ca else null },
        )
        val pi = SyncEngine.newID()
        val (a, b) = Pipe.pair()
        a.peerChain = listOf(byteArrayOf(1))
        val task = Background { phone.serve(a, pi) }
        b.write(Member.encode(Member.Message.Hello(Member.Role.FULL, Member.Hello(0, adminKey = key))))
        val got = mutableListOf<Member.Message>()
        while (got.none { it is Member.Message.Admin }) got.add(Member.decode(b.read(Member.length(b.read(4)))))
        assertTrue(Member.Message.Cert(renewed) in got)
        assertEquals(Member.Message.Admin(ca), got.last(), "the root sends the admin CA it issued for the offered key")
        assertTrue(phone.offeredAdminKeys.getValue(pi).contentEquals(key))
        phone.sendAdminCA(byteArrayOf(8), pi)
        var m: Member.Message
        do m = Member.decode(b.read(Member.length(b.read(4)))) while (m !is Member.Message.Admin)
        assertEquals(Member.Message.Admin(byteArrayOf(8)), m)
        phone.closeAll()
        task.join()
        assertIs<Member.Message.Hello>(got.first())
    }

    @Test
    fun nodeOffersTheTunnelKeyAndKeepsTheOffer() {
        val key = ByteArray(32) { 1 }
        val offers = LinkedBlockingQueue<Pair<String?, Member.TunnelOffer>>()
        val phone = MemberNode(
            SyncEngine(SyncEngine.newID(), HybridClock()), "Pixel",
            tunnelKey = { key to ByteArray(32) { 4 } },
            onTunnel = { from, o -> offers.put(from to o) },
        )
        val hub = SyncEngine.newID()
        val (a, b) = Pipe.pair()
        val task = Background { phone.serve(a, hub) }
        val hello = assertIs<Member.Message.Hello>(Member.decode(b.read(Member.length(b.read(4)))))
        assertContentEquals(key, hello.hello.tunnelKey)
        assertContentEquals(ByteArray(32) { 4 }, hello.hello.tunnelPSK)
        b.write(Member.encode(Member.Message.Hello(Member.Role.FULL, Member.Hello(0))))
        // A bad offer is dropped; a good one reaches onTunnel.
        b.write(Member.encode(Member.Message.Tunnel(Member.TunnelOffer(ByteArray(31), ByteArray(32)))))
        b.write(Member.encode(Member.Message.Tunnel(null)))
        // With the hub's key for the next period, which reaches onTunnel too.
        val good = Member.TunnelOffer(ByteArray(32) { 2 }, ByteArray(32) { 3 }, listOf("192.0.2.1:8764"), nextKey = ByteArray(32) { 4 })
        b.write(Member.encode(Member.Message.Tunnel(good)))
        val (from, got) = assertNotNull(offers.poll(10, TimeUnit.SECONDS))
        assertEquals(hub, from)
        assertEquals(good, got)
        phone.closeAll()
        task.join()
        assertTrue(offers.isEmpty())
    }

    /** The node sends the credentials it keeps after the hello, and takes those a peer sends. */
    @Test
    fun nodeSendsAndTakesCredentials() {
        val signer = SoftwareSigner()
        fun cred(v: Long) = ServerCredentials.sign(
            ServerCredentials.Body(type = ServerCredentials.HUBS, group = "0123456789abcdef", version = v, expiresMS = 1, hubs = ServerCredentials.pad(emptyList())),
            signer,
        )
        val kept = cred(1)
        val took = LinkedBlockingQueue<List<ServerCredentials.Credential>>()
        val keeper = object : CredentialKeeper {
            override val all = listOf(kept)
            override fun add(credentials: List<ServerCredentials.Credential>) = credentials.also { took.put(it) }
        }
        val phone = MemberNode(SyncEngine(SyncEngine.newID(), HybridClock()), "Pixel", credentials = keeper)
        val (a, b) = Pipe.pair()
        val task = Background { phone.serve(a, SyncEngine.newID()) }
        assertIs<Member.Message.Hello>(Member.decode(b.read(Member.length(b.read(4)))))
        b.write(Member.encode(Member.Message.Hello(Member.Role.FULL, Member.Hello(0))))
        var m: Member.Message
        do m = Member.decode(b.read(Member.length(b.read(4)))) while (m !is Member.Message.Credentials)
        assertEquals(listOf(kept), m.credentials)
        val sent = cred(2)
        b.write(Member.encode(Member.Message.Credentials(listOf(sent))))
        assertEquals(listOf(sent), took.poll(10, TimeUnit.SECONDS))
        phone.closeAll()
        task.join()
    }

    /** A RecordStore over a RecordSet. */
    class Store(private val groupCA: ByteArray, val set: RecordSet) : RecordStore {
        override val digest: String? get() = synchronized(this) { set.digest }
        override val all: List<Member.Record> get() = synchronized(this) { set.records.toList() }
        override fun add(records: List<Member.Record>): List<Member.Record> = synchronized(this) { records.filter { set.add(it, groupCA) } }
    }
}
