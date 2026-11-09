// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import java.io.File
import java.time.Instant
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import kotlin.io.path.createTempDirectory
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.fail

/** The phone's member in the Rust core through the kit's wrapper (CoreMember), against the host's library. */
class CoreMemberTest {
    private val now = Instant.now()
    private val dirs = mutableListOf<File>()
    private val members = mutableListOf<CoreMember>()

    /** The secret for sealed messages: the core keeps the first member's for the process. */
    private val seal = ByteArray(32) { 9 }

    @AfterTest
    fun stop() {
        members.forEach { it.close() }
        dirs.forEach { it.deleteRecursively() }
    }

    private fun start(device: String, key: SoftwareSigner, cert: ByteArray, ca: ByteArray, events: (CoreMember.Event) -> Unit = {}): CoreMember {
        val dir = createTempDirectory("cbb-member").toFile().also { dirs += it }
        return CoreMember.start(
            CoreMember.Start(dir, "Pixel", "android", "17", "0.6.0", device = device, publicKey = key.publicKeyDER, seal = seal, cert = cert, groupCA = ca),
            key::signDigest,
            events = events,
        ).also { members += it }
    }

    @Test
    fun startsAnswersAndStops() {
        val root = SoftwareSigner()
        val key = SoftwareSigner()
        val g = PhoneGroup.create(root, key.publicKeyDER, now, seal = Core.sealPublic(seal))
        val m = start(g.device, key, g.memberCert, g.groupCA)
        assertNull(m.current())
        assertNull(m.waiting())
        assertTrue(m.peers().isEmpty())
        m.addRecords(g.records.records)
        assertEquals(g.records.records.size, m.records().size)
        assertTrue(m.sends("on the phone"), "a clipboard nothing sent yet goes out")
        assertFailsWith<Core.Refusal> { m.setSync(true, forMS = 1_000) }
        assertFailsWith<Core.Refusal> { m.fetch("nothing", 1 shl 20, File(dirs[0], "out")) }
        m.copy("from the phone")
        assertEquals("from the phone", m.current()?.text)
        assertTrue(!m.sends("from the phone"), "what the phone sent does not go again")
        m.close()
        assertFailsWith<IllegalStateException> { m.current() }
    }

    /** A lone phone says why it does not sync: sync off first, then no other device; the app's own tunnel adds its reasons. */
    @Test
    fun saysWhyItDoesNotSync() {
        val root = SoftwareSigner()
        val key = SoftwareSigner()
        val g = PhoneGroup.create(root, key.publicKeyDER, now, seal = Core.sealPublic(seal))
        val m = start(g.device, key, g.memberCert, g.groupCA)
        m.addRecords(g.records.records)
        assertEquals(listOf("only_device"), m.why().map { it.code })
        m.setSync(false)
        assertEquals(listOf("sync_off", "only_device"), m.why().map { it.code })
        assertEquals(listOf("sync_off", "only_device"), m.view().warnings.map { it.code }, "the view carries the same reasons")
        m.setSync(true)
        val away = WhyAway(hub = true, forwarder = true, error = "no answer")
        val r = m.why(away)
        assertEquals("no answer", r.first { it.code == "forwarder_down" }.detail)
        assertTrue(m.view(away = away).warnings.any { it.code == "forwarder_down" })
        m.close()
    }

    /** The member keeps the tiles' order: a change shows in its view, and one that does not fit throws and changes nothing. */
    @Test
    fun keepsTheTilesOrder() {
        val root = SoftwareSigner()
        val keyA = SoftwareSigner()
        val g = PhoneGroup.create(root, keyA.publicKeyDER, now, seal = Core.sealPublic(seal))
        val keyB = SoftwareSigner()
        val idB = SyncEngine.newID()
        g.record(idB, "Phone two", "phone", Records.keyHash(keyB.publicKeyDER), root, now, os = "android", store = Records.HARDWARE, seal = Core.sealPublic(seal))
        val m = start(g.device, keyA, g.memberCert, g.groupCA)
        m.addRecords(g.records.records)
        val v = m.view()
        assertTrue(!v.custom)
        assertEquals(listOf(Arrangement.Item.Device(g.device), Arrangement.Item.Device(idB)), v.tiles)
        val after = m.view(Arrangement.Op.New("Desk", listOf(idB)))
        assertTrue(after.custom)
        val desk = after.tiles.last() as Arrangement.Item.Collection
        assertEquals(listOf(idB), desk.devices)
        assertFailsWith<Core.Refusal> { m.view(Arrangement.Op.Rename(desk.id, "x".repeat(65))) }
        m.view(Arrangement.Op.Move(Arrangement.Ref.Collection(desk.id), Arrangement.Ref.Device(g.device)))
        assertEquals(desk.id, (m.view().tiles.first() as Arrangement.Item.Collection).id)
    }

    @Test
    fun refusesAnIdentityThatDoesNotCheck() {
        val root = SoftwareSigner()
        val key = SoftwareSigner()
        val g = PhoneGroup.create(root, key.publicKeyDER, now)
        assertFailsWith<Core.Refusal> { start(g.device, SoftwareSigner(), g.memberCert, g.groupCA) }
    }

    @Test
    fun twoPhonesSyncAndAnswerCommands() {
        val root = SoftwareSigner()
        val keyA = SoftwareSigner()
        val g = PhoneGroup.create(root, keyA.publicKeyDER, now, seal = Core.sealPublic(seal))
        val keyB = SoftwareSigner()
        val idB = SyncEngine.newID()
        val certB = GroupCertificates.member(idB, keyB.publicKeyDER, g.groupCA, root, now)
        g.record(idB, "Phone two", "phone", Records.keyHash(keyB.publicKeyDER), root, now, os = "android", store = Records.HARDWARE, seal = Core.sealPublic(seal))

        val eventsA = LinkedBlockingQueue<CoreMember.Event>()
        val eventsB = LinkedBlockingQueue<CoreMember.Event>()
        val a = start(g.device, keyA, g.memberCert, g.groupCA) { eventsA.add(it) }
        val b = start(idB, keyB, certB, g.groupCA) { eventsB.add(it) }
        a.addRecords(g.records.records)
        b.addRecords(g.records.records)
        val port = a.listen(port = 0)
        b.found("a", listOf("127.0.0.1:$port"), g.device)

        val peer = next<CoreMember.Event.PeerConnected>(eventsA).peer
        assertEquals(idB, peer.device)
        assertTrue(peer.chain.isNotEmpty(), "the peer comes with its chain")
        waitUntil { a.peers().size == 1 && b.peers().size == 1 }

        b.copy("hello from two")
        val got = next<CoreMember.Event.CopyChanged>(eventsA) { it.copy.text == "hello from two" }.copy
        assertEquals(idB, got.origin)
        assertEquals(got.id, a.waiting()?.id)
        a.took(got.id)
        assertNull(a.waiting())

        // A command for the phone itself other than a mute goes to its app,
        // whose answer goes back.
        val mode = g.modeCommand(idB, "receive", root, Instant.now())
        var answered: Throwable? = null
        val answering = Thread {
            try {
                val c = next<CoreMember.Event.Command>(eventsB)
                assertEquals(Commands.idOf(mode), Commands.idOf(c.command))
                b.answer(c.token, Member.CommandResult("", "done"))
            } catch (e: Throwable) {
                answered = e
            }
        }.apply { start() }
        val r = a.command(mode, 10_000)
        answering.join()
        answered?.let { throw it }
        assertTrue(r.done, "the command's result: ${r.status} ${r.reason}")
        assertEquals(Commands.idOf(mode), r.id)

        // A mute the node carries out itself and tells the app.
        val mute = g.muteCommand(idB, 60_000, root, Instant.now())
        val muted = a.command(mute, 10_000)
        assertTrue(muted.done, "the mute's result: ${muted.status} ${muted.reason}")
        val m = next<CoreMember.Event.Mute>(eventsB)
        assertTrue(m.muted)
        assertEquals(g.device, m.by)
        assertTrue(eventsB.none { it is CoreMember.Event.Command && Commands.idOf(it.command) == Commands.idOf(mute) }, "the app got the mute")

        b.setTunnelKey(ByteArray(32) { 1 } to ByteArray(32) { 2 })
        assertFailsWith<Core.Refusal> { b.setTunnelKey(ByteArray(3) to ByteArray(32)) }
        b.setTunnelKey(null)
        b.lost("a")
    }

    @Test
    fun relayServesOnlyTheAnnouncedCaller() {
        val root = SoftwareSigner()
        val keyA = SoftwareSigner()
        val g = PhoneGroup.create(root, keyA.publicKeyDER, now, seal = Core.sealPublic(seal))
        val keyB = SoftwareSigner()
        val idB = SyncEngine.newID()
        val certB = GroupCertificates.member(idB, keyB.publicKeyDER, g.groupCA, root, now)
        g.record(idB, "Phone two", "phone", Records.keyHash(keyB.publicKeyDER), root, now, os = "android", store = Records.HARDWARE, seal = Core.sealPublic(seal))
        val eventsB = LinkedBlockingQueue<CoreMember.Event>()
        val a = start(g.device, keyA, g.memberCert, g.groupCA)
        val b = start(idB, keyB, certB, g.groupCA) { eventsB.add(it) }
        a.addRecords(g.records.records)
        b.addRecords(g.records.records)
        val port = b.listen(CoreMember.Listen.RELAY)
        assertEquals(port, b.listen(CoreMember.Listen.RELAY), "a port already open stays")
        a.found("relay", listOf("127.0.0.1:$port"), idB)
        // A call the relay announced from another device is closed; the next, named right, is served.
        val first = next<CoreMember.Event.Caller>(eventsB)
        assertEquals(g.device, first.device)
        b.caller(first.token, SyncEngine.newID())
        val second = next<CoreMember.Event.Caller>(eventsB) { it.token != first.token }
        assertTrue(b.peers().isEmpty(), "a call the relay did not announce from that device was served")
        b.caller(second.token, g.device)
        waitUntil { b.peers().map { it.device } == listOf(g.device) }
        b.unlisten(CoreMember.Listen.RELAY)
    }

    /**
     * Calls from other threads while the member stops answer or fail, and never reach freed memory: an event's handler that
     * called the member as the app restarted it crashed the Android app.
     */
    @Test
    fun stopsWhileCalled() {
        val root = SoftwareSigner()
        val key = SoftwareSigner()
        val g = PhoneGroup.create(root, key.publicKeyDER, now, seal = Core.sealPublic(seal))
        val m = start(g.device, key, g.memberCert, g.groupCA)
        val calls = java.util.concurrent.atomic.AtomicInteger()
        val callers = List(4) {
            Thread {
                repeat(2_000) {
                    runCatching { m.current(); m.peers() }
                    calls.incrementAndGet()
                }
            }.apply { start() }
        }
        Thread.sleep(20)
        m.close()
        callers.forEach { it.join() }
        assertEquals(8_000, calls.get())
        assertFailsWith<IllegalStateException> { m.current() }
    }

    private inline fun <reified T : CoreMember.Event> next(q: LinkedBlockingQueue<CoreMember.Event>, crossinline ok: (T) -> Boolean = { true }): T {
        val deadline = System.nanoTime() + 15_000_000_000L
        while (true) {
            val e = q.poll(maxOf(0, deadline - System.nanoTime()), TimeUnit.NANOSECONDS) ?: fail("no ${T::class.simpleName} within 15 s")
            if (e is T && ok(e)) return assertNotNull(e)
        }
    }
}
