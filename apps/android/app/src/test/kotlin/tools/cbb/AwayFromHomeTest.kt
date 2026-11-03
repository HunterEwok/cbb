// SPDX-License-Identifier: AGPL-3.0-only

package tools.cbb

import tools.cbb.kit.FrameTransport
import tools.cbb.kit.Member
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

class AwayFromHomeTest {
    private val hub = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    private val offer = Member.TunnelOffer(ByteArray(32) { 2 }, ByteArray(32) { 3 }, listOf("203.0.113.7:8764", "[2001:db8::7]:8764"))

    @Test
    fun stateRoundTrips() {
        val key = ByteArray(32) { 1 }
        val off = AwayState.decode(AwayState(key).encode())
        assertNotNull(off)
        assertArrayEquals(key, off!!.key)
        assertEquals(32, off.psk.size)
        assertTrue(off.hubs.isEmpty())

        val pc = "dddddddddddddddddddddddddddddddd"
        val both = AwayState(key).withOffer(hub, offer).withOffer(pc, offer)
        val on = AwayState.decode(both.encode())
        assertNotNull(on)
        assertArrayEquals(both.psk, on!!.psk)
        assertEquals(listOf(hub, pc), on.hubs.map { it.first })
        assertEquals(offer, on.offer(hub))
        assertEquals(listOf(pc), on.without(hub).hubs.map { it.first })

        // An obfuscated hub's settings are kept as they came.
        val hidden = Member.TunnelOffer(offer.hubKey, offer.psk, offer.endpoints, """{"jc":4,"s1":20}""")
        assertEquals(hidden, AwayState.decode(AwayState(key).withOffer(hub, hidden).encode())!!.offer(hub))
        // So is the way over VLESS.
        val tunneled = Member.TunnelOffer(offer.hubKey, offer.psk, offer.endpoints, null, """{"endpoint":"203.0.113.9:443"}""")
        assertEquals(tunneled, AwayState.decode(AwayState(key).withOffer(hub, tunneled).encode())!!.offer(hub))
        // And the hub's key for the next period, which the phone tries right after its key now.
        val next = Member.TunnelOffer(offer.hubKey, offer.psk, offer.endpoints, nextKey = ByteArray(32) { 7 })
        val withNext = AwayState(key).withOffer(hub, next)
        assertEquals(next, AwayState.decode(withNext.encode())!!.offer(hub))
        val tried = AwayFromHome.hubsToTry(listOf(hub), withNext)
        assertEquals(listOf(hub, hub), tried.map { it.first })
        assertArrayEquals(ByteArray(32) { 7 }, tried[1].second.hubKey)
        assertNull(tried[1].second.nextKey)

        // Another version, a cut file, a longer one and a bad offer are not states.
        val b = both.encode()
        assertNull(AwayState.decode(byteArrayOf(9) + b.copyOfRange(1, b.size)))
        assertNull(AwayState.decode(b.copyOf(b.size - 3)))
        assertNull(AwayState.decode(b + 0))
        assertNull(AwayState.decode(AwayState(key).withOffer(hub, Member.TunnelOffer(ByteArray(31), ByteArray(32))).encode()))
    }

    /** The state of version 3, one hub's offer and no preshared key of the phone's own, is not read. */
    @Test
    fun readsTheOneHubOfVersion3() {
        val out = java.io.ByteArrayOutputStream()
        java.io.DataOutputStream(out).run {
            writeByte(3)
            write(ByteArray(32) { 1 })
            writeBoolean(true)
            writeUTF(hub)
            write(offer.hubKey)
            write(offer.psk)
            writeByte(offer.endpoints.size)
            offer.endpoints.forEach { writeUTF(it) }
            writeUTF("")
            writeUTF("")
        }
        assertNull(AwayState.decode(out.toByteArray()))
    }

    private class FakeTunnel(
        override val port: Int,
        val endpoint: String,
        val obfuscation: String = "",
        val vless: String = "",
        val hubKey: ByteArray = ByteArray(0),
    ) : OpenTunnel {
        val endpoints = CopyOnWriteArrayList(listOf(endpoint))
        @Volatile var closed = false
        override fun setEndpoint(endpoint: String) {
            endpoints.add(endpoint)
        }
        override fun close() {
            closed = true
        }
    }

    private class FakeTunnels : Tunnels {
        val started = LinkedBlockingQueue<FakeTunnel>()
        val all = CopyOnWriteArrayList<FakeTunnel>()
        override fun newKey() = ByteArray(32) { 7 }
        override fun publicKey(private: ByteArray) = private.map { (it + 1).toByte() }.toByteArray()
        override fun start(
            private: ByteArray,
            psk: ByteArray,
            hubKey: ByteArray,
            device: String,
            hub: String,
            endpoint: String,
            obfuscation: String,
            vless: String,
        ): OpenTunnel = FakeTunnel(40_000 + all.size, endpoint, obfuscation, vless, hubKey).also {
            all.add(it)
            started.add(it)
        }
    }

    private object NoTransport : FrameTransport {
        override fun write(data: ByteArray) = Unit
        override fun read(n: Int): ByteArray = throw IOException("closed")
        override fun close() = Unit
    }

    private fun eventually(what: String, check: () -> Boolean) {
        val deadline = System.currentTimeMillis() + 5_000
        while (!check()) {
            if (System.currentTimeMillis() > deadline) throw AssertionError(what)
            Thread.sleep(5)
        }
    }

    @Test
    fun reachesTheHubOnlyWhileItIsAway() {
        val tunnels = FakeTunnels()
        val saved = AtomicReference<AwayState?>(null)
        val home = AtomicBoolean(false)
        val answers = AtomicBoolean(false)
        val dialed = LinkedBlockingQueue<Pair<Int, String>>()
        val served = LinkedBlockingQueue<String>()
        val release = LinkedBlockingQueue<Unit>()
        val a = AwayFromHome(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            tunnels,
            load = { null },
            save = { saved.set(it) },
            atHome = { home.get() },
            dial = { port, h ->
                dialed.add(port to h)
                if (!answers.get()) throw IOException("no answer")
                NoTransport
            },
            serve = { _, h ->
                served.add(h)
                release.poll(5, TimeUnit.SECONDS)
            },
            mayHost = { it == hub },
            order = { listOf(hub) },
            firstWaitMS = 10,
            maxWaitMS = 20,
            homeCheckMS = 10,
        )
        a.start()
        try {
            // Off: no key for the hellos, no tunnel.
            assertFalse(a.isOn)
            assertNull(a.publicKey)
            eventually("off") { a.status == AwayFromHome.Status.OFF }

            a.turnOn()
            assertTrue(a.isOn)
            assertArrayEquals(ByteArray(32) { 8 }, a.publicKey)
            assertNotNull(saved.get())
            eventually("waiting for the hub") { a.status == AwayFromHome.Status.WAITING_FOR_HUB }
            assertTrue(tunnels.started.isEmpty())

            // An offer from a device that is neither the root nor an admin is ignored.
            a.keep("cccccccccccccccccccccccccccccccc", offer)
            assertTrue(saved.get()!!.hubs.isEmpty())
            // The hub's answer, from a peer the node named: away, the tunnel starts on its first endpoint.
            a.keep(null, offer)
            a.keep(hub, offer)
            assertEquals(offer, saved.get()?.offer(hub))
            assertEquals(hub, a.hub)
            assertArrayEquals(saved.get()!!.psk, a.keys!!.second)
            val t = tunnels.started.poll(5, TimeUnit.SECONDS)!!
            assertEquals(offer.endpoints[0], t.endpoint)
            assertEquals("", t.obfuscation)
            assertEquals("", t.vless)
            assertEquals(t.port to hub, dialed.poll(5, TimeUnit.SECONDS))
            // No answer: the next endpoint, on a new tunnel.
            val next = tunnels.started.poll(5, TimeUnit.SECONDS)!!
            assertTrue(t.closed)
            assertEquals(offer.endpoints[1], next.endpoint)

            answers.set(true)
            assertEquals(hub, served.poll(5, TimeUnit.SECONDS))
            assertEquals(AwayFromHome.Status.CONNECTED, a.status)

            // At home the tunnel closes and the phone dials the hub directly.
            home.set(true)
            release.add(Unit)
            eventually("at home") { a.status == AwayFromHome.Status.AT_HOME }
            assertTrue(tunnels.all.all { it.closed })

            // Away again: a new tunnel.
            tunnels.started.clear()
            home.set(false)
            val t2 = tunnels.started.poll(5, TimeUnit.SECONDS)!!
            assertEquals(hub, served.poll(5, TimeUnit.SECONDS))

            // Off: the tunnel closes and the state is forgotten.
            a.turnOff()
            release.add(Unit)
            assertTrue(t2.closed)
            assertNull(saved.get())
            assertNull(a.publicKey)
            eventually("off again") { a.status == AwayFromHome.Status.OFF }
        } finally {
            a.stop()
        }
    }

    /**
     * Every hub's offer is kept, its own or passed on by another hub, and
     * one marked moved makes the phone forget the sender's (docs/protocol.md,
     * section 11, "Several hubs").
     */
    @Test
    fun keepsEveryHubsOffer() {
        val saved = AtomicReference<AwayState?>(null)
        val pc = "dddddddddddddddddddddddddddddddd"
        val admins = mutableSetOf(hub, pc)
        val a = AwayFromHome(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            FakeTunnels(),
            load = { AwayState(ByteArray(32) { 1 }).withOffer(hub, offer) },
            save = { saved.set(it) },
            atHome = { true },
            dial = { _, _ -> NoTransport },
            serve = { _, _ -> },
            mayHost = { it in admins },
            order = { listOf(hub, pc) },
        )
        val pcOffer = Member.TunnelOffer(ByteArray(32) { 5 }, ByteArray(32) { 6 }, listOf("203.0.113.5:8764"))
        // Another hub's own offer is kept beside the first's.
        a.keep(pc, pcOffer)
        assertEquals(listOf(hub, pc), saved.get()?.hubs?.map { it.first })
        assertEquals(hub, a.hub)
        assertEquals(listOf(hub, pc), a.hubs)
        // Passed on by the hub, without the hub field, in place of the earlier one.
        val passed = Member.TunnelOffer(pcOffer.hubKey, offer.psk, listOf("203.0.113.6:8764"))
        a.keep(hub, passed.with(passed.psk, pc))
        assertEquals(passed, saved.get()?.offer(pc))
        // The hub moves to the computer: its own offer goes.
        a.keep(hub, pcOffer.with(pcOffer.psk, pc, moved = true))
        assertEquals(listOf(pc), saved.get()?.hubs?.map { it.first })
        assertEquals(pcOffer, saved.get()?.offer(pc))
        // An offer naming a device that is no admin, or from one, is ignored, as is this phone's own.
        a.keep(pc, pcOffer.with(pcOffer.psk, "cccccccccccccccccccccccccccccccc"))
        a.keep("cccccccccccccccccccccccccccccccc", offer)
        a.keep(pc, offer.with(offer.psk, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
        assertEquals(listOf(pc), saved.get()?.hubs?.map { it.first })
        admins.remove(pc)
        a.keep(pc, offer)
        assertEquals(listOf(pc), saved.get()?.hubs?.map { it.first })
    }

    /**
     * The first hub in the order that answers is used; on a lower one the
     * connection ends after the up check, and the phone goes back up to
     * the first once it answers.
     */
    @Test
    fun usesTheFirstHubThatAnswers() {
        val pc = "dddddddddddddddddddddddddddddddd"
        val pcOffer = Member.TunnelOffer(ByteArray(32) { 5 }, ByteArray(32) { 6 }, listOf("203.0.113.5:8764"))
        val tunnels = FakeTunnels()
        val pcUp = AtomicBoolean(false)
        val served = LinkedBlockingQueue<String>()
        val a = AwayFromHome(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            tunnels,
            load = { AwayState(ByteArray(32) { 1 }).withOffer(hub, offer).withOffer(pc, pcOffer) },
            save = {},
            atHome = { false },
            dial = { _, h ->
                if (h == pc && !pcUp.get()) throw IOException("no answer")
                Closing()
            },
            serve = { t, h ->
                served.add(h)
                (t as Closing).closed.poll(5, TimeUnit.SECONDS)
            },
            mayHost = { true },
            order = { listOf(pc, hub) },
            firstWaitMS = 10,
            maxWaitMS = 20,
            upCheckMS = 100,
        )
        a.start()
        try {
            assertEquals(hub, served.poll(5, TimeUnit.SECONDS))
            assertEquals(hub, a.hub)
            assertEquals(hub, a.inUse)
            assertEquals(listOf(pc, hub), a.hubs)
            pcUp.set(true)
            assertEquals(pc, served.poll(5, TimeUnit.SECONDS))
            assertEquals(pc, a.hub)
            // On the first hub there is no up check.
            assertNull(served.poll(300, TimeUnit.MILLISECONDS))
        } finally {
            a.stop()
        }
    }

    /**
     * A hub that offers its next key is tried with each key at each of its
     * endpoints in turn: the key it serves with now may answer only at the
     * second endpoint, as a hub at home does from away through its
     * forwarder.
     */
    @Test
    fun eachKeyTriesEachEndpoint() {
        val next = ByteArray(32) { 9 }
        val both = Member.TunnelOffer(offer.hubKey, offer.psk, offer.endpoints, nextKey = next)
        val tunnels = FakeTunnels()
        val served = LinkedBlockingQueue<String>()
        val a = AwayFromHome(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            tunnels,
            load = { AwayState(ByteArray(32) { 1 }).withOffer(hub, both) },
            save = {},
            atHome = { false },
            dial = { port, _ ->
                val t = tunnels.all.first { it.port == port }
                if (!t.hubKey.contentEquals(both.hubKey) || t.endpoint != both.endpoints[1]) throw IOException("no answer")
                Closing()
            },
            serve = { t, h ->
                served.add(h)
                (t as Closing).closed.poll(5, TimeUnit.SECONDS)
            },
            mayHost = { true },
            order = { listOf(hub) },
            firstWaitMS = 10,
            maxWaitMS = 20,
        )
        a.start()
        try {
            // Only the key now at the second endpoint answers.
            assertEquals(hub, served.poll(5, TimeUnit.SECONDS))
            assertTrue(tunnels.all.any { it.hubKey.contentEquals(next) })
        } finally {
            a.stop()
        }
    }

    /** A connection whose close the serve sees. */
    private class Closing : FrameTransport {
        val closed = LinkedBlockingQueue<Unit>()
        override fun write(data: ByteArray) = Unit
        override fun read(n: Int): ByteArray = throw IOException("closed")
        override fun close() {
            closed.add(Unit)
        }
    }

    @Test
    fun aNewOfferStartsAgain() {
        val tunnels = FakeTunnels()
        val release = LinkedBlockingQueue<Unit>()
        val a = AwayFromHome(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            tunnels,
            load = { AwayState(ByteArray(32) { 1 }).withOffer(hub, offer) },
            save = {},
            atHome = { false },
            dial = { _, _ -> NoTransport },
            serve = { _, _ -> release.poll(5, TimeUnit.SECONDS) },
            mayHost = { true },
            order = { listOf(hub, "dddddddddddddddddddddddddddddddd") },
            firstWaitMS = 10,
            maxWaitMS = 20,
        )
        a.start()
        try {
            val t = tunnels.started.poll(5, TimeUnit.SECONDS)!!
            eventually("connected") { a.status == AwayFromHome.Status.CONNECTED }
            // The same offer again changes nothing, nor does another admin's; a new one closes the tunnel and starts with it.
            a.keep(hub, offer)
            a.keep("dddddddddddddddddddddddddddddddd", Member.TunnelOffer(offer.hubKey, ByteArray(32) { 4 }, listOf("203.0.113.7:8764")))
            assertFalse(t.closed)
            val moved = Member.TunnelOffer(offer.hubKey, offer.psk, listOf("198.51.100.9:8764"))
            a.keep(hub, moved)
            assertTrue(t.closed)
            release.add(Unit)
            val t2 = tunnels.started.poll(5, TimeUnit.SECONDS)!!
            assertEquals("198.51.100.9:8764", t2.endpoint)
        } finally {
            a.stop()
        }
    }
}
