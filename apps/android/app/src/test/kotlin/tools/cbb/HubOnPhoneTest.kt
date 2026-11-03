// SPDX-License-Identifier: AGPL-3.0-only

package tools.cbb

import tools.cbb.kit.Member
import tools.cbb.kit.PhoneHub
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.InetAddress
import java.util.concurrent.CopyOnWriteArrayList

class HubOnPhoneTest {
    private val phone = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    private val pc = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    private val tv = "cccccccccccccccccccccccccccccccc"
    private val pin = "A".repeat(43) + "="

    private class FakeHub(val memberPort: Int, var held: String) : HubTunnel {
        var registered: List<String>? = null
        var obfuscation = ""
        var vlessID = ""
        var shown = ""
        var report = "{}"
        @Volatile var closed = false

        override fun setClients(json: String) {
            held = json
        }

        override fun register(endpoint: String, pin: String, chain: String, sign: (ByteArray) -> ByteArray, records: String, vlessID: String) {
            registered = listOf(endpoint, pin, chain)
            shown = records
            this.vlessID = vlessID
        }

        override fun setRecords(records: String) {
            shown = records
        }

        override fun status(): String = report

        var invited: List<Any>? = null

        override fun invite(group: String, endpoints: String, lifetimeS: Int, guestPort: Int): HubGuest {
            invited = listOf(group, endpoints, lifetimeS, guestPort)
            return object : HubGuest {
                override val text = "cbb://invite#x"
                override val secret = ByteArray(16)
                override val expires = 0L
                override fun admitted() {}
                override fun close() {}
            }
        }

        override fun close() {
            closed = true
        }
    }

    private class FakeTunnels : HubTunnels {
        val started = CopyOnWriteArrayList<FakeHub>()
        override fun newKey(): ByteArray = ByteArray(32) { 7 }
        override fun publicKey(private: ByteArray): ByteArray = ByteArray(32) { 8 }
        var made = 0
        override fun start(private: ByteArray, device: String, memberPort: Int, obfuscation: String, clients: String): HubTunnel =
            FakeHub(memberPort, clients).also {
                it.obfuscation = obfuscation
                started.add(it)
            }
        override fun newObfuscation(): String {
            made++
            return OBFUSCATION
        }
        override fun newVLESSID(): String = VLESS_ID
    }

    private fun group(records: List<Member.Record> = emptyList()) = HubOnPhone.Group(4242, listOf(ByteArray(3) { 1 }), { it }, records)

    @Test
    fun stateRoundTrips() {
        val s = HubState(
            ByteArray(32) { 1 }, on = true, forwarder = HubState.Forwarder("203.0.113.9:8764", pin), background = true,
            homes = listOf("192.168.0.1 192.168.0.0/24"), clients = listOf(PhoneHub.Client(pc, ByteArray(32) { 2 }, ByteArray(32) { 3 })),
        )
        val back = HubState.decode(s.encode())
        assertEquals(s, back)
        assertArrayEquals(s.clients[0].psk, back!!.clients[0].psk)
        assertNull(HubState.decode("{}".toByteArray()))
        assertNull(HubState.decode("not json".toByteArray()))
        assertNull(HubState.decode("""{"key":"AAAA"}""".toByteArray()))
    }

    @Test
    fun forwarderInput() {
        assertTrue(HubState.validPin(pin))
        assertTrue(HubState.validPin("a+/9".repeat(10) + "abc="))
        assertFalse(HubState.validPin("sha256:" + "A".repeat(43) + "="))
        assertFalse(HubState.validPin("A".repeat(43)))
        assertFalse(HubState.validPin("a-_9".repeat(10) + "abc="))
        assertFalse(HubState.validPin("A".repeat(42) + "B="))
        assertEquals("203.0.113.9:8764", HubState.resolve(" 203.0.113.9:8764 "))
        // IPv6 in brackets, which Go's netip reads in either form.
        val v6 = HubState.resolve("[2001:db8::9]:8764") ?: ""
        assertTrue(v6, v6.startsWith("[2001:db8:") && v6.endsWith("9]:8764"))
        assertNull(HubState.resolve("203.0.113.9"))
        assertNull(HubState.resolve("203.0.113.9:0"))
        assertNull(HubState.resolve(":8764"))
    }

    @Test
    fun networkKeys() {
        val gw = InetAddress.getByName("192.168.0.1")
        assertEquals("192.168.0.1 192.168.0.0/24", HubOnPhone.networkKey(gw, InetAddress.getByName("192.168.0.57"), 24))
        assertEquals("192.168.0.1 192.168.0.0/23", HubOnPhone.networkKey(gw, InetAddress.getByName("192.168.1.57"), 23))
        assertEquals("192.168.0.1 10.1.2.3/32", HubOnPhone.networkKey(gw, InetAddress.getByName("10.1.2.3"), 32))
        assertNull(HubOnPhone.networkKey(null, InetAddress.getByName("192.168.0.57"), 24))
        assertNull(HubOnPhone.networkKey(gw, InetAddress.getByName("192.168.0.57"), 33))
    }

    /**
     * Several hubs (docs/protocol.md, section 11): it shares its clients,
     * takes the ones another hub shares that the records know, keeps them
     * as it saves them, and passes that hub's offer on to its clients.
     */
    @Test
    fun sharesWithTheOtherHubs() {
        var saved: HubState? = null
        val h = HubOnPhone(phone, FakeTunnels(), load = { saved }, save = { saved = it })
        h.turnOn(null)
        val share = Member.HubShare(
            true, Member.TunnelOffer(ByteArray(32) { 5 }, ByteArray(0), listOf("198.51.100.5:8764")),
            listOf(PhoneHub.Client(tv, ByteArray(32) { 6 }, ByteArray(32) { 7 }), PhoneHub.Client("d".repeat(32), ByteArray(32) { 9 }, ByteArray(32) { 9 })),
        )
        // Without a forwarder it neither shares nor takes.
        assertNull(h.share())
        assertFalse(h.shared(pc, share) { true })
        h.setForwarder(HubState.Forwarder("203.0.113.9:8764", pin))
        assertTrue(h.share()!!.serving)
        assertTrue(h.shared(pc, share) { it != "d".repeat(32) })
        assertFalse("the same offer again", h.shared(pc, share) { it != "d".repeat(32) })
        assertEquals(listOf(tv), h.clients)
        assertEquals(listOf(tv), saved!!.clients.map { it.device })
        assertEquals(listOf(tv), h.share()!!.clients.map { it.device })

        // A client gets its own offer, then the other hub's with its own preshared key.
        val offers = h.offers(tv, ByteArray(32) { 6 }, ByteArray(32) { 8 }, listOf(phone, pc))
        assertEquals(listOf(null, pc), offers.map { it.hub })
        assertArrayEquals(ByteArray(32) { 8 }, offers[1].psk)
        assertTrue(HubState.decode(saved!!.encode())!!.clients.single().met)
        // The other hub, a client too, does not get its own offer back. A
        // new client makes the hub share again; one it knows is no news.
        var admitted = 0
        h.offers(pc, ByteArray(32) { 2 }, ByteArray(32) { 3 }) { admitted++ }
        h.offers(pc, ByteArray(32) { 2 }, ByteArray(32) { 3 }) { admitted++ }
        assertEquals(1, admitted)
        assertEquals(1, h.offersFor(pc, emptyList()).size)
        assertEquals(2, h.offersFor(tv, emptyList()).size)
    }

    /** On with a forwarder: it offers the forwarder's endpoint, keeps the clients, and hands them and the records to the tunnel. */
    @Test
    fun servesWithAForwarder() {
        var saved: HubState? = null
        val tunnels = FakeTunnels()
        val h = HubOnPhone(phone, tunnels, load = { saved }, save = { saved = it })
        assertFalse(h.isOn)
        assertNull(h.offer(pc, ByteArray(32) { 2 }))
        h.turnOn("192.168.0.1 192.168.0.0/24")
        assertTrue(h.isOn)
        assertThrows(HubOnPhone.NotRunning::class.java) { h.invite("tag", 3600, 5555) }
        assertTrue(h.isHome("192.168.0.1 192.168.0.0/24"))
        assertFalse(h.isHome("10.0.0.1 10.0.0.0/24"))
        assertFalse(h.isHome(null))
        // At home only: no offer, nothing to register.
        assertEquals(HubOnPhone.Status.HOME_ONLY, h.status(paused = false).first)
        assertNull(h.offer(pc, ByteArray(32) { 2 }))
        h.start(group())
        assertTrue(tunnels.started.isEmpty())

        h.setForwarder(HubState.Forwarder("203.0.113.9:8764", pin))
        val o = requireNotNull(h.offer(pc, ByteArray(32) { 2 }))
        assertEquals(listOf("203.0.113.9:8764"), o.endpoints)
        assertArrayEquals(ByteArray(32) { 8 }, o.hubKey)
        assertEquals(listOf(pc), saved!!.clients.map { it.device })
        assertEquals(HubOnPhone.Status.PAUSED, h.status(paused = true).first)

        val rec = Member.Record(byteArrayOf(1), byteArrayOf(2))
        h.start(group(listOf(rec)))
        val t = tunnels.started.single()
        assertEquals(4242, t.memberPort)
        assertTrue(t.held.contains(pc))
        assertEquals("203.0.113.9:8764", t.registered!![0])
        assertTrue(t.shown.contains("\"body\""))
        h.start(group()) // running already
        assertEquals(1, tunnels.started.size)
        assertEquals(HubOnPhone.Status.REGISTERING, h.status(paused = false).first)
        t.report = """{"registered":true,"seen":"198.51.100.1:5555"}"""
        assertEquals(HubOnPhone.Status.REGISTERED, h.status(paused = false).first)
        t.report = """{"error":"the forwarder refused it"}"""
        assertEquals(HubOnPhone.Status.FAILED to "the forwarder refused it", h.status(paused = false))

        // An invitation goes through the running tunnel, with the forwarder as the hub's address.
        h.invite("tag", 3600, 5555)
        assertEquals(listOf("tag", "[\"203.0.113.9:8764\"]", 3600, 5555), t.invited)

        // A new client reaches the running tunnel; a removed one leaves it.
        h.offer(tv, ByteArray(32) { 4 })
        assertTrue(t.held.contains(tv))
        assertEquals(listOf(pc), h.prune { it != pc })
        assertFalse(t.held.contains(pc))
        assertEquals(listOf(tv), saved!!.clients.map { it.device })
        h.setRecords(emptyList())
        assertEquals("[]", t.shown)

        // A new forwarder stops the tunnel; turning it off stops it and keeps the clients.
        h.setForwarder(HubState.Forwarder("203.0.113.10:8764", pin))
        assertTrue(t.closed)
        h.start(group())
        h.turnOff()
        assertTrue(tunnels.started.last().closed)
        assertEquals(HubOnPhone.Status.OFF, h.status(paused = false).first)
        assertEquals(listOf(tv), HubOnPhone(phone, FakeTunnels(), load = { saved }, save = {}).clients)
    }

    /**
     * The tunnel hides as the user chose: the AmneziaWG settings go to the
     * tunnel and into the offers and stay while it stays on; VLESS keeps
     * them, and waits for the forwarder's way there before it offers anything.
     */
    @Test
    fun disguise() {
        val tunnels = FakeTunnels()
        var saved: HubState? = null
        val h = HubOnPhone(phone, tunnels, load = { null }, save = { saved = it })
        h.turnOn(null)
        h.setForwarder(HubState.Forwarder("203.0.113.9:8764", pin))
        assertEquals(HubOnPhone.Disguise.PLAIN, h.disguise)
        h.setDisguise(HubOnPhone.Disguise.OBFUSCATE)
        h.setDisguise(HubOnPhone.Disguise.OBFUSCATE)
        assertEquals(HubOnPhone.Disguise.OBFUSCATE, h.disguise)
        assertEquals(1, tunnels.made)
        assertEquals(OBFUSCATION, saved?.obfuscation)
        assertEquals(saved, HubState.decode(saved!!.encode()))
        assertEquals(OBFUSCATION, h.offer(pc, ByteArray(32) { 2 })?.obfuscation)
        h.start(group())
        val t = tunnels.started.last()
        assertEquals(OBFUSCATION, t.obfuscation)
        assertEquals("", t.vlessID)

        h.setDisguise(HubOnPhone.Disguise.VLESS)
        assertTrue(t.closed)
        assertEquals(OBFUSCATION, saved?.obfuscation)
        assertEquals(VLESS_ID, saved?.vlessID)
        assertEquals(VLESS_ID, HubState.decode(saved!!.encode())?.vlessID)
        assertNull(h.offer(pc, ByteArray(32) { 2 }))
        h.start(group())
        val v = tunnels.started.last()
        assertEquals(OBFUSCATION, v.obfuscation)
        assertEquals(VLESS_ID, v.vlessID)
        v.report = """{"registered":true,"vless":{"endpoint":"203.0.113.9:443","public_key":"CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk=","short_id":"ab","server_name":"www.example.com","id":"$VLESS_ID"}}"""
        assertEquals(HubOnPhone.Status.REGISTERED, h.status(paused = false).first)
        assertTrue(h.offer(pc, ByteArray(32) { 2 })?.vless?.contains("203.0.113.9:443") == true)

        h.setDisguise(HubOnPhone.Disguise.PLAIN)
        assertEquals(HubOnPhone.Disguise.PLAIN, h.disguise)
        assertNull(saved?.vlessID)
        assertNull(saved?.obfuscation)
        assertNull(h.offer(pc, ByteArray(32) { 2 })?.vless)
    }

    @Test
    fun remembersAFewHomes() {
        var saved: HubState? = null
        val h = HubOnPhone(phone, FakeTunnels(), load = { saved }, save = { saved = it })
        h.turnOn(null)
        for (i in 1..HubState.MAX_HOMES + 2) h.addHome("home $i")
        assertEquals(HubState.MAX_HOMES, saved!!.homes.size)
        assertFalse(h.isHome("home 1"))
        assertTrue(h.isHome("home ${HubState.MAX_HOMES + 2}"))
        h.setBackground(true)
        assertTrue(h.background)
    }

    private companion object {
        const val OBFUSCATION = """{"jc":4,"jmin":50,"jmax":300,"s1":20,"s2":30,"s3":17,"s4":18,"h1":"5-100","h2":"200-300","h3":"400-500","h4":"600-700","header_protection_key":"CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk="}"""
        const val VLESS_ID = "00000000-0000-4000-8000-000000000000"
    }
}
