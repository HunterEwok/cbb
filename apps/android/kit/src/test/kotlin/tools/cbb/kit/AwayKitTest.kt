// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import java.io.File
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.TimeUnit
import kotlin.io.path.createTempDirectory
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.fail
import kotlinx.serialization.json.JsonPrimitive

/**
 * Sync away from home, the phone as a hub and the group's relay on a group of 0.6, as the Live member runs them in
 * the app's process (docs/core-api.md, `away`, `hub`, `hub_off`, `away_status`, the manage action `relay`): an admin
 * phone serves as the hub and a phone syncs through its tunnel, how the hub's tunnel hides, what the member refuses,
 * and the link to the group's relay telling why it is not connected.
 */
class AwayKitTest {
    private val top: File = createTempDirectory("cbb-away-kit").toFile()
    private val members = mutableListOf<CoreMember>()

    @AfterTest
    fun cleanUp() {
        members.forEach { runCatching { it.close() } }
        top.deleteRecursively()
    }

    /** A root phone and an admin phone of a group of 0.6, connected at home. */
    private inner class Group {
        val rootKey = SoftwareSigner()
        val rKey = SoftwareSigner()
        val made = CorePairing.newGroup06(File(top, "root"), "Root phone", "android", Records.HARDWARE, rootKey.publicKeyDER, rKey.publicKeyDER, rootKey::signDigest)
        var r = member06(File(top, "root"), "Root phone", made.device, rKey)
        val rPort = r.listen(CoreMember.Listen.HOME)
        val aKey = SoftwareSigner()
        val aAdmin = SoftwareSigner()
        val aDir = File(top, "admin")
        val admitted = CorePairing.Window(r, rootKey.publicKeyDER, listOf("127.0.0.1"), sign = rootKey::signDigest).use { w ->
            CorePairing.Joiner(aDir.path, w.qr, "Admin phone", "android", aKey.publicKeyDER, aKey::signDigest, admin = aAdmin.publicKeyDER to aAdmin::signDigest).use { j ->
                until("done", { it.state }, { it.version }, { it.failure }) { j.next(it, 100) }
                until("done", { it.state }, { it.version }, { it.failure }) { w.next(it, 100) }
            }
        }

        init {
            // The test's keys are in software, which the root lets be an admin's at the key level files.
            r.manage(Wire.obj("action" to Wire.str("key_level"), "level" to Wire.str("files"), "public" to Wire.bytes(CoreMember.point(rootKey.publicKeyDER))), rootKey::signDigest)
            r.manage(
                Wire.obj("action" to Wire.str("make_admin"), "device" to Wire.str("Admin phone"), "allow_file_key" to JsonPrimitive(true),
                    "public" to Wire.bytes(CoreMember.point(rootKey.publicKeyDER))),
                rootKey::signDigest,
            )
        }

        val a = member06(aDir, "Admin phone", admitted.device, aKey, peers = listOf("127.0.0.1:$rPort"))

        /** Has the admin phone serve as the hub once it learned it is an admin, as hub asks. */
        fun serve(hub: () -> CoreMember.AwayState?): CoreMember.AwayState {
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(60)
            while (true) {
                val got = runCatching { hub() }
                got.getOrNull()?.let { return it }
                assertTrue(System.nanoTime() < deadline, "the admin phone never became a hub: ${got.exceptionOrNull()}")
                Thread.sleep(200)
            }
        }
    }

    /**
     * An admin phone serves as the group's hub; the root phone turns sync away from home on, takes the hub's offer
     * while they are connected at home, and once it starts again knowing no home address, it syncs through the hub's
     * tunnel: a copy made on it reaches the hub.
     */
    @Test
    fun aPhoneSyncsThroughTheTunnelOfAnAdminPhoneHub() {
        val g = Group()
        val port = freeUDP()
        val hub = g.serve { g.a.serveAsHub(port, listOf("127.0.0.1:$port")) }
        assertTrue(hub.hub, "the admin phone is a hub")
        assertEquals(port, hub.port)
        assertEquals(listOf("127.0.0.1:$port"), hub.endpoints)
        assertTrue(hub.obfuscated, "a hub speaks AmneziaWG unless told not to")
        assertFalse(hub.vless, "no VLESS without a forwarder")

        val on = assertNotNull(g.r.setAway(true))
        assertTrue(on.isOn, "sync away from home is on")
        assertFalse(on.hub)
        val held = waitFor("the root phone never took the hub's offer") { g.r.awayStatus()?.takeIf { it.hubDevice == g.admitted.device } }
        assertFalse(held.through, "at home the phone reaches the hub without the tunnel")

        // The root phone starts again with no home address of the hub: it reaches it through the tunnel.
        g.r.close()
        members -= g.r
        g.r = member06(File(top, "root"), "Root phone", g.made.device, g.rKey)
        waitFor("the root phone never went through the hub's tunnel") { g.r.awayStatus()?.takeIf { it.through && it.hubDevice == g.admitted.device } }
        g.r.copy("through the tunnel")
        waitFor("the copy never reached the hub") { g.a.current()?.takeIf { it.text == "through the tunnel" } }

        // Off, the phone goes through no tunnel.
        val off = g.r.setAway(false)
        assertTrue(off == null || !off.isOn, "sync away from home is off: $off")
    }

    /**
     * How the hub's tunnel hides (docs/design.md, "Blocked networks"): AmneziaWG by default, plain WireGuard when told,
     * and VLESS only to a forwarder and only with AmneziaWG; stopping the hub leaves the phone a client.
     */
    @Test
    fun theHubsTunnelHidesAsTheUserChose() {
        val g = Group()
        val port = freeUDP()
        val plain = g.serve { g.a.serveAsHub(port, listOf("127.0.0.1:$port"), obfuscateOff = true, vlessOff = true) }
        assertTrue(plain.hub)
        assertFalse(plain.obfuscated, "plain WireGuard")
        val hidden = assertNotNull(g.a.serveAsHub(port, listOf("127.0.0.1:$port")))
        assertTrue(hidden.obfuscated, "AmneziaWG again")
        assertEquals(port, hidden.port)
        // VLESS carries AmneziaWG: plain WireGuard with VLESS to a forwarder is refused.
        val pin = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
        val e = assertFailsWith<Core.Refusal> { g.a.serveAsHub(port, forwarder = "127.0.0.1:1", key = pin, obfuscateOff = true) }
        assertTrue(e.message.orEmpty().contains("VLESS"), e.message)
        val stopped = assertNotNull(g.a.stopHub())
        assertFalse(stopped.hub, "the phone is no hub after hub_off")
        assertFailsWith<Core.Refusal>("a phone that is no hub cannot stop being one") { g.a.stopHub() }
    }

    /**
     * The hub's forwarder is the root's setting: the root names it for an admin phone, which keeps it without becoming
     * a hub and serves through it once its own switch is on; nobody else names it.
     */
    @Test
    fun theRootNamesAnAdminPhonesForwarder() {
        val g = Group()
        val pin = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
        val fw = "127.0.0.1:${freeUDP()}"
        assertFailsWith<Core.Refusal>("an admin key is no root key") { g.a.nameForwarder("Root phone", fw, pin, g.aAdmin.publicKeyDER, g.aAdmin::signDigest) }
        assertFailsWith<Core.Refusal>("the root is no hub") { g.r.nameForwarder("Root phone", fw, pin, g.rootKey.publicKeyDER, g.rootKey::signDigest) }
        assertNull(g.a.rootForwarder())
        val named = waitFor("the admin phone never took the root's forwarder") {
            runCatching { g.r.nameForwarder("Admin phone", fw, pin, g.rootKey.publicKeyDER, g.rootKey::signDigest) }.getOrNull()?.takeIf { it.first == "done" }
        }
        assertEquals("done" to "", named)
        assertEquals(CoreMember.RootForwarder(fw, pin), g.a.rootForwarder())
        assertTrue(g.a.awayStatus()?.hub != true, "the root's command does not switch the hub on")
        // Its own switch on, with no forwarder given: the root's.
        val hub = g.serve { g.a.serveAsHub() }
        assertTrue(hub.hub)
        assertEquals(fw, hub.forwarder?.endpoint)
    }

    /** What the member refuses: a phone the records do not make a hub, a hub with no way to it, and bad addresses. */
    @Test
    fun theMemberRefusesABadHub() {
        val g = Group()
        // The root phone holds no admin key, so the records make it no hub.
        val notHub = assertFailsWith<Core.Refusal> { g.r.serveAsHub(freeUDP(), listOf("127.0.0.1:9")) }
        assertTrue(notHub.message.orEmpty().contains("do not make this phone a hub"), notHub.message)
        val port = freeUDP()
        g.serve { g.a.serveAsHub(port, listOf("127.0.0.1:$port")) }
        assertFailsWith<Core.Refusal>("no address and no forwarder") { g.a.serveAsHub(port) }
        assertFailsWith<Core.Refusal>("an address with no port") { g.a.serveAsHub(port, listOf("127.0.0.1")) }
        assertFailsWith<Core.Refusal>("a bad port") { g.a.serveAsHub(70000, listOf("127.0.0.1:$port")) }
        assertFailsWith<Core.Refusal>("a forwarder that is no address") { g.a.serveAsHub(port, forwarder = "nowhere", key = "x") }
    }

    /**
     * The group's relay is the root's setting: a bad key and "default" beside another relay are refused, a phone that
     * is not the root cannot set it, and a phone away from home whose relay does not answer says why.
     */
    @Test
    fun theRelayIsTheGroupsAndSaysWhyItIsNotConnected() {
        val g = Group()
        val pin = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
        assertFailsWith<Core.Refusal>("not a relay's key") { g.r.setRelays(listOf("127.0.0.1:1 nope"), g.rootKey.publicKeyDER, g.rootKey::signDigest) }
        assertFailsWith<Core.Refusal>("default goes alone") { g.r.setRelays(listOf("default", "127.0.0.1:1 $pin"), g.rootKey.publicKeyDER, g.rootKey::signDigest) }
        assertFailsWith<Core.Refusal>("an admin key is no root key") { g.a.setRelays(listOf("127.0.0.1:1 $pin"), g.aAdmin.publicKeyDER, g.aAdmin::signDigest) }

        // Nothing listens at the relay's address.
        val relayPort = freeUDP()
        assertEquals(listOf("127.0.0.1:$relayPort"), g.r.setRelays(listOf("127.0.0.1:$relayPort $pin"), g.rootKey.publicKeyDER, g.rootKey::signDigest))
        g.a.setAway(true)
        val relay = waitFor("the admin phone never tried the group's relay") { g.a.awayStatus()?.relay?.takeIf { it.endpoint == "127.0.0.1:$relayPort" && it.error.isNotEmpty() } }
        assertFalse(relay.connected, "the relay does not take it")
        assertTrue(relay.online.isEmpty())

        // None again: the phone meets nobody at a relay.
        assertEquals(emptyList(), g.r.setRelays(emptyList(), g.rootKey.publicKeyDER, g.rootKey::signDigest))
        waitFor("the admin phone kept the relay") { g.a.awayStatus()?.takeIf { it.relay == null } }
        assertNull(g.a.awayStatus()?.relay)
    }

    private fun freeUDP(): Int = DatagramSocket(0, InetAddress.getLoopbackAddress()).use { it.localPort }

    /** The first non-null of get, waiting up to 60 seconds. */
    private fun <T : Any> waitFor(what: String, get: () -> T?): T {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(60)
        while (System.nanoTime() < deadline) {
            runCatching(get).getOrNull()?.let { return it }
            Thread.sleep(200)
        }
        fail(what)
    }

    /** The first state named want, failing on a failed one, for at most 400 waits of 100 ms. */
    private fun <S> until(want: String, state: (S) -> String, version: (S) -> Long, failure: (S) -> Exception?, next: (Long) -> S): S {
        var v = 0L
        repeat(400) {
            val s = next(v)
            if (state(s) == want) return s
            if (state(s) == "failed") throw failure(s) ?: AssertionError("failed, waiting for $want")
            v = version(s)
        }
        fail("no state $want")
    }

    /** A member of 0.6 started on the set in dir. */
    private fun member06(dir: File, name: String, device: String, key: SoftwareSigner, peers: List<String> = emptyList()): CoreMember =
        CoreMember.start(
            CoreMember.Start(dir, name, "android", device = device, publicKey = key.publicKeyDER, seal = CoreGroup.SEAL, cert = ByteArray(0), groupCA = ByteArray(0), peers = peers),
            key::signDigest,
            events = { },
        ).also { members += it }
}
