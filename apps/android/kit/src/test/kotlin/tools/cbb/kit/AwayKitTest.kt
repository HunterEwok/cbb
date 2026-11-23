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
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.fail
import kotlinx.serialization.json.JsonPrimitive

/**
 * Sync away from home and the group's relay on a group of 0.6, as the Live member runs them in the app's process
 * (docs/core-api.md, `away_status`, the manage actions `forwarder` and `relay`): no phone is a hub, and the link to
 * the group's relay tells why it is not connected.
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
        val made = CorePairing.newGroup(File(top, "root"), "Root phone", "android", Records.HARDWARE, rootKey.publicKeyDER, rKey.publicKeyDER, rootKey::signDigest)
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

    }

    /**
     * A hub is a computer, a router or a board, never a phone (docs/decisions.md, D-134): the root names no
     * forwarder for an admin phone, nor for its own, and an admin names none at all.
     */
    @Test
    fun theRootNamesNoForwarderForAPhone() {
        val g = Group()
        val pin = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
        val fw = "127.0.0.1:${freeUDP()}"
        assertFailsWith<Core.Refusal>("an admin key is no root key") { g.a.nameForwarder("Root phone", fw, pin, g.aAdmin.publicKeyDER, g.aAdmin::signDigest) }
        assertFailsWith<Core.Refusal>("the root names no forwarder for its own phone") { g.r.nameForwarder("Root phone", fw, pin, g.rootKey.publicKeyDER, g.rootKey::signDigest) }
        // The admin phone may know it is an admin only later: it is no hub either way.
        val e = assertFailsWith<Core.Refusal>("an admin phone is no hub") { g.r.nameForwarder("Admin phone", fw, pin, g.rootKey.publicKeyDER, g.rootKey::signDigest) }
        assertTrue(e.message.orEmpty().contains("do not make Admin phone a hub"), e.message)
        assertTrue(g.a.awayStatus()?.hub != true, "the admin phone is no hub")
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

        // Nothing listens at the relay's address. The root key that sets it
        // also renews the group's server credentials, which were due.
        assertTrue(g.r.periods().first, "the root phone's first period is due")
        assertEquals(false to false, g.a.periods(), "only the root phone signs periods")
        assertFailsWith<Core.Refusal>("an admin key is no root key") { g.a.renewPeriod(g.aAdmin.publicKeyDER, g.aAdmin::signDigest) }
        val relayPort = freeUDP()
        assertEquals(listOf("127.0.0.1:$relayPort"), g.r.setRelays(listOf("127.0.0.1:$relayPort $pin"), g.rootKey.publicKeyDER, g.rootKey::signDigest))
        assertEquals(false to false, g.r.periods(), "the relay's root key renewed the credentials")
        assertEquals(false to false, g.r.renewPeriod(g.rootKey.publicKeyDER, g.rootKey::signDigest))
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
            CoreMember.Start(dir, name, "android", device = device, publicKey = key.publicKeyDER, peers = peers),
            key::signDigest,
            events = { },
        ).also { members += it }
}
