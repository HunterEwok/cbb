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
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlin.test.fail
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long

/**
 * Remote invitations in the kit (docs/protocol.md, section 12): reading one, a phone that joins by one of 0.6 through
 * its guest tunnel to an admin phone that serves as the hub, and an admin phone that has no hub to invite through. A phone that joins through a computer hub and one that invites through a computer hub are
 * tested in Go (internal/service, TestFFIJoinInvite, TestFFIInviteThroughHub).
 */
class InviteKitTest {
    private val top: File = createTempDirectory("cbb-invite-kit").toFile()
    private val members = mutableListOf<CoreMember>()
    private val hubID = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
    private val tag = "0123456789abcdef"

    @AfterTest
    fun cleanUp() {
        members.forEach { it.close() }
        top.deleteRecursively()
    }

    @Test
    fun readsAnInvitationAndRefusesOthers() {
        // testdata/interop/invites.json, which the core reads as Go wrote it.
        val v = Interop.read("invites.json").jsonObject.getValue("valid").jsonArray.first().jsonObject
        val read = assertIs<Core.InviteReading.Read>(Core.readInvite(v.getValue("text").jsonPrimitive.content))
        assertEquals(v.getValue("group").jsonPrimitive.content, read.invitation.group)
        assertEquals(v.getValue("hub").jsonPrimitive.content, read.invitation.hub)
        assertEquals(v.getValue("expires").jsonPrimitive.long, read.invitation.expires)
        val refused = assertIs<Core.InviteReading.Refused>(Core.readInvite("cbb://invite#{}"))
        assertTrue(refused.reason.isNotEmpty())
        assertTrue(refused.message.isNotEmpty())
        assertIs<Core.InviteReading.Refused>(Core.readInvite("not an invitation"))
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

    /**
     * A phone that joins by an invitation of 0.6 dials the hub through the invitation's guest tunnel and shows its
     * fingerprint. Here the hub is an admin phone of the group, serving as the Live hub the computers run: the joiner
     * reaches it through the tunnel (the hub answers), the inviting phone asks about the fingerprint the joiner shows,
     * and the joiner is in the group once the user says yes.
     */
    @Test
    fun joinsThroughTheGuestTunnel() {
        // The root phone, and an admin phone that joined its home window offering its admin key.
        val rootKey = SoftwareSigner()
        val rKey = SoftwareSigner()
        val made = CorePairing.newGroup(File(top, "root"), "Root phone", "android", Records.HARDWARE, rootKey.publicKeyDER, rKey.publicKeyDER, rootKey::signDigest)
        val r = member06(File(top, "root"), "Root phone", made.device, rKey)
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
        // The test's keys are in software, which the root lets be an admin's at the key level files.
        r.manage(Wire.obj("action" to Wire.str("key_level"), "level" to Wire.str("files"), "public" to Wire.bytes(CoreMember.point(rootKey.publicKeyDER))), rootKey::signDigest)
        r.manage(
            Wire.obj("action" to Wire.str("make_admin"), "device" to Wire.str("Admin phone"), "allow_file_key" to JsonPrimitive(true),
                "public" to Wire.bytes(CoreMember.point(rootKey.publicKeyDER))),
            rootKey::signDigest,
        )
        val a = member06(aDir, "Admin phone", admitted.device, aKey, peers = listOf("127.0.0.1:$rPort"))
        // The admin phone learns it is an admin from the root, then serves as the group's hub.
        val port = DatagramSocket(0, InetAddress.getLoopbackAddress()).use { it.localPort }
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(60)
        while (true) {
            val e = runCatching { a.serveAsHub(port, listOf("127.0.0.1:$port")) }.exceptionOrNull() ?: break
            assertTrue(System.nanoTime() < deadline, "the admin phone never became a hub: $e")
            Thread.sleep(200)
        }
        var inviting: CorePairing.Inviting? = null
        while (inviting == null) {
            val got = runCatching { CorePairing.Inviting(a, aAdmin.publicKeyDER, 600, kind = "phone", sign = aAdmin::signDigest) }
            inviting = got.getOrNull()
            if (inviting == null) {
                assertTrue(System.nanoTime() < deadline, "the hub never opened the invitation: ${got.exceptionOrNull()}")
                Thread.sleep(200)
            }
        }
        inviting.use { inv ->
            assertTrue(inv.text.startsWith("cbb://join#"), inv.text)
            val key = SoftwareSigner()
            val joiner = CorePairing.Joiner(File(top, "far").path, "", "Far phone", "android", key.publicKeyDER, key::signDigest, invite = inv.text)
            joiner.use {
                assertTrue(joiner.fingerprint.isNotEmpty(), "the phone shows its fingerprint")
                val asked = until("joining", { it.state }, { it.version }, { it.failure }) { inv.next(it, 100) }
                assertEquals("Far phone", asked.request?.name)
                assertEquals(joiner.fingerprint, asked.request?.fingerprint, "the inviting phone asks about the fingerprint the joiner shows")
                inv.answer(true)
                val done = until("done", { it.state }, { it.version }, { it.failure }) { joiner.next(it, 100) }
                assertTrue(done.answered, "the hub answered through the guest tunnel")
                assertEquals(made.group, done.group, "the phone joined the group of the invitation")
                assertEquals("Far phone", until("done", { it.state }, { it.version }, { it.failure }) { inv.next(it, 100) }.name)
            }
            assertFailsWith<IllegalStateException>("a closed joiner says no more") { joiner.next(0, 10) }
        }
    }

    /** A phone joins by an invitation of 0.6 (cbb://join#); a text that is none fails at once, before any dialing. */
    @Test
    fun aJoinerRefusesABadInvitation() {
        val key = SoftwareSigner()
        for (text in listOf("cbb://join#{}", "cbb://invite#{}", "not an invitation")) {
            assertFailsWith<CorePairing.Failure>(text) {
                CorePairing.Joiner(File(top, "far").path, "", "Far phone", "android", key.publicKeyDER, key::signDigest, invite = text).close()
            }
        }
    }

    /** A root phone that is no hub, with no hub connected: its invitation has nowhere to open and says so. */
    @Test
    fun anAdminWithoutAHubCannotInvite() {
        val root = SoftwareSigner()
        val key = SoftwareSigner()
        val dir = File(top, "root")
        val made = CorePairing.newGroup(dir, "Root phone", "android", Records.HARDWARE, root.publicKeyDER, key.publicKeyDER, root::signDigest)
        val m = CoreMember.start(
            CoreMember.Start(dir, "Root phone", "android", "17", "0.6.0", device = made.device, publicKey = key.publicKeyDER),
            key::signDigest,
            events = { },
        )
        members += m

        assertFailsWith<CorePairing.Failure> { CorePairing.Inviting(m, root.publicKeyDER, 600, sign = root::signDigest) }
        // Its own device ID as the hub, while it is none.
        assertFailsWith<CorePairing.Failure> { CorePairing.Inviting(m, root.publicKeyDER, 600, hub = made.device, sign = root::signDigest) }
        // A key that is not the group's root or an admin.
        val other = SoftwareSigner()
        assertFailsWith<CorePairing.Failure> { CorePairing.Inviting(m, other.publicKeyDER, 600, sign = other::signDigest) }
        assertFailsWith<CorePairing.Failure> { CorePairing.Inviting(m, root.publicKeyDER, 600, hub = "not a device", sign = root::signDigest) }
    }
}
