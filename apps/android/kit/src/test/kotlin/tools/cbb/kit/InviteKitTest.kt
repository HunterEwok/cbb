// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import java.io.File
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.time.Instant
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.io.path.createTempDirectory
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/**
 * Remote invitations in the kit (docs/protocol.md, section 12): reading one, a phone that joins by one through its
 * guest tunnel, and an admin phone that has no hub to invite through. The whole way, a phone that joins and one that
 * invites through a computer hub, is tested in Go (internal/service, TestFFIJoinInvite, TestFFIInviteThroughHub).
 */
class InviteKitTest {
    private val top: File = createTempDirectory("cbb-invite-kit").toFile()
    private val members = mutableListOf<CoreMember>()
    private val pool = Executors.newCachedThreadPool()
    private val hubID = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
    private val tag = "0123456789abcdef"

    @AfterTest
    fun cleanUp() {
        members.forEach { it.close() }
        pool.shutdownNow()
        top.deleteRecursively()
    }

    /** A hub on the loopback address whose guests reach member, and an invitation it opened toward it. */
    private fun <T> withInvitation(member: ServerSocket, f: (RustTunnel.Guest) -> T): T {
        val hub = RustTunnel.startHub(RustTunnel.newKey(), hubID, member.localPort, "", "[]")
        try {
            val g = hub.invite(tag, "[\"127.0.0.1:${hub.udpPort()}\"]", 600, member.localPort)
            try {
                return f(g)
            } finally {
                g.close()
            }
        } finally {
            hub.close()
        }
    }

    @Test
    fun readsAnInvitationAndRefusesOthers() {
        ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { member ->
            withInvitation(member) { g ->
                val read = assertIs<Core.InviteReading.Read>(Core.readInvite(g.text))
                assertEquals(tag, read.invitation.group)
                assertEquals(hubID, read.invitation.hub)
                assertTrue(read.invitation.expires > Instant.now().epochSecond, "it expires later")
            }
        }
        val refused = assertIs<Core.InviteReading.Refused>(Core.readInvite("cbb://invite#{}"))
        assertTrue(refused.reason.isNotEmpty())
        assertTrue(refused.message.isNotEmpty())
        assertIs<Core.InviteReading.Refused>(Core.readInvite("not an invitation"))
    }

    /**
     * A phone that joins by an invitation dials its guest tunnel's loopback port and speaks first; here the
     * invitation's window is a socket that hangs up, so the attempt fails after the hub answered the tunnel.
     */
    @Test
    fun joinsThroughTheGuestTunnel() {
        ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { member ->
            withInvitation(member) { g ->
                val key = SoftwareSigner()
                val joining = CorePairing.Joining(
                    "Far phone", "android", key.publicKeyDER, Core.sealPublic(CoreGroup.SEAL), emptyList(), key::signDigest, invite = g.text,
                )
                try {
                    assertNotEquals(0, joining.port, "the guest tunnel has a loopback port")
                    assertTrue(joining.fingerprint.isNotEmpty(), "the phone shows its fingerprint")
                    // The invitation's window: it takes the joiner's first bytes and hangs up.
                    val window = pool.submit<Int> {
                        member.soTimeout = 15_000
                        member.accept().use { s ->
                            s.soTimeout = 15_000
                            s.getInputStream().read(ByteArray(512))
                        }
                    }
                    Socket(InetAddress.getLoopbackAddress(), joining.port).use { s ->
                        s.soTimeout = 15_000
                        assertFailsWith<Exception> { joining.attempt(s) { true } }
                    }
                    assertTrue(window.get(20, TimeUnit.SECONDS) > 0, "the joiner spoke first, through the tunnel")
                    assertTrue(joining.answered, "the hub answered through the guest tunnel")
                } finally {
                    joining.close()
                }
                assertFalse(joining.answered, "a closed joiner says no more")
            }
        }
    }

    @Test
    fun aJoinerRefusesABadInvitation() {
        val key = SoftwareSigner()
        assertFailsWith<CorePairing.Failure> {
            CorePairing.Joining("Far phone", "android", key.publicKeyDER, Core.sealPublic(CoreGroup.SEAL), emptyList(), key::signDigest, invite = "cbb://invite#{}")
        }
    }

    @Test
    fun theGuestTunnelOfAnInvitation() {
        ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { member ->
            withInvitation(member) { g ->
                val t = RustTunnel.guest(g.text)
                try {
                    assertNotEquals(0, t.port)
                } finally {
                    t.close()
                }
            }
        }
        assertFailsWith<RustTunnel.Failure> { RustTunnel.guest("cbb://invite#{}") }
    }

    /** A root phone that is no hub, with no hub connected: its invitation has nowhere to open and says so. */
    @Test
    fun anAdminWithoutAHubCannotInvite() {
        val root = SoftwareSigner()
        val key = SoftwareSigner()
        val made = CorePairing.newGroup("Root phone", "android", Records.HARDWARE, root.publicKeyDER, key.publicKeyDER, Core.sealPublic(CoreGroup.SEAL), root::signDigest)
        val g = PhoneGroup.of(made, root = true)
        val m = CoreMember.start(
            CoreMember.Start(File(top, "root").apply { mkdirs() }, "Root phone", "android", "17", "0.6.0", device = g.device, publicKey = key.publicKeyDER,
                seal = CoreGroup.SEAL, cert = g.memberCert, groupCA = g.groupCA, roots = g.trusted),
            key::signDigest,
            events = { },
        )
        members += m
        m.addRecords(g.records.records)

        assertFailsWith<CorePairing.Failure> { CorePairing.Inviting(m, root.publicKeyDER, null, 600, sign = root::signDigest) }
        // Its own device ID as the hub, while it is none.
        assertFailsWith<CorePairing.Failure> { CorePairing.Inviting(m, root.publicKeyDER, null, 600, hub = g.device, sign = root::signDigest) }
        // A key that is not the CA's.
        val other = SoftwareSigner()
        assertFailsWith<CorePairing.Failure> { CorePairing.Inviting(m, other.publicKeyDER, null, 600, sign = other::signDigest) }
        assertFailsWith<CorePairing.Failure> { CorePairing.Inviting(m, root.publicKeyDER, null, 600, hub = "not a device", sign = root::signDigest) }
    }
}
