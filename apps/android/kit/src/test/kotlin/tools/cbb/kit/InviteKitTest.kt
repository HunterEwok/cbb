// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import java.io.File
import kotlin.io.path.createTempDirectory
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * Remote invitations in the kit (docs/protocol.md, section 12): reading one, a bad invitation, and an admin phone
 * that has no hub to invite through. A phone that joins through a computer hub and one that invites through a computer
 * hub are tested in Go (internal/service, TestFFIJoinInvite, TestFFIInviteThroughHub).
 */
class InviteKitTest {
    private val top: File = createTempDirectory("cbb-invite-kit").toFile()
    private val members = mutableListOf<CoreMember>()

    @AfterTest
    fun cleanUp() {
        members.forEach { it.close() }
        top.deleteRecursively()
    }

    /** What is no invitation of 0.6 is refused with a reason and a sentence: an invitation of 0.5 among them. */
    @Test
    fun refusesWhatIsNoInvitation() {
        for (text in listOf("cbb://invite#e30", "cbb://join#", "not an invitation", "")) {
            val refused = assertIs<Core.InviteReading.Refused>(Core.readInvite(text), text)
            assertTrue(refused.reason.isNotEmpty(), text)
            assertTrue(refused.message.isNotEmpty(), text)
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
        // Its own device ID as the hub: a phone is none.
        assertFailsWith<CorePairing.Failure> { CorePairing.Inviting(m, root.publicKeyDER, 600, hub = made.device, sign = root::signDigest) }
        // A key that is not the group's root or an admin.
        val other = SoftwareSigner()
        assertFailsWith<CorePairing.Failure> { CorePairing.Inviting(m, other.publicKeyDER, 600, sign = other::signDigest) }
        assertFailsWith<CorePairing.Failure> { CorePairing.Inviting(m, root.publicKeyDER, 600, hub = "not a device", sign = root::signDigest) }
    }
}
