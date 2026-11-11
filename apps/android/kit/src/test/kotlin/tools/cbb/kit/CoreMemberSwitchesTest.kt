// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import java.io.File
import kotlin.io.path.createTempDirectory
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals

/** The switches the app turns on a phone's member with no other member around: pausing, sync, muting, ports and dialing. */
class CoreMemberSwitchesTest {
    private val top: File = createTempDirectory("cbb-member-switches").toFile()
    private val members = mutableListOf<CoreMember>()

    @AfterTest
    fun cleanUp() {
        members.forEach { it.close() }
        top.deleteRecursively()
    }

    private fun rootPhone(): CoreMember {
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
        return m
    }

    @Test
    fun switches() {
        val m = rootPhone()
        m.pause()
        m.resume()
        assertFalse(m.waitConnected(50), "no member connects")

        m.setSync(false, 60_000)
        m.setSync(true)
        assertFailsWith<Exception> { m.setSync(true, 60_000) }

        m.setMute(0)
        m.setMute(null)

        val port = m.listen()
        assertNotEquals(0, port)
        m.unlisten()
        // A member that is not there: the member keeps dialing it until the app lost it.
        m.found("nsd-name", listOf("127.0.0.1:9"))
        m.lost("nsd-name")
        assertEquals(emptyList(), m.sendHubs(Member.HubShare()), "no member to share the hubs with")
    }
}
