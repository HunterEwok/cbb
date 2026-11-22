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
        val dir = File(top, "root")
        val made = CorePairing.newGroup(dir, "Root phone", "android", Records.HARDWARE, root.publicKeyDER, key.publicKeyDER, root::signDigest)
        val m = CoreMember.start(
            CoreMember.Start(dir, "Root phone", "android", "17", "0.6.0", device = made.device, publicKey = key.publicKeyDER),
            key::signDigest,
            events = { },
        )
        members += m
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
    }
}
