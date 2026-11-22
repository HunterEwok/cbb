// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import java.io.File
import kotlin.io.path.createTempDirectory
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Making a group through the Rust core (CorePairing), as the apps do; joining by a pairing window is in the window's tests. */
class CorePairingTest {
    private val top: File = createTempDirectory("cbb-core-pairing").toFile()
    private val members = mutableListOf<CoreMember>()

    @AfterTest
    fun cleanUp() {
        members.forEach { it.close() }
        top.deleteRecursively()
    }

    @Test
    fun newGroupHasTheRootAndItsPhone() {
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
        val g = m.group()
        assertTrue(g.isRoot, "the phone that made the group holds its root")
        assertEquals(made.device, g.rootDevice)
        val me = g.devices.single()
        assertEquals(made.device, me.device)
        assertEquals("phone", me.role)
        assertEquals(Records.HARDWARE, g.keyLevel)
        assertNull(g.ttlMS, "no copies record yet")
        assertNull(g.secretTtlMS, "no copies record yet")
    }
}
