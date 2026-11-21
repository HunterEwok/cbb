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

    /** A root phone: the group the core made with its root key, and its member running. */
    private class Root(val root: SoftwareSigner, val group: PhoneGroup, val member: CoreMember)

    private fun root(): Root {
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
        return Root(root, g, m)
    }

    @Test
    fun newGroupHasTheRootAndItsPhone() {
        val r = root()
        assertTrue(r.group.isRoot)
        assertNull(r.group.adminCA)
        val me = r.group.devices.single()
        assertEquals(r.group.device, me.id)
        assertEquals("phone", me.role)
        // The member certificate comes from the group's root, whose key signed it.
        assertContentEquals(r.root.publicKeyDER, CertificateInfo(r.group.groupCA).publicKey)
    }
}
