// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import java.security.SecureRandom
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class HubKindTest {
    /**
     * A computer that only passes the copies on may be a hub, and no copy is
     * sealed to it from then on; the root's own device cannot be one.
     */
    @Test
    fun forwardOnlyHub() {
        val now = Instant.now()
        val ca = SoftwareSigner()
        val ka = SoftwareSigner()
        val kb = SoftwareSigner()
        fun secret() = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val sa = secret()
        val g = PhoneGroup.create(ca, ka.publicKeyDER, now, seal = Core.sealPublic(sa))
        val pc = SyncEngine.newID()
        g.record(pc, "pi", "full", Records.keyHash(kb.publicKeyDER), ca, now, os = "linux", store = Records.FILE, seal = Core.sealPublic(secret()))
        assertFalse(g.records.mayHost(pc))
        val engine = SyncEngine(g.device, HybridClock())
        val e = engine.local("before", Member.Kind.TEXT)
        fun readers() = CopyKeys(g.device, g.memberCert, null, ka, sa) { g.records }.seal(e, null, null).wraps.map { it.to }
        assertTrue(pc in readers())

        assertNotNull(g.markForwardOnly(pc, ca, now))
        assertEquals(true, g.devices.first { it.id == pc }.forwardOnly)
        assertTrue(g.records.mayHost(pc))
        assertNull(g.markForwardOnly(pc, ca, now))
        assertFalse(pc in readers())
        // A rename keeps it.
        g.rename(pc, "router", ca, now)
        assertEquals(true, g.devices.first { it.id == pc }.forwardOnly)
        // The root's own device reads the copies.
        assertFailsWith<Exception> { g.markForwardOnly(g.device, ca, now) }
    }
}
