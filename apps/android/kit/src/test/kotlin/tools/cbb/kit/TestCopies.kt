// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import java.security.SecureRandom
import java.time.Instant

/**
 * A group of a phone and a computer whose copies are sealed end to end, for
 * tests of two nodes: each side's CopyKeys over the same records.
 */
class TestCopies(roleB: String = "full") {
    val a: CopyKeys
    val b: CopyKeys

    /** The computer with a secret its record does not name: copies sealed to it do not open. */
    val bLost: CopyKeys
    val idA: String get() = a.device
    val idB: String get() = b.device

    init {
        val now = Instant.now()
        val ca = SoftwareSigner()
        val ka = SoftwareSigner()
        val kb = SoftwareSigner()
        fun secret() = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val sa = secret()
        val sb = secret()
        val g = PhoneGroup.create(ca, ka.publicKeyDER, now, seal = Core.sealPublic(sa))
        val idB = SyncEngine.newID()
        val certB = GroupCertificates.member(idB, kb.publicKeyDER, g.groupCA, ca, now)
        g.record(idB, "pi", roleB, Records.keyHash(kb.publicKeyDER), ca, now, os = "linux", store = Records.FILE, seal = Core.sealPublic(sb))
        val set = g.records
        a = CopyKeys(g.device, g.memberCert, null, ka, sa) { set }
        b = CopyKeys(idB, certB, null, kb, sb) { set }
        bLost = CopyKeys(idB, certB, null, kb, secret()) { set }
    }
}
