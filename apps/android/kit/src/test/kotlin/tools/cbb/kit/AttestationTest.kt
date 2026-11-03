// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class AttestationTest {
    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

    @Test
    fun challenge() {
        val salt = ByteArray(16) { it.toByte() }
        // The same as Go's and Swift's, once they check evidence.
        val c = Attestation.challenge("", ByteArray(0), salt)
        assertContentEquals(
            sha256("cbb attest v1".toByteArray() + byteArrayOf(0, 0, 0, 0) + salt),
            c,
        )
        // Moving bytes between the fields changes it.
        val a = Attestation.challenge("ab", byteArrayOf(1), salt)
        // The same value as Go's internal/attest TestChallenge.
        assertEquals("aac189125c2fbb83190c46e0864cc0c74f3463664c6b0c71bf8911a18a1723d8", hex(a))
        val b = Attestation.challenge("a", "b".toByteArray() + byteArrayOf(1), salt)
        assertFalse(hex(a) == hex(b))
        assertFailsWith<IllegalArgumentException> { Attestation.challenge("", ByteArray(0), ByteArray(15)) }
        assertTrue(Attestation.newSalt().size == Attestation.SALT_SIZE)
    }
}
