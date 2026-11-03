// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import java.security.SecureRandom

/**
 * The challenge a phone's key is made with, so that the key's attestation
 * (Android's Key Attestation, later Apple's App Attest) proves it belongs
 * to this device and, when there is one, this group
 * (docs/protocol.md, section 17). It is no live nonce: the key itself
 * is bound by the attestation's leaf certificate, and whoever presents the
 * key proves holding it in member TLS, so the proof can be made with the
 * key, offline, and shown later.
 *
 *     SHA-256("cbb attest v1" || field(group tag) || field(member key) || salt)
 *
 * field is a two-byte big-endian length and the bytes; the group tag is
 * empty while the phone is in no group, and the member key (its SPKI) is
 * empty for the member key itself. The salt is 16 random bytes kept with
 * the key and shown with its evidence.
 */
object Attestation {
    const val SALT_SIZE = 16
    private val PREFIX = "cbb attest v1".toByteArray()

    fun newSalt(): ByteArray = ByteArray(SALT_SIZE).also { SecureRandom().nextBytes(it) }

    fun challenge(groupTag: String, memberKey: ByteArray, salt: ByteArray): ByteArray {
        require(salt.size == SALT_SIZE) { "the salt is ${salt.size} bytes" }
        val tag = groupTag.toByteArray()
        return sha256(PREFIX + field(tag) + field(memberKey) + salt)
    }

    private fun field(b: ByteArray): ByteArray {
        require(b.size <= 0xFFFF) { "a field of ${b.size} bytes" }
        return byteArrayOf((b.size shr 8).toByte(), b.size.toByte()) + b
    }
}
