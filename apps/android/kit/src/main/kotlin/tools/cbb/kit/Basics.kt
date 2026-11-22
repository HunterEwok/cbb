// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PublicKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec

/**
 * A P-256 key that signs certificates: a software key in tests, a key in
 * the Android Keystore in the app, which never leaves it.
 */
interface CertificateSigner {
    /** The public key as a SubjectPublicKeyInfo, DER. */
    val publicKeyDER: ByteArray

    /** An ECDSA signature with SHA-256 over data, DER. */
    fun signature(data: ByteArray): ByteArray

    /** An ECDSA signature, DER, of a SHA-256 digest: what the Rust core's signing callback asks for; not every key gives one. */
    fun signDigest(digest: ByteArray): ByteArray = throw UnsupportedOperationException("this key signs only whole data")
}

/** A software P-256 key as a CertificateSigner. */
class SoftwareSigner(val keyPair: KeyPair = generate()) : CertificateSigner {
    override val publicKeyDER: ByteArray get() = keyPair.public.encoded

    override fun signature(data: ByteArray): ByteArray =
        Signature.getInstance("SHA256withECDSA").run {
            initSign(keyPair.private)
            update(data)
            sign()
        }

    /** An ECDSA signature, DER, of a SHA-256 digest: what the Rust member's signing callback asks for. */
    override fun signDigest(digest: ByteArray): ByteArray =
        Signature.getInstance("NONEwithECDSA").run {
            initSign(keyPair.private)
            update(digest)
            sign()
        }

    companion object {
        fun generate(): KeyPair =
            KeyPairGenerator.getInstance("EC").run {
                initialize(ECGenParameterSpec("secp256r1"))
                generateKeyPair()
            }
    }
}

/** The DER header of a P-256 SubjectPublicKeyInfo with an uncompressed point. */
private val P256_SPKI_PREFIX = byteArrayOf(
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86.toByte(), 0x48, 0xce.toByte(), 0x3d, 0x02, 0x01,
    0x06, 0x08, 0x2a, 0x86.toByte(), 0x48, 0xce.toByte(), 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
)

/** The SubjectPublicKeyInfo of a P-256 public key given as an uncompressed point (0x04, X, Y); null for anything else. */
internal fun p256SPKI(point: ByteArray): ByteArray? {
    if (point.size != 65 || point[0] != 0x04.toByte()) return null
    val spki = P256_SPKI_PREFIX + point.copyOfRange(1, 65)
    return spki.takeIf { p256PublicKey(it) != null }
}

/** The P-256 public key of a SubjectPublicKeyInfo, or null for anything else. */
internal fun p256PublicKey(spki: ByteArray): PublicKey? {
    if (spki.size != 91 || !spki.copyOf(P256_SPKI_PREFIX.size).contentEquals(P256_SPKI_PREFIX)) return null
    // The JDK's KeyFactory takes a point that is not on the curve; Go, Rust and Swift refuse it.
    if (!onP256(spki.copyOfRange(27, 59), spki.copyOfRange(59, 91))) return null
    return try {
        KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(spki))
    } catch (e: java.security.GeneralSecurityException) {
        null
    }
}

private val P256_P = BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16)
private val P256_B = BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16)

/** Whether (x, y), big-endian, is a point of P-256: both below p and y^2 = x^3 - 3x + b mod p. */
private fun onP256(xb: ByteArray, yb: ByteArray): Boolean {
    val x = BigInteger(1, xb)
    val y = BigInteger(1, yb)
    if (x >= P256_P || y >= P256_P) return false
    val right = x.pow(3).subtract(x.multiply(BigInteger.valueOf(3))).add(P256_B).mod(P256_P)
    return y.multiply(y).mod(P256_P) == right
}

/** Whether sig (DER) is an ECDSA SHA-256 signature by spki over data. */
internal fun verifySignature(spki: ByteArray, data: ByteArray, sig: ByteArray): Boolean {
    val key = p256PublicKey(spki) ?: return false
    return try {
        Signature.getInstance("SHA256withECDSA").run {
            initVerify(key)
            update(data)
            verify(sig)
        }
    } catch (e: Exception) {
        false
    }
}

internal fun sha256(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(b)

internal fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

/**
 * What the group's records name that the app reads too: device IDs and
 * names, key hashes, where a device's keys live and the group's key levels
 * (docs/protocol.md, section 17). The member keeps the records themselves.
 */
object Records {
    /** Whether s is a device ID: 32 of 0-9 and a-f. */
    fun isDeviceID(s: String?): Boolean = s != null && s.length == 32 && s.all { it in '0'..'9' || it in 'a'..'f' }

    /** Whether s is a device name: 1 to 64 bytes of UTF-8 without control characters. */
    fun validName(s: String?): Boolean =
        s != null && s.isNotEmpty() && s.toByteArray().size <= 64 && s.codePoints().noneMatch { Character.isISOControl(it) }

    /** The hash that names a key in records: SHA-256 over a SubjectPublicKeyInfo. */
    fun keyHash(spki: ByteArray): ByteArray = sha256(spki)

    const val FILE = "file"
    const val HARDWARE = "hardware"

    /** How long a copy from another device stays live after it arrives without a copies record, and the bounds of one, in milliseconds. */
    const val DEFAULT_INCOMING_MS = 60_000L
    val INCOMING_BOUNDS = 5_000L..3_600_000L

    /** A key in hardware whose attestation a signer checked. */
    const val PROVEN = "proven"

    /**
     * A rootless install's keys: in a file every program of its user may
     * read, so the device is never the root, an admin or a hub (D-79).
     */
    const val ROOTLESS = "rootless"

    /**
     * The group's key levels (docs/guide/keys.md, "The three levels"): which
     * keys may be its root, an admin or a hub. The levels proven and
     * hardware share their names with the stores they let in; files lets in
     * keys in files too, each after a warning.
     */
    const val LEVEL_FILES = "files"
    val KEY_LEVELS = listOf(PROVEN, HARDWARE, LEVEL_FILES)

    /** Whether the key level lets a device whose keys are in store be the group's root, an admin or a hub; a key in a file needs consent too. */
    fun levelAllows(level: String, store: String, consent: Boolean): Boolean = when (store) {
        ROOTLESS -> false
        PROVEN -> true
        FILE -> level == LEVEL_FILES && consent
        else -> level != PROVEN
    }

    /**
     * Where a device's keys live, as a hello's key_store or a record's store
     * says (docs/protocol.md, section 17): FILE, HARDWARE, PROVEN or ROOTLESS.
     * Without one, or with one this version does not know, a phone's and a
     * watch's keys are in hardware and any other device's in a file.
     */
    fun storeOf(store: String?, role: String): String = when (store) {
        FILE, HARDWARE, PROVEN, ROOTLESS -> store
        else -> if (role == "phone" || role == "watch") HARDWARE else FILE
    }
}
