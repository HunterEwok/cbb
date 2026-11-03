// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import java.io.ByteArrayInputStream
import java.security.KeyFactory
import java.security.PublicKey
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

/**
 * Checks an Android Key Attestation chain, as Go's internal/attest
 * CheckAndroid does (docs/protocol.md, section 17): the leaf certifies the
 * key and carries the Keystore's description of it, every certificate that
 * signs another is a CA that may sign it, and the chain leads to
 * one of Google's attestation roots. testdata/interop/go-attest.json keeps
 * the two in step.
 */
object AndroidAttestation {
    /**
     * The SubjectPublicKeyInfos of Google's attestation roots: the RSA root
     * of every chain until 2026 and the ECDSA P-384 "Key Attestation CA1".
     */
    val googleRoots: List<ByteArray> = listOf(
        "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdSSxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggjnar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGqC4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQoVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+OJtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/EgsTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRiigHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+MRPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9EaDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+NpUFgNPN9PvQi8WEg5UmAGMCAwEAAQ==",
        "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEI9ojcU7fPlsFCjxy6IRqzgeOoK0b+YsV9FPQywiyw8EQRTkJ9u3qwfnI4DGoSLlBqClTXJfgfCcZvs60FikNMHnu4fkRzObfgDkU2KNXezT9/RQ+XvNslxPHrHCowhGr",
    ).map { Base64.getDecoder().decode(it) }

    const val KIND_TEE = "android-tee"
    const val KIND_STRONGBOX = "android-strongbox"

    /** What a valid attestation shows of a key; [why] is "" when its store is [Records.PROVEN]. */
    data class Result(val store: String, val kind: String, val rkp: Boolean, val why: String, val serials: List<String>)

    /** Strict proves only chains of Remote Key Provisioning; [revoked] holds lowercase hex serials. */
    data class Policy(val strict: Boolean = false, val revoked: Set<String> = emptySet(), val roots: List<ByteArray>? = null)

    /** An attestation that proves nothing: a broken chain, another root, key or challenge, a revoked certificate ([revoked]). */
    class Invalid(message: String, val revoked: Boolean = false) : Exception("invalid attestation: $message")

    private const val OID_KEY_DESCRIPTION = "1.3.6.1.4.1.11129.2.1.17"
    private const val OID_PROVISIONING = "1.3.6.1.4.1.11129.2.1.30"
    private const val LEVEL_SOFTWARE = 0
    private const val LEVEL_STRONGBOX = 2
    private const val BOOT_VERIFIED = 0
    private const val BOOT_SELF_SIGNED = 1
    private const val TAG_ROOT_OF_TRUST = 704

    /** keyCertSign's index in X509Certificate.getKeyUsage. */
    private const val KEY_CERT_SIGN = 5

    /**
     * Checks [chain] (DER certificates, leaf first) for the key [spki] made
     * with [challenge]; throws [Invalid] when it proves nothing.
     */
    fun check(chain: List<ByteArray>, spki: ByteArray, challenge: ByteArray, policy: Policy = Policy()): Result {
        if (chain.size < 2 || chain.size > 10) throw Invalid("a chain of ${chain.size} certificates")
        val factory = CertificateFactory.getInstance("X.509")
        val certs = chain.mapIndexed { i, der ->
            try {
                factory.generateCertificate(ByteArrayInputStream(der)) as X509Certificate
            } catch (e: Exception) {
                throw Invalid("certificate $i: ${e.message}")
            }
        }
        val serials = certs.map { it.serialNumber.toString(16) }
        var rkp = false
        certs.forEachIndexed { i, c ->
            if (i + 1 < certs.size && !verifies(c, certs[i + 1].publicKey)) {
                throw Invalid("certificate $i is not signed by the next")
            }
            if (serials[i] in policy.revoked) throw Invalid("certificate $i (${serials[i]}) is revoked", revoked = true)
            if (i == 0) return@forEachIndexed // the leaf signs nothing and says nothing of provisioning
            // Every other certificate signed the one before it: it must be a CA
            // that may sign certificates, with a path length that fits.
            val pathLen = c.basicConstraints // -1 without a CA, Int.MAX_VALUE for a CA without a limit
            if (pathLen < 0) throw Invalid("certificate $i signs another and is not a CA")
            val usage = c.keyUsage
            if (usage != null && !(usage.size > KEY_CERT_SIGN && usage[KEY_CERT_SIGN])) {
                throw Invalid("certificate $i signs another and may not sign certificates")
            }
            if (pathLen < i - 1) throw Invalid("certificate $i allows $pathLen CAs below it, the chain has ${i - 1}")
            if (OID_PROVISIONING in c.oids()) rkp = true
        }
        val last = certs.last()
        if ((policy.roots ?: googleRoots).none { r -> publicKey(r)?.let { verifies(last, it) } == true }) {
            throw Invalid("the chain does not lead to a known root")
        }
        val leaf = certs[0]
        val leafKey = try {
            subjectPublicKeyInfo(leaf.tbsCertificate)
        } catch (e: MalformedException) {
            throw Invalid("the leaf: ${e.message}")
        }
        if (!leafKey.contentEquals(spki)) throw Invalid("the leaf certifies another key")
        val ext = leaf.getExtensionValue(OID_KEY_DESCRIPTION) ?: throw Invalid("the leaf has no key description")
        val kd = try {
            KeyDescription.parse(Tlv.read(ext, 0).expect(0x04).content(ext))
        } catch (e: MalformedException) {
            throw Invalid("the key description: ${e.message}")
        }
        if (!kd.challenge.contentEquals(challenge)) throw Invalid("another challenge")
        if (kd.attestationLevel == LEVEL_SOFTWARE || kd.keyMintLevel == LEVEL_SOFTWARE) {
            return Result(Records.FILE, "", rkp, "the Keystore keeps the key in software", serials)
        }
        val kind = if (kd.attestationLevel == LEVEL_STRONGBOX && kd.keyMintLevel == LEVEL_STRONGBOX) KIND_STRONGBOX else KIND_TEE
        val why = when {
            kd.root == null -> "the key description has no root of trust"
            !kd.root.locked -> "the phone's bootloader is unlocked"
            kd.root.state == BOOT_SELF_SIGNED -> "the phone boots a system signed with its own key"
            kd.root.state != BOOT_VERIFIED -> "the phone's boot is not verified"
            policy.strict && !rkp -> "the chain did not come through Remote Key Provisioning"
            else -> ""
        }
        return Result(if (why == "") Records.PROVEN else Records.HARDWARE, kind, rkp, why, serials)
    }

    private fun X509Certificate.oids(): Set<String> =
        (criticalExtensionOIDs ?: emptySet()) + (nonCriticalExtensionOIDs ?: emptySet())

    private fun verifies(c: X509Certificate, key: PublicKey): Boolean = try {
        c.verify(key)
        true
    } catch (e: Exception) {
        false
    }

    private fun publicKey(spki: ByteArray): PublicKey? {
        for (alg in listOf("EC", "RSA")) {
            try {
                return KeyFactory.getInstance(alg).generatePublic(X509EncodedKeySpec(spki))
            } catch (e: Exception) {
                continue
            }
        }
        return null
    }

    /** The subjectPublicKeyInfo of a TBSCertificate, as its bytes stand. */
    private fun subjectPublicKeyInfo(tbs: ByteArray): ByteArray {
        val fields = Tlv.read(tbs, 0).expect(0x30).children(tbs)
        // version [0] is optional; then serial, signature, issuer, validity, subject.
        val skip = if (fields.firstOrNull()?.let { it.cls == 2 && it.number == 0 } == true) 6 else 5
        return fields.getOrNull(skip)?.full(tbs) ?: throw MalformedException("no subjectPublicKeyInfo")
    }

    private class RootOfTrust(val locked: Boolean, val state: Int)

    private class KeyDescription(val attestationLevel: Int, val keyMintLevel: Int, val challenge: ByteArray, val root: RootOfTrust?) {
        companion object {
            /** attestationVersion, attestationSecurityLevel, keyMintVersion, keyMintSecurityLevel, attestationChallenge, uniqueId, softwareEnforced, hardwareEnforced. */
            fun parse(der: ByteArray): KeyDescription {
                val top = Tlv.read(der, 0)
                if (top.tag != 0x30 || top.end != der.size) throw MalformedException("not a sequence")
                val f = top.children(der)
                if (f.size < 8) throw MalformedException("${f.size} fields")
                val challenge = f[4].expect(0x04).content(der)
                var root: RootOfTrust? = null
                for (a in f[7].expect(0x30).children(der)) {
                    if (a.cls != 2 || a.number != TAG_ROOT_OF_TRUST) continue
                    val r = a.children(der).single().expect(0x30).children(der)
                    if (r.size < 3) throw MalformedException("rootOfTrust")
                    val locked = r[1].expect(0x01).content(der)
                    if (locked.size != 1) throw MalformedException("deviceLocked")
                    root = RootOfTrust(locked[0] != 0.toByte(), enumerated(r[2], der))
                }
                return KeyDescription(enumerated(f[1], der), enumerated(f[3], der), challenge, root)
            }

            private fun enumerated(t: Tlv, der: ByteArray): Int {
                val b = t.expect(0x0a).content(der)
                if (b.isEmpty() || b.size > 4) throw MalformedException("an enumerated of ${b.size} bytes")
                return b.fold(if (b[0] < 0) -1 else 0) { v, x -> (v shl 8) or (x.toInt() and 0xff) }
            }
        }
    }

    /**
     * One DER element at [start] of a buffer, with the tags above 30 that
     * the Keystore's authorization lists use. [tag] is the first byte;
     * [cls] (0 universal, 2 context-specific) and [number] the tag itself.
     */
    private class Tlv(val start: Int, val tag: Int, val cls: Int, val number: Int, val body: Int, val end: Int) {
        fun content(b: ByteArray): ByteArray = b.copyOfRange(body, end)
        fun full(b: ByteArray): ByteArray = b.copyOfRange(start, end)
        fun expect(t: Int): Tlv = if (tag == t) this else throw MalformedException("tag ${"%02x".format(tag)}, not ${"%02x".format(t)}")

        fun children(b: ByteArray): List<Tlv> {
            if (tag and 0x20 == 0) throw MalformedException("a primitive element")
            val out = mutableListOf<Tlv>()
            var p = body
            while (p < end) {
                val t = read(b, p, end)
                out += t
                p = t.end
            }
            return out
        }

        companion object {
            fun read(b: ByteArray, start: Int, limit: Int = b.size): Tlv {
                var p = start
                fun next(): Int = if (p < limit) b[p++].toInt() and 0xff else throw MalformedException("truncated")
                val tag = next()
                var number = tag and 0x1f
                if (number == 0x1f) {
                    number = 0
                    do {
                        val x = next()
                        if (number > 0xffff) throw MalformedException("a tag too long")
                        number = (number shl 7) or (x and 0x7f)
                    } while (x and 0x80 != 0)
                }
                var n = next()
                if (n and 0x80 != 0) {
                    val k = n and 0x7f
                    if (k == 0 || k > 3) throw MalformedException("a length of $k bytes")
                    n = 0
                    repeat(k) { n = (n shl 8) or next() }
                }
                if (n > limit - p) throw MalformedException("truncated")
                return Tlv(start, tag, tag shr 6, number, p, p + n)
            }
        }
    }
}
