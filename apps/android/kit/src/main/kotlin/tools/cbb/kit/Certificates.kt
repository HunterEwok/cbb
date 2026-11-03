// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

/**
 * A P-256 key that signs certificates: a software key in tests, a key in
 * the Android Keystore in the app, which never leaves it.
 */
interface CertificateSigner {
    /** The public key as a SubjectPublicKeyInfo, DER. */
    val publicKeyDER: ByteArray

    /** An ECDSA signature with SHA-256 over data, DER. */
    fun signature(data: ByteArray): ByteArray
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
 * The group's certificates, with the profiles of docs/protocol.md,
 * section 2, as the Go side issues them (internal/group/cert.go).
 */
object GroupCertificates {
    /** How long a member certificate lasts. */
    const val MEMBER_YEARS = 2L

    /** How long the group CA lasts. */
    const val CA_YEARS = 20L

    /** Certificates start this much before now, for clocks a little behind. */
    const val BACKDATE_SECONDS = 24L * 3600

    /** A member certificate is renewed when less than this much remains. */
    const val RENEW_BEFORE_SECONDS = 240L * 24 * 3600

    internal const val OID_EC_PUBLIC_KEY = "1.2.840.10045.2.1"
    internal const val OID_ECDSA_WITH_SHA256 = "1.2.840.10045.4.3.2"
    internal const val OID_COMMON_NAME = "2.5.4.3"
    internal const val OID_BASIC_CONSTRAINTS = "2.5.29.19"
    internal const val OID_KEY_USAGE = "2.5.29.15"
    internal const val OID_EXT_KEY_USAGE = "2.5.29.37"
    internal const val OID_SUBJECT_ALT_NAME = "2.5.29.17"
    internal const val OID_SUBJECT_KEY_ID = "2.5.29.14"
    internal const val OID_AUTHORITY_KEY_ID = "2.5.29.35"
    internal const val OID_SERVER_AUTH = "1.3.6.1.5.5.7.3.1"
    internal const val OID_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"

    class CertificateException(message: String) : Exception(message)

    enum class VerifyFailure { NOT_FROM_GROUP_CA, EXPIRED, NOT_YET_VALID, BAD_NAME, IS_CA, NOT_ADMIN_CA, NOT_ROOT }

    class VerifyException(val failure: VerifyFailure) : Exception(failure.name)

    private fun plusYears(t: Instant, years: Long): Instant = t.atZone(ZoneOffset.UTC).plusYears(years).toInstant()

    /**
     * A new group CA certificate for the signer's key: self-signed, a CA
     * for certificate and CRL signing, valid from a day ago for 20 years.
     * With path length 0 it is a group CA as a computer makes it; with 1 it
     * is the root a phone makes, which can certify admin CAs later
     * (docs/protocol.md, sections 9 and 10).
     */
    fun groupCA(signer: CertificateSigner, now: Instant, pathLength: Int = 0): ByteArray {
        val day = DateTimeFormatter.ISO_LOCAL_DATE.withZone(ZoneOffset.UTC).format(now)
        val name = distinguishedName((if (pathLength == 0) "cbb group CA " else "cbb group root ") + day)
        val extensions = listOf(
            ext(OID_BASIC_CONSTRAINTS, true, DER.sequence(DER.bool(true), DER.integer(pathLength.toLong()))),
            // keyCertSign (bit 5) and cRLSign (bit 6).
            ext(OID_KEY_USAGE, true, DER.bitString(byteArrayOf(0x06), unused = 1)),
            ext(OID_SUBJECT_KEY_ID, false, DER.octetString(keyIdentifier(signer.publicKeyDER))),
        )
        return sign(name, name, signer.publicKeyDER, now.minusSeconds(BACKDATE_SECONDS), plusYears(now, CA_YEARS), extensions, signer)
    }

    /**
     * A member certificate for a device's public key (a SubjectPublicKeyInfo),
     * signed by the group CA: the device ID as its CN, cb-<ID>.local as its
     * one DNS name, for server and client use, from the CA's start until
     * two years from now or the CA's end, whichever is sooner.
     */
    fun member(device: String, publicKey: ByteArray, ca: ByteArray, caSigner: CertificateSigner, now: Instant): ByteArray {
        if (!isDeviceID(device)) throw CertificateException("bad device ID")
        val caInfo = CertificateInfo(ca)
        if (now < caInfo.notBefore || now >= caInfo.notAfter) throw CertificateException("outside the CA's lifetime")
        val notAfter = minOf(plusYears(now, MEMBER_YEARS), caInfo.notAfter)
        val extensions = listOf(
            // digitalSignature (bit 0).
            ext(OID_KEY_USAGE, true, DER.bitString(byteArrayOf(0x80.toByte()), unused = 7)),
            ext(OID_EXT_KEY_USAGE, false, DER.sequence(DER.oid(OID_SERVER_AUTH), DER.oid(OID_CLIENT_AUTH))),
            ext(OID_BASIC_CONSTRAINTS, true, DER.sequence()),
            ext(OID_SUBJECT_ALT_NAME, false, DER.sequence(DER.context(2, false, "cb-$device.local".toByteArray()))),
            ext(OID_AUTHORITY_KEY_ID, false, DER.sequence(DER.context(0, false, keyIdentifier(caSigner.publicKeyDER)))),
        )
        return sign(distinguishedName(device), caInfo.rawSubject, publicKey, caInfo.notBefore, notAfter, extensions, caSigner)
    }

    /**
     * An admin CA certificate for another admin's key (a
     * SubjectPublicKeyInfo), signed by the group's root: a CA with path
     * length 0 that issues member certificates and signs records, valid as
     * long as the root (docs/protocol.md, section 10). device names the
     * admin in its CN.
     */
    fun adminCA(device: String, publicKey: ByteArray, root: ByteArray, rootSigner: CertificateSigner): ByteArray {
        if (!isDeviceID(device)) throw CertificateException("bad device ID")
        val rootInfo = CertificateInfo(root)
        val extensions = listOf(
            ext(OID_BASIC_CONSTRAINTS, true, DER.sequence(DER.bool(true), DER.integer(0))),
            ext(OID_KEY_USAGE, true, DER.bitString(byteArrayOf(0x06), unused = 1)),
            ext(OID_SUBJECT_KEY_ID, false, DER.octetString(keyIdentifier(publicKey))),
            ext(OID_AUTHORITY_KEY_ID, false, DER.sequence(DER.context(0, false, keyIdentifier(rootSigner.publicKeyDER)))),
        )
        return sign(
            distinguishedName("cbb admin $device"), rootInfo.rawSubject, publicKey,
            rootInfo.notBefore, rootInfo.notAfter, extensions, rootSigner,
        )
    }

    /**
     * The self-signed certificate a joining device presents in pairing, as
     * Go's joiner makes it: the device ID as its CN, valid from 1970 to
     * 9999. Nobody trusts it; the QR code's fingerprint names it, and the
     * pairing exchange binds it.
     */
    fun selfSigned(device: String, signer: CertificateSigner): ByteArray {
        if (!isDeviceID(device)) throw CertificateException("bad device ID")
        val name = distinguishedName(device)
        val extensions = listOf(
            ext(OID_KEY_USAGE, true, DER.bitString(byteArrayOf(0x80.toByte()), unused = 7)),
            ext(OID_BASIC_CONSTRAINTS, true, DER.sequence()),
        )
        return sign(name, name, signer.publicKeyDER, Instant.EPOCH, Instant.parse("9999-12-31T23:59:59Z"), extensions, signer)
    }

    /**
     * Checks an admin CA as Go's checkAdminCA does: a CA with path length 0
     * that may sign certificates, with a P-256 key, signed by a root whose
     * path length is at least 1.
     */
    fun checkAdminCA(der: ByteArray, root: ByteArray) {
        val c = try { ParsedCertificate(der) } catch (e: MalformedException) { throw VerifyException(VerifyFailure.NOT_ADMIN_CA) }
        val r = try { ParsedCertificate(root) } catch (e: MalformedException) { throw VerifyException(VerifyFailure.NOT_ADMIN_CA) }
        if (!c.isCA || c.pathLength != 0 || !c.canSignCertificates || p256PublicKey(c.info.publicKey) == null) {
            throw VerifyException(VerifyFailure.NOT_ADMIN_CA)
        }
        // A root without a path length limit is refused, as in Go.
        if ((r.pathLength ?: -1) < 1) throw VerifyException(VerifyFailure.NOT_ADMIN_CA)
        if (!signed(c, r.info)) throw VerifyException(VerifyFailure.NOT_FROM_GROUP_CA)
    }

    /**
     * Checks the new root of a root record as Go's checkRoot does: a
     * self-signed CA with path length 1 that may sign certificates, with a
     * P-256 key (docs/protocol.md, section 10, "Roots").
     */
    fun checkRoot(der: ByteArray) {
        val c = try { ParsedCertificate(der) } catch (e: MalformedException) { throw VerifyException(VerifyFailure.NOT_ROOT) }
        if (!c.isCA || c.pathLength != 1 || !c.canSignCertificates || p256PublicKey(c.info.publicKey) == null || !signed(c, c.info)) {
            throw VerifyException(VerifyFailure.NOT_ROOT)
        }
    }

    /** Whether the certificate der was signed by the CA issuer. */
    internal fun signed(der: ByteArray, issuer: ByteArray): Boolean =
        try {
            signed(ParsedCertificate(der), CertificateInfo(issuer))
        } catch (e: MalformedException) {
            false
        }

    internal fun signed(cert: ParsedCertificate, issuer: CertificateInfo): Boolean =
        cert.rawIssuer.contentEquals(issuer.rawSubject) &&
            cert.signatureAlgorithm.contentEquals(DER.oid(OID_ECDSA_WITH_SHA256)) &&
            verifySignature(issuer.publicKey, cert.tbs, cert.signature)

    /**
     * The group tag: the first 8 bytes of SHA-256 over the group CA
     * certificate, in hex. Members publish it, and the welcome names it.
     */
    fun tag(groupCA: ByteArray): String = sha256(groupCA).copyOf(8).toHex()

    /** Whether s is a device ID: 32 lowercase hex characters. */
    fun isDeviceID(s: String): Boolean = s.length == 32 && s.all { it in '0'..'9' || it in 'a'..'f' }

    internal fun distinguishedName(cn: String): ByteArray =
        DER.sequence(DER.set(DER.sequence(DER.oid(OID_COMMON_NAME), DER.utf8String(cn))))

    internal fun ext(oid: String, critical: Boolean, value: ByteArray): ByteArray =
        if (critical) {
            DER.sequence(DER.oid(oid), DER.bool(true), DER.octetString(value))
        } else {
            DER.sequence(DER.oid(oid), DER.octetString(value))
        }

    /** The key identifier Go uses: SHA-1 over the public key's bit string. */
    internal fun keyIdentifier(spki: ByteArray): ByteArray {
        val bits = try { CertificateInfo.subjectPublicKeyBits(spki) } catch (e: MalformedException) { spki }
        return MessageDigest.getInstance("SHA-1").digest(bits)
    }

    private val random = SecureRandom()

    internal fun sign(
        subject: ByteArray,
        issuer: ByteArray,
        publicKey: ByteArray,
        notBefore: Instant,
        notAfter: Instant,
        extensions: List<ByteArray>,
        signer: CertificateSigner,
    ): ByteArray {
        val serial = ByteArray(16).also { random.nextBytes(it) }
        serial[0] = ((serial[0].toInt() and 0x7f) or 0x01).toByte() // non-zero, so the minimal encoding keeps 16 bytes
        val algorithm = DER.sequence(DER.oid(OID_ECDSA_WITH_SHA256))
        val tbs = DER.sequence(
            DER.context(0, true, DER.integer(2)), // v3
            DER.integerUnsigned(serial),
            algorithm,
            issuer,
            DER.sequence(DER.time(notBefore), DER.time(notAfter)),
            subject,
            publicKey,
            DER.context(3, true, DER.sequence(extensions)),
        )
        val sig = signer.signature(tbs)
        return DER.sequence(tbs, algorithm, DER.bitString(sig))
    }

    /**
     * Whether a member certificate is due for renewal, as Go's renewable
     * decides: less than 240 days left, and its CA lasts longer than it. A
     * clock before the CA's start is wrong, and nothing is due then.
     */
    fun isDue(cert: ByteArray, groupCA: ByteArray, now: Instant): Boolean {
        val c = try { CertificateInfo(cert) } catch (e: MalformedException) { return false }
        val ca = try { CertificateInfo(groupCA) } catch (e: MalformedException) { return false }
        if (now < ca.notBefore) return false
        return now > c.notAfter.minusSeconds(RENEW_BEFORE_SECONDS) && ca.notAfter > c.notAfter
    }

    /**
     * A renewed member certificate for the device and key of cert, which
     * the group CA issued (or issuer, an admin CA under it), or null when it
     * is not due (or not from the CA). The renewed one is from the group CA,
     * or from adminCA when caSigner holds that admin CA's key, which the
     * cert message then carries (section 10).
     */
    fun renewal(
        cert: ByteArray,
        groupCA: ByteArray,
        caSigner: CertificateSigner,
        now: Instant,
        issuer: ByteArray? = null,
        adminCA: ByteArray? = null,
    ): ByteArray? {
        if (!isDue(cert, groupCA, now)) return null
        val device = try { verifyMember(cert, groupCA, now, issuer) } catch (e: Exception) { return null }
        return member(device, CertificateInfo(cert).publicKey, adminCA ?: groupCA, caSigner, now)
    }

    /**
     * The renewal for a peer's chain from a TLS handshake, leaf first, in a
     * group with several roots, the current one last (section 10, "Roots"):
     * the certificate may be from any of them, or from an admin CA under any
     * of them, and the renewed one is from the current root, or from adminCA.
     */
    fun renewal(chain: List<ByteArray>, roots: List<ByteArray>, caSigner: CertificateSigner, now: Instant, adminCA: ByteArray? = null): ByteArray? {
        val leaf = chain.firstOrNull() ?: return null
        val current = roots.lastOrNull() ?: return null
        for (root in roots) {
            val issuer = chain.drop(1).firstOrNull { runCatching { checkAdminCA(it, root) }.isSuccess }
            val device = try { verifyMember(leaf, root, now, issuer) } catch (e: Exception) { continue }
            val ca = adminCA ?: current
            if (!isDue(leaf, ca, now)) return null
            return member(device, CertificateInfo(leaf).publicKey, ca, caSigner, now)
        }
        return null
    }

    /**
     * Checks a member certificate as Go's checkPeer does (docs/protocol.md,
     * section 2): signed by the group CA, or by issuer when that is an
     * admin CA under it, valid at max(now, the CA's start), not a CA, its
     * CN a device ID and its one DNS name cb-<ID>.local. It returns the
     * device ID.
     */
    fun verifyMember(der: ByteArray, groupCA: ByteArray, now: Instant, issuer: ByteArray? = null): String {
        val ca = try { CertificateInfo(groupCA) } catch (e: MalformedException) { throw VerifyException(VerifyFailure.NOT_FROM_GROUP_CA) }
        var signer = ca
        if (issuer != null) {
            checkAdminCA(issuer, groupCA)
            signer = CertificateInfo(issuer)
        }
        val cert = try { ParsedCertificate(der) } catch (e: MalformedException) { throw VerifyException(VerifyFailure.NOT_FROM_GROUP_CA) }
        if (!signed(cert, signer)) throw VerifyException(VerifyFailure.NOT_FROM_GROUP_CA)
        val t = maxOf(now, ca.notBefore)
        if (t < cert.info.notBefore) throw VerifyException(VerifyFailure.NOT_YET_VALID)
        if (t > cert.info.notAfter) throw VerifyException(VerifyFailure.EXPIRED)
        if (cert.isCA) throw VerifyException(VerifyFailure.IS_CA)
        val id = cert.info.commonName
        if (id == null || !isDeviceID(id) || cert.dnsNames != listOf("cb-$id.local")) throw VerifyException(VerifyFailure.BAD_NAME)
        return id
    }

    /**
     * Checks a peer's certificate chain from a TLS handshake, leaf first:
     * the leaf from the group CA, or from the admin CA that follows it.
     * Other certificates after the leaf are ignored, as Go's verifier
     * ignores what it does not need.
     */
    fun verifyMember(chain: List<ByteArray>, groupCA: ByteArray, now: Instant): String {
        val leaf = chain.firstOrNull() ?: throw VerifyException(VerifyFailure.NOT_FROM_GROUP_CA)
        runCatching { return verifyMember(leaf, groupCA, now) }
        for (issuer in chain.drop(1)) {
            runCatching { return verifyMember(leaf, groupCA, now, issuer) }
        }
        return verifyMember(leaf, groupCA, now)
    }

    /**
     * verifyMember for a chain in a group with several roots (section 10,
     * "Roots"): the leaf from any of them, or from an admin CA under any of
     * them.
     */
    fun verifyMember(chain: List<ByteArray>, roots: List<ByteArray>, now: Instant): String {
        var last: Exception = VerifyException(VerifyFailure.NOT_FROM_GROUP_CA)
        for (root in roots) {
            try {
                return verifyMember(chain, root, now)
            } catch (e: Exception) {
                last = e
            }
        }
        throw last
    }
}

/**
 * The parts of a certificate that verifying it needs: the signed bytes,
 * the signature, the issuer and the extensions.
 */
internal class ParsedCertificate(der: ByteArray) {
    val info = CertificateInfo(der)
    val tbs: ByteArray
    val signatureAlgorithm: ByteArray // the OID, encoded
    val signature: ByteArray // DER
    val rawIssuer: ByteArray
    val dnsNames: List<String>
    val isCA: Boolean

    /** The path length limit of a CA; null without one. */
    val pathLength: Int?

    /** Whether key usage allows signing certificates. */
    val canSignCertificates: Boolean

    init {
        val cert = DERReader(der).read(0x30)
        tbs = cert.readAny(raw = true).bytes
        val alg = cert.read(0x30)
        signatureAlgorithm = alg.readAny(raw = true).bytes
        signature = cert.read(0x03).bytes.drop(1).toByteArray() // the unused-bits byte
        val body = DERReader(tbs).read(0x30)
        if (body.peek == 0xa0) body.readAny() // version
        body.read(0x02) // serial
        body.read(0x30) // algorithm
        rawIssuer = body.readAny(raw = true).bytes
        body.read(0x30) // validity
        body.readAny() // subject
        body.readAny() // public key
        val names = mutableListOf<String>()
        var ca = false
        var pathLen: Int? = null
        var certSign = false
        while (true) {
            val tag = body.peek ?: break
            val e = body.readAny()
            if (tag != 0xa3) continue // extensions
            val exts = e.read(0x30)
            while (exts.peek != null) {
                val ext = exts.read(0x30)
                val oid = ext.readAny(raw = true).bytes
                if (ext.peek == 0x01) ext.readAny() // critical
                val value = DERReader(ext.read(0x04).bytes)
                when {
                    oid.contentEquals(DER.oid(GroupCertificates.OID_SUBJECT_ALT_NAME)) -> {
                        val seq = value.read(0x30)
                        while (true) {
                            val t = seq.peek ?: break
                            val n = seq.readAny()
                            if (t == 0x82) names.add(String(n.bytes)) // dNSName
                        }
                    }
                    oid.contentEquals(DER.oid(GroupCertificates.OID_BASIC_CONSTRAINTS)) -> {
                        val seq = value.read(0x30)
                        if (seq.peek == 0x01) ca = !seq.readAny().bytes.contentEquals(byteArrayOf(0))
                        if (seq.peek == 0x02) pathLen = seq.readAny().bytes.fold(0) { acc, b -> (acc shl 8) or (b.toInt() and 0xff) }
                    }
                    oid.contentEquals(DER.oid(GroupCertificates.OID_KEY_USAGE)) -> {
                        val bits = value.read(0x03).bytes
                        certSign = bits.size > 1 && bits[1].toInt() and 0x04 != 0 // keyCertSign, bit 5
                    }
                }
            }
        }
        dnsNames = names
        isCA = ca
        pathLength = pathLen
        canSignCertificates = certSign
    }
}

/**
 * What the kit reads from a certificate: its subject, validity and public
 * key. It is a minimal DER reader, not a verifier.
 */
class CertificateInfo(der: ByteArray) {
    val rawIssuer: ByteArray
    val rawSubject: ByteArray
    val notBefore: Instant
    val notAfter: Instant

    /** The SubjectPublicKeyInfo, DER. */
    val publicKey: ByteArray

    init {
        val cert = DERReader(der).read(0x30)
        val tbs = cert.read(0x30)
        if (tbs.peek == 0xa0) tbs.readAny() // version
        tbs.read(0x02) // serial
        tbs.read(0x30) // algorithm
        rawIssuer = tbs.readAny(raw = true).bytes
        val validity = tbs.read(0x30)
        notBefore = validity.readTime()
        notAfter = validity.readTime()
        rawSubject = tbs.readAny(raw = true).bytes
        publicKey = tbs.readAny(raw = true).bytes
    }

    /** Whether the certificate names itself as its issuer, as a root does. */
    val selfIssued: Boolean get() = rawIssuer.contentEquals(rawSubject)

    /** The subject's common name, or null without one. */
    val commonName: String?
        get() = try {
            val name = DERReader(rawSubject).read(0x30)
            var cn: String? = null
            outer@ while (name.peek != null) {
                val rdn = name.read(0x31)
                while (rdn.peek != null) {
                    val atv = rdn.read(0x30)
                    val oid = atv.readAny(raw = true).bytes
                    val value = atv.readAny()
                    if (oid.contentEquals(DER.oid(GroupCertificates.OID_COMMON_NAME))) {
                        cn = String(value.bytes)
                        break@outer
                    }
                }
            }
            cn
        } catch (e: MalformedException) {
            null
        }

    companion object {
        /** The bits of the public key in a SubjectPublicKeyInfo. */
        internal fun subjectPublicKeyBits(spki: ByteArray): ByteArray {
            val seq = DERReader(spki).read(0x30)
            seq.read(0x30)
            return seq.read(0x03).bytes.drop(1).toByteArray() // the unused-bits byte
        }
    }
}
