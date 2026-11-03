// SPDX-License-Identifier: AGPL-3.0-only

package tools.cbb.kit

import java.time.Instant
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.fail

/**
 * Mutates a member certificate and its admin CA at random, a fixed seed so
 * that a failure repeats, and checks that the kit's own DER reader fails
 * only with its own errors and never lets a changed signed part through. The
 * Swift kit has the same test (CertificateFuzzTests).
 */
class CertificatesFuzzTest {
    private val now = Instant.ofEpochSecond(1_790_000_000) // 2026-09
    private val id = "0123456789abcdef0123456789abcdef"

    private val rootSigner = SoftwareSigner()
    private val root = GroupCertificates.groupCA(rootSigner, now, pathLength = 1)
    private val adminSigner = SoftwareSigner()
    private val admin = GroupCertificates.adminCA("fedcba9876543210fedcba9876543210", adminSigner.publicKeyDER, root, rootSigner)
    private val member = GroupCertificates.member(id, SoftwareSigner().publicKeyDER, admin, adminSigner, now)

    /** One random change: a bit, a byte with a telling value, a cut, a byte out or in, or bytes after the end. */
    private fun mutate(der: ByteArray, r: Random): ByteArray {
        val b = der.copyOf()
        val i = r.nextInt(b.size)
        return when (r.nextInt(6)) {
            0 -> b.also { it[i] = (it[i].toInt() xor (1 shl r.nextInt(8))).toByte() }
            1 -> b.also { it[i] = listOf(0x00, 0x01, 0x7f, 0x80, 0x81, 0x84, 0xff).random(r).toByte() }
            2 -> b.copyOf(i)
            3 -> b.copyOfRange(0, i) + b.copyOfRange(i + 1, b.size)
            4 -> b.copyOfRange(0, i) + byteArrayOf(r.nextInt(256).toByte()) + b.copyOfRange(i, b.size)
            else -> b + r.nextBytes(1 + r.nextInt(8))
        }
    }

    private fun tbs(der: ByteArray): ByteArray = ParsedCertificate(der).tbs

    /** Runs block on a mutant; only the kit's own errors may come out of it. */
    private fun <T> expected(mutant: ByteArray, block: () -> T): T? =
        try {
            block()
        } catch (e: GroupCertificates.VerifyException) {
            null
        } catch (e: GroupCertificates.CertificateException) {
            null
        } catch (e: MalformedException) {
            null
        } catch (e: Exception) {
            fail("${e::class.simpleName} on ${mutant.toHex()}: ${e.message}")
        }

    // A length near Int.MAX_VALUE once overflowed the reader's bounds check.
    @Test
    fun hugeLengths() {
        for (len in listOf("847fffffff", "84ffffffff", "8480000000", "847ffffffe")) {
            val der = unhex("30${len}00")
            expected(der) { DERReader(der).readAny() }
            expected(der) { CertificateInfo(der) }
            expected(der) { GroupCertificates.verifyMember(der, root, now, admin) }
        }
    }

    @Test
    fun mutatedMemberCertificates() {
        val r = Random(20261025)
        repeat(3000) {
            val m = mutate(member, r)
            expected(m) { CertificateInfo(m).commonName }
            expected(m) { ParsedCertificate(m) }
            val got = expected(m) { GroupCertificates.verifyMember(m, root, now, admin) }
            if (got != null) {
                assertEquals(id, got, m.toHex())
                assertContentEquals(tbs(member), tbs(m), m.toHex())
            }
            val chain = expected(m) { GroupCertificates.verifyMember(listOf(m, admin), listOf(root), now) }
            if (chain != null) assertContentEquals(tbs(member), tbs(m), m.toHex())
        }
    }

    @Test
    fun mutatedAdminCAs() {
        val r = Random(20261026)
        repeat(3000) {
            val a = mutate(admin, r)
            expected(a) { GroupCertificates.checkAdminCA(a, root) }?.let { assertContentEquals(tbs(admin), tbs(a), a.toHex()) }
            val got = expected(a) { GroupCertificates.verifyMember(member, root, now, a) }
            if (got != null) {
                assertEquals(id, got, a.toHex())
                assertContentEquals(tbs(admin), tbs(a), a.toHex())
            }
        }
    }

    @Test
    fun mutatedRoots() {
        val r = Random(20261027)
        repeat(2000) {
            val x = mutate(root, r)
            expected(x) { GroupCertificates.checkRoot(x) }?.let { assertContentEquals(tbs(root), tbs(x), x.toHex()) }
            // A root is a trust anchor, as in Go: only its name and key count, not its own signature.
            val got = expected(x) { GroupCertificates.verifyMember(listOf(member, admin), listOf(x), now) }
            if (got != null) {
                assertContentEquals(CertificateInfo(root).rawSubject, CertificateInfo(x).rawSubject, x.toHex())
                assertContentEquals(CertificateInfo(root).publicKey, CertificateInfo(x).publicKey, x.toHex())
            }
        }
    }
}
