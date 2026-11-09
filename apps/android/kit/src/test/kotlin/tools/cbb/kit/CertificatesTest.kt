// SPDX-License-Identifier: AGPL-3.0-only

package tools.cbb.kit

import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import java.time.Instant
import java.time.ZoneOffset
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class CertificatesTest {
    private val now = Instant.ofEpochSecond(1_790_000_000) // 2026-09
    private val id = "0123456789abcdef0123456789abcdef"

    @Test
    fun groupCAAndMember() {
        val caSigner = SoftwareSigner()
        val ca = GroupCertificates.groupCA(caSigner, now)
        val caInfo = CertificateInfo(ca)
        assertTrue(GroupCertificates.signed(ca, ca))
        assertEquals(now.minusSeconds(GroupCertificates.BACKDATE_SECONDS), caInfo.notBefore)
        assertContentEquals(caSigner.publicKeyDER, caInfo.publicKey)

        val device = SoftwareSigner()
        val member = GroupCertificates.member(id, device.publicKeyDER, ca, caSigner, now)
        val info = CertificateInfo(member)
        assertTrue(GroupCertificates.signed(member, ca))
        assertFalse(GroupCertificates.signed(member, GroupCertificates.groupCA(SoftwareSigner(), now)))
        assertEquals(caInfo.notBefore, info.notBefore)
        assertEquals(now.atZone(ZoneOffset.UTC).plusYears(2).toInstant(), info.notAfter)
        assertContentEquals(device.publicKeyDER, info.publicKey)
        assertEquals(id, GroupCertificates.verifyMember(member, ca, now))

        assertFailsWith<GroupCertificates.CertificateException> {
            GroupCertificates.member("nope", device.publicKeyDER, ca, caSigner, now)
        }
        assertFailsWith<GroupCertificates.CertificateException> {
            GroupCertificates.member(id, device.publicKeyDER, ca, caSigner, now.minusSeconds(3 * 24 * 3600))
        }
    }

    @Test
    fun adminCAAndRoot() {
        val rootSigner = SoftwareSigner()
        val root = GroupCertificates.groupCA(rootSigner, now, pathLength = 1)
        GroupCertificates.checkRoot(root)
        val adminSigner = SoftwareSigner()
        val admin = GroupCertificates.adminCA(id, adminSigner.publicKeyDER, root, rootSigner)
        GroupCertificates.checkAdminCA(admin, root)
        // A computer's group CA, with path length 0, certifies no admins.
        val ca = GroupCertificates.groupCA(rootSigner, now)
        assertFailsWith<GroupCertificates.VerifyException> { GroupCertificates.checkRoot(ca) }
        assertFailsWith<GroupCertificates.VerifyException> { GroupCertificates.checkAdminCA(admin, ca) }

        val other = "fedcba9876543210fedcba9876543210"
        val member = GroupCertificates.member(other, SoftwareSigner().publicKeyDER, admin, adminSigner, now)
        assertFailsWith<GroupCertificates.VerifyException> { GroupCertificates.verifyMember(member, root, now) }
        assertEquals(other, GroupCertificates.verifyMember(listOf(member, admin), root, now))
        assertEquals(other, GroupCertificates.verifyMember(listOf(member, admin), listOf(ca, root), now))
    }

    @Test
    fun renewal() {
        val caSigner = SoftwareSigner()
        val ca = GroupCertificates.groupCA(caSigner, now)
        val member = GroupCertificates.member(id, SoftwareSigner().publicKeyDER, ca, caSigner, now)
        assertNull(GroupCertificates.renewal(member, ca, caSigner, now))
        val later = now.plusSeconds(500L * 24 * 3600)
        val renewed = assertNotNull(GroupCertificates.renewal(member, ca, caSigner, later))
        assertEquals(id, GroupCertificates.verifyMember(renewed, ca, later))
        assertContentEquals(CertificateInfo(member).publicKey, CertificateInfo(renewed).publicKey)
    }

    @Test
    fun derTime() {
        assertContentEquals(DER.tlv(0x17, "700101000000Z".toByteArray()), DER.time(Instant.EPOCH))
        assertContentEquals(DER.tlv(0x18, "20500101000000Z".toByteArray()), DER.time(Instant.ofEpochSecond(2_524_608_000)))
        assertEquals(Instant.EPOCH, DERReader(DER.time(Instant.EPOCH)).readTime())
        assertEquals(Instant.parse("2049-12-31T23:59:59Z"), DERReader(DER.time(Instant.parse("2049-12-31T23:59:59Z"))).readTime())
    }

    @Test
    fun derInteger() {
        assertContentEquals(byteArrayOf(0x02, 0x01, 0x00), DER.integer(0))
        assertContentEquals(byteArrayOf(0x02, 0x02, 0x00, 0x80.toByte()), DER.integer(128))
        assertContentEquals(byteArrayOf(0x02, 0x01, 0x01), DER.integerUnsigned(byteArrayOf(0, 0, 1)))
        assertContentEquals(unhex("06082a8648ce3d040302"), DER.oid("1.2.840.10045.4.3.2"))
    }

    // Go's member certificates, and the ones a member refuses.
    @Test
    fun goMemberCertificates() {
        val v = Interop.read("member-certs.json").jsonObject
        val ca = b64(v.str("group_ca"))
        for (c in v.getValue("cases").jsonArray) {
            val o = c.jsonObject
            val t = Instant.ofEpochMilli(o.getValue("now_ms").jsonPrimitive.long)
            val want = o.str("device")
            val got = runCatching { GroupCertificates.verifyMember(b64(o.str("cert")), ca, t) }.getOrNull()
            assertEquals(want.ifEmpty { null }, got, o.str("name"))
        }
    }

    // The Swift kit's certificates.
    @Test
    fun swiftCertificates() {
        val v = Interop.read("swift-certs.json").jsonObject
        val ca = b64(v.str("group_ca"))
        assertEquals(v.str("device"), GroupCertificates.verifyMember(b64(v.str("member")), ca, CertificateInfo(ca).notBefore))
    }
}
