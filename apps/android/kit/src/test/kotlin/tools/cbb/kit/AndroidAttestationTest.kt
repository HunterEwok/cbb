// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class AndroidAttestationTest {
    private fun JsonObject.bytes(key: String) = b64(str(key))
    private fun JsonObject.list(key: String): List<String>? =
        get(key)?.takeIf { it != JsonNull }?.jsonArray?.map { it.jsonPrimitive.content }
    private fun JsonObject.flag(key: String) = get(key)?.jsonPrimitive?.boolean ?: false

    /** testdata/interop/go-attest.json, from Go's TestAttestVectors. */
    @Test
    fun goAttest() {
        val v = Interop.read("go-attest.json").jsonObject
        val roots = v.list("google_roots")!!.map(::b64)
        assertEquals(AndroidAttestation.googleRoots.size, roots.size)
        roots.zip(AndroidAttestation.googleRoots).forEach { (a, b) -> assertContentEquals(a, b) }
        for (c in v.getValue("challenges").jsonArray.map { it.jsonObject }) {
            val key = c["member_key"]?.takeIf { it != JsonNull }?.let { b64(it.jsonPrimitive.content) } ?: ByteArray(0)
            assertContentEquals(c.bytes("challenge"), Attestation.challenge(c.str("group_tag"), key, c.bytes("salt")))
        }
        val cases = v.getValue("vectors").jsonArray.map { it.jsonObject }
        assertEquals(30, cases.size)
        for (c in cases) {
            val name = c.str("name")
            val policy = AndroidAttestation.Policy(c.flag("strict"), c.list("revoked")?.toSet() ?: emptySet(), c.list("roots")?.map(::b64))
            val got = runCatching { AndroidAttestation.check(c.list("chain")!!.map(::b64), c.bytes("spki"), c.bytes("challenge"), policy) }
            assertEquals(c.flag("ok"), got.isSuccess, "$name: ${got.exceptionOrNull()}")
            got.exceptionOrNull()?.let { assertEquals(AndroidAttestation.Invalid::class, it::class, name) }
            got.getOrNull()?.let { r ->
                assertEquals(c.str("store"), r.store, name)
                assertEquals(c["kind"]?.jsonPrimitive?.content ?: "", r.kind, name)
                assertEquals(c.flag("rkp"), r.rkp, name)
                assertEquals(c.list("serials"), r.serials, name)
                assertEquals(r.store == Records.PROVEN, r.why == "", name)
            }
        }
    }

    /** The root phone records a phone whose evidence proves its member key as proven, once (section 17, "Evidence"). */
    @Test
    fun rootRecordsEvidence() {
        val e = Interop.read("go-attest.json").jsonObject.getValue("evidence").jsonObject
        val chain = e.list("chain")!!.map(::b64)
        val evidence = Member.Evidence(Member.Evidence.ANDROID, Member.Evidence.MEMBER, null, e.bytes("salt"), chain)
        val roots = listOf(e.bytes("root"))
        val now = java.time.Instant.now()
        val rootKey = SoftwareSigner()
        val root = PhoneGroup.create(rootKey, SoftwareSigner().publicKeyDER, now, "Root")
        // The leaf certifies the phone's member key; it stands in for the member certificate here.
        val phone = SyncEngine.newID()
        root.record(phone, "Pixel", "phone", Records.keyHashOfCert(chain[0]), rootKey, now, os = "android", store = Records.HARDWARE)
        val other = SyncEngine.newID()
        assertEquals(null, root.evidence(other, listOf(chain[0]), evidence, rootKey, now, roots), "an unlisted device")
        val r = root.evidence(phone, listOf(chain[0]), evidence, rootKey, now.plusSeconds(1), roots)
        assertTrue(r != null)
        val d = root.devices.first { it.id == phone }
        assertEquals(Records.PROVEN, d.store)
        assertEquals(AndroidAttestation.KIND_TEE, d.kind)
        assertEquals(64, d.proof?.length)
        assertEquals(null, root.evidence(phone, listOf(chain[0]), evidence, rootKey, now, roots), "nothing new")
        // Renaming keeps what the attestation proved.
        root.rename(phone, "Pixel 9", rootKey, now.plusSeconds(2))
        assertEquals(Records.PROVEN, root.devices.first { it.id == phone }.store)
        kotlin.test.assertFailsWith<AndroidAttestation.Invalid> {
            root.evidence(phone, listOf(chain[0]), Member.Evidence(Member.Evidence.ANDROID, Member.Evidence.MEMBER, "another", e.bytes("salt"), chain), rootKey, now, roots)
        }
        // Google revokes the attestation key: the phone's keys count as only in hardware.
        val ca = java.security.cert.CertificateFactory.getInstance("X.509")
            .generateCertificate(chain[1].inputStream()) as java.security.cert.X509Certificate
        val revoked = setOf(ca.serialNumber.toString(16))
        assertTrue(root.evidence(phone, listOf(chain[0]), evidence, rootKey, now.plusSeconds(3), roots, revoked) != null)
        val after = root.devices.first { it.id == phone }
        assertEquals(Records.HARDWARE, after.store)
        assertEquals(AndroidAttestation.KIND_TEE, after.kind)
        assertEquals(null, after.proof)
        assertEquals(null, root.evidence(phone, listOf(chain[0]), evidence, rootKey, now.plusSeconds(4), roots, revoked), "already in hardware")
    }
}
