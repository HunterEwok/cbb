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

}
