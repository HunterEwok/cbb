// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ReleasesTest {
    /** testdata/interop/go-release.json, from Go's TestReleaseVectors: which release files a device takes. */
    @Test
    fun goRelease() {
        val v = Interop.read("go-release.json").jsonObject
        val roots = v.getValue("roots").jsonArray.map { b64(it.jsonPrimitive.content) }
        val now = v.getValue("now_ms").jsonPrimitive.long
        val cases = v.getValue("vectors").jsonArray.map { it.jsonObject }
        assertEquals(33, cases.size)
        for (c in cases) {
            val name = c.str("name")
            val file = { k: String -> Releases.File.fromJson(c.getValue(k).jsonObject) }
            val s = c.getValue("seen").jsonObject
            val seen = Releases.Seen(
                s.optLong("keys_seq") ?: 0, s.optLong("channel_seq") ?: 0, s.optString("version") ?: "",
                channelKeysSeq = s.optLong("channel_keys_seq") ?: 0,
            )
            val got = runCatching { Releases.check(file("keys"), file("channel"), file("release"), roots, v.str("channel"), now, seen) }
            assertEquals(c.getValue("ok").jsonPrimitive.boolean, got.isSuccess, "$name: ${got.exceptionOrNull()?.message}")
            got.getOrNull()?.let { (r, next) ->
                assertEquals(c.str("version"), r.version, name)
                assertEquals(r.version, next.version, name)
                assertEquals(r.version, Releases.named(file("channel")), name)
                assertTrue(r.direct("0.5.3") && !r.direct("0.3.9"), name)
            }
        }
    }

    /** The revocation lists of the same file: which attest-status.json a root takes. */
    @Test
    fun goStatus() {
        val v = Interop.read("go-release.json").jsonObject
        val roots = v.getValue("roots").jsonArray.map { b64(it.jsonPrimitive.content) }
        val now = v.getValue("now_ms").jsonPrimitive.long
        val cases = v.getValue("status").jsonArray.map { it.jsonObject }
        assertEquals(18, cases.size)
        for (c in cases) {
            val name = c.str("name")
            val file = { k: String -> Releases.File.fromJson(c.getValue(k).jsonObject) }
            val s = c.getValue("seen").jsonObject
            val seen = Releases.Seen(s.optLong("keys_seq") ?: 0, statusSeq = s.optLong("status_seq") ?: 0, statusKeysSeq = s.optLong("status_keys_seq") ?: 0)
            val got = runCatching { Releases.checkStatus(file("keys"), file("status"), roots, now, seen) }
            assertEquals(c.getValue("ok").jsonPrimitive.boolean, got.isSuccess, "$name: ${got.exceptionOrNull()?.message}")
            got.getOrNull()?.let { (st, next) ->
                assertEquals(c.getValue("revoked").jsonArray.map { it.jsonPrimitive.content }, st.androidRevoked, name)
                assertEquals(st.seq, next.statusSeq, name)
            }
        }
    }

    @Test
    fun compare() {
        assertEquals(1, Releases.compare("0.10.0", "0.9.0"))
        assertEquals(0, Releases.compare("0.6.0", "0.6.0"))
        assertEquals(-1, Releases.compare("0.6.0", "0.6.1"))
        assertEquals(-1, Releases.compare("v0.6.0", "0.0.0"))
        assertEquals(-1, Releases.compare("0.06.0", "0.0.0"))
        assertEquals(-1, Releases.compare("0.6.0-rc.1", "0.6.0"))
        assertEquals(-1, Releases.compare("0.6.0-rc.2", "0.6.0-rc.10"))
        assertEquals(1, Releases.compare("0.6.0-rc.1", "0.5.9"))
        assertEquals(-1, Releases.compare("0.6.0-rc.0", "0.0.0"))
    }
}
