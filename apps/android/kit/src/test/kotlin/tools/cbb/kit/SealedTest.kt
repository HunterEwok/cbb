// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

class SealedTest {
    @Test
    fun copiesOpenOnlyForTheirReaders() {
        val keys = TestCopies()
        val engine = SyncEngine(keys.idA, HybridClock())
        engine.seal = { e, key, blob -> keys.a.seal(e, key, blob) }
        val ev = engine.local("from Kotlin / <ok>", Member.Kind.TEXT)
        val secret = engine.local("hunter2", Member.Kind.SECRET)
        val s = ev.sealed!!
        assertTrue(s.isValid)
        // The wire carries the sealed copy only, never the text.
        val json = Wire.encode(ev.toJson()).decodeToString()
        assertTrue("from Kotlin" !in json && "\"kind\"" !in json, json)
        val back = Member.Event.fromJson(Wire.parse(json.toByteArray()))!!
        assertTrue(back.unread)
        assertEquals(s, back.sealed)
        // The other side opens what is sealed to it.
        assertEquals("from Kotlin / <ok>", keys.b.take(s).text)
        assertEquals(Member.Kind.SECRET, keys.b.take(secret.sealed!!).kind)
        // A hello carries a secret's mark, which only orders.
        val mark = engine.hello("Pixel").current!!
        assertTrue(mark.isMark)
        assertNull(mark.sealed!!.payload)
        assertTrue(keys.b.take(mark.sealed!!).unread)
        // A changed copy is refused.
        val changed = Sealed(s.id, s.origin, s.time, 0, s.cert, s.issuer, s.wraps, s.payload!!.copyOf().also { it[0] = (it[0] + 1).toByte() }, null, null, s.sig)
        assertFailsWith<Core.Refusal> { keys.b.take(changed) }
    }

    @Test
    fun blobsOpenWhole() {
        val store = MemoryContent()
        val one = Random(2).nextBytes(Blob.SEGMENT + 17)
        val m = Content.files(store, listOf("a.bin" to one, "empty" to ByteArray(0), "b.txt" to "two".toByteArray()))
        val (key, blob) = store.sealBlob(m)!!
        assertEquals(Blob.sizeOf(m.size), blob.size)
        val data = store.bytes(blob.sha256)!!
        val parts = Blob.open(key, blob, data, m)
        assertContentEquals(one, parts[0])
        assertEquals(0, parts[1].size)
        assertContentEquals("two".toByteArray(), parts[2])
        // Another key, or a changed byte, does not open.
        assertFailsWith<Core.Refusal> { Blob.open(Blob.newKey(), blob, data, m) }
        assertFailsWith<Content.Mismatch> { Blob.open(key, blob, data.copyOf().also { it[0] = (it[0] + 1).toByte() }, m) }
        // Copies of no bytes have no blob; parts the store lost cannot be sealed.
        assertNull(store.sealBlob(Media.Manifest(0, listOf(Media.Part(path = "e", size = 0, sha256 = MemoryContent.sha256(ByteArray(0)))))))
        assertFailsWith<Content.NoParts> { MemoryContent().sealBlob(m) }
    }
}
