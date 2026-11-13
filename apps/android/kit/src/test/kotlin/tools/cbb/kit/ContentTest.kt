// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import java.util.Base64
import java.util.Collections
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue

/** Checks the content of images and files against the vectors in testdata/interop and between two nodes. */
class ContentTest {
    /** A phone's picture and files reach the other phone, which fetches their sealed blob and opens it, each part checked; one over the limit is not fetched. */
    @Test
    fun nodesFetch() = CoreGroup().use { t ->
        val (a, b) = t.phones
        t.connect(1, 0)
        val png = ByteArray((5 shl 20) + 1234).also { java.security.SecureRandom().nextBytes(it) }
        val sent = a.member.copyMedia("", listOf(CoreMember.Part.data("image/png", png)), board = true)
        assertEquals(Member.Kind.MEDIA, sent.kind)
        b.next("the picture") { (it as? CoreMember.Event.CopyChanged)?.copy?.takeIf { c -> c.id == sent.id } }
        assertEquals(sent.id, b.member.waiting()?.id)
        val out = kotlin.io.path.createTempDirectory("cbb-fetch").toFile()
        try {
            val parts = b.member.fetch(sent.id, 64L shl 20, java.io.File(out, "picture"))
            assertEquals(1, parts.size)
            assertTrue(parts[0].file.readBytes().contentEquals(png))
            // The phone that shared it sees it was read to the end.
            val (served, size) = a.member.served(sent.id)
            assertEquals(size, served)
            assertEquals(Blob.sizeOf(png.size.toLong()), size)
            val files = a.member.copyMedia("", listOf(CoreMember.Part.folder("docs"), CoreMember.Part.file("docs/one.txt", "one".toByteArray())))
            b.next("the files") { (it as? CoreMember.Event.CopyChanged)?.copy?.takeIf { c -> c.id == files.id } }
            assertFailsWith<Core.Refusal> { b.member.fetch(files.id, 1, java.io.File(out, "small")) }
            val opened = b.member.fetch(files.id, 1L shl 20, java.io.File(out, "files"))
            assertEquals(listOf("docs", "docs/one.txt"), opened.map { it.path })
            assertEquals("one", opened.first { !it.dir }.file.readText())
        } finally {
            out.deleteRecursively()
        }
    }

    private val v = Interop.read("content.json").jsonObject

    @Test
    fun goFrames() {
        val decoded = v.getValue("frames").jsonArray.map { goFrame ->
            val m = Member.decode(Wire.encode(goFrame))
            val encoded = Member.encode(m)
            assertEquals<Any?>(goFrame, Wire.parse(encoded.copyOfRange(4, encoded.size)))
            m
        }
        val sum = ByteArray(32) { 7 }
        assertEquals(Member.Message.Get(Member.Get(sum, 0, Member.GET_WINDOW.toLong())), decoded[0])
        assertEquals(Member.Message.Get(Member.Get(sum, 3L shl 20, 12345)), decoded[1])
        assertEquals(Member.Message.Missing(Member.Get(sum, 0, Member.GET_WINDOW.toLong())), decoded[2])
        assertEquals(Member.Message.Get(Member.Get(sum, 0, 0)), decoded[3])
        assertTrue(decoded.all { (it as? Member.Message.Get)?.get?.isValid ?: true })
    }

    @Test
    fun goChunks() {
        val b64 = Base64.getDecoder()
        for (c in v.getValue("chunks").jsonArray) {
            val o = c.jsonObject
            val trimmed = b64.decode(o.getValue("frame").jsonPrimitive.content)
            val frame = trimmed.copyOf(o.getValue("frame_len").jsonPrimitive.int)
            val chunk = Member.Message.Chunk(
                b64.decode(o.getValue("sha256").jsonPrimitive.content),
                o.getValue("offset").jsonPrimitive.long,
                o["data"]?.jsonPrimitive?.takeIf { it.isString }?.let { b64.decode(it.content) } ?: ByteArray(0),
            )
            assertContentEquals(frame, Member.encode(chunk))
            val (n, binary) = Member.header(frame.copyOf(4))
            assertTrue(binary)
            assertEquals(frame.size - 4, n)
            assertEquals(chunk, Member.decodeChunk(frame.copyOfRange(4, frame.size)))
        }
    }

    @Test
    fun frameLimits() {
        // A chunk frame longer than a padded chunk, and a short or lying chunk, are errors.
        assertFailsWith<Member.WireException> { Member.header(byteArrayOf(0x80.toByte(), 0x04, 0x40, 0x01)) }
        assertEquals(Member.MAX_CHUNK_FRAME to true, Member.header(byteArrayOf(0x80.toByte(), 0x04, 0x40, 0x00)))
        assertEquals(278_528, Member.MAX_CHUNK_FRAME)
        assertFailsWith<Member.WireException> { Member.decodeChunk(ByteArray(10)) }
        val lying = Member.encode(Member.Message.Chunk(ByteArray(32), 0, ByteArray(3))).copyOfRange(4, 4 + Member.CHUNK_HEAD + 3)
        lying[Member.CHUNK_HEAD - 1] = 9
        assertFailsWith<Member.WireException> { Member.decodeChunk(lying) }
        assertFailsWith<Member.WireException> { Member.encode(Member.Message.Chunk(ByteArray(32), 0, ByteArray(Member.CHUNK_SIZE + 1))) }
    }

    @Test
    fun cleanNames() {
        for ((given, want) in listOf(
            "report.pdf" to "report.pdf",
            "a/b:c?.txt" to "a_b_c_.txt",
            "CON.txt" to "CON_.txt",
            "lpt1" to "lpt1_",
            "dots..." to "dots..._",
            "" to "_",
            ".." to "_",
            "tab\there" to "tab_here",
            "x".repeat(800) to "x".repeat(765),
            "CON." + "a".repeat(759) + ".x" to "CON_." + "a".repeat(759),
            "a".repeat(764) + "." to "a".repeat(764),
        )) {
            val got = Media.cleanName(given)
            assertEquals(want, got, given)
            assertTrue(Media.checkName(got), got)
        }
        val m = Content.files(MemoryContent(), listOf("a.txt" to ByteArray(1), "A.txt" to ByteArray(2), "a.txt" to ByteArray(3), "CON" to ByteArray(0)))
        assertEquals(listOf("a.txt", "A (2).txt", "a (3).txt", "CON_"), m.parts.map { it.path })
        assertTrue(m.isValid)
        assertEquals(6L, m.size)
    }

    /**
     * testdata/interop/media-names.json, as Go's TestNameVectors writes it: the kit takes the names Go takes, writes the
     * device names of Windows under Go's names and cleans names as Go does.
     */
    @Test
    fun nameVectors() {
        val cases = Interop.read("media-names.json").jsonArray
        assertTrue(cases.isNotEmpty())
        for (c in cases) {
            val o = c.jsonObject
            val name = o.str("name")
            val valid = o.getValue("valid").jsonPrimitive.boolean
            assertEquals(valid, Media.checkName(name), name)
            if (valid) assertEquals(o.str("save"), Media.saveName(name), name)
            assertEquals(o.str("clean"), Media.cleanName(name), name)
        }
    }

    @Test
    fun memoryContentKeepsTheNewest() {
        // Twice maxBytes, for a copy's parts and its sealed blob.
        val store = MemoryContent(maxBytes = 10)
        val one = store.put(ByteArray(6) { 1 })
        val two = store.put(ByteArray(6) { 2 }, blob = true)
        val three = store.put(ByteArray(10) { 3 })
        assertEquals(null, store.bytes(one))
        assertEquals(10, store.bytes(three)!!.size)
        // Only blobs are served, never the parts in the open.
        assertEquals(null, store.open(three))
        assertEquals(6, store.open(two)!!.size.toInt())
        // One part over the limit is still kept, alone.
        val big = store.put(ByteArray(40), blob = true)
        assertEquals(null, store.open(two))
        assertEquals(40L, store.open(big)!!.size)
    }

}
