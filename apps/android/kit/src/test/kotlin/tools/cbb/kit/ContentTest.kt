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

/** Checks the content of images and files against Go's vectors (go test ./internal/node -update) and between two nodes. */
class ContentTest {
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
    fun nodesFetch() {
        val store = MemoryContent()
        val changes = Collections.synchronizedList(mutableListOf<Member.Event>())
        val a = MemberNode(SyncEngine("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", HybridClock()), "Pixel", content = store)
        val b = MemberNode(SyncEngine("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", HybridClock()), "pi", Member.Role.FULL, onChange = { changes.add(it) })
        val (pa, pb) = Pipe.pair()
        val ta = Background { a.serve(pa, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb") }
        val tb = Background { b.serve(pb, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") }
        waitUntil { a.peers == 1 && b.peers == 1 }
        assertEquals(listOf("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), b.mediaPeers)
        assertEquals(emptyList(), a.mediaPeers) // b serves nothing

        // A picture of 5 MiB and a bit, more than the fetch asks for ahead.
        val png = Random(1).nextBytes((5 shl 20) + 1234)
        val e = a.send("", Member.Kind.TEXT, media = Content.manifest(store, listOf("image/png" to png)))
        assertEquals(Member.Kind.MEDIA, e.kind)
        waitUntil { changes.any { it.id == e.id } }
        val got = changes.first { it.id == e.id }
        val part = got.media!!.parts.single()
        // Events keep flowing while the content does.
        val fetch = Background { Content.bytes(b, got, part) }
        b.send("meanwhile", Member.Kind.TEXT)
        waitUntil { a.usable?.first == "meanwhile" }
        assertContentEquals(png, fetch.join())

        // A part the phone does not hold is missing; one over the limit is not fetched.
        assertFailsWith<MemberNode.MissingException> { b.fetch("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ByteArray(32) { 1 }, 10) { _, _ -> } }
        assertFailsWith<Content.TooLarge> { Content.bytes(b, got, part, limit = 1 shl 20) }
        // b serves nothing.
        assertFailsWith<MemberNode.ProtocolException> { a.fetch("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", part.sha256!!, part.size) { _, _ -> } }

        // An interrupted fetch cancels, and the next one gets it all.
        val slow = Thread {
            runCatching { b.fetch("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", part.sha256!!, part.size) { _, _ -> Thread.sleep(50) } }
        }.apply { start() }
        Thread.sleep(100)
        slow.interrupt()
        slow.join(5_000)
        assertContentEquals(png, Content.bytes(b, got, part))

        // A sink that fails ends the fetch with its error.
        assertFailsWith<IllegalStateException> {
            b.fetch("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", part.sha256!!, part.size) { _, _ -> error("disk full") }
        }
        assertContentEquals(png, Content.bytes(b, got, part))

        a.closeAll()
        ta.join()
        tb.join()
    }

    @Test
    fun tooManyGets() {
        // A store that reads slowly, so the gets wait.
        val sum = ByteArray(32) { 3 }
        val store = object : ContentStore {
            override fun open(sum: ByteArray) = object : ContentSource {
                override val size = 1L shl 20
                override fun read(offset: Long, length: Int): ByteArray {
                    Thread.sleep(2_000)
                    return ByteArray(length)
                }
            }
        }
        val a = MemberNode(SyncEngine("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", HybridClock()), "Pixel", content = store)
        val (pa, pb) = Pipe.pair()
        val ta = Background { runCatching { a.serve(pa) } }
        // A peer that asks for more than 64 ranges at once, and reads nothing, is closed.
        pb.write(Member.encode(Member.Message.Hello(Member.Role.FULL, Member.Hello(0))))
        runCatching { for (i in 0 until 80) pb.write(Member.encode(Member.Message.Get(Member.Get(sum, i.toLong() * 1000, 1000)))) }
        assertIs<MemberNode.ProtocolException>(ta.join().exceptionOrNull())
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
            "x".repeat(300) to "x".repeat(255),
            "CON." + "a".repeat(249) + ".x" to "CON_." + "a".repeat(249),
            "a".repeat(254) + "." to "a".repeat(254),
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
        val store = MemoryContent(maxBytes = 10)
        val one = store.put(ByteArray(6) { 1 })
        val two = store.put(ByteArray(6) { 2 })
        assertEquals(null, store.open(one))
        assertEquals(6, store.open(two)!!.size.toInt())
        // One part over the limit is still kept, alone.
        val big = store.put(ByteArray(20))
        assertEquals(null, store.open(two))
        assertEquals(20L, store.open(big)!!.size)
    }

    /** While a part is served, a cancel of a part that is neither queued nor served is not kept, as in Go, so the peer's cancels hold at most one count for each part it asked for. */
    @Test
    fun cancelsOfOtherParts() {
        val node = MemberNode(SyncEngine("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", HybridClock()), "Pixel")
        val c = MemberNode.Conn(Pipe.pair().first, null)
        val part = ByteArray(32) { 7 }
        synchronized(c.gets) {
            c.serving = true
            c.current = part.toHex()
        }
        for (i in 0 until 1000) node.get(c, Member.Get(ByteArray(32).also { it[0] = i.toByte(); it[1] = (i shr 8).toByte() }, 0, 0))
        assertEquals(0, synchronized(c.gets) { c.cancels.size })
        node.get(c, Member.Get(part, 0, 0))
        assertEquals(mapOf(part.toHex() to 1), synchronized(c.gets) { c.cancels.toMap() })
    }
}
