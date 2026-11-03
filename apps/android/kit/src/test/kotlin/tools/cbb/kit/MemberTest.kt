// SPDX-License-Identifier: AGPL-3.0-only

package tools.cbb.kit

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Checks the member protocol against the vectors that the Go tests write (go test ./internal/node -update). */
class MemberTest {
    private val v = Interop.read("member.json").jsonObject

    @Test
    fun recordsGoInMessagesOfAboutOneMiB() {
        // 1024 records of the largest body: more than one frame holds.
        val rs = (0 until 1024).map { i -> Member.Record(ByteArray(8 shl 10) { i.toByte() }, ByteArray(72) { 1 }) }
        assertFailsWith<Member.WireException> { Member.encode(Member.Message.Records(rs)) }
        val chunks = Member.Record.chunks(rs)
        assertTrue(chunks.size > 8)
        assertEquals(rs, chunks.flatten())
        for (c in chunks) assertTrue(Member.encode(Member.Message.Records(c)).size <= Member.Record.CHUNK * 5 / 4)
        assertTrue(Member.Record.chunks(emptyList()).isEmpty())
    }

    @Test
    fun goFrames() {
        val decoded = v.getValue("frames").jsonArray.map { goFrame ->
            val m = Member.decode(Wire.encode(goFrame))
            // Encoding it again gives the same JSON object as Go's.
            val encoded = Member.encode(m)
            assertEquals(encoded.size - 4, Member.length(encoded.copyOf(4)))
            assertEquals<Any?>(goFrame, Wire.parse(encoded.copyOfRange(4, encoded.size)))
            m
        }
        val hello = assertIs<Member.Message.Hello>(decoded[0])
        assertEquals(Member.Role.FULL, hello.role)
        assertEquals("pi", hello.hello.name)
        assertEquals("q83vEjRWeJA=", hello.hello.records)
        assertEquals("hello <world> & \"you\" / ✓", hello.hello.current?.text)
        assertEquals(Member.Timestamp(1_761_024_000_000, 3), hello.hello.current?.time)
        assertEquals(1500L, hello.hello.current?.ageMS)
        val mark = assertIs<Member.Message.Hello>(decoded[1]).hello.current!!
        assertTrue(mark.isMark)
        assertEquals(Member.Via.PHONE, mark.via)
        assertEquals(Member.Via.UNIVERSAL_CLIPBOARD, assertIs<Member.Message.Event>(decoded[5]).event?.via)
        assertEquals(Member.Message.Ping, decoded[6])
        assertEquals(Member.Message.Bye, decoded[7])
        assertEquals(Member.Message.Cert("member certificate DER".toByteArray()), decoded[8])
        val rs = assertIs<Member.Message.Records>(decoded[9]).records
        assertEquals(2, rs.size)
        assertContentEquals("admin CA".toByteArray(), rs[1].chain!!.single())
        val key = ByteArray(32) { (it + 1).toByte() }
        assertContentEquals(key, assertIs<Member.Message.Hello>(decoded[10]).hello.tunnelKey)
        val offer = assertIs<Member.Message.Tunnel>(decoded[11]).offer!!
        assertTrue(offer.isValid)
        assertContentEquals(ByteArray(32) { (it + 2).toByte() }, offer.hubKey)
        assertContentEquals(ByteArray(32) { (it + 3).toByte() }, offer.psk)
        assertEquals(listOf("203.0.113.7:8764", "[2001:db8::7]:8764"), offer.endpoints)
        assertEquals(emptyList(), assertIs<Member.Message.Tunnel>(decoded[12]).offer!!.endpoints)
        // A computer's hello says what it is.
        val laptop = Member.DeviceInfo(form = "laptop", osVersion = "15.1", version = "0.5.0", mac = "a4:83:e7:01:02:0f")
        assertEquals(laptop, assertIs<Member.Message.Hello>(decoded[15]).hello.device)
        assertEquals(laptop, laptop.cleaned)
        assertNull(Member.DeviceInfo(form = "toaster", osVersion = "9".repeat(33), version = "1\n2", mac = "A4:83:E7:01:02:0F").cleaned)
        assertEquals(Member.DeviceInfo(form = "phone"), Member.DeviceInfo(form = "phone", mac = "nope").cleaned)
        // An obfuscated hub's settings are kept as they came, for the tunnel.
        val hidden = assertIs<Member.Message.Tunnel>(decoded[13]).offer!!
        assertTrue(hidden.isValid)
        assertNull(offer.obfuscation)
        assertTrue(hidden.obfuscation!!.contains("\"header_protection_key\""))
        // So is the way to the hub's forwarder over VLESS.
        val tunneled = assertIs<Member.Message.Tunnel>(decoded[14]).offer!!
        assertTrue(tunneled.isValid)
        assertNull(offer.vless)
        assertNull(hidden.vless)
        assertTrue(tunneled.vless!!.contains("\"short_id\":\"0123456789abcdef\""))
    }

    @Test
    fun timestamps() {
        for (t in v.getValue("timestamps").jsonArray) {
            val o = t.jsonObject
            assertEquals(o.getValue("ok").jsonPrimitive.boolean, Member.Timestamp.parse(o.str("text")) != null, "\"${o.str("text")}\"")
        }
        assertTrue(Member.Timestamp(1, 9) < Member.Timestamp(2, 0))
        assertEquals("17.4", Member.Timestamp.parse("17.4").toString())
    }

    @Test
    fun bodies() {
        val bodies = v.getValue("bodies").jsonArray
        assertTrue(bodies.size >= 14)
        for (e in bodies) {
            val o = e.jsonObject
            val text = o.getValue("text").jsonPrimitive.content
            assertEquals(o.getValue("ok").jsonPrimitive.boolean, runCatching { Member.decode(text.toByteArray()) }.isSuccess, text)
        }
    }

    @Test
    fun events() {
        for (e in v.getValue("events").jsonArray) {
            val o = e.jsonObject
            val ev = Member.Event.fromJson(o.getValue("json"))
            assertEquals(o.getValue("valid").jsonPrimitive.boolean, ev?.isValid ?: false, o.getValue("json").toString())
        }
        for (e in v.getValue("order").jsonArray) {
            val o = e.jsonObject
            val a = Member.Event.fromJson(o.getValue("a"))!!
            val b = Member.Event.fromJson(o.getValue("b"))!!
            assertEquals(o.getValue("later").jsonPrimitive.boolean, a.isLater(b))
        }
    }

    @Test
    fun badMessages() {
        assertFailsWith<Member.WireException> { Member.decode("{".toByteArray()) }
        assertFailsWith<Member.WireException> { Member.decode("""{"t":"hello","role":"toaster","hello":{}}""".toByteArray()) }
        assertFailsWith<Member.WireException> { Member.decode("""{"t":"hello","role":"full"}""".toByteArray()) }
        // An event from a newer version is dropped, not an error.
        assertEquals(Member.Message.Event(null), Member.decode("""{"t":"event","event":{"kind":"image"}}""".toByteArray()))
        assertEquals(Member.Message.Unknown("gift"), Member.decode("""{"t":"gift"}""".toByteArray()))
        // A hello whose current event does not decode has none.
        val h = assertIs<Member.Message.Hello>(
            Member.decode("""{"t":"hello","role":"full","hello":{"wall_ms":1,"current":{"kind":"image"}}}""".toByteArray()),
        )
        assertNull(h.hello.current)
        assertFailsWith<Member.WireException> { Member.length(byteArrayOf(0x00, 0x70, 0x00, 0x01)) }
    }

    private fun JsonObject.str(key: String) = getValue(key).jsonPrimitive.content
}
