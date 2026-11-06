// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class EntriesTest {
    private val v = Interop.read("go-entries.json").jsonObject
    private val roots = v.getValue("roots").jsonArray.map { b64(it.jsonPrimitive.content) }
    private val now = v.getValue("now_ms").jsonPrimitive.long

    private fun case(name: String): Releases.EntriesSet {
        val c = v.getValue("vectors").jsonArray.map { it.jsonObject }.first { it.getValue("name").jsonPrimitive.content == name }
        return Releases.EntriesSet.fromJson(c)!!
    }

    /** The phone keeps the newest list that checks out, across a restart, and stops using it once it expires. */
    @Test
    fun keepsTheNewest() {
        val dir = Files.createTempDirectory("entries").toFile()
        val file = dir.resolve("entries.json")
        var at = now
        val logged = mutableListOf<String>()
        val e = EntriesFile(file, roots, { at }, { logged += it })
        assertNull(e.current)
        assertNull(e.order)
        assertNull(e.expiresMS)
        assertTrue(e.ways("cbb.tools:8764").isEmpty())

        e.add(case("signed by another key"))
        assertNull(e.current)
        assertTrue(logged.single().startsWith("dropped the entry points"))
        e.add(case("valid"))
        assertEquals(3L to 5L, e.order)
        assertEquals(listOf(Releases.EntryVLESS("xhttp", "cbb.tools", 443, "/banMEJvnYJJap8S")), e.ways("cbb.tools:8764"))
        assertTrue(e.ways("example.com:8764").isEmpty())
        assertTrue(file.exists())
        // The same list again, or an older one, leaves it as it is.
        e.add(case("the same again"))
        e.add(case("an older list"))
        assertEquals(3L to 5L, e.order)

        val again = EntriesFile(file, roots, { at })
        assertEquals(5L, again.current?.seq)
        assertEquals(e.expiresMS, again.expiresMS)
        at = e.expiresMS!!
        assertNull(again.current)
        assertNull(again.order)

        // A file that does not check out is logged and dropped.
        val other = mutableListOf<String>()
        assertNull(EntriesFile(file, emptyList(), { now }, { other += it }).current)
        assertTrue(other.single().startsWith("the entry points kept in"))

        again.remove()
        assertFalse(file.exists())
        assertNull(again.current)
        dir.deleteRecursively()
    }

    /** The entries message and the hello's seqs go over the wire and come back the same. */
    @Test
    fun wire() {
        val set = case("valid")
        val m = Member.decode(Member.encode(Member.Message.Entries(set)).let { it.copyOfRange(4, it.size) })
        assertTrue(m is Member.Message.Entries)
        assertEquals(set.toJson(), (m as Member.Message.Entries).set.toJson())
        assertEquals(set.toJson(), Releases.EntriesSet.fromJson(set.toJson())!!.toJson())
        assertNull(Releases.EntriesSet.fromJson(JsonObject(emptyMap())))
        assertEquals(Member.Message.Unknown("entries"), Member.decode("""{"t":"entries"}""".toByteArray()))

        val hello = Member.Hello(wallMS = 1, entriesSeq = 5, entriesKeysSeq = 3)
        val back = Member.decode(Member.encode(Member.Message.Hello(Member.Role.PHONE, hello)).let { it.copyOfRange(4, it.size) })
        assertEquals(Member.Message.Hello(Member.Role.PHONE, hello), back)
        val none = String(Member.encode(Member.Message.Hello(Member.Role.PHONE, Member.Hello(wallMS = 1))).let { it.copyOfRange(4, it.size) })
        assertFalse("entries_seq" in none)
    }
}
