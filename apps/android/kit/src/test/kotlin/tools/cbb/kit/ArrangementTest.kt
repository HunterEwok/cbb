// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ArrangementTest {
    private fun ref(o: JsonObject): Arrangement.Ref =
        o["device"]?.let { Arrangement.Ref.Device(it.jsonPrimitive.content) }
            ?: Arrangement.Ref.Collection(o.getValue("collection").jsonPrimitive.content)

    private fun op(o: JsonObject): Arrangement.Op? {
        fun s(k: String) = o.getValue(k).jsonPrimitive.content
        return when (s("op")) {
            "move" -> Arrangement.Op.Move(ref(o.getValue("item").jsonObject), (o["before"] as? JsonObject)?.let(::ref))
            "into" -> Arrangement.Op.Into(s("device"), s("collection"))
            "out" -> Arrangement.Op.Out(s("device"))
            "new" -> Arrangement.Op.New(s("name"), o["devices"]?.jsonArray?.map { it.jsonPrimitive.content } ?: emptyList())
            "rename" -> Arrangement.Op.Rename(s("collection"), s("name"))
            "ungroup" -> Arrangement.Op.Ungroup(s("collection"))
            "reset" -> Arrangement.Op.Reset
            else -> null
        }
    }

    /** Each change of testdata/arrangement/vectors.json goes to the member as the vectors write it, which cbb_core::arrange reads. */
    @Test
    fun changesGoAsTheMemberReadsThem() {
        val text = File(Interop.dir.parentFile, "arrangement/vectors.json").readText()
        var n = 0
        for (c in Json.parseToJsonElement(text).jsonObject.getValue("cases").jsonArray) {
            for (raw in c.jsonObject.getValue("ops").jsonArray) {
                val o = raw.jsonObject
                val parsed = op(o) ?: continue
                var want = JsonObject(o.filterValues { it != JsonNull })
                if (parsed is Arrangement.Op.New && "devices" !in want) want = JsonObject(want + ("devices" to JsonArray(emptyList())))
                assertEquals(want, Arrangement.json(parsed), c.jsonObject.getValue("name").jsonPrimitive.content)
                n++
            }
        }
        assertTrue(n > 10)
    }

    /** The member's view reads as tiles by their devices' IDs. */
    @Test
    fun readsTheView() {
        val v = Arrangement.view(
            Json.parseToJsonElement(
                """{"tiles":[{"device":{"id":"s"}},{"collection":{"id":"c1","name":"Desk","devices":[{"id":"a"},{"id":"b"}]}}],"online":1,"others":2,"custom":true}""",
            ).jsonObject,
        )
        assertEquals(listOf(Arrangement.Item.Device("s"), Arrangement.Item.Collection("c1", "Desk", listOf("a", "b"))), v.tiles)
        assertEquals(Arrangement.View(v.tiles, 1, 2, true), v)
    }
}
