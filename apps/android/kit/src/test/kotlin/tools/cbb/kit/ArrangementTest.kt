// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail

class ArrangementTest {
    private fun ref(o: JsonObject): Arrangement.Ref =
        o["device"]?.let { Arrangement.Ref.Device(it.jsonPrimitive.content) }
            ?: Arrangement.Ref.Collection(o.str("collection"))

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

    /** testdata/arrangement/vectors.json, which the tray app and the Swift kit read too. */
    @Test
    fun vectors() {
        val doc = Json.parseToJsonElement(File(Interop.dir.parentFile, "arrangement/vectors.json").readText()).jsonObject
        val cases = doc.getValue("cases").jsonArray
        assertTrue(cases.isNotEmpty())
        for (c in cases) {
            c as JsonObject
            val name = c.str("name")
            val devices = c.getValue("devices").jsonArray.map { it.jsonPrimitive.content }
            val self = c.str("self")
            val stored = c["stored"]
            val a = if (stored == null || stored is JsonNull) Arrangement.empty(c.str("group"))
            else Arrangement.decode(stored.jsonObject, c.str("group"))
            if (c.getValue("prune").jsonPrimitive.boolean) a.prune(devices)
            val ops = c.getValue("ops").jsonArray
            for ((i, e) in ops.withIndex()) {
                val wantError = c.getValue("error").jsonPrimitive.boolean && i == ops.size - 1
                val failed = try {
                    a.apply(op(e.jsonObject) ?: throw Arrangement.Refused("no such operation"), devices, self)
                    false
                } catch (_: Arrangement.Refused) {
                    true
                }
                if (failed != wantError) fail("$name: op $i failed: $failed")
            }
            assertEquals(c.getValue("items").jsonArray.map(Arrangement::item), a.items, "$name: items")
            assertEquals(c.getValue("view").jsonArray.map(Arrangement::item), a.view(devices, self), "$name: view")
            // What is stored reads back the same.
            assertEquals(a.items, Arrangement.decode(a.encode(), c.str("group")).items, "$name: encoded")
        }
    }

    @Test
    fun badJSONStartsFresh() {
        assertEquals(emptyList(), Arrangement.decode("{", "G").items)
        assertEquals(emptyList(), Arrangement.decode("""{"v":1,"group":"G","items":[{"x":1}]}""", "G").items)
        assertEquals(emptyList(), Arrangement.decode(null, "G").items)
        assertEquals(JsonArray(emptyList()), Json.parseToJsonElement(Arrangement.empty("G").encode()).jsonObject["items"])
    }
}
