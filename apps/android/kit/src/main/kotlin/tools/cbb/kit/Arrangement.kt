// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/**
 * The device tiles as the member answers `view` and `arrange`
 * (docs/apps.md, "What the member shows"): the member keeps the user's
 * order and collections (`cbb_core::arrange`), and the apps only draw them
 * and send the user's changes.
 */
object Arrangement {
    /** A collection's name has at most so many bytes. */
    const val MAX_NAME = 64

    /** A tile: a device, or a collection of devices, by their IDs. */
    sealed interface Item {
        data class Device(val id: String) : Item
        data class Collection(val id: String, val name: String, val devices: List<String>) : Item
    }

    /** A device or a collection, as a change names it. */
    sealed interface Ref {
        data class Device(val id: String) : Ref
        data class Collection(val id: String) : Ref
    }

    /** A change the user makes, which the member applies and keeps. */
    sealed interface Op {
        /** item before before, or at the end of its level. */
        data class Move(val item: Ref, val before: Ref? = null) : Op
        data class Into(val device: String, val collection: String) : Op
        data class Out(val device: String) : Op
        data class New(val name: String, val devices: List<String> = emptyList()) : Op
        data class Rename(val collection: String, val name: String) : Op
        data class Ungroup(val collection: String) : Op
        data object Reset : Op
    }

    /** The member's answer to view and arrange: the tiles in order, whether the user changed it, and why this device does not sync (docs/apps.md). */
    data class View(
        val tiles: List<Item> = emptyList(),
        val online: Int = 0,
        val others: Int = 0,
        val custom: Boolean = false,
        val warnings: List<WhyReason> = emptyList(),
    )

    private fun json(r: Ref): JsonObject = when (r) {
        is Ref.Device -> JsonObject(mapOf("device" to JsonPrimitive(r.id)))
        is Ref.Collection -> JsonObject(mapOf("collection" to JsonPrimitive(r.id)))
    }

    /** The change as `arrange` takes it (cbb_core::arrange::Op). */
    fun json(op: Op): JsonObject {
        fun o(name: String, vararg fields: Pair<String, JsonElement>) = JsonObject(mapOf("op" to JsonPrimitive(name)) + fields)
        return when (op) {
            is Op.Move -> if (op.before == null) o("move", "item" to json(op.item)) else o("move", "item" to json(op.item), "before" to json(op.before))
            is Op.Into -> o("into", "device" to JsonPrimitive(op.device), "collection" to JsonPrimitive(op.collection))
            is Op.Out -> o("out", "device" to JsonPrimitive(op.device))
            is Op.New -> o("new", "name" to JsonPrimitive(op.name), "devices" to JsonArray(op.devices.map(::JsonPrimitive)))
            is Op.Rename -> o("rename", "collection" to JsonPrimitive(op.collection), "name" to JsonPrimitive(op.name))
            is Op.Ungroup -> o("ungroup", "collection" to JsonPrimitive(op.collection))
            Op.Reset -> o("reset")
        }
    }

    /** The member's view from its JSON. */
    fun view(o: JsonObject): View {
        fun id(e: JsonElement) = e.jsonObject.getValue("id").jsonPrimitive.content
        val tiles = (o["tiles"] as? JsonArray).orEmpty().map { t ->
            val tile = t.jsonObject
            tile["device"]?.let { return@map Item.Device(id(it)) }
            val c = tile.getValue("collection").jsonObject
            Item.Collection(
                c.getValue("id").jsonPrimitive.content,
                c.getValue("name").jsonPrimitive.content,
                (c["devices"] as? JsonArray).orEmpty().map(::id),
            )
        }
        return View(
            tiles,
            o["online"]?.jsonPrimitive?.intOrNull ?: 0,
            o["others"]?.jsonPrimitive?.intOrNull ?: 0,
            o["custom"]?.jsonPrimitive?.booleanOrNull ?: false,
            (o["warnings"] as? JsonArray).orEmpty().mapNotNull { (it as? JsonObject)?.let(WhyReason::fromJson) },
        )
    }
}
