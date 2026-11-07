// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/**
 * The arrangement of the device tiles (docs/apps.md, "Collections and the
 * order of the tiles"): the user's own order and collections, kept in the
 * app's settings and never sent to the group. The twin of the tray app's
 * arrange.go and the Swift kit's Arrangement.swift, all three checked
 * against testdata/arrangement/vectors.json.
 */
class Arrangement private constructor(val group: String, items: List<Item>) {
    /** A device, or a collection of devices. */
    sealed interface Item {
        data class Device(val id: String) : Item
        data class Collection(val id: String, val name: String, val devices: List<String>) : Item
    }

    /** A device or a collection, as an operation names it. */
    sealed interface Ref {
        data class Device(val id: String) : Ref
        data class Collection(val id: String) : Ref
    }

    /** A change the user makes; see Arrangement.apply. */
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

    /** An operation that does not fit the arrangement. */
    class Refused(message: String) : Exception(message)

    /** The stored items. */
    var items: List<Item> = items
        private set

    companion object {
        /** devices with self, this device, first: the group's order as the app shows it. */
        internal fun selfFirst(devices: List<String>, self: String?): List<String> =
            if (self == null || self !in devices) devices else listOf(self) + devices.filter { it != self }

        const val VERSION = 1
        const val MAX_COLLECTIONS = 32
        const val MAX_NAME = 64 // bytes

        /** A fresh arrangement for the group. */
        fun empty(group: String) = Arrangement(group, emptyList())

        /**
         * The stored arrangement for the group, from its JSON: a fresh one
         * when there is none, it does not parse, or it was made for another
         * group or by another version.
         */
        fun decode(json: String?, group: String): Arrangement {
            val o = runCatching { Json.parseToJsonElement(json ?: return empty(group)).jsonObject }.getOrNull()
                ?: return empty(group)
            return decode(o, group)
        }

        fun decode(o: JsonObject, group: String): Arrangement {
            if (o["v"]?.jsonPrimitive?.intOrNull != VERSION || o["group"]?.jsonPrimitive?.content != group) return empty(group)
            val items = runCatching { (o["items"] as? JsonArray ?: JsonArray(emptyList())).map(::item) }.getOrNull()
                ?: return empty(group)
            return Arrangement(group, items)
        }

        /** An item from JSON. */
        fun item(e: JsonElement): Item {
            val o = e.jsonObject
            o["device"]?.let { return Item.Device(it.jsonPrimitive.content) }
            val c = o.getValue("collection").jsonObject
            return Item.Collection(
                c.getValue("id").jsonPrimitive.content,
                c.getValue("name").jsonPrimitive.content,
                (c["devices"] as? JsonArray ?: JsonArray(emptyList())).map { it.jsonPrimitive.content },
            )
        }

        /** An item as JSON. */
        fun json(it: Item): JsonObject = when (it) {
            is Item.Device -> JsonObject(mapOf("device" to JsonPrimitive(it.id)))
            is Item.Collection -> JsonObject(
                mapOf(
                    "collection" to JsonObject(
                        mapOf(
                            "id" to JsonPrimitive(it.id),
                            "name" to JsonPrimitive(it.name),
                            "devices" to JsonArray(it.devices.map(::JsonPrimitive)),
                        ),
                    ),
                ),
            )
        }

        /** A collection's name trimmed, 1 to 64 bytes. */
        fun collectionName(s: String): String {
            val t = s.trim()
            if (t.isEmpty() || t.toByteArray(Charsets.UTF_8).size > MAX_NAME) {
                throw Refused("a collection's name has 1 to $MAX_NAME bytes")
            }
            return t
        }
    }

    /** The arrangement as JSON, for the settings. */
    fun encode(): String = JsonObject(
        mapOf("v" to JsonPrimitive(VERSION), "group" to JsonPrimitive(group), "items" to JsonArray(items.map(::json))),
    ).toString()

    /**
     * What the app shows: the stored items in order without the devices
     * that are not listed, collections without listed devices left out
     * unless they were just made, then the listed devices that appear
     * nowhere, in the order given. self, this device, is an item as the
     * others are, first while the stored items do not place it.
     */
    fun view(devices: List<String>, self: String?): List<Item> {
        val listed = devices.toSet()
        val seen = mutableSetOf<String>()
        val out = mutableListOf<Item>()
        for (it in items) {
            when (it) {
                is Item.Device -> if (it.id in listed && seen.add(it.id)) out += it
                is Item.Collection -> {
                    val ds = it.devices.filter { d -> d in listed && seen.add(d) }
                    if (ds.isNotEmpty() || it.devices.isEmpty()) out += it.copy(devices = ds)
                }
            }
        }
        for (d in selfFirst(devices, self)) {
            if (!seen.add(d)) continue
            if (d == self) out.add(0, Item.Device(d)) else out += Item.Device(d)
        }
        return out
    }

    /**
     * Drops the devices that are not listed, and the collections that lose
     * their last device that way; the app calls it only when the list is
     * whole (the group loaded, this device in it).
     */
    fun prune(devices: List<String>) {
        val listed = devices.toSet()
        items = items.mapNotNull {
            when (it) {
                is Item.Device -> it.takeIf { _ -> it.id in listed }
                is Item.Collection -> {
                    val ds = it.devices.filter { d -> d in listed }
                    if (it.devices.isEmpty() || ds.isNotEmpty()) it.copy(devices = ds) else null
                }
            }
        }
    }

    /**
     * Makes the change, on the arrangement as view shows it for devices
     * (self among them); the stored items then hold the whole order. move puts
     * an item before another, or at the end of its level (a device in a
     * collection: the end of the collection); a device before a device in a
     * collection joins it, a collection never goes into one. into appends a
     * device to a collection, out puts it after its collection, new makes a
     * collection where its first device was, ungroup puts the devices back
     * where it was, and reset brings back the order given with the
     * collections kept. A change that does not fit throws Refused and
     * leaves the arrangement as it was.
     */
    fun apply(op: Op, devices: List<String>, self: String?) {
        val w = Work(items.toMutableList())
        val shown = mutableSetOf<String>()
        for (it in view(devices, self)) {
            when (it) {
                is Item.Device -> shown += it.id
                is Item.Collection -> shown += it.devices
            }
        }
        val ordered = selfFirst(devices, self)
        for (d in ordered) {
            if (d !in shown || w.find(d) >= 0) continue
            if (d == self) w.items.add(0, Item.Device(d)) else w.items += Item.Device(d)
        }
        w.apply(op, ordered, shown)
        items = w.items.toList()
    }

    private class Work(val items: MutableList<Item>) {
        fun find(d: String) = items.indexOfFirst {
            when (it) {
                is Item.Device -> it.id == d
                is Item.Collection -> d in it.devices
            }
        }

        fun collection(id: String) = items.indexOfFirst { it is Item.Collection && it.id == id }

        fun coll(i: Int) = items[i] as Item.Collection

        /** Removes d from where it is; a collection it leaves empty goes away. */
        fun take(d: String, keep: String? = null) {
            val out = mutableListOf<Item>()
            for (it in items) {
                when {
                    it is Item.Device -> if (it.id == d) continue
                    it is Item.Collection && it.id != keep && d in it.devices -> {
                        val ds = it.devices - d
                        if (ds.isEmpty()) continue
                        out += it.copy(devices = ds)
                        continue
                    }
                }
                out += it
            }
            items.clear()
            items += out
        }

        fun newID(): String {
            var n = 1
            while (collection("c$n") >= 0) n++
            return "c$n"
        }

        fun refuse(): Nothing = throw Refused("the arrangement cannot take that")

        fun apply(op: Op, devices: List<String>, shown: Set<String>) {
            when (op) {
                is Op.Move -> move(op.item, op.before, shown)
                is Op.Into -> {
                    if (op.device !in shown) refuse()
                    val ci = collection(op.collection)
                    if (ci < 0) refuse()
                    if (op.device in coll(ci).devices) return
                    take(op.device)
                    val i = collection(op.collection)
                    items[i] = coll(i).let { it.copy(devices = it.devices + op.device) }
                }
                is Op.Out -> {
                    val ci = find(op.device)
                    if (op.device !in shown || ci < 0 || items[ci] !is Item.Collection) refuse()
                    val id = coll(ci).id
                    take(op.device)
                    val at = collection(id) + 1
                    items.add(if (at == 0) ci else at, Item.Device(op.device))
                }
                is Op.New -> {
                    val name = collectionName(op.name)
                    if (items.count { it is Item.Collection } >= MAX_COLLECTIONS) {
                        throw Refused("at most $MAX_COLLECTIONS collections")
                    }
                    val ds = mutableListOf<String>()
                    for (d in op.devices) {
                        if (d !in shown || d in ds) refuse()
                        ds += d
                    }
                    val at = if (ds.isEmpty()) items.size else find(ds[0])
                    val c = Item.Collection(newID(), name, ds)
                    items.add(at, c)
                    for (d in ds) take(d, keep = c.id)
                }
                is Op.Rename -> {
                    val ci = collection(op.collection)
                    if (ci < 0) refuse()
                    items[ci] = coll(ci).copy(name = collectionName(op.name))
                }
                is Op.Ungroup -> {
                    val ci = collection(op.collection)
                    if (ci < 0) refuse()
                    val ds = coll(ci).devices.map { Item.Device(it) }
                    items.removeAt(ci)
                    items.addAll(ci, ds)
                }
                Op.Reset -> reset(devices)
            }
        }

        fun move(item: Ref, before: Ref?, shown: Set<String>) {
            when (item) {
                is Ref.Device -> {
                    val d = item.id
                    if (d !in shown || find(d) < 0) refuse()
                    if (before is Ref.Device && before.id == d) return
                    val src = items[find(d)] as? Item.Collection
                    when {
                        before == null && src != null -> {
                            take(d)
                            val ci = collection(src.id)
                            if (ci >= 0) items[ci] = coll(ci).let { it.copy(devices = it.devices + d) } else items += Item.Device(d)
                        }
                        before == null -> {
                            take(d)
                            items += Item.Device(d)
                        }
                        before is Ref.Collection -> {
                            var at = collection(before.id)
                            if (at < 0) refuse()
                            take(d)
                            // The collection may have gone with its last
                            // device: then the device stands where it was.
                            collection(before.id).let { if (it >= 0) at = it }
                            items.add(at, Item.Device(d))
                        }
                        before is Ref.Device -> {
                            if (before.id !in shown || find(before.id) < 0) refuse()
                            take(d)
                            val bi = find(before.id)
                            val c = items[bi]
                            if (c is Item.Collection) {
                                val ds = c.devices.toMutableList()
                                ds.add(ds.indexOf(before.id), d)
                                items[bi] = c.copy(devices = ds)
                            } else {
                                items.add(bi, Item.Device(d))
                            }
                        }
                    }
                }
                is Ref.Collection -> {
                    val ci = collection(item.id)
                    if (ci < 0) refuse()
                    if (before is Ref.Collection && before.id == item.id) return
                    if (before != null) {
                        val at = when (before) {
                            is Ref.Collection -> collection(before.id)
                            is Ref.Device -> if (before.id in shown) find(before.id) else -1
                        }
                        if (at < 0) refuse()
                    }
                    val it = items.removeAt(ci)
                    when (before) {
                        null -> items += it
                        is Ref.Collection -> items.add(collection(before.id), it)
                        is Ref.Device -> items.add(find(before.id), it)
                    }
                }
            }
        }

        fun reset(devices: List<String>) {
            val rank = devices.withIndex().associate { (i, d) -> d to i }
            val byRank = Comparator<String> { x, y ->
                val rx = rank[x]
                val ry = rank[y]
                when {
                    rx != null && ry != null -> rx - ry
                    rx != null -> -1
                    ry != null -> 1
                    else -> x.compareTo(y)
                }
            }
            for (i in items.indices) {
                val c = items[i]
                if (c is Item.Collection) items[i] = c.copy(devices = c.devices.sortedWith(byRank))
            }
            fun first(it: Item) = when (it) {
                is Item.Device -> it.id
                is Item.Collection -> it.devices.firstOrNull()
            }
            val sorted = items.sortedWith { x, y ->
                val fx = first(x)
                val fy = first(y)
                when {
                    fx == null && fy == null -> 0
                    fx == null -> 1
                    fy == null -> -1
                    else -> byRank.compare(fx, fy)
                }
            }
            items.clear()
            items += sorted
        }
    }
}
