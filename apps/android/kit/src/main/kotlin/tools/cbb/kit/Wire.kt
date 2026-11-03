// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.longOrNull
import java.util.Base64

/** The JSON of the wire: objects with sorted keys, bytes as base64, as Go writes them. */
internal object Wire {
    /** An object of the non-null values, its keys sorted. */
    fun obj(vararg pairs: Pair<String, JsonElement?>): JsonObject =
        JsonObject(pairs.filter { it.second != null }.sortedBy { it.first }.associate { it.first to it.second!! })

    fun str(s: String?): JsonElement? = s?.let { JsonPrimitive(it) }
    fun num(n: Long?): JsonElement? = n?.let { JsonPrimitive(it) }
    fun bytes(b: ByteArray?): JsonElement? = b?.let { JsonPrimitive(Base64.getEncoder().encodeToString(it)) }
    fun list(bs: List<ByteArray>?): JsonElement? = bs?.let { l -> JsonArray(l.map { bytes(it)!! }) }

    fun encode(e: JsonElement): ByteArray = Json.encodeToString(JsonElement.serializer(), e).toByteArray()

    /** The object in body, or null when it is not JSON or not an object. */
    fun parse(body: ByteArray): JsonObject? =
        try {
            Json.parseToJsonElement(String(body, Charsets.UTF_8)) as? JsonObject
        } catch (e: kotlinx.serialization.SerializationException) {
            null
        } catch (e: IllegalArgumentException) {
            null
        }
}

/** Thrown when a JSON value has the wrong type. */
internal class WireTypeException(message: String) : Exception(message)

// Readers that take a missing key, or null, as absent, and refuse a value
// of another type, as Go's encoding/json does.
internal fun JsonObject.opt(key: String): JsonElement? = get(key)?.takeUnless { it is JsonNull }

internal fun JsonObject.optString(key: String): String? =
    opt(key)?.let { (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content ?: throw WireTypeException("$key: not a string") }

internal fun JsonObject.optLong(key: String): Long? =
    // -?[1-9][0-9]*|0 as written, as in Go: "-0" and "-00" are no integers here (Go reads
    // "-0" as 0, the lite member's reader as a float).
    opt(key)?.let { (it as? JsonPrimitive)?.takeIf { p -> !p.isString && INTEGER.matches(p.content) }?.longOrNull ?: throw WireTypeException("$key: not an integer") }

private val INTEGER = Regex("0|-?[1-9][0-9]*")

internal fun JsonObject.optBool(key: String): Boolean? =
    opt(key)?.let { (it as? JsonPrimitive)?.takeIf { p -> !p.isString }?.booleanOrNull ?: throw WireTypeException("$key: not a boolean") }

internal fun JsonObject.optBytes(key: String): ByteArray? =
    optString(key)?.let { Strict.base64(it) ?: throw WireTypeException("$key: not base64") }

internal fun JsonObject.optObject(key: String): JsonObject? =
    opt(key)?.let { it as? JsonObject ?: throw WireTypeException("$key: not an object") }

internal fun JsonObject.optArray(key: String): JsonArray? =
    opt(key)?.let { it as? JsonArray ?: throw WireTypeException("$key: not an array") }

internal fun JsonObject.optBytesList(key: String): List<ByteArray>? =
    optArray(key)?.map {
        val p = it as? JsonPrimitive ?: throw WireTypeException("$key: not a string")
        if (!p.isString) throw WireTypeException("$key: not a string")
        Strict.base64(p.content) ?: throw WireTypeException("$key: not base64")
    }
