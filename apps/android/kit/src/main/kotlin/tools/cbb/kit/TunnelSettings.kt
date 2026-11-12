// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import java.security.MessageDigest
import java.util.Base64
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject

/**
 * The checks of the settings a hub gives with its next key (section 11,
 * "The hub's key"), which the kit carries as JSON text for the tunnel.
 */
internal object TunnelSettings {
    /**
     * Whether the tunnel takes the obfuscation settings text, within the
     * bounds both the Rust member and internal/tunnel check: at most 16 junk
     * packets of at most 1000 bytes, paddings of 16 to 64 bytes that keep the
     * handshake messages' sizes apart, type ranges above 4 that do not
     * overlap, and a header protection key of 32 bytes, not all zeros.
     */
    fun obfuscationValid(text: String): Boolean {
        val o = parse(text) ?: return false
        val jc = int(o, "jc") ?: return false
        val jmin = int(o, "jmin") ?: return false
        val jmax = int(o, "jmax") ?: return false
        val pads = listOf("s1", "s2", "s3", "s4").map { int(o, it) ?: return false }
        if (jc > 16 || jmin > jmax || jmax > 1000 || pads.any { it !in 16..64 }) return false
        if (setOf(148 + pads[0], 92 + pads[1], 64 + pads[2]).size != 3) return false
        val key = string(o, "header_protection_key")?.let { runCatching { Base64.getDecoder().decode(it) }.getOrNull() }
        if (key == null || key.size != 32 || key.all { it == 0.toByte() }) return false
        val types = listOf("h1", "h2", "h3", "h4").map { k -> string(o, k)?.let(::range) ?: return false }
        if (types.any { it.first <= 4 }) return false
        for (i in types.indices) for (j in i + 1 until types.size) {
            if (types[i].first <= types[j].last && types[j].first <= types[i].last) return false
        }
        return true
    }

    /**
     * Whether next is the way over VLESS a hub gives with its next key beside
     * now: the same forwarder, a VLESS user ID, and now's path with its group
     * part made for that ID (section 13, "VLESS").
     */
    fun isNextVless(next: String, now: String): Boolean {
        val n = parse(next) ?: return false
        val p = parse(now) ?: return false
        val same = listOf("transport", "endpoint", "server_name").all { string(n, it) == string(p, it) }
        val id = string(n, "id") ?: return false
        val path = string(p, "path")?.takeIf { it.startsWith("/") } ?: return false
        if (!same || string(n, "endpoint") == null || !isUserId(id)) return false
        val base = path.substring(1).substringBefore('/')
        return string(n, "path") == "/$base/${groupPath(id)}"
    }

    /**
     * The group's part of the XHTTP path for the VLESS user ID id, as the
     * forwarder makes it: the first 16 bytes of SHA-256 over "cbb group
     * path", a zero byte and the ID, in unpadded base64url.
     */
    fun groupPath(id: String): String {
        val sum = MessageDigest.getInstance("SHA-256").digest("cbb group path\u0000$id".toByteArray())
        return Base64.getUrlEncoder().withoutPadding().encodeToString(sum.copyOf(16))
    }

    /** Whether s is a VLESS user ID: a UUID of version 4 in lowercase. */
    fun isUserId(s: String): Boolean =
        s.length == 36 && s.withIndex().all { (i, c) ->
            when (i) {
                8, 13, 18, 23 -> c == '-'
                14 -> c == '4'
                19 -> c in "89ab"
                else -> c in "0123456789abcdef"
            }
        }

    /** "min-max": two decimal numbers of 32 bits in their shortest form, the first not above the second. */
    private fun range(s: String): LongRange? {
        val parts = s.split('-')
        if (parts.size != 2) return null
        val lo = number(parts[0]) ?: return null
        val hi = number(parts[1]) ?: return null
        return if (lo <= hi) lo..hi else null
    }

    private fun number(s: String): Long? =
        if (s.isEmpty() || s.length > 10 || (s.length > 1 && s[0] == '0') || !s.all { it in '0'..'9' }) {
            null
        } else {
            s.toLong().takeIf { it <= 0xFFFFFFFFL }
        }

    private fun parse(text: String): JsonObject? = runCatching { Json.parseToJsonElement(text).jsonObject }.getOrNull()

    private fun int(o: JsonObject, key: String): Int? =
        (o[key] as? JsonPrimitive)?.takeIf { !it.isString }?.content?.toIntOrNull()?.takeIf { it >= 0 }

    private fun string(o: JsonObject, key: String): String? = (o[key] as? JsonPrimitive)?.takeIf { it.isString }?.content
}
