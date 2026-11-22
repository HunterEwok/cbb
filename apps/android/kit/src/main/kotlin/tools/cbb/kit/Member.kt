// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * What the member's answers and events name that the app reads (docs/protocol.md,
 * sections 4, 5, 15 and 17): sync modes, a copy's kind and how it came, a
 * device's description, a command's result and a key's evidence.
 */
object Member {
    /** The sync modes (design.md, "Sync modes"). */
    val MODES = setOf("own", "shared", "receive", "send")

    /** Whether a device in sync mode mode takes the group's copies into its clipboard by itself; a device without a mode (null) shares. */
    fun receives(mode: String?): Boolean = mode == null || mode == "shared" || mode == "receive"

    /** Whether a device in sync mode mode sends its own copies to the group by itself. */
    fun sends(mode: String?): Boolean = mode == null || mode == "shared" || mode == "send"

    /** The kind of an event: a secret is kept only briefly (section 5); media is images or files, of which the kit takes the text. */
    enum class Kind(val wire: String) {
        TEXT("text"), SECRET("secret"), MEDIA("media");

        companion object {
            fun of(s: String): Kind? = entries.firstOrNull { it.wire == s }
        }
    }

    /** How a text reached the member that made the event. */
    enum class Via(val wire: String) {
        COPY("copy"),
        /** Sent from a phone's app. */
        PHONE("phone"),
        UNIVERSAL_CLIPBOARD("universal-clipboard");

        companion object {
            fun of(s: String): Via? = entries.firstOrNull { it.wire == s }
        }
    }

    /**
     * What a hello says about the sender's device (section 4, "Device"): its
     * form, its system's version, its own version and its network card's MAC
     * address. Shown, never trusted; any field may be absent.
     */
    data class DeviceInfo(
        val form: String? = null,
        val osVersion: String? = null,
        val version: String? = null,
        val mac: String? = null,
    ) {
        /**
         * The same without its invalid fields: an unknown form, a version
         * longer than 32 bytes or with control characters, a MAC address
         * other than six lowercase hex bytes with colons; null when nothing
         * is left.
         */
        val cleaned: DeviceInfo?
            get() {
                fun short(s: String?): String? =
                    s?.takeIf { it.isNotEmpty() && it.toByteArray().size <= 32 && it.none { c -> Character.isISOControl(c) } }
                val d = DeviceInfo(
                    form = form?.takeIf { it in FORMS },
                    osVersion = short(osVersion),
                    version = short(version),
                    mac = mac?.takeIf { MAC.matches(it) },
                )
                return d.takeIf { it != DeviceInfo() }
            }

        fun toJson(): JsonObject = Wire.obj(
            "form" to Wire.str(form),
            "os_version" to Wire.str(osVersion),
            "version" to Wire.str(version),
            "mac" to Wire.str(mac),
        )

        companion object {
            /** The forms a device may name, for its icon. */
            val FORMS = listOf("laptop", "desktop", "phone", "tablet", "tv", "board", "server", "router", "console", "watch", "retro", "other")
            private val MAC = Regex("^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")

            /** The device of a hello, null when it does not decode. */
            fun fromJson(e: JsonElement?): DeviceInfo? = (e as? JsonObject)?.let {
                runCatching {
                    DeviceInfo(it.optString("form"), it.optString("os_version"), it.optString("version"), it.optString("mac"))
                }.getOrNull()
            }
        }
    }

    /** The answer to a command (section 15): its ID, "done", "refused" or "failed", and why for the last two. */
    data class CommandResult(
        val id: String,
        val status: String,
        val reason: String? = null,
        /** The device that answered, the command's receiver; a member that passes the result back leaves it. */
        val by: String? = null,
    ) {
        val done: Boolean get() = status == "done"

        fun toJson(): JsonObject =
            Wire.obj("id" to Wire.str(id), "by" to Wire.str(by), "status" to Wire.str(status), "reason" to Wire.str(reason))

        companion object {
            fun fromJson(o: JsonObject): CommandResult = CommandResult(
                o.optString("id") ?: "",
                o.optString("status") ?: "",
                o.optString("reason"),
                o.optString("by"),
            )
        }
    }

    /**
     * An attestation of one of a device's keys (section 17, "Evidence"):
     * format ANDROID with the Keystore's chain, leaf first, for the key
     * MEMBER, made with the challenge of groupTag (null outside a group)
     * and salt.
     */
    class Evidence(
        val format: String,
        val key: String,
        val groupTag: String?,
        val salt: ByteArray,
        val chain: List<ByteArray>,
    ) {
        fun toJson(): JsonObject = Wire.obj(
            "format" to Wire.str(format),
            "key" to Wire.str(key),
            "group_tag" to Wire.str(groupTag),
            "salt" to Wire.bytes(salt),
            "chain" to Wire.list(chain),
        )

        override fun equals(other: Any?): Boolean =
            other is Evidence && format == other.format && key == other.key && groupTag == other.groupTag && salt.contentEquals(other.salt) &&
                chain.size == other.chain.size && chain.zip(other.chain).all { (a, b) -> a.contentEquals(b) }

        override fun hashCode(): Int = salt.contentHashCode()

        companion object {
            const val ANDROID = "android-key"
            const val MEMBER = "member"

            fun fromJson(o: JsonObject): Evidence = Evidence(
                o.optString("format") ?: "",
                o.optString("key") ?: "",
                o.optString("group_tag")?.takeIf { it.isNotEmpty() },
                o.optBytes("salt") ?: ByteArray(0),
                o.optBytesList("chain") ?: emptyList(),
            )
        }
    }
}

internal fun ByteArray?.contentEqualsOrNull(other: ByteArray?): Boolean =
    if (this == null) other == null else other != null && contentEquals(other)
