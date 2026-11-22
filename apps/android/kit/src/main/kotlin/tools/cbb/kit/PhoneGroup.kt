// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import kotlinx.serialization.json.JsonPrimitive
import java.io.File

/**
 * The phone's group as the app notes it beside the member's own folder:
 * the phone's device ID, the group's ID and whether the phone holds the
 * root. The member keeps the group's set itself (CoreMember, D-126) and
 * answers its state (CoreMember.group); the keys stay in the Android
 * Keystore. It is saved as JSON next to the app's other data.
 */
class PhoneGroup private constructor(
    /** This phone's device ID. */
    val device: String,
    /** The Group ID (hex) the member's set names. */
    val group: String,
) {
    /** Whether this phone holds the current root's key: it made the group, or changed its root to itself. */
    var isRoot = true
        internal set

    /** Whether the member's state names this phone an admin (GroupState.me.admin); set as the state arrives. */
    @Volatile var admin = false

    /** Whether this phone may add and remove devices: the root and the admins. */
    val isAdmin: Boolean get() = isRoot || admin

    /** The group tag the computers publish. */
    val tag: String get() = group.take(16)

    class Failure(message: String) : Exception(message)

    /**
     * The computer keeps its keys in a file, which a thief with it can copy
     * and then act as an admin: the user allows it after a warning
     * (docs/protocol.md, section 17).
     */
    class FileKey : Exception("its keys sit in a file")

    /** The computer is a rootless install, which is never an admin (D-79). */
    class Rootless : Exception("it is installed without root")

    /** The group's key level does not let the device's keys be an admin or the root; the root sets another level first. */
    class BelowKeyLevel : Exception("the group's key level does not let these keys in")

    /** The group as JSON, to save it. */
    fun toJson(): ByteArray = Wire.encode(
        Wire.obj(
            "device" to Wire.str(device),
            "is_root" to JsonPrimitive(isRoot),
            "group06" to Wire.str(group),
            "admin06" to JsonPrimitive(admin),
        ),
    )

    /** Saves the group in one step, so a crash leaves the old file or the new one. */
    fun save(file: File) {
        file.parentFile?.mkdirs()
        val tmp = File(file.parentFile, file.name + ".tmp")
        tmp.writeBytes(toJson())
        if (!tmp.renameTo(file)) {
            file.delete()
            if (!tmp.renameTo(file)) throw java.io.IOException("cannot save ${file.path}")
        }
    }

    companion object {
        /** The message of the Failure for a name that the records do not accept. */
        const val INVALID_NAME = "a device name has 1 to 64 bytes and no control characters"

        /** A name that the records accept: 1 to 64 bytes without control characters, or "Android". */
        fun validName(s: String): String {
            val out = StringBuilder()
            var i = 0
            while (i < s.length) {
                val cp = s.codePointAt(i)
                i += Character.charCount(cp)
                if (Character.getType(cp) == Character.CONTROL.toInt()) continue
                val ch = String(Character.toChars(cp))
                if ((out.toString() + ch).toByteArray().size > 64) break
                out.append(ch)
            }
            return out.toString().ifEmpty { "Android" }
        }

        /**
         * A group this phone made (CorePairing.newGroup06, root) or joined
         * (CorePairing.Joiner): its device and Group ID; the member keeps
         * the set.
         */
        fun of(device: String, group: String, root: Boolean): PhoneGroup {
            val g = PhoneGroup(device, group)
            g.isRoot = root
            return g
        }

        /** A group saved with toJson; Failure for one made before 0.6, which names no Group ID. */
        fun fromJson(data: ByteArray): PhoneGroup {
            val o = Wire.parse(data) ?: throw Failure("not a saved group")
            try {
                val group = o.optString("group06") ?: throw Before06()
                val g = PhoneGroup(o.optString("device") ?: throw Failure("no device"), group)
                g.isRoot = (o.opt("is_root") as? JsonPrimitive)?.booleanOrNull() ?: true
                g.admin = o.optBool("admin06") ?: false
                return g
            } catch (e: WireTypeException) {
                throw Failure("not a saved group: ${e.message}")
            }
        }

        /**
         * Reads a saved group; null when there is none. A group made before
         * 0.6 is Before06: the app shows that a new group is needed, and
         * the file stays until the person leaves it (D-126).
         */
        fun load(file: File): PhoneGroup? = if (file.exists()) fromJson(file.readBytes()) else null

        private fun JsonPrimitive.booleanOrNull(): Boolean? = content.toBooleanStrictOrNull().takeIf { !isString }
    }

    /** The saved group was made before 0.6, which this version no longer runs (D-126). */
    class Before06 : Exception("this group was made before 0.6: make a new group")
}
