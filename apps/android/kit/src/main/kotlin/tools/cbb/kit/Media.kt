// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * The manifest of a media event: images or files (docs/protocol.md,
 * section 4, "Media"), checked as Go's package clip does. The kit takes the
 * event and its plain-text alternative; fetching the content comes later.
 */
object Media {
    /** The largest copy, all its parts together, that the group carries. */
    const val MAX_MEDIA = 1L shl 30
    const val MAX_PARTS = 10_000
    const val MAX_TYPES = 8
    const val MAX_PATHS = 2 shl 20
    const val MAX_PATH = 16 shl 10
    const val MAX_NAME = 765

    /** The largest plain-text alternative of a media event, in bytes of UTF-8. */
    const val MAX_ALT_TEXT = 256 shl 10

    val TYPES = setOf("image/png", "image/jpeg", "image/gif", "text/html")

    /** What a media event's content is. */
    data class Manifest(val size: Long, val parts: List<Part>) {
        /** Whether it is a copy of files, not clipboard data. */
        val isFiles: Boolean get() = parts.firstOrNull()?.path != null

        /** Whether it passes Go's Manifest.Validate. */
        val isValid: Boolean
            get() {
                if (parts.isEmpty() || parts.size > MAX_PARTS) return false
                val files = isFiles
                if (!files && parts.size > MAX_TYPES) return false
                var total = 0L
                var paths = 0
                val seen = HashSet<String>()
                for (p in parts) {
                    val key = if (files) {
                        if (p.path == null || p.type != null || !checkPath(p.path)) return false
                        paths += p.path.toByteArray().size
                        // Paths compare as a receiver writes them: two that savePath makes one would land in one place.
                        savePath(p.path)
                    } else {
                        if (p.type == null || p.dir || p.type !in TYPES) return false
                        p.type
                    }
                    if (!seen.add(key)) return false
                    if (p.dir) {
                        if (p.size != 0L || p.sha256 != null) return false
                        continue
                    }
                    if (p.sha256?.size != 32 || p.size < 0 || p.size > MAX_MEDIA) return false
                    total += p.size
                }
                if (paths > MAX_PATHS || total != size || total > MAX_MEDIA) return false
                if (files) {
                    // No file is inside another, by the paths as a receiver writes them.
                    val saved = parts.map { savePath(it.path!!) to it.dir }
                    val dirs = saved.toMap()
                    for ((path, _) in saved) {
                        var i = path.indexOf('/')
                        while (i >= 0) {
                            if (dirs[path.substring(0, i)] == false) return false
                            i = path.indexOf('/', i + 1)
                        }
                    }
                }
                return true
            }

        fun toJson(): JsonObject = Wire.obj(
            "size" to Wire.num(size),
            "parts" to JsonArray(parts.map { it.toJson() }),
        )

        companion object {
            /**
             * Reads a manifest received from another member (docs/protocol.md, section 4, "Media"): the Rust core decides
             * whether it is taken, in the strict form of signed bodies and in its canonical form, with no member its table
             * does not name; null when it is not.
             */
            fun parse(body: ByteArray): Manifest? {
                if (Core.bodyRefusal("manifest", body) != null) return null
                val m = runCatching { Wire.parse(body)?.let { fromJson(it) } }.getOrNull() ?: return null
                return m.takeIf { it.isValid }
            }

            fun fromJson(o: JsonObject): Manifest = Manifest(
                o.optLong("size") ?: 0,
                o.optArray("parts")?.map { Part.fromJson(it as? JsonObject ?: throw WireTypeException("parts: not an object")) } ?: emptyList(),
            )
        }
    }

    /** One item of a manifest: clipboard data of a type, or a file or folder at a path. */
    class Part(
        val type: String? = null,
        val path: String? = null,
        val dir: Boolean = false,
        val size: Long = 0,
        val sha256: ByteArray? = null,
    ) {
        override fun equals(other: Any?): Boolean =
            other is Part && type == other.type && path == other.path && dir == other.dir && size == other.size &&
                sha256.contentEqualsOrNull(other.sha256)

        override fun hashCode(): Int = (type ?: path).hashCode()

        fun toJson(): JsonObject = Wire.obj(
            "type" to Wire.str(type),
            "path" to Wire.str(path),
            "dir" to if (dir) JsonPrimitive(true) else null,
            "size" to Wire.num(size.takeIf { it != 0L }),
            "sha256" to Wire.bytes(sha256?.takeIf { it.isNotEmpty() }),
        )

        companion object {
            fun fromJson(o: JsonObject): Part = Part(
                o.optString("type")?.takeIf { it.isNotEmpty() },
                o.optString("path")?.takeIf { it.isNotEmpty() },
                o.optBool("dir") ?: false,
                o.optLong("size") ?: 0,
                // An empty hash stays: a folder has none, as in Go, not even an empty one.
                o.optBytes("sha256"),
            )
        }
    }

    /** Whether path is names joined by "/", each one checkName takes, at most MAX_PATH bytes as a receiver writes it. */
    fun checkPath(path: String): Boolean =
        path.isNotEmpty() && path.toByteArray().size <= MAX_PATH && savePath(path).toByteArray().size <= MAX_PATH &&
            path.split('/').all { checkName(it) }

    /** saveName for each name of a path, as Go's clip.SavePath. */
    fun savePath(path: String): String = path.split('/').joinToString("/") { saveName(it) }

    /**
     * A name that checkName takes, made of one a system gave, as Go's
     * clip.CleanName: the characters it does not allow become "_", a
     * device name of Windows gets "_" after its base and one that ends in a
     * dot or a space gets "_" after it.
     */
    fun cleanName(given: String): String {
        val sb = StringBuilder()
        var i = 0
        while (i < given.length) {
            val cp = given.codePointAt(i)
            i += Character.charCount(cp)
            val bad = cp in 0xd800..0xdfff || cp < 0x20 || cp == 0x7f || cp in 0x80..0x9f || (cp < 0x80 && cp.toChar() in "/\\:*?\"<>|")
            if (bad) sb.append('_') else sb.appendCodePoint(cp)
        }
        // What fixName adds can take the name past MAX_NAME, so the name
        // loses characters at its end until the fixed name fits.
        var name = sb.toString()
        while (true) {
            if (name.isEmpty() || name == "." || name == "..") return "_"
            val fixed = fixName(name)
            if (fixed.toByteArray().size <= MAX_NAME) return fixed
            val cp = name.codePointBefore(name.length)
            name = name.substring(0, name.length - Character.charCount(cp))
        }
    }

    /** Gives a device name of Windows "_" after its base and one that ends in a dot or a space "_" after it. */
    private fun fixName(given: String): String {
        var name = given
        if (device(name)) name = withUnderscore(name)
        if (name.endsWith('.') || name.endsWith(' ')) name += "_"
        return name
    }

    /**
     * The name under which a receiver writes a name that checkName took, as Go's clip.SaveName: a device name of
     * Windows gets "_" after its base, the part before its first dot, and any other name stays as it is.
     */
    fun saveName(name: String): String = if (device(name)) withUnderscore(name) else name

    /** Puts "_" after a name's base: CON.txt becomes CON_.txt, as Windows reserves the base with any extension. */
    private fun withUnderscore(name: String): String =
        name.substringBefore('.') + "_" + if ('.' in name) "." + name.substringAfter('.') else ""

    /** name with its ASCII letters in upper case and every other character as it is, as every implementation compares names. */
    private fun upperASCII(s: String): String = buildString { for (c in s) append(if (c in 'a'..'z') c - 32 else c) }

    /**
     * Whether name is a device name of Windows, as Go's clip.device: before its first dot, and without the spaces that
     * end that part, one of CON, PRN, AUX, NUL, CONIN$, CONOUT$, or COM or LPT followed by one digit 0 to 9 or one of
     * the superscripts ¹, ² and ³, in any case of ASCII letters.
     */
    private fun device(name: String): Boolean {
        val base = upperASCII(name.substringBefore('.').trimEnd(' '))
        if (base in setOf("CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$")) return true
        if (!base.startsWith("COM") && !base.startsWith("LPT")) return false
        return base.substring(3) in setOf("0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "\u00b9", "\u00b2", "\u00b3")
    }

    /**
     * Whether a name of a path is one every system can hold, as Go's
     * clip.CheckName decides: 1 to 765 bytes, as a receiver writes it too (saveName), not "." or "..", no control
     * characters, separators or characters Windows does not allow, no dot
     * or space at the end, no name Windows reserves.
     */
    fun checkName(name: String): Boolean {
        val bytes = name.toByteArray().size
        if (bytes == 0 || bytes > MAX_NAME || saveName(name).toByteArray().size > MAX_NAME || name == "." || name == "..") return false
        if (name.any { it in "/\\:*?\"<>|" || it < ' ' || it == '\u007f' || it in '\u0080'..'\u009f' }) return false
        if (name.endsWith('.') || name.endsWith(' ')) return false
        return !reserved(name)
    }

    /**
     * Whether name, before its first dot, is a device name of Windows that a manifest may not hold: CON, PRN, AUX, NUL,
     * COM1 to COM9 and LPT1 to LPT9, in any case of ASCII letters, as Go's clip.reserved.
     */
    private fun reserved(name: String): Boolean {
        val base = upperASCII(name.substringBefore('.'))
        if (base in setOf("CON", "PRN", "AUX", "NUL")) return true
        return base.length == 4 && (base.startsWith("COM") || base.startsWith("LPT")) && base[3] in '1'..'9'
    }
}
