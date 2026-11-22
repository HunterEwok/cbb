// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.security.MessageDigest
import java.security.SecureRandom

/** The sealed blob of a copy's images and files: its size and SHA-256 (docs/protocol.md, section 4, "The blob"). */
class Blob(val size: Long, val sha256: ByteArray) {
    override fun equals(other: Any?): Boolean = other is Blob && size == other.size && sha256.contentEquals(other.sha256)
    override fun hashCode(): Int = size.hashCode()
    override fun toString(): String = "Blob($size, ${sha256.toHex()})"
    fun toJson(): JsonObject = Wire.obj("size" to Wire.num(size), "sha256" to Wire.bytes(sha256))

    companion object {
        /** A blob's segment before sealing, and after. */
        const val SEGMENT = 64 shl 10
        const val SEALED_SEGMENT = SEGMENT + 16L

        /** The most segments a blob has: 1 GiB of parts. */
        val MAX_SEGMENTS = (Media.MAX_MEDIA + SEGMENT - 1) / SEGMENT

        fun fromJson(o: JsonObject): Blob? = Blob(o.optLong("size") ?: return null, o.optBytes("sha256") ?: return null)

        /** The size of the sealed blob of n bytes of parts. */
        fun sizeOf(n: Long): Long = (n + SEGMENT - 1) / SEGMENT * SEALED_SEGMENT

        /** A new random key for a copy's blob. */
        fun newKey(): ByteArray = ByteArray(32).also { SecureRandom().nextBytes(it) }

        /** Seals the bytes of a copy's parts, one after another, into its blob under the copy's key. */
        fun seal(key: ByteArray, parts: List<ByteArray>): Pair<Blob, ByteArray> {
            val plain = java.io.ByteArrayOutputStream().also { o -> parts.forEach { o.write(it) } }.toByteArray()
            if (plain.isEmpty()) throw Core.Mismatch("a blob of no bytes")
            val n = (plain.size + SEGMENT - 1) / SEGMENT
            val out = java.io.ByteArrayOutputStream(n * SEALED_SEGMENT.toInt())
            for (i in 0 until n) {
                val start = i * SEGMENT
                out.write(segment("seal_segment", key, i, i == n - 1, plain.copyOfRange(start, minOf(start + SEGMENT, plain.size))))
            }
            val data = out.toByteArray()
            return Blob(data.size.toLong(), sha256(data)) to data
        }

        /**
         * Opens a copy's blob into the bytes of the manifest's parts that are
         * no folders, each checked against its own hash; the zeros after them
         * must be zeros. It throws Content.Mismatch when anything does not match.
         */
        fun open(key: ByteArray, blob: Blob, data: ByteArray, m: Media.Manifest): List<ByteArray> {
            if (m.size <= 0 || blob.size != sizeOf(m.size) || data.size.toLong() != blob.size || !sha256(data).contentEquals(blob.sha256)) {
                throw Content.Mismatch()
            }
            val n = (blob.size / SEALED_SEGMENT).toInt()
            val plain = java.io.ByteArrayOutputStream(n * SEGMENT)
            for (i in 0 until n) {
                val start = i * SEALED_SEGMENT.toInt()
                plain.write(segment("open_segment", key, i, i == n - 1, data.copyOfRange(start, start + SEALED_SEGMENT.toInt())))
            }
            val p = plain.toByteArray()
            for (i in m.size.toInt() until p.size) if (p[i] != 0.toByte()) throw Content.Mismatch()
            var at = 0
            return m.parts.filter { !it.dir }.map { part ->
                val bytes = p.copyOfRange(at, at + part.size.toInt())
                if (!sha256(bytes).contentEquals(part.sha256 ?: ByteArray(0))) throw Content.Mismatch()
                at += part.size.toInt()
                bytes
            }
        }

        private fun segment(op: String, key: ByteArray, index: Int, last: Boolean, data: ByteArray): ByteArray {
            val ok = Core.run(
                op,
                Wire.obj("key" to Wire.bytes(key), "index" to Wire.num(index.toLong()), "last" to JsonPrimitive(last), "data" to Wire.bytes(data)),
            ) as? JsonObject ?: throw Core.Mismatch("the answer to $op is not an object")
            return ok.optBytes("data") ?: throw Core.Mismatch("the answer to $op has no data")
        }
    }
}
