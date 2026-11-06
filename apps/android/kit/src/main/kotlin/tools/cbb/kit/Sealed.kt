// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * Copies sealed end to end (docs/protocol.md, section 4): the device that
 * copies seals each copy to the devices of the group that read copies and
 * signs it, so that the members that pass it on, a hub among them, neither
 * read nor change it. The Rust core seals, checks and opens them
 * (cbb_core::copy, docs/core-api.md); the kit carries them.
 */
class Sealed(
    val id: String,
    val origin: String,
    val time: Member.Timestamp,
    /** Milliseconds since the copy, as of the moment the frame is written; not signed. */
    val ageMS: Long = 0,
    val cert: ByteArray,
    val issuer: ByteArray? = null,
    val wraps: List<Wrap>,
    val payload: ByteArray? = null,
    val payloadSHA256: ByteArray? = null,
    val blob: Blob? = null,
    val sig: ByteArray = ByteArray(0),
) {
    /** A copy's key, wrapped for one reader. */
    class Wrap(val to: String, val key: ByteArray) {
        override fun equals(other: Any?): Boolean = other is Wrap && to == other.to && key.contentEquals(other.key)
        override fun hashCode(): Int = to.hashCode()
        fun toJson(): JsonObject = Wire.obj("to" to Wire.str(to), "key" to Wire.bytes(key))
    }

    /** Whether it is a secret's mark: the copy without its payload. */
    val isMark: Boolean get() = payload == null

    /** The SHA-256 of the payload, which a mark carries. */
    val payloadHash: ByteArray? get() = payload?.let { sha256(it) } ?: payloadSHA256

    /** The mark of this copy: the same without its payload. */
    val mark: Sealed get() = with(payload = null, payloadSHA256 = payloadHash)

    fun with(ageMS: Long = this.ageMS, payload: ByteArray? = this.payload, payloadSHA256: ByteArray? = this.payloadSHA256, sig: ByteArray = this.sig): Sealed =
        Sealed(id, origin, time, ageMS, cert, issuer, wraps, payload, payloadSHA256, blob, sig)

    /** The shape a receiver checks before anything else, as Go's Sealed.Validate; the core checks the rest. */
    val isValid: Boolean
        get() {
            if (!GroupCertificates.isDeviceID(id) || !GroupCertificates.isDeviceID(origin) || time.isZero ||
                time.wall > Member.Timestamp.MAX_WALL || ageMS < 0 || cert.isEmpty() || sig.isEmpty() || wraps.size !in 1..MAX_READERS
            ) {
                return false
            }
            for ((i, w) in wraps.withIndex()) {
                if (!GroupCertificates.isDeviceID(w.to) || w.key.size != WRAP_SIZE) return false
                if (i > 0 && wraps[i - 1].to >= w.to) return false
            }
            val p = payload
            val h = payloadSHA256
            when {
                p != null && h == null -> if (p.size - 16 !in PAYLOAD_STEPS) return false
                p == null && h != null -> if (h.size != 32) return false
                else -> return false
            }
            val b = blob
            if (b != null) {
                if (b.size <= 0 || b.size % Blob.SEALED_SEGMENT != 0L || b.size / Blob.SEALED_SEGMENT > Blob.MAX_SEGMENTS || b.sha256.size != 32) return false
            }
            return true
        }

    fun toJson(): JsonObject = Wire.obj(
        "id" to Wire.str(id),
        "origin" to Wire.str(origin),
        "time" to Wire.str(time.toString()),
        "age_ms" to Wire.num(ageMS),
        "cert" to Wire.bytes(cert),
        "issuer" to Wire.bytes(issuer?.takeIf { it.isNotEmpty() }),
        "wraps" to JsonArray(wraps.map { it.toJson() }),
        "payload" to Wire.bytes(payload),
        "payload_sha256" to Wire.bytes(payloadSHA256),
        "blob" to blob?.toJson(),
        "sig" to Wire.bytes(sig),
    )

    override fun equals(other: Any?): Boolean =
        other is Sealed && id == other.id && origin == other.origin && time == other.time && ageMS == other.ageMS &&
            cert.contentEquals(other.cert) && issuer.contentEqualsOrNull(other.issuer) && wraps == other.wraps &&
            payload.contentEqualsOrNull(other.payload) && payloadSHA256.contentEqualsOrNull(other.payloadSHA256) && blob == other.blob &&
            sig.contentEquals(other.sig)

    override fun hashCode(): Int = id.hashCode()

    override fun toString(): String = "Sealed($id from $origin at $time, ${wraps.size} readers${if (isMark) ", mark" else ""})"

    companion object {
        /** The most readers a copy is sealed to. */
        const val MAX_READERS = 256

        /** A wrap's size: X-Wing's encapsulated key, the copy's key and its tag. */
        const val WRAP_SIZE = 1120 + 32 + 16

        /** The sizes a copy's content is padded to. */
        internal val PAYLOAD_STEPS = setOf(1 shl 10, 4 shl 10, 16 shl 10, 64 shl 10, 256 shl 10, 1 shl 20, 2 shl 20, 3 shl 20, 4 shl 20)

        /** The keys a copy in the open has, which a sealed one never takes. */
        private val OPEN = listOf("kind", "text", "via", "media")

        /** The sealed copy in o, or null when it does not decode or is a copy in the open. */
        fun fromJson(o: JsonObject): Sealed? =
            try {
                if (OPEN.any { o.opt(it) != null }) {
                    null
                } else {
                    Sealed(
                        id = o.optString("id") ?: return null,
                        origin = o.optString("origin") ?: return null,
                        time = Member.Timestamp.parse(o.optString("time") ?: return null) ?: return null,
                        ageMS = o.optLong("age_ms") ?: 0,
                        cert = o.optBytes("cert") ?: return null,
                        issuer = o.optBytes("issuer")?.takeIf { it.isNotEmpty() },
                        wraps = (o.optArray("wraps") ?: return null).map { w ->
                            val wo = w as? JsonObject ?: return null
                            Wrap(wo.optString("to") ?: return null, wo.optBytes("key") ?: return null)
                        },
                        payload = o.optBytes("payload")?.takeIf { it.isNotEmpty() },
                        payloadSHA256 = o.optBytes("payload_sha256")?.takeIf { it.isNotEmpty() },
                        blob = o.optObject("blob")?.let { Blob.fromJson(it) ?: return null },
                        // The core's sealed copy has no signature yet.
                        sig = o.optBytes("sig") ?: ByteArray(0),
                    )
                }
            } catch (e: WireTypeException) {
                null
            }

        internal fun sha256(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(b)
    }
}

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
            return Blob(data.size.toLong(), Sealed.sha256(data)) to data
        }

        /**
         * Opens a copy's blob into the bytes of the manifest's parts that are
         * no folders, each checked against its own hash; the zeros after them
         * must be zeros. It throws Content.Mismatch when anything does not match.
         */
        fun open(key: ByteArray, blob: Blob, data: ByteArray, m: Media.Manifest): List<ByteArray> {
            if (m.size <= 0 || blob.size != sizeOf(m.size) || data.size.toLong() != blob.size || !Sealed.sha256(data).contentEquals(blob.sha256)) {
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
                if (!Sealed.sha256(bytes).contentEquals(part.sha256 ?: ByteArray(0))) throw Content.Mismatch()
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

/**
 * What this phone seals its copies with and opens the others' with: its
 * member certificate and key, which signs, its secret for sealed messages,
 * and the group's records, which name the readers and check the origins.
 */
class CopyKeys(
    val device: String,
    private val cert: ByteArray,
    private val issuer: ByteArray?,
    private val signer: CertificateSigner,
    private val secret: ByteArray,
    private val records: () -> RecordSet?,
) {
    class NoRecords : Exception("this phone has no records of its group yet, so it neither seals nor checks copies")

    /** Why the last copy sealed to this phone did not open, for the app's log and the tests. */
    @Volatile var lastUnopened: String? = null
        private set

    /** Seals and signs a copy this phone made (section 4, "Sealing"), with the blob of its images or files sealed under key. */
    fun seal(e: Member.Event, key: ByteArray?, blob: Blob?): Sealed =
        (records() ?: throw NoRecords()).sealCopy(e, cert, issuer, key, blob, signer)

    /**
     * Checks a copy a peer sent against the records and opens it when it is
     * sealed to this phone (section 4, "Opening"); a copy that is not is
     * kept unread, to order and pass on. It throws for a copy the records
     * refuse, which is dropped.
     */
    fun take(s: Sealed): Member.Event {
        val set = records() ?: throw NoRecords()
        set.checkCopy(s)
        val e = Member.Event.of(s)
        if (s.isMark || s.wraps.none { it.to == device }) return e
        // A copy sealed to this phone that does not open stays unread, as
        // the others may read theirs.
        return try {
            val o = open(s)
            val k = o.optString("kind")
            val kind = k?.let { Member.Kind.of(it) } ?: throw Core.Mismatch("its kind ${k ?: "is missing"} is not one this phone knows")
            val v = o.optString("via")
            val via = if (v == null) Member.Via.COPY else Member.Via.of(v) ?: throw Core.Mismatch("its via $v is not one this phone knows")
            val media = o.optObject("media")?.let { Media.Manifest.fromJson(it) }
            e.copy(kind = kind, via = via, text = o.optString("text") ?: "", media = media, key = o.optBytes("key"), unread = false)
        } catch (x: Exception) {
            lastUnopened = "the copy ${s.id} from ${s.origin} did not open: ${x.message ?: x.javaClass.simpleName}"
            e
        }
    }

    private fun open(s: Sealed): JsonObject =
        Core.run("open_copy", Wire.obj("event" to s.toJson(), "me" to Wire.str(device), "secret" to Wire.bytes(secret))) as? JsonObject
            ?: throw Core.Mismatch("the answer to open_copy is not an object")
}

/** The JSON a sealed copy's fields need, for the core. */
internal fun Member.Event.sealArgs(cert: ByteArray, issuer: ByteArray?, key: ByteArray?, blob: Blob?): Array<Pair<String, JsonElement?>> = arrayOf(
    "id" to Wire.str(id),
    "origin" to Wire.str(origin),
    "time" to Wire.str(time.toString()),
    "cert" to Wire.bytes(cert),
    "issuer" to Wire.bytes(issuer),
    "kind" to Wire.str(kind.wire),
    "via" to Wire.str(via.wire),
    "text" to Wire.str(text),
    "media" to media?.toJson(),
    "blob" to blob?.toJson(),
    "key" to Wire.bytes(key),
)
