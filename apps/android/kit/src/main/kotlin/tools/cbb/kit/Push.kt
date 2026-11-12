// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * Push to the phone whose app is closed (docs/core-api.md, "Push"): the
 * core's four calls, the Android twin of the Swift kit's `Push`. The app
 * draws the keys and makes each group's registration; its background code
 * opens what arrives. No number of the format lives here but the platforms'
 * env values the app names: the core checks them.
 */
object Push {
    /** The platforms as the env registry numbers them. */
    object Env {
        const val FCM = 3L
        const val UNIFIED_PUSH = 4L
    }

    /** The kinds a phone asks for, as bits. */
    object Kinds {
        const val COPIES = 1L
        const val EVENTS = 2L
    }

    /** A new push key and slot (one per group) and send key (one per token, for every group). */
    class Keys(val key: ByteArray, val sendKey: ByteArray, val slot: ByteArray)

    fun newKeys(): Keys {
        val ok = Core.run("push_key") as? JsonObject ?: throw Core.Mismatch("the answer to push_key is not an object")
        return Keys(need(ok, "key"), need(ok, "send_key"), need(ok, "slot"))
    }

    /** What the core knows of a platform. */
    class Limits(val known: Boolean, val body: Long, val token: Long, val kinds: Long)

    fun limits(env: Long): Limits {
        val ok = Core.run("push_limits", Wire.obj("env" to Wire.num(env))) as? JsonObject
            ?: throw Core.Mismatch("the answer to push_limits is not an object")
        return Limits(ok.optBool("known") ?: false, ok.optLong("body") ?: 0, ok.optLong("token") ?: 0, ok.optLong("kinds") ?: 0)
    }

    /** A UnifiedPush endpoint as the distributor gave it, with the app's RFC 8291 keys. */
    class UnifiedPush(val url: String, val p256dh: ByteArray, val auth: ByteArray) {
        override fun equals(other: Any?): Boolean =
            other is UnifiedPush && other.url == url && other.p256dh.contentEquals(p256dh) && other.auth.contentEquals(auth)

        override fun hashCode(): Int = url.hashCode()
    }

    /**
     * A registration made: the frame of message `push` for the group's
     * members and the number it carries, which the app saves first, and with
     * push on the send key's hint, which the push service puts beside each
     * challenge.
     */
    class Registration(val frame: ByteArray, val seq: Long, val keyHint: ByteArray?)

    /**
     * Makes the registration for one group: its slot, and the last challenge
     * the push service sent to the token, if any. With [kinds] 0 push is off
     * and the rest is not read. Give either [token] or [unifiedPush].
     */
    fun registration(
        savedSeq: Long?,
        nowMs: Long,
        kinds: Long,
        env: Long? = null,
        token: ByteArray? = null,
        unifiedPush: UnifiedPush? = null,
        key: ByteArray? = null,
        sendKey: ByteArray? = null,
        slot: ByteArray? = null,
        challenge: ByteArray? = null,
    ): Registration {
        val on = kinds != 0L
        val up = unifiedPush?.takeIf { on }?.let {
            Wire.obj("url" to Wire.str(it.url), "p256dh" to Wire.bytes(it.p256dh), "auth" to Wire.bytes(it.auth))
        }
        val ok = Core.run(
            "push_registration",
            Wire.obj(
                "saved_seq" to Wire.num(savedSeq),
                "now_ms" to Wire.num(maxOf(0, nowMs)),
                "kinds" to Wire.num(kinds),
                "env" to Wire.num(env?.takeIf { on }),
                "token" to Wire.bytes(token?.takeIf { on }),
                "unifiedpush" to up,
                "key" to Wire.bytes(key?.takeIf { on }),
                "send_key" to Wire.bytes(sendKey?.takeIf { on }),
                "slot" to Wire.bytes(slot?.takeIf { on }),
                "challenge" to Wire.bytes(challenge?.takeIf { on }),
            ),
        ) as? JsonObject ?: throw Core.Mismatch("the answer to push_registration is not an object")
        return Registration(need(ok, "frame"), ok.optLong("seq") ?: throw Core.Mismatch("push_registration: no seq"), ok.optBytes("key_hint"))
    }

    /** A push key with the registration number it was sent with. */
    class KeyAndSeq(val key: ByteArray, val seq: Long)

    /** A device the app last saved, as `push_open` checks an origin. */
    class Origin(val key: ByteArray, val rights: Long, val frozen: Boolean = false)

    /** One of the phone's sealing secrets, of an epoch in the group's window. */
    class Sealing(val epoch: Long, val secret: ByteArray)

    /** What a body said. Only `copy` states a fact; the rest is shown as "open the app". */
    class Opened(
        val kind: String,
        val keyIndex: Int,
        val id: ByteArray?,
        val origin: ByteArray?,
        val type: String?,
        val secret: Boolean?,
        val ttlMs: Long?,
        val text: String?,
        val event: Long?,
        val device: ByteArray?,
        val timeMs: Long?,
    )

    /** The group as the background code sees it when a body arrives. */
    class Context(
        val keys: List<KeyAndSeq>,
        val me: ByteArray,
        val origins: List<Origin> = emptyList(),
        val sealing: List<Sealing> = emptyList(),
        val tooOld: Boolean = false,
        val halted: Boolean = false,
        val hintsOnly: Boolean = false,
        val windowMs: Long? = null,
    )

    /** Opens a body with the group's keys; throws a [Core.Refusal] (code 18) when none opens it. */
    fun open(body: ByteArray, c: Context, nowMs: Long): Opened {
        val ok = Core.run(
            "push_open",
            Wire.obj(
                "keys" to JsonArray(c.keys.map { Wire.obj("key" to Wire.bytes(it.key), "seq" to Wire.num(it.seq)) }),
                "body" to Wire.bytes(body),
                "me" to Wire.bytes(c.me),
                "origins" to JsonArray(c.origins.map {
                    Wire.obj("key" to Wire.bytes(it.key), "rights" to Wire.num(it.rights), "frozen" to JsonPrimitive(it.frozen))
                }),
                "sealing" to JsonArray(c.sealing.map { Wire.obj("epoch" to Wire.num(it.epoch), "secret" to Wire.bytes(it.secret)) }),
                "too_old" to JsonPrimitive(c.tooOld),
                "halted" to JsonPrimitive(c.halted),
                "hints_only" to JsonPrimitive(c.hintsOnly),
                "now_ms" to Wire.num(maxOf(0, nowMs)),
                "window_ms" to Wire.num(c.windowMs),
            ),
        ) as? JsonObject ?: throw Core.Mismatch("the answer to push_open is not an object")
        return Opened(
            kind = ok.optString("kind") ?: throw Core.Mismatch("push_open: no kind"),
            keyIndex = (ok.optLong("key_index") ?: 0).toInt(),
            id = ok.optBytes("id"),
            origin = ok.optBytes("origin"),
            type = ok.optString("type"),
            secret = ok.optBool("secret"),
            ttlMs = ok.optLong("ttl_ms"),
            text = ok.optString("text"),
            event = ok.optLong("event"),
            device = ok.optBytes("device"),
            timeMs = ok.optLong("time_ms"),
        )
    }

    /** What one push carries: the sealed body, the push service's challenge (24 bytes), or both. */
    class Delivery(val body: ByteArray?, val challenge: ByteArray?)

    /** The kinds of a UnifiedPush message's parts (docs/core-api.md, "Push"). */
    const val PART_BODY = 1
    const val PART_CHALLENGE = 2

    /**
     * A decrypted UnifiedPush message: parts, each a kind (1 byte), a length
     * (2 bytes, big endian) and its bytes. Parts are told apart by the kind
     * byte only, never by their length; a kind not known here is skipped. Null
     * when the parts do not add up to the message.
     */
    fun parts(message: ByteArray): Delivery? {
        var body: ByteArray? = null
        var challenge: ByteArray? = null
        var i = 0
        while (i < message.size) {
            if (i + 3 > message.size) return null
            val kind = message[i].toInt() and 0xff
            val len = ((message[i + 1].toInt() and 0xff) shl 8) or (message[i + 2].toInt() and 0xff)
            i += 3
            if (i + len > message.size) return null
            val part = message.copyOfRange(i, i + len)
            i += len
            when (kind) {
                PART_BODY -> body = part
                PART_CHALLENGE -> challenge = part
            }
        }
        return Delivery(body, challenge)
    }

    /** A data message of FCM or Push Kit: the body under "c", the challenge under "k", both base64. */
    fun data(data: Map<String, String>): Delivery {
        fun b64(s: String?) = s?.let { runCatching { java.util.Base64.getDecoder().decode(it) }.getOrNull() }
        return Delivery(b64(data["c"]), b64(data["k"]))
    }

    private fun need(o: JsonObject, key: String): ByteArray = o.optBytes(key) ?: throw Core.Mismatch("push: the answer has no $key")
}
