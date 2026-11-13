// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * The member protocol of docs/protocol.md, sections 4 and 5, as the Rust core
 * speaks it (core/src/wire.rs, core/src/clip.rs, core/src/hlc.rs): frames of a
 * 4-byte big-endian length and a JSON message, a hello first, then events,
 * pings, records and goodbyes.
 */
object Member {
    /** The sync modes (design.md, "Sync modes"). */
    val MODES = setOf("own", "shared", "receive", "send")

    /** Whether a device in sync mode mode takes the group's copies into its clipboard by itself; a device without a mode (null) shares. */
    fun receives(mode: String?): Boolean = mode == null || mode == "shared" || mode == "receive"

    /** Whether a device in sync mode mode sends its own copies to the group by itself. */
    fun sends(mode: String?): Boolean = mode == null || mode == "shared" || mode == "send"

    /** The longest reason a result carries, in UTF-8 bytes (section 15). */
    const val MAX_REASON = 256

    /**
     * A result's reason made fit to show: a control character (escape
     * included) becomes a space, and it is cut to [MAX_REASON] bytes at a
     * character boundary. The member that answers is a peer, so the member
     * that shows the reason cleans it.
     */
    fun cleanReason(s: String): String {
        val out = StringBuilder()
        var bytes = 0
        var i = 0
        while (i < s.length) {
            val cp = s.codePointAt(i)
            i += Character.charCount(cp)
            val c = if (Character.getType(cp) == Character.CONTROL.toInt()) ' '.code else cp
            val size = String(Character.toChars(c)).toByteArray(Charsets.UTF_8).size
            if (bytes + size > MAX_REASON) break
            out.appendCodePoint(c)
            bytes += size
        }
        return out.toString()
    }

    /** The ALPN protocol of member connections. */
    const val ALPN = "cbb/3"

    /** The feature of the hello (section 4, "Hello") that says the sender serves the content of media events. */
    const val FEATURE_MEDIA = "media"

    /** How many names of the hello's features a receiver reads. */
    const val MAX_FEATURES = 32

    /** The most device IDs of a reach message (section 4, "Reach"). */
    const val MAX_REACH = 256

    /** Frames larger than this close the connection. */
    const val MAX_FRAME = 7 shl 20

    /** The most bytes of a part one chunk carries (section 4, "Content"). */
    const val CHUNK_SIZE = 256 shl 10

    /** The most bytes one get asks for. */
    const val GET_WINDOW = 1 shl 20

    /** A chunk's frame is padded to a multiple of this, so the network learns less of the parts' sizes. */
    const val CHUNK_PAD = 16 shl 10

    /** The start of a chunk's frame: the part's SHA-256, the offset and the data's length. */
    const val CHUNK_HEAD = 32 + 8 + 4

    /** The largest chunk frame, padding included; a longer one closes the connection. */
    const val MAX_CHUNK_FRAME = (CHUNK_HEAD + CHUNK_SIZE + CHUNK_PAD - 1) / CHUNK_PAD * CHUNK_PAD

    /** The top bit of a frame's length marks a binary chunk frame. */
    private const val BINARY_FRAME = 1L shl 31

    /** A side that wrote nothing for this long, in milliseconds, sends a ping. */
    const val PING_EVERY_MS = 5_000L

    /** A connection silent for this long, in milliseconds, is dead. */
    const val TIMEOUT_MS = 15_000L

    /** Texts are at most this many bytes of UTF-8. */
    const val MAX_TEXT = 1 shl 20

    /** What kind of member is at the other end: MEMBER is any device with the service or the firmware, PHONE a phone's app. */
    enum class Role(val wire: String) {
        MEMBER("member"), PHONE("phone");

        companion object {
            fun of(s: String): Role? = entries.firstOrNull { it.wire == s }
        }
    }

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
     * A hybrid logical clock timestamp: milliseconds since the Unix epoch
     * and a counter, written as "<wall>.<logical>".
     */
    data class Timestamp(val wall: Long, val logical: Long) : Comparable<Timestamp> {
        override fun compareTo(other: Timestamp): Int =
            if (wall != other.wall) wall.compareTo(other.wall) else logical.compareTo(other.logical)

        override fun toString(): String = "$wall.$logical"

        val isZero: Boolean get() = wall == 0L && logical == 0L

        companion object {
            /** The last millisecond of 9999. */
            const val MAX_WALL = 253_402_300_799_999L
            private const val MAX_LOGICAL = 0xffff_ffffL
            val ZERO = Timestamp(0, 0)

            /**
             * Parses the text form: two decimal numbers and a dot, no sign or
             * spaces, the wall time at most MAX_WALL.
             */
            fun parse(text: String): Timestamp? {
                val parts = text.split(".")
                if (parts.size != 2 || parts.any { p -> p.isEmpty() || !p.all { it in '0'..'9' } }) return null
                val w = parts[0].toBigInteger()
                val l = parts[1].toBigInteger()
                if (w > MAX_WALL.toBigInteger() || l > MAX_LOGICAL.toBigInteger()) return null
                return Timestamp(w.toLong(), l.toLong())
            }
        }
    }

    /** One copy as the engine holds it: its header, and its content once this member opened it. It travels sealed ([Sealed]). */
    data class Event(
        val id: String,
        val origin: String,
        val via: Via = Via.COPY,
        val time: Timestamp,
        /** Milliseconds since the copy, as of the moment the frame is written. */
        val ageMS: Long = 0,
        val kind: Kind,
        /** The text; "" only in the mark of a secret, and in images or files without one. */
        val text: String,
        /** The content of a media event, which only it has. */
        val media: Media.Manifest? = null,
        /** The copy as it travels, sealed end to end (section 4); null for an event of an engine without keys, as in tests of the engine alone. */
        val sealed: Sealed? = null,
        /**
         * Whether this member does not know the event's content: a mark, or a
         * copy not sealed to this member. kind, via, text and media are then
         * empty, and the event is current only for ordering.
         */
        val unread: Boolean = false,
        /** The copy's key, which opens its blob, when this member opened it. */
        val key: ByteArray? = null,
    ) {
        /** Whether it is the mark of a secret: the event without its payload, or, unsealed, without its text. */
        val isMark: Boolean get() = sealed?.isMark ?: (kind == Kind.SECRET && text.isEmpty())

        /** The mark of this event: a secret without its payload and text, as a hello carries it. */
        val mark: Event get() = if (kind == Kind.SECRET && !unread) copy(text = "", key = null, sealed = sealed?.mark) else this

        /** Whether f carries the payload whose hash this mark has. */
        internal fun samePayload(f: Event): Boolean {
            val s = sealed ?: return true
            val t = f.sealed ?: return true
            return t.payload != null && s.payloadHash.contentEqualsOrNull(t.payloadHash)
        }

        override fun equals(other: Any?): Boolean =
            other is Event && id == other.id && origin == other.origin && via == other.via && time == other.time && ageMS == other.ageMS &&
                kind == other.kind && text == other.text && media == other.media && sealed == other.sealed && unread == other.unread &&
                key.contentEqualsOrNull(other.key)

        override fun hashCode(): Int = id.hashCode()

        /** Checks an event received from another member, as Go's Event.Validate does. */
        val isValid: Boolean
            get() {
                if (!GroupCertificates.isDeviceID(id) || !GroupCertificates.isDeviceID(origin) ||
                    time.isZero || time.wall > Timestamp.MAX_WALL || ageMS < 0
                ) {
                    return false
                }
                val s = sealed
                if (s != null && (!s.isValid || s.id != id || s.origin != origin || s.time != time)) return false
                if (unread) return s != null
                if ((kind == Kind.MEDIA) != (media != null)) return false
                if (isMark) return true
                if (media != null) {
                    return media.isValid && (text.isEmpty() || text.toByteArray().size <= Media.MAX_ALT_TEXT)
                }
                return text.isNotEmpty() && text.toByteArray().size <= MAX_TEXT
            }

        /** Whether it sorts after f: by time, then by ID, so every member orders any two events the same way. */
        fun isLater(than: Event): Boolean = if (time != than.time) time > than.time else id > than.id

        /** The event as it travels: the sealed copy with its age as of now, or, unsealed, in the open. */
        fun toJson(): JsonObject = sealed?.with(ageMS = ageMS)?.toJson() ?: Wire.obj(
            "id" to Wire.str(id),
            "origin" to Wire.str(origin),
            "via" to Wire.str(via.wire.takeIf { via != Via.COPY }), // absent means copy
            "time" to Wire.str(time.toString()),
            "age_ms" to Wire.num(ageMS),
            "kind" to Wire.str(kind.wire),
            "text" to Wire.str(text),
            "media" to media?.toJson(),
        )

        companion object {
            /** The engine's event of a copy that arrived sealed, before it is opened: its header, unread. */
            fun of(s: Sealed): Event = Event(s.id, s.origin, Via.COPY, s.time, s.ageMS, Kind.TEXT, "", sealed = s, unread = true)

            /** The event in o, or null when it does not decode; on the wire a copy is sealed. */
            fun fromJson(o: JsonObject): Event? =
                if (o.opt("wraps") != null) Sealed.fromJson(o)?.let { of(it) } else try {
                    Event(
                        id = o.optString("id") ?: return null,
                        origin = o.optString("origin") ?: return null,
                        via = o.optString("via")?.let { Via.of(it) ?: return null } ?: Via.COPY,
                        time = Timestamp.parse(o.optString("time") ?: return null) ?: return null,
                        ageMS = o.optLong("age_ms") ?: 0,
                        kind = Kind.of(o.optString("kind") ?: return null) ?: return null,
                        text = o.optString("text") ?: "",
                        media = o.optObject("media")?.let { Media.Manifest.fromJson(it) },
                    )
                } catch (e: WireTypeException) {
                    null
                }

            fun fromJson(e: JsonElement?): Event? = (e as? JsonObject)?.let { fromJson(it) }
        }
    }

    /** The first message of each side. */
    data class Hello(
        /** The sender's wall clock, milliseconds since the Unix epoch; for skew reports only. */
        val wallMS: Long,
        /** The sender's current event; a secret only as its mark. null when there is none, or when it did not decode. */
        val current: Event? = null,
        /** The digest of the sender's records (section 10). */
        val records: String? = null,
        /** The sender's device name. */
        val name: String? = null,
        /** The sender's operating system: "linux", "windows", "macos", "ios", "android", "aurora", "sailfish", "harmonyos" or "none"; shown, never trusted. */
        val os: String? = null,
        /**
         * From a computer that is no admin yet: the SubjectPublicKeyInfo of
         * its admin key, for the root to certify (section 10, "A computer as admin").
         */
        val adminKey: ByteArray? = null,
        /** The sender's WireGuard public key, 32 bytes, for the group's hub (section 11). */
        val tunnelKey: ByteArray? = null,
        /**
         * With tunnelKey, the preshared key the sender chose for its
         * tunnels, 32 bytes, so every hub of the group uses the same one
         * (section 11, "Several hubs"); null from an older member.
         */
        val tunnelPSK: ByteArray? = null,
        /** What the sender says about its device, for showing. */
        val device: DeviceInfo? = null,
        /** The sender's sync mode: "own", "shared", "receive" or "send"; null from a member without one, which shares. */
        val mode: String? = null,
        /** Where the sender says its keys live: Records.FILE or Records.HARDWARE; null when it does not say. */
        val keyStore: String? = null,
        /** The sender's quick actions that are on, for the buttons (section 15). */
        val actions: List<String> = emptyList(),
        /** Whether the sender serves the content of media events (section 4, "Content"). */
        val media: Boolean = false,
        /**
         * The group's first root, DER, which a computer sends on a
         * records-only connection with a device no record names yet, as a
         * new phone restoring the group with the recovery key (section 10,
         * "The recovery key").
         */
        val groupCA: ByteArray? = null,
        /** The seq of the newest entries.json the sender holds and of the keys.json it came with (section 16, "Entry points"); 0 for none. */
        val entriesSeq: Long = 0,
        val entriesKeysSeq: Long = 0,
        /**
         * Whether an admin muted the sender, whose copies then do not reach
         * the group, and for how long still in milliseconds, 0 for until an
         * admin unmutes it (section 4; design.md, "Muting a device").
         */
        val muted: Boolean = false,
        val mutedForMS: Long = 0,
    ) {
        override fun equals(other: Any?): Boolean =
            other is Hello && wallMS == other.wallMS && current == other.current && records == other.records && keyStore == other.keyStore &&
                actions == other.actions && media == other.media &&
                name == other.name && os == other.os && adminKey.contentEqualsOrNull(other.adminKey) &&
                tunnelKey.contentEqualsOrNull(other.tunnelKey) &&
                tunnelPSK.contentEqualsOrNull(other.tunnelPSK) && device == other.device && mode == other.mode &&
                groupCA.contentEqualsOrNull(other.groupCA) && entriesSeq == other.entriesSeq && entriesKeysSeq == other.entriesKeysSeq &&
                muted == other.muted && mutedForMS == other.mutedForMS

        override fun hashCode(): Int = wallMS.hashCode()
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

    /**
     * The group's hub's answer to the tunnel key a hello carried (section
     * 11): the hub's WireGuard public key, this member's own preshared key,
     * the hub's addresses away from home, "ip:port" or "[ipv6]:port", the
     * group's obfuscation settings as JSON text, null for plain WireGuard,
     * and the way to the hub's forwarder over VLESS as JSON text, null
     * without it. The kit keeps both as they came and the tunnel reads them.
     */
    class TunnelOffer(
        val hubKey: ByteArray,
        val psk: ByteArray,
        val endpoints: List<String> = emptyList(),
        val obfuscation: String? = null,
        val vless: String? = null,
        /**
         * In an offer the hub passes on when it hands the hub over, the
         * device that is the hub now (section 11, "Moving the hub"); null
         * when the sender is the hub.
         */
        val hub: String? = null,
        /**
         * Whether the sender is no hub any more and hands its clients over
         * to hub: the client forgets the sender's own offer.
         */
        val moved: Boolean = false,
        /**
         * The key the hub serves with in the next period of the group's
         * server credentials, which the client tries after hubKey (section
         * 11, "The hub's key"); null for none.
         */
        val nextKey: ByteArray? = null,
    ) {
        /**
         * Whether it is an offer a tunnel can take, as Go checks one: keys of 32
         * bytes that are not all zeros, at most 8 endpoints, each with a port
         * that is not 0.
         */
        val isValid: Boolean get() =
            hubKey.size == 32 && psk.size == 32 && endpoints.size <= 8 && (nextKey == null || nextKey.size == 32) &&
                hubKey.any { it != 0.toByte() } && psk.any { it != 0.toByte() } && endpoints.all(::hasPort)

        /** The same offer with another preshared key and hub, and moved set. */
        fun with(psk: ByteArray, hub: String?, moved: Boolean = false): TunnelOffer =
            TunnelOffer(hubKey, psk, endpoints, obfuscation, vless, hub, moved, nextKey)

        /** The offer with the next key as the hub's key, or null without one. */
        fun withNextKey(): TunnelOffer? = nextKey?.let { TunnelOffer(it, psk, endpoints, obfuscation, vless, hub, moved) }

        override fun equals(other: Any?): Boolean =
            other is TunnelOffer && hubKey.contentEquals(other.hubKey) && psk.contentEquals(other.psk) && endpoints == other.endpoints &&
                obfuscation == other.obfuscation && vless == other.vless && hub == other.hub && moved == other.moved &&
                (nextKey ?: ByteArray(0)).contentEquals(other.nextKey ?: ByteArray(0))

        override fun hashCode(): Int = hubKey.contentHashCode()

        fun toJson(): JsonObject = Wire.obj(
            "hub_key" to Wire.bytes(hubKey),
            "psk" to Wire.bytes(psk),
            "endpoints" to endpoints.takeIf { it.isNotEmpty() }?.let { l -> JsonArray(l.map { Wire.str(it)!! }) },
            "obfuscation" to obfuscation?.let { Json.parseToJsonElement(it) },
            "vless" to vless?.let { Json.parseToJsonElement(it) },
            "hub" to Wire.str(hub),
            "moved" to if (moved) JsonPrimitive(true) else null,
            "next_key" to nextKey?.let { Wire.bytes(it) },
        )

        companion object {
            fun fromJson(o: JsonObject): TunnelOffer = TunnelOffer(
                o.optBytes("hub_key") ?: ByteArray(0),
                o.optBytes("psk") ?: ByteArray(0),
                o.optArray("endpoints")?.map {
                    (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content ?: throw WireTypeException("endpoints: not a string")
                } ?: emptyList(),
                o.optObject("obfuscation")?.toString(),
                o.optObject("vless")?.toString(),
                o.optString("hub"),
                o.optBool("moved") ?: false,
                o.optBytes("next_key")?.takeIf { it.isNotEmpty() },
            )
        }
    }

    /**
     * What a hub tells the group's other hubs (section 11, "Several hubs"):
     * whether it serves as the hub now, its offer without a preshared key,
     * and its clients, itself among them, with their keys.
     */
    class HubShare(val serving: Boolean = false, val offer: TunnelOffer? = null, val clients: List<PhoneHub.Client> = emptyList()) {
        override fun equals(other: Any?): Boolean =
            other is HubShare && serving == other.serving && offer == other.offer &&
                clients.map { Triple(it.device, it.key.toList(), it.psk.toList()) } ==
                other.clients.map { Triple(it.device, it.key.toList(), it.psk.toList()) }

        override fun hashCode(): Int = clients.size

        fun toJson(): JsonObject = Wire.obj(
            "serving" to if (serving) JsonPrimitive(true) else null,
            "offer" to offer?.toJson(),
            "clients" to clients.takeIf { it.isNotEmpty() }?.let { l -> JsonArray(l.map { it.toJson() }) },
        )

        companion object {
            fun fromJson(o: JsonObject): HubShare = HubShare(
                o.optBool("serving") ?: false,
                o.optObject("offer")?.let { TunnelOffer.fromJson(it) },
                o.optArray("clients")?.map { PhoneHub.Client.fromJson(it as? JsonObject ?: throw WireTypeException("clients: not an object")) }
                    ?: emptyList(),
            )
        }
    }

    /** A signed record of the group (section 10), carried as it came. */
    class Record(val body: ByteArray, val sig: ByteArray, val chain: List<ByteArray>? = null) {
        override fun equals(other: Any?): Boolean =
            other is Record && body.contentEquals(other.body) && sig.contentEquals(other.sig) &&
                (chain?.map { it.toList() }) == (other.chain?.map { it.toList() })

        override fun hashCode(): Int = body.contentHashCode()

        companion object {
            /**
             * The records of one message at most, well below the frame limit: a
             * set is sent in messages of about 1 MiB (section 10, "Exchange in the
             * member protocol"), as Go's chunkRecords does.
             */
            const val CHUNK = 1 shl 20

            /** rs in the messages that carry them, in order, each of about CHUNK bytes at most unless one record alone is larger. */
            fun chunks(rs: List<Record>): List<List<Record>> {
                val out = mutableListOf<List<Record>>()
                var cur = mutableListOf<Record>()
                var size = 0
                for (r in rs) {
                    // base64 and the JSON around it
                    val n = (r.body.size + r.sig.size + (r.chain?.sumOf { it.size } ?: 0)) * 4 / 3 + 64
                    if (cur.isNotEmpty() && size + n > CHUNK) {
                        out += cur
                        cur = mutableListOf()
                        size = 0
                    }
                    cur += r
                    size += n
                }
                if (cur.isNotEmpty()) out += cur
                return out
            }

            fun fromJson(o: JsonObject): Record =
                Record(o.optBytes("body") ?: ByteArray(0), o.optBytes("sig") ?: ByteArray(0), o.optBytesList("chain"))
        }

        fun toJson(): JsonObject = Wire.obj("body" to Wire.bytes(body), "sig" to Wire.bytes(sig), "chain" to Wire.list(chain))
    }

    /** The answer to a command (section 15): its ID, "done", "refused" or "failed", and why for the last two. */
    data class CommandResult(
        val id: String,
        val status: String,
        val reason: String? = null,
        /** In the result of a hub command, the new hub's offer without a preshared key (section 11, "Moving the hub"). */
        val tunnel: TunnelOffer? = null,
        /** The device that answered, the command's receiver; a member that passes the result back leaves it. */
        val by: String? = null,
    ) {
        val done: Boolean get() = status == "done"

        fun toJson(): JsonObject =
            Wire.obj("id" to Wire.str(id), "by" to Wire.str(by), "status" to Wire.str(status), "reason" to Wire.str(reason), "tunnel" to tunnel?.toJson())

        companion object {
            fun fromJson(o: JsonObject): CommandResult = CommandResult(
                o.optString("id") ?: "",
                o.optString("status") ?: "",
                o.optString("reason"),
                o.optObject("tunnel")?.let { runCatching { TunnelOffer.fromJson(it) }.getOrNull() },
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

    /** A range of a part of images or files, by its SHA-256 (section 4, "Content"); length 0 cancels the sender's gets of the part. */
    class Get(val sha256: ByteArray, val offset: Long, val length: Long) {
        /** Whether a server takes it: a 32-byte hash and a range of at most GET_WINDOW. */
        val isValid: Boolean get() = sha256.size == 32 && offset >= 0 && length in 0..GET_WINDOW.toLong()

        override fun equals(other: Any?): Boolean =
            other is Get && sha256.contentEquals(other.sha256) && offset == other.offset && length == other.length

        override fun hashCode(): Int = sha256.contentHashCode()

        fun toJson(): JsonObject = Wire.obj("sha256" to Wire.bytes(sha256), "offset" to Wire.num(offset), "length" to Wire.num(length))

        companion object {
            fun fromJson(o: JsonObject): Get = Get(o.optBytes("sha256") ?: ByteArray(0), o.optLong("offset") ?: 0, o.optLong("length") ?: 0)
        }
    }

    /** One message of the protocol. */
    sealed class Message {
        data class Hello(val role: Role, val hello: Member.Hello) : Message()

        /** An event; null when it did not decode, for example from a newer version, which is dropped without ending the connection. */
        data class Event(val event: Member.Event?) : Message()

        object Ping : Message()

        object Bye : Message()

        /** A renewed member certificate for the receiver, DER, and the admin CA that issued it when an admin did. */
        class Cert(val cert: ByteArray, val issuer: ByteArray? = null) : Message() {
            override fun equals(other: Any?): Boolean =
                other is Cert && cert.contentEquals(other.cert) && issuer.contentEqualsOrNull(other.issuer)

            override fun hashCode(): Int = cert.contentHashCode()
        }

        data class Records(val records: List<Record>) : Message()

        /** The group's server credentials the sender keeps, or new ones it passes on (section 18). */
        data class Credentials(val credentials: List<ServerCredentials.Credential>) : Message()

        /** The newest signed entry points the sender holds (section 16, "Entry points"). */
        class Entries(val set: Releases.EntriesSet) : Message()

        /** From the root: the receiver's admin CA, DER, for the admin key its hello offered. */
        class Admin(val adminCA: ByteArray) : Message() {
            override fun equals(other: Any?): Boolean = other is Admin && adminCA.contentEquals(other.adminCA)

            override fun hashCode(): Int = adminCA.contentHashCode()
        }

        /** From the group's hub: its offer for the tunnel key the receiver's hello carried; null when absent. */
        data class Tunnel(val offer: TunnelOffer?) : Message()

        /**
         * Between the group's hubs (section 11, "Several hubs"): whether the
         * sender serves as the hub, its offer without a preshared key, and
         * its clients with their keys, so any hub can take them.
         */
        data class Hubs(val share: HubShare) : Message()

        /** From an admin: a command signed for the receiver (section 15). */
        data class Command(val command: Record) : Message()

        /** The answer to a command. */
        data class Result(val result: CommandResult) : Message()

        /** An attestation of one of the sender's keys (section 17, "Evidence"). */
        data class Evidence(val evidence: Member.Evidence) : Message()

        /** Asks for a range of a part the receiver serves. */
        data class Get(val get: Member.Get) : Message()

        /** Answers a get for a part the sender does not hold whole, and ends that fetch. */
        data class Missing(val get: Member.Get) : Message()

        /** A piece of a part, in a binary frame. */
        class Chunk(val sha256: ByteArray, val offset: Long, val data: ByteArray) : Message() {
            override fun equals(other: Any?): Boolean =
                other is Chunk && sha256.contentEquals(other.sha256) && offset == other.offset && data.contentEquals(other.data)

            override fun hashCode(): Int = sha256.contentHashCode()
        }

        /**
         * From a computer: the device IDs of the other members it is connected
         * to now (section 4, "Reach"), its valid ones, at most MAX_REACH.
         */
        data class Reach(val ids: List<String>) : Message()

        /** A type from a newer version, ignored. */
        data class Unknown(val type: String) : Message()
    }

    class WireException(message: String) : Exception(message)

    /** The JSON of a message. */
    fun toJson(m: Message): JsonObject = when (m) {
        is Message.Hello -> Wire.obj(
            "t" to Wire.str("hello"),
            "role" to Wire.str(m.role.wire),
            "hello" to Wire.obj(
                "wall_ms" to Wire.num(m.hello.wallMS),
                "current" to m.hello.current?.toJson(),
                "records" to Wire.str(m.hello.records),
                "name" to Wire.str(m.hello.name),
                "os" to Wire.str(m.hello.os),
                "device" to m.hello.device?.toJson(),
                "admin_key" to Wire.bytes(m.hello.adminKey),
                "tunnel_key" to Wire.bytes(m.hello.tunnelKey),
                "tunnel_psk" to Wire.bytes(m.hello.tunnelPSK),
                "mode" to Wire.str(m.hello.mode),
                "key_store" to Wire.str(m.hello.keyStore),
                "features" to if (m.hello.media) JsonArray(listOf(JsonPrimitive(FEATURE_MEDIA))) else null,
                "group_ca" to Wire.bytes(m.hello.groupCA),
                "entries_seq" to if (m.hello.entriesSeq > 0) Wire.num(m.hello.entriesSeq) else null,
                "entries_keys_seq" to if (m.hello.entriesSeq > 0) Wire.num(m.hello.entriesKeysSeq) else null,
                "muted" to if (m.hello.muted) JsonPrimitive(true) else null,
                "muted_for_ms" to if (m.hello.muted) Wire.num(m.hello.mutedForMS) else null,
            ),
        )
        is Message.Event -> Wire.obj("t" to Wire.str("event"), "event" to m.event?.toJson())
        Message.Ping -> Wire.obj("t" to Wire.str("ping"))
        Message.Bye -> Wire.obj("t" to Wire.str("bye"))
        is Message.Cert -> Wire.obj("t" to Wire.str("cert"), "cert" to Wire.bytes(m.cert), "issuer" to Wire.bytes(m.issuer))
        is Message.Records -> Wire.obj("t" to Wire.str("records"), "records" to JsonArray(m.records.map { it.toJson() }))
        is Message.Credentials -> Wire.obj("t" to Wire.str("credentials"), "credentials" to JsonArray(m.credentials.map { it.toJson() }))
        is Message.Entries -> Wire.obj("t" to Wire.str("entries"), "entries" to m.set.toJson())
        is Message.Admin -> Wire.obj("t" to Wire.str("admin"), "admin_ca" to Wire.bytes(m.adminCA))
        is Message.Tunnel -> Wire.obj("t" to Wire.str("tunnel"), "tunnel" to m.offer?.toJson())
        is Message.Hubs -> Wire.obj("t" to Wire.str("hubs"), "hubs" to m.share.toJson())
        is Message.Command -> Wire.obj("t" to Wire.str("command"), "command" to m.command.toJson())
        is Message.Result -> Wire.obj("t" to Wire.str("result"), "result" to m.result.toJson())
        is Message.Evidence -> Wire.obj("t" to Wire.str("evidence"), "evidence" to m.evidence.toJson())
        is Message.Get -> Wire.obj("t" to Wire.str("get"), "get" to m.get.toJson())
        is Message.Missing -> Wire.obj("t" to Wire.str("missing"), "get" to m.get.toJson())
        is Message.Reach -> Wire.obj("t" to Wire.str("reach"), "reach" to m.ids.takeIf { it.isNotEmpty() }?.let { ids -> JsonArray(ids.map { JsonPrimitive(it) }) })
        is Message.Chunk -> throw WireException("a chunk is a binary frame")
        is Message.Unknown -> Wire.obj("t" to Wire.str(m.type))
    }

    /** Encodes a message as a frame: the length, then the JSON, or for a chunk its binary frame. */
    fun encode(m: Message): ByteArray {
        if (m is Message.Chunk) return encodeChunk(m)
        val body = Wire.encode(toJson(m))
        if (body.size > MAX_FRAME) throw WireException("frame too large")
        return frame(body)
    }

    internal fun frame(body: ByteArray): ByteArray {
        val n = body.size
        return byteArrayOf((n ushr 24).toByte(), (n ushr 16).toByte(), (n ushr 8).toByte(), n.toByte()) + body
    }

    /** The length a frame header announces, or an error when too large. */
    fun length(header: ByteArray, max: Int = MAX_FRAME): Int {
        if (header.size != 4) throw WireException("short frame header")
        val n = header.fold(0L) { acc, b -> (acc shl 8) or (b.toLong() and 0xff) }
        if (n > max) throw WireException("frame too large")
        return n.toInt()
    }

    /**
     * The length a member frame's header announces and whether it is a
     * binary chunk frame, or an error when too large for its kind.
     */
    fun header(header: ByteArray): Pair<Int, Boolean> {
        if (header.size != 4) throw WireException("short frame header")
        val n = header.fold(0L) { acc, b -> (acc shl 8) or (b.toLong() and 0xff) }
        if (n and BINARY_FRAME != 0L) {
            val l = n and (BINARY_FRAME - 1)
            if (l > MAX_CHUNK_FRAME) throw WireException("chunk frame too large")
            return l.toInt() to true
        }
        if (n > MAX_FRAME) throw WireException("frame too large")
        return n.toInt() to false
    }

    /**
     * The frame of a chunk: the binary length, the part's SHA-256, the
     * offset and the data's length, the data, and zeros up to a multiple of
     * CHUNK_PAD.
     */
    fun encodeChunk(c: Message.Chunk): ByteArray {
        if (c.sha256.size != 32 || c.data.size > CHUNK_SIZE || c.offset < 0) throw WireException("not a valid chunk")
        val padded = (CHUNK_HEAD + c.data.size + CHUNK_PAD - 1) / CHUNK_PAD * CHUNK_PAD
        val b = java.nio.ByteBuffer.allocate(4 + padded) // big-endian, zeroed
        b.putInt((padded.toLong() or BINARY_FRAME).toInt())
        b.put(c.sha256)
        b.putLong(c.offset)
        b.putInt(c.data.size)
        b.put(c.data)
        return b.array()
    }

    /** Reads the body of a chunk frame. */
    fun decodeChunk(body: ByteArray): Message.Chunk {
        if (body.size < CHUNK_HEAD) throw WireException("a chunk is too short")
        val b = java.nio.ByteBuffer.wrap(body)
        val sum = ByteArray(32).also { b.get(it) }
        val offset = b.getLong()
        val n = b.getInt()
        if (offset < 0 || n < 0 || n > CHUNK_SIZE || CHUNK_HEAD + n > body.size) throw WireException("a chunk's length is not valid")
        return Message.Chunk(sum, offset, body.copyOfRange(CHUNK_HEAD, CHUNK_HEAD + n))
    }

    /**
     * Decodes the body of a frame. A hello whose role is unknown or whose
     * hello object does not decode is an error; an event that does not
     * decode is an Event(null).
     */
    fun decode(body: ByteArray): Message {
        if (!Strict.integersOnly(body)) throw WireException("not a message")
        val o = Wire.parse(body) ?: throw WireException("not a message")
        try {
            return when (val t = o.optString("t") ?: throw WireException("not a message")) {
                "hello" -> {
                    val role = o.optString("role")?.let { Role.of(it) } ?: throw WireException("bad hello: unknown role")
                    val h = o.optObject("hello") ?: throw WireException("bad hello: no hello object")
                    Message.Hello(
                        role,
                        Hello(
                            wallMS = h.optLong("wall_ms") ?: 0,
                            current = Event.fromJson(h.opt("current")),
                            records = h.optString("records"),
                            name = h.optString("name"),
                            os = h.optString("os"),
                            adminKey = h.optBytes("admin_key"),
                            tunnelKey = h.optBytes("tunnel_key"),
                            tunnelPSK = h.optBytes("tunnel_psk"),
                            device = DeviceInfo.fromJson(h.opt("device")),
                            mode = h.optString("mode")?.takeIf { it in MODES },
                            keyStore = h.optString("key_store")?.takeIf { it == Records.FILE || it == Records.HARDWARE || it == Records.ROOTLESS },
                            actions = (h.opt("actions") as? JsonArray).orEmpty()
                                .mapNotNull { (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content }
                                .filter { Commands.validActionName(it) }
                                .take(Commands.MAX_HELLO_ACTIONS),
                            media = (h.opt("features") as? JsonArray).orEmpty().take(MAX_FEATURES)
                                .any { (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content == FEATURE_MEDIA },
                            groupCA = h.optBytes("group_ca"),
                            entriesSeq = h.optLong("entries_seq") ?: 0,
                            entriesKeysSeq = h.optLong("entries_keys_seq") ?: 0,
                            muted = h.optBool("muted") ?: false,
                            // A time out of range counts as 30 days, as Go reads it.
                            mutedForMS = if (h.optBool("muted") == true) (h.optLong("muted_for_ms") ?: 0).coerceIn(0, Commands.MAX_MUTE_MS) else 0,
                        ),
                    )
                }
                "event" -> Message.Event(Event.fromJson(o.opt("event")))
                "ping" -> Message.Ping
                "bye" -> Message.Bye
                "cert" -> Message.Cert(o.optBytes("cert") ?: ByteArray(0), o.optBytes("issuer"))
                "records" -> Message.Records(
                    o.optArray("records")?.map { Record.fromJson(it as? JsonObject ?: throw WireTypeException("records")) } ?: emptyList(),
                )
                "credentials" -> Message.Credentials(
                    o.optArray("credentials")?.map {
                        ServerCredentials.Credential.fromJson(it as? JsonObject ?: throw WireTypeException("credentials"))
                    } ?: emptyList(),
                )
                "entries" -> o.optObject("entries")?.let(Releases.EntriesSet::fromJson)?.let { Message.Entries(it) } ?: Message.Unknown(t)
                "admin" -> Message.Admin(o.optBytes("admin_ca") ?: ByteArray(0))
                "tunnel" -> Message.Tunnel(o.optObject("tunnel")?.let { TunnelOffer.fromJson(it) })
                "hubs" -> o.optObject("hubs")?.let { Message.Hubs(HubShare.fromJson(it)) } ?: Message.Unknown(t)
                "command" -> o.optObject("command")?.let { Message.Command(Record.fromJson(it)) } ?: Message.Unknown(t)
                "result" -> o.optObject("result")?.let { Message.Result(CommandResult.fromJson(it)) } ?: Message.Unknown(t)
                "evidence" -> o.optObject("evidence")?.let { Message.Evidence(Evidence.fromJson(it)) } ?: Message.Unknown(t)
                "get" -> o.optObject("get")?.let { Message.Get(Get.fromJson(it)) } ?: Message.Unknown(t)
                "missing" -> o.optObject("get")?.let { Message.Missing(Get.fromJson(it)) } ?: Message.Unknown(t)
                "reach" -> Message.Reach(
                    (o.opt("reach") as? JsonArray).orEmpty()
                        .mapNotNull { (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content }
                        .filter { GroupCertificates.isDeviceID(it) }
                        .take(MAX_REACH),
                )
                else -> Message.Unknown(t)
            }
        } catch (e: WireTypeException) {
            throw WireException("not a message: ${e.message}")
        }
    }
}

internal fun ByteArray?.contentEqualsOrNull(other: ByteArray?): Boolean =
    if (this == null) other == null else other != null && contentEquals(other)

/** Whether endpoint ends in a port from 1 to 65535, as in "192.0.2.1:8764" or "[2001:db8::1]:8764". */
internal fun hasPort(endpoint: String): Boolean {
    val colon = endpoint.lastIndexOf(':')
    if (colon <= 0) return false
    val digits = endpoint.substring(colon + 1)
    if (digits.isEmpty() || digits.length > 5 || !digits.all { it in '0'..'9' }) return false
    return digits.toInt() in 1..65535
}
