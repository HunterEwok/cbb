// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * What the app keeps for push (docs/core-api.md, "Push"), the Android twin
 * of the Swift kit's `PushVault`, over a [Store] the app gives: on Android a
 * file sealed with a Keystore key of its own, apart from the member key.
 *
 * It holds what opens a body and a copy in it, and nothing that signs a
 * record: the push keys, the send key (which signs only registrations to
 * the push service), and the phone's sealing secrets of the epochs still in
 * the group's window, with the origins and the window. Never the member
 * key, an admin's or the root's key, or the recovery secret.
 *
 * One sender per token, for every group: the token (or UnifiedPush
 * endpoint), its platform, the send key drawn for it, the key's hint and the
 * last challenge the push service sent to it. Per group: the push keys (the
 * current one first; the previous one kept for late bodies, but not after a
 * membership change), the slot, the last registration and what `push_open`
 * needs.
 */
class PushVault(private val store: Store) {
    /** Named blobs the app keeps sealed on the device; null removes one. */
    interface Store {
        fun get(name: String): ByteArray?
        fun put(name: String, value: ByteArray?)
        fun names(): List<String>
    }

    class Incomplete : Exception("push needs a token and its platform")

    /** The token's sender, shared by every group. */
    class Sender(
        var token: ByteArray? = null,
        var unifiedPush: Push.UnifiedPush? = null,
        var env: Long? = null,
        var sendKey: ByteArray? = null,
        var keyHint: ByteArray? = null,
        var challenge: ByteArray? = null,
    ) {
        internal fun json(): JsonObject = Wire.obj(
            "token" to Wire.bytes(token),
            "unifiedpush" to unifiedPush?.let { Wire.obj("url" to Wire.str(it.url), "p256dh" to Wire.bytes(it.p256dh), "auth" to Wire.bytes(it.auth)) },
            "env" to Wire.num(env),
            "send_key" to Wire.bytes(sendKey),
            "key_hint" to Wire.bytes(keyHint),
            "challenge" to Wire.bytes(challenge),
        )

        internal companion object {
            fun of(o: JsonObject) = Sender(
                token = o.optBytes("token"),
                unifiedPush = o.optObject("unifiedpush")?.let {
                    Push.UnifiedPush(it.optString("url") ?: "", it.optBytes("p256dh") ?: ByteArray(0), it.optBytes("auth") ?: ByteArray(0))
                },
                env = o.optLong("env"),
                sendKey = o.optBytes("send_key"),
                keyHint = o.optBytes("key_hint"),
                challenge = o.optBytes("challenge"),
            )
        }
    }

    /** What a registration was made of. */
    data class Registered(
        val token: String?,
        val env: Long?,
        val kinds: Long,
        val key: String?,
        val sendKey: String?,
        val challenge: String?,
    )

    /** The group's devices (their IDs) and its root, as the app applied them. */
    class Devices(val members: List<ByteArray>, val root: ByteArray?)

    /** One group's push state. */
    class Group(
        var keys: List<Push.KeyAndSeq> = emptyList(),
        var slot: ByteArray? = null,
        var kinds: Long = 0,
        var seq: Long? = null,
        var frame: ByteArray? = null,
        var registered: Registered? = null,
        /** When the current push key was drawn (the phone's clock). */
        var keyDrawnMs: Long? = null,
        /** This phone's device ID in the group. */
        var me: ByteArray? = null,
        /** The group's devices and its root as the app last applied them. */
        var members: List<ByteArray>? = null,
        var root: ByteArray? = null,
        var origins: List<Push.Origin> = emptyList(),
        var sealing: List<Push.Sealing> = emptyList(),
        var tooOld: Boolean = false,
        var halted: Boolean = false,
        var windowMs: Long? = null,
    ) {
        /** What `push_open` is given, or null when push is off here. */
        fun context(hintsOnly: Boolean): Push.Context? {
            val me = me ?: return null
            if (keys.isEmpty()) return null
            return Push.Context(keys, me, origins, sealing, tooOld, halted, hintsOnly, windowMs)
        }

        internal fun json(): JsonObject = Wire.obj(
            "keys" to JsonArray(keys.map { Wire.obj("key" to Wire.bytes(it.key), "seq" to Wire.num(it.seq)) }),
            "slot" to Wire.bytes(slot),
            "kinds" to Wire.num(kinds),
            "seq" to Wire.num(seq),
            "frame" to Wire.bytes(frame),
            "registered" to registered?.let {
                Wire.obj(
                    "token" to Wire.str(it.token), "env" to Wire.num(it.env), "kinds" to Wire.num(it.kinds),
                    "key" to Wire.str(it.key), "send_key" to Wire.str(it.sendKey), "challenge" to Wire.str(it.challenge),
                )
            },
            "key_drawn_ms" to Wire.num(keyDrawnMs),
            "me" to Wire.bytes(me),
            "members" to members?.let { Wire.list(it) },
            "root" to Wire.bytes(root),
            "origins" to JsonArray(origins.map {
                Wire.obj("key" to Wire.bytes(it.key), "rights" to Wire.num(it.rights), "frozen" to JsonPrimitive(it.frozen))
            }),
            "sealing" to JsonArray(sealing.map { Wire.obj("epoch" to Wire.num(it.epoch), "secret" to Wire.bytes(it.secret)) }),
            "too_old" to JsonPrimitive(tooOld),
            "halted" to JsonPrimitive(halted),
            "window_ms" to Wire.num(windowMs),
        )

        internal companion object {
            fun of(o: JsonObject) = Group(
                keys = o.optArray("keys")?.map { val k = it as JsonObject; Push.KeyAndSeq(k.optBytes("key")!!, k.optLong("seq")!!) } ?: emptyList(),
                slot = o.optBytes("slot"),
                kinds = o.optLong("kinds") ?: 0,
                seq = o.optLong("seq"),
                frame = o.optBytes("frame"),
                registered = o.optObject("registered")?.let {
                    Registered(it.optString("token"), it.optLong("env"), it.optLong("kinds") ?: 0, it.optString("key"), it.optString("send_key"), it.optString("challenge"))
                },
                keyDrawnMs = o.optLong("key_drawn_ms"),
                me = o.optBytes("me"),
                members = o.optBytesList("members"),
                root = o.optBytes("root"),
                origins = o.optArray("origins")?.map {
                    val x = it as JsonObject
                    Push.Origin(x.optBytes("key")!!, x.optLong("rights") ?: 0, x.optBool("frozen") ?: false)
                } ?: emptyList(),
                sealing = o.optArray("sealing")?.map { val x = it as JsonObject; Push.Sealing(x.optLong("epoch")!!, x.optBytes("secret")!!) } ?: emptyList(),
                tooOld = o.optBool("too_old") ?: false,
                halted = o.optBool("halted") ?: false,
                windowMs = o.optLong("window_ms"),
            )
        }
    }

    /** Why a group registers again. */
    enum class Reason {
        /** The phone applied a removal or a new root: a new push key, and the previous one is not kept. */
        MEMBERSHIP,

        /** A member asked for it (`push-renew`): the push service lost the registration. */
        RENEW,
    }

    private val lock = Any()

    private fun read(name: String): JsonObject? =
        store.get(name)?.let { Json.parseToJsonElement(it.decodeToString()) as? JsonObject }

    private fun write(name: String, o: JsonElement?) = store.put(name, o?.let { Wire.encode(it) })

    fun load(group: String): Group = read(GROUP + group)?.let { Group.of(it) } ?: Group()

    fun save(group: String, g: Group?) = write(GROUP + group, g?.json())

    fun sender(): Sender = read(SENDER)?.let { Sender.of(it) } ?: Sender()

    fun save(sender: Sender?) = write(SENDER, sender?.json())

    /** Every group with push state. */
    fun groups(): List<String> = store.names().filter { it.startsWith(GROUP) }.map { it.removePrefix(GROUP) }.sorted()

    /** Every item the vault wrote, as stored. */
    fun items(): List<ByteArray> = store.names().filter { it == SENDER || it.startsWith(GROUP) }.mapNotNull { store.get(it) }

    /** Removes the group and, with no group left, the sender. */
    fun forget(group: String) = synchronized(lock) {
        save(group, null)
        if (groups().isEmpty()) save(null as Sender?)
    }

    /**
     * What opens a copy in a body, which the app writes on every rotation of
     * its sealing key and whenever the group's devices change: the sealing
     * secrets of the epochs still in the window (any other is erased here),
     * the devices as origins, the window, and whether the group is halted or
     * the records too old.
     */
    fun opening(group: String, sealing: List<Push.Sealing>, origins: List<Push.Origin>, windowMs: Long?, halted: Boolean, tooOld: Boolean = false) =
        synchronized(lock) {
            val g = load(group)
            g.sealing = sealing
            g.origins = origins
            g.windowMs = windowMs
            g.halted = halted
            g.tooOld = tooOld
            save(group, g)
        }

    /**
     * Keeps a challenge the push service sent (24 bytes: the value, then the
     * hint of the send key it is for) when it is for this phone's send key,
     * and says whether it kept it. Any other is dropped: a challenge of
     * another key or token confirms nothing.
     */
    fun keep(challenge: ByteArray): Boolean = synchronized(lock) {
        if (challenge.size != 24) return false
        val s = sender()
        val hint = s.keyHint ?: return false
        if (s.sendKey == null || !hint.contentEquals(challenge.copyOfRange(16, 24))) return false
        val value = challenge.copyOfRange(0, 16)
        if (s.challenge?.contentEquals(value) == true) return false
        s.challenge = value
        save(s)
        true
    }

    /**
     * The group's registration for [token] (or [unifiedPush]) of [env] with
     * [kinds] (0: push off), made again only when something in it changed or
     * for [reasons]; null when the saved one still says it all. A new token
     * gets a new send key, which drops the challenge of the old one. A device
     * gone or a new root in [devices] is a membership change. The seq is
     * saved with the frame, so the next one is higher.
     */
    fun register(
        group: String,
        me: ByteArray,
        token: ByteArray?,
        unifiedPush: Push.UnifiedPush? = null,
        env: Long?,
        kinds: Long,
        reasons: Set<Reason> = emptySet(),
        devices: Devices? = null,
        nowMs: Long = System.currentTimeMillis(),
    ): Push.Registration? = synchronized(lock) {
        val g = load(group)
        val s = sender()
        g.me = me
        val why = reasons.toMutableSet()
        if (devices != null) {
            val old = g.members
            if (old != null && old.any { o -> devices.members.none { it.contentEquals(o) } }) why += Reason.MEMBERSHIP
            val oldRoot = g.root
            if (oldRoot != null && devices.root != null && !oldRoot.contentEquals(devices.root)) why += Reason.MEMBERSHIP
            g.members = devices.members
            g.root = devices.root ?: g.root
        }
        if (Reason.MEMBERSHIP in why && (kinds == 0L || g.kinds == 0L)) {
            // Push is off: no key is kept for bodies from before the change.
            g.keys = emptyList()
            g.keyDrawnMs = nowMs
        }
        if (kinds == 0L) {
            val off = Registered(null, null, 0, null, null, null)
            if (g.registered == off || (g.registered == null && g.kinds == 0L)) {
                save(group, g)
                return null
            }
            val r = Push.registration(g.seq, nowMs, 0)
            g.kinds = 0
            g.seq = r.seq
            g.frame = r.frame
            g.registered = off
            save(group, g)
            return r
        }
        if ((token == null && unifiedPush == null) || env == null) throw Incomplete()
        val sameToken = (s.token?.contentEquals(token ?: ByteArray(0)) ?: (token == null)) && s.unifiedPush == unifiedPush
        if (s.sendKey == null || !sameToken || s.env != env) {
            s.sendKey = Push.newKeys().sendKey
            s.token = token
            s.unifiedPush = unifiedPush
            s.env = env
            s.keyHint = null
            s.challenge = null
        }
        if (g.slot == null) g.slot = Push.newKeys().slot
        val drew = g.keys.isEmpty() || g.kinds == 0L || Reason.MEMBERSHIP in why
        val key = if (drew) Push.newKeys().key else g.keys[0].key
        val wanted = Registered(
            token?.let(::hex) ?: unifiedPush?.let { it.url + "|" + hex(it.p256dh) + "|" + hex(it.auth) },
            env, kinds, hex(key), s.sendKey?.let(::hex), s.challenge?.let(::hex),
        )
        if (!drew && Reason.RENEW !in why && g.registered == wanted) {
            save(group, g)
            return null
        }
        val r = Push.registration(g.seq, nowMs, kinds, env, token, unifiedPush, key, s.sendKey, g.slot, s.challenge)
        // The body's seq is in its associated data: the key under the previous
        // seq stays for bodies already on their way, one entry; after a
        // membership change none, so a removed member's bodies open nothing.
        val previous = if (Reason.MEMBERSHIP in why || g.kinds == 0L) null else g.keys.firstOrNull()
        g.keys = listOf(Push.KeyAndSeq(key, r.seq)) + listOfNotNull(previous)
        if (drew) g.keyDrawnMs = nowMs
        g.kinds = kinds
        g.seq = r.seq
        g.frame = r.frame
        g.registered = wanted
        s.keyHint = r.keyHint ?: s.keyHint
        save(s)
        save(group, g)
        r
    }

    /** The group whose slot this is, for a `push-renew`. */
    fun group(slot: ByteArray): String? = groups().firstOrNull { load(it).slot?.contentEquals(slot) == true }

    private companion object {
        const val SENDER = "push.sender"
        const val GROUP = "push.group."

        fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }
    }
}

/**
 * The hints-only marks (docs/core-api.md, "Push"): after an event of a
 * removal, a new root or a stop, the group's copies show only as hints until
 * the app has applied that change and drawn a new push key. Kept by the app
 * beside the vault, nothing secret.
 */
class PushMarks(private val store: PushVault.Store) {
    class Mark(val event: Long, val device: ByteArray?, val atMs: Long) {
        /**
         * Whether the change it tells of is still to be applied. Any mark ends
         * with a push key drawn after it; before that, a removal of a device
         * the app no longer lists, or a new root the app already knows, was
         * applied before the event came.
         */
        fun inForce(g: PushVault.Group): Boolean {
            if (atMs <= (g.keyDrawnMs ?: 0)) return false
            val d = device
            val members = g.members
            return when {
                event == 2L && d != null && members != null -> members.any { it.contentEquals(d) }
                event == 4L && d != null -> g.root?.contentEquals(d) != true
                else -> true
            }
        }
    }

    private fun all(): MutableMap<String, MutableList<Mark>> {
        val o = store.get(NAME)?.let { Json.parseToJsonElement(it.decodeToString()) as? JsonObject } ?: return mutableMapOf()
        return o.mapValues { (_, v) ->
            (v as JsonArray).map { val m = it as JsonObject; Mark(m.optLong("event") ?: 0, m.optBytes("device"), m.optLong("at_ms") ?: 0) }.toMutableList()
        }.toMutableMap()
    }

    private fun save(marks: Map<String, List<Mark>>) =
        store.put(NAME, Wire.encode(JsonObject(marks.mapValues { (_, l) ->
            JsonArray(l.map { Wire.obj("event" to Wire.num(it.event), "device" to Wire.bytes(it.device), "at_ms" to Wire.num(it.atMs)) })
        })))

    /** Marks the group with an event that arrived at [nowMs]. */
    fun mark(group: String, event: Long, device: ByteArray?, nowMs: Long = System.currentTimeMillis()) = synchronized(this) {
        val marks = all()
        val l = marks.getOrPut(group) { mutableListOf() }
        l += Mark(event, device, nowMs)
        marks[group] = l.takeLast(MAX).toMutableList()
        save(marks)
    }

    /** Whether the group shows copies only as hints. */
    fun hintsOnly(group: String, g: PushVault.Group): Boolean = all()[group]?.any { it.inForce(g) } ?: false

    /** Drops the marks the group's state has spent. */
    fun spend(group: String, g: PushVault.Group) {
        synchronized(this) {
            val marks = all()
            val l = marks[group] ?: return
            val left = l.filter { it.inForce(g) }
            if (left.size == l.size) return
            if (left.isEmpty()) marks.remove(group) else marks[group] = left.toMutableList()
            save(marks)
        }
    }

    private companion object {
        const val NAME = "push.marks"
        const val MAX = 16
    }
}
