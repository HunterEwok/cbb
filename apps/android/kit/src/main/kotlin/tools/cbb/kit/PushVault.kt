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
 * membership change), the slot, the last registration, the highest seq
 * given and what `push_open` needs.
 */
class PushVault(private val store: Store) {
    /** Named blobs the app keeps sealed on the device; null removes one. */
    interface Store {
        fun get(name: String): ByteArray?
        fun put(name: String, value: ByteArray?)
        fun names(): List<String>
    }

    class Incomplete : Exception("push needs a token and its platform")

    class NoFace : Exception("push needs the group's face for the push service, which this group has not given yet")

    /** The token's sender, shared by every group. */
    class Sender(
        var token: ByteArray? = null,
        var unifiedPush: Push.UnifiedPush? = null,
        var env: Long? = null,
        var sendKey: ByteArray? = null,
        var keyHint: ByteArray? = null,
        var challenge: ByteArray? = null,
        /** When the challenge was kept (the phone's clock). */
        var challengeAtMs: Long? = null,
    ) {
        internal fun json(): JsonObject = Wire.obj(
            "token" to Wire.bytes(token),
            "unifiedpush" to unifiedPush?.let { Wire.obj("url" to Wire.str(it.url), "p256dh" to Wire.bytes(it.p256dh), "auth" to Wire.bytes(it.auth)) },
            "env" to Wire.num(env),
            "send_key" to Wire.bytes(sendKey),
            "key_hint" to Wire.bytes(keyHint),
            "challenge" to Wire.bytes(challenge),
            "challenge_at_ms" to Wire.num(challengeAtMs),
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
                challengeAtMs = o.optLong("challenge_at_ms"),
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
        val face: String? = null,
    )

    /** The group's devices (their IDs) and its root, as the app applied them. */
    class Devices(val members: List<ByteArray>, val root: ByteArray?)

    /** One group's push state. */
    class Group(
        var keys: List<Push.KeyAndSeq> = emptyList(),
        var slot: ByteArray? = null,
        var kinds: Long = 0,
        /** The last registration's seq, and the highest one given. */
        var seq: Long? = null,
        var highest: Long? = null,
        var frame: ByteArray? = null,
        var registered: Registered? = null,
        /**
         * The challenge period of the last registration made for a new
         * challenge alone (UnifiedPush), and the send key it was made under
         * (hex): a new send key starts afresh.
         */
        var challengedPeriod: Long? = null,
        var challengedKey: String? = null,
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
            "highest" to Wire.num(highest),
            "frame" to Wire.bytes(frame),
            "registered" to registered?.let {
                Wire.obj(
                    "token" to Wire.str(it.token), "env" to Wire.num(it.env), "kinds" to Wire.num(it.kinds),
                    "key" to Wire.str(it.key), "send_key" to Wire.str(it.sendKey), "challenge" to Wire.str(it.challenge),
                    "face" to Wire.str(it.face),
                )
            },
            "challenged_period" to Wire.num(challengedPeriod),
            "challenged_key" to Wire.str(challengedKey),
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
                highest = o.optLong("highest"),
                frame = o.optBytes("frame"),
                registered = o.optObject("registered")?.let {
                    Registered(
                        it.optString("token"), it.optLong("env"), it.optLong("kinds") ?: 0, it.optString("key"),
                        it.optString("send_key"), it.optString("challenge"), it.optString("face"),
                    )
                },
                challengedPeriod = o.optLong("challenged_period"),
                challengedKey = o.optString("challenged_key"),
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

        /**
         * A member's `push-renew` said the push service found the number more
         * than a day past its clock: the next one starts again from the
         * phone's clock, once.
         */
        AHEAD,
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

    /**
     * Removes the group: its push keys, slot, secrets and origins. The sender
     * stays while the token does, so the next group registers under the same
     * send key, whose binding the push service has confirmed.
     */
    fun forget(group: String) = synchronized(lock) {
        save(group, null)
    }

    /**
     * The phone is leaving the group: the registration that turns push off
     * there, which the member's sync sends to the group's members while the
     * phone still can (null when push is already off there).
     */
    fun leaving(group: String, nowMs: Long = System.currentTimeMillis()): Push.Registration? {
        val g = load(group)
        val me = g.me ?: return null
        if (g.kinds == 0L) return null
        return register(group, me, null, null, null, 0, nowMs = nowMs)
    }

    /**
     * The phone left the group: the group goes, and so does the send key, so
     * that the registration the left group's members hold stops being good
     * once the phone's other groups confirm the new one. The token stays; the
     * next registration draws the new send key.
     */
    fun left(group: String): Boolean = synchronized(lock) {
        save(group, null)
        if (groups().isEmpty()) {
            // No group left: the sender goes whole, token and all, and the
            // app gives the token up (no other group would confirm a new key).
            save(null as Sender?)
            return@synchronized true
        }
        val s = sender()
        if (s.sendKey == null) return@synchronized false
        s.sendKey = null
        s.keyHint = null
        s.challenge = null
        s.challengeAtMs = null
        save(s)
        false
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
     * another key or token confirms nothing. A UnifiedPush endpoint takes a
     * message from whoever knows it and its keys, every member among them, so
     * there at most one new challenge an hour is kept.
     */
    fun keep(challenge: ByteArray, nowMs: Long = System.currentTimeMillis()): Boolean = synchronized(lock) {
        if (challenge.size != 24) return false
        val s = sender()
        val hint = s.keyHint ?: return false
        if (s.sendKey == null || !hint.contentEquals(challenge.copyOfRange(16, 24))) return false
        val value = challenge.copyOfRange(0, 16)
        if (s.challenge?.contentEquals(value) == true) return false
        val at = s.challengeAtMs
        if (s.unifiedPush != null && at != null && nowMs in at until at + CHALLENGE_EVERY_MS) return false
        s.challenge = value
        s.challengeAtMs = nowMs
        save(s)
        true
    }

    /**
     * The group's registration for [token] (or [unifiedPush]) of [env] with
     * [kinds] (0: push off), made again only when something in it changed or
     * for [reasons]; null when the saved one still says it all. A new token
     * gets a new send key, which drops the challenge of the old one. A device
     * gone or a new root in [devices] is a membership change. [face] is the
     * group's face for the push service, which the registration names: a new
     * face makes a new registration. The highest seq is saved with the frame,
     * so the next one is higher. On UnifiedPush a new challenge alone makes a
     * new registration once in a challenge period.
     */
    fun register(
        group: String,
        me: ByteArray,
        token: ByteArray?,
        unifiedPush: Push.UnifiedPush? = null,
        env: Long?,
        kinds: Long,
        face: ByteArray? = null,
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
            val r = Push.registration(g.highest ?: g.seq, nowMs, Reason.AHEAD in why, 0)
            g.kinds = 0
            g.seq = r.seq
            g.highest = r.highest
            g.frame = r.frame
            g.registered = off
            save(group, g)
            return r
        }
        if ((token == null && unifiedPush == null) || env == null) throw Incomplete()
        if (face == null) throw NoFace()
        val sameToken = (s.token?.contentEquals(token ?: ByteArray(0)) ?: (token == null)) && s.unifiedPush == unifiedPush
        if (s.sendKey == null || !sameToken || s.env != env) {
            s.sendKey = Push.newKeys().sendKey
            s.token = token
            s.unifiedPush = unifiedPush
            s.env = env
            s.keyHint = null
            s.challenge = null
            // The hour between challenges and the period's one registration
            // over a challenge belong to the old key.
            s.challengeAtMs = null
        }
        if (g.slot == null) g.slot = Push.newKeys().slot
        val drew = g.keys.isEmpty() || g.kinds == 0L || Reason.MEMBERSHIP in why
        val key = if (drew) Push.newKeys().key else g.keys[0].key
        val wanted = Registered(
            token?.let(::hex) ?: unifiedPush?.let { it.url + "|" + hex(it.p256dh) + "|" + hex(it.auth) },
            env, kinds, hex(key), s.sendKey?.let(::hex), s.challenge?.let(::hex), hex(face),
        )
        val asked = Reason.RENEW in why || Reason.AHEAD in why
        if (!drew && !asked && g.registered == wanted) {
            save(group, g)
            return null
        }
        // Only the challenge is new: on UnifiedPush, once a period.
        val challengeAlone = g.registered?.copy(challenge = wanted.challenge) == wanted && g.registered != wanted
        val period = nowMs / CHALLENGE_PERIOD_MS
        val sendKeyHex = s.sendKey?.let(::hex)
        if (!drew && !asked && challengeAlone && unifiedPush != null && g.challengedPeriod == period && g.challengedKey == sendKeyHex) {
            save(group, g)
            return null
        }
        val r = Push.registration(
            g.highest ?: g.seq, nowMs, Reason.AHEAD in why, kinds, env, token, unifiedPush, key, s.sendKey, g.slot, face, s.challenge,
        )
        if (challengeAlone) {
            g.challengedPeriod = period
            g.challengedKey = sendKeyHex
        }
        // The body's seq is in its associated data: the key under the previous
        // seq stays for bodies already on their way, one entry; after a
        // membership change none, so a removed member's bodies open nothing.
        val previous = if (Reason.MEMBERSHIP in why || g.kinds == 0L) null else g.keys.firstOrNull()
        g.keys = listOf(Push.KeyAndSeq(key, r.seq)) + listOfNotNull(previous)
        if (drew) g.keyDrawnMs = nowMs
        g.kinds = kinds
        g.seq = r.seq
        g.highest = r.highest
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

        /** The push service's challenge period (member/src/pushd/binding.rs). */
        const val CHALLENGE_PERIOD_MS = 14L * 24 * 3600 * 1000

        /** At most one new challenge an hour on UnifiedPush. */
        const val CHALLENGE_EVERY_MS = 3600L * 1000

        fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }
    }
}

/**
 * The hints-only marks (docs/core-api.md, "Push"): after an event of a
 * removal, a new root or a stop, the group's copies show only as hints until
 * the app has applied that change and drawn a new push key. Kept by the app
 * beside the vault, nothing secret.
 */
class PushMarks(private val store: PushVault.Store, private val clock: () -> Long = System::currentTimeMillis) {
    /**
     * [metMs]: when the app first synced, after the mark, with a member other
     * than the device it names; the week a mark lasts at most counts from
     * then, so a phone that met no member keeps a true mark however long.
     */
    class Mark(val event: Long, val device: ByteArray?, val atMs: Long, var metMs: Long? = null) {
        /**
         * Whether the change it tells of is still to be applied. Any mark ends
         * with a push key drawn after it, and a week after the app first met
         * another member; before that, a removal of a device the app no
         * longer lists, or a new root the app already knows, was applied
         * before the event came.
         */
        fun inForce(g: PushVault.Group, nowMs: Long = System.currentTimeMillis()): Boolean {
            val met = metMs
            if (atMs <= (g.keyDrawnMs ?: 0) || (met != null && nowMs >= met + LIFE_MS)) return false
            val d = device
            val members = g.members
            return when {
                event == 2L && d != null && members != null -> members.any { it.contentEquals(d) }
                event == 4L && d != null -> g.root?.contentEquals(d) != true
                else -> true
            }
        }

        /** Whether the group's records as the app applied them say the change did not happen. */
        fun contradicted(g: PushVault.Group): Boolean {
            val d = device
            return when {
                event == 2L && d != null -> g.members?.any { it.contentEquals(d) } ?: false
                event == 4L && d != null -> g.root?.let { !it.contentEquals(d) } ?: false
                event == 6L -> !g.halted
                else -> false
            }
        }
    }

    private fun all(): MutableMap<String, MutableList<Mark>> {
        val o = store.get(NAME)?.let { Json.parseToJsonElement(it.decodeToString()) as? JsonObject } ?: return mutableMapOf()
        return o.mapValues { (_, v) ->
            (v as JsonArray).map { val m = it as JsonObject; Mark(m.optLong("event") ?: 0, m.optBytes("device"), m.optLong("at_ms") ?: 0, m.optLong("met_ms")) }.toMutableList()
        }.toMutableMap()
    }

    private fun save(marks: Map<String, List<Mark>>) =
        store.put(NAME, Wire.encode(JsonObject(marks.mapValues { (_, l) ->
            JsonArray(l.map { Wire.obj("event" to Wire.num(it.event), "device" to Wire.bytes(it.device), "at_ms" to Wire.num(it.atMs), "met_ms" to Wire.num(it.metMs)) })
        })))

    /**
     * Marks the group with an event that arrived at [nowMs]. When the list is
     * full a mark no longer in force goes first; a mark not in force when it
     * arrives (a removal of a device the group does not list) never pushes
     * one out.
     */
    fun mark(group: String, event: Long, device: ByteArray?, state: PushVault.Group?, nowMs: Long = System.currentTimeMillis()) =
        synchronized(this) {
            val marks = all()
            val l = marks.getOrPut(group) { mutableListOf() }
            val g = state ?: PushVault.Group()
            val m = Mark(event, device, nowMs)
            val now = clock()
            if (l.size >= MAX) {
                if (!m.inForce(g, now)) return@synchronized
                val i = l.indexOfFirst { !it.inForce(g, now) }
                l.removeAt(if (i >= 0) i else 0)
            }
            l += m
            marks[group] = l.takeLast(MAX).toMutableList()
            save(marks)
        }

    /** Whether the group shows copies only as hints. */
    fun hintsOnly(group: String, g: PushVault.Group): Boolean {
        val now = clock()
        return all()[group]?.any { it.inForce(g, now) } ?: false
    }

    /**
     * The app has synced the group's records with [peers] (members that
     * stayed connected a while) since [atMs], and applied them into [state];
     * [recordsAtMs] is when the app last took in records it did not have. A
     * mark that arrived before [atMs] is spent when those records contradict
     * its event (the device it names is still listed, the root is not the one
     * it names, the group is not stopped), they came from a member other than
     * the device it names, and the app took in new records after the mark: a
     * member that brought nothing newer has not heard of the change either.
     * That ends a mark of an event made by a holder of the push key that names
     * a change which never comes. A mark whose change is there is spent once
     * the app applies it ([spend]). A mark that stays and met a member other
     * than the device it names here has its week start ([Mark.metMs]).
     */
    fun synced(group: String, atMs: Long, peers: List<ByteArray>, recordsAtMs: Long?, state: PushVault.Group) {
        synchronized(this) {
            val marks = all()
            val l = marks[group] ?: return
            var met = false
            val left = l.filter { m ->
                if (m.atMs >= atMs) return@filter true
                val d = m.device
                if (peers.none { d == null || !it.contentEquals(d) }) return@filter true
                if (m.metMs == null) {
                    m.metMs = atMs
                    met = true
                }
                (recordsAtMs ?: 0) <= m.atMs || !m.contradicted(state)
            }
            if (left.size == l.size && !met) return
            if (left.isEmpty()) marks.remove(group) else marks[group] = left.toMutableList()
            save(marks)
        }
    }

    /** Drops every mark of a group the phone left. */
    fun forget(group: String) {
        synchronized(this) {
            val marks = all()
            if (marks.remove(group) == null) return
            save(marks)
        }
    }

    /** The marks of the group, oldest first. */
    fun of(group: String): List<Mark> = all()[group] ?: emptyList()

    /** Drops the marks the group's state has spent. */
    fun spend(group: String, g: PushVault.Group) {
        synchronized(this) {
            val marks = all()
            val l = marks[group] ?: return
            val now = clock()
            val left = l.filter { it.inForce(g, now) }
            if (left.size == l.size) return
            if (left.isEmpty()) marks.remove(group) else marks[group] = left.toMutableList()
            save(marks)
        }
    }

    companion object {
        private const val NAME = "push.marks"
        const val MAX = 16

        /** How long a mark lasts when nothing ends it before: a week. */
        const val LIFE_MS = 7L * 24 * 3600 * 1000
    }
}
