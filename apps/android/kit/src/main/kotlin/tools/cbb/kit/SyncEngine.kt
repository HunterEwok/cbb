// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import java.security.SecureRandom

/**
 * The hybrid logical clock of docs/protocol.md, section 5, as internal/hlc
 * implements it. A timestamp more than [MAX_AHEAD_MS] ahead of it is
 * refused ([ahead]).
 */
class HybridClock(
    /** A timestamp the clock must not go below, such as the last one this device issued before a restart. */
    floor: Member.Timestamp = Member.Timestamp.ZERO,
    private val wallMS: () -> Long = { System.currentTimeMillis() },
) {
    private var last = floor

    /** The last timestamp issued or observed. */
    val latest: Member.Timestamp @Synchronized get() = last

    /** A timestamp for a local event, later than every one before it. */
    @Synchronized
    fun now(): Member.Timestamp {
        val pt = wallMS().coerceIn(0, Member.Timestamp.MAX_WALL)
        last = when {
            pt > last.wall -> Member.Timestamp(pt, 0)
            last.logical == MAX_LOGICAL -> Member.Timestamp(minOf(last.wall + 1, Member.Timestamp.MAX_WALL), 0)
            else -> Member.Timestamp(last.wall, last.logical + 1)
        }
        return last
    }

    /** Takes in the timestamp of an event received for the first time. */
    @Synchronized
    fun observe(r: Member.Timestamp) {
        val pt = wallMS().coerceIn(0, Member.Timestamp.MAX_WALL)
        val w = maxOf(last.wall, r.wall, pt)
        last = when {
            w == last.wall && w == r.wall -> Member.Timestamp(w, inc(maxOf(last.logical, r.logical)))
            w == last.wall -> Member.Timestamp(w, inc(last.logical))
            w == r.wall -> Member.Timestamp(r.wall, inc(r.logical))
            else -> Member.Timestamp(w, 0)
        }
    }

    /**
     * Whether r is more than [MAX_AHEAD_MS] ahead of this clock's wall time,
     * as Go's Ahead: the timestamps it issued or observed do not move that
     * limit. A clock that reads before 2026 refuses nothing.
     */
    @Synchronized
    fun ahead(r: Member.Timestamp): Boolean {
        val ref = wallMS()
        return ref >= PLAUSIBLE && r.wall > ref + MAX_AHEAD_MS
    }

    private fun inc(l: Long): Long = if (l == MAX_LOGICAL) l else l + 1

    companion object {
        private const val MAX_LOGICAL = 0xffff_ffffL

        /** How far a received timestamp may be ahead of the clock: 7 days. */
        const val MAX_AHEAD_MS = 7L * 24 * 3600 * 1000

        /** 2026-01-01: before it the clock is not trusted to refuse anything. */
        private const val PLAUSIBLE = 1_767_225_600_000L
    }
}

/**
 * The phone's sync engine: the group's current event, the IDs seen, and
 * the forwarding rules of docs/protocol.md, section 5 ("wire" parts). What
 * it keeps is simply the current event while it is live. Not safe for
 * concurrent use.
 */
class SyncEngine(
    val device: String,
    internal val clock: HybridClock,
    /** A monotonic clock in milliseconds. */
    private val uptimeMS: () -> Long = { System.nanoTime() / 1_000_000 },
) {
    private var current: Member.Event? = null

    /** When the current event was copied, on the uptime clock. */
    private var copiedAt = 0L
    private val seen = LinkedHashSet<String>()

    /**
     * Seals a new event to the group's readers, with the key and the blob of
     * its images or files (CopyKeys.seal); null leaves events unsealed, as in
     * tests of the engine alone.
     */
    var seal: ((Member.Event, ByteArray?, Blob?) -> Sealed)? = null

    /** What to do with a received event. */
    data class Result(
        /** The event to send to the other connections, if any. */
        val forward: Member.Event?,
        /** Whether it became the current event, or the current event got its text. */
        val changed: Boolean,
    )

    /** The current event with its age as of now. */
    val currentEvent: Member.Event? get() = current?.copy(ageMS = maxOf(0, uptimeMS() - copiedAt))

    /**
     * The current text while it is usable: a text, a secret younger than
     * the secret lifetime, or the text of images or files, as a text.
     */
    val usable: Pair<String, Member.Kind>?
        get() {
            val e = current ?: return null
            if (e.isMark || e.unread) return null
            if (e.kind == Member.Kind.SECRET && uptimeMS() - copiedAt >= SECRET_TTL_MS) return null
            if (e.kind == Member.Kind.MEDIA) return e.text.takeIf { it.isNotEmpty() }?.let { it to Member.Kind.TEXT }
            return e.text to e.kind
        }

    /** The hello for a new connection: the current event, a secret only as its mark. */
    fun hello(name: String?, wallMS: Long = System.currentTimeMillis()): Member.Hello =
        Member.Hello(wallMS = wallMS, current = currentEvent?.mark, name = name)

    /**
     * Makes an event of a text this phone copied or sent, or with media of
     * images or files and text their plain-text alternative, which becomes
     * the current event, sealed with seal; key sealed the blob of the images
     * or files. It goes to every connection.
     */
    fun local(
        text: String,
        kind: Member.Kind,
        via: Member.Via = Member.Via.COPY,
        media: Media.Manifest? = null,
        key: ByteArray? = null,
        blob: Blob? = null,
    ): Member.Event {
        var e = Member.Event(newID(), device, via, clock.now(), 0, if (media != null) Member.Kind.MEDIA else kind, text, media)
        seal?.let { e = e.copy(sealed = it(e, key, blob), key = key) }
        remember(e.id)
        current = e
        copiedAt = uptimeMS()
        return e
    }

    /**
     * Takes in an event from a connection, or the current event of a hello.
     * An event that is not valid, or more than 7 days ahead of the clock,
     * changes nothing.
     */
    fun received(e: Member.Event): Result {
        if (!e.isValid || clock.ahead(e.time)) return Result(null, false)
        if (e.id in seen) {
            // Seen before: only a mark that gets its text matters.
            val cur = current
            if (cur != null && cur.id == e.id && cur.isMark && !e.isMark && cur.samePayload(e)) {
                current = e
                copiedAt = uptimeMS() - minOf(e.ageMS, MAX_AGE_MS)
                return Result(e, true)
            }
            return Result(null, false)
        }
        clock.observe(e.time)
        remember(e.id)
        var changed = false
        val cur = current
        if (cur == null || e.isLater(cur)) {
            current = e
            copiedAt = uptimeMS() - minOf(e.ageMS, MAX_AGE_MS)
            changed = true
        }
        return Result(e, changed)
    }

    class HelloException(message: String) : Exception(message)

    /** Drops the current event when it is the event id: its origin was removed from the group, so its copy no longer counts. What the phone's clipboard holds stays. */
    fun forget(id: String) {
        if (current?.id != id) return
        current = null
        copiedAt = 0
    }

    /** Takes in a peer's hello. A hello that carries a secret's text is a protocol error and closes the connection. */
    fun reconcile(h: Member.Hello): Result {
        val cur = h.current ?: return Result(null, false)
        if (cur.sealed == null && cur.kind == Member.Kind.SECRET && cur.text.isNotEmpty()) throw HelloException("a secret's text in a hello")
        if (!cur.isValid) throw HelloException("a hello with a bad event")
        return received(cur)
    }

    private fun remember(id: String) {
        if (!seen.add(id)) return
        if (seen.size > REMEMBER_IDS) seen.remove(seen.first())
    }

    companion object {
        /** How many event IDs are remembered. */
        const val REMEMBER_IDS = 4096

        /** How long a secret is usable after its copy. */
        const val SECRET_TTL_MS = 60_000L

        /** Ages are capped at 365 days. */
        internal const val MAX_AGE_MS = 365L * 24 * 3600 * 1000

        private val random = SecureRandom()

        /** A new event or device ID: 128 random bits as 32 lowercase hex characters. */
        fun newID(): String = ByteArray(16).also { random.nextBytes(it) }.toHex()
    }
}
