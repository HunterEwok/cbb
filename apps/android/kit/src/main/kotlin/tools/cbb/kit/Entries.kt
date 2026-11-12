// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import java.io.File

/**
 * The newest signed entry points this phone holds (docs/protocol.md,
 * section 16, "Entry points"), kept in a file: the computers of the group
 * send them after the hello, and the phone's hub registers with the
 * project's forwarder through the ways in they name. The signature is what
 * the phone trusts, so any peer may send them.
 */
class EntriesFile(
    private val file: File,
    private val roots: List<Releases.Key>? = null,
    private val now: () -> Long = System::currentTimeMillis,
    private val log: (String) -> Unit = {},
) : EntriesKeeper {
    private class Held(val set: Releases.EntriesSet, val entries: Releases.Entries, val seen: Releases.Seen)

    private val lock = Any()
    private var held: Held? = runCatching {
        if (!file.exists()) return@runCatching null
        val set = Wire.parse(file.readBytes())?.let(Releases.EntriesSet::fromJson) ?: return@runCatching null
        val (e, seen) = Releases.checkEntries(set, roots, now(), Releases.Seen())
        Held(set, e, seen)
    }.onFailure { log("the entry points kept in ${file.name}: ${it.message}") }.getOrNull()

    private fun live(): Held? = held?.takeIf { now() < it.entries.expiresMS }

    /** The list held, null for none or for one that has expired. */
    val current: Releases.Entries? get() = synchronized(lock) { live()?.entries }

    /** When the list held expires, Unix milliseconds; null for none. */
    val expiresMS: Long? get() = synchronized(lock) { held?.entries?.expiresMS }

    /** The ways in over VLESS the list names for the forwarder [name] (host:port). */
    fun ways(name: String): List<Releases.EntryVLESS> = current?.forwarder(name)?.vless.orEmpty()

    override val order: Pair<Long, Long>? get() = synchronized(lock) { live()?.let { it.seen.keysSeq to it.entries.seq } }

    override fun add(set: Releases.EntriesSet) {
        synchronized(lock) {
            val h = live()
            try {
                val (e, seen) = Releases.checkEntries(set, roots, now(), h?.seen ?: Releases.Seen())
                if (h != null && seen.keysSeq == h.seen.keysSeq && e.seq <= h.entries.seq) return
                val tmp = File(file.path + ".tmp")
                tmp.writeText(set.toJson().toString())
                tmp.renameTo(file)
                held = Held(set, e, seen)
            } catch (e: Exception) {
                log("dropped the entry points a peer sent: ${e.message}")
            }
        }
    }

    /** Forgets the list, when the phone leaves its group. */
    fun remove() {
        synchronized(lock) { held = null }
        file.delete()
    }
}

/**
 * Keeps the newest signed entry points for a node (docs/protocol.md,
 * section 16, "Entry points"): peers send them after the hello, and the
 * phone's hub registers through the ways in they name. The phone takes them
 * and passes none on.
 */
interface EntriesKeeper {
    /** The seq of the list held's keys.json and its own, null for none. */
    val order: Pair<Long, Long>?

    /** Takes a list a peer sent when it checks out and is newer. */
    fun add(set: Releases.EntriesSet)
}
