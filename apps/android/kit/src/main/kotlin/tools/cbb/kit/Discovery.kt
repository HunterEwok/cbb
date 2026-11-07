// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

/**
 * A Linux member found by mDNS browsing (docs/protocol.md, section 3): its
 * device ID, the first label of its service instance, and what its TXT
 * record says.
 */
data class FoundMember(
    val device: String,
    /** The group tag (`g`); null when the TXT record has none. */
    val group: String?,
    /** Whether a computer pairing window is open (`p=1`). */
    val pairing: Boolean = false,
)

object Discovery {
    /** The DNS-SD service type the Linux members publish. */
    const val SERVICE_TYPE = "_cbb._tcp"

    /**
     * Reads a found service: the instance name must be a device ID; the TXT
     * strings are "key=value", keys matched without regard to case, the
     * value what follows the first "=". Unknown keys are ignored.
     */
    fun member(instance: String, txt: List<String>): FoundMember? {
        if (!GroupCertificates.isDeviceID(instance)) return null
        val fields = mutableMapOf<String, String>()
        for (s in txt) {
            val i = s.indexOf('=')
            val k = (if (i < 0) s else s.substring(0, i)).lowercase()
            val v = if (i < 0) "" else s.substring(i + 1)
            fields.putIfAbsent(k, v)
        }
        return FoundMember(instance, fields["g"], fields["p"] == "1")
    }

    /** The same from a TXT record already split into keys and values, as Android's NsdServiceInfo gives it. */
    fun member(instance: String, txt: Map<String, ByteArray?>): FoundMember? =
        member(instance, txt.map { (k, v) -> "$k=${v?.toString(Charsets.UTF_8) ?: ""}" })

    /**
     * The TXT record of a device that waits to join, listening with its QR
     * code on screen: no group tag, so no member dials it, and the
     * fingerprint of its certificate, which a computer of the group checks
     * when it admits the device by the code typed there (docs/protocol.md,
     * sections 3 and 6).
     */
    fun joinerTXT(fingerprint: String): Map<String, String> = mapOf("v" to "1", "j" to "1", "f" to fingerprint)

    /**
     * The members to dial: those browsing found, and the devices of the
     * group with a known address that it did not find, as a member in
     * another subnet, which mDNS does not reach (docs/protocol.md, section 9).
     */
    fun withKnown(found: Set<FoundMember>, known: Set<String>, group: String): Set<FoundMember> =
        found + known.filter { d -> found.none { it.device == d } }.map { FoundMember(it, group) }
}

/**
 * Keeps one connection to every found member of the phone's group: it dials
 * each, runs the connection on the node, and dials again after it ends,
 * waiting 1 s, doubling to 30 s; a connection that lasted more than 30 s
 * resets the wait (docs/protocol.md, section 4, "Who dials whom"). A member
 * that is no longer found is not dialed again. Each member has a thread of
 * its own while it is wanted.
 */
class MemberDialer(
    private val node: MemberNode,
    private val group: String,
    private val firstWaitMS: Long = 1_000,
    private val maxWaitMS: Long = 30_000,
    /** Connects to a found member and finishes the TLS handshake, checking that the peer is that device of this group. */
    private val dial: (FoundMember) -> FrameTransport,
) {
    private val lock = Object()
    private var found = setOf<String>()
    private val threads = mutableMapOf<String, Thread>()
    private val direct = mutableSetOf<String>()
    private var stopped = false

    /** The members being dialed or connected. */
    val dialing: Set<String> get() = synchronized(lock) { threads.keys.toSet() }

    /** The members connected on the home network: their TLS handshake passed. */
    val connected: Set<String> get() = synchronized(lock) { direct.toSet() }

    /**
     * Takes the members browsing finds now. Those of another group are ignored;
     * beyond MAX_DIALED, the members not dialed yet wait for a later update.
     */
    fun update(members: Set<FoundMember>) = synchronized(lock) {
        if (stopped) return
        found = members.filter { it.group == group }.map { it.device }.toSet()
        for (d in found.sorted()) {
            if (threads[d] != null) continue
            if (threads.size >= MAX_DIALED) break
            threads[d] = Thread({ keep(FoundMember(d, group)) }, "dial $d").apply {
                isDaemon = true
                start()
            }
        }
        lock.notifyAll()
    }

    /** Stops dialing; the node's connections stay until closed. */
    fun stop() = synchronized(lock) {
        stopped = true
        threads.values.forEach { it.interrupt() }
        threads.clear()
        lock.notifyAll()
    }

    private fun stillWanted(d: String) = synchronized(lock) { !stopped && d in found }

    companion object {
        /** How many found members are dialed at once, as on the lite member: a host that announces many members of the group starts no more. */
        const val MAX_DIALED = 64
    }

    private fun keep(m: FoundMember) {
        var wait = firstWaitMS
        try {
            while (stillWanted(m.device)) {
                val started = System.nanoTime()
                val t = runCatching { dial(m) }.getOrNull()
                if (t != null) {
                    synchronized(lock) { direct.add(m.device) }
                    try {
                        runCatching { node.serve(t, m.device) }
                    } finally {
                        synchronized(lock) { direct.remove(m.device) }
                    }
                    if ((System.nanoTime() - started) / 1_000_000 > maxWaitMS) wait = firstWaitMS
                }
                if (!stillWanted(m.device)) break
                Thread.sleep(wait)
                wait = minOf(wait * 2, maxWaitMS)
            }
        } catch (e: InterruptedException) {
            // stopped
        } finally {
            synchronized(lock) { if (threads[m.device] == Thread.currentThread()) threads.remove(m.device) }
        }
    }
}
