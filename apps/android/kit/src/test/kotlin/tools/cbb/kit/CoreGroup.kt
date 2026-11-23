// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import java.io.File
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.io.path.createTempDirectory
import kotlin.test.fail

/** One phone of a test group: its member in the Rust core (CoreMember), its keys, and the events it got. */
class CorePhone(
    val member: CoreMember,
    val device: String,
    val key: SoftwareSigner,
    val events: CopyOnWriteArrayList<CoreMember.Event>,
) {
    /** The port it listens on as the hub, once it does. */
    var port: Int? = null

    /** Every event [pick] picks so far. */
    fun <T> all(pick: (CoreMember.Event) -> T?): List<T> = events.mapNotNull(pick)

    /** The first event [pick] picks, waiting up to 15 s. */
    fun <T> next(what: String, pick: (CoreMember.Event) -> T?): T {
        val deadline = System.nanoTime() + 15_000_000_000L
        while (System.nanoTime() < deadline) {
            events.firstNotNullOfOrNull(pick)?.let { return it }
            Thread.sleep(50)
        }
        fail("no $what within 15 s")
    }

    /** Waits up to 15 s until [cond] holds. */
    fun until(what: String, cond: () -> Boolean) {
        val deadline = System.nanoTime() + 15_000_000_000L
        while (System.nanoTime() < deadline) {
            if (cond()) return
            Thread.sleep(50)
        }
        fail("no $what within 15 s")
    }

    /** The copy with [text] that became the group's here. */
    fun copy(text: String): CoreMember.Copy = next("the copy $text") { (it as? CoreMember.Event.CopyChanged)?.copy?.takeIf { c -> c.text == text } }

    /** The member [device], once it is connected. */
    fun peer(device: String): CoreMember.Peer {
        var p: CoreMember.Peer? = null
        until("the connection of $device") { p = member.peers().firstOrNull { it.device == device }; p != null }
        return p!!
    }

    /** The devices connected now. */
    fun connected(): Set<String> = member.peers().map { it.device }.toSet()
}

/**
 * A group of 0.6 whose members run in the Rust core: the root phone ([root])
 * made it, and the others joined by its home window, as the apps do. [close]
 * stops them and removes their folders.
 */
class CoreGroup(n: Int = 2) : AutoCloseable {
    /** The group's root key, which the root phone holds. */
    val rootKey = SoftwareSigner()
    val phones: List<CorePhone>

    /** The text of the recovery sheet's QR code, which the app shows once when it makes the group. */
    val recovery: String
    private val top: File = createTempDirectory("cbb-core-group").toFile()

    val root: CorePhone get() = phones[0]

    init {
        val key = SoftwareSigner()
        val made = CorePairing.newGroup(File(top, "0"), "Root phone", "android", Records.HARDWARE, rootKey.publicKeyDER, key.publicKeyDER, rootKey::signDigest)
        recovery = made.recoveryQR
        val first = start(0, "Root phone", made.device, key)
        val all = mutableListOf(first)
        val port = first.member.listen(CoreMember.Listen.HOME)
        first.port = port
        for (i in 1 until maxOf(n, 1)) {
            val k = SoftwareSigner()
            val w = CorePairing.Window(first.member, rootKey.publicKeyDER, listOf("127.0.0.1"), sign = rootKey::signDigest)
            val j = CorePairing.Joiner(File(top, "$i").path, w.qr, "Phone $i", "android", k.publicKeyDER, k::signDigest)
            try {
                val done = finish("phone $i joining") { v -> j.next(v, 100).let { Triple(it.version, it.state, it.failure) to it } }
                all += start(i, "Phone $i", done.device, k)
            } finally {
                j.close()
                w.close()
            }
        }
        phones = all
    }

    private fun start(i: Int, name: String, device: String, k: SoftwareSigner): CorePhone {
        val events = CopyOnWriteArrayList<CoreMember.Event>()
        val m = CoreMember.start(
            CoreMember.Start(File(top, "$i").apply { mkdirs() }, name, "android", "17", "0.6.0", device = device, publicKey = k.publicKeyDER),
            k::signDigest,
        ) { e -> events.add(e) }
        return CorePhone(m, device, k, events)
    }

    /** Follows a pairing's states until done, failing on failed or after 15 s. */
    private fun <T> finish(what: String, next: (Long) -> Pair<Triple<Long, String, Throwable?>, T>): T {
        val deadline = System.nanoTime() + 15_000_000_000L
        var version = 0L
        while (System.nanoTime() < deadline) {
            val (st, value) = next(version)
            version = st.first
            when (st.second) {
                "done" -> return value
                "failed" -> fail("$what failed: ${st.third}")
            }
        }
        fail("$what did not end within 15 s")
    }

    /** Phone [i] dials phone [hub], which listens as the group's hub, and both wait until they are connected. */
    fun connect(i: Int, hub: Int) {
        val h = phones[hub]
        val port = h.port ?: h.member.listen(CoreMember.Listen.HOME).also { h.port = it }
        phones[i].member.found("phone $hub", listOf("127.0.0.1:$port"), h.device)
        phones[i].peer(h.device)
        h.peer(phones[i].device)
    }

    override fun close() {
        phones.forEach { it.member.close() }
        top.deleteRecursively()
    }
}
