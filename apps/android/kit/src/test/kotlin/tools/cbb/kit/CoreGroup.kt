// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import java.io.File
import java.time.Instant
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.io.path.createTempDirectory
import kotlin.test.fail

/** One phone of a test group: its member in the Rust core (CoreMember), its keys, and the events it got. */
class CorePhone(
    val member: CoreMember,
    val device: String,
    val cert: ByteArray,
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

    /** The hello of [device], once it came. */
    fun peer(device: String): CoreMember.Peer = next("the hello of $device") { (it as? CoreMember.Event.PeerConnected)?.peer?.takeIf { p -> p.device == device } }

    /** The devices connected now. */
    fun connected(): Set<String> = member.peers().map { it.device }.toSet()
}

/**
 * A group of phones whose members run in the Rust core: the root phone ([root]) made it and certified the others, each with a
 * device record that seals the copies to it. [close] stops them and removes their folders.
 */
class CoreGroup(n: Int = 2) : AutoCloseable {
    val ca = SoftwareSigner()
    val g: PhoneGroup
    val phones: List<CorePhone>
    private val top: File = createTempDirectory("cbb-core-group").toFile()

    val root: CorePhone get() = phones[0]

    init {
        val now = Instant.now()
        val sealKey = Core.sealPublic(SEAL)
        val rootKey = SoftwareSigner()
        g = PhoneGroup.create(ca, rootKey.publicKeyDER, now, seal = sealKey)
        val made = mutableListOf(Triple(g.device, g.memberCert, rootKey))
        for (i in 1 until maxOf(n, 1)) {
            val k = SoftwareSigner()
            val id = SyncEngine.newID()
            val cert = GroupCertificates.member(id, k.publicKeyDER, g.groupCA, ca, now)
            g.record(id, "Phone $i", "phone", Records.keyHash(k.publicKeyDER), ca, now, os = "android", store = Records.HARDWARE, seal = sealKey)
            made += Triple(id, cert, k)
        }
        phones = made.mapIndexed { i, (id, cert, k) ->
            val dir = File(top, "$i").apply { mkdirs() }
            val events = CopyOnWriteArrayList<CoreMember.Event>()
            val m = CoreMember.start(
                CoreMember.Start(dir, if (i == 0) "Root phone" else "Phone $i", "android", "17", "0.6.0", device = id, publicKey = k.publicKeyDER,
                    seal = SEAL, cert = cert, groupCA = g.groupCA, roots = g.trusted),
                k::signDigest,
            ) { e -> events.add(e) }
            m.addRecords(g.records.records)
            CorePhone(m, id, cert, k, events)
        }
    }

    /** Phone [i] dials phone [hub], which listens as the group's hub, and both wait for the other's hello. */
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

    companion object {
        /** The core keeps the secret for sealed messages for the process, as an app runs one member with one secret: every phone of every test has it. */
        val SEAL = ByteArray(32) { 9 }
    }
}
