// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import java.io.File
import kotlinx.serialization.json.JsonPrimitive
import kotlin.io.path.createTempDirectory
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The phone's member of 0.6 in the Rust core through the kit's wrapper (CoreMember), against the host's library. */
class CoreMemberTest {
    private val groups = mutableListOf<CoreGroup>()

    @AfterTest
    fun stop() {
        groups.forEach { it.close() }
    }

    private fun group(n: Int): CoreGroup = CoreGroup(n).also { groups += it }

    @Test
    fun startsAnswersAndStops() {
        val m = group(1).root.member
        assertNull(m.current())
        assertNull(m.swap("").copy, "an empty group buffer gives nothing")
        assertTrue(m.peers().isEmpty())
        assertTrue(m.swap("on the phone").sends, "a clipboard nothing sent yet goes out")
        assertFailsWith<Core.Refusal> { m.setSync(true, forMS = 1_000) }
        assertFailsWith<Core.Refusal> { m.fetch("nothing", 1 shl 20, File(createTempDirectory("cbb-out").toFile(), "out")) }
        // A lone phone's copy reaches nobody; the button's rule still knows it went out.
        m.copy("from the phone")
        assertTrue(!m.swap("from the phone").sends, "what the phone sent does not go again")
        assertTrue(!m.opened("from the phone", changed = true).sends, "opening on the phone's own copy sends nothing")
        m.close()
        assertFailsWith<IllegalStateException> { m.current() }
    }

    /** A lone phone says why it does not sync: sync off first, then no other device; the member of 0.6 adds the reasons of away from home itself. */
    @Test
    fun saysWhyItDoesNotSync() {
        val m = group(1).root.member
        assertEquals(listOf("only_device"), m.why().map { it.code })
        m.setSync(false)
        assertEquals(listOf("sync_off", "only_device"), m.why().map { it.code })
        m.setSync(true)
    }

    /** A member key that does not make the device ID the group knows does not start. */
    @Test
    fun refusesAnIdentityThatDoesNotCheck() {
        val root = SoftwareSigner()
        val key = SoftwareSigner()
        val dir = createTempDirectory("cbb-member").toFile()
        try {
            val made = CorePairing.newGroup(dir, "Pixel", "android", Records.HARDWARE, root.publicKeyDER, key.publicKeyDER, root::signDigest)
            val other = SoftwareSigner()
            assertFailsWith<Core.Refusal> {
                CoreMember.start(CoreMember.Start(dir, "Pixel", "android", device = made.device, publicKey = other.publicKeyDER), other::signDigest) { }.close()
            }
        } finally {
            dir.deleteRecursively()
        }
    }

    /** Two phones sync a copy; the root's commands for the other phone, which its member carries out itself and tells its app. */
    @Test
    fun twoPhonesSyncAndAnswerCommands() {
        val g = group(2)
        val (a, b) = g.phones
        g.connect(1, 0)
        b.member.copy("hello from two")
        val got = a.copy("hello from two")
        assertEquals(b.device, got.origin)
        val swap = a.member.swap("on a")
        assertTrue(swap.sends, "the gesture sends what the phone holds")
        assertEquals(got.id, swap.copy?.id, "and takes the group's copy")
        a.member.took(got.id)
        assertNull(a.member.swap("hello from two").copy, "a clipboard holding the group's text takes nothing")
        assertEquals(got.id, a.member.opened("on a", changed = false).copy?.id, "opening on an unchanged clipboard takes the group's copy")
        assertTrue(a.member.opened("on a", changed = true).let { it.sends && it.copy == null }, "opening on a changed clipboard only sends")

        fun act(action: String, vararg more: Pair<String, kotlinx.serialization.json.JsonElement>): kotlinx.serialization.json.JsonObject =
            a.member.act(
                kotlinx.serialization.json.JsonObject(mapOf("action" to JsonPrimitive(action), "device" to JsonPrimitive(b.device)) + more),
                g.rootKey.publicKeyDER, g.rootKey::signDigest,
            )
        val muted = act("mute", "for_ms" to JsonPrimitive(60_000))
        assertEquals("done", (muted["status"] as JsonPrimitive).content, "the mute's result: $muted")
        val m = b.next("the mute") { it as? CoreMember.Event.Mute }
        assertTrue(m.muted)
        assertEquals(a.device, m.by)
        val off = act("sync_off")
        assertEquals("done", (off["status"] as JsonPrimitive).content, "sync off's result: $off")
        assertTrue(b.next("sync off") { it as? CoreMember.Event.Sync }.off)
        // A key that is not the root's or an admin's writes nothing.
        val stranger = SoftwareSigner()
        assertFailsWith<Core.Refusal> {
            a.member.act(
                kotlinx.serialization.json.JsonObject(mapOf("action" to JsonPrimitive("rename"), "device" to JsonPrimitive(b.device), "name" to JsonPrimitive("x"))),
                stranger.publicKeyDER, stranger::signDigest,
            )
        }
        b.member.lost("phone 0")
    }

    /**
     * Calls from other threads while the member stops answer or fail, and never reach freed memory: an event's handler that
     * called the member as the app restarted it crashed the Android app.
     */
    @Test
    fun stopsWhileCalled() {
        val m = group(1).root.member
        val calls = java.util.concurrent.atomic.AtomicInteger()
        val callers = List(4) {
            Thread {
                repeat(2_000) {
                    runCatching { m.current(); m.peers() }
                    calls.incrementAndGet()
                }
            }.apply { start() }
        }
        Thread.sleep(20)
        m.close()
        callers.forEach { it.join() }
        assertEquals(8_000, calls.get())
        assertFailsWith<IllegalStateException> { m.current() }
    }

    /** The root's own settings, which the member writes and signs with the root key outside it: the key level and the copies' lifetimes. */
    @Test
    fun theRootSignsItsOwnRecordsInTheCore() {
        val g = group(1)
        val m = g.root.member
        val pub = g.rootKey.publicKeyDER
        val other = SoftwareSigner()
        assertFailsWith<Core.Refusal> { m.setKeyLevel(Records.LEVEL_FILES, other.publicKeyDER, other::signDigest) }
        assertFailsWith<Core.Refusal> { m.setKeyLevel("any", pub, g.rootKey::signDigest) }
        assertEquals(emptyList(), m.setKeyLevel(Records.LEVEL_FILES, pub, g.rootKey::signDigest))
        assertEquals(Records.LEVEL_FILES, m.group().keyLevel)
        m.setTtl(120_000, null, pub, g.rootKey::signDigest)
        assertEquals(120_000L, m.group().ttlMS)
        m.setTtl(null, 30_000, pub, g.rootKey::signDigest)
        assertEquals(120_000L to 30_000L, m.group().let { it.ttlMS to it.secretTtlMS }, "a left-out lifetime keeps its value")
    }

    /**
     * The notices and the change of root with the recovery key (docs/core-api.md, "The member"): a new group tells
     * nothing and takes a hidden notice; once the root is lost, the phone shows who stays, refuses to leave itself
     * out, and becomes the root with its new root key.
     */
    @Test
    fun changesTheRootWithTheRecoveryKey() {
        val g = group(2)
        val phone = g.phones[1]
        val m = phone.member
        assertTrue(m.notices().isEmpty(), "a new group tells nothing")
        assertFailsWith<Core.Refusal> { m.dismiss("AAAA") }
        m.dismiss(java.util.Base64.getEncoder().encodeToString(ByteArray(32) { 9 }))
        assertTrue(m.notices().isEmpty())
        m.rootChangeSeen()
        m.setEvidence(emptyList())

        g.root.member.close()
        val sheet = RecoveryInput.Qr(g.recovery)
        val preview = m.changePreview(sheet, listOf("Root phone"))
        assertTrue(!preview.waiting)
        assertEquals(mapOf("Root phone" to "out"), preview.rows.associate { it.name to it.outcome }, "every other device, with what the change does to it")
        val newRoot = SoftwareSigner()
        assertFailsWith<Core.Refusal>("the phone that becomes the root stays") {
            m.changeRoot(sheet, listOf("Phone 1"), newRoot.publicKeyDER, newRoot::signDigest)
        }
        assertTrue(m.changeRoot(sheet, listOf("Root phone"), newRoot.publicKeyDER, newRoot::signDigest) > 0)
        phone.until("the phone as the root") { m.group().rootDevice == phone.device }
        assertFailsWith<Core.Refusal>("the root changes the root no more") {
            m.changeRoot(sheet, emptyList(), newRoot.publicKeyDER, newRoot::signDigest)
        }
    }
}
