// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import java.io.File
import kotlin.io.path.createTempDirectory
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.test.fail

/** A phone makes a group of 0.6, opens its pairing window, and a new phone joins by its QR code, through the Rust core as the apps do. */
class WindowTest {
    private val top: File = createTempDirectory("cbb-core-window").toFile()
    private val closing = mutableListOf<AutoCloseable>()

    @AfterTest
    fun cleanUp() {
        closing.asReversed().forEach { runCatching { it.close() } }
        top.deleteRecursively()
    }

    private fun <T : AutoCloseable> T.closed(): T = also { closing += it }

    private fun <S> wait(want: String, state: (S) -> String, version: (S) -> Long, failure: (S) -> Exception?, next: (Long) -> S): S {
        var v = 0L
        repeat(200) {
            val s = next(v)
            if (state(s) == want) return s
            failure(s)?.takeIf { state(s) == "failed" }?.let { throw it }
            v = version(s)
        }
        fail("no state $want")
    }

    @Test
    fun aPhoneThatMadeItsGroupLetsANewPhoneJoinByItsWindow() {
        val root = SoftwareSigner()
        val key = SoftwareSigner()
        val dir = File(top, "root")
        val made = CorePairing.newGroup06(dir, "Root phone", "android", Records.HARDWARE, root.publicKeyDER, key.publicKeyDER, root::signDigest)
        assertEquals(4, made.recoveryText.size)
        assertTrue(made.recoveryQR.isNotEmpty())
        // Once only.
        assertFailsWith<CorePairing.Failure> {
            CorePairing.newGroup06(dir, "Root phone", "android", Records.HARDWARE, root.publicKeyDER, key.publicKeyDER, root::signDigest)
        }

        val m = CoreMember.start(
            CoreMember.Start(dir, "Root phone", "android", device = made.device, publicKey = key.publicKeyDER, seal = CoreGroup.SEAL,
                cert = ByteArray(0), groupCA = ByteArray(0)),
            key::signDigest,
            events = { },
        ).closed()
        m.listen(CoreMember.Listen.HOME)
        val w = CorePairing.Window(m, root.publicKeyDER, listOf("127.0.0.1"), sign = root::signDigest).closed()
        assertTrue(w.qr.startsWith("cbb://pair?addr=127.0.0.1%3A"), w.qr)
        assertTrue(w.qr.endsWith("fp=${w.fingerprint}"))

        val newKey = SoftwareSigner()
        val j = CorePairing.Joiner(File(top, "new").path, w.qr, "Tablet", "android", newKey.publicKeyDER, newKey::signDigest).closed()
        val atWindow = wait("joining", { it.state }, { it.version }, { it.failure }) { w.next(it, 100) }
        val atJoiner = wait("joining", { it.state }, { it.version }, { it.failure }) { j.next(it, 100) }
        val asked = assertNotNull(atWindow.request)
        assertEquals(asked.code, assertNotNull(atJoiner.shown).code, "both screens show one code")
        assertEquals("Tablet", asked.name)
        assertEquals("Root phone", atJoiner.shown?.name)
        w.answer(true)
        j.answer(true)
        val done = wait("done", { it.state }, { it.version }, { it.failure }) { j.next(it, 100) }
        val admitted = wait("done", { it.state }, { it.version }, { it.failure }) { w.next(it, 100) }
        assertEquals(made.group, done.group, "the new phone is in the group the phone made")
        assertEquals("Tablet", admitted.name)
        // The new phone keeps the set where its member then starts.
        assertTrue(File(top, "new/group.cbor").isFile)
        val g = m.group()
        assertEquals(made.device, g.rootDevice)
        assertEquals(listOf("Root phone", "Tablet"), g.devices.map { it.name }.sorted())
    }

    @Test
    fun aGroupOf06KeepsItsIDsAndNoCertificates() {
        val g = PhoneGroup.of06("0a".repeat(16), "1b".repeat(16), root = false)
        g.admin06 = true
        val f = File(top, "group.json")
        g.save(f)
        val back = assertNotNull(PhoneGroup.load(f))
        assertTrue(back.isV06 && back.isAdmin && !back.isRoot)
        assertEquals("1b".repeat(8), back.tag)
        assertEquals("0a".repeat(16), back.device)
        assertTrue(back.devices.isEmpty(), "the member keeps the set")
    }

    @Test
    fun aJoinerRefusesACodeThatIsNoWindows() {
        val k = SoftwareSigner()
        assertFailsWith<CorePairing.Failure> {
            CorePairing.Joiner(File(top, "x").path, "cbb://join?code=1", "Tablet", "android", k.publicKeyDER, k::signDigest).close()
        }
    }
}
