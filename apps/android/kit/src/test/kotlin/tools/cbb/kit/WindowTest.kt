// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import java.io.File
import kotlin.io.path.createTempDirectory
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.test.fail

/** A phone makes a group of 0.6, opens its home window, and a new phone joins by its QR code or six digits, through the Rust core as the apps do. */
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
        assertTrue(w.qr.startsWith("cbb://pair?addr=127.0.0.1:"), w.qr)
        assertTrue(w.qr.endsWith("fp=${w.fingerprint}&i=${w.id}&c=${w.digits}"), w.qr)
        assertTrue(w.digits.length == 6 && w.digits.all { it.isDigit() })

        val newKey = SoftwareSigner()
        val j = CorePairing.Joiner(File(top, "new").path, w.qr, "Tablet", "android", newKey.publicKeyDER, newKey::signDigest).closed()
        val done = wait("done", { it.state }, { it.version }, { it.failure }) { j.next(it, 100) }
        val admitted = wait("done", { it.state }, { it.version }, { it.failure }) { w.next(it, 100) }
        assertEquals(made.group, done.group, "the new phone is in the group the phone made")
        assertEquals("Root phone", done.name, "the member that let it in")
        assertEquals("Tablet", admitted.name)
        // The new phone keeps the set where its member then starts.
        assertTrue(File(top, "new/group.cbor").isFile)
        val g = m.group()
        assertEquals(made.device, g.rootDevice)
        assertEquals(listOf("Root phone", "Tablet"), g.devices.map { it.name }.sorted())
    }

    /** A phone's group of 0.6 with its member running and the port open. */
    private class Root(val made: CorePairing.Made, val member: CoreMember, val root: SoftwareSigner)

    private fun root(): Root {
        val root = SoftwareSigner()
        val key = SoftwareSigner()
        val dir = File(top, "root")
        val made = CorePairing.newGroup06(dir, "Root phone", "android", Records.HARDWARE, root.publicKeyDER, key.publicKeyDER, root::signDigest)
        val m = CoreMember.start(
            CoreMember.Start(dir, "Root phone", "android", device = made.device, publicKey = key.publicKeyDER, seal = CoreGroup.SEAL,
                cert = ByteArray(0), groupCA = ByteArray(0)),
            key::signDigest,
            events = { },
        ).closed()
        return Root(made, m, root)
    }

    private fun Root.window(): CorePairing.Window =
        CorePairing.Window(member, root.publicKeyDER, listOf("127.0.0.1"), sign = root::signDigest).closed()

    private fun joiner(name: String, qr: String): CorePairing.Joiner {
        val k = SoftwareSigner()
        return CorePairing.Joiner(File(top, name).path, qr, name, "android", k.publicKeyDER, k::signDigest).closed()
    }

    /** The first state named one of want past the start, failed included. */
    private fun <S> until(want: Set<String>, state: (S) -> String, version: (S) -> Long, next: (Long) -> S): S {
        var v = 0L
        repeat(200) {
            val s = next(v)
            if (state(s) in want) return s
            v = version(s)
        }
        fail("none of $want")
    }

    @Test
    fun aWindowNeedsTheMemberPortOpen() {
        val r = root()
        assertFailsWith<CorePairing.Failure> { r.window() }
    }

    @Test
    fun aWrongCodeJoinsNoOneAndWritesNothingAndThreeCloseTheWindow() {
        val r = root()
        r.member.listen(CoreMember.Listen.HOME)
        val w = r.window()
        val wrong = w.qr.replace("c=${w.digits}", "c=" + if (w.digits == "000000") "000001" else "000000")
        var v = 0L
        for (n in 1..3) {
            val j = joiner("Wrong$n", wrong)
            val st = until(setOf("done", "failed"), { it.state }, { it.version }) { j.next(it, 100) }
            assertEquals("failed", st.state)
            assertTrue(st.failure?.message?.contains("not the window's") == true, "${st.failure}")
            assertFalse(File(top, "Wrong$n/group.cbor").exists(), "the refused phone keeps no group")
            assertEquals(listOf("Root phone"), r.member.group().devices.map { it.name }, "nothing reached the records")
            // The window stays open for the next attempt, and closes after the third.
            val want = if (n < 3) "failed" else "closed"
            val ws = run {
                repeat(200) {
                    val s = w.next(v, 100)
                    v = s.version
                    if (s.state == want) return@run s
                }
                fail("no state $want")
            }
            assertEquals(want, ws.state)
        }
        // Closed, the window takes not even the right digits.
        val late = joiner("Late", w.qr)
        assertEquals("failed", until(setOf("done", "failed"), { it.state }, { it.version }) { late.next(it, 100) }.state)
        assertEquals(listOf("Root phone"), r.member.group().devices.map { it.name })
    }

    @Test
    fun aWindowLetsOneDeviceJoinAndThenCloses() {
        val r = root()
        r.member.listen(CoreMember.Listen.HOME)
        val w = r.window()
        val first = joiner("Tablet", w.qr)
        assertEquals("done", until(setOf("done", "failed"), { it.state }, { it.version }) { first.next(it, 100) }.state)
        val second = joiner("Laptop", w.qr)
        assertEquals("failed", until(setOf("done", "failed"), { it.state }, { it.version }) { second.next(it, 100) }.state)
        assertEquals(listOf("Root phone", "Tablet"), r.member.group().devices.map { it.name }.sorted())
    }

    @Test
    fun aJoinerTakesSixDigits() {
        val k = SoftwareSigner()
        for (d in listOf("", "12345", "1234567", "12a456")) {
            assertFailsWith<CorePairing.Failure>(d) {
                CorePairing.Joiner(File(top, "x").path, "", "Tablet", "android", k.publicKeyDER, k::signDigest, digits = d).close()
            }
        }
    }

    @Test
    fun aWindowFoundByMdnsMakesTheCodeTheCoreReads() {
        val t = Discovery.windowLink("[fd00::20]:8764", "ab".repeat(32), "11".repeat(16), "123456")
        assertEquals("cbb://pair?addr=[fd00::20]:8764&fp=${"ab".repeat(32)}&i=${"11".repeat(16)}&c=123456", t)
        val f = assertNotNull(Discovery.member("0a".repeat(16), listOf("v=1", "g=x", "p=1", "f=${"ab".repeat(32)}", "i=${"11".repeat(16)}")))
        assertTrue(f.pairing)
        assertEquals("11".repeat(16), f.windowID)
        assertEquals("ab".repeat(32), f.fingerprint)
    }

    @Test
    fun aClosedWindowLetsNoOneJoin() {
        val r = root()
        r.member.listen(CoreMember.Listen.HOME)
        val w = r.window()
        val qr = w.qr
        w.close()
        val j = runCatching { joiner("Tablet", qr) }.getOrNull()
        if (j != null) {
            assertEquals("failed", until(setOf("done", "failed"), { it.state }, { it.version }) { j.next(it, 100) }.state)
        }
        assertFalse(File(top, "Tablet/group.cbor").exists())
        assertEquals(listOf("Root phone"), r.member.group().devices.map { it.name })
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
