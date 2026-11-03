// SPDX-License-Identifier: AGPL-3.0-only

package tools.cbb.kit

import java.security.SecureRandom
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * A phone dials a computer's pairing window (docs/protocol.md, section 6,
 * "A phone joins a computer's group"): this phone confirms the code first,
 * so every failure after that spends it. The whole exchange with a real
 * window runs in Go's TestSwiftJoinsComputerRoot.
 */
class ComputerJoinTest {
    private val sid = ByteArray(32).also { SecureRandom().nextBytes(it) }
    private val phone = PhoneGroupTest.Listener()
    private val computer = PhoneGroupTest.Listener()
    private val info = Pairing.Info("Phone", "android", SoftwareSigner().publicKeyDER)

    /**
     * Plays the computer's window with the code it shows: it answers the
     * phone's key without a tag, reads the phone's confirmation and hands
     * it to last, which writes the final frame.
     */
    private fun join(code: String, last: (CPace, ByteArray, Pipe) -> Unit): PairingJoiner.Failure {
        val (m, j) = Pipe.pair()
        val window = Background {
            val first = m.readFrame()
            val adb = Pairing.MemberAD(computer.device, "a group").encode()
            val st = CPace(CPace.Role.RESPONDER, code.toByteArray(), Pairing.channelID(computer.cert, phone.cert), sid, adb)
            st.finish(first.msg!!, first.ad!!)
            m.writeFrame(Pairing.Frame(msg = st.message, ad = adb))
            last(st, m.readFrame().tag!!, m)
        }
        val e = assertFailsWith<PairingJoiner.Failure> {
            PairingJoiner.join(j, "123456", info, computer.cert, phone.cert, sid, Instant.now()) { error("stored") }
        }
        j.close()
        window.join()
        return e
    }

    @Test
    fun wrongCodeIsSpent() {
        val e = join("654321") { st, ta, m ->
            assertTrue(runCatching { st.verify(ta) }.isFailure, "the computer took a wrong code")
            m.writeFrame(Pairing.Frame(error = Pairing.ErrorCode.WRONG_CODE.wire))
        }
        assertEquals(Pairing.ErrorCode.WRONG_CODE, e.code)
        assertTrue(e.spent, "a wrong code, once confirmed, is spent")
    }

    @Test
    fun computerMustProveTheCode() {
        // A window that does not know the code sends its own tag anyway.
        val e = join("654321") { st, _, m -> m.writeFrame(Pairing.Frame(tag = st.confirmationTag)) }
        assertTrue(e.spent && e.code == null, "${e.message}")
        // And one without any tag.
        val f = join("123456") { _, _, m -> m.writeFrame(Pairing.Frame(ok = true)) }
        assertTrue(f.spent, "${f.message}")
    }
}
