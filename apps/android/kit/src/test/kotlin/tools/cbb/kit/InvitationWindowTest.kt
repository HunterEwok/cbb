// SPDX-License-Identifier: AGPL-3.0-only

package tools.cbb.kit

import java.time.Instant
import java.util.concurrent.CountDownLatch
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** The pairing window of a remote invitation on a phone hub: one device once, until it expires, three failed attempts at most. */
class InvitationWindowTest {
    private val hubKey = SoftwareSigner()
    private val hubCert = GroupCertificates.selfSigned(SyncEngine.newID(), hubKey)
    private val joinerKey = SoftwareSigner()
    private val joinerCert = GroupCertificates.selfSigned(SyncEngine.newID(), joinerKey)

    private fun dial(port: Int): TLSTransport =
        TLSTransport.dial("127.0.0.1", port, Pairing.ALPN, joinerKey.keyPair.private, listOf(joinerCert)) { true }

    private fun admitted(cert: ByteArray) = PairingMember.Admitted(SyncEngine.newID(), Pairing.Info("deck", "linux"), cert, confirmed = true)

    private fun ended(q: LinkedBlockingQueue<Result<PairingMember.Admitted>>): Result<PairingMember.Admitted> =
        assertNotNull(q.poll(10, TimeUnit.SECONDS), "the window did not end")

    private fun code(r: Result<PairingMember.Admitted>): Pairing.ErrorCode =
        (r.exceptionOrNull() as? InvitationWindow.Ended ?: throw AssertionError("ended with $r")).code

    @Test
    fun admitsOneDevice() {
        val ends = LinkedBlockingQueue<Result<PairingMember.Admitted>>()
        val window = InvitationWindow(
            hubKey.keyPair.private, hubCert, Instant.now().plusSeconds(60),
            admit = { t, cert, sid ->
                assertEquals(32, sid.size)
                t.readFrame()
                t.writeFrame(Pairing.Frame(ok = true))
                admitted(cert)
            },
            onEnd = { ends.add(it) },
        )
        dial(window.port).use { t ->
            t.writeFrame(Pairing.Frame(msg = ByteArray(1)))
            assertEquals(true, t.readFrame().ok)
        }
        val r = ended(ends)
        assertContentEquals(joinerCert, r.getOrThrow().cert, "the window hands over the joiner's certificate")
        // It admitted its device: the window is closed, and a close changes nothing.
        window.close()
        assertTrue(ends.isEmpty())
    }

    @Test
    fun endsAfterThreeFailedAttempts() {
        val ends = LinkedBlockingQueue<Result<PairingMember.Admitted>>()
        val errors = LinkedBlockingQueue<Exception>()
        val window = InvitationWindow(
            hubKey.keyPair.private, hubCert, Instant.now().plusSeconds(60),
            admit = { t, _, _ ->
                t.readFrame()
                throw PairingMember.Failure("a wrong code")
            },
            onEnd = { ends.add(it) },
            onError = { errors.add(it) },
        )
        repeat(InvitationWindow.MAX_FAILURES) {
            dial(window.port).use { t ->
                t.writeFrame(Pairing.Frame(msg = ByteArray(1)))
                runCatching { t.readFrame() }
            }
            assertNotNull(errors.poll(10, TimeUnit.SECONDS), "attempt ${it + 1} did not fail")
        }
        assertEquals(Pairing.ErrorCode.TOO_MANY, code(ended(ends)))
    }

    @Test
    fun answersBusyWhileAnAttemptRuns() {
        val ends = LinkedBlockingQueue<Result<PairingMember.Admitted>>()
        val inside = CountDownLatch(1)
        val window = InvitationWindow(
            hubKey.keyPair.private, hubCert, Instant.now().plusSeconds(60),
            admit = { t, cert, _ ->
                inside.countDown()
                t.readFrame() // until the first device ends
                admitted(cert)
            },
            onEnd = { ends.add(it) },
        )
        try {
            val first = dial(window.port)
            first.writeFrame(Pairing.Frame(msg = ByteArray(1)))
            assertTrue(inside.await(10, TimeUnit.SECONDS))
            dial(window.port).use { t ->
                t.writeFrame(Pairing.Frame(msg = ByteArray(1)))
                assertEquals(Pairing.ErrorCode.BUSY.wire, t.readFrame().error)
            }
            first.close()
        } finally {
            window.close()
        }
        ended(ends)
    }

    @Test
    fun endsWhenItExpiresOrIsCancelled() {
        val expired = LinkedBlockingQueue<Result<PairingMember.Admitted>>()
        InvitationWindow(hubKey.keyPair.private, hubCert, Instant.now().plusMillis(100), admit = { _, cert, _ -> admitted(cert) }, onEnd = { expired.add(it) })
        assertEquals(Pairing.ErrorCode.EXPIRED, code(ended(expired)))

        val cancelled = LinkedBlockingQueue<Result<PairingMember.Admitted>>()
        val window = InvitationWindow(hubKey.keyPair.private, hubCert, Instant.now().plusSeconds(60), admit = { _, cert, _ -> admitted(cert) }, onEnd = { cancelled.add(it) })
        window.close()
        assertEquals(Pairing.ErrorCode.CLOSED, code(ended(cancelled)))
        window.close()
        assertTrue(cancelled.isEmpty(), "a window ends once")
    }
}
