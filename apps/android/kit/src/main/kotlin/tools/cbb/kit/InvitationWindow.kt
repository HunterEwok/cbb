// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import java.security.PrivateKey
import java.time.Instant

/**
 * The pairing window of a remote invitation on the phone that is the
 * group's hub (docs/protocol.md, section 12): it listens on the loopback
 * address, where the phone's hub joins the connections of the invitation's
 * guest tunnel, and runs each attempt with admit, one at a time. It admits
 * one device once, until expires, and ends after three failed attempts;
 * onEnd gets the admitted device, or why it ended without one. Another app
 * on the phone can reach the loopback port too: a connection that fromGuest
 * says the hub did not make for the invitation's guest is closed after the
 * TLS handshake, before any pairing message, and neither counts nor keeps
 * the window busy.
 */
class InvitationWindow(
    key: PrivateKey,
    memberCert: ByteArray,
    private val expires: Instant,
    /** Whether the connection from this loopback port came through the invitation's guest tunnel (RustTunnel.Guest.dialed). */
    private val fromGuest: (Int) -> Boolean,
    /** Runs the exchange (PhoneGroup.admit with the invitation): the connection, the joiner's certificate, the session ID. */
    private val admit: (TLSTransport, ByteArray, ByteArray) -> PairingMember.Admitted,
    private val onEnd: (Result<PairingMember.Admitted>) -> Unit,
    /** Gets why an attempt failed, for the log. */
    private val onError: (Exception) -> Unit = {},
) {
    /** Why the window ended without a device. */
    class Ended(message: String, val code: Pairing.ErrorCode) : Exception(message)

    /** A connection the hub did not make for the guest, closed before any pairing message. */
    class NotFromGuest : Exception("a connection to the invitation's window did not come through its guest tunnel")

    private val listener = TLSListener(0, Pairing.ALPN, key, listOf(memberCert), TLSTransport.LOOPBACK) { it.isNotEmpty() }
    private val expiry = Thread({
        val wait = expires.toEpochMilli() - System.currentTimeMillis()
        try {
            if (wait > 0) Thread.sleep(wait)
            end(Result.failure(Ended("the invitation expired", Pairing.ErrorCode.EXPIRED)))
        } catch (e: InterruptedException) {
            // the window ended
        }
    }, "cbb-invitation-expiry").apply { isDaemon = true }
    private val lock = Any()
    private var busy = false
    private var failures = 0
    private var ended = false
    private var current: TLSTransport? = null

    /** The port it listens on: RustTunnel.Hub.invite takes it. */
    val port: Int get() = listener.port

    init {
        Thread(::run, "cbb-invitation").apply { isDaemon = true; start() }
        expiry.start()
    }

    private fun run() {
        while (true) {
            val handshake = try {
                listener.acceptLater()
            } catch (e: Exception) {
                return // closed
            }
            Thread({ attempt(handshake) }, "cbb-invitation-attempt").apply { isDaemon = true; start() }
        }
    }

    private fun attempt(handshake: (Int) -> TLSTransport) {
        val t = try {
            handshake(TLSTransport.HANDSHAKE_TIMEOUT_MS)
        } catch (e: Exception) {
            onError(e)
            return
        }
        if (!fromGuest(t.remotePort)) {
            onError(NotFromGuest())
            t.close()
            return
        }
        val joiner = t.peerCertificate
        val free = synchronized(lock) {
            if (ended || busy || joiner == null) {
                false
            } else {
                busy = true
                current = t
                true
            }
        }
        if (!free) {
            // Read the device's first message before answering, as a computer's window does.
            runCatching {
                t.readFrame()
                t.writeFrame(Pairing.Frame(error = Pairing.ErrorCode.BUSY.wire))
            }
            t.close()
            return
        }
        try {
            val admitted = admit(t, joiner!!, t.exportKeyingMaterial(Pairing.EXPORTER_LABEL, 32))
            end(Result.success(admitted))
        } catch (e: Exception) {
            onError(e)
            val tooMany = synchronized(lock) {
                busy = false
                current = null
                ++failures >= MAX_FAILURES
            }
            if (tooMany) end(Result.failure(Ended("three attempts failed", Pairing.ErrorCode.TOO_MANY)))
        } finally {
            t.close()
        }
    }

    private fun end(result: Result<PairingMember.Admitted>) {
        val t = synchronized(lock) {
            if (ended) return
            ended = true
            current.also { current = null }
        }
        listener.stop()
        if (Thread.currentThread() !== expiry) expiry.interrupt()
        // An attempt still waiting for the admin ends with the window, unless it admitted the device.
        if (result.isFailure) t?.close()
        onEnd(result)
    }

    /** Closes the window, as the admin cancelling the invitation. */
    fun close() = end(Result.failure(Ended("the invitation was cancelled", Pairing.ErrorCode.CLOSED)))

    companion object {
        /** Failed attempts after which the window ends (docs/protocol.md, section 12). */
        const val MAX_FAILURES = 3
    }
}
