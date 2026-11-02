// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package io.github.hunterewok.clipboardbridge.kit

import java.net.InetAddress
import java.security.PrivateKey
import java.time.Instant

/**
 * Takes member connections for a node: the phone's member port while it is
 * the group's hub (docs/design.md, "The phone as the hub"), on the loopback
 * address, where cbbtun's Hub joins each connection through the tunnel. It
 * accepts a peer whose chain (leaf first) is a member's of the group's
 * roots, which trusted gives for each handshake, and serves each connection
 * on a thread of its own, naming the peer by its device ID. For a blind
 * relay's calls, caller names the device each connection must be by its
 * source port; a connection it does not know, or whose certificate names
 * another device, is closed.
 */
class MemberListener(
    private val node: MemberNode,
    key: PrivateKey,
    chain: List<ByteArray>,
    private val trusted: () -> List<ByteArray>,
    port: Int = 0,
    address: InetAddress? = InetAddress.getLoopbackAddress(),
    /** Gets why a connection failed, for the log. */
    private val onError: (Exception) -> Unit = {},
    /** For a relay's calls: the device each connection is by its source port, once (RelayOnPhone.caller). */
    private val caller: ((Int) -> String?)? = null,
) {
    private val listener = TLSListener(port, Member.ALPN, key, chain, address) { peerID(it) != null }

    @Volatile private var stopped = false

    /** The port it listens on: cbbtun's StartHub takes it. */
    val port: Int get() = listener.port

    init {
        Thread(::run, "cbb-member-listener").apply { isDaemon = true; start() }
    }

    private fun peerID(chain: List<ByteArray>): Result<String> =
        runCatching { GroupCertificates.verifyMember(chain, trusted(), Instant.now()) }

    private fun run() {
        while (!stopped) {
            val handshake = try {
                listener.acceptLater()
            } catch (e: Exception) {
                if (!stopped) onError(e) // the listener broke
                return
            }
            Thread({
                try {
                    val t = handshake(TLSTransport.HANDSHAKE_TIMEOUT_MS)
                    val checked = peerID(t.peerChain)
                    val id = checked.getOrNull()
                    when {
                        id == null -> {
                            t.close()
                            onError(NotAMember(checked.exceptionOrNull()))
                        }
                        // The relay said who calls; the certificate must say the same.
                        caller != null && caller.invoke(t.remotePort) != id -> {
                            t.close()
                            onError(NotTheCaller(id))
                        }
                        else -> node.serve(t, id)
                    }
                } catch (e: Exception) {
                    onError(e)
                }
            }, "cbb-member").apply { isDaemon = true; start() }
        }
    }

    /** A caller whose certificate chain is no member's of the group; cause says why. */
    class NotAMember(cause: Throwable?) : Exception("the caller is no member of the group: ${cause?.message ?: "no certificate"}", cause)

    /** A relay call whose certificate names another device than the relay said, or one the relay did not announce. */
    class NotTheCaller(device: String) : Exception("the relay did not announce a call from $device on this connection")

    /** Stops listening; the connections it took go on until the node closes them. */
    fun stop() {
        stopped = true
        listener.stop()
    }
}
