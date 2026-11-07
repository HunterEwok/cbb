// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import org.conscrypt.Conscrypt
import java.io.Closeable
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.security.Principal
import java.security.PrivateKey
import java.security.Provider
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket
import javax.net.ssl.X509ExtendedKeyManager
import javax.net.ssl.X509ExtendedTrustManager

/**
 * TLS 1.3 with Conscrypt, which has the exporter and ALPN that the protocol
 * needs on every Android version: pairing with a listening device, member
 * connections, and a pairing connection that a TLSListener accepted.
 *
 * Both sides present a certificate, and verifyChain decides on the peer's
 * chain (DER, leaf first, never empty) in place of a CA check: for pairing,
 * against the QR code's fingerprint; for members, against the group's roots.
 */
class TLSTransport private constructor(private val socket: SSLSocket, private val alpn: String) : FrameTransport, Closeable {
    class Failure(message: String, cause: Throwable? = null) : IOException(message, cause)

    private val input = socket.inputStream
    private val output = socket.outputStream
    private val writeLock = Any()

    override var peerChain: List<ByteArray> = emptyList()
        private set

    /** The peer's leaf certificate, DER, once the handshake is done. */
    val peerCertificate: ByteArray? get() = peerChain.firstOrNull()

    /** The peer's port, as an accepted connection names its client: on the loopback address it tells whose connection a relay call is. */
    val remotePort: Int get() = socket.port

    /** Runs the handshake, at most timeoutMS, and checks the ALPN protocol; closes the socket when it fails. */
    private fun handshake(timeoutMS: Int) {
        try {
            socket.soTimeout = timeoutMS
            socket.startHandshake()
            val chosen = Conscrypt.getApplicationProtocol(socket)
            if (chosen != alpn) throw Failure("the peer speaks ${chosen ?: "no protocol"}, not $alpn")
            peerChain = socket.session.peerCertificates.map { it.encoded }
            if (peerChain.isEmpty()) throw Failure("the peer sent no certificate")
            // The member protocol has its own timeouts; pairing waits on a person.
            socket.soTimeout = 0
        } catch (e: Exception) {
            close()
            throw e as? Failure ?: Failure("the TLS handshake failed: ${e.message}", e)
        }
    }

    /** The TLS exporter's output for label with an empty context, as Go's ExportKeyingMaterial(label, nil, length) gives it. */
    fun exportKeyingMaterial(label: String, length: Int): ByteArray =
        Conscrypt.exportKeyingMaterial(socket, label, null, length) ?: throw Failure("no exporter output")

    override fun write(data: ByteArray) {
        synchronized(writeLock) {
            output.write(data)
            output.flush()
        }
    }

    override fun read(n: Int): ByteArray {
        val b = ByteArray(n)
        var off = 0
        while (off < n) {
            val k = input.read(b, off, n - off)
            if (k < 0) throw Failure("connection closed")
            off += k
        }
        return b
    }

    override fun close() {
        try {
            socket.close()
        } catch (e: IOException) {
            // already closed
        }
    }

    companion object {
        /** How long dialling takes at most, and the handshake after it: a peer that drops the packets, or never answers, fails then. */
        const val CONNECT_TIMEOUT_MS = 5_000
        const val HANDSHAKE_TIMEOUT_MS = 10_000

        /**
         * 127.0.0.1, where cbbtun's hub and relay dial the kit's listeners.
         * Android's InetAddress.getLoopbackAddress() is ::1, which takes no
         * connection to 127.0.0.1; the JVM's is 127.0.0.1.
         */
        val LOOPBACK: InetAddress = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))

        /**
         * Dials host:port with TLS 1.3 and the ALPN protocol, presenting
         * chain (DER, leaf first: key's certificate, then the admin CA that
         * issued it, if one did), and runs the handshake.
         */
        fun dial(
            host: String,
            port: Int,
            alpn: String,
            key: PrivateKey,
            chain: List<ByteArray>,
            timeoutMS: Int = HANDSHAKE_TIMEOUT_MS,
            verifyChain: (List<ByteArray>) -> Boolean,
        ): TLSTransport {
            val raw = Socket()
            try {
                raw.connect(InetSocketAddress(host, port), CONNECT_TIMEOUT_MS)
            } catch (e: IOException) {
                raw.close()
                throw Failure("cannot reach $host:$port: ${e.message}", e)
            }
            val ctx = context(key, chain, verifyChain)
            val s = ctx.socketFactory.createSocket(raw, host, port, true) as SSLSocket
            setUp(s, alpn)
            s.useClientMode = true
            return TLSTransport(s, alpn).apply { handshake(timeoutMS) }
        }

        /** The Conscrypt provider, made once; the app does not install it as the system's. */
        val provider: Provider by lazy { Conscrypt.newProvider() }

        internal fun context(key: PrivateKey, chain: List<ByteArray>, verifyChain: (List<ByteArray>) -> Boolean): SSLContext {
            val certs = chain.map(::x509).toTypedArray()
            require(certs.isNotEmpty()) { "no certificate for the key" }
            return SSLContext.getInstance("TLSv1.3", provider).apply {
                init(arrayOf(KeyManager(key, certs)), arrayOf(TrustManager(verifyChain)), null)
            }
        }

        internal fun setUp(s: SSLSocket, alpn: String) {
            s.enabledProtocols = arrayOf("TLSv1.3")
            Conscrypt.setApplicationProtocols(s, arrayOf(alpn))
        }

        internal fun accepted(s: SSLSocket, alpn: String, timeoutMS: Int): TLSTransport = TLSTransport(s, alpn).apply { handshake(timeoutMS) }

        private fun x509(der: ByteArray): X509Certificate =
            CertificateFactory.getInstance("X.509").generateCertificate(der.inputStream()) as X509Certificate
    }

    /** Presents one key with its chain, whatever the peer asks for. */
    private class KeyManager(private val key: PrivateKey, private val chain: Array<X509Certificate>) : X509ExtendedKeyManager() {
        override fun getClientAliases(keyType: String?, issuers: Array<out Principal>?) = arrayOf(ALIAS)
        override fun chooseClientAlias(keyType: Array<out String>?, issuers: Array<out Principal>?, socket: Socket?) = ALIAS
        override fun chooseEngineClientAlias(keyType: Array<out String>?, issuers: Array<out Principal>?, engine: SSLEngine?) = ALIAS
        override fun getServerAliases(keyType: String?, issuers: Array<out Principal>?) = arrayOf(ALIAS)
        override fun chooseServerAlias(keyType: String?, issuers: Array<out Principal>?, socket: Socket?) = ALIAS
        override fun chooseEngineServerAlias(keyType: String?, issuers: Array<out Principal>?, engine: SSLEngine?) = ALIAS
        override fun getCertificateChain(alias: String?) = chain
        override fun getPrivateKey(alias: String?) = key

        companion object {
            const val ALIAS = "cbb"
        }
    }

    /** Lets verifyChain decide on the peer's chain, on both sides. */
    private class TrustManager(private val verifyChain: (List<ByteArray>) -> Boolean) : X509ExtendedTrustManager() {
        private fun check(chain: Array<out X509Certificate>?) {
            if (chain.isNullOrEmpty() || !verifyChain(chain.map { it.encoded })) throw CertificateException("the peer's certificate is not trusted")
        }

        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) = check(chain)
        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) = check(chain)
        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?, socket: Socket?) = check(chain)
        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?, socket: Socket?) = check(chain)
        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?, engine: SSLEngine?) = check(chain)
        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?, engine: SSLEngine?) = check(chain)
        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
    }
}

/**
 * Listens for TLS 1.3 connections, as a phone does while it shows its join
 * QR code (docs/protocol.md, section 6, "The joiner listens") and for a
 * remote invitation's pairing window. It requires a client certificate and
 * lets verifyChain decide on it. It listens on every address, or on address.
 */
class TLSListener(
    port: Int = 0,
    private val alpn: String,
    key: PrivateKey,
    chain: List<ByteArray>,
    address: InetAddress? = null,
    verifyChain: (List<ByteArray>) -> Boolean,
) {
    private val server: SSLServerSocket =
        TLSTransport.context(key, chain, verifyChain).serverSocketFactory.createServerSocket() as SSLServerSocket

    init {
        server.reuseAddress = true
        server.bind(InetSocketAddress(address, port))
    }

    /** The port it listens on. */
    val port: Int get() = server.localPort

    /**
     * Waits for the next connection and runs its handshake; throws when the
     * handshake fails, and once the listener is stopped.
     */
    fun accept(timeoutMS: Int = TLSTransport.HANDSHAKE_TIMEOUT_MS): TLSTransport = acceptLater()(timeoutMS)

    /**
     * Waits for the next connection and returns its handshake, to run on
     * another thread, so that a slow peer holds up no other; throws once the
     * listener is stopped.
     */
    internal fun acceptLater(): (Int) -> TLSTransport {
        val s = server.accept() as SSLSocket
        TLSTransport.setUp(s, alpn)
        s.useClientMode = false
        s.needClientAuth = true
        return { timeoutMS -> TLSTransport.accepted(s, alpn, timeoutMS) }
    }

    fun stop() {
        try {
            server.close()
        } catch (e: IOException) {
            // already closed
        }
    }
}
