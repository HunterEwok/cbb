// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import java.io.IOException
import java.io.InputStream
import java.io.OutputStream

/**
 * A connection that carries frames: a TLS connection in the app, anything
 * in tests. Its calls block; closing it makes a blocked read or write fail.
 */
interface FrameTransport {
    fun write(data: ByteArray)

    /** Reads exactly n bytes, or throws. */
    fun read(n: Int): ByteArray

    fun close()

    /** The peer's certificate chain from the TLS handshake, DER, leaf first: the leaf, then its admin CA when one issued it. */
    val peerChain: List<ByteArray> get() = emptyList()
}

internal fun FrameTransport.writeFrame(f: Pairing.Frame) = write(Pairing.encode(f))

internal fun FrameTransport.readFrame(): Pairing.Frame {
    val n = Pairing.length(read(4))
    return Pairing.decode(read(n))
}

/** A FrameTransport over a pair of streams, such as a socket's. */
open class StreamTransport(
    private val input: InputStream,
    private val output: OutputStream,
    private val onClose: () -> Unit,
    override val peerChain: List<ByteArray> = emptyList(),
) : FrameTransport {
    private val writeLock = Any()

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
            if (k < 0) throw IOException("connection closed")
            off += k
        }
        return b
    }

    override fun close() {
        try {
            onClose()
        } catch (e: IOException) {
            // closing twice, or a peer that went away
        }
    }
}
