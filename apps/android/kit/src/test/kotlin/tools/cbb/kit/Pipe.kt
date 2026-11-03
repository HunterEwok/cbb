// SPDX-License-Identifier: AGPL-3.0-only

package tools.cbb.kit

import java.io.ByteArrayOutputStream
import java.io.IOException

/** One end of an in-memory connection. */
class Pipe private constructor() : FrameTransport {
    private val lock = Object()
    private var buf = ByteArrayOutputStream()
    private var closed = false
    private lateinit var peer: Pipe

    /** What a TLS transport would report as the peer's chain. */
    override var peerChain: List<ByteArray> = emptyList()

    private fun deliver(d: ByteArray) = synchronized(lock) {
        buf.write(d)
        lock.notifyAll()
    }

    override fun write(data: ByteArray) {
        if (synchronized(lock) { closed }) throw IOException("closed")
        peer.deliver(data)
    }

    override fun read(n: Int): ByteArray = synchronized(lock) {
        while (buf.size() < n) {
            if (closed) throw IOException("closed")
            lock.wait()
        }
        val all = buf.toByteArray()
        buf = ByteArrayOutputStream().apply { write(all, n, all.size - n) }
        all.copyOf(n)
    }

    override fun close() {
        for (p in listOf(this, peer)) synchronized(p.lock) {
            p.closed = true
            p.lock.notifyAll()
        }
    }

    companion object {
        fun pair(): Pair<Pipe, Pipe> {
            val a = Pipe()
            val b = Pipe()
            a.peer = b
            b.peer = a
            return a to b
        }
    }
}

/** Runs f on a thread of its own; join returns its result or throws its error. */
class Background<T>(f: () -> T) {
    @Volatile private var result: Result<T>? = null
    private val thread = Thread { result = runCatching(f) }.apply { isDaemon = true; start() }

    fun join(timeoutMS: Long = 10_000): T {
        thread.join(timeoutMS)
        return (result ?: error("timed out")).getOrThrow()
    }
}

/** Waits until cond holds, for at most two seconds. */
fun waitUntil(cond: () -> Boolean) {
    repeat(200) {
        if (cond()) return
        Thread.sleep(10)
    }
    error("timed out")
}
