// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb

import android.util.Log
import tools.cbb.kit.Releases
import java.io.ByteArrayOutputStream
import java.io.File
import java.net.HttpURLConnection
import java.net.URL

/**
 * The revocation list of Android attestations that a root phone checks
 * evidence against (docs/protocol.md, section 17, "Revoked attestations"):
 * keys.json and attest-status.json from the mirror, kept in [dir] and
 * fetched again at most once a day, checked by the core under the roots it
 * pins; [roots] replaces them in tests, and an empty list turns it off.
 */
class AttestStatus(private val dir: File, private val roots: List<Releases.Key>? = null) {
    @Volatile
    var revoked: Set<String> = emptySet()
        private set

    @Volatile
    private var seen = Releases.Seen()

    @Volatile
    private var fetchedAt = 0L

    init {
        if (roots?.isEmpty() != true) load()
    }

    private fun load() {
        val keys = Releases.File.parse(runCatching { File(dir, KEYS).readBytes() }.getOrNull() ?: return) ?: return
        val status = Releases.File.parse(runCatching { File(dir, STATUS).readBytes() }.getOrNull() ?: return) ?: return
        runCatching { Releases.checkStatus(keys, status, roots, System.currentTimeMillis(), Releases.Seen()) }
            .onSuccess { (st, next) ->
                revoked = st.androidRevoked.toSet()
                seen = next
            }
    }

    /** Fetches the mirror's list on a thread of its own, unless that was done in the last day. */
    fun refreshIfDue() {
        val now = System.currentTimeMillis()
        if (roots?.isEmpty() == true || now - fetchedAt < DAY_MS) return
        fetchedAt = now
        Thread({ runCatching { fetch() }.onFailure { Log.w(TAG, "fetching the revocation list: ${it.message}") } }, "attest status").start()
    }

    private fun fetch() {
        val keysData = get(MIRROR + KEYS)
        val statusData = get(MIRROR + STATUS)
        val keys = Releases.File.parse(keysData) ?: error("keys.json is not valid")
        val status = Releases.File.parse(statusData) ?: error("attest-status.json is not valid")
        val (st, next) = Releases.checkStatus(keys, status, roots, System.currentTimeMillis(), seen)
        if (next == seen) return
        dir.mkdirs()
        File(dir, "$KEYS.new").apply { writeBytes(keysData) }.renameTo(File(dir, KEYS))
        File(dir, "$STATUS.new").apply { writeBytes(statusData) }.renameTo(File(dir, STATUS))
        revoked = st.androidRevoked.toSet()
        seen = next
        Log.i(TAG, "took the revocation list of Android attestations, ${st.androidRevoked.size} certificates")
    }

    private fun get(url: String): ByteArray {
        val c = URL(url).openConnection() as HttpURLConnection
        c.connectTimeout = 30_000
        c.readTimeout = 60_000
        try {
            if (c.responseCode != 200) error("$url: ${c.responseCode}")
            val out = ByteArrayOutputStream()
            c.inputStream.use { s ->
                val buf = ByteArray(8192)
                while (true) {
                    val n = s.read(buf)
                    if (n < 0) break
                    out.write(buf, 0, n)
                    if (out.size() > Releases.MAX_FILE) error("$url is too large")
                }
            }
            return out.toByteArray()
        } finally {
            c.disconnect()
        }
    }

    companion object {
        private const val TAG = "AttestStatus"
        private const val MIRROR = "https://cbb.tools/attest/"
        private const val KEYS = "keys.json"
        private const val STATUS = "attest-status.json"
        private const val DAY_MS = 24L * 3600 * 1000
    }
}
