// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package io.github.hunterewok.clipboardbridge

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import io.github.hunterewok.clipboardbridge.kit.FrameTransport
import io.github.hunterewok.clipboardbridge.kit.Member
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.io.IOException
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * What sync away from home keeps on this phone (docs/protocol.md, section
 * 11): its WireGuard private key, made on the phone, the preshared key it
 * chose for its tunnels, which its hellos offer every hub, and the last
 * offer of each of the group's hubs, by the hub's device ID.
 */
class AwayState(val key: ByteArray, val psk: ByteArray = newPSK(), val hubs: List<Pair<String, Member.TunnelOffer>> = emptyList()) {
    /** The offer of the hub hub, or null. */
    fun offer(hub: String): Member.TunnelOffer? = hubs.firstOrNull { it.first == hub }?.second

    /** The same with offer as hub's, in place of its earlier one. */
    fun withOffer(hub: String, offer: Member.TunnelOffer): AwayState {
        val i = hubs.indexOfFirst { it.first == hub }
        val next = if (i >= 0) hubs.toMutableList().also { it[i] = hub to offer } else (hubs + (hub to offer)).takeLast(MAX_HUBS)
        return AwayState(key, psk, next)
    }

    /** The same without the offer of hub. */
    fun without(hub: String): AwayState = AwayState(key, psk, hubs.filterNot { it.first == hub })

    fun encode(): ByteArray {
        val out = ByteArrayOutputStream()
        DataOutputStream(out).run {
            writeByte(VERSION)
            write(key)
            write(psk)
            writeByte(hubs.size)
            for ((hub, o) in hubs) {
                writeUTF(hub)
                write(o.hubKey)
                write(o.psk)
                writeByte(o.endpoints.size)
                o.endpoints.forEach { writeUTF(it) }
                writeUTF(o.obfuscation ?: "")
                writeUTF(o.vless ?: "")
                writeByte(if (o.nextKey != null) 1 else 0)
                o.nextKey?.let { write(it) }
            }
        }
        return out.toByteArray()
    }

    companion object {
        private const val VERSION = 5

        /** The most hubs whose offers the phone keeps, as a byte counts them. */
        const val MAX_HUBS = 255

        private val random = SecureRandom()

        fun newPSK(): ByteArray = ByteArray(32).also { random.nextBytes(it) }

        /**
         * The state in b, or null when it is not one this version wrote.
         * Versions 1 to 3 kept one hub's offer and no preshared key of the
         * phone's own: it gets one now.
         */
        fun decode(b: ByteArray): AwayState? = try {
            DataInputStream(ByteArrayInputStream(b)).run {
                val version = readByte().toInt()
                if (version !in 1..VERSION) return null
                val key = ByteArray(32).also { readFully(it) }
                fun offer(): Pair<String, Member.TunnelOffer>? {
                    val hub = readUTF()
                    val hubKey = ByteArray(32).also { readFully(it) }
                    val psk = ByteArray(32).also { readFully(it) }
                    val endpoints = List(readUnsignedByte()) { readUTF() }
                    // Version 1 had no obfuscation settings.
                    val obfuscation = if (version == 1) "" else readUTF()
                    // Nor had version 2 the way over VLESS.
                    val vless = if (version <= 2) "" else readUTF()
                    // Nor had version 4 the hub's next key.
                    val next = if (version >= 5 && readBoolean()) ByteArray(32).also { readFully(it) } else null
                    val o = Member.TunnelOffer(
                        hubKey, psk, endpoints, obfuscation.takeIf { it.isNotEmpty() }, vless.takeIf { it.isNotEmpty() }, nextKey = next,
                    )
                    return if (o.isValid) hub to o else null
                }
                if (version < 4) {
                    if (!readBoolean()) return AwayState(key)
                    return AwayState(key, hubs = listOf(offer() ?: return null))
                }
                val psk = ByteArray(32).also { readFully(it) }
                val hubs = List(readUnsignedByte()) { offer() ?: return null }
                if (read() != -1) return null
                AwayState(key, psk, hubs)
            }
        } catch (e: IOException) {
            null
        }
    }
}

/** A running tunnel to the hub: a loopback port that leads to the hub's member port. */
interface OpenTunnel {
    val port: Int
    fun setEndpoint(endpoint: String)
    fun close()
}

/** Makes keys and tunnels; the app's comes from mobile/cbbtun, the tests' from a fake. */
interface Tunnels {
    fun newKey(): ByteArray
    fun publicKey(private: ByteArray): ByteArray
    /**
     * Starts a tunnel; obfuscation is the offer's settings as JSON, "" for plain WireGuard, and vless its
     * way over VLESS as JSON, "" without it.
     */
    fun start(
        private: ByteArray, psk: ByteArray, hubKey: ByteArray, device: String, hub: String, endpoint: String,
        obfuscation: String, vless: String,
    ): OpenTunnel
}

/** The tunnel of mobile/cbbtun, WireGuard in the app's process. */
object GoTunnels : Tunnels {
    override fun newKey(): ByteArray = cbbtun.Cbbtun.newKey()
    override fun publicKey(private: ByteArray): ByteArray = cbbtun.Cbbtun.publicKey(private)
    override fun start(
        private: ByteArray, psk: ByteArray, hubKey: ByteArray, device: String, hub: String, endpoint: String,
        obfuscation: String, vless: String,
    ): OpenTunnel {
        val t = cbbtun.Cbbtun.start(private, psk, hubKey, device, hub, endpoint, obfuscation, vless)
        return object : OpenTunnel {
            override val port: Int = t.port().toInt()
            override fun setEndpoint(endpoint: String) = t.setEndpoint(endpoint)
            override fun close() {
                t.close()
            }
        }
    }
}

/**
 * A small file encrypted with an AES key in the Keystore, under alias,
 * that never leaves it and needs no unlock, so the phone syncs in the
 * background as at home.
 */
class SealedFile(private val file: File, private val alias: String) {
    /** The file's contents, or null when there is none. */
    fun read(): ByteArray? {
        if (!file.exists()) return null
        val b = file.readBytes()
        if (b.size < IV) return null
        val c = Cipher.getInstance(CIPHER)
        c.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, b, 0, IV))
        return c.doFinal(b, IV, b.size - IV)
    }

    fun write(data: ByteArray) {
        val c = Cipher.getInstance(CIPHER)
        c.init(Cipher.ENCRYPT_MODE, key())
        val tmp = File(file.path + ".tmp")
        // The phone's first secret may come before its group's folder exists.
        file.parentFile?.mkdirs()
        tmp.writeBytes(c.iv + c.doFinal(data))
        if (!tmp.renameTo(file)) throw IOException("cannot replace $file")
    }

    /** Deletes the file and its key. */
    fun delete() {
        file.delete()
        val ks = KeyStore.getInstance(PROVIDER).apply { load(null) }
        if (ks.containsAlias(alias)) ks.deleteEntry(alias)
    }

    private fun key(): SecretKey {
        val ks = KeyStore.getInstance(PROVIDER).apply { load(null) }
        (ks.getKey(alias, null) as? SecretKey)?.let { return it }
        val g = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER)
        g.init(
            KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build(),
        )
        return g.generateKey()
    }

    companion object {
        private const val PROVIDER = "AndroidKeyStore"
        private const val CIPHER = "AES/GCM/NoPadding"
        private const val IV = 12
    }
}

/** The state of sync away from home in its sealed file. */
class AwayFile(file: File) {
    private val sealed = SealedFile(file, "clipboardbridge.away")

    fun read(): AwayState? = sealed.read()?.let(AwayState::decode)

    fun write(s: AwayState) = sealed.write(s.encode())

    fun delete() = sealed.delete()
}

/**
 * Sync away from home on this phone: off until the user turns it on. Then
 * the hellos offer the phone's WireGuard key and its preshared key, every
 * hub's answer is kept, and while no hub is on the home network the phone
 * reaches the first hub in the group's order that answers through the
 * tunnel, in the app's own process, with the same member TLS as at home
 * (docs/design.md, "Sync away from home"; docs/protocol.md, section 11,
 * "Several hubs"). On a hub below the first it tries the ones above again
 * every [upCheckMS]. It fails closed: without a tunnel there is no
 * connection.
 */
class AwayFromHome(
    private val device: String,
    private val tunnels: Tunnels,
    private val load: () -> AwayState?,
    private val save: (AwayState?) -> Unit,
    /** Whether the hub is found on the home network, where it is dialed directly. */
    private val atHome: (String) -> Boolean,
    /** Dials the hub's member TLS through the loopback port, checking that the peer is the hub. */
    private val dial: (port: Int, hub: String) -> FrameTransport,
    /** Runs a connection to the hub until it ends. */
    private val serve: (FrameTransport, String) -> Unit,
    /** Whether a device may be a hub: the group's root or an admin (Records.mayHost). */
    private val mayHost: (String) -> Boolean,
    /** The group's hubs, highest first (RecordSet.hubOrder); only these are tried. */
    private val order: () -> List<String>,
    private val log: (String, Throwable?) -> Unit = { _, _ -> },
    private val firstWaitMS: Long = 1_000,
    private val maxWaitMS: Long = 30_000,
    /**
     * Whether a hub is a phone, there only while its app is open (docs/design.md, "The phone as the hub"): it is
     * tried at least every [phoneWaitMS].
     */
    private val isPhone: (String) -> Boolean = { false },
    private val phoneWaitMS: Long = 5_000,
    private val homeCheckMS: Long = 5_000,
    /** How long the phone stays on a hub below the first that has an offer before it tries the ones above again. */
    private val upCheckMS: Long = 5 * 60_000,
) {
    /** What the screens show. */
    enum class Status { OFF, WAITING_FOR_HUB, AT_HOME, CONNECTING, CONNECTED }

    private val lock = Object()
    private var state: AwayState? = runCatching { load() }.onFailure { log("cannot read the tunnel's state", it) }.getOrNull()
    private var tunnel: OpenTunnel? = null

    /** The hub and offer the open tunnel goes to. */
    private var tunnelTo: Pair<String, Member.TunnelOffer>? = null

    /** The hub the phone reaches now, through the tunnel or at home. */
    private var using: String? = null

    /** Which of each hub's endpoints the next try takes. */
    private val endpointOf = mutableMapOf<String, Int>()
    private var thread: Thread? = null
    private var stopped = false

    @Volatile var status: Status = Status.OFF
        private set

    @Volatile var lastError: Throwable? = null
        private set

    val isOn: Boolean get() = synchronized(lock) { state != null }

    /** The hub the phone reaches now, or else the first in the group's order whose offer it keeps; null without one. */
    val hub: String?
        get() {
            val o = order()
            return synchronized(lock) { using ?: state?.let { hubsToTry(o, it) }?.firstOrNull()?.first ?: state?.hubs?.firstOrNull()?.first }
        }

    /** The public key the hellos offer the hubs; null while it is off. */
    val publicKey: ByteArray?
        get() = synchronized(lock) { state?.key }?.let { runCatching { tunnels.publicKey(it) }.getOrNull() }

    /** The public key and the preshared key the hellos offer the hubs; null while it is off. */
    val keys: Pair<ByteArray, ByteArray>?
        get() {
            val s = synchronized(lock) { state } ?: return null
            return runCatching { tunnels.publicKey(s.key) }.getOrNull()?.let { it to s.psk }
        }

    /** Turns it on with new keys; the hubs' offers come at home, on the next connection to them. */
    fun turnOn() {
        val s = AwayState(tunnels.newKey())
        save(s)
        synchronized(lock) {
            state = s
            lock.notifyAll()
        }
    }

    /** Turns it off: forgets the keys and the offers and closes the tunnel. */
    fun turnOff() {
        save(null)
        synchronized(lock) {
            state = null
            closeTunnelLocked()
            lock.notifyAll()
        }
    }

    /**
     * Keeps the offer a peer sent for this phone's key (docs/protocol.md,
     * section 11, "Several hubs"): from a hub, the group's root or an
     * admin, its own or another hub's that it passes on, for each hub in
     * place of its earlier one. An offer marked moved makes the phone
     * forget the sender's own. A new offer for the hub in use, or one for a
     * hub above it, starts the tunnel again.
     */
    fun keep(from: String?, received: Member.TunnelOffer) {
        if (from == null || !received.isValid || !mayHost(from)) return
        val hub = received.hub ?: from
        if (hub == device || !mayHost(hub)) return
        val offer = received.with(received.psk, null)
        val o = order()
        val next = synchronized(lock) {
            val s = state ?: return
            val forgot = received.moved && from != hub && s.offer(from) != null
            var n = if (forgot) s.without(from) else s
            if (n.offer(hub) != offer) n = n.withOffer(hub, offer)
            if (n === s) return
            state = n
            val u = using
            if (u == null || u == hub || rank(o, hub) < rank(o, u) || forgot && u == from) {
                // The hub in use changed, or one above it came: try again.
                closeTunnelLocked()
                lock.notifyAll()
            }
            n
        }
        runCatching { save(next) }.onFailure { log("cannot keep the hub's offer", it) }
    }

    /** Starts the loop that reaches a hub through the tunnel while the hubs are away. */
    fun start() = synchronized(lock) {
        if (thread != null) return
        stopped = false
        thread = Thread(::run, "cbb global").apply {
            isDaemon = true
            start()
        }
    }

    fun stop() {
        val t = synchronized(lock) {
            stopped = true
            closeTunnelLocked()
            lock.notifyAll()
            thread.also { thread = null }
        }
        t?.interrupt()
    }

    private fun closeTunnelLocked() {
        val t = tunnel ?: return
        tunnel = null
        tunnelTo = null
        runCatching { t.close() }
    }

    private fun run() {
        var wait = firstWaitMS
        try {
            while (true) {
                val s = synchronized(lock) {
                    if (stopped) return
                    state
                }
                if (s == null) {
                    status = Status.OFF
                    synchronized(lock) { using = null }
                    idle(0)
                    continue
                }
                val hubs = hubsToTry(order(), s)
                if (hubs.isEmpty()) {
                    status = Status.WAITING_FOR_HUB
                    synchronized(lock) {
                        using = null
                        closeTunnelLocked()
                    }
                    idle(0)
                    continue
                }
                val home = hubs.firstOrNull { atHome(it.first) }
                if (home != null) {
                    // At home with a hub: the phone dials the members directly.
                    status = Status.AT_HOME
                    synchronized(lock) {
                        using = home.first
                        closeTunnelLocked()
                    }
                    wait = firstWaitMS
                    idle(homeCheckMS)
                    continue
                }
                var served: Long? = null
                for (h in hubs) {
                    served = tryHub(s, h.first, h.second, up = h.first != hubs[0].first)
                    if (served != null) break
                    if (synchronized(lock) { stopped || state !== s }) break
                }
                if (synchronized(lock) { stopped }) return
                if (served != null) {
                    // A connection that lasted starts the waits again; one that ended at once waits as a failure.
                    if (served > maxWaitMS) wait = firstWaitMS else wait = backoff(wait, hubs[0].first)
                    continue
                }
                synchronized(lock) { using = null }
                if (synchronized(lock) { state !== s }) continue
                wait = backoff(wait, hubs[0].first)
            }
        } catch (e: InterruptedException) {
            // stopped
        } finally {
            status = Status.OFF
        }
    }

    /**
     * Reaches hub through the tunnel at the next of its endpoints and
     * serves the connection until it ends, or for [upCheckMS] when up is
     * set, so the hubs above are tried again; returns how long it served
     * the connection, in milliseconds, or null when it did not reach the hub.
     */
    private fun tryHub(s: AwayState, hub: String, offer: Member.TunnelOffer, up: Boolean): Long? {
        status = Status.CONNECTING
        val n = synchronized(lock) { endpointOf[hub] ?: 0 }
        val endpoint = offer.endpoints[n % offer.endpoints.size]
        val open = synchronized(lock) {
            if (tunnelTo == (hub to offer)) {
                tunnel
            } else {
                closeTunnelLocked()
                null
            }
        }
        val t = if (open != null) {
            open
        } else {
            val started = try {
                tunnels.start(s.key, offer.psk, offer.hubKey, device, hub, endpoint, offer.obfuscation ?: "", offer.vless ?: "")
            } catch (e: Exception) {
                fail("the tunnel to the hub could not start", e)
                return null
            }
            val kept = synchronized(lock) {
                (!stopped && state === s).also {
                    if (it) {
                        tunnel = started
                        tunnelTo = hub to offer
                    }
                }
            }
            if (!kept) {
                runCatching { started.close() }
                return null
            }
            started
        }
        val conn = try {
            dial(t.port, hub)
        } catch (e: Exception) {
            fail("the hub does not answer through the tunnel", e)
            // The next of the hub's endpoints, in turn, on the same tunnel.
            synchronized(lock) { endpointOf[hub] = n + 1 }
            runCatching { t.setEndpoint(offer.endpoints[(n + 1) % offer.endpoints.size]) }
            return null
        }
        synchronized(lock) { using = hub }
        status = Status.CONNECTED
        lastError = null
        // On a hub below the first, the connection ends after upCheckMS.
        val timer = if (up) {
            Thread({
                try {
                    Thread.sleep(upCheckMS)
                    conn.close()
                } catch (e: InterruptedException) {
                    // the connection ended first
                }
            }, "cbb up check").apply {
                isDaemon = true
                start()
            }
        } else {
            null
        }
        val began = System.nanoTime()
        try {
            serve(conn, hub)
        } catch (e: Exception) {
            fail("the connection to the hub ended", e)
        } finally {
            timer?.interrupt()
        }
        return (System.nanoTime() - began) / 1_000_000
    }

    private fun fail(what: String, e: Exception) {
        lastError = e
        log(what, e)
    }

    private fun backoff(wait: Long, hub: String): Long {
        idle(wait)
        return minOf(wait * 2, if (isPhone(hub)) phoneWaitMS else maxWaitMS)
    }

    /** Waits ms, or until something changes; 0 waits for a change only. */
    private fun idle(ms: Long) = synchronized(lock) {
        if (!stopped) lock.wait(ms)
    }

    companion object {
        /** Where hub is in order; order.size when it is not there. */
        fun rank(order: List<String>, hub: String): Int = order.indexOf(hub).let { if (it < 0) order.size else it }

        /** The kept offers the phone tries, of the hubs in the group's order and with endpoints, highest first. */
        /**
         * The hubs in their order; a hub that gave its key for the next
         * period comes again right after, with that key: it may have moved
         * on to it while the phone was away (section 11, "The hub's key").
         */
        fun hubsToTry(order: List<String>, s: AwayState): List<Pair<String, Member.TunnelOffer>> =
            s.hubs.filter { (h, o) -> rank(order, h) < order.size && o.endpoints.isNotEmpty() }.sortedBy { rank(order, it.first) }
                .flatMap { (h, o) -> listOfNotNull(h to o, o.withNextKey()?.let { h to it }) }
    }
}
