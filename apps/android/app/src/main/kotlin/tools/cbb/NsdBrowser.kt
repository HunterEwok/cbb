// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb

import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.net.wifi.WifiManager
import tools.cbb.kit.Discovery
import tools.cbb.kit.FoundMember
import java.net.InetSocketAddress

/**
 * Browses for the Linux members with NsdManager: the services of type
 * _cbb._tcp, resolved one at a time to an address, a port and
 * the TXT record. It holds a multicast lock while it browses, as some Wi-Fi
 * drivers drop mDNS answers without one.
 *
 * onChange gets the members found now, after every change, on NsdManager's
 * thread. On Android 17 and later the app needs ACCESS_LOCAL_NETWORK first.
 */
class NsdBrowser(context: Context, private val onChange: (Set<FoundMember>) -> Unit) {
    private val nsd = context.getSystemService(NsdManager::class.java)
    private val multicast = context.applicationContext.getSystemService(WifiManager::class.java)
        .createMulticastLock("cbb").apply { setReferenceCounted(false) }

    private val lock = Any()
    private val found = mutableMapOf<String, Pair<FoundMember, InetSocketAddress>>()
    private val pending = ArrayDeque<NsdServiceInfo>()
    private var resolving = false
    private var running = false

    private val discovery = object : NsdManager.DiscoveryListener {
        override fun onDiscoveryStarted(serviceType: String) {}
        override fun onDiscoveryStopped(serviceType: String) {}
        override fun onStartDiscoveryFailed(serviceType: String, errorCode: Int) {
            synchronized(lock) { running = false }
        }

        override fun onStopDiscoveryFailed(serviceType: String, errorCode: Int) {}

        override fun onServiceFound(info: NsdServiceInfo) {
            synchronized(lock) { pending.addLast(info) }
            resolveNext()
        }

        override fun onServiceLost(info: NsdServiceInfo) {
            val changed = synchronized(lock) { found.remove(info.serviceName) != null }
            if (changed) publish()
        }
    }

    fun start() = synchronized(lock) {
        if (running) return
        running = true
        multicast.acquire()
        nsd.discoverServices(Discovery.SERVICE_TYPE, NsdManager.PROTOCOL_DNS_SD, discovery)
    }

    fun stop() = synchronized(lock) {
        if (!running) return
        running = false
        runCatching { nsd.stopServiceDiscovery(discovery) }
        if (multicast.isHeld) multicast.release()
        pending.clear()
        found.clear()
    }

    /** The address of a found member, to dial. */
    fun address(device: String): InetSocketAddress? = synchronized(lock) { found[device]?.second }

    /** NsdManager resolves one service at a time before Android 14; the found ones wait their turn. */
    private fun resolveNext() {
        val info = synchronized(lock) {
            if (resolving || !running) return
            pending.removeFirstOrNull()?.also { resolving = true } ?: return
        }
        @Suppress("DEPRECATION")
        nsd.resolveService(
            info,
            object : NsdManager.ResolveListener {
                override fun onResolveFailed(serviceInfo: NsdServiceInfo, errorCode: Int) = done()

                @Suppress("DEPRECATION") // host: one address is all the dialer needs
                override fun onServiceResolved(r: NsdServiceInfo) {
                    val m = Discovery.member(r.serviceName, r.attributes)
                    val host = r.host
                    if (m != null && host != null) {
                        synchronized(lock) { found[m.device] = m to InetSocketAddress(host, r.port) }
                        publish()
                    }
                    done()
                }
            },
        )
    }

    private fun done() {
        synchronized(lock) { resolving = false }
        resolveNext()
    }

    private fun publish() = onChange(synchronized(lock) { found.values.map { it.first }.toSet() })
}
