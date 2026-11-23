// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb

import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import tools.cbb.kit.Discovery

/**
 * Publishes the service <device ID>._cbb._tcp with port and the TXT record
 * txt on the home network (docs/protocol.md, section 3): an admin phone
 * that opens a home window publishes Discovery.windowTXT while it is open,
 * so that a device without a camera finds it by the six digits.
 */
class NsdPublisher(context: Context, private val device: String, private val port: Int, private val txt: Map<String, String>) {
    private val nsd = context.getSystemService(NsdManager::class.java)
    private val lock = Any()
    private var published = false

    private val listener = object : NsdManager.RegistrationListener {
        override fun onServiceRegistered(info: NsdServiceInfo) {}
        override fun onRegistrationFailed(info: NsdServiceInfo, errorCode: Int) {
            synchronized(lock) { published = false }
        }

        override fun onServiceUnregistered(info: NsdServiceInfo) {}
        override fun onUnregistrationFailed(info: NsdServiceInfo, errorCode: Int) {}
    }

    fun start(): Unit = synchronized(lock) {
        if (published) return
        published = true
        val info = NsdServiceInfo().apply {
            serviceName = device
            serviceType = Discovery.SERVICE_TYPE
            port = this@NsdPublisher.port
            for ((k, v) in txt) setAttribute(k, v)
        }
        runCatching { nsd.registerService(info, NsdManager.PROTOCOL_DNS_SD, listener) }.onFailure { published = false }
        Unit
    }

    /** Stops publishing; NsdManager sends the goodbye. */
    fun stop(): Unit = synchronized(lock) {
        if (!published) return
        published = false
        runCatching { nsd.unregisterService(listener) }
        Unit
    }
}
