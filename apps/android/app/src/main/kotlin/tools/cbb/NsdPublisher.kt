// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb

import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import tools.cbb.kit.Discovery

/**
 * Publishes the phone that is the group's hub on the home network while
 * its app is open (docs/protocol.md, section 3): the service
 * <device ID>._cbb._tcp with the member port and the TXT
 * v=1, g=<tag>, r=phone, so that the other phones and the Android TVs,
 * which only dial, find it. The computers and the lite members note it but
 * do not dial it: it dials them.
 */
class NsdPublisher(context: Context, private val device: String, private val tag: String, private val memberPort: Int) {
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
            port = memberPort
            setAttribute("v", "1")
            setAttribute("g", tag)
            setAttribute("r", "phone")
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
