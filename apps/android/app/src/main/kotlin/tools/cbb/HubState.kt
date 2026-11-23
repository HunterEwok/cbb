// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb

import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.util.Base64

/**
 * The forwarder of a computer that is the group's hub, which the root
 * names from the phone, and the relay's address and key, as the user gives
 * them. A phone is no hub (D-134).
 */
object HubState {
    /** The forwarder: its endpoint, "ip:port", and the pin of its key: SHA-256 of its key in standard base64. */
    data class Forwarder(val endpoint: String, val pin: String) {
        /** Whether this is the project's forwarder. */
        val isProject get() = pin == PROJECT_PIN

        companion object {
            /** The project's forwarder, which the hub uses unless the user gives their own: its name with the port, looked up when it is set, and the pin of its key, as cbb has them (internal/forward/project.go). */
            const val PROJECT_HOST = "cbb.tools:8764"
            const val PROJECT_PIN = "efzUG2YzJBqS8FfojZGwqioECt46VzQcFo3oWpPru/g="

            /** The project's forwarder at the address its name has now, IPv4 first; null when it cannot be looked up. On an IO thread. */
            fun project(): Forwarder? = HubState.resolve(PROJECT_HOST)?.let { Forwarder(it, PROJECT_PIN) }
        }
    }

    /** Whether pin is the pin of a forwarder's key, as `cbb forward` prints it. */
    fun validPin(pin: String): Boolean = runCatching {
        val b = Base64.getDecoder().decode(pin)
        b.size == 32 && Base64.getEncoder().encodeToString(b) == pin
    }.getOrDefault(false)

    /**
     * The forwarder's address as the hub takes it, "ip:port", from what
     * the user typed: an address or a name with its port. A name is
     * looked up now, IPv4 first; on the caller's IO thread.
     */
    fun resolve(s: String): String? {
        val t = s.trim()
        val i = t.lastIndexOf(':')
        if (i <= 0 || i == t.length - 1) return null
        val port = t.substring(i + 1).toIntOrNull()?.takeIf { it in 1..65535 } ?: return null
        val host = t.substring(0, i).removePrefix("[").removeSuffix("]")
        val addrs = runCatching { InetAddress.getAllByName(host).toList() }.getOrNull() ?: return null
        val a = addrs.firstOrNull { it is Inet4Address } ?: addrs.firstOrNull() ?: return null
        val ip = a.hostAddress ?: return null
        return if (a is Inet6Address) "[${ip.substringBefore('%')}]:$port" else "$ip:$port"
    }
}
