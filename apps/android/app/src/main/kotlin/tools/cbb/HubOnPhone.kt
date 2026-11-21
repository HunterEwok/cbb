// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb

import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.util.Base64

/**
 * The forwarder and the home networks of the phone as a hub of a group of
 * 0.6, which the Live member runs (AwayOn06); a phone of a group of 0.5 is
 * never a hub (D-123).
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

    /** The most home networks the phone remembers; the oldest goes first. */
    const val MAX_HOMES = 8

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

/** The phone as a hub of a group of 0.6, as the screens show it (AwayOn06). */
object HubOnPhone {
    /** What the screens show. */
    enum class Status { OFF, PAUSED, HOME_ONLY, REGISTERING, REGISTERED, FAILED }

    /** How the hub's tunnel hides (docs/design.md, "Blocked networks"): plain WireGuard, AmneziaWG, or AmneziaWG with VLESS to the forwarder. */
    enum class Disguise { PLAIN, OBFUSCATE, VLESS }

    /**
     * A network as the hub remembers it: its gateway's address and the
     * network of the phone's address on it, as "192.168.0.1 192.168.0.0/24".
     * Wi-Fi in a café has another, so the phone neither takes members
     * nor publishes itself there (as D-63 on the computers).
     */
    fun networkKey(gateway: InetAddress?, address: InetAddress?, prefixLength: Int): String? {
        val g = gateway?.hostAddress ?: return null
        val a = address?.address ?: return null
        if (prefixLength !in 0..a.size * 8) return null
        val n = a.copyOf()
        for (i in n.indices) {
            val bits = (prefixLength - i * 8).coerceIn(0, 8)
            n[i] = (n[i].toInt() and (0xff shl (8 - bits)).toByte().toInt()).toByte()
        }
        val net = InetAddress.getByAddress(n).hostAddress ?: return null
        return "${g.substringBefore('%')} $net/$prefixLength"
    }
}
