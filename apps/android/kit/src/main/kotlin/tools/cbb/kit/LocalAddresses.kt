// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import java.net.Inet4Address
import java.net.Inet6Address
import java.net.NetworkInterface

/**
 * This device's addresses on the home network, for the join QR code a
 * phone shows (docs/protocol.md, section 6, "The joiner listens"): private
 * IPv4 addresses first, then unique local IPv6 ones, never loopback,
 * link-local or a cellular carrier's address, at most four.
 */
object LocalAddresses {
    fun current(): List<String> {
        val all = runCatching { NetworkInterface.getNetworkInterfaces()?.toList().orEmpty() }.getOrDefault(emptyList())
        val v4 = mutableListOf<String>()
        val v6 = mutableListOf<String>()
        for (i in all) {
            if (!runCatching { i.isUp && !i.isLoopback }.getOrDefault(false)) continue
            for (a in i.inetAddresses.toList()) {
                when (a) {
                    is Inet4Address -> a.hostAddress?.let { if (isHomeIPv4(it) && it !in v4) v4.add(it) }
                    // The interface's addresses carry its zone, which a unique local one does not need.
                    is Inet6Address -> a.hostAddress?.substringBefore('%')?.let { if (isHomeIPv6(it) && it !in v6) v6.add(it) }
                    else -> {}
                }
            }
        }
        return (v4 + v6).take(JoinCode.MAX_ADDRS)
    }

    /** Whether an IPv4 address is a private one (RFC 1918). */
    fun isHomeIPv4(s: String): Boolean {
        val b = s.split('.').mapNotNull { it.toIntOrNull()?.takeIf { n -> n in 0..255 } }
        if (b.size != 4) return false
        return b[0] == 10 || (b[0] == 172 && b[1] in 16..31) || (b[0] == 192 && b[1] == 168)
    }

    /** Whether an IPv6 address is a unique local one (fc00::/7), without a zone. */
    fun isHomeIPv6(s: String): Boolean {
        val l = s.lowercase()
        return '%' !in l && (l.startsWith("fc") || l.startsWith("fd"))
    }
}
