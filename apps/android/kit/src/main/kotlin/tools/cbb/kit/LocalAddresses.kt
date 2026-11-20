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

    /** Whether an IPv4 address is a private one (RFC 1918). Only an address in its one spelling is judged ([octets]). */
    fun isHomeIPv4(s: String): Boolean {
        val b = octets(s) ?: return false
        return b[0] == 10 || (b[0] == 172 && b[1] in 16..31) || (b[0] == 192 && b[1] == 168)
    }

    /**
     * Whether an IPv6 address is a unique local one (fc00::/7), without a zone. The text is read as
     * an address first ([bytesIPv6]); an IPv4 address written as IPv6 (::ffff:a.b.c.d) is not one of
     * these, as the format's `addr` has no such spelling.
     */
    fun isHomeIPv6(s: String): Boolean {
        val b = bytesIPv6(s) ?: return false
        return (b[0] and 0xfe) == 0xfc
    }

    /**
     * The four numbers of an IPv4 address in its one spelling: four parts of one to three decimal
     * digits, none above 255, without a sign or a leading zero. Null for a name and for every other
     * spelling.
     */
    internal fun octets(s: String): List<Int>? {
        val parts = s.split('.')
        if (parts.size != 4) return null
        val out = mutableListOf<Int>()
        for (p in parts) {
            if (p.isEmpty() || p.length > 3 || !p.all { it in '0'..'9' } || (p.length > 1 && p[0] == '0')) return null
            val n = p.toInt()
            if (n > 255) return null
            out.add(n)
        }
        return out
    }

    /**
     * The 16 bytes of an IPv6 address written as text (RFC 4291: groups of one to four hex digits,
     * "::" once at most, an IPv4 tail), without a zone. Null for a name and for anything else.
     */
    internal fun bytesIPv6(s: String): List<Int>? {
        if (s.isEmpty() || s.length > 45) return null
        val halves = s.split("::")
        if (halves.size > 2) return null
        fun groups(t: String, last: Boolean): List<Int>? {
            if (t.isEmpty()) return emptyList()
            val out = mutableListOf<Int>()
            val parts = t.split(':')
            for ((i, p) in parts.withIndex()) {
                if (last && i == parts.size - 1 && '.' in p) {
                    out.addAll(octets(p) ?: return null)
                    continue
                }
                if (p.isEmpty() || p.length > 4 || !p.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) return null
                val g = p.toInt(16)
                out.add(g shr 8)
                out.add(g and 0xff)
            }
            return out
        }
        if (halves.size == 1) {
            val all = groups(halves[0], true) ?: return null
            return if (all.size == 16) all else null
        }
        val head = groups(halves[0], false) ?: return null
        val tail = groups(halves[1], true) ?: return null
        if (head.size + tail.size > 14) return null
        return head + List(16 - head.size - tail.size) { 0 } + tail
    }
}
