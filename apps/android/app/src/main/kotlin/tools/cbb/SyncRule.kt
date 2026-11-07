// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb

/** The addresses of the computers as the phone dials them (the button's rule is the Rust member's now). */
object SyncRule {
    /** The addresses to try, IPv4 first: a home network reaches those most surely, and each that fails costs its timeout. */
    fun ordered(addrs: List<String>): List<String> = addrs.filter { !it.startsWith("[") } + addrs.filter { it.startsWith("[") }

    /** host and port of "host:port" or "[IPv6]:port". */
    fun split(addr: String): Pair<String, Int>? {
        val i = addr.lastIndexOf(':')
        if (i < 0) return null
        val port = addr.substring(i + 1).toIntOrNull()?.takeIf { it in 1..65535 } ?: return null
        var host = addr.substring(0, i)
        if (host.startsWith("[") && host.endsWith("]")) host = host.substring(1, host.length - 1)
        return if (host.isEmpty()) null else host to port
    }
}
