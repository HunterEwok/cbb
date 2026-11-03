// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb

import tools.cbb.kit.Member

/**
 * The one button's rule, as for the iPhone's shortcut (internal/phone/sync.go):
 * a computer's copy of a moment ago comes to the phone; otherwise a new text
 * on the phone goes to the computers; otherwise the computers' latest text
 * comes.
 */
object SyncRule {
    /** How recent a computer's copy must be for the button to fetch it first. */
    const val RECENT_COPY_MS = 45_000L

    enum class Action { FETCH, SEND, NOTHING }

    /**
     * What to do, given what the phone's clipboard holds now (board), the
     * group's current event and its text while usable, and this phone's
     * device ID.
     */
    fun decide(board: String?, current: Member.Event?, usable: Pair<String, Member.Kind>?, device: String): Action {
        if (current != null && usable != null && current.origin != device && current.via == Member.Via.COPY &&
            current.ageMS < RECENT_COPY_MS && usable.first != board
        ) {
            return Action.FETCH
        }
        if (!board.isNullOrEmpty() && board != usable?.first) return Action.SEND
        if (usable != null && usable.first != board) return Action.FETCH
        return Action.NOTHING
    }

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
