// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb

import tools.cbb.kit.Member

/**
 * The one rule of every device (docs/design.md, "The one button"), as on
 * the iPhone (LiveGroup.sync): a copy from another device that waits for
 * the phone comes in; otherwise what the phone copied goes out, however
 * old, unless it is the group's text already.
 */
object SyncRule {
    enum class Action { FETCH, SEND, NOTHING }

    /**
     * Whether current is a copy from another device that waits for this
     * phone: younger than the group's live window windowMS, with a text, an
     * image or files (usable), in a sync mode that takes the group's copies
     * (receives), and not the copy the phone took last (taken).
     */
    fun waiting(current: Member.Event?, usable: Pair<String, Member.Kind>?, device: String, windowMS: Long, receives: Boolean, taken: String?): Boolean =
        receives && current != null && usable != null && !current.isMark && !current.unread && current.origin != device &&
            current.ageMS < windowMS && current.id != taken

    /**
     * What the button does: fetch a copy that waits (waiting), else send
     * what the phone's clipboard holds (board, read only then) when it is
     * not the group's text already.
     */
    fun decide(waits: Boolean, board: () -> String?, usable: Pair<String, Member.Kind>?): Action {
        if (waits) return Action.FETCH
        val b = board()
        return if (!b.isNullOrEmpty() && b != usable?.first) Action.SEND else Action.NOTHING
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
