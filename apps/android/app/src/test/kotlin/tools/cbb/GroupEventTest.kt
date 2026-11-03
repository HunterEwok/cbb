// SPDX-License-Identifier: AGPL-3.0-only

package tools.cbb

import tools.cbb.GroupEvent.Seen
import tools.cbb.GroupEvent.What
import org.junit.Assert.assertEquals
import org.junit.Test

class GroupEventTest {
    /** The same events, in the same order, as the iPhone app's testGroupEvents. */
    @Test
    fun between() {
        val old = mapOf("a" to Seen("deck"), "b" to Seen("mac"), "c" to Seen("pi", admin = true), "d" to Seen("phone2", admin = true))
        val new = mapOf("a" to Seen("deck", admin = true), "b" to Seen("mac", frozen = true), "d" to Seen("phone2", admin = true, root = true), "e" to Seen("zero"))
        assertEquals(
            listOf(GroupEvent(What.MADE_ADMIN, "deck"), GroupEvent(What.FROZEN, "mac"), GroupEvent(What.TAKEN_OVER, "phone2"), GroupEvent(What.ADDED, "zero"), GroupEvent(What.REMOVED, "pi")),
            GroupEvent.between(old, new),
        )
        assertEquals(emptyList<GroupEvent>(), GroupEvent.between(new, new))
        assertEquals(listOf(GroupEvent(What.UNFROZEN, "mac")), GroupEvent.between(mapOf("b" to Seen("mac", frozen = true)), mapOf("b" to Seen("mac"))))
    }

    /** This phone is never news to itself. */
    @Test
    fun seen() {
        val me = LiveGroup.Device("me", "pixel", online = true, isSelf = true)
        assertEquals(mapOf("a" to Seen("deck")), GroupEvent.seen(listOf(me, LiveGroup.Device("a", "deck", online = false))))
    }
}
