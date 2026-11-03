// SPDX-License-Identifier: AGPL-3.0-only

package tools.cbb

import tools.cbb.SyncRule.Action
import tools.cbb.kit.Member
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class SyncRuleTest {
    private val me = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    private val pc = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

    private fun event(origin: String, text: String, ageMS: Long, via: Member.Via = Member.Via.COPY) =
        Member.Event("e", origin, via, Member.Timestamp(1, 0), ageMS, Member.Kind.TEXT, text)

    @Test
    fun theButton() {
        val recent = event(pc, "from the pc", 1_000)
        // A computer's copy of a moment ago comes first, even over a new text on the phone.
        assertEquals(Action.FETCH, SyncRule.decide("on the phone", recent, "from the pc" to Member.Kind.TEXT, me))
        // Once the phone has it, nothing is new.
        assertEquals(Action.NOTHING, SyncRule.decide("from the pc", recent, "from the pc" to Member.Kind.TEXT, me))
        // An older copy: the phone's new text goes.
        val old = event(pc, "from the pc", 60_000)
        assertEquals(Action.SEND, SyncRule.decide("on the phone", old, "from the pc" to Member.Kind.TEXT, me))
        // Nothing on the phone: the latest comes.
        assertEquals(Action.FETCH, SyncRule.decide(null, old, "from the pc" to Member.Kind.TEXT, me))
        assertEquals(Action.FETCH, SyncRule.decide("", old, "from the pc" to Member.Kind.TEXT, me))
        // The phone's own event is not fetched first.
        val mine = event(me, "sent", 1_000)
        assertEquals(Action.SEND, SyncRule.decide("new", mine, "sent" to Member.Kind.TEXT, me))
        // A copy that came through Universal Clipboard is not fetched first either.
        val handoff = event(pc, "x", 1_000, Member.Via.UNIVERSAL_CLIPBOARD)
        assertEquals(Action.SEND, SyncRule.decide("new", handoff, "x" to Member.Kind.TEXT, me))
        // Nothing anywhere.
        assertEquals(Action.NOTHING, SyncRule.decide(null, null, null, me))
        assertEquals(Action.SEND, SyncRule.decide("first", null, null, me))
    }

    @Test
    fun addresses() {
        assertEquals(listOf("192.168.0.2:8764", "[fd00::1]:8764"), SyncRule.ordered(listOf("[fd00::1]:8764", "192.168.0.2:8764")))
        assertEquals("192.168.0.2" to 8764, SyncRule.split("192.168.0.2:8764"))
        assertEquals("fd00::1" to 8764, SyncRule.split("[fd00::1]:8764"))
        assertNull(SyncRule.split("192.168.0.2"))
        assertNull(SyncRule.split(":8764"))
        assertNull(SyncRule.split("host:99999"))
    }
}
