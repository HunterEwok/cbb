// SPDX-License-Identifier: AGPL-3.0-only

package tools.cbb

import tools.cbb.SyncRule.Action
import tools.cbb.kit.Member
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.assertNull
import org.junit.Test

class SyncRuleTest {
    private val me = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    private val pc = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

    private fun event(origin: String, text: String, ageMS: Long) =
        Member.Event("e", origin, Member.Via.COPY, Member.Timestamp(1, 0), ageMS, Member.Kind.TEXT, text)

    private val text = "from the pc" to Member.Kind.TEXT

    private fun waits(e: Member.Event?, usable: Pair<String, Member.Kind>? = text, receives: Boolean = true, taken: String? = null) =
        SyncRule.waiting(e, usable, me, 60_000, receives, taken)

    @Test
    fun aCopyWaits() {
        // Another device's copy within the live window waits for the phone.
        assertTrue(waits(event(pc, "from the pc", 1_000)))
        // Once the window has passed it is gone.
        assertFalse(waits(event(pc, "from the pc", 60_000)))
        // The phone's own copy, a copy the phone took already, a mode that takes no copies, and nothing usable never wait.
        assertFalse(waits(event(me, "sent", 1_000)))
        assertFalse(waits(event(pc, "from the pc", 1_000), taken = "e"))
        assertFalse(waits(event(pc, "from the pc", 1_000), receives = false))
        assertFalse(waits(event(pc, "from the pc", 1_000), usable = null))
        assertFalse(waits(null))
    }

    @Test
    fun theButton() {
        // A copy that waits comes in, and the phone's clipboard is not even read.
        assertEquals(Action.FETCH, SyncRule.decide(true, { throw AssertionError("read the clipboard") }, text))
        // Otherwise what the phone copied goes, however old.
        assertEquals(Action.SEND, SyncRule.decide(false, { "on the phone" }, text))
        assertEquals(Action.SEND, SyncRule.decide(false, { "first" }, null))
        // Unless it is the group's text already, or there is nothing.
        assertEquals(Action.NOTHING, SyncRule.decide(false, { "from the pc" }, text))
        assertEquals(Action.NOTHING, SyncRule.decide(false, { null }, text))
        assertEquals(Action.NOTHING, SyncRule.decide(false, { "" }, null))
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
