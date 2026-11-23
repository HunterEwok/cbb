// SPDX-License-Identifier: AGPL-3.0-only

package tools.cbb

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** A forwarder's or a relay's address and key as the user gives them (HubState). */
class HubStateTest {
    private val pin = "A".repeat(43) + "="

    @Test
    fun forwarderInput() {
        assertTrue(HubState.validPin(pin))
        assertTrue(HubState.validPin("a+/9".repeat(10) + "abc="))
        assertFalse(HubState.validPin("sha256:" + "A".repeat(43) + "="))
        assertFalse(HubState.validPin("A".repeat(43)))
        assertFalse(HubState.validPin("a-_9".repeat(10) + "abc="))
        assertFalse(HubState.validPin("A".repeat(42) + "B="))
        assertEquals("203.0.113.9:8764", HubState.resolve(" 203.0.113.9:8764 "))
        // IPv6 in brackets, which Go's netip reads in either form.
        val v6 = HubState.resolve("[2001:db8::9]:8764") ?: ""
        assertTrue(v6, v6.startsWith("[2001:db8:") && v6.endsWith("9]:8764"))
        assertNull(HubState.resolve("203.0.113.9"))
        assertNull(HubState.resolve("203.0.113.9:0"))
        assertNull(HubState.resolve(":8764"))
    }
}
