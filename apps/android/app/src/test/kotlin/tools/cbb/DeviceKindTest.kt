// SPDX-License-Identifier: AGPL-3.0-only

package tools.cbb

import tools.cbb.kit.Member
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class DeviceKindTest {
    private fun device(role: String = "member", os: String? = null, info: Member.DeviceInfo? = null) =
        LiveGroup.Device("a", "deck", online = true, role = role, os = os, device = info)

    /** The hello's form first; else the role and the system, as on the iPhone. */
    @Test
    fun kind() {
        assertEquals(DeviceKind.CONSOLE, device(os = "linux", info = Member.DeviceInfo(form = "console")).kind)
        assertEquals(DeviceKind.LAPTOP, device(os = "macos").kind)
        assertEquals(DeviceKind.DESKTOP, device(os = "windows").kind)
        assertEquals(DeviceKind.BOARD, device(os = "none").kind)
        assertEquals(DeviceKind.PHONE, device(role = "phone", os = "android").kind)
        assertEquals(DeviceKind.DESKTOP, device(info = Member.DeviceInfo(form = "toaster")).kind)
    }

    @Test
    fun systemWithVersion() {
        assertEquals("macOS 15.1", device(os = "macos", info = Member.DeviceInfo(osVersion = "15.1")).systemWithVersion)
        // Linux names its distribution, which says more.
        assertEquals("Ubuntu 24.04", device(os = "linux", info = Member.DeviceInfo(osVersion = "Ubuntu 24.04")).systemWithVersion)
        assertEquals("Windows", device(os = "windows").systemWithVersion)
        assertNull(device().systemWithVersion)
    }

    /** A mute or pause from its end in Unix milliseconds: 0 holds until it is lifted, one that ended holds no more. */
    @Test
    fun hold() {
        assertEquals(LiveGroup.Hold(null), LiveGroup.Hold.of(0, now = 1_000))
        assertEquals(LiveGroup.Hold(2_000), LiveGroup.Hold.of(2_000, now = 1_000))
        assertNull(LiveGroup.Hold.of(1_000, now = 1_000))
        assertNull(LiveGroup.Hold.of(null))
        assertEquals(listOf(900_000L, 3_600_000L, 28_800_000L, 0L), PauseTime.entries.map { it.ms })
    }
}
