// SPDX-License-Identifier: AGPL-3.0-only

package tools.cbb

import tools.cbb.kit.Member
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class DeviceKindTest {
    private fun device(role: String = "full", os: String? = null, info: Member.DeviceInfo? = null) =
        LiveGroup.Device("a", "deck", online = true, role = role, os = os, device = info)

    /** The hello's form first; else the role and the system, as on the iPhone. */
    @Test
    fun kind() {
        assertEquals(DeviceKind.CONSOLE, device(os = "linux", info = Member.DeviceInfo(form = "console")).kind)
        assertEquals(DeviceKind.LAPTOP, device(os = "macos").kind)
        assertEquals(DeviceKind.DESKTOP, device(os = "windows").kind)
        assertEquals(DeviceKind.BOARD, device(role = "lite").kind)
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
}
