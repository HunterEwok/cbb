// SPDX-License-Identifier: AGPL-3.0-only

package tools.cbb

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class SyncRuleTest {
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
