// SPDX-License-Identifier: AGPL-3.0-only

package tools.cbb

import org.junit.Assert.assertEquals
import org.junit.Test

class RecoveryTest {
    @Test
    fun keyRowsPutFourGroupsToALine() {
        val text = (1..14).joinToString("-") { "G%03d".format(it) }
        val rows = keyRows(text).lines()
        assertEquals(4, rows.size)
        assertEquals("G001 G002 G003 G004", rows[0])
        assertEquals("G013 G014", rows[3])
    }
}
