// SPDX-License-Identifier: AGPL-3.0-only

package tools.cbb

import tools.cbb.kit.CPace
import org.junit.Assert.assertArrayEquals
import org.junit.Test

// The app reaches the protocol core through the included build.
class KitTest {
    @Test
    fun cpaceAgrees() {
        val ci = "ci".toByteArray()
        val sid = ByteArray(16)
        val a = CPace(CPace.Role.INITIATOR, "123456".toByteArray(), ci, sid, ByteArray(0))
        val b = CPace(CPace.Role.RESPONDER, "123456".toByteArray(), ci, sid, ByteArray(0))
        assertArrayEquals(a.finish(b.message, ByteArray(0)), b.finish(a.message, ByteArray(0)))
    }
}
