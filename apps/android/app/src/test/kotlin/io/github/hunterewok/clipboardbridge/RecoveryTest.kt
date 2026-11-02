// SPDX-License-Identifier: AGPL-3.0-only

package io.github.hunterewok.clipboardbridge

import io.github.hunterewok.clipboardbridge.kit.Member
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.time.Instant
import java.util.Base64

class RecoveryTest {
    @Test
    fun keyRowsPutFourGroupsToALine() {
        val text = (1..14).joinToString("-") { "G%03d".format(it) }
        val rows = keyRows(text).lines()
        assertEquals(4, rows.size)
        assertEquals("G001 G002 G003 G004", rows[0])
        assertEquals("G013 G014", rows[3])
    }

    private fun record(type: String, admin: ByteArray, ms: Long) = Member.Record(
        """{"v":2,"type":"$type","admin":"${Base64.getEncoder().encodeToString(admin)}","time_ms":$ms}""".toByteArray(),
        ByteArray(64),
    )

    @Test
    fun recoveryMadeIsTheNewestRecordForTheKey() {
        val key = ByteArray(32) { 1 }
        val other = ByteArray(32) { 2 }
        val records = listOf(
            record("recovery", key, 1_000),
            record("device", key, 2_000),
            record("recovery", other, 3_000),
            record("recovery", key, 4_000),
            record("recovery", other, 5_000),
        )
        assertEquals(Instant.ofEpochMilli(4_000), LiveGroup.recoveryMade(key, records))
        assertNull(LiveGroup.recoveryMade(ByteArray(32) { 3 }, records))
    }
}
