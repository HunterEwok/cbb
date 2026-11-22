// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The recovery key (docs/protocol.md, section 10, "The recovery key"): the root makes it and its sheet, and the core reads the sheet back. */
class RecoveryTest {
    private val now = Instant.now()

    /** testdata/interop/recovery-sheet.json, which the core and the Swift kit check too. */
    @Test
    fun vectors() {
        val v = Interop.read("recovery-sheet.json").jsonObject
        val s = v.getValue("sheet").jsonObject
        val sheet = Core.recoverySheet(b64(s.str("key")), b64(s.str("cert")), s.str("group"))
        assertEquals(s.str("qr"), sheet.qr)
        assertEquals(s.str("text"), sheet.text)
        assertContentEquals(b64(s.str("admin")), sheet.admin)
        val k = assertIs<Core.SheetReading.Key>(Core.readRecoverySheet(s.str("qr"))).key
        assertContentEquals(b64(s.str("key")), k.key)
        assertContentEquals(b64(s.str("cert")), k.cert)
        assertEquals(s.str("group"), k.group)
        assertContentEquals(b64(s.str("admin")), k.admin)
        for (e in v.getValue("refused").jsonArray) {
            val c = e.jsonObject
            val r = assertIs<Core.SheetReading.Refused>(Core.readRecoverySheet(c.str("text")), c.str("text"))
            assertEquals(c.str("reason"), r.reason, c.str("text"))
            assertFalse(r.message.isEmpty())
        }
        val bad = assertFailsWith<Core.Refusal> { Core.recoverySheet(ByteArray(32), b64(s.str("cert")), s.str("group")) }
        assertEquals("request", bad.name)
    }

}
