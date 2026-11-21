// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * The 0.6 member's group, notices, "who stays" list and events, read from
 * testdata/interop/member-group.json, which the Swift kit reads too.
 */
class GroupStateTest {
    private val v = Interop.read("member-group.json").jsonObject

    @Test
    fun group() {
        val g = GroupState.fromJson(v.getValue("group").jsonObject)
        assertEquals("q83vEjRWeJCrze8SNFZ4kA==", g.group)
        assertEquals("01010101010101010101010101010101", g.rootDevice)
        assertTrue(g.me.admin)
        assertFalse(g.isRoot)
        assertEquals("secrets", g.stop)
        assertFalse(g.stopped)
        assertTrue(g.tooOld)
        assertTrue(g.changeArriving)
        assertFalse(g.updateNeeded)
        assertEquals(listOf("Root phone", "Pixel", "Desk"), g.devices.map { it.name })
        assertEquals(listOf(false, true, false), g.devices.map { it.admin })
        assertTrue(g.devices[2].frozen && g.devices[2].hub)
        assertTrue(g.copy(me = g.me.copy(device = g.rootDevice)).isRoot)
    }

    @Test
    fun notices() {
        val ns = (v.getValue("notices") as kotlinx.serialization.json.JsonArray).map { Notice.fromJson(it.jsonObject) }
        assertEquals(listOf("admins_silent", "change_arriving", "root_room_waiting"), ns.map { it.kind })
        assertEquals("5", ns[0].args["days_left"])
        assertEquals(listOf(true, false, true), ns.map { it.dismissable })
        assertEquals("72", ns[2].args["percent"])
    }

    @Test
    fun preview() {
        val p = ChangePreview.fromJson(v.getValue("preview").jsonObject)
        assertTrue(p.waiting)
        assertEquals(listOf("out", "admin_kept", "stays", "removed_earlier"), p.rows.map { it.outcome })
        assertEquals(listOf(false, false, true, false), p.rows.map { it.frozen })
    }

    @Test
    fun events() {
        val e = v.getValue("events").jsonObject
        fun ev(name: String) = CoreMember.decode(Wire.encode(e.getValue(name) as JsonObject))
        val s = assertIs<CoreMember.Event.State>(ev("state")).state
        assertTrue(s.halted && s.stopped)
        assertEquals("recovery_not_saved", assertIs<CoreMember.Event.NoticeAdded>(ev("notice")).notice.kind)
        val r = assertIs<CoreMember.Event.RootChanged>(ev("root_changed"))
        assertEquals(Triple("01010101010101010101010101010101", "02020202020202020202020202020202", 2L), Triple(r.from, r.to, r.seq))
        val k = assertIs<CoreMember.Event.NeedKey>(ev("need_key"))
        assertEquals(7L to "spare_admin", k.token to k.kind)
        assertEquals(listOf<Byte>(4, 0, 1), assertIs<CoreMember.Event.KeyDone>(ev("key_done")).public.toList())
    }

    @Test
    fun recoveryInput() {
        assertEquals("""{"qr":"CBBR1X"}""", Wire.encode(RecoveryInput.Qr("CBBR1X").toJson()).decodeToString())
        assertEquals("""{"text":"ABCD"}""", Wire.encode(RecoveryInput.Text("ABCD").toJson()).decodeToString())
        assertEquals("""{"secret":"AQI="}""", Wire.encode(RecoveryInput.Secret(byteArrayOf(1, 2)).toJson()).decodeToString())
    }
}
