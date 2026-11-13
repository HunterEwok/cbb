// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Push's calls from the Kotlin kit, as the Swift kit's PushTests: one send key
 * per token for every group, a slot per group, a new registration only when
 * something in it changed, the previous key not kept after a membership
 * change, the push service's challenge kept only for this phone's send key, a
 * real copy across a rotation of the sealing key, what the vault holds, the
 * hints-only marks and the UnifiedPush message's parts.
 */
class PushTest {
    private class MemoryStore : PushVault.Store {
        val m = sortedMapOf<String, ByteArray>()
        override fun get(name: String) = m[name]
        override fun put(name: String, value: ByteArray?) {
            if (value == null) m.remove(name) else m[name] = value
        }
        override fun names() = m.keys.toList()
    }

    private fun bytes(b: Int, n: Int) = ByteArray(n) { b.toByte() }

    @Test
    fun keysLimitsAndRegistration() {
        val a = Push.newKeys()
        val b = Push.newKeys()
        assertEquals(32, a.key.size)
        assertEquals(16, a.slot.size)
        assertFalse(a.key.contentEquals(b.key) || a.sendKey.contentEquals(b.sendKey) || a.slot.contentEquals(b.slot))
        val fcm = Push.limits(Push.Env.FCM)
        assertTrue(fcm.known)
        assertEquals(Push.Kinds.COPIES or Push.Kinds.EVENTS, fcm.kinds)
        assertFalse(Push.limits(200).known)
        val now = 1_800_000_000_000L
        fun reg(highest: Long?, restart: Boolean = false, face: ByteArray? = FACE, key: ByteArray = a.key) =
            Push.registration(highest, now, restart, Push.Kinds.COPIES, Push.Env.FCM, bytes(7, 160), key = key, sendKey = a.sendKey, slot = a.slot, face = face)
        val r = reg(null)
        assertEquals(now, r.seq)
        assertEquals(now, r.highest)
        assertEquals(8, r.keyHint?.size)
        val off = Push.registration(r.highest, now, kinds = 0)
        assertEquals(r.seq + 1, off.seq)
        assertNull(off.keyHint)
        // Saved while the clock was two days ahead: above it until a member
        // says the service found it ahead; then from the clock, and so is the
        // highest, which the phone's clock finds ahead too. A restart the
        // clock disagrees with keeps the highest.
        val ahead = reg(now + 2 * 86_400_000L)
        assertEquals(now + 2 * 86_400_000L + 1, ahead.seq)
        val restarted = reg(ahead.highest, restart = true)
        assertEquals(now, restarted.seq)
        assertEquals(now, restarted.highest)
        val falseAhead = reg(now + 1000, restart = true)
        assertEquals(now, falseAhead.seq)
        assertEquals(now + 1000, falseAhead.highest)
        // Another face signs other bytes.
        assertFalse(reg(r.seq, face = bytes(5, 16)).frame.contentEquals(reg(r.seq).frame))
        // A key not 32 bytes, a face not 16 or none: code 18.
        for (bad in listOf({ reg(null, key = ByteArray(31)) }, { reg(null, face = ByteArray(15)) }, { reg(null, face = null) })) {
            assertEquals(18, assertFailsWith<Core.Refusal> { bad() }.code)
        }
        // A UnifiedPush endpoint the core takes, and a plain-HTTP one it refuses.
        val p256dh = UNIFIED_POINT
        Push.registration(null, now, kinds = 1, env = Push.Env.UNIFIED_PUSH, unifiedPush = Push.UnifiedPush("https://up.example.org/x", p256dh, bytes(1, 16)), key = a.key, sendKey = a.sendKey, slot = a.slot, face = FACE)
        assertFailsWith<Core.Refusal> {
            Push.registration(null, now, kinds = 1, env = Push.Env.UNIFIED_PUSH, unifiedPush = Push.UnifiedPush("http://up.example.org/x", p256dh, bytes(1, 16)), key = a.key, sendKey = a.sendKey, slot = a.slot, face = FACE)
        }
    }

    @Test
    fun theVaultRegistersOnlyWhatChanged() {
        val vault = PushVault(MemoryStore())
        val me = bytes(1, 16)
        val token = bytes(7, 160)
        val devices = PushVault.Devices(listOf(me, bytes(2, 16), bytes(3, 16)), me)
        val first = assertNotNull(vault.register("g1", me, token, env = Push.Env.FCM, kinds = 3, face = FACE, devices = devices))
        val g1 = vault.load("g1")
        assertEquals(first.seq, g1.seq)
        assertEquals(1, g1.keys.size)
        assertEquals(16, g1.slot?.size)
        assertEquals(listOf("g1"), vault.groups())
        assertNotNull(g1.context(false))
        val sender = vault.sender()
        assertContentEquals(first.keyHint, sender.keyHint)
        // Nothing new: no registration.
        assertNull(vault.register("g1", me, token, env = Push.Env.FCM, kinds = 3, face = FACE, devices = devices))
        // A member asked for it again: the same keys, a higher seq.
        val renewed = assertNotNull(vault.register("g1", me, token, env = Push.Env.FCM, kinds = 3, face = FACE, reasons = setOf(PushVault.Reason.RENEW), devices = devices))
        assertTrue(renewed.seq > g1.seq!!)
        assertEquals(2, vault.load("g1").keys.size)
        assertEquals("g1", vault.group(g1.slot!!))
        // A second group: the same send key, its own slot and push key.
        val other = assertNotNull(vault.register("g2", me, token, env = Push.Env.FCM, kinds = 1, face = FACE))
        assertContentEquals(first.keyHint, other.keyHint)
        assertFalse(vault.load("g2").slot!!.contentEquals(g1.slot))
        // The challenge: another key's is dropped, this send key's kept once.
        val value = bytes(9, 16)
        assertFalse(vault.keep(value + ByteArray(8)))
        assertFalse(vault.keep(ByteArray(23)))
        assertTrue(vault.keep(value + sender.keyHint!!))
        assertFalse(vault.keep(value + sender.keyHint!!))
        val withChallenge = assertNotNull(vault.register("g1", me, token, env = Push.Env.FCM, kinds = 3, face = FACE, devices = devices))
        assertTrue(withChallenge.seq > renewed.seq)
        // A device removed: a new key, the previous not kept.
        val before = vault.load("g1")
        val fewer = PushVault.Devices(listOf(me, bytes(2, 16)), me)
        assertNotNull(vault.register("g1", me, token, env = Push.Env.FCM, kinds = 3, face = FACE, devices = fewer))
        val after = vault.load("g1")
        assertEquals(1, after.keys.size)
        assertFalse(after.keys[0].key.contentEquals(before.keys[0].key))
        // A device added changes no key.
        assertNull(vault.register("g1", me, token, env = Push.Env.FCM, kinds = 3, face = FACE, devices = devices))
        // A new token: a new send key, its challenge gone, the slot kept.
        vault.register("g1", me, bytes(8, 160), env = Push.Env.FCM, kinds = 1, face = FACE)
        val s3 = vault.sender()
        assertFalse(s3.sendKey!!.contentEquals(sender.sendKey))
        assertNull(s3.challenge)
        assertContentEquals(g1.slot, vault.load("g1").slot)
        // Off, then off again: nothing new; on again: one fresh key.
        assertNotNull(vault.register("g1", me, null, env = null, kinds = 0))
        assertNull(vault.register("g1", me, null, env = null, kinds = 0))
        vault.register("g1", me, bytes(8, 160), env = Push.Env.FCM, kinds = 1, face = FACE)
        assertEquals(1, vault.load("g1").keys.size)
        // Leaving every group drops the groups and keeps the sender: a group
        // joined later registers under the same send key and challenge.
        val kept = vault.sender()
        assertTrue(vault.keep(value + kept.keyHint!!))
        vault.forget("g1")
        vault.forget("g2")
        assertTrue(vault.groups().isEmpty())
        assertEquals(1, vault.items().size, "the sender alone")
        val g3 = assertNotNull(vault.register("g3", me, bytes(8, 160), env = Push.Env.FCM, kinds = 1, face = FACE))
        assertContentEquals(kept.keyHint, g3.keyHint)
        assertNotNull(vault.load("g3").registered?.challenge, "registered with the kept challenge")
        // A new face: a new registration naming it, the same push key; none
        // at all registers nothing and saves nothing.
        val key3 = vault.load("g3").keys[0].key
        val moved = bytes(6, 16)
        val onMoved = assertNotNull(vault.register("g3", me, bytes(8, 160), env = Push.Env.FCM, kinds = 1, face = moved))
        assertEquals(PushVault.Registered(hexStr(bytes(8, 160)), Push.Env.FCM, 1, hexStr(key3), vault.sender().sendKey?.let(::hexStr), vault.sender().challenge?.let(::hexStr), hexStr(moved)), vault.load("g3").registered)
        assertFailsWith<PushVault.NoFace> { vault.register("g3", me, bytes(8, 160), env = Push.Env.FCM, kinds = 1) }
        assertEquals(onMoved.seq, vault.load("g3").seq)
        // A member said the number was ahead, and the phone's clock agrees:
        // one registration from the clock, which becomes the highest.
        val past = System.currentTimeMillis() + 3 * 86_400_000L
        vault.save("g3", vault.load("g3").also { it.seq = past; it.highest = past })
        val restarted = assertNotNull(vault.register("g3", me, bytes(8, 160), env = Push.Env.FCM, kinds = 1, face = moved, reasons = setOf(PushVault.Reason.RENEW, PushVault.Reason.AHEAD)))
        assertTrue(restarted.seq < past)
        assertEquals(restarted.seq, vault.load("g3").highest)
        val again = assertNotNull(vault.register("g3", me, bytes(8, 160), env = Push.Env.FCM, kinds = 1, face = moved, reasons = setOf(PushVault.Reason.RENEW)))
        assertTrue(again.seq in (restarted.seq + 1) until past)
    }

    /**
     * Leaving a group turns push off there first, then drops the group and
     * the send key: the left group's members get a registration of kinds 0,
     * and the phone's next registration anywhere carries a new send key.
     */
    @Test
    fun leavingTurnsPushOffThereAndRetiresTheSendKey() {
        val vault = PushVault(MemoryStore())
        val me = bytes(1, 16)
        val token = bytes(7, 160)
        val on = assertNotNull(vault.register("left", me, token, env = Push.Env.FCM, kinds = 1, face = FACE))
        val stays = assertNotNull(vault.register("stays", me, token, env = Push.Env.FCM, kinds = 1, face = FACE))
        val before = vault.sender()
        assertTrue(vault.keep(bytes(9, 16) + before.keyHint!!))
        val off = assertNotNull(vault.leaving("left"))
        assertTrue(off.seq > on.seq)
        assertNull(off.keyHint, "push off carries no send key")
        assertContentEquals(off.frame, vault.load("left").frame, "the frame the members get turns push off")
        assertEquals(0, vault.load("left").kinds)
        assertNull(vault.leaving("left"), "already off: nothing more")
        assertFalse(vault.left("left"), "another group stays")
        assertEquals(listOf("stays"), vault.groups())
        val after = vault.sender()
        assertNull(after.sendKey)
        assertNull(after.challenge)
        assertContentEquals(token, after.token, "the token stays")
        val again = assertNotNull(vault.register("stays", me, token, env = Push.Env.FCM, kinds = 1, face = FACE))
        assertFalse(again.keyHint!!.contentEquals(stays.keyHint))
        assertFalse(vault.sender().sendKey!!.contentEquals(before.sendKey))
        assertNull(vault.load("stays").registered?.challenge)
        // Leaving the last group gives the token up: the sender goes whole.
        assertNotNull(vault.leaving("stays"))
        assertTrue(vault.left("stays"))
        assertNull(vault.sender().token)
        assertTrue(vault.items().isEmpty())
    }

    /**
     * A UnifiedPush endpoint takes a challenge part from whoever knows it: at
     * most one new challenge an hour is kept, and a challenge alone makes a
     * new registration once in a challenge period.
     */
    @Test
    fun unifiedPushChallengesAreKeptSparingly() {
        val vault = PushVault(MemoryStore())
        val me = bytes(1, 16)
        val up = Push.UnifiedPush("https://up.example.org/x", UNIFIED_POINT, bytes(1, 16))
        val t0 = 1_800_000_000_000L
        assertNotNull(vault.register("g1", me, null, up, Push.Env.UNIFIED_PUSH, 1, FACE, nowMs = t0))
        assertNotNull(vault.register("g2", me, null, up, Push.Env.UNIFIED_PUSH, 1, FACE, nowMs = t0))
        val hint = vault.sender().keyHint!!
        // Twenty challenge parts in a minute: the first is kept, no other.
        assertTrue(vault.keep(bytes(10, 16) + hint, t0))
        for (i in 1 until 20) assertFalse(vault.keep(bytes(10 + i, 16) + hint, t0 + i * 1000L), "part $i")
        assertContentEquals(bytes(10, 16), vault.sender().challenge)
        // Each group registers again over it, once.
        val g1 = assertNotNull(vault.register("g1", me, null, up, Push.Env.UNIFIED_PUSH, 1, FACE, nowMs = t0 + 30_000))
        assertNotNull(vault.register("g2", me, null, up, Push.Env.UNIFIED_PUSH, 1, FACE, nowMs = t0 + 30_000))
        // An hour on, another is kept, but within the period it makes no new
        // registration: the one over a challenge stands.
        assertTrue(vault.keep(bytes(40, 16) + hint, t0 + 3_600_000))
        assertNull(vault.register("g1", me, null, up, Push.Env.UNIFIED_PUSH, 1, FACE, nowMs = t0 + 3_600_000))
        assertEquals(g1.seq, vault.load("g1").seq)
        // A member's ask still registers, with the newest challenge.
        assertNotNull(vault.register("g1", me, null, up, Push.Env.UNIFIED_PUSH, 1, FACE, setOf(PushVault.Reason.RENEW), nowMs = t0 + 3_700_000))
        assertEquals(hexStr(bytes(40, 16)), vault.load("g1").registered?.challenge)
        // The next period: a challenge alone registers again.
        val next = t0 + 14L * 24 * 3600 * 1000
        assertTrue(vault.keep(bytes(41, 16) + hint, next))
        assertNotNull(vault.register("g2", me, null, up, Push.Env.UNIFIED_PUSH, 1, FACE, nowMs = next))
        // A new endpoint (a new send key) in the same period: the hour and the
        // period's one registration over a challenge start afresh.
        val up2 = Push.UnifiedPush("https://up.example.org/y", UNIFIED_POINT, bytes(2, 16))
        val t1 = next + 5L * 24 * 3600 * 1000
        assertTrue(vault.keep(bytes(42, 16) + vault.sender().keyHint!!, t1))
        assertNotNull(vault.register("g1", me, null, up, Push.Env.UNIFIED_PUSH, 1, FACE, nowMs = t1))
        val newKey = assertNotNull(vault.register("g1", me, null, up2, Push.Env.UNIFIED_PUSH, 1, FACE, nowMs = t1 + 60_000))
        assertFalse(newKey.keyHint!!.contentEquals(hint))
        assertTrue(vault.keep(bytes(43, 16) + newKey.keyHint!!, t1 + 120_000), "the new key's challenge is kept at once")
        assertNotNull(vault.register("g1", me, null, up2, Push.Env.UNIFIED_PUSH, 1, FACE, nowMs = t1 + 180_000), "and registered over")
        // FCM, which only the push service reaches, keeps every new challenge.
        val fcm = PushVault(MemoryStore())
        fcm.register("g", me, bytes(7, 160), env = Push.Env.FCM, kinds = 1, face = FACE, nowMs = t0)
        val h = fcm.sender().keyHint!!
        assertTrue(fcm.keep(bytes(10, 16) + h, t0))
        assertTrue(fcm.keep(bytes(11, 16) + h, t0 + 1000))
        assertNotNull(fcm.register("g", me, bytes(7, 160), env = Push.Env.FCM, kinds = 1, face = FACE, nowMs = t0 + 2000))
        assertTrue(fcm.keep(bytes(12, 16) + h, t0 + 3000))
        assertNotNull(fcm.register("g", me, bytes(7, 160), env = Push.Env.FCM, kinds = 1, face = FACE, nowMs = t0 + 4000))
    }

    /** testdata/interop/push-open.json, from the Rust core's push tests: a real copy shows across a rotation. */
    @Test
    fun aRealCopyShowsAcrossARotation() {
        val v = Interop.read("push-open.json").jsonObject
        val vault = PushVault(MemoryStore())
        vault.save("g", PushVault.Group(keys = listOf(Push.KeyAndSeq(b64(v.str("key")), v.getValue("seq").jsonPrimitive.long)), me = b64(v.str("me"))))
        val origins = v.getValue("origins").jsonArray.map { val o = it.jsonObject; Push.Origin(b64(o.str("key")), o.getValue("rights").jsonPrimitive.long) }
        val steps = v.getValue("steps").jsonArray
        assertEquals(3, steps.size)
        for (st in steps) {
            val step = st.jsonObject
            val sealing = step.getValue("sealing").jsonArray.map { val s = it.jsonObject; Push.Sealing(s.getValue("epoch").jsonPrimitive.long, b64(s.str("secret"))) }
            vault.opening("g", sealing, origins, v.getValue("window_ms").jsonPrimitive.long, halted = false)
            val c = assertNotNull(vault.load("g").context(false))
            val opens = step.getValue("opens").jsonArray.map { it.jsonPrimitive.content }
            for ((name, b) in v.getValue("bodies").jsonObject) {
                val body = b.jsonObject
                val o = Push.open(b64(body.str("body")), c, body.getValue("now_ms").jsonPrimitive.long)
                val what = "${step.str("name")} $name"
                if (name in opens) {
                    assertEquals("copy", o.kind, what)
                    assertEquals(body.str("text"), o.text, what)
                } else {
                    assertEquals("waits", o.kind, what)
                    assertNull(o.text, what)
                }
            }
            val held = Push.Context(c.keys, c.me, c.origins, c.sealing, hintsOnly = true, windowMs = c.windowMs)
            val first = v.getValue("bodies").jsonObject.getValue("first").jsonObject
            assertNull(Push.open(b64(first.str("body")), held, first.getValue("now_ms").jsonPrimitive.long).text)
        }
    }

    /** The vault holds what opens a body and a copy, and no field of a key that signs a record. */
    @Test
    fun theVaultHoldsNoSigningKey() {
        val vault = PushVault(MemoryStore())
        val me = bytes(1, 16)
        vault.register("g1", me, bytes(7, 160), env = Push.Env.FCM, kinds = 3, face = FACE, devices = PushVault.Devices(listOf(me), me))
        vault.opening("g1", listOf(Push.Sealing(1, ByteArray(32))), listOf(Push.Origin(ByteArray(70), 1)), 120_000, false)
        val allowed = setOf(
            "token", "unifiedpush", "url", "p256dh", "auth", "env", "send_key", "key_hint", "challenge", "challenge_at_ms",
            "keys", "key", "seq", "highest", "face", "challenged_period", "slot", "kinds", "frame", "registered", "key_drawn_ms", "me", "members", "root",
            "origins", "rights", "frozen", "sealing", "epoch", "secret", "too_old", "halted", "window_ms",
        )
        fun names(e: JsonElement): Set<String> = when (e) {
            is JsonObject -> e.keys + e.values.flatMap { names(it) }
            is JsonArray -> e.flatMap { names(it) }.toSet()
            else -> emptySet()
        }
        val items = vault.items()
        assertEquals(2, items.size)
        for (item in items) {
            val found = names(Json.parseToJsonElement(item.decodeToString()))
            assertTrue(allowed.containsAll(found), "unexpected fields: ${found - allowed}")
        }
    }

    @Test
    fun aHintsOnlyMarkLastsUntilItsChangeIsApplied() {
        var clock = NOW
        val marks = PushMarks(MemoryStore()) { clock }
        val me = bytes(1, 16)
        val gone = bytes(2, 16)
        val g = PushVault.Group(members = listOf(me, gone), root = me, keyDrawnMs = 1_000)
        assertFalse(marks.hintsOnly("g", g))
        marks.mark("g", 2, gone, g, 2_000)
        assertTrue(marks.hintsOnly("g", g))
        assertFalse(marks.hintsOnly("other", g))
        marks.spend("g", g)
        assertTrue(marks.hintsOnly("g", g))
        g.members = listOf(me)
        g.keyDrawnMs = 3_000
        assertFalse(marks.hintsOnly("g", g))
        marks.spend("g", g)
        // Applied before the event came: nothing.
        marks.mark("g", 2, gone, g, 9_000)
        assertFalse(marks.hintsOnly("g", g))
        marks.spend("g", g)
        g.members = listOf(me, gone)
        marks.mark("g", 4, me, g, 9_000)
        assertFalse(marks.hintsOnly("g", g))
        marks.mark("g", 4, gone, g, 9_000)
        assertTrue(marks.hintsOnly("g", g))
        g.root = gone
        g.keyDrawnMs = 9_500
        assertFalse(marks.hintsOnly("g", g))
        marks.mark("g", 6, null, g, 10_000)
        assertTrue(marks.hintsOnly("g", g))
        g.keyDrawnMs = 11_000
        assertFalse(marks.hintsOnly("g", g))
        // An event naming a change that never comes: spent once the app has
        // synced the group's records after it with a member other than the
        // device it names, taken in records newer than the mark, and those
        // records say it did not happen.
        val other = bytes(3, 16)
        marks.spend("g", g)
        assertTrue(marks.of("g").isEmpty())
        marks.mark("g", 2, gone, g, 20_000)
        marks.mark("g", 6, null, g, 21_000)
        assertTrue(marks.hintsOnly("g", g))
        // A member that brought nothing newer than the marks has not heard of
        // the change either: nothing spent.
        marks.synced("g", 25_000, listOf(other), 19_000, g)
        marks.synced("g", 25_000, listOf(other), null, g)
        assertEquals(listOf(2L, 6L), marks.of("g").map { it.event }, "no newer records: no mark spent")
        marks.synced("g", 20_500, listOf(other), 20_200, g)
        assertTrue(marks.hintsOnly("g", g), "the stop came after that sync")
        assertEquals(listOf(6L), marks.of("g").map { it.event })
        marks.mark("g", 2, gone, g, 23_000)
        marks.synced("g", 24_000, listOf(gone), 23_500, g)
        assertEquals(listOf(2L), marks.of("g").map { it.event }, "the device a mark names never clears it")
        marks.synced("g", 24_000, emptyList(), 23_500, g)
        assertTrue(marks.hintsOnly("g", g), "no member: nothing synced")
        marks.synced("g", 24_000, listOf(other), 23_500, g)
        assertFalse(marks.hintsOnly("g", g))
        // A stop that is there stays in force whatever a sync brings, until a
        // key drawn after it.
        g.halted = true
        marks.mark("g", 6, null, g, 30_000)
        marks.synced("g", 31_000, listOf(other), 30_500, g)
        assertTrue(marks.hintsOnly("g", g))
        g.keyDrawnMs = 32_000
        assertFalse(marks.hintsOnly("g", g))
        // A mark ends a week after the app first met a member other than
        // the device it names; a phone that met none keeps it.
        g.halted = false
        marks.mark("g", 2, gone, g, 40_000)
        assertTrue(marks.hintsOnly("g", g))
        clock = 40_000 + 30 * PushMarks.LIFE_MS
        assertTrue(marks.hintsOnly("g", g), "a phone that met no member keeps a true mark")
        marks.synced("g", 50_000, listOf(gone), 45_000, g)
        assertTrue(marks.hintsOnly("g", g), "the device a mark names starts no week")
        marks.synced("g", 50_000, listOf(other), null, g)
        clock = 50_000 + PushMarks.LIFE_MS - 1
        assertTrue(marks.hintsOnly("g", g), "the week counts from the first meeting")
        marks.synced("g", 60_000, listOf(other), null, g)
        clock = 50_000 + PushMarks.LIFE_MS
        assertFalse(marks.hintsOnly("g", g))
        marks.forget("g")
        assertTrue(marks.of("g").isEmpty())
    }

    /** A full list keeps the marks in force; an event naming no device of the group never pushes one out. */
    @Test
    fun aFullListOfMarksKeepsTheOnesInForce() {
        val marks = PushMarks(MemoryStore()) { NOW }
        val me = bytes(1, 16)
        val gone = bytes(2, 16)
        val g = PushVault.Group(members = listOf(me, gone), root = me, keyDrawnMs = 1_000)
        marks.mark("g", 2, gone, g, 2_000)
        for (i in 0 until 40) marks.mark("g", 2, bytes(10 + i, 16), g, 3_000L + i * 1000)
        var l = marks.of("g")
        assertEquals(PushMarks.MAX, l.size)
        assertContentEquals(gone, l.first().device, "forty events naming no device of the group: the true mark stays")
        assertTrue(marks.hintsOnly("g", g))
        marks.mark("g", 6, null, g, 50_000)
        l = marks.of("g")
        assertEquals(PushMarks.MAX, l.size)
        assertEquals(listOf(2L, 6L), l.filter { it.inForce(g, NOW) }.map { it.event })
        for (i in 0 until PushMarks.MAX) marks.mark("g", 6, null, g, 60_000L + i * 1000)
        l = marks.of("g")
        assertEquals(PushMarks.MAX, l.size)
        assertTrue(l.all { it.event == 6L && it.atMs >= 60_000 })
    }

    @Test
    fun aUnifiedPushMessageIsPartsByKind() {
        val body = bytes(5, 2972)
        val challenge = bytes(6, 24)
        fun part(kind: Int, b: ByteArray) = byteArrayOf(kind.toByte(), (b.size shr 8).toByte(), b.size.toByte()) + b
        val both = assertNotNull(Push.parts(part(1, body) + part(2, challenge)))
        assertContentEquals(body, both.body)
        assertContentEquals(challenge, both.challenge)
        // Told apart by kind, not length: a challenge first, an unknown kind skipped.
        val other = assertNotNull(Push.parts(part(9, bytes(1, 24)) + part(2, challenge)))
        assertNull(other.body)
        assertContentEquals(challenge, other.challenge)
        assertNull(Push.parts(part(1, body).copyOf(100)), "a part longer than the message")
        assertNull(Push.parts(byteArrayOf(1, 0)), "a head cut short")
        val data = Push.data(mapOf("c" to b64(body), "k" to b64(challenge)))
        assertContentEquals(body, data.body)
        assertContentEquals(challenge, data.challenge)
        assertNull(Push.data(mapOf("c" to "not base64!")).body)
    }

    private companion object {
        /** A P-256 point (the generator), uncompressed. */
        val UNIFIED_POINT: ByteArray = hexOf(
            "04" +
                "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296" +
                "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
        )

        fun hexOf(s: String) = ByteArray(s.length / 2) { s.substring(2 * it, 2 * it + 2).toInt(16).toByte() }

        fun hexStr(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

        /** A group's face for the push service. */
        val FACE = ByteArray(16) { 4 }

        /** The marks' clock in the tests, after every mark they make. */
        const val NOW = 100_000L
    }
}
