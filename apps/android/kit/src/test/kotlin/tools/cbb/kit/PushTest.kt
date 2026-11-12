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
        val r = Push.registration(null, now, Push.Kinds.COPIES, Push.Env.FCM, bytes(7, 160), key = a.key, sendKey = a.sendKey, slot = a.slot)
        assertEquals(now, r.seq)
        assertEquals(8, r.keyHint?.size)
        val off = Push.registration(r.seq, now, 0)
        assertEquals(r.seq + 1, off.seq)
        assertNull(off.keyHint)
        val e = assertFailsWith<Core.Refusal> {
            Push.registration(null, now, Push.Kinds.COPIES, Push.Env.FCM, bytes(7, 160), key = ByteArray(31), sendKey = a.sendKey, slot = a.slot)
        }
        assertEquals(18, e.code)
        // A UnifiedPush endpoint the core takes, and a plain-HTTP one it refuses.
        val p256dh = UNIFIED_POINT
        Push.registration(null, now, 1, Push.Env.UNIFIED_PUSH, unifiedPush = Push.UnifiedPush("https://up.example.org/x", p256dh, bytes(1, 16)), key = a.key, sendKey = a.sendKey, slot = a.slot)
        assertFailsWith<Core.Refusal> {
            Push.registration(null, now, 1, Push.Env.UNIFIED_PUSH, unifiedPush = Push.UnifiedPush("http://up.example.org/x", p256dh, bytes(1, 16)), key = a.key, sendKey = a.sendKey, slot = a.slot)
        }
    }

    @Test
    fun theVaultRegistersOnlyWhatChanged() {
        val vault = PushVault(MemoryStore())
        val me = bytes(1, 16)
        val token = bytes(7, 160)
        val devices = PushVault.Devices(listOf(me, bytes(2, 16), bytes(3, 16)), me)
        val first = assertNotNull(vault.register("g1", me, token, env = Push.Env.FCM, kinds = 3, devices = devices))
        val g1 = vault.load("g1")
        assertEquals(first.seq, g1.seq)
        assertEquals(1, g1.keys.size)
        assertEquals(16, g1.slot?.size)
        assertEquals(listOf("g1"), vault.groups())
        assertNotNull(g1.context(false))
        val sender = vault.sender()
        assertContentEquals(first.keyHint, sender.keyHint)
        // Nothing new: no registration.
        assertNull(vault.register("g1", me, token, env = Push.Env.FCM, kinds = 3, devices = devices))
        // A member asked for it again: the same keys, a higher seq.
        val renewed = assertNotNull(vault.register("g1", me, token, env = Push.Env.FCM, kinds = 3, reasons = setOf(PushVault.Reason.RENEW), devices = devices))
        assertTrue(renewed.seq > g1.seq!!)
        assertEquals(2, vault.load("g1").keys.size)
        assertEquals("g1", vault.group(g1.slot!!))
        // A second group: the same send key, its own slot and push key.
        val other = assertNotNull(vault.register("g2", me, token, env = Push.Env.FCM, kinds = 1))
        assertContentEquals(first.keyHint, other.keyHint)
        assertFalse(vault.load("g2").slot!!.contentEquals(g1.slot))
        // The challenge: another key's is dropped, this send key's kept once.
        val value = bytes(9, 16)
        assertFalse(vault.keep(value + ByteArray(8)))
        assertFalse(vault.keep(ByteArray(23)))
        assertTrue(vault.keep(value + sender.keyHint!!))
        assertFalse(vault.keep(value + sender.keyHint!!))
        val withChallenge = assertNotNull(vault.register("g1", me, token, env = Push.Env.FCM, kinds = 3, devices = devices))
        assertTrue(withChallenge.seq > renewed.seq)
        // A device removed: a new key, the previous not kept.
        val before = vault.load("g1")
        val fewer = PushVault.Devices(listOf(me, bytes(2, 16)), me)
        assertNotNull(vault.register("g1", me, token, env = Push.Env.FCM, kinds = 3, devices = fewer))
        val after = vault.load("g1")
        assertEquals(1, after.keys.size)
        assertFalse(after.keys[0].key.contentEquals(before.keys[0].key))
        // A device added changes no key.
        assertNull(vault.register("g1", me, token, env = Push.Env.FCM, kinds = 3, devices = devices))
        // A new token: a new send key, its challenge gone, the slot kept.
        vault.register("g1", me, bytes(8, 160), env = Push.Env.FCM, kinds = 1)
        val s3 = vault.sender()
        assertFalse(s3.sendKey!!.contentEquals(sender.sendKey))
        assertNull(s3.challenge)
        assertContentEquals(g1.slot, vault.load("g1").slot)
        // Off, then off again: nothing new; on again: one fresh key.
        assertNotNull(vault.register("g1", me, null, env = null, kinds = 0))
        assertNull(vault.register("g1", me, null, env = null, kinds = 0))
        vault.register("g1", me, bytes(8, 160), env = Push.Env.FCM, kinds = 1)
        assertEquals(1, vault.load("g1").keys.size)
        vault.forget("g1")
        vault.forget("g2")
        assertNull(vault.sender().sendKey)
        assertTrue(vault.items().isEmpty())
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
        vault.register("g1", me, bytes(7, 160), env = Push.Env.FCM, kinds = 3, devices = PushVault.Devices(listOf(me), me))
        vault.opening("g1", listOf(Push.Sealing(1, ByteArray(32))), listOf(Push.Origin(ByteArray(70), 1)), 120_000, false)
        val allowed = setOf(
            "token", "unifiedpush", "url", "p256dh", "auth", "env", "send_key", "key_hint", "challenge",
            "keys", "key", "seq", "slot", "kinds", "frame", "registered", "key_drawn_ms", "me", "members", "root",
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
        val marks = PushMarks(MemoryStore())
        val me = bytes(1, 16)
        val gone = bytes(2, 16)
        val g = PushVault.Group(members = listOf(me, gone), root = me, keyDrawnMs = 1_000)
        assertFalse(marks.hintsOnly("g", g))
        marks.mark("g", 2, gone, 2_000)
        assertTrue(marks.hintsOnly("g", g))
        assertFalse(marks.hintsOnly("other", g))
        marks.spend("g", g)
        assertTrue(marks.hintsOnly("g", g))
        g.members = listOf(me)
        g.keyDrawnMs = 3_000
        assertFalse(marks.hintsOnly("g", g))
        marks.spend("g", g)
        // Applied before the event came: nothing.
        marks.mark("g", 2, gone, 9_000)
        assertFalse(marks.hintsOnly("g", g))
        marks.spend("g", g)
        g.members = listOf(me, gone)
        marks.mark("g", 4, me, 9_000)
        assertFalse(marks.hintsOnly("g", g))
        marks.mark("g", 4, gone, 9_000)
        assertTrue(marks.hintsOnly("g", g))
        g.root = gone
        g.keyDrawnMs = 9_500
        assertFalse(marks.hintsOnly("g", g))
        marks.mark("g", 6, null, 10_000)
        assertTrue(marks.hintsOnly("g", g))
        g.keyDrawnMs = 11_000
        assertFalse(marks.hintsOnly("g", g))
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
    }
}
