// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The values the kit reads from the member's answers and hands it (Member,
 * Media, WhyReason and WhyAway), the keys it signs with and the records'
 * names it checks (Basics): each as Go and the core read them.
 */
class KitValuesTest {
    @Test
    fun syncModesSayWhoSendsAndWhoTakes() {
        assertEquals(setOf("own", "shared", "receive", "send"), Member.MODES)
        assertTrue(Member.receives(null) && Member.receives("shared") && Member.receives("receive"))
        assertFalse(Member.receives("send") || Member.receives("own"))
        assertTrue(Member.sends(null) && Member.sends("shared") && Member.sends("send"))
        assertFalse(Member.sends("receive") || Member.sends("own"))
    }

    @Test
    fun kindsAndWaysReadTheirWireNames() {
        for (k in Member.Kind.entries) assertEquals(k, Member.Kind.of(k.wire))
        for (v in Member.Via.entries) assertEquals(v, Member.Via.of(v.wire))
        assertNull(Member.Kind.of("video"))
        assertNull(Member.Via.of("telepathy"))
    }

    /** A hello's device is shown, never trusted: what does not fit is dropped, and nothing left is null. */
    @Test
    fun aDeviceKeepsOnlyItsValidFields() {
        val good = Member.DeviceInfo("laptop", "14.2", "0.6.0", "aa:bb:cc:dd:ee:ff")
        assertEquals(good, good.cleaned)
        assertEquals(good, Member.DeviceInfo.fromJson(good.toJson()))
        val bad = Member.DeviceInfo("spaceship", "x".repeat(33), "0.6\u0007", "AA:BB:CC:DD:EE:FF")
        assertNull(bad.cleaned)
        assertEquals(Member.DeviceInfo(osVersion = "14"), Member.DeviceInfo("toaster", "14", "", "nope").cleaned)
        assertNull(Member.DeviceInfo.fromJson(JsonPrimitive("phone")))
        assertNull(Member.DeviceInfo.fromJson(null))
        assertTrue("watch" in Member.DeviceInfo.FORMS)
    }

    @Test
    fun aCommandsResultGoesThereAndBack() {
        val r = Member.CommandResult("c1", "refused", "the screen is locked", "dev")
        assertEquals(r, Member.CommandResult.fromJson(r.toJson()))
        assertFalse(r.done)
        assertTrue(Member.CommandResult("c2", "done").done)
        assertEquals(Member.CommandResult("", ""), Member.CommandResult.fromJson(Wire.obj()))
    }

    @Test
    fun anAttestationGoesThereAndBack() {
        val e = Member.Evidence(Member.Evidence.ANDROID, Member.Evidence.MEMBER, "tag", byteArrayOf(1, 2), listOf(byteArrayOf(3), byteArrayOf(4, 5)))
        val back = Member.Evidence.fromJson(e.toJson())
        assertEquals(e, back)
        assertEquals(e.hashCode(), back.hashCode())
        assertNotEquals(e, Member.Evidence(e.format, e.key, null, e.salt, e.chain))
        assertNotEquals(e, Member.Evidence(e.format, e.key, e.groupTag, e.salt, listOf(byteArrayOf(3))))
        assertNotEquals<Any>(e, "evidence")
        val outside = Member.Evidence.fromJson(Wire.obj("format" to Wire.str("x"), "group_tag" to Wire.str("")))
        assertNull(outside.groupTag)
        assertTrue(outside.salt.isEmpty() && outside.chain.isEmpty())
    }

    private val sum = ByteArray(32) { 7 }

    /** Files: each path checked as a receiver writes it, no folder twice, no file inside another file. */
    @Test
    fun aManifestOfFilesFollowsGo() {
        val ok = Media.Manifest(
            3,
            listOf(Media.Part(path = "dir", dir = true), Media.Part(path = "dir/a.txt", size = 3, sha256 = sum)),
        )
        assertTrue(ok.isFiles && ok.isValid)
        assertEquals(ok, Media.Manifest.fromJson(ok.toJson()))
        fun files(vararg parts: Media.Part) = Media.Manifest(parts.sumOf { it.size }, parts.toList()).isValid
        assertFalse(files(Media.Part(path = "a/../b", size = 1, sha256 = sum)), "a path with ..")
        assertFalse(files(Media.Part(path = "a", type = "image/png", size = 1, sha256 = sum)), "a file with a type")
        assertFalse(files(Media.Part(path = "con.txt", size = 1, sha256 = sum)), "a reserved name")
        assertFalse(files(Media.Part(path = "a", size = 1, sha256 = sum), Media.Part(path = "a/b", size = 1, sha256 = sum)), "a file in a file")
        assertFalse(files(Media.Part(path = "d", dir = true, size = 1)), "a folder with bytes")
        assertFalse(files(Media.Part(path = "d", dir = true, sha256 = sum)), "a folder with a hash")
        assertFalse(files(Media.Part(path = "a", size = 1, sha256 = ByteArray(31))), "a short hash")
        assertFalse(files(Media.Part(path = "a", size = 1, sha256 = sum), Media.Part(path = "a", size = 1, sha256 = sum)), "a path twice")
        assertFalse(Media.Manifest(2, listOf(Media.Part(path = "a", size = 1, sha256 = sum))).isValid, "a size that is not the parts'")
        assertTrue(files(Media.Part(path = "COM1x", size = 1, sha256 = sum)))
    }

    @Test
    fun aManifestOfClipboardDataFollowsGo() {
        val png = Media.Part(type = "image/png", size = 2, sha256 = sum)
        assertTrue(Media.Manifest(2, listOf(png)).isValid)
        assertFalse(Media.Manifest(0, emptyList()).isValid)
        assertFalse(Media.Manifest(2, listOf(Media.Part(type = "image/webp", size = 2, sha256 = sum))).isValid)
        assertFalse(Media.Manifest(4, listOf(png, png)).isValid, "a type twice")
        assertFalse(Media.Manifest(0, listOf(Media.Part(type = "image/png", dir = true))).isValid)
        assertEquals(png, Media.Part.fromJson(png.toJson()))
        assertEquals(png.hashCode(), Media.Part(type = "image/png").hashCode())
        assertNotEquals(png, Media.Part(type = "image/png", size = 2))
        assertNotEquals<Any>(png, "image/png")
        assertNull(Media.Manifest.parse("not json".toByteArray()))
    }

    @Test
    fun namesAreMadeOnesEverySystemTakes() {
        assertEquals("a_b", Media.cleanName("a/b"))
        assertEquals("CON_.txt", Media.cleanName("CON.txt"))
        assertEquals("name._", Media.cleanName("name."))
        assertEquals("_", Media.cleanName(".."))
        assertEquals("_", Media.cleanName(""))
        assertTrue(Media.cleanName("é".repeat(400)).toByteArray().size <= Media.MAX_NAME)
        assertEquals("COM¹_", Media.saveName("COM¹"))
        assertEquals("LPT3_.log", Media.savePath("LPT3.log"))
        assertEquals("ok/CONIN\$_", Media.savePath("ok/CONIN\$"))
        assertFalse(Media.checkName("trailing "))
        assertFalse(Media.checkName("LPT9"))
        assertTrue(Media.checkName("LPT10"))
        assertFalse(Media.checkPath(""))
    }

    @Test
    fun whyReadsTheCoresReasonsAndHandsItTheTunnels() {
        val r = WhyReason.fromJson(
            Wire.obj(
                "code" to Wire.str("muted"), "level" to Wire.str("warn"), "until_ms" to Wire.num(5),
                "device" to Wire.str("hub"), "devices" to JsonArray(listOf(JsonPrimitive("a"), JsonPrimitive("b"))),
                "value" to Wire.str("3"), "detail" to Wire.str("why"),
            ),
        )
        assertEquals(WhyReason("muted", "warn", 5, "hub", listOf("a", "b"), "3", "why"), r)
        assertEquals(WhyReason("", ""), WhyReason.fromJson(Wire.obj()))
        val away = WhyAway(hub = true, standby = true, hubDevice = "d", through = true, hidden = true, relay = true, relayConnected = true, forwarder = true, forwarderRegistered = true, entriesStale = true, error = "e")
        val o = away.toJson()
        assertEquals(11, o.size)
        assertEquals("d", o.optString("hub_device"))
        assertEquals(true, o.optBool("entries_stale"))
    }

    @Test
    fun aSoftwareKeySignsAndItsSignaturesCheck() {
        val k = SoftwareSigner()
        val data = "data".toByteArray()
        val spki = k.publicKeyDER
        assertTrue(verifySignature(spki, data, k.signature(data)))
        assertFalse(verifySignature(spki, "other".toByteArray(), k.signature(data)))
        assertFalse(verifySignature(spki, data, byteArrayOf(1, 2, 3)))
        assertFalse(verifySignature(ByteArray(91), data, k.signature(data)))
        assertTrue(k.signDigest(sha256(data)).isNotEmpty())
        val point = spki.copyOfRange(26, 91)
        assertTrue(p256SPKI(point).contentEquals(spki))
        assertNull(p256SPKI(point.copyOf(64)))
        // A point off the curve, which the JDK alone would take.
        assertNull(p256SPKI(point.copyOf().also { it[64] = (it[64] + 1).toByte() }))
        assertNull(p256PublicKey(spki.copyOf(90)))
        val other = object : CertificateSigner {
            override val publicKeyDER = spki
            override fun signature(data: ByteArray) = k.signature(data)
        }
        assertFailsWith<UnsupportedOperationException> { other.signDigest(ByteArray(32)) }
        assertEquals("00ff", byteArrayOf(0, -1).toHex())
    }

    @Test
    fun recordsNamesAndKeyLevels() {
        assertTrue(Records.isDeviceID("0123456789abcdef0123456789abcdef"))
        assertFalse(Records.isDeviceID("0123456789ABCDEF0123456789ABCDEF"))
        assertFalse(Records.isDeviceID(null))
        assertTrue(Records.validName("Pixel"))
        assertFalse(Records.validName("a\u0001"))
        assertFalse(Records.validName("x".repeat(65)))
        assertFalse(Records.validName(null))
        assertEquals(32, Records.keyHash(byteArrayOf(1)).size)
        assertFalse(Records.levelAllows(Records.LEVEL_FILES, Records.ROOTLESS, true))
        assertTrue(Records.levelAllows(Records.PROVEN, Records.PROVEN, false))
        assertTrue(Records.levelAllows(Records.LEVEL_FILES, Records.FILE, true))
        assertFalse(Records.levelAllows(Records.LEVEL_FILES, Records.FILE, false))
        assertFalse(Records.levelAllows(Records.HARDWARE, Records.FILE, true))
        assertTrue(Records.levelAllows(Records.HARDWARE, Records.HARDWARE, false))
        assertFalse(Records.levelAllows(Records.PROVEN, Records.HARDWARE, false))
        assertEquals(Records.PROVEN, Records.storeOf(Records.PROVEN, "computer"))
        assertEquals(Records.HARDWARE, Records.storeOf(null, "phone"))
        assertEquals(Records.HARDWARE, Records.storeOf("tpm", "watch"))
        assertEquals(Records.FILE, Records.storeOf(null, "computer"))
        assertEquals(listOf(Records.PROVEN, Records.HARDWARE, Records.LEVEL_FILES), Records.KEY_LEVELS)
    }

    @Test
    fun aBlobsSizeCountsItsSealedSegments() {
        assertEquals(0, Blob.sizeOf(0))
        assertEquals(Blob.SEALED_SEGMENT, Blob.sizeOf(1))
        assertEquals(Blob.SEALED_SEGMENT, Blob.sizeOf(Blob.SEGMENT.toLong()))
        assertEquals(2 * Blob.SEALED_SEGMENT, Blob.sizeOf(Blob.SEGMENT + 1L))
        assertNotNull(Blob.sizeOf(Media.MAX_MEDIA))
    }
    /** The group file of 0.6: saved and read again; a name made fit for the records. */
    @Test
    fun aPhoneGroupIsSavedAndReadAgain() {
        val g = PhoneGroup.of("0123456789abcdef0123456789abcdef", "fedcba9876543210fedcba9876543210", root = false)
        g.admin = true
        assertTrue(g.isAdmin)
        assertEquals("fedcba9876543210", g.tag)
        val file = java.io.File(kotlin.io.path.createTempDirectory("cbb-group").toFile(), "sub/group.json")
        g.save(file)
        g.save(file)
        val back = PhoneGroup.fromJson(file.readBytes())
        assertEquals(g.device, back.device)
        assertEquals(g.group, back.group)
        assertFalse(back.isRoot)
        assertTrue(back.admin)
        assertFailsWith<PhoneGroup.Failure> { PhoneGroup.fromJson("[]".toByteArray()) }
        assertFailsWith<PhoneGroup.Before06> { PhoneGroup.fromJson("""{"device":"d"}""".toByteArray()) }
        assertFailsWith<PhoneGroup.Failure> { PhoneGroup.fromJson("""{"group06":"x"}""".toByteArray()) }
        assertFailsWith<PhoneGroup.Failure> { PhoneGroup.fromJson("""{"group06":5,"device":"d"}""".toByteArray()) }
        assertEquals("Android", PhoneGroup.validName("\u0001\u0002"))
        assertEquals("ab", PhoneGroup.validName("a\u0007b"))
        assertEquals(64, PhoneGroup.validName("é".repeat(40)).toByteArray().size)
        assertTrue(PhoneGroup.INVALID_NAME.isNotEmpty())
        assertTrue(PhoneGroup.FileKey().message!!.isNotEmpty() && PhoneGroup.Rootless().message!!.isNotEmpty() && PhoneGroup.BelowKeyLevel().message!!.isNotEmpty())
    }
}
