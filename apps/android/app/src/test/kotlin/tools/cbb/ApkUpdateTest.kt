// SPDX-License-Identifier: AGPL-3.0-only

package tools.cbb

import tools.cbb.kit.Releases
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.MessageDigest

class ApkUpdateTest {
    private fun asset(data: ByteArray, name: String = "cbb-0.6.1.apk") =
        Releases.Asset(name, data.size.toLong(), MessageDigest.getInstance("SHA-256").digest(data).joinToString("") { "%02x".format(it) }, emptyList())

    /** The same places as cbb update: GitHub's download/vX.Y.Z, latest/download and branch channel, the mirror's vX.Y.Z and top. */
    @Test
    fun urls() {
        val (github, mirror) = ApkUpdate.SOURCES
        assertEquals("https://raw.githubusercontent.com/HunterEwok/cbb/channel/stable.json", ApkUpdate.url(github, "stable.json", null))
        assertEquals("https://raw.githubusercontent.com/HunterEwok/cbb/channel/keys.json", ApkUpdate.url(github, "keys.json", null))
        assertEquals("https://github.com/HunterEwok/cbb/releases/latest/download/release.json", ApkUpdate.url(github, "release.json", null))
        assertEquals("https://github.com/HunterEwok/cbb/releases/download/v0.6.1/release.json", ApkUpdate.url(github, "release.json", "0.6.1"))
        assertEquals("https://dl.cbb.tools/keys.json", ApkUpdate.url(mirror, "keys.json", null))
        assertEquals("https://dl.cbb.tools/v0.6.1/cbb-0.6.1.apk", ApkUpdate.url(mirror, "cbb-0.6.1.apk", "0.6.1"))
    }

    /** The phone's full APK, not the watch's or the F-Droid build's. */
    @Test
    fun picksTheApk() {
        val wear = asset(byteArrayOf(1), "cbb-wear-0.6.1.apk")
        val fdroid = asset(byteArrayOf(3), "cbb-fdroid-0.6.1.apk")
        val apk = asset(byteArrayOf(2))
        assertEquals(apk, ApkUpdate.asset(Releases.Release("0.6.1", "stable", "", listOf(wear, fdroid, apk), null)))
        assertNull(ApkUpdate.asset(Releases.Release("0.6.1", "stable", "", listOf(wear), null)))
    }

    @Test
    fun copyChecked() {
        val data = ByteArray(200_000) { it.toByte() }
        val out = ByteArrayOutputStream()
        ApkUpdate.copyChecked(ByteArrayInputStream(data), out, asset(data))
        assertArrayEquals(data, out.toByteArray())

        val longer = data + byteArrayOf(0)
        assertThrows(Releases.Refused::class.java) { ApkUpdate.copyChecked(ByteArrayInputStream(longer), ByteArrayOutputStream(), asset(data)) }
        val shorter = data.copyOf(data.size - 1)
        assertThrows(Releases.Refused::class.java) { ApkUpdate.copyChecked(ByteArrayInputStream(shorter), ByteArrayOutputStream(), asset(data)) }
        val other = data.copyOf().also { it[7] = 0 }
        assertThrows(Releases.Refused::class.java) { ApkUpdate.copyChecked(ByteArrayInputStream(other), ByteArrayOutputStream(), asset(data)) }
    }

    @Test
    fun signers() {
        val a = byteArrayOf(1, 2, 3)
        val b = byteArrayOf(4, 5)
        assertTrue(ApkUpdate.sameSigners(listOf(a, b), listOf(b.copyOf(), a.copyOf())))
        assertFalse(ApkUpdate.sameSigners(listOf(a), listOf(b)))
        assertFalse(ApkUpdate.sameSigners(listOf(a), listOf(a, b)))
        assertFalse(ApkUpdate.sameSigners(emptyList(), emptyList()))
    }

    @Test
    fun hosts() {
        assertTrue(ApkUpdate.allowedHost("github.com"))
        assertTrue(ApkUpdate.allowedHost("objects.githubusercontent.com"))
        assertTrue(ApkUpdate.allowedHost("DL.cbb.tools"))
        assertFalse(ApkUpdate.allowedHost("cbb.tools"))
        assertFalse(ApkUpdate.allowedHost("evilgithub.com"))
    }
}
