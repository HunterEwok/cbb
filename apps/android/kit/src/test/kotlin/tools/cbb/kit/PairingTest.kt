// SPDX-License-Identifier: AGPL-3.0-only

package tools.cbb.kit

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Checks the pairing messages against the vectors that the Go tests write (go test ./internal/pair -update). */
class PairingTest {
    @Test
    fun goPairing() {
        val v = Interop.read("pairing.json").jsonObject
        assertEquals(v.str("channel_id"), Pairing.channelID(b64(v.str("member_cert")), b64(v.str("joiner_cert"))).toHex())
        assertEquals(v.str("fingerprint"), Pairing.fingerprint(b64(v.str("joiner_cert"))))
        val frames = v.getValue("frames").jsonArray
        for (goFrame in frames) {
            val f = Pairing.decode(Wire.encode(goFrame))
            // Encoding it again gives the same JSON object as Go's.
            val encoded = Pairing.encode(f)
            assertEquals(encoded.size - 4, Pairing.length(encoded.copyOf(4)))
            assertEquals<Any?>(goFrame, Wire.parse(encoded.copyOfRange(4, encoded.size)))
        }
        val first = Pairing.decode(Wire.encode(frames[0]))
        assertEquals(Pairing.Info("laptop", "linux"), Pairing.Info.decode(first.ad!!))
    }

    @Test
    fun goJoinQR() {
        val vs = Interop.read("joinqr.json").jsonArray
        assertTrue(vs.isNotEmpty())
        for (v in vs) {
            val o = v.jsonObject
            val got = JoinCode.parse(o.str("text"))
            val want = o["want"] as? JsonObject
            if (want == null) {
                assertNull(got, o.str("text"))
                continue
            }
            val addrs = (want["Addrs"] as? JsonArray)?.map { it.jsonPrimitive.content } ?: emptyList()
            assertEquals(JoinCode(want.str("Code"), addrs, want.str("Fingerprint")), got, o.str("text"))
            assertEquals(got, JoinCode.parse(got!!.qrText))
        }
    }

    @Test
    fun joinerShowsAndAnnouncesTheCode() {
        assertEquals("246 802", JoinCode("246802", emptyList(), "f").grouped)
        assertEquals(mapOf("v" to "1", "j" to "1", "f" to "ab+c/d="), Discovery.joinerTXT("ab+c/d="))
    }

    @Test
    fun info() {
        assertTrue(Pairing.Info("pi", "linux").isValid)
        assertFalse(Pairing.Info("", "linux").isValid)
        assertFalse(Pairing.Info("a\u0007b", "linux").isValid)
        assertTrue(Pairing.Info("Café — Büro 1", "linux").isValid)
        for (bad in listOf("evil\u202Egpj", "a\u200Bb", "a\uE000b", "a\u00A0b", "a\u2028b")) {
            assertFalse(Pairing.Info(bad, "linux").isValid, "a name is printable, as in Go: $bad")
        }
        assertTrue(Pairing.Info("pc", "windows").isValid)
        assertTrue(Pairing.Info("mac", "macos").isValid)
        assertFalse(Pairing.Info("mac", "darwin").isValid)
        assertFalse(Pairing.Info("pi", "none").isValid)
        assertTrue(Pairing.Info("board", "none", role = Pairing.Info.LITE).isValid)
        val admin = SoftwareSigner()
        val sid = ByteArray(32) { it.toByte() }
        val proved = Pairing.Info("Pixel", "android", admin.publicKeyDER).proving(sid, admin)
        assertTrue(proved.isValid)
        assertEquals(proved, Pairing.Info.decode(proved.encode()))
        assertFalse(Pairing.Info("Pixel", "android", admin.publicKeyDER).isValid, "an admin key comes with its proof")
        assertTrue(proved.provesAdminKey(sid))
        assertFalse(proved.provesAdminKey(ByteArray(32)), "a proof for another session")
        assertFalse(proved.copy(adminKey = SoftwareSigner().publicKeyDER).provesAdminKey(sid), "a proof by another key")
        assertFalse(Pairing.Info("pi", "linux", SoftwareSigner().publicKeyDER).isValid)
        assertTrue(Pairing.Info("router", "linux", role = Pairing.Info.LITE).isValid)
        assertFalse(Pairing.Info("router", "linux", role = "full").isValid)
        val lite = Pairing.Info("router", "linux", role = Pairing.Info.LITE)
        assertEquals(lite, Pairing.Info.decode(lite.encode()))
        assertTrue(JoinCode.newCode().let { JoinCode(it, emptyList(), "").codeIsValid })
        assertEquals("[fd00::1]:8764", JoinCode.address("fd00::1", 8764))
    }

    private fun JsonObject.str(key: String) = getValue(key).jsonPrimitive.content
}
