// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.test.Test

class TunnelSettingsTest {
    /** The group path of a VLESS user ID is the forwarder's and the Rust member's (section 13, "VLESS"). */
    @Test
    fun groupPathOfAUserId() {
        assertEquals("FAf82MUKFMjUNz3SkIYXXw", TunnelSettings.groupPath("6f1c2b9e-3d4a-4f5b-8c7d-0e1f2a3b4c5d"))
        assertEquals("mefvDB5qwj9eeFnyKOOk4A", TunnelSettings.groupPath("0b6e7f10-2a3b-4c5d-9e8f-112233445566"))
    }

    /** Only a UUID of version 4 in lowercase is a VLESS user ID. */
    @Test
    fun userIds() {
        assertTrue(TunnelSettings.isUserId("0b6e7f10-2a3b-4c5d-9e8f-112233445566"))
        for (bad in listOf(
            "", "0b6e7f10-2a3b-3c5d-9e8f-112233445566", "0b6e7f10-2a3b-4c5d-7e8f-112233445566",
            "0B6E7F10-2A3B-4C5D-9E8F-112233445566", "0b6e7f102a3b-4c5d-9e8f-1122334455667", "0b6e7f10-2a3b-4c5d-9e8f-11223344556",
        )) {
            assertFalse(TunnelSettings.isUserId(bad), bad)
        }
    }

    private fun obf(jc: Int = 4, h2: String = "300-400", s2: Int = 40, jmax: Int = 300, key: String = KEY) =
        """{"jc":$jc,"jmin":50,"jmax":$jmax,"s1":20,"s2":$s2,"s3":16,"s4":24,"h1":"100-200","h2":"$h2",""" +
            """"h3":"500-600","h4":"700-800","header_protection_key":"$key"}"""

    private fun way(path: String, id: String, endpoint: String = "203.0.113.9:443", name: String = "cbb.tools") =
        """{"transport":"xhttp","endpoint":"$endpoint","server_name":"$name","path":"$path","id":"$id"}"""

    /** Obfuscation settings are taken within the bounds of the Rust member's and internal/tunnel's checks. */
    @Test
    fun obfuscationBounds() {
        assertTrue(TunnelSettings.obfuscationValid(obf()))
        for (bad in listOf(
            obf(jc = 17), obf(jmax = 1001), obf(jmax = 40), obf(s2 = 96), obf(s2 = 8), obf(s2 = 76),
            obf(h2 = "150-250"), obf(h2 = "4-40"), obf(h2 = "0300-400"), obf(h2 = "400-300"), obf(h2 = "300"),
            obf(h2 = "300-4294967296"), obf(key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="), obf(key = "CAgI"),
            obf(key = "not base64!"), """{"jc":4}""", """{"jc":"4"}""", "[]", "{",
        )) {
            assertFalse(TunnelSettings.obfuscationValid(bad), bad)
        }
    }

    /** The next way over VLESS goes to the same forwarder with the path made for its user ID. */
    @Test
    fun nextWayOverVless() {
        val now = way("/banMEJvnYJJap8S/AbCdEfGhIjKlMnOpQr", "5f0c1e2d-3b4a-4c5d-8e6f-7a8b9c0d1e2f")
        val id = "0b6e7f10-2a3b-4c5d-9e8f-112233445566"
        assertTrue(TunnelSettings.isNextVless(way("/banMEJvnYJJap8S/mefvDB5qwj9eeFnyKOOk4A", id), now))
        for (bad in listOf(
            way("/banMEJvnYJJap8S/mefvDB5qwj9eeFnyKOOk4A", id, endpoint = "198.51.100.7:443"),
            way("/banMEJvnYJJap8S/mefvDB5qwj9eeFnyKOOk4A", id, name = "example.com"),
            way("/banMEJvnYJJap8S/AbCdEfGhIjKlMnOpQr", id),
            way("/otherBase0/mefvDB5qwj9eeFnyKOOk4A", id),
            way("/banMEJvnYJJap8S/mefvDB5qwj9eeFnyKOOk4A", id.uppercase()),
            """{"id":"$id"}""", "{",
        )) {
            assertFalse(TunnelSettings.isNextVless(bad, now), bad)
        }
        assertFalse(TunnelSettings.isNextVless(way("/banMEJvnYJJap8S/mefvDB5qwj9eeFnyKOOk4A", id), """{"endpoint":"203.0.113.9:443"}"""))
    }

    private companion object {
        const val KEY = "CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg="
    }
}
