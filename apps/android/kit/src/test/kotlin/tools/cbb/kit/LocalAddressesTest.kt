// SPDX-License-Identifier: AGPL-3.0-only

package tools.cbb.kit

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class LocalAddressesTest {
    @Test
    fun home() {
        for (a in listOf("10.0.0.1", "172.16.5.4", "172.31.255.255", "192.168.1.20")) assertTrue(LocalAddresses.isHomeIPv4(a), a)
        for (a in listOf("172.15.0.1", "172.32.0.1", "100.64.0.1", "8.8.8.8", "127.0.0.1", "192.168.1", "192.168.1.300")) {
            assertFalse(LocalAddresses.isHomeIPv4(a), a)
        }
        assertTrue(LocalAddresses.isHomeIPv6("fd12:3456::1"))
        assertTrue(LocalAddresses.isHomeIPv6("FC00::1"))
        assertFalse(LocalAddresses.isHomeIPv6("fe80::1"))
        assertFalse(LocalAddresses.isHomeIPv6("fd00::1%wlan0"))
        assertFalse(LocalAddresses.isHomeIPv6("2001:db8::1"))
        // Only an address in its one spelling is judged: a name, a sign, a leading zero, a missing or
        // extra part and a zone are none.
        for (a in listOf(
            "10.1.2.3.example.org", "example.org.10.1.2.3", "10.a.1.b.2.c.3", "010.1.2.3", "+10.1.2.3", "10.1.2",
            "10.1.2.3.4", "10.1.2.256", "10..2.3", " 10.1.2.3", "10.1.2.3 ", "\u0661\u0660.1.2.3", "",
        )) {
            assertFalse(LocalAddresses.isHomeIPv4(a), a)
        }
        for (a in listOf("fd00::1", "FD12:3456::1", "fc00:0:0:0:0:0:0:1", "fd00::10.1.2.3")) assertTrue(LocalAddresses.isHomeIPv6(a), a)
        for (a in listOf(
            "fd.example.org", "fd", "fcab", "fd00::1::2", "fd00:::1", "fd00::12345", "fd00::g", "::ffff:10.1.2.3",
            "fd00:0:0:0:0:0:0:0:1", "fd00:0:0:0:0:0:0", "fd00::010.1.2.3", "fd00::1 ", "",
        )) {
            assertFalse(LocalAddresses.isHomeIPv6(a), a)
        }
        assertFalse(JoinCode.isHome("10.1.2.3.example.org:8764"))
        assertFalse(JoinCode.isHome("[fd.example.org]:8764"))
        assertTrue(JoinCode.isHome("[fd00::5]:8764"))
        // Whatever this machine has, at most four, IPv4 first, each one home.
        val now = LocalAddresses.current()
        assertTrue(now.size <= JoinCode.MAX_ADDRS)
        assertTrue(now.all { LocalAddresses.isHomeIPv4(it) || LocalAddresses.isHomeIPv6(it) })
    }
}
