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
        // Whatever this machine has, at most four, IPv4 first, each one home.
        val now = LocalAddresses.current()
        assertTrue(now.size <= JoinCode.MAX_ADDRS)
        assertTrue(now.all { LocalAddresses.isHomeIPv4(it) || LocalAddresses.isHomeIPv6(it) })
    }
}
