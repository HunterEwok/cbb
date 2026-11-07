// SPDX-License-Identifier: AGPL-3.0-only

package tools.cbb.kit

import java.io.IOException
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class DiscoveryTest {
    private val dev = "0123456789abcdef0123456789abcdef"

    @Test
    fun txt() {
        assertEquals(FoundMember(dev, "0011223344556677", true), Discovery.member(dev, listOf("v=1", "g=0011223344556677", "p=1")))
        // Keys without regard to case, the value after the first "=", the first of a repeated key.
        assertEquals(FoundMember(dev, "a=b", false), Discovery.member(dev, listOf("G=a=b", "g=other", "x")))
        assertNull(Discovery.member(dev, emptyList<String>())?.group)
        assertEquals(FoundMember(dev, "77"), Discovery.member(dev, mapOf("g" to "77".toByteArray(), "p" to "0".toByteArray(), "x" to null)))
        assertNull(Discovery.member("printer", listOf("g=77")))
        assertNull(Discovery.member(dev.uppercase(), listOf("g=77")))
    }

    @Test
    fun withKnown() {
        val other = "fedcba9876543210fedcba9876543210"
        val found = setOf(FoundMember(dev, "g1", true))
        // A member browsing finds stays as found; one it does not find is added by its known address.
        assertEquals(found + FoundMember(other, "g1"), Discovery.withKnown(found, setOf(dev, other), "g1"))
        assertEquals(found, Discovery.withKnown(found, emptySet(), "g1"))
    }

}
