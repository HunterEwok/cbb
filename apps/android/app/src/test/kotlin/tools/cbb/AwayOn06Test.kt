// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb

import tools.cbb.kit.CoreMember
import org.junit.Assert.assertEquals
import org.junit.Test

/** The cards' states on a group of 0.6, from where the Live member says sync away from home stands. */
class AwayOn06Test {
    private val hubID = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"

    private fun state(
        hub: Boolean = false,
        hubDevice: String = "",
        through: Boolean = false,
        forwarder: CoreMember.ForwarderState? = null,
        relay: CoreMember.RelayState? = null,
        error: String = "",
        detail: String = "",
    ) = CoreMember.AwayState(hub, false, 0, 0, true, false, emptyList(), hubDevice, through, true, forwarder, relay, error, detail)

    @Test
    fun awayStatus() {
        assertEquals(AwayFromHome.Status.OFF, AwayOn06.awayStatus(null) { false })
        assertEquals(AwayFromHome.Status.WAITING_FOR_HUB, AwayOn06.awayStatus(state()) { false })
        assertEquals(AwayFromHome.Status.AT_HOME, AwayOn06.awayStatus(state(hubDevice = hubID)) { it == hubID })
        assertEquals(AwayFromHome.Status.CONNECTING, AwayOn06.awayStatus(state(hubDevice = hubID)) { false })
        assertEquals(AwayFromHome.Status.CONNECTED, AwayOn06.awayStatus(state(hubDevice = hubID, through = true)) { false })
    }

    @Test
    fun relayStatus() {
        assertEquals(RelayOnPhone.Status.OFF to null, AwayOn06.relayStatus(null))
        assertEquals(RelayOnPhone.Status.OFF to null, AwayOn06.relayStatus(state()))
        val r = CoreMember.RelayState("203.0.113.9:8764", false, emptyList(), "", "")
        assertEquals(RelayOnPhone.Status.CONNECTING to null, AwayOn06.relayStatus(state(relay = r)))
        assertEquals(RelayOnPhone.Status.CONNECTED to null, AwayOn06.relayStatus(state(relay = r.copy(connected = true))))
        assertEquals(RelayOnPhone.Status.FAILED to "timed out (udp)", AwayOn06.relayStatus(state(relay = r.copy(error = "timed out", detail = "udp"))))
    }
}
