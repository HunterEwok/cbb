// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb

import tools.cbb.kit.CoreMember
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** The hub's settings and the cards' states on a group of 0.6, from where the Live member says sync away from home stands. */
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
    fun settingsRoundTrip() {
        val p = AwayOn06.Prefs(true, HubOnPhone.Disguise.VLESS, true, listOf("a", "b"))
        assertEquals(p, AwayOn06.Prefs.decode(p.encode()))
        assertEquals(AwayOn06.Prefs(), AwayOn06.Prefs.decode(AwayOn06.Prefs().encode()))
        assertNull(AwayOn06.Prefs.decode("not json".toByteArray()))
    }

    @Test
    fun awayStatus() {
        assertEquals(AwayFromHome.Status.OFF, AwayOn06.awayStatus(null) { false })
        assertEquals(AwayFromHome.Status.OFF, AwayOn06.awayStatus(state(hub = true)) { false })
        assertEquals(AwayFromHome.Status.WAITING_FOR_HUB, AwayOn06.awayStatus(state()) { false })
        assertEquals(AwayFromHome.Status.AT_HOME, AwayOn06.awayStatus(state(hubDevice = hubID)) { it == hubID })
        assertEquals(AwayFromHome.Status.CONNECTING, AwayOn06.awayStatus(state(hubDevice = hubID)) { false })
        assertEquals(AwayFromHome.Status.CONNECTED, AwayOn06.awayStatus(state(hubDevice = hubID, through = true)) { false })
    }

    @Test
    fun hubStatus() {
        val on = AwayOn06.Prefs(on = true)
        assertEquals(HubOnPhone.Status.OFF to null, AwayOn06.hubStatus(AwayOn06.Prefs(), state(hub = true), false, true))
        assertEquals(HubOnPhone.Status.PAUSED to null, AwayOn06.hubStatus(on, state(hub = true), true, true))
        assertEquals(HubOnPhone.Status.REGISTERING to null, AwayOn06.hubStatus(on, null, false, true))
        assertEquals(HubOnPhone.Status.FAILED to "no way (bind)", AwayOn06.hubStatus(on, state(error = "no way", detail = "bind"), false, true))
        // The root set no forwarder: the hub serves at home only.
        assertEquals(HubOnPhone.Status.HOME_ONLY to null, AwayOn06.hubStatus(on, state(hub = true), false, false))
        assertEquals(HubOnPhone.Status.REGISTERING to null, AwayOn06.hubStatus(on, state(hub = true), false, true))
        val registered = CoreMember.ForwarderState("203.0.113.9:8764", true, "198.51.100.1:5000", false, "", "")
        assertEquals(HubOnPhone.Status.REGISTERED to null, AwayOn06.hubStatus(on, state(hub = true, forwarder = registered), false, true))
        val refused = registered.copy(registered = false, error = "refused", detail = "refused")
        assertEquals(HubOnPhone.Status.FAILED to "refused", AwayOn06.hubStatus(on, state(hub = true, forwarder = refused), false, true))
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
