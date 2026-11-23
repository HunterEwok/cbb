// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb

import tools.cbb.kit.CoreMember

/**
 * Sync away from home and the group's relay on a group of 0.6 (docs/apps.md,
 * "Away from home"). The Live member runs the tunnel and the link to the
 * relay in the app's process, in user space, and keeps their keys itself;
 * the app maps where the member says they stand onto its cards. The relay
 * is the group's setting, which the root writes; every device meets the
 * others there. A phone is no hub (D-134).
 */
object AwayOn06 {
    /**
     * Where sync away from home stands, as Settings shows it: off; waiting
     * until a hub offered its tunnel; through it; or at home, where the
     * member reaches the hub without it.
     */
    fun awayStatus(a: CoreMember.AwayState?, reached: (String) -> Boolean): AwayFromHome.Status = when {
        a == null -> AwayFromHome.Status.OFF
        a.through -> AwayFromHome.Status.CONNECTED
        a.hubDevice.isEmpty() -> AwayFromHome.Status.WAITING_FOR_HUB
        reached(a.hubDevice) -> AwayFromHome.Status.AT_HOME
        else -> AwayFromHome.Status.CONNECTING
    }

    /** Where the link to the group's relay stands, with the reason it failed; off while the group has no relay or sync away from home is off. */
    fun relayStatus(a: CoreMember.AwayState?): Pair<RelayOnPhone.Status, String?> {
        val r = a?.relay ?: return RelayOnPhone.Status.OFF to null
        return when {
            r.connected -> RelayOnPhone.Status.CONNECTED to null
            r.error.isNotEmpty() -> RelayOnPhone.Status.FAILED to reason(r.error, r.detail)
            else -> RelayOnPhone.Status.CONNECTING to null
        }
    }

    /** The error with its underlying cause, for the log and for the error's details. */
    private fun reason(error: String, detail: String): String = if (detail.isEmpty() || detail == error) error else "$error ($detail)"
}
