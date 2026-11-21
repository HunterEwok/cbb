// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb

/**
 * The phone at the group's blind relay, as the screens show it. On a group
 * of 0.6 the Live member links to the relay the root set (AwayOn06); a
 * phone of a group of 0.5 syncs at home only (D-123).
 */
object RelayOnPhone {
    /** What the screens show. */
    enum class Status { OFF, PAUSED, CONNECTING, CONNECTED, FAILED }
}
