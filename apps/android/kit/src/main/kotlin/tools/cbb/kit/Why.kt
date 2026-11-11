// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull

/**
 * One reason why this phone does not sync, as the core gives it
 * (`cbb_core::why`, docs/apps.md "Why it does not sync"): a stable code the
 * app says in its own words, its level (stop, warn or info) and its
 * parameters. The member answers them ([CoreMember.why]); the Swift kit's
 * WhyReason is its twin.
 */
data class WhyReason(
    val code: String,
    val level: String,
    /** When sync turns on again, a mute ends or the certificate ends, in Unix milliseconds; 0 without a time. */
    val untilMS: Long = 0,
    /** A device's name: the hub, the admin that took the group over. */
    val device: String = "",
    /** The devices the reason is about, by name. */
    val devices: List<String> = emptyList(),
    /** A version, or a count as text. */
    val value: String = "",
    /** The member's own words for what went wrong, for the error details. */
    val detail: String = "",
) {
    companion object {
        internal fun fromJson(o: JsonObject): WhyReason = WhyReason(
            o.optString("code") ?: "",
            o.optString("level") ?: "",
            o.optLong("until_ms") ?: 0,
            o.optString("device") ?: "",
            o.optArray("devices").orEmpty().mapNotNull { (it as? JsonPrimitive)?.contentOrNull },
            o.optString("value") ?: "",
            o.optString("detail") ?: "",
        )
    }
}

/**
 * Where a tunnel the app runs itself stands, for [CoreMember.why]: the
 * phone as the hub, its sync away from home and its relay, which the member
 * does not see (`cbb_core::why::AwayFacts`).
 */
data class WhyAway(
    val hub: Boolean = false,
    val standby: Boolean = false,
    /** The hub's device ID; empty while the phone knows none. */
    val hubDevice: String = "",
    val through: Boolean = false,
    val hidden: Boolean = false,
    val relay: Boolean = false,
    val relayConnected: Boolean = false,
    val forwarder: Boolean = false,
    val forwarderRegistered: Boolean = false,
    val entriesStale: Boolean = false,
    val error: String = "",
) {
    internal fun toJson(): JsonObject = Wire.obj(
        "hub" to JsonPrimitive(hub),
        "standby" to JsonPrimitive(standby),
        "hub_device" to JsonPrimitive(hubDevice),
        "through" to JsonPrimitive(through),
        "hidden" to JsonPrimitive(hidden),
        "relay" to JsonPrimitive(relay),
        "relay_connected" to JsonPrimitive(relayConnected),
        "forwarder" to JsonPrimitive(forwarder),
        "forwarder_registered" to JsonPrimitive(forwarderRegistered),
        "entries_stale" to JsonPrimitive(entriesStale),
        "error" to JsonPrimitive(error),
    )
}
