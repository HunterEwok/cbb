// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb

import tools.cbb.kit.CoreMember
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.jsonPrimitive

/**
 * Sync away from home, the phone as a hub and the group's relay on a
 * group of 0.6 (docs/apps.md, "Away from home"). The Live member runs the
 * tunnel, the hub and the link to the relay in the app's process, in user
 * space as before, and keeps their keys and clients itself; the app keeps
 * only what the user chose for the hub: whether it is on, how its tunnel
 * hides, whether it runs in the background and the home networks where it
 * publishes itself. The hub's forwarder is the root's setting, which its
 * hub command names and the member keeps (CoreMember.rootForwarder), as
 * the relay is the group's setting, which the root writes; every device
 * meets the others there.
 */
class AwayOn06(private val file: SealedFile, private val log: (String, Throwable?) -> Unit) {
    /** What the user chose for the hub. */
    data class Prefs(
        val on: Boolean = false,
        val disguise: HubOnPhone.Disguise = HubOnPhone.Disguise.OBFUSCATE,
        val background: Boolean = false,
        val homes: List<String> = emptyList(),
    ) {
        fun encode(): ByteArray = JsonObject(
            mapOf(
                "on" to JsonPrimitive(on),
                "disguise" to JsonPrimitive(disguise.name),
                "background" to JsonPrimitive(background),
                "homes" to JsonArray(homes.map { JsonPrimitive(it) }),
            ),
        ).toString().toByteArray()

        companion object {
            /** The choices in b, or null when they are not ones this version wrote. */
            fun decode(b: ByteArray): Prefs? = runCatching {
                val o = Json.parseToJsonElement(b.toString(Charsets.UTF_8)) as JsonObject
                Prefs(
                    on = o["on"]?.jsonPrimitive?.booleanOrNull ?: false,
                    disguise = (o["disguise"] as? JsonPrimitive)?.content?.let { d -> HubOnPhone.Disguise.entries.firstOrNull { it.name == d } }
                        ?: HubOnPhone.Disguise.OBFUSCATE,
                    background = o["background"]?.jsonPrimitive?.booleanOrNull ?: false,
                    homes = (o["homes"] as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.content }.orEmpty(),
                )
            }.getOrNull()
        }
    }

    private val lock = Object()
    private var prefs: Prefs = runCatching { file.read()?.let(Prefs::decode) }
        .onFailure { log("cannot read the hub's settings", it) }.getOrNull() ?: Prefs()

    /** The hub's settings as the user chose them. */
    val hub: Prefs get() = synchronized(lock) { prefs }

    private fun change(f: (Prefs) -> Prefs) {
        synchronized(lock) {
            val next = f(prefs)
            file.write(next.encode())
            prefs = next
        }
    }

    fun setOn(on: Boolean, home: String?) = change { p -> p.copy(on = on, homes = if (on) withHome(p.homes, home) else p.homes) }

    fun setDisguise(d: HubOnPhone.Disguise) = change { it.copy(disguise = d) }

    fun setBackground(on: Boolean) = change { it.copy(background = on) }

    fun addHome(home: String) = change { p -> p.copy(homes = withHome(p.homes, home)) }

    /** Whether home is one of the hub's home networks. */
    fun isHome(home: String?): Boolean = home != null && home in hub.homes

    private fun withHome(homes: List<String>, home: String?): List<String> =
        if (home == null || home in homes) homes else (homes + home).takeLast(HubState.MAX_HOMES)

    /**
     * Makes the member a hub with the user's settings, as the phone of 0.5
     * was: through the forwarder the root set when there is one (byRoot;
     * the member takes it itself, VLESS there unless the tunnel is plain),
     * or at home only. A hub at home only has no address away from home, so
     * the member takes it on its home port's address.
     */
    fun serve(n: CoreMember, homeAddrs: List<String>, byRoot: CoreMember.RootForwarder?): CoreMember.AwayState? {
        val p = hub
        return n.serveAsHub(
            port = if (byRoot == null) HOME_PORT else 0,
            addrs = if (byRoot == null) homeAddrs else emptyList(),
            obfuscateOff = p.disguise == HubOnPhone.Disguise.PLAIN,
            vlessOff = p.disguise != HubOnPhone.Disguise.VLESS,
        )
    }

    companion object {
        /** The UDP port of a hub at home only, which its addresses on the home network name. */
        const val HOME_PORT = 8764

        /**
         * Where sync away from home stands, as Settings shows it: off, or
         * on a hub (which is no client of another); waiting until a hub
         * offered its tunnel; through it; or at home, where the member
         * reaches the hub without it.
         */
        fun awayStatus(a: CoreMember.AwayState?, reached: (String) -> Boolean): AwayFromHome.Status = when {
            a == null || a.hub -> AwayFromHome.Status.OFF
            a.through -> AwayFromHome.Status.CONNECTED
            a.hubDevice.isEmpty() -> AwayFromHome.Status.WAITING_FOR_HUB
            reached(a.hubDevice) -> AwayFromHome.Status.AT_HOME
            else -> AwayFromHome.Status.CONNECTING
        }

        /**
         * Where the hub stands, as Settings and Home show it, with the
         * reason it failed: paused while the app is in the background
         * without leave to run there; at home only while the root set no
         * forwarder (forwarder false); registered once the forwarder took it.
         */
        fun hubStatus(p: Prefs, a: CoreMember.AwayState?, paused: Boolean, forwarder: Boolean): Pair<HubOnPhone.Status, String?> {
            if (!p.on) return HubOnPhone.Status.OFF to null
            if (paused) return HubOnPhone.Status.PAUSED to null
            if (a == null || !a.hub) return if (a != null && a.error.isNotEmpty()) HubOnPhone.Status.FAILED to reason(a.error, a.detail) else HubOnPhone.Status.REGISTERING to null
            if (!forwarder) return HubOnPhone.Status.HOME_ONLY to null
            val f = a.forwarder ?: return HubOnPhone.Status.REGISTERING to null
            return when {
                f.registered -> HubOnPhone.Status.REGISTERED to null
                f.error.isNotEmpty() -> HubOnPhone.Status.FAILED to reason(f.error, f.detail)
                else -> HubOnPhone.Status.REGISTERING to null
            }
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
}
