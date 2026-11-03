// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

/**
 * What the group's records stop and what ends it, for the apps to show
 * (docs/protocol.md, section 10, "Stopping the exchange"): the group's stop,
 * each conflict, each claim that waits or stops the group, and the records of
 * a later version. The root ends a conflict or a claim with a resolve of
 * records, or by removing a device. The twin of the Swift kit's GroupAlert.
 */
class GroupAlert(
    val kind: Kind,
    /** The names of the devices involved, and their IDs, those known here. */
    val names: List<String> = emptyList(),
    val devices: List<String> = emptyList(),
    /** The records a resolve names to end it. */
    val records: List<ByteArray> = emptyList(),
    /** How long a pending claim waits still; null when this device does not know yet. */
    val leftMS: Long? = null,
    val count: Int = 0,
) {
    enum class Kind {
        /** Every member exchanges records only. */
        STOPPED,

        /** No member sends a secret. */
        SECRETS_STOPPED,

        /** A key signed two histories: the root voids both (records). */
        TWO_HISTORIES,

        /** Admins removed or froze each other: the root removes one (devices). */
        ADMINS,

        /** Two claims under one root: the root cancels one or both (records). */
        CLAIMS,

        /** A claim waits (leftMS) unless the root cancels it (records). */
        CLAIM_PENDING,

        /** A claim another admin removed or that competes with another: the group stops until the root cancels it (records). */
        CLAIM_STOPPED,

        /** Records of a later version: update the app (count). */
        NEWER,
    }

    val id: String get() = kind.name + ":" + devices.joinToString(",") + records.joinToString("") { it.toHex() }
}

/** The device of a signer's key: the device whose admin key it is, or the root's own device for a root's key. */
fun RecordSet.deviceOfSigner(k: ByteArray): RecordSet.Device? =
    devices.firstOrNull { it.adminKey?.contentEquals(k) == true }
        ?: if (view.state.roots.any { it.contentEquals(k) }) devices.firstOrNull { it.id == rootDevice } else null

/** The alerts of the state, in the order the apps show them. */
val RecordSet.alerts: List<GroupAlert>
    get() {
        val st = view.state
        val out = mutableListOf<GroupAlert>()
        when (st.stop) {
            "full" -> out.add(GroupAlert(GroupAlert.Kind.STOPPED))
            "secrets" -> out.add(GroupAlert(GroupAlert.Kind.SECRETS_STOPPED))
        }
        fun involved(keys: List<ByteArray>): List<RecordSet.Device> = keys.mapNotNull { deviceOfSigner(it) }
        for (c in st.conflicts) {
            val kind = when (c.kind) {
                "two_histories" -> GroupAlert.Kind.TWO_HISTORIES
                "admins" -> GroupAlert.Kind.ADMINS
                "claims" -> GroupAlert.Kind.CLAIMS
                else -> continue
            }
            val who = involved(c.signers)
            out.add(GroupAlert(kind, who.map { it.name }, who.map { it.id }, c.records))
        }
        for (c in st.claims) {
            val who = involved(listOf(c.claimant))
            when (c.state) {
                "pending" -> out.add(GroupAlert(GroupAlert.Kind.CLAIM_PENDING, who.map { it.name }, who.map { it.id }, listOf(c.record), c.leftMS))
                "disputed", "competing" -> out.add(GroupAlert(GroupAlert.Kind.CLAIM_STOPPED, who.map { it.name }, who.map { it.id }, listOf(c.record)))
            }
        }
        if (st.newer > 0) out.add(GroupAlert(GroupAlert.Kind.NEWER, count = st.newer))
        return out
    }
