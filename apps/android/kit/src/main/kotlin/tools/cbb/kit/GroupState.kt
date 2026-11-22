// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull

/**
 * The group as the 0.6 member sees it (the member's `group` op and its `state` event): who is
 * the root, this device's place, whether the group is stopped and its devices. The member
 * evaluates the records; the app only shows this. The Swift kit's GroupState is its twin.
 */
data class GroupState(
    /** The Group ID, base64. */
    val group: String,
    /** The current root's key hash, base64. */
    val root: String,
    /** The root's device ID, empty while the root has none in the group. */
    val rootDevice: String,
    val me: Me,
    /** none, secrets (no secrets are sealed) or full (nothing but the root's own records counts). */
    val stop: String,
    /** The recovery chain has two records at one step, or one this version cannot read: the group stopped for good here. */
    val halted: Boolean,
    /** A recovery record this version cannot read: update the app. */
    val updateNeeded: Boolean,
    /** The settings ask for newer rules than this version's: no secrets here. */
    val tooOld: Boolean,
    /** A change of root is arriving: its records are not all here yet. */
    val changeArriving: Boolean,
    val devices: List<Device>,
    /** The group's key level: proven, hardware or files (Records.KEY_LEVELS). */
    val keyLevel: String = Records.HARDWARE,
    /** How long a copy from another device stays live, as the newest copies record sets it; null for the default. */
    val incomingMS: Long? = null,
) {
    /** This device's place in the group. */
    data class Me(
        val device: String,
        /** phone, computer, watch, board, … as the device record says. */
        val role: String,
        /** The admin key the records name for it is one of the group's admins. */
        val admin: Boolean,
        val frozen: Boolean,
        val leaf: Boolean,
    )

    /** One device the group counts; removed devices are not listed. */
    data class Device(
        val device: String,
        val name: String,
        val os: String,
        val role: String,
        /** The admin key the records name for it is one of the group's admins. */
        val admin: Boolean,
        val frozen: Boolean,
        val hub: Boolean,
    )

    val stopped: Boolean get() = stop == "full" || halted

    /** This device is the group's root. */
    val isRoot: Boolean get() = me.device.isNotEmpty() && me.device == rootDevice

    companion object {
        fun fromJson(o: JsonObject): GroupState {
            val me = o.optObject("me")
            return GroupState(
                group = o.optString("group") ?: "",
                root = o.optString("root") ?: "",
                rootDevice = o.optString("root_device") ?: "",
                me = Me(
                    device = me?.optString("device") ?: "",
                    role = me?.optString("role") ?: "",
                    admin = me?.optBool("admin") ?: false,
                    frozen = me?.optBool("frozen") ?: false,
                    leaf = me?.optBool("leaf") ?: false,
                ),
                stop = o.optString("stop") ?: "none",
                halted = o.optBool("halted") ?: false,
                updateNeeded = o.optBool("update_needed") ?: false,
                tooOld = o.optBool("too_old") ?: false,
                changeArriving = o.optBool("change_arriving") ?: false,
                keyLevel = o.optString("key_level") ?: Records.HARDWARE,
                incomingMS = o.optLong("incoming_ms"),
                devices = o.objects("devices").map {
                    Device(
                        device = it.optString("device") ?: "",
                        name = it.optString("name") ?: "",
                        os = it.optString("os") ?: "",
                        role = it.optString("role") ?: "",
                        admin = it.optBool("admin") ?: false,
                        frozen = it.optBool("frozen") ?: false,
                        hub = it.optBool("hub") ?: false,
                    )
                },
            )
        }
    }
}

/**
 * A notice of the member (its `notices` op and `notice` event): something the person should
 * know about the group's records, such as a silent admin or a change of root arriving. kind
 * names it, args are its parameters, which the app says in its own words.
 */
data class Notice(
    val id: String,
    /**
     * change_arriving, admins_silent, removal_warning, removals_waiting, root_room_waiting,
     * ack_owed, frozen_holding, checkpoint_stuck, returned_after_removal or recovery_not_saved.
     */
    val kind: String,
    val args: Map<String, String>,
    val dismissable: Boolean,
) {
    companion object {
        fun fromJson(o: JsonObject): Notice = Notice(
            id = o.optString("id") ?: "",
            kind = o.optString("kind") ?: "",
            args = o.optObject("args")?.mapNotNull { (k, v) -> (v as? JsonPrimitive)?.contentOrNull?.let { k to it } }?.toMap().orEmpty(),
            dismissable = o.optBool("dismissable") ?: true,
        )
    }
}

/**
 * The list a change of root shows before it is signed ("who stays", the member's
 * `change_preview`): one row per device of the group, with what the change does to it.
 * The core writes the list; the person only unticks devices, each untick a removal the new
 * root signs in the same act.
 */
data class ChangePreview(
    val rows: List<Row>,
    /** A change already waits for its records: sync first, and write over it only after that fails. */
    val waiting: Boolean,
) {
    data class Row(
        val device: String,
        val name: String,
        val os: String,
        /** stays, out, admin_kept, admin_lost, frozen or removed_earlier. */
        val outcome: String,
        /** Re-issued frozen: it acts only once the new root thaws it. */
        val frozen: Boolean,
    )

    companion object {
        fun fromJson(o: JsonObject): ChangePreview = ChangePreview(
            rows = o.objects("rows").map {
                Row(
                    device = it.optString("device") ?: "",
                    name = it.optString("name") ?: "",
                    os = it.optString("os") ?: "",
                    outcome = it.optString("outcome") ?: "",
                    frozen = it.optBool("frozen") ?: false,
                )
            },
            waiting = o.optBool("waiting") ?: false,
        )
    }
}

/** The group's recovery key as the person gives it to a change of root: the sheet's QR code, its typed text, or the secret a YubiKey opened. */
sealed class RecoveryInput {
    data class Qr(val text: String) : RecoveryInput()

    data class Text(val text: String) : RecoveryInput()

    class Secret(val bytes: ByteArray) : RecoveryInput()

    internal fun toJson(): JsonObject = when (this) {
        is Qr -> Wire.obj("qr" to Wire.str(text))
        is Text -> Wire.obj("text" to Wire.str(text))
        is Secret -> Wire.obj("secret" to Wire.bytes(bytes))
    }
}

internal fun JsonObject.objects(key: String): List<JsonObject> = (optArray(key) ?: JsonArray(emptyList())).mapNotNull { it as? JsonObject }
