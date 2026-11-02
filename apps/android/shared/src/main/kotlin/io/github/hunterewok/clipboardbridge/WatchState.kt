// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package io.github.hunterewok.clipboardbridge

import org.json.JSONArray
import org.json.JSONObject
import java.util.Base64

/**
 * What the phone tells its Wear OS watch, through the Wearable Data Layer:
 * the watch shows the group as the phone sees it (docs/apps.md, Wear OS),
 * as the iPhone's WatchState does for the Apple Watch. Never the clipboard.
 */
data class WatchState(
    val hasGroup: Boolean = false,
    val devices: List<Device> = emptyList(),
    /** null without a group. */
    val away: Away? = null,
    /** The latest events, newest first. */
    val events: List<String> = emptyList(),
    /** The phone's colour, by its name in Tokens.colors. */
    val color: String = "terminal",
    /** Whether the phone shows the error under its messages (its Settings); the watch does as it does. */
    val details: Boolean = false,
) {
    /**
     * can: what this watch may do to it (the kit's PhoneGroup.WatchAction
     * keys); actions: the quick actions it has on, while connected;
     * collection: the name of the phone's collection it is in, if any;
     * phone: the watch's own phone, which the phone lists first as every
     * app lists the device it runs on.
     */
    data class Device(
        val id: String,
        val name: String,
        val form: String,
        val online: Boolean,
        val can: List<String> = emptyList(),
        val actions: List<String> = emptyList(),
        val collection: String? = null,
        val phone: Boolean = false,
    )

    /**
     * The devices as the watch lists them: those in no collection, then
     * each of the phone's collections in its order (docs/apps.md,
     * "Collections and the order of the tiles"). The phone sends a
     * collection's devices one after another.
     */
    val sections: List<Pair<String?, List<Device>>>
        get() {
            val out = mutableListOf<Pair<String?, List<Device>>>(null to devices.filter { it.collection == null })
            for (d in devices) {
                val c = d.collection ?: continue
                val last = out.last()
                if (out.size > 1 && last.first == c) out[out.size - 1] = c to last.second + d else out += c to listOf(d)
            }
            return out
        }

    /** The watch's ask that the phone build the body of an emergency action (docs/protocol.md, section 10, "Watches"). */
    data class Ask(val action: String, val device: String, val name: String?, val watch: String) {
        fun encode(): ByteArray = JSONObject()
            .put("action", action).put("device", device).put("name", name ?: JSONObject.NULL).put("watch", watch)
            .toString().toByteArray()

        companion object {
            fun decode(data: ByteArray?): Ask? = data?.let {
                runCatching {
                    val o = JSONObject(String(it))
                    Ask(o.getString("action"), o.getString("device"), if (o.isNull("name")) null else o.optString("name"), o.getString("watch"))
                }.getOrNull()
            }
        }
    }

    /** What the watch signed: the body, its signature (ECDSA with SHA-256, DER) and its admin CA. */
    data class Signed(val body: ByteArray, val signature: ByteArray, val adminCA: ByteArray) {
        fun encode(): ByteArray = JSONObject()
            .put("body", b64(body)).put("signature", b64(signature)).put("adminCA", b64(adminCA))
            .toString().toByteArray()

        override fun equals(other: Any?): Boolean =
            other is Signed && body.contentEquals(other.body) && signature.contentEquals(other.signature) && adminCA.contentEquals(other.adminCA)

        override fun hashCode(): Int = body.contentHashCode()

        companion object {
            fun decode(data: ByteArray?): Signed? = data?.let {
                runCatching {
                    val o = JSONObject(String(it))
                    Signed(unb64(o.getString("body")), unb64(o.getString("signature")), unb64(o.getString("adminCA")))
                }.getOrNull()
            }
        }
    }

    /** The phone's answer to an Ask (the body) or to a Signed (done), or why it refused. */
    data class Answer(val body: ByteArray? = null, val done: Boolean = false, val refused: String? = null) {
        fun encode(): ByteArray = JSONObject()
            .put("body", body?.let { b64(it) } ?: JSONObject.NULL).put("done", done).put("refused", refused ?: JSONObject.NULL)
            .toString().toByteArray()

        override fun equals(other: Any?): Boolean =
            other is Answer && (body?.contentEquals(other.body ?: ByteArray(0)) ?: (other.body == null)) && done == other.done && refused == other.refused

        override fun hashCode(): Int = done.hashCode()

        companion object {
            fun decode(data: ByteArray?): Answer? = data?.let {
                runCatching {
                    val o = JSONObject(String(it))
                    Answer(
                        if (o.isNull("body")) null else unb64(o.getString("body")),
                        o.optBoolean("done"),
                        if (o.isNull("refused")) null else o.optString("refused"),
                    )
                }.getOrNull()
            }
        }
    }

    /** Where sync away from home stands, as the phone's Settings say it. */
    enum class Away(val key: String) {
        OFF("off"), AT_HOME("atHome"), CONNECTING("connecting"), CONNECTED("connected"), WAITING("waiting");

        companion object {
            fun of(key: String?): Away? = entries.firstOrNull { it.key == key }
        }
    }

    /**
     * The watch's answer to the root phone's CERTIFY_PATH (docs/protocol.md,
     * section 10, "Watches"): the key it made, under the device ID it picked,
     * or why it made none (refused, NOT_PROTECTED or another reason).
     */
    data class KeyRequest(val device: String = "", val name: String = "", val key: ByteArray = ByteArray(0), val refused: String? = null) {
        fun encode(): ByteArray = JSONObject()
            .put("device", device)
            .put("name", name)
            .put("key", Base64.getEncoder().encodeToString(key))
            .put("refused", refused ?: JSONObject.NULL)
            .toString()
            .toByteArray()

        override fun equals(other: Any?): Boolean =
            other is KeyRequest && device == other.device && name == other.name && key.contentEquals(other.key) && refused == other.refused

        override fun hashCode(): Int = device.hashCode()

        companion object {
            fun decode(data: ByteArray?): KeyRequest? = data?.let {
                runCatching {
                    val o = JSONObject(String(it))
                    KeyRequest(
                        o.optString("device"), o.optString("name"), Base64.getDecoder().decode(o.optString("key")),
                        if (o.isNull("refused")) null else o.optString("refused"),
                    )
                }.getOrNull()
            }
        }
    }

    /** What the root gave the watch: its admin CA, in the group with that tag. */
    data class Admission(val device: String, val adminCA: ByteArray, val group: String) {
        fun encode(): ByteArray = JSONObject()
            .put("device", device)
            .put("adminCA", Base64.getEncoder().encodeToString(adminCA))
            .put("group", group)
            .toString()
            .toByteArray()

        override fun equals(other: Any?): Boolean =
            other is Admission && device == other.device && adminCA.contentEquals(other.adminCA) && group == other.group

        override fun hashCode(): Int = device.hashCode()

        companion object {
            fun decode(data: ByteArray?): Admission? = data?.let {
                runCatching {
                    val o = JSONObject(String(it))
                    Admission(o.getString("device"), Base64.getDecoder().decode(o.getString("adminCA")), o.getString("group"))
                }.getOrNull()
            }
        }
    }

    fun encode(): ByteArray = JSONObject()
        .put("hasGroup", hasGroup)
        .put(
            "devices",
            JSONArray(
                devices.map {
                    JSONObject().put("id", it.id).put("name", it.name).put("form", it.form).put("online", it.online)
                        .put("can", JSONArray(it.can)).put("actions", JSONArray(it.actions))
                        .put("collection", it.collection ?: JSONObject.NULL).put("phone", it.phone)
                },
            ),
        )
        .put("away", away?.key ?: JSONObject.NULL)
        .put("events", JSONArray(events))
        .put("color", color)
        .put("details", details)
        .toString()
        .toByteArray()

    companion object {
        /** The data item with the state, which the phone replaces. */
        const val STATE_PATH = "/cbb/state"

        /** The watch's message that turns the phone's sync away from home on (1) or off (0). */
        const val AWAY_PATH = "/cbb/away"

        /** The root phone's ask that the watch make its admin key; the watch answers on KEY_PATH. */
        const val CERTIFY_PATH = "/cbb/certify"

        /** The watch's KeyRequest. */
        const val KEY_PATH = "/cbb/key"

        /** The root's Admission; the watch answers on ADMITTED_PATH with the device ID it kept, or nothing. */
        const val ADMITTED_PATH = "/cbb/admitted"

        /** Why a watch makes no key: it has no secure lock screen. */
        const val NOT_PROTECTED = "not-protected"

        /** The watch's Ask; the phone answers on BODY_PATH. */
        const val ASK_PATH = "/cbb/ask"
        const val BODY_PATH = "/cbb/body"

        /** What the watch signed; the phone answers on DONE_PATH. */
        const val SIGNED_PATH = "/cbb/signed"
        const val DONE_PATH = "/cbb/done"

        private fun b64(b: ByteArray): String = Base64.getEncoder().encodeToString(b)

        private fun unb64(s: String): ByteArray = Base64.getDecoder().decode(s)

        private fun strings(a: JSONArray?): List<String> = a?.let { (0 until it.length()).map { i -> it.getString(i) } } ?: emptyList()

        /** The state the phone sent, or null for anything else. */
        fun decode(data: ByteArray?): WatchState? = data?.let {
            runCatching {
                val o = JSONObject(String(it))
                val ds = o.optJSONArray("devices") ?: JSONArray()
                val es = o.optJSONArray("events") ?: JSONArray()
                WatchState(
                    hasGroup = o.optBoolean("hasGroup"),
                    devices = (0 until ds.length()).map { i ->
                        val d = ds.getJSONObject(i)
                        Device(
                            d.getString("id"), d.getString("name"), d.optString("form", "other"), d.optBoolean("online"),
                            strings(d.optJSONArray("can")), strings(d.optJSONArray("actions")),
                            if (d.isNull("collection")) null else d.getString("collection"),
                            d.optBoolean("phone"),
                        )
                    },
                    away = if (o.isNull("away")) null else Away.of(o.optString("away")),
                    events = (0 until es.length()).map { i -> es.getString(i) },
                    color = o.optString("color", "terminal"),
                    details = o.optBoolean("details"),
                )
            }.getOrNull()
        }
    }
}
