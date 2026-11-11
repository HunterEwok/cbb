// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put

/**
 * The bug report (docs/core-api.md, "Bug reports"): the core builds and
 * seals the report and keeps the state; this class keeps that state where
 * [load] and [save] say (the app's settings), posts with [post] and sends
 * again what waits. [post] takes the URL and the body and returns the
 * server's answer, or throws when the report did not go.
 */
class BugReports(
    private val load: () -> String?,
    private val save: (String) -> Unit,
    private val post: (url: String, body: ByteArray) -> String,
    private val now: () -> Long = System::currentTimeMillis,
) {
    /**
     * What the core made of a break: the report as "Technical details" shows
     * it, the body to post, what the app does ([action]: `ask`, `send` or
     * `skip`), whether the dialog offers "Always allow", and the version that
     * fixes this break, as the server said.
     */
    class Offer(
        val action: String,
        val report: JsonObject,
        val fingerprint: String,
        val version: String,
        val post: String,
        val url: String,
        val offerAlways: Boolean,
        val fixedIn: String,
    ) {
        /** The report as text, for "Technical details". */
        val text: String get() = report.toString()
    }

    /**
     * The break the app tells: [kind] `panic` or `error`, the refusal's
     * code, name, message and details, the app and system, CBB's [log]
     * (oldest first) and [names] that must not leave the device.
     */
    class Input(
        val kind: String,
        val code: Int,
        val name: String,
        val message: String,
        val details: String,
        val app: String,
        val version: String,
        val build: String = "",
        val os: String = "",
        val osVersion: String = "",
        val model: String = "",
        val arch: String = "",
        val log: List<String> = emptyList(),
        val names: List<String> = emptyList(),
    )

    private fun state(): JsonElement =
        load()?.let { runCatching { kotlinx.serialization.json.Json.parseToJsonElement(it) }.getOrNull() } ?: JsonObject(emptyMap())

    private fun keep(answer: JsonElement) {
        answer.jsonObject["state"]?.let { save(it.toString()) }
    }

    /** What the core makes of a break, with the state kept. */
    @Synchronized
    fun offer(i: Input): Offer {
        val input = buildJsonObject {
            put("kind", i.kind)
            put("code", i.code)
            put("name", i.name)
            put("message", i.message)
            put("details", i.details)
            put("app", i.app)
            put("version", i.version)
            put("build", i.build)
            put("os", i.os)
            put("os_version", i.osVersion)
            put("model", i.model)
            put("arch", i.arch)
            put("log", JsonArray(i.log.map { JsonPrimitive(it) }))
            put("names", JsonArray(i.names.map { JsonPrimitive(it) }))
            put("now_ms", now())
        }
        val a = Core.run("bug_report", buildJsonObject {
            put("input", input)
            put("state", state())
        }).jsonObject
        val report = a.getValue("report").jsonObject
        return Offer(
            action = a.getValue("action").jsonPrimitive.content,
            report = report,
            fingerprint = a.getValue("fingerprint").jsonPrimitive.content,
            version = report.getValue("version").jsonPrimitive.content,
            post = a.getValue("post").jsonPrimitive.content,
            url = a.getValue("url").jsonPrimitive.content,
            offerAlways = a.getValue("offer_always").jsonPrimitive.boolean,
            fixedIn = a.getValue("fixed_in").jsonPrimitive.content,
        )
    }

    /** The user allowed a report, and maybe always. */
    @Synchronized
    fun allow(always: Boolean) {
        keep(Core.run("bug_allow", buildJsonObject {
            put("state", state())
            put("always", always)
        }))
    }

    /**
     * Posts the report; one that does not go waits and goes with [resend].
     * Returns the version the server says fixes the break, empty when it
     * says none, or null when the report did not go.
     */
    fun send(o: Offer): String? = send(o.fingerprint, o.version, o.post, o.url)

    private fun send(fingerprint: String, version: String, body: String, url: String): String? {
        if (body.isEmpty()) return null
        val fixed = runCatching {
            val answer = post(url, body.toByteArray())
            runCatching { kotlinx.serialization.json.Json.parseToJsonElement(answer).jsonObject["fixed_in"]?.jsonPrimitive?.content }
                .getOrNull().orEmpty()
        }.getOrNull()
        synchronized(this) {
            keep(Core.run("bug_sent", buildJsonObject {
                put("state", state())
                put("fingerprint", fingerprint)
                put("version", version)
                put("post", body)
                put("ok", fixed != null)
                put("fixed_in", fixed.orEmpty())
                put("now_ms", now())
            }))
        }
        return fixed
    }

    /** Sends the reports that wait, as when the network is back; returns how many went. */
    fun resend(url: String = URL): Int {
        val queue = synchronized(this) {
            val a = Core.run("bug_pending", buildJsonObject {
                put("state", state())
                put("now_ms", now())
            }).jsonObject
            keep(a)
            a.getValue("queue").jsonArray.map { it.jsonObject }
        }
        return queue.count { q ->
            send(
                q.getValue("fingerprint").jsonPrimitive.content,
                q.getValue("version").jsonPrimitive.content,
                q.getValue("post").jsonPrimitive.content,
                url,
            ) != null
        }
    }

    companion object {
        /** Where reports go (cbb_core::bug::URL). */
        const val URL = "https://bug.cbb.tools/"
    }
}
