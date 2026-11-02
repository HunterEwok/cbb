// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package io.github.hunterewok.clipboardbridge

import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.Socket
import java.net.URLDecoder
import java.net.URLEncoder

/**
 * The bench's helper on the computer that runs the emulator (tools/bench,
 * the phone suite): it runs cbb on the fleet's members, copies there and
 * waits for a text. One JSON request a line and one answer a line, over a
 * plain socket, which the app's network rules leave alone. The suite passes
 * its address as the instrumentation argument helper; without it the tests
 * that need a group are skipped.
 */
object Bench {
    val address: String? = InstrumentationRegistry.getArguments().getString("helper")

    /** A failure the helper reported, with the command's output. */
    class Failed(message: String, val output: String) : AssertionError(if (output.isBlank()) message else "$message\n$output")

    private fun call(vararg fields: Pair<String, Any>): JsonObject {
        val (host, port) = address!!.split(":").let { it[0] to it[1].toInt() }
        Socket(host, port).use { s ->
            s.soTimeout = 10 * 60 * 1000
            val req = buildJsonObject {
                for ((k, v) in fields) put(k, when (v) { is Number -> JsonPrimitive(v); is Boolean -> JsonPrimitive(v); else -> JsonPrimitive(v.toString()) })
            }
            val w = OutputStreamWriter(s.getOutputStream(), Charsets.UTF_8)
            w.write(req.toString() + "\n")
            w.flush()
            val line = BufferedReader(InputStreamReader(s.getInputStream(), Charsets.UTF_8)).readLine()
                ?: throw AssertionError("the bench's helper hung up")
            val a = Json.parseToJsonElement(line) as JsonObject
            a.str("error")?.let { throw Failed("${fields.first().second}: $it", a.str("out").orEmpty()) }
            return a
        }
    }

    private fun JsonObject.str(k: String): String? = (get(k) as? JsonPrimitive)?.takeIf { it.isString }?.content

    /** The first member, which the suite starts in no group. */
    const val PC = "m01"

    /** Starts another member in no group; its name. */
    fun add(): String = call("op" to "add").str("dev")!!

    /**
     * Starts another member in no group with a UDP port for a hub's tunnel,
     * the same number on the emulator's host and in the member; its name and
     * the port, which this emulator dials at 10.0.2.2.
     */
    fun addHub(): Pair<String, Int> {
        val a = call("op" to "add", "udp" to true)
        return a.str("dev")!! to a["port"]!!.jsonPrimitive.content.toInt()
    }

    /**
     * Starts the run's forwarder, once; its address as this emulator dials
     * it, which the members reach too, and its key.
     */
    fun forwarder(): Pair<String, String> {
        val a = call("op" to "forwarder")
        return a.str("addr")!! to a.str("out")!!
    }

    /** This computer's loopback as the emulator dials it. */
    const val HOST = "10.0.2.2"

    /** The member's port as this emulator dials it. */
    fun addr(dev: String): String = call("op" to "addr", "dev" to dev).str("addr")!!

    /** Runs cmd with sh on the member; what it printed. */
    fun run(dev: String, cmd: String, stdin: String = "", seconds: Int = 0): String =
        call("op" to "run", "dev" to dev, "cmd" to cmd, "text" to stdin, "seconds" to seconds).str("out").orEmpty()

    /** The last lines of the member's service log, for a failure's message. */
    fun logs(dev: String): String = runCatching { call("op" to "logs", "dev" to dev).str("out").orEmpty() }.getOrElse { it.toString() }

    /** Copies text on the member as its user would. */
    fun copy(dev: String, text: String) {
        call("op" to "copy", "dev" to dev, "text" to text)
    }

    /** Waits until the member has text on its clipboard; fails with what it has instead. */
    fun arrives(dev: String, text: String, seconds: Int = 30) {
        call("op" to "arrives", "dev" to dev, "text" to text, "seconds" to seconds)
    }

    /** A command that runs on, such as cbb pair. */
    class Job(val id: String) {
        fun output(): Pair<String, Boolean> {
            val a = call("op" to "output", "id" to id)
            return a.str("out").orEmpty() to (a["done"]?.jsonPrimitive?.content == "true")
        }

        fun stop() {
            call("op" to "stop", "id" to id)
        }

        /** Waits until the output has a line that starts with prefix; the rest of that line. */
        fun line(prefix: String, seconds: Int = 60): String {
            val deadline = System.currentTimeMillis() + seconds * 1000L
            while (true) {
                val (out, done) = output()
                out.lineSequence().firstOrNull { it.trimStart().startsWith(prefix) }?.let { return it.trimStart().removePrefix(prefix).trim() }
                if (done || System.currentTimeMillis() > deadline) throw AssertionError("no line \"$prefix\" in:\n$out")
                Thread.sleep(250)
            }
        }

        /** Waits until the command ends; what it printed. */
        fun finish(seconds: Int = 60): String {
            val deadline = System.currentTimeMillis() + seconds * 1000L
            while (true) {
                val (out, done) = output()
                if (done) return out
                if (System.currentTimeMillis() > deadline) throw AssertionError("still running after ${seconds}s:\n$out")
                Thread.sleep(250)
            }
        }
    }

    fun start(dev: String, cmd: String): Job = Job(call("op" to "start", "dev" to dev, "cmd" to cmd).str("id")!!)

    /**
     * Runs cbb pair on the member, which is in no group, and returns its QR
     * code's text with the member's port as this emulator dials it in place
     * of the addresses inside the fleet's network, and the job, which ends
     * once the phone admitted the member.
     */
    fun pairCode(dev: String): Pair<String, Job> {
        val job = start(dev, "cbb pair </dev/null")
        val text = job.line("Or paste this into the app:")
        val query = text.substringAfter('?').split('&').associate { p ->
            p.substringBefore('=') to URLDecoder.decode(p.substringAfter('=', ""), "UTF-8")
        }
        val code = query["code"] ?: throw AssertionError("no code in $text")
        val fp = query["fp"] ?: throw AssertionError("no fingerprint in $text")
        val port = query["addr"]?.substringAfterLast(':')
        if (port != "8764") throw AssertionError("$dev waits for the phone on port $port, not the member port the suite publishes: $text")
        val enc = { s: String -> URLEncoder.encode(s, "UTF-8") }
        return "clipboardbridge://join?code=${enc(code)}&addr=${enc(addr(dev))}&fp=${enc(fp)}" to job
    }
}
