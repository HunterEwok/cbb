// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package io.github.hunterewok.clipboardbridge.kit

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class StrictTest {
    private val v = Interop.read("strict.json").jsonObject

    private fun cases(kind: String): List<Triple<String, ByteArray, Boolean>> =
        v.getValue(kind).jsonArray.map {
            val o = it.jsonObject
            Triple(o.str("name"), b64(o.str("body")), o.getValue("valid").jsonPrimitive.boolean)
        }.also { assertTrue(it.isNotEmpty(), "no $kind") }

    /** Whether the core's check_body takes a record body. */
    private fun takes(body: ByteArray): Boolean = runCatching { Core.run("check_body", Wire.obj("body" to Wire.bytes(body))) }.isSuccess

    /** Well-formed record bodies of version 2: the records of the cases of testdata/interop/v2-records.json that hold only good records. */
    private fun goodBodies(): List<ByteArray> {
        val good = listOf("basic", "powers", "hubs table", "freeze and thaw", "claim waits and takes effect")
        val bodies = Interop.read("v2-records.json").jsonObject.getValue("cases").jsonArray.map { it.jsonObject }
            .filter { c -> good.any { c.str("name").startsWith(it) } }
            .flatMap { c -> c.getValue("records").jsonArray.map { Member.Record.fromJson(it.jsonObject).body } }
        assertTrue(bodies.isNotEmpty())
        return bodies
    }

    /**
     * Record bodies of version 2 are the Rust core's to check (check_body): each good body passes, and the same body
     * with a field the rows do not have, its keys out of order or a space in front does not.
     */
    @Test
    fun records() {
        assertTrue(cases("records").isNotEmpty())
        for (body in goodBodies()) {
            val text = String(body)
            assertTrue(takes(body), text)
            for (b in listOf("{\"zz\":1," + text.drop(1), " $text", "{\"a\":1," + text.drop(1))) assertFalse(takes(b.toByteArray()), b)
            val o = Json.parseToJsonElement(text).jsonObject
            val reordered = JsonObject(o.entries.reversed().associate { it.toPair() }).toString()
            if (reordered != text) assertFalse(takes(reordered.toByteArray()), reordered)
        }
    }

    @Test
    fun commands() {
        for ((name, body, valid) in cases("commands")) {
            val got = runCatching { Commands.parse(body) }
            assertEquals(valid, got.isSuccess, "command $name: ${got.exceptionOrNull()?.message}")
        }
    }

    @Test
    fun manifests() {
        for ((name, body, valid) in cases("manifests")) {
            val got = runCatching { Wire.parse(body)?.let { Media.Manifest.fromJson(it) }?.isValid == true }.getOrDefault(false)
            assertEquals(valid, got, "manifest $name")
        }
    }

    /**
     * testdata/interop/strict-generated.json, from the tables of docs/protocol.md: the kit takes exactly the bodies the
     * tables take, and says which row it reads otherwise.
     */
    @Test
    fun generated() {
        val v = Interop.read("strict-generated.json").jsonObject
        for (kind in listOf("records", "commands", "manifests")) assertTrue(v.getValue(kind).jsonArray.isNotEmpty(), "no $kind")
        val wrong = strictWrong(v)
        assertTrue(wrong.isEmpty(), "${wrong.size} vectors read otherwise:\n" + wrong.joinToString("\n"))
    }

    /** testdata/interop/strict-mutants-*.json: valid bodies changed byte by byte, each with the verdict of the tables of docs/protocol.md. */
    @Test
    fun mutants() {
        val wrong = mutableListOf<String>()
        var n = 0
        generateSequence(1) { it + 1 }.map { File(Interop.dir, "strict-mutants-$it.json") }.takeWhile { it.exists() }.forEach { f ->
            val v = Interop.read(f.name).jsonObject
            n += listOf("records", "commands").sumOf { v[it]?.jsonArray?.size ?: 0 }
            wrong += strictWrong(v)
        }
        assertTrue(n > 0, "no mutant vectors")
        // Mutants of good record bodies of version 2, each refused by the core: a field every record has dropped, a version or an alg
        // it does not know, a number written as a float or with a sign, a duplicate key, a null.
        for (body in goodBodies()) {
            val text = String(body)
            val o = Json.parseToJsonElement(text).jsonObject
            val mutants = REQUIRED.filter { it in o }.map { k -> JsonObject(o - k).toString() } + listOf(
                text.replace("\"v\":2", "\"v\":3"),
                text.replace("\"alg\":\"es256\"", "\"alg\":\"rs256\""),
                text.replace("\"v\":2", "\"v\":2.0"),
                text.replace("\"v\":2", "\"v\":+2"),
                text.replace("\"v\":2", "\"v\":2,\"v\":2"),
                text.replace("\"v\":2", "\"v\":null"),
            )
            for (m in mutants) if (m != text && takes(m.toByteArray())) wrong += "record mutant taken: $m"
        }
        assertTrue(wrong.isEmpty(), "${wrong.size} vectors read otherwise:\n" + wrong.joinToString("\n"))
    }

    /**
     * The vectors of a file in the form of strict-generated.json that the kit reads otherwise. A record is taken when
     * its decoder returns a body and a command when its parser does; a reader refuses only by returning null or by its
     * own exception, so any other exception fails the test.
     */
    private fun strictWrong(v: JsonObject): List<String> {
        val wrong = mutableListOf<String>()
        // Record bodies are the core's to check (check_body). The mutants' records are of version 1, which it refuses.
        for (kind in listOf("records", "commands", "manifests")) {
            for (c in v[kind]?.jsonArray ?: continue) {
                val o = c.jsonObject
                if (kind == "records" && o.str("rule") == "mutant") continue
                var body = b64(o.str("body"))
                o["pad"]?.let {
                    val at = o.getValue("pad_at").jsonPrimitive.int
                    body = body.copyOfRange(0, at) + ByteArray(it.jsonPrimitive.int) { 'a'.code.toByte() } + body.copyOfRange(at, body.size)
                }
                val got = when (kind) {
                    "records" -> takes(body)
                    "commands" -> try {
                        Commands.parse(body)
                        true
                    } catch (_: Commands.Refused) {
                        false
                    }
                    else -> runCatching { Wire.parse(body)?.let { Media.Manifest.fromJson(it) }?.isValid == true }.getOrDefault(false)
                }
                val valid = o.getValue("valid").jsonPrimitive.boolean
                if (got != valid) wrong += "$kind ${o.str("name")} (${o.str("rule")}): valid $valid, got $got"
            }
        }
        return wrong
    }

    /** strict-files.json: the server credentials and release files, as Go's TestStrictGeneratedFiles writes them. */
    @Test
    fun generatedFiles() {
        val v = Interop.read("strict-files.json").jsonObject
        val wrong = mutableListOf<String>()
        for (section in listOf("credentials", "releases")) {
            val cases = v.getValue(section).jsonArray
            assertTrue(cases.isNotEmpty(), "no $section")
            for (c in cases) {
                val o = c.jsonObject
                var body = b64(o.str("body"))
                o["pad"]?.let {
                    val at = o.getValue("pad_at").jsonPrimitive.int
                    body = body.copyOfRange(0, at) + ByteArray(it.jsonPrimitive.int) { 'a'.code.toByte() } + body.copyOfRange(at, body.size)
                }
                val got = runCatching {
                    if (section == "credentials") {
                        ServerCredentials.Body.parse(body)
                    } else {
                        if (body.size > Releases.MAX_BODY) throw Releases.Refused("too large")
                        when (val kind = o.str("kind")) {
                            "keys" -> Releases.decodeKeys(body)
                            "release" -> Releases.decodeRelease(body)
                            "channel" -> Releases.decodeChannel(body)
                            "attest-status" -> Releases.decodeStatus(body)
                            else -> error("unknown kind $kind")
                        }
                    }
                }
                // A reader refuses with its own exception, never with another that escapes it.
                got.exceptionOrNull()?.let { if (it !is ServerCredentials.Refused && it !is Releases.Refused) throw it }
                val valid = o.getValue("valid").jsonPrimitive.boolean
                if (got.isSuccess != valid) wrong += "$section ${o.str("name")} (${o.str("rule")}): valid $valid, got ${got.exceptionOrNull()?.message ?: "taken"}"
            }
        }
        assertTrue(wrong.isEmpty(), "${wrong.size} vectors read otherwise:\n" + wrong.joinToString("\n"))
    }

    private companion object {
        /** The fields every record body of version 2 has (docs/records-v2.md). */
        val REQUIRED = listOf("v", "alg", "type", "signer", "time_ms", "group", "seq")
    }
}
