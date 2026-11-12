// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * The kit's verdicts on a corpus of tools/difffuzz (docs/differential.md): one line per case, which the comparison
 * checks against the other implementations' lines. It runs on the corpus that CBB_VERDICTS names and writes to
 * CBB_VERDICTS_OUT; without them, on a corpus of its own.
 */
class VerdictTest {
    private fun hex(b: ByteArray?): String = b?.joinToString("") { "%02x".format(it) } ?: ""
    private fun hex(s: String?): String = hex(s?.toByteArray(Charsets.UTF_8))
    private fun hashes(l: List<ByteArray>?): String = l.orEmpty().joinToString(".") { hex(it) }
    private fun bit(b: Boolean) = if (b) "1" else "0"
    private fun sha256(b: ByteArray) = MessageDigest.getInstance("SHA-256").digest(b)

    private fun taken(vararg pairs: Pair<String, String>) = "taken" + pairs.joinToString("") { " ${it.first}=${it.second}" }

    private fun verdict(c: JsonObject): String {
        val kind = c.str("kind")
        val body = c["body"]?.let { b64(it.jsonPrimitive.content) } ?: ByteArray(0)
        // A reader refuses with its own exception; any other is a verdict of its own, which no other reader gives.
        fun refused(f: () -> String): String = runCatching(f).getOrElse {
            when (it) {
                is Commands.Refused, is ServerCredentials.Refused, is Releases.Refused -> "refused"
                is Error -> throw it
                else -> "threw ${it::class.simpleName}"
            }
        }
        return when (kind) {
            // The phones read records v2 only through the Rust core (docs/core-api.md), which the comparison reads as
            // rust: the kit's own reader of version 1 has no verdict on them.
            "record", "set" -> "skip"
            "command" -> refused {
                val b = Commands.parse(body)
                taken(
                    "type" to hex(b.type), "group" to hex(b.group), "by" to hex(b.by), "to" to hex(b.to), "id" to hex(b.id),
                    "time_ms" to b.timeMS.toString(), "expires_ms" to b.expiresMS.toString(), "mode" to hex(b.mode),
                    "enter" to bit(b.enter), "kind" to hex(b.kind), "text" to hex(sha256((b.text ?: "").toByteArray(Charsets.UTF_8))),
                    "action" to hex(b.action),
                )
            }
            "credential" -> refused {
                val b = ServerCredentials.Body.parse(body)
                taken(
                    "type" to hex(b.type), "group" to hex(b.group), "version" to b.version.toString(),
                    "expires_ms" to b.expiresMS.toString(), "tag" to hex(b.tag), "key" to hex(b.key), "hubs" to hashes(b.hubs),
                    "admins" to hashes(b.admins), "members" to hashes(b.members),
                )
            }
            "manifest" -> if (Media.Manifest.parse(body) != null) "taken" else "refused"
            "keys", "release", "channel", "attest-status" -> refused {
                // The core reads release files for the kit (docs/core-api.md).
                Core.bodyRefusal(kind, body)?.let { throw Releases.Refused(it) }
                "taken"
            }
            else -> error("unknown kind $kind")
        }
    }

    @Test
    fun verdicts() {
        val input = System.getenv("CBB_VERDICTS")?.takeIf { it.isNotEmpty() }
        val lines = (input?.let { File(it).readLines() } ?: listOf("""{"kind":"record","body":"e30="}""", """{"kind":"keys","body":"e30="}"""))
            .filter { it.isNotEmpty() }
            .joinToString("") { verdict(Json.parseToJsonElement(it).jsonObject) + "\n" }
        if (input != null) {
            File(System.getenv("CBB_VERDICTS_OUT")).writeText(lines)
        } else {
            assertEquals("skip\nrefused\n", lines)
        }
    }
}
