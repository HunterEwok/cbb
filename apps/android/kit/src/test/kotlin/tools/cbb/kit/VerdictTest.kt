// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * The kit's verdicts on a corpus of tools/difffuzz (docs/differential.md): one line per case, which the comparison
 * checks against the other implementations' lines. It runs on the corpus that CBB_VERDICTS names and writes to
 * CBB_VERDICTS_OUT; without them, on a corpus of its own.
 */
class VerdictTest {

    private fun verdict(c: JsonObject): String {
        val kind = c.str("kind")
        val body = c["body"]?.let { b64(it.jsonPrimitive.content) } ?: ByteArray(0)
        // A reader refuses with its own exception; any other is a verdict of its own, which no other reader gives.
        fun refused(f: () -> String): String = runCatching(f).getOrElse {
            when (it) {
                is Releases.Refused -> "refused"
                is Error -> throw it
                else -> "threw ${it::class.simpleName}"
            }
        }
        return when (kind) {
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
        val lines = (input?.let { File(it).readLines() } ?: listOf("""{"kind":"manifest","body":"e30="}""", """{"kind":"keys","body":"e30="}"""))
            .filter { it.isNotEmpty() }
            .joinToString("") { verdict(Json.parseToJsonElement(it).jsonObject) + "\n" }
        if (input != null) {
            File(System.getenv("CBB_VERDICTS_OUT")).writeText(lines)
        } else {
            assertEquals("refused\nrefused\n", lines)
        }
    }
}
