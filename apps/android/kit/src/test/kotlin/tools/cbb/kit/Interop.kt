// SPDX-License-Identifier: AGPL-3.0-only

package tools.cbb.kit

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import java.util.Base64

/** The vectors in testdata/interop, which the Go and Swift tests write. */
object Interop {
    val dir = File(System.getProperty("interop.dir") ?: "../../../testdata/interop")

    fun read(name: String): JsonElement = Json.parseToJsonElement(File(dir, name).readText())

    /**
     * Where the kit's tests write what they make for the Go tests to check,
     * named as the Swift kit names them, so that the same Go tests read
     * them: CBB_INTEROP_OUT, or null to write nothing.
     */
    val out: File? = System.getenv("CBB_INTEROP_OUT")?.let { File(it).apply { mkdirs() } }
}

fun b64(s: String): ByteArray = Base64.getDecoder().decode(s)

fun b64(b: ByteArray): String = Base64.getEncoder().encodeToString(b)

fun JsonObject.str(key: String): String = getValue(key).jsonPrimitive.content
