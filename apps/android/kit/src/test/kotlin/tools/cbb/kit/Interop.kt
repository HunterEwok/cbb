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

}

fun b64(s: String): ByteArray = Base64.getDecoder().decode(s)

fun b64(b: ByteArray): String = Base64.getEncoder().encodeToString(b)

fun JsonObject.str(key: String): String = getValue(key).jsonPrimitive.content
