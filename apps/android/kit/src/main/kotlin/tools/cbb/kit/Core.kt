// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import com.sun.jna.IntegerType
import com.sun.jna.Library
import com.sun.jna.Memory
import com.sun.jna.Native
import com.sun.jna.Pointer
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/**
 * The Rust core's one entry point (docs/core-api.md), the group's rules that
 * every member shares: JSON bytes in, JSON bytes out, through the C functions
 * of ffi/ (ffi/include/cbb_core.h), loaded by JNA from libcbb_ffi:
 * from the app's native libraries on Android, from jna.library.path in the
 * tests. The kit asks the core instead of writing the rules again in Kotlin.
 */
object Core {
    /** The version of the request and answer shapes the kit speaks; [call] refuses a core of another. */
    const val ABI = 1

    /**
     * An error answer of the core: a stable code and name, a short message for
     * the user and the causes under it. The app shows [message], and [details]
     * under it in debug mode; the log always gets both.
     */
    class Refusal(val code: Int, val name: String, override val message: String, val details: String?) :
        Exception(message) {
        override fun toString(): String =
            if (details.isNullOrEmpty()) "core: $message ($name, code $code)" else "core: $message ($name, code $code): $details"
    }

    /** A linked core that speaks another ABI, or an answer the kit cannot read: a build that put the wrong library in. */
    class Mismatch(reason: String, cause: Throwable? = null) : Exception("core: $reason", cause)

    /** The core's answer to the operation `version`. */
    data class Version(val abi: Int, val core: String, val source: String?) {
        /** How `cbb version` names the core, for the apps' about screens and error reports. */
        val line: String get() = "core $core, abi $abi, source ${source ?: "unknown"}"
    }

    @Suppress("FunctionName")
    private interface Lib : Library {
        fun cbb_abi(): Int

        fun cbb_call(request: ByteArray?, len: SizeT, answerLen: Pointer): Pointer?

        fun cbb_free(answer: Pointer?, len: SizeT)
    }

    /** C's size_t: 64 bits on arm64-v8a, x86_64 and the JVM tests, 32 on armeabi-v7a. */
    class SizeT(value: Long = 0) : IntegerType(Native.SIZE_T_SIZE, value, true) {
        override fun toByte(): Byte = toLong().toByte()

        override fun toShort(): Short = toLong().toShort()
    }

    private val lib: Lib by lazy { Native.load("cbb_ffi", Lib::class.java) }

    /**
     * Sends one request and returns the core's answer, after checking that the
     * core speaks [ABI]. A refusal of the request is an answer with an error,
     * not an exception of [call].
     */
    fun call(request: ByteArray): ByteArray {
        val got = lib.cbb_abi()
        if (got != ABI) throw Mismatch("the linked core speaks ABI $got, not $ABI")
        val count = Memory(Native.SIZE_T_SIZE.toLong())
        count.clear()
        val answer = lib.cbb_call(request.takeIf { it.isNotEmpty() }, SizeT(request.size.toLong()), count)
            ?: throw Mismatch("the core gave no answer")
        val n = if (Native.SIZE_T_SIZE == 8) count.getLong(0) else count.getInt(0).toLong() and 0xffffffffL
        try {
            if (n > Int.MAX_VALUE) throw Mismatch("the core's answer is $n bytes long")
            return answer.getByteArray(0, n.toInt())
        } finally {
            lib.cbb_free(answer, SizeT(n))
        }
    }

    /**
     * Sends the operation [op] with [args] (null for none) and returns the
     * answer's `ok`; a refusal comes back as a [Refusal].
     */
    fun run(op: String, args: JsonElement? = null): JsonElement {
        val request = buildJsonObject {
            put("abi", JsonPrimitive(ABI))
            put("op", JsonPrimitive(op))
            if (args != null) put("args", args)
        }
        val answer = try {
            Json.parseToJsonElement(call(request.toString().toByteArray()).decodeToString()).jsonObject
        } catch (e: IllegalArgumentException) {
            throw Mismatch("the answer to $op does not read", e)
        }
        (answer["error"] as? JsonObject)?.let { e ->
            try {
                throw Refusal(
                    e.getValue("code").jsonPrimitive.int,
                    e.getValue("name").jsonPrimitive.content,
                    e.getValue("message").jsonPrimitive.content,
                    (e["details"] as? JsonPrimitive)?.content,
                )
            } catch (bad: NoSuchElementException) {
                throw Mismatch("the error answer to $op does not read", bad)
            }
        }
        return answer["ok"]?.takeIf { it != JsonNull } ?: throw Mismatch("the answer to $op has neither ok nor error")
    }

    /**
     * Checks a signed body that is not a record through the core's
     * parse_body (docs/core-api.md, "Signed bodies"): [kind] is `command`,
     * `credential`, `keys`, `release`, `channel` or `attest-status`. The
     * core alone decides whether the body is taken; it answers null for a
     * body it takes and why it refused one otherwise, the message and the
     * details, for the log.
     */
    internal fun bodyRefusal(kind: String, body: ByteArray): String? =
        try {
            run("parse_body", Wire.obj("kind" to Wire.str(kind), "body" to Wire.bytes(body)))
            null
        } catch (r: Refusal) {
            r.details?.takeIf { it.isNotEmpty() }?.let { "${r.message}: $it" } ?: r.message
        }

    /**
     * A command in the open with its orders sealed to key, the receiver's key
     * for sealed messages (seal_command, docs/core-api.md, "Signed bodies"),
     * for the sender to sign.
     */
    internal fun sealCommand(body: ByteArray, key: ByteArray): ByteArray {
        val ok = run("seal_command", Wire.obj("body" to Wire.bytes(body), "key" to Wire.bytes(key))) as? JsonObject
            ?: throw Mismatch("the answer to seal_command is not an object")
        return ok.optBytes("body") ?: throw Mismatch("the answer to seal_command has no body")
    }

    /** The public key for sealed messages of secret, 32 random bytes the device keeps: the `seal` its pairing and device record carry. */
    fun sealPublic(secret: ByteArray): ByteArray {
        val ok = run("seal_public", Wire.obj("secret" to Wire.bytes(secret))) as? JsonObject
            ?: throw Mismatch("the answer to seal_public is not an object")
        return ok.optBytes("key") ?: throw Mismatch("the answer to seal_public has no key")
    }

    /** A recovery sheet (docs/protocol.md, section 10, "The recovery key"): the QR code's text, the key in groups of four, and the key hash the `recovery` record names. */
    class RecoverySheet(val qr: String, val text: String, val admin: ByteArray)

    /** The recovery sheet for key (its 32 bytes), its admin CA and the group's tag. */
    fun recoverySheet(key: ByteArray, cert: ByteArray, group: String): RecoverySheet {
        val ok = run("recovery_sheet", Wire.obj("key" to Wire.bytes(key), "cert" to Wire.bytes(cert), "group" to Wire.str(group))) as? JsonObject
            ?: throw Mismatch("the answer to recovery_sheet is not an object")
        return RecoverySheet(
            ok.optString("qr") ?: throw Mismatch("the answer to recovery_sheet has no qr"),
            ok.optString("text") ?: throw Mismatch("the answer to recovery_sheet has no text"),
            ok.optBytes("admin") ?: throw Mismatch("the answer to recovery_sheet has no admin"),
        )
    }

    /** A recovery key read from a sheet: [key] its 32 bytes, [public] uncompressed, [admin] its key hash; [cert] and [group] only from its QR code. */
    class RecoveredKey(
        val key: ByteArray,
        val pkcs8: ByteArray,
        val public: ByteArray,
        val admin: ByteArray,
        val cert: ByteArray?,
        val group: String?,
    )

    /** What read_recovery_sheet says of a text: the key, or why it is not one. */
    sealed class SheetReading {
        class Key(val key: RecoveredKey) : SheetReading()

        /** reason is not_sheet, damaged, check, key, cert, mismatch or group; message a sentence for the user. */
        class Refused(val reason: String, val message: String) : SheetReading()
    }

    /** Reads what the user scanned or typed from a recovery sheet. */
    fun readRecoverySheet(text: String): SheetReading {
        val ok = run("read_recovery_sheet", Wire.obj("text" to Wire.str(text))) as? JsonObject
            ?: throw Mismatch("the answer to read_recovery_sheet is not an object")
        (ok["sheet"] as? JsonObject)?.let { s ->
            fun need(k: String) = s.optBytes(k) ?: throw Mismatch("the answer to read_recovery_sheet has no $k")
            return SheetReading.Key(RecoveredKey(need("key"), need("pkcs8"), need("public"), need("admin"), s.optBytes("cert"), s.optString("group")))
        }
        val r = ok["refused"] as? JsonObject ?: throw Mismatch("the answer to read_recovery_sheet has neither sheet nor refused")
        return SheetReading.Refused(r.optString("reason") ?: "", r.optString("message") ?: "")
    }

    /** The linked core's version, ABI and the commit it was built from. */
    fun version(): Version {
        val ok = run("version") as? JsonObject ?: throw Mismatch("the answer to version is not an object")
        val abi = (ok["abi"] as? JsonPrimitive)?.intOrNull ?: throw Mismatch("the answer to version has no abi")
        val core = (ok["core"] as? JsonPrimitive)?.content ?: throw Mismatch("the answer to version has no core")
        return Version(abi, core, (ok["source"] as? JsonPrimitive)?.content)
    }
}
