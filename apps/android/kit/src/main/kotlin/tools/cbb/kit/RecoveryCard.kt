// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import com.sun.jna.Callback
import com.sun.jna.Library
import com.sun.jna.Memory
import com.sun.jna.Native
import com.sun.jna.Pointer
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * A connection to a smart card, as the app gets one over NFC (IsoDep):
 * [transmit] sends one APDU and returns the answer with its status word last.
 */
fun interface SmartCard {
    fun transmit(apdu: ByteArray): ByteArray
}

/**
 * The group's recovery secret on a YubiKey (docs/protocol.md, "The recovery
 * key on a YubiKey (0.6)"): the core speaks PIV (`cbb_piv`, docs/core-api.md)
 * and the app only carries each APDU to the card. The root phone seals the
 * sheet's secret onto the card; a phone in the group opens it with the PIN
 * to change the root. The same as the Swift kit's RecoveryCard.
 */
object RecoveryCard {
    enum class Kind {
        /** The PIN is wrong; [Failure.left] says how many tries are left. */
        WRONG_PIN,

        /** The PIN is blocked: the card's PUK unblocks it. */
        BLOCKED,

        /** The card is older than firmware 5.3 or no YubiKey 5. */
        OLD_FIRMWARE,

        /** The card holds no recovery key of cbb. */
        NO_KEY,

        /** The card holds a recovery key already, which is never sealed again. */
        HOLDS_ONE,

        /** Something else is in the place cbb uses on the card. */
        TAKEN,

        /** The card's management key is one the app cannot use. */
        MANAGEMENT_KEY,

        /** The card left, refused, or its answer does not parse. */
        CARD,
    }

    /** The core's refusal, with what the app says of it; [left] is the PIN's tries left after [Kind.WRONG_PIN]. */
    class Failure(val kind: Kind, message: String, val details: String = "", val left: Int = 0) :
        Exception(if (details.isEmpty()) "yubikey: $message" else "yubikey: $message: $details") {
        /** The core's own message, without the prefix. */
        val reason: String = message

        companion object {
            /** The kind of the core's message (member/src/piv.rs and piv/recovery.rs). */
            internal fun of(m: String, details: String): Failure = when {
                "wrong PIN" in m -> Failure(
                    Kind.WRONG_PIN, m, details,
                    m.substringAfterLast(';').trim().split(' ').firstNotNullOfOrNull { it.toIntOrNull() } ?: 0,
                )
                "PIN is blocked" in m -> Failure(Kind.BLOCKED, m, details)
                "firmware 5.3" in m -> Failure(Kind.OLD_FIRMWARE, m, details)
                "holds no recovery key" in m -> Failure(Kind.NO_KEY, m, details)
                "already holds a recovery key" in m -> Failure(Kind.HOLDS_ONE, m, details)
                "already holds something" in m -> Failure(Kind.TAKEN, m, details)
                "management key" in m -> Failure(Kind.MANAGEMENT_KEY, m, details)
                else -> Failure(Kind.CARD, m, details)
            }
        }
    }

    /**
     * What sealing did: the card still has its factory management key
     * ([warning] then says what to tell the person), or the app replaced it
     * with a PIN-protected one.
     */
    data class Sealed(val defaultKey: Boolean, val replaced: Boolean, val warning: String?)

    /**
     * Whether the card can take the secret, with nothing written: true when
     * it still has its factory management key, which the app tells the
     * person before [seal] and asks whether to replace.
     */
    fun inspect(card: SmartCard, pin: String): Boolean =
        run(card, Wire.obj("op" to Wire.str("inspect"), "pin" to Wire.str(pin))).optBool("default_key")
            ?: throw Core.Mismatch("the core's answer to inspect has no default_key")

    /**
     * Seals the recovery key's secret onto the card: sheet is the sheet's QR
     * code or its text; replaceDefault is the person's consent to replace a
     * factory management key.
     */
    fun seal(card: SmartCard, pin: String, sheet: String, replaceDefault: Boolean): Sealed {
        val ok = run(
            card,
            Wire.obj(
                "op" to Wire.str("seal"),
                "pin" to Wire.str(pin),
                "recovery" to Wire.obj("text" to Wire.str(sheet)),
                "replace_default" to JsonPrimitive(replaceDefault),
            ),
        )
        return Sealed(ok.optBool("default_key") ?: false, ok.optBool("replaced") ?: false, ok.optString("warning"))
    }

    /** Opens the secret after the PIN and a touch, for a change of root; the caller drops it after that one use. */
    fun open(card: SmartCard, pin: String): ByteArray =
        run(card, Wire.obj("op" to Wire.str("open"), "pin" to Wire.str(pin))).optBytes("secret")
            ?: throw Core.Mismatch("the core's answer to open has no secret")

    /** cbb_transmit_fn: one APDU to the card of the call; any other value than 0 when the card is gone. */
    fun interface TransmitFn : Callback {
        fun invoke(ctx: Pointer?, apdu: Pointer, len: Core.SizeT, out: Pointer, cap: Core.SizeT, outLen: Pointer): Int
    }

    @Suppress("FunctionName")
    private interface Lib : Library {
        fun cbb_piv(request: ByteArray, len: Core.SizeT, transmit: TransmitFn, ctx: Pointer?, answerLen: Pointer): Pointer?

        fun cbb_free(answer: Pointer?, len: Core.SizeT)
    }

    private val lib: Lib by lazy { Native.load("cbb_ffi", Lib::class.java) }

    private fun run(card: SmartCard, request: JsonElement): JsonObject {
        val bytes = Wire.encode(request)
        val transmit = TransmitFn { _, apdu, len, out, cap, outLen ->
            try {
                val r = card.transmit(apdu.getByteArray(0, len.toInt()))
                if (r.size > cap.toLong()) return@TransmitFn 1
                out.write(0, r, 0, r.size)
                if (Native.SIZE_T_SIZE == 8) outLen.setLong(0, r.size.toLong()) else outLen.setInt(0, r.size)
                0
            } catch (e: Exception) {
                1
            }
        }
        val count = Memory(Native.SIZE_T_SIZE.toLong()).apply { clear() }
        // transmit stays referenced through the call, which is the only time the core calls it.
        val answer = lib.cbb_piv(bytes, Core.SizeT(bytes.size.toLong()), transmit, null, count)
            ?: throw Core.Mismatch("the core gave no answer to the YubiKey step")
        val n = if (Native.SIZE_T_SIZE == 8) count.getLong(0) else count.getInt(0).toLong() and 0xffffffffL
        val got = try {
            answer.getByteArray(0, n.toInt())
        } finally {
            lib.cbb_free(answer, Core.SizeT(n))
            java.lang.ref.Reference.reachabilityFence(transmit)
        }
        val a = runCatching { Json.parseToJsonElement(got.decodeToString()) as JsonObject }.getOrNull()
            ?: throw Core.Mismatch("the core's answer to the YubiKey step does not read")
        a.optObject("error")?.let { e ->
            throw Failure.of(e.optString("message") ?: "the YubiKey step was refused", e.optString("details") ?: "")
        }
        return a.optObject("ok") ?: throw Core.Mismatch("the core's answer to the YubiKey step has neither ok nor error")
    }
}
