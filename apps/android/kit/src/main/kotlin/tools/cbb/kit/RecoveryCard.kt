// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import com.sun.jna.Callback
import com.sun.jna.Library
import com.sun.jna.Memory
import com.sun.jna.Native
import com.sun.jna.Pointer
import kotlinx.serialization.json.Json
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
 * The bulk endpoints of a YubiKey's CCID interface on USB-C, which the app
 * claimed: the core frames each APDU (`cbb_piv`'s transport `ccid_bulk`).
 */
interface CcidBulk {
    /** Writes bytes to the bulk-out endpoint. */
    fun write(data: ByteArray)

    /** Reads one bulk-in transfer, at most max bytes; empty when nothing came within about a second. */
    fun read(max: Int): ByteArray
}

/** How the app reaches the card: an APDU at a time (NFC), or the bytes of its CCID interface (USB-C). */
sealed class CardLink {
    class Apdu(val card: SmartCard) : CardLink()

    class Ccid(val bulk: CcidBulk) : CardLink()
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

        /** The card holds this group's recovery key already, which is never sealed again. */
        HOLDS_ONE,

        /** Every retired PIV slot of the card is in use. */
        NO_FREE_SLOT,

        /** The card holds two recovery keys for the group, and cbb does not choose. */
        TWO_SLOTS,

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
                "already holds this group's recovery key" in m -> Failure(Kind.HOLDS_ONE, m, details)
                "retired PIV slot" in m -> Failure(Kind.NO_FREE_SLOT, m, details)
                "two recovery keys" in m || "more than one group" in m -> Failure(Kind.TWO_SLOTS, m, details)
                "management key" in m -> Failure(Kind.MANAGEMENT_KEY, m, details)
                else -> Failure(Kind.CARD, m, details)
            }
        }
    }

    /**
     * What sealing did: the retired slot that holds the key, and whether the
     * card keeps its factory management key, which cbb never changes (D-127).
     */
    data class Sealed(val slot: Int, val defaultKey: Boolean)

    /**
     * Seals the recovery key's secret onto the card, in its first empty
     * retired slot: sheet is the sheet's QR code or its text; group is the
     * group's ID in hex, or its tag, whose slot it becomes.
     */
    fun seal(card: SmartCard, pin: String, sheet: String, group: String): Sealed =
        seal(CardLink.Apdu(card), pin, sheet, group)

    fun seal(card: CardLink, pin: String, sheet: String, group: String): Sealed {
        val ok = run(
            card,
            Wire.obj(
                "op" to Wire.str("seal"),
                "pin" to Wire.str(pin),
                "recovery" to Wire.obj("text" to Wire.str(sheet)),
                "group" to Wire.str(group),
            ),
        )
        val slot = ok.optLong("slot") ?: throw Core.Mismatch("the core's answer to seal has no slot")
        return Sealed(slot.toInt(), ok.optBool("default_key") ?: false)
    }

    /**
     * Opens the group's secret after the PIN and a touch, for a change of
     * root; the caller drops it after that one use.
     */
    fun open(card: SmartCard, pin: String, group: String): ByteArray = open(CardLink.Apdu(card), pin, group)

    fun open(card: CardLink, pin: String, group: String): ByteArray =
        run(card, Wire.obj("op" to Wire.str("open"), "pin" to Wire.str(pin), "group" to Wire.str(group))).optBytes("secret")
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

    private fun run(card: CardLink, request: JsonObject): JsonObject {
        val transport = if (card is CardLink.Ccid) "ccid_bulk" else "apdu"
        val bytes = Wire.encode(JsonObject(request + ("transport" to JsonPrimitive(transport))))
        val transmit = TransmitFn { _, apdu, len, out, cap, outLen ->
            try {
                val data = if (len.toLong() > 0) apdu.getByteArray(0, len.toInt()) else ByteArray(0)
                val r = when (card) {
                    is CardLink.Apdu -> card.card.transmit(data)
                    is CardLink.Ccid -> if (data.isNotEmpty()) {
                        card.bulk.write(data)
                        ByteArray(0)
                    } else {
                        card.bulk.read(cap.toInt())
                    }
                }
                if (r.size > cap.toLong()) return@TransmitFn 1
                if (r.isNotEmpty()) out.write(0, r, 0, r.size)
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
