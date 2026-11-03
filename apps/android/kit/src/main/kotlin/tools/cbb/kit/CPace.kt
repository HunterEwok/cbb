// SPDX-License-Identifier: AGPL-3.0-only
//
// A port of internal/third_party/cpace/cpace.go, Copyright 2026 The Go
// Authors, under the BSD-style license in internal/third_party/cpace/LICENSE.

package tools.cbb.kit

import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * The CPace password-authenticated key exchange, suite
 * CPACE-X25519-SHA512 of draft-irtf-cfrg-cpace-21, with explicit key
 * confirmation, as the Go side uses it (docs/protocol.md, section 6).
 */
class CPace internal constructor(
    private val role: Role,
    password: ByteArray,
    channelID: ByteArray,
    private val sid: ByteArray,
    private val ad: ByteArray,
    scalar: ByteArray,
) {
    enum class Role { INITIATOR, RESPONDER }

    class Failure(val reason: Reason) : Exception(reason.name) {
        enum class Reason { ALREADY_FINISHED, OWN_MESSAGE, INVALID_MESSAGE, LOW_ORDER, NOT_FINISHED, CONFIRMATION }
    }

    /** Starts an exchange; send [message] with [ad] to the other party. */
    constructor(role: Role, password: ByteArray, channelID: ByteArray, sessionID: ByteArray, ad: ByteArray) :
        this(role, password, channelID, sessionID, ad, ByteArray(32).also { SecureRandom().nextBytes(it) })

    /** This party's message, Ya or Yb. */
    val message: ByteArray

    private var scalar: ByteArray? = scalar.copyOf()
    private var tag: ByteArray? = null
    private var peerTag: ByteArray? = null

    init {
        val y = x25519(scalar, generator(password, channelID, sid))
        if (y.all { it == 0.toByte() }) throw Failure(Failure.Reason.INVALID_MESSAGE)
        message = y
    }

    /**
     * Finishes the exchange with the other party's message and AD,
     * returning the intermediate session key. It works once.
     */
    fun finish(peerMessage: ByteArray, peerAD: ByteArray): ByteArray {
        val s = scalar ?: throw Failure(Failure.Reason.ALREADY_FINISHED)
        scalar = null
        if (peerMessage.contentEquals(message)) throw Failure(Failure.Reason.OWN_MESSAGE)
        if (peerMessage.size != 32) throw Failure(Failure.Reason.INVALID_MESSAGE)
        val k = x25519(s, peerMessage)
        s.fill(0)
        if (k.all { it == 0.toByte() }) throw Failure(Failure.Reason.LOW_ORDER)

        val transcript = if (role == Role.INITIATOR) {
            lvCat(message, ad) + lvCat(peerMessage, peerAD)
        } else {
            lvCat(peerMessage, peerAD) + lvCat(message, ad)
        }
        val isk = sha512(lvCat(DSI_ISK, sid, k) + transcript)
        val macKey = sha512(DSI_MAC + sid + isk)
        tag = mac(macKey, message, ad)
        peerTag = mac(macKey, peerMessage, peerAD)
        return isk
    }

    /** This party's key confirmation tag, after [finish]. */
    val confirmationTag: ByteArray? get() = tag?.copyOf()

    /** Checks the other party's key confirmation tag. */
    fun verify(peerTag: ByteArray) {
        val want = this.peerTag ?: throw Failure(Failure.Reason.NOT_FINISHED)
        if (!MessageDigest.isEqual(peerTag, want)) throw Failure(Failure.Reason.CONFIRMATION)
    }

    companion object {
        private val DSI = "CPace255".toByteArray()
        private val DSI_ISK = "CPace255_ISK".toByteArray()
        private val DSI_MAC = "CPaceMac".toByteArray()
        private const val BLOCK_SIZE = 128 // of SHA-512

        internal fun sha512(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-512").digest(b)

        private fun mac(key: ByteArray, msg: ByteArray, ad: ByteArray): ByteArray {
            val m = Mac.getInstance("HmacSHA512")
            m.init(SecretKeySpec(key, "HmacSHA512"))
            return m.doFinal(lvCat(msg, ad))
        }

        /**
         * generator_string(DSI, PRS, CI, sid): the zero padding fills SHA-512's
         * first block, so the bytes hashed do not depend on the password length.
         */
        internal fun generatorString(password: ByteArray, channelID: ByteArray, sessionID: ByteArray): ByteArray {
            val b = lvCat(DSI, password)
            val zpad = maxOf(0, BLOCK_SIZE - 1 - b.size)
            return b + lvCat(ByteArray(zpad), channelID, sessionID)
        }

        internal fun generator(password: ByteArray, channelID: ByteArray, sessionID: ByteArray): ByteArray {
            val h = sha512(generatorString(password, channelID, sessionID))
            return elligator2(FieldElement.fromBytes(h.copyOf(32)))
        }

        /** prepend_len: the length in LEB128, then the bytes. */
        internal fun prependLen(v: ByteArray): ByteArray {
            val out = java.io.ByteArrayOutputStream()
            var n = v.size
            do {
                out.write(if (n < 128) n else (n and 0x7f) or 0x80)
                n = n ushr 7
            } while (n != 0)
            out.write(v)
            return out.toByteArray()
        }

        internal fun lvCat(vararg vs: ByteArray): ByteArray =
            vs.fold(ByteArray(0)) { acc, v -> acc + prependLen(v) }
    }
}
