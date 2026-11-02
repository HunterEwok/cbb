// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package io.github.hunterewok.clipboardbridge.kit

import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * A connection to a smart card, as the app gets one over NFC (IsoDep) or
 * USB: [transmit] sends one APDU and returns the answer with its status word
 * last.
 */
fun interface SmartCard {
    fun transmit(apdu: ByteArray): ByteArray
}

/**
 * The group's recovery key on a YubiKey, or another card with the PIV
 * application (docs/protocol.md, section 10, "The recovery key", "On a
 * hardware key"): the root phone has the card make a P-256 key in a free
 * retired slot (82 to 95), where it never leaves the card, and stores the
 * key's admin CA as the slot's certificate; a new phone, as Go's
 * internal/piv on a computer, finds the slot by that certificate and has
 * the card sign. Nothing else on the card is changed: it may be in use for
 * other things. The same as the Swift kit's Piv.
 */
object Piv {
    /** A refusal; [left] is the PIN's tries left after [Kind.WRONG_PIN]. */
    class Failure(val kind: Kind, message: String, val left: Int = 0) : Exception(message)

    enum class Kind {
        /** The card has no PIV application. */
        NO_PIV,

        /** The PIN is wrong; [Failure.left] says how many tries are left. */
        WRONG_PIN,

        /** The PIN is blocked: the card's PUK unblocks it. */
        BLOCKED,

        /** The card's management key is not the default one, which making a key needs. */
        MANAGEMENT_KEY,

        /** Every retired slot holds a key or a certificate. */
        NO_FREE_SLOT,

        /** No retired slot holds a recovery key's certificate. */
        NO_KEY,

        /** The card refused, or its answer does not parse. */
        CARD,
    }

    /** The retired slots, where the recovery key goes. */
    const val FIRST_SLOT = 0x82
    const val LAST_SLOT = 0x95

    private val AID = byteArrayOf(0xa0.toByte(), 0x00, 0x00, 0x03, 0x08)
    private const val ALG_P256 = 0x11
    private const val PIN_REF = 0x80
    private const val MANAGEMENT_SLOT = 0x9b

    /** The management key a YubiKey has from the factory: 3DES before firmware 5.7, AES-192 from it. */
    private val DEFAULT_MANAGEMENT_KEY = ByteArray(24) { ((it % 8) + 1).toByte() }

    /** The PIN and touch policies of the recovery key: the PIN and a touch before each signature. */
    private const val PIN_ALWAYS = 0x03
    private const val TOUCH_ALWAYS = 0x02

    private fun fail(kind: Kind, message: String): Nothing = throw Failure(kind, message)

    private fun cardFail(what: String, sw: Int): Nothing = fail(Kind.CARD, "$what: the card answered %04x".format(sw))

    /** A certificate object's tag: 5FC10D for slot 82, up to 5FC120 for slot 95. */
    private fun certObject(slot: Int): ByteArray {
        require(slot in FIRST_SLOT..LAST_SLOT) { "not a retired slot" }
        return byteArrayOf(0x5f, 0xc1.toByte(), (0x0d + slot - FIRST_SLOT).toByte())
    }

    /** Sends one command, chaining data longer than 255 bytes and following 61xx with GET RESPONSE. */
    internal fun command(card: SmartCard, ins: Int, p1: Int, p2: Int, data: ByteArray = ByteArray(0)): Pair<ByteArray, Int> {
        var rest = data
        while (rest.size > 255) {
            val (_, sw) = transmit(card, byteArrayOf(0x10, ins.toByte(), p1.toByte(), p2.toByte(), 0xff.toByte()) + rest.copyOf(255))
            if (sw != 0x9000) return ByteArray(0) to sw
            rest = rest.copyOfRange(255, rest.size)
        }
        var apdu = byteArrayOf(0x00, ins.toByte(), p1.toByte(), p2.toByte())
        if (rest.isNotEmpty()) apdu += byteArrayOf(rest.size.toByte()) + rest
        return transmit(card, apdu + byteArrayOf(0))
    }

    private fun transmit(card: SmartCard, first: ByteArray): Pair<ByteArray, Int> {
        var apdu = first
        var out = ByteArray(0)
        while (true) {
            val r = card.transmit(apdu)
            if (r.size < 2) fail(Kind.CARD, "the card's answer has no status word")
            out += r.copyOf(r.size - 2)
            if (out.size > MAX_ANSWER) fail(Kind.CARD, "the card's answer is too long")
            val sw1 = r[r.size - 2].toInt() and 0xff
            val sw2 = r[r.size - 1].toInt() and 0xff
            if (sw1 != 0x61) return out to (sw1 shl 8 or sw2)
            apdu = byteArrayOf(0x00, 0xc0.toByte(), 0x00, 0x00, sw2.toByte())
        }
    }

    private const val MAX_ANSWER = 16 shl 10

    /** Selects the PIV application. */
    fun select(card: SmartCard) {
        val (_, sw) = command(card, 0xa4, 0x04, 0x00, AID)
        if (sw != 0x9000) fail(Kind.NO_PIV, "this card has no PIV application")
    }

    /** Checks the PIN, which the card then takes as given for the next signature. */
    fun verify(card: SmartCard, pin: String) {
        val b = pin.toByteArray(Charsets.UTF_8)
        if (b.size !in 6..8) throw IllegalArgumentException("a YubiKey's PIN has 6 to 8 characters")
        val (_, sw) = command(card, 0x20, 0x00, PIN_REF, b + ByteArray(8 - b.size) { 0xff.toByte() })
        when {
            sw == 0x9000 -> return
            sw == 0x6983 || sw == 0x63c0 -> fail(Kind.BLOCKED, "the YubiKey's PIN is blocked: its PUK unblocks it")
            sw and 0xfff0 == 0x63c0 -> throw Failure(Kind.WRONG_PIN, "wrong PIN for the YubiKey; ${sw and 0xf} tries left before it is blocked", sw and 0xf)
            else -> cardFail("checking the PIN", sw)
        }
    }

    /** A retired slot's certificate, DER; null when it holds none. */
    fun certificate(card: SmartCard, slot: Int): ByteArray? {
        val (data, sw) = command(card, 0xcb, 0x3f, 0xff, tlv(0x5c, certObject(slot)))
        if (sw == 0x6a82) return null
        if (sw != 0x9000) cardFail("reading a certificate", sw)
        return try {
            val obj = TLV(data).value(0x53)
            val t = TLV(obj)
            val der = t.value(0x70)
            if (!t.done && t.peek == 0x71) {
                val info = t.value(0x71)
                if (info.isNotEmpty() && info[0] != 0.toByte()) fail(Kind.CARD, "the certificate is compressed")
            }
            der
        } catch (e: IndexOutOfBoundsException) {
            fail(Kind.CARD, "the certificate object does not parse")
        }
    }

    /**
     * The recovery keys the card may hold: each retired slot whose
     * certificate is not its own issuer, as an admin CA under a root is, with
     * the slot. The certificate of the one the group's records name is the
     * recovery key's admin CA.
     */
    fun recoveryKeys(card: SmartCard): List<Pair<Int, ByteArray>> =
        (FIRST_SLOT..LAST_SLOT).mapNotNull { slot ->
            val der = certificate(card, slot) ?: return@mapNotNull null
            val info = try {
                CertificateInfo(der)
            } catch (e: Exception) {
                return@mapNotNull null
            }
            if (p256PublicKey(info.publicKey) == null || info.selfIssued) null else slot to der
        }

    /**
     * Whether a slot is free: no key, as the card's metadata says (YubiKey
     * 5.3 and later), and no certificate. A card without metadata counts a
     * slot without a certificate as free.
     */
    private fun free(card: SmartCard, slot: Int): Boolean {
        if (certificate(card, slot) != null) return false
        val (_, sw) = command(card, 0xf7, 0x00, slot)
        return sw == 0x6a82 || sw == 0x6d00 || sw == 0x6a81
    }

    /** The first free retired slot. */
    fun freeSlot(card: SmartCard): Int =
        (FIRST_SLOT..LAST_SLOT).firstOrNull { free(card, it) } ?: fail(Kind.NO_FREE_SLOT, "every retired PIV slot of this YubiKey is in use")

    /**
     * Authenticates with the default management key, which making a key and
     * storing its certificate need; the algorithm is the one the card's
     * metadata names, 3DES without it.
     */
    fun authenticate(card: SmartCard, key: ByteArray = DEFAULT_MANAGEMENT_KEY) {
        val (meta, msw) = command(card, 0xf7, 0x00, MANAGEMENT_SLOT)
        val alg = if (msw == 0x9000) {
            val t = TLV(meta)
            var a = 0x03
            while (!t.done) {
                val tag = t.peek
                val v = t.value(tag)
                if (tag == 0x01 && v.size == 1) a = v[0].toInt() and 0xff
            }
            a
        } else {
            0x03
        }
        val (cipher, block) = when (alg) {
            0x03 -> "DESede" to 8
            0x0a, 0x0b, 0x0c -> "AES" to 16
            else -> fail(Kind.MANAGEMENT_KEY, "the YubiKey's management key has an unknown algorithm")
        }
        val keyLen = when (alg) { 0x0a -> 16; 0x0c -> 32; else -> 24 }
        if (key.size != keyLen) fail(Kind.MANAGEMENT_KEY, "the YubiKey's management key is not the default one")
        val spec = SecretKeySpec(key, cipher)
        // One block, as the card's challenge and witness are: CBC with a zero IV is the block cipher itself.
        fun crypt(mode: Int, b: ByteArray): ByteArray {
            if (b.size != block) fail(Kind.CARD, "the YubiKey's challenge is not one block")
            return Cipher.getInstance("$cipher/CBC/NoPadding").run { init(mode, spec, IvParameterSpec(ByteArray(block))); doFinal(b) }
        }

        val (w, sw1) = command(card, 0x87, alg, MANAGEMENT_SLOT, tlv(0x7c, tlv(0x80, ByteArray(0))))
        if (sw1 != 0x9000) cardFail("starting authentication", sw1)
        val witness = try {
            TLV(TLV(w).value(0x7c)).value(0x80)
        } catch (e: IndexOutOfBoundsException) {
            fail(Kind.CARD, "the card's witness does not parse")
        }
        if (witness.size != block) fail(Kind.CARD, "the card's witness has the wrong size")
        val challenge = ByteArray(block).also { SecureRandom().nextBytes(it) }
        val (r, sw2) = command(card, 0x87, alg, MANAGEMENT_SLOT,
            tlv(0x7c, tlv(0x80, crypt(Cipher.DECRYPT_MODE, witness)) + tlv(0x81, challenge)))
        if (sw2 == 0x6982 || sw2 == 0x6a80) fail(Kind.MANAGEMENT_KEY, "the YubiKey's management key is not the default one")
        if (sw2 != 0x9000) cardFail("authenticating", sw2)
        val answer = try {
            TLV(TLV(r).value(0x7c)).value(0x82)
        } catch (e: IndexOutOfBoundsException) {
            fail(Kind.CARD, "the card's answer does not parse")
        }
        if (!answer.contentEquals(crypt(Cipher.ENCRYPT_MODE, challenge))) fail(Kind.CARD, "the card did not prove the management key")
    }

    /**
     * Has the card make a P-256 key in slot, which asks for the PIN and a
     * touch before each signature, and returns its SubjectPublicKeyInfo;
     * [authenticate] must come first.
     */
    fun generate(card: SmartCard, slot: Int): ByteArray {
        certObject(slot)
        val spec = tlv(0xac, tlv(0x80, byteArrayOf(ALG_P256.toByte())) +
            tlv(0xaa, byteArrayOf(PIN_ALWAYS.toByte())) + tlv(0xab, byteArrayOf(TOUCH_ALWAYS.toByte())))
        val (data, sw) = command(card, 0x47, 0x00, slot, spec)
        if (sw == 0x6982) fail(Kind.MANAGEMENT_KEY, "the YubiKey wants its management key first")
        if (sw != 0x9000) cardFail("making the key", sw)
        val point = try {
            val outer = TLV(data)
            if (outer.peek != 0x7f) fail(Kind.CARD, "the new key does not parse")
            TLV(outer.value2(0x7f49)).value(0x86)
        } catch (e: IndexOutOfBoundsException) {
            fail(Kind.CARD, "the new key does not parse")
        }
        return p256SPKI(point) ?: fail(Kind.CARD, "the new key is not a P-256 key")
    }

    /** Stores cert, DER, as slot's certificate; [authenticate] must come first. */
    fun putCertificate(card: SmartCard, slot: Int, cert: ByteArray) {
        val obj = tlv(0x53, tlv(0x70, cert) + tlv(0x71, byteArrayOf(0)) + tlv(0xfe, ByteArray(0)))
        val (_, sw) = command(card, 0xdb, 0x3f, 0xff, tlv(0x5c, certObject(slot)) + obj)
        if (sw != 0x9000) cardFail("storing the certificate", sw)
    }

    /**
     * The key in slot as a [CertificateSigner], with the public key spki:
     * each signature checks pin first, as the key asks, and is checked
     * against spki, so that a card with another key in the slot never signs
     * what would not verify.
     */
    class Signer(private val card: SmartCard, private val slot: Int, override val publicKeyDER: ByteArray, private val pin: String) : CertificateSigner {
        override fun signature(data: ByteArray): ByteArray {
            verify(card, pin)
            val digest = sha256(data)
            val (r, sw) = command(card, 0x87, ALG_P256, slot, tlv(0x7c, tlv(0x82, ByteArray(0)) + tlv(0x81, digest)))
            if (sw == 0x6982) fail(Kind.CARD, "the YubiKey wants its PIN first")
            if (sw != 0x9000) cardFail("signing", sw)
            val sig = try {
                TLV(TLV(r).value(0x7c)).value(0x82)
            } catch (e: IndexOutOfBoundsException) {
                fail(Kind.CARD, "the signature does not parse")
            }
            val pub = p256PublicKey(publicKeyDER) ?: fail(Kind.CARD, "the recovery key is not a P-256 key")
            val ok = java.security.Signature.getInstance("SHA256withECDSA").run {
                initVerify(pub)
                update(data)
                try {
                    verify(sig)
                } catch (e: java.security.SignatureException) {
                    false
                }
            }
            if (!ok) fail(Kind.CARD, "the YubiKey's signature does not match its certificate's key")
            return sig
        }
    }

    internal fun tlv(tag: Int, v: ByteArray): ByteArray {
        val t = if (tag > 0xff) byteArrayOf((tag shr 8).toByte(), tag.toByte()) else byteArrayOf(tag.toByte())
        val n = v.size
        val len = when {
            n < 0x80 -> byteArrayOf(n.toByte())
            n < 0x100 -> byteArrayOf(0x81.toByte(), n.toByte())
            else -> byteArrayOf(0x82.toByte(), (n shr 8).toByte(), n.toByte())
        }
        return t + len + v
    }

    /** Reads BER-TLV values in a row; a short or malformed one throws IndexOutOfBoundsException. */
    internal class TLV(private val b: ByteArray) {
        private var pos = 0
        val done: Boolean get() = pos >= b.size
        val peek: Int get() = b[pos].toInt() and 0xff

        /** The value of the next element, whose one-byte tag must be tag. */
        fun value(tag: Int): ByteArray {
            if (peek != tag) throw IndexOutOfBoundsException("unexpected tag")
            pos++
            return rest()
        }

        /** The value of the next element, whose two-byte tag must be tag. */
        fun value2(tag: Int): ByteArray {
            if (peek != tag shr 8 || (b[pos + 1].toInt() and 0xff) != (tag and 0xff)) throw IndexOutOfBoundsException("unexpected tag")
            pos += 2
            return rest()
        }

        private fun rest(): ByteArray {
            var n = b[pos++].toInt() and 0xff
            when (n) {
                0x81 -> n = b[pos++].toInt() and 0xff
                0x82 -> {
                    n = (b[pos].toInt() and 0xff shl 8) or (b[pos + 1].toInt() and 0xff)
                    pos += 2
                }
                else -> if (n >= 0x80) throw IndexOutOfBoundsException("unsupported length")
            }
            if (n > b.size - pos) throw IndexOutOfBoundsException("short value")
            return b.copyOfRange(pos, pos + n).also { pos += n }
        }
    }
}
