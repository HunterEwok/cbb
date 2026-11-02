// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package io.github.hunterewok.clipboardbridge.kit

import java.security.KeyPair
import java.security.SecureRandom
import java.security.Signature
import java.time.Instant
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Plays a YubiKey's PIV application, as Go's internal/piv/pivtest does:
 * the commands the kit sends, with the default management key (AES-192 as
 * firmware 5.7 has it; alg 0x03 names 3DES, as before, which the kit
 * refuses before it gets so far), answers in parts of 100 bytes and command
 * chaining.
 */
class FakePivCard(val alg: Int = 0x0b, val metadata: Boolean = true) : SmartCard {
    class Slot(val key: KeyPair?, var cert: ByteArray?, val pinPolicy: Int = 0, val touchPolicy: Int = 0)

    val slots = mutableMapOf<Int, Slot>()
    var pin = "123456"
    var tries = 3
    var signed = 0
    var managementKey = ByteArray(24) { ((it % 8) + 1).toByte() }
    private var selected = false
    private var verified = false
    private var authenticated = false
    private var witness: ByteArray? = null
    private var chain = ByteArray(0)
    private var pending = ByteArray(0)

    private fun sw(data: ByteArray, w: Int) = data + byteArrayOf((w shr 8).toByte(), w.toByte())

    private fun send(data: ByteArray): ByteArray {
        pending = data
        return next()
    }

    private fun next(): ByteArray {
        val part = pending.copyOf(minOf(100, pending.size))
        pending = pending.copyOfRange(part.size, pending.size)
        return if (pending.isEmpty()) sw(part, 0x9000) else sw(part, 0x6100 or minOf(pending.size, 0xff))
    }

    private val block = 16

    private fun crypt(mode: Int, b: ByteArray) =
        Cipher.getInstance("AES/CBC/NoPadding").run { init(mode, SecretKeySpec(managementKey, "AES"), IvParameterSpec(ByteArray(block))); doFinal(b) }

    override fun transmit(apdu: ByteArray): ByteArray {
        val cla = apdu[0].toInt() and 0xff
        val ins = apdu[1].toInt() and 0xff
        val p1 = apdu[2].toInt() and 0xff
        val p2 = apdu[3].toInt() and 0xff
        var data = if (apdu.size > 5) apdu.copyOfRange(5, 5 + (apdu[4].toInt() and 0xff)) else ByteArray(0)
        if (ins == 0xc0) return next()
        if (cla and 0x10 != 0) {
            chain += data
            return sw(ByteArray(0), 0x9000)
        }
        data = chain + data
        chain = ByteArray(0)
        if (ins == 0xa4) {
            if (!data.contentEquals(byteArrayOf(0xa0.toByte(), 0, 0, 3, 8))) return sw(ByteArray(0), 0x6a82)
            selected = true
            verified = false
            authenticated = false
            return sw(ByteArray(0), 0x9000)
        }
        if (!selected) return sw(ByteArray(0), 0x6d00)
        return when (ins) {
            0xcb -> {
                val obj = Piv.TLV(data).value(0x5c)
                val slot = 0x82 + (obj[2].toInt() and 0xff) - 0x0d
                val c = slots[slot]?.cert ?: return sw(ByteArray(0), 0x6a82)
                send(Piv.tlv(0x53, Piv.tlv(0x70, c) + Piv.tlv(0x71, byteArrayOf(0)) + Piv.tlv(0xfe, ByteArray(0))))
            }
            0xdb -> {
                if (!authenticated) return sw(ByteArray(0), 0x6982)
                val t = Piv.TLV(data)
                val obj = t.value(0x5c)
                val slot = 0x82 + (obj[2].toInt() and 0xff) - 0x0d
                val inner = Piv.TLV(t.value(0x53))
                val s = slots[slot] ?: Slot(null, null).also { slots[slot] = it }
                s.cert = inner.value(0x70)
                sw(ByteArray(0), 0x9000)
            }
            0xf7 -> {
                if (!metadata) return sw(ByteArray(0), 0x6d00)
                if (p2 == 0x9b) return sw(Piv.tlv(0x01, byteArrayOf(alg.toByte())), 0x9000)
                if (slots[p2]?.key == null) sw(ByteArray(0), 0x6a82) else sw(Piv.tlv(0x01, byteArrayOf(0x11)), 0x9000)
            }
            0x20 -> {
                if (tries == 0) return sw(ByteArray(0), 0x6983)
                val got = String(data.takeWhile { it != 0xff.toByte() }.toByteArray())
                if (got != pin) {
                    tries--
                    return sw(ByteArray(0), 0x63c0 or tries)
                }
                tries = 3
                verified = true
                sw(ByteArray(0), 0x9000)
            }
            0x47 -> {
                if (!authenticated) return sw(ByteArray(0), 0x6982)
                val spec = Piv.TLV(Piv.TLV(data).value(0xac))
                assertContentEquals(byteArrayOf(0x11), spec.value(0x80))
                val pinPolicy = spec.value(0xaa)[0].toInt()
                val touchPolicy = spec.value(0xab)[0].toInt()
                val k = SoftwareSigner.generate()
                slots[p2] = Slot(k, null, pinPolicy, touchPolicy)
                val point = byteArrayOf(4) + k.public.encoded.copyOfRange(27, 91)
                send(byteArrayOf(0x7f, 0x49) + Piv.tlv(0x86, point).let { byteArrayOf(it.size.toByte()) + it })
            }
            0x87 -> {
                val v = Piv.TLV(Piv.TLV(data).value(0x7c))
                if (p2 == 0x9b) {
                    val tag = v.peek
                    val first = v.value(0x80)
                    if (first.isEmpty()) {
                        witness = ByteArray(block).also { SecureRandom().nextBytes(it) }
                        return send(Piv.tlv(0x7c, Piv.tlv(0x80, crypt(Cipher.ENCRYPT_MODE, witness!!))))
                    }
                    check(tag == 0x80)
                    if (!first.contentEquals(witness)) return sw(ByteArray(0), 0x6982)
                    val challenge = v.value(0x81)
                    authenticated = true
                    return send(Piv.tlv(0x7c, Piv.tlv(0x82, crypt(Cipher.ENCRYPT_MODE, challenge))))
                }
                val s = slots[p2]?.key ?: return sw(ByteArray(0), 0x6a86)
                if (!verified) return sw(ByteArray(0), 0x6982)
                if (slots[p2]!!.pinPolicy == 0x03) verified = false
                v.value(0x82)
                val digest = v.value(0x81)
                val sig = Signature.getInstance("NONEwithECDSA").run {
                    initSign(s.private)
                    update(digest)
                    sign()
                }
                signed++
                send(Piv.tlv(0x7c, Piv.tlv(0x82, sig)))
            }
            else -> sw(ByteArray(0), 0x6d00)
        }
    }
}

class PivTest {
    private val t0 = Instant.now().minusSeconds(100L * 3600)

    @Test
    fun putsTheRecoveryKeyOnTheCardAndRestoresWithIt() {
        run {
            val card = FakePivCard()
            // Slot 82 holds something else, as a release root.
            card.slots[0x82] = FakePivCard.Slot(SoftwareSigner.generate(), null)
            val rootKey = SoftwareSigner()
            val root = PhoneGroup.create(rootKey, SoftwareSigner().publicKeyDER, t0, "Lost")
            root.records.clock = { t0 }

            Piv.select(card)
            Piv.verify(card, "123456")
            Piv.authenticate(card)
            val slot = Piv.freeSlot(card)
            assertEquals(0x83, slot, "the first free slot")
            val spki = Piv.generate(card, slot)
            assertEquals(0x03, card.slots[slot]!!.pinPolicy, "the PIN before each signature")
            assertEquals(0x02, card.slots[slot]!!.touchPolicy, "a touch before each signature")
            val (ca, record) = root.makeRecoveryOnCard(spki, rootKey, t0)
            Piv.putCertificate(card, slot, ca)
            assertTrue(root.records.records.any { it.body.contentEquals(record.body) })
            assertContentEquals(Records.keyHashOfCert(ca), root.records.recovery)

            // A new phone finds it.
            Piv.select(card)
            val keys = Piv.recoveryKeys(card)
            assertEquals(listOf(slot), keys.map { it.first })
            val signer = Piv.Signer(card, slot, CertificateInfo(keys[0].second).publicKey, "123456")
            val r = Restore.onCard(signer, keys[0].second, SoftwareSigner().publicKeyDER, t0)
            assertEquals(r.device, GroupCertificates.verifyMember(r.chain, listOf(root.groupCA), t0))
            assertEquals(1, card.signed, "the card signed the member certificate")
        }
    }

    @Test
    fun refusesWhatDoesNotFit() {
        val card = FakePivCard()
        Piv.select(card)
        val wrong = assertFailsWith<Piv.Failure> { Piv.verify(card, "654321") }
        assertEquals(Piv.Kind.WRONG_PIN, wrong.kind)
        assertEquals(2, wrong.left)
        Piv.verify(card, "123456")

        card.managementKey = ByteArray(24) { 7 }
        assertEquals(Piv.Kind.MANAGEMENT_KEY, assertFailsWith<Piv.Failure> { Piv.authenticate(card) }.kind)
        assertEquals(Piv.Kind.MANAGEMENT_KEY, assertFailsWith<Piv.Failure> { Piv.generate(card, 0x83) }.kind)
        assertTrue(Piv.recoveryKeys(card).isEmpty())

        val full = FakePivCard()
        for (s in Piv.FIRST_SLOT..Piv.LAST_SLOT) full.slots[s] = FakePivCard.Slot(SoftwareSigner.generate(), null)
        Piv.select(full)
        assertEquals(Piv.Kind.NO_FREE_SLOT, assertFailsWith<Piv.Failure> { Piv.freeSlot(full) }.kind)

        // A card without metadata counts a slot without a certificate as free.
        val old = FakePivCard(metadata = false)
        Piv.select(old)
        assertEquals(Piv.FIRST_SLOT, Piv.freeSlot(old))
        // The kit uses AES only: a 3DES management key, or a card that does not say, is refused.
        Piv.verify(old, "123456")
        assertEquals(Piv.Kind.OLD_FIRMWARE, assertFailsWith<Piv.Failure> { Piv.authenticate(old) }.kind)
        val des = FakePivCard(alg = 0x03)
        Piv.select(des)
        Piv.verify(des, "123456")
        assertEquals(Piv.Kind.OLD_FIRMWARE, assertFailsWith<Piv.Failure> { Piv.authenticate(des) }.kind)

        assertEquals(Piv.Kind.NO_PIV, assertFailsWith<Piv.Failure> { Piv.select { byteArrayOf(0x6a, 0x82.toByte()) } }.kind)
    }

    @Test
    fun signerChecksTheKey() {
        val card = FakePivCard()
        Piv.select(card)
        Piv.verify(card, "123456")
        Piv.authenticate(card)
        val spki = Piv.generate(card, 0x84)
        val s = Piv.Signer(card, 0x84, spki, "123456")
        val sig = s.signature("data".toByteArray())
        assertTrue(Signature.getInstance("SHA256withECDSA").run {
            initVerify(p256PublicKey(spki))
            update("data".toByteArray())
            verify(sig)
        })
        val other = Piv.Signer(card, 0x84, SoftwareSigner().publicKeyDER, "123456")
        assertFailsWith<Piv.Failure> { other.signature("data".toByteArray()) }
        assertFalse(card.slots[0x84]!!.cert != null)
        assertNotNull(card.slots[0x84]!!.key)
    }

    @Test
    fun tlv() {
        for (n in listOf(0, 0x7f, 0x80, 0xff, 0x100, 0x1234)) {
            val t = Piv.TLV(Piv.tlv(0x53, ByteArray(n)) + byteArrayOf(1))
            assertEquals(n, t.value(0x53).size)
            assertFalse(t.done)
        }
        for (b in listOf(byteArrayOf(0x53), byteArrayOf(0x54, 0), byteArrayOf(0x53, 0x83.toByte(), 0, 0, 1), byteArrayOf(0x53, 2, 0))) {
            assertFailsWith<IndexOutOfBoundsException> { Piv.TLV(b).value(0x53) }
        }
    }
}
