// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

package tools.cbb.kit

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * The recovery key on a YubiKey (RecoveryCard): the core's refusals reach
 * the app as kinds it explains, and a card that leaves mid-step is a refusal
 * of the core, not a crash. The card's own steps are checked on the core's
 * fake card (TestFFIPhoneYubiKey). The same as the Swift kit's RecoveryCardTests.
 */
class RecoveryCardTest {
    @Test
    fun kindsOfTheCoresMessages() {
        val cases = listOf(
            "wrong PIN for the YubiKey; 2 attempts left before it is blocked" to RecoveryCard.Kind.WRONG_PIN,
            "the YubiKey's PIN is blocked: unblock it with its PUK (ykman piv access unblock-pin)" to RecoveryCard.Kind.BLOCKED,
            "cbb keeps the recovery key on a YubiKey 5 with firmware 5.3 or later" to RecoveryCard.Kind.OLD_FIRMWARE,
            "this YubiKey holds no recovery key of cbb" to RecoveryCard.Kind.NO_KEY,
            "this YubiKey already holds this group's recovery key: cbb opens it and never seals it again" to RecoveryCard.Kind.HOLDS_ONE,
            "every retired PIV slot of this YubiKey is in use" to RecoveryCard.Kind.NO_FREE_SLOT,
            "this YubiKey holds two recovery keys for this group: cbb does not choose between them" to RecoveryCard.Kind.TWO_SLOTS,
            "set a PIN-protected management key in YubiKey Manager first" to RecoveryCard.Kind.MANAGEMENT_KEY,
            "the YubiKey left the phone: hold it still until it is done (code 1)" to RecoveryCard.Kind.CARD,
        )
        for ((message, kind) in cases) {
            val f = RecoveryCard.Failure.of(message, "")
            assertEquals(kind, f.kind, message)
            assertEquals(message, f.reason)
        }
        assertEquals(2, RecoveryCard.Failure.of(cases[0].first, "").left)
        assertEquals("yubikey: x: y", RecoveryCard.Failure.of("x", "y").message)
    }

    @Test
    fun aCardThatLeavesIsACardFailure() {
        var sent = 0
        val gone = SmartCard {
            sent++
            throw java.io.IOException("gone")
        }
        val f = assertFailsWith<RecoveryCard.Failure> { RecoveryCard.open(gone, "123456", GROUP) }
        assertEquals(RecoveryCard.Kind.CARD, f.kind)
        assertTrue("left the phone" in f.reason, f.reason)
        assertEquals(1, sent, "the core stops at the first APDU the card does not answer")
    }

    @Test
    fun aCardWithoutPIVIsRefused() {
        val noPIV = SmartCard { byteArrayOf(0x6a, 0x82.toByte()) }
        assertFailsWith<RecoveryCard.Failure> { RecoveryCard.open(noPIV, "123456", GROUP) }
        assertFailsWith<RecoveryCard.Failure> { RecoveryCard.seal(noPIV, "123456", "a typo", GROUP) }
    }

    private companion object {
        /** A group's tag, as the app names the group's slot. */
        const val GROUP = "0123456789abcdef"
    }
}
