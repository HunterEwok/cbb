// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

@testable import CBBKit
import Foundation
import XCTest

/// The recovery key on a YubiKey (RecoveryCard): the core's refusals reach
/// the app as kinds it explains, and a card that leaves mid-step is a
/// refusal of the core, not a crash. The card's own steps are checked on
/// the core's fake card (TestFFIPhoneYubiKey).
final class RecoveryCardTests: XCTestCase {
    private let group = "0123456789abcdef"

    /// A card that is gone before it answers.
    private final class Gone: SmartCard {
        var sent = 0
        func transmit(_: Data) throws -> Data {
            sent += 1
            throw RecoveryCard.Failure(kind: .card, message: "gone")
        }
    }

    /// A card that answers every APDU "file not found".
    private final class NoPIV: SmartCard {
        func transmit(_: Data) throws -> Data { Data([0x6A, 0x82]) }
    }

    func testKindsOfTheCoresMessages() {
        let cases: [(String, RecoveryCard.Kind)] = [
            ("wrong PIN for the YubiKey; 2 attempts left before it is blocked", .wrongPIN),
            ("the YubiKey's PIN is blocked: unblock it with its PUK (ykman piv access unblock-pin)", .blocked),
            ("cbb keeps the recovery key on a YubiKey 5 with firmware 5.3 or later", .oldFirmware),
            ("this YubiKey holds no recovery key of cbb", .noKey),
            ("this YubiKey already holds this group's recovery key: cbb opens it and never seals it again", .holdsOne),
            ("every retired PIV slot of this YubiKey is in use", .noFreeSlot),
            ("this YubiKey holds two recovery keys for this group: cbb does not choose between them", .twoSlots),
            ("this YubiKey holds the recovery keys of more than one group: open it on a device of the group", .twoSlots),
            ("set a PIN-protected management key in YubiKey Manager first", .managementKey),
            ("the YubiKey left the phone: hold it still until it is done (code 1)", .card),
        ]
        for (message, kind) in cases {
            let f = RecoveryCard.Failure.of(message: message, details: "")
            XCTAssertEqual(f.kind, kind, message)
            XCTAssertEqual(f.message, message)
        }
        let wrong = RecoveryCard.Failure.of(message: cases[0].0, details: "")
        XCTAssertEqual(wrong.left, 2)
        XCTAssertEqual(RecoveryCard.Failure.of(message: "x", details: "y").description, "yubikey: x: y")
    }

    func testACardThatLeavesIsACardFailure() {
        let card = Gone()
        XCTAssertThrowsError(try RecoveryCard.open(card, pin: "123456", group: group)) { error in
            guard let f = error as? RecoveryCard.Failure else { return XCTFail("\(error)") }
            XCTAssertEqual(f.kind, .card)
            XCTAssertTrue(f.message.contains("left the phone"), f.message)
        }
        XCTAssertEqual(card.sent, 1, "the core stops at the first APDU the card does not answer")
    }

    func testACardWithoutPIVIsRefused() {
        XCTAssertThrowsError(try RecoveryCard.open(NoPIV(), pin: "123456", group: group)) { error in
            XCTAssertTrue(error is RecoveryCard.Failure, "\(error)")
        }
        XCTAssertThrowsError(try RecoveryCard.seal(NoPIV(), pin: "123456", sheet: "a typo", group: group)) { error in
            XCTAssertTrue(error is RecoveryCard.Failure, "\(error)")
        }
    }
}
