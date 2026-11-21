// SPDX-License-Identifier: AGPL-3.0-only

import CBBKit
import CryptoTokenKit
import Foundation

/// A YubiKey plugged into the iPhone's USB-C port, through CryptoTokenKit:
/// iOS drives the key's CCID interface itself and the app sends whole APDUs
/// (RecoveryCard's apdu transport). The slot manager may be missing (an
/// iPhone with Lightning, or a build iOS gives none), and then the app goes
/// on over NFC (YubiKeys.withCard).
enum YubiKeyUsb {
    /// The slot of a plugged-in smart card, if iOS shows one.
    static func pluggedSlot() async -> TKSmartCardSlot? {
        guard let manager = TKSmartCardSlotManager.default else { return nil }
        for name in manager.slotNames {
            let slot: TKSmartCardSlot? = await withCheckedContinuation { c in
                manager.getSlot(withName: name) { c.resume(returning: $0) }
            }
            if let slot, slot.state == .validCard { return slot }
        }
        return nil
    }

    /// Runs block on the card in slot, inside one session of the card.
    static func withCard<T>(_ slot: TKSmartCardSlot, _ block: @escaping (SmartCard) throws -> T) async throws -> T {
        guard let card = slot.makeSmartCard() else {
            throw RecoveryCard.Failure(kind: .card, message: "the YubiKey on USB gave no card")
        }
        let began: Bool = try await withCheckedThrowingContinuation { c in
            card.beginSession { ok, error in
                if let error { c.resume(throwing: RecoveryCard.Failure(kind: .card, message: "the YubiKey on USB: \(error)")) } else { c.resume(returning: ok) }
            }
        }
        guard began else { throw RecoveryCard.Failure(kind: .card, message: "the YubiKey on USB refused a session") }
        defer { card.endSession() }
        let wired = Wired(card: card)
        return try await withCheckedThrowingContinuation { (c: CheckedContinuation<T, Error>) in
            // The PIV commands wait for their answers here, not on a task's thread.
            DispatchQueue(label: "tools.cbb.yubikey.usb").async {
                c.resume(with: Result { try block(wired) })
            }
        }
    }

    /// The card as the kit's SmartCard: each command waits for its answer,
    /// the touch included.
    private final class Wired: SmartCard, @unchecked Sendable {
        let card: TKSmartCard
        init(card: TKSmartCard) { self.card = card }

        func transmit(_ apdu: Data) throws -> Data {
            let wait = DispatchSemaphore(value: 0)
            var out: Result<Data, Error> = .failure(RecoveryCard.Failure(kind: .card, message: "the YubiKey on USB did not answer"))
            card.transmit(apdu) { data, error in
                if let error {
                    out = .failure(RecoveryCard.Failure(kind: .card, message: "the YubiKey on USB: \(error)"))
                } else if let data {
                    out = .success(data)
                }
                wait.signal()
            }
            // Long enough for the touch.
            guard wait.wait(timeout: .now() + 30) == .success else {
                throw RecoveryCard.Failure(kind: .card, message: "the YubiKey on USB did not answer in time")
            }
            return try out.get()
        }
    }
}

/// A YubiKey for a step of the recovery key: one plugged into the USB-C port
/// when iOS shows it, else one held to the phone over NFC with the system's
/// sheet. plugged is called before a step on USB, so the screen can ask for
/// the touch.
enum YubiKeys {
    static func withCard<T>(prompt: String, done: String, plugged: @MainActor () -> Void,
                            _ block: @escaping (SmartCard) throws -> T) async throws -> T {
        if let slot = await YubiKeyUsb.pluggedSlot() {
            await plugged()
            return try await YubiKeyUsb.withCard(slot, block)
        }
        return try await YubiKeyNfc.withCard(prompt: prompt, done: done, block)
    }
}
