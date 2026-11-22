// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import CCbbCore
import Foundation

/// A connection to a smart card, as the app gets one over NFC
/// (NFCISO7816Tag): transmit sends one APDU and returns the answer with its
/// status word last.
public protocol SmartCard: AnyObject {
    func transmit(_ apdu: Data) throws -> Data
}

/// The group's recovery secret on a YubiKey (docs/protocol.md, "The recovery
/// key on a YubiKey (0.6)"): the core speaks PIV (`cbb_piv`, docs/core-api.md)
/// and the app only carries each APDU to the card. The root phone seals the
/// sheet's secret onto the card; a phone in the group opens it with the PIN
/// to change the root. The same as the Kotlin kit's RecoveryCard.
public enum RecoveryCard {
    public enum Kind: Sendable, Equatable {
        /// The PIN is wrong; Failure.left says how many tries are left.
        case wrongPIN
        /// The PIN is blocked: the card's PUK unblocks it.
        case blocked
        /// The card is older than firmware 5.3 or no YubiKey 5.
        case oldFirmware
        /// The card holds no recovery key of cbb.
        case noKey
        /// The card holds this group's recovery key already, which is never sealed again.
        case holdsOne
        /// Every retired PIV slot of the card is in use.
        case noFreeSlot
        /// The card holds two recovery keys for the group, and cbb does not choose.
        case twoSlots
        /// The card's management key is one the app cannot use.
        case managementKey
        /// The card left, refused, or its answer does not parse.
        case card
    }

    /// The core's refusal, with what the app says of it.
    public struct Failure: Error, CustomStringConvertible {
        public let kind: Kind
        public let message: String
        public let details: String
        /// The PIN's tries left after .wrongPIN.
        public var left = 0
        public var description: String { details.isEmpty ? "yubikey: \(message)" : "yubikey: \(message): \(details)" }

        public init(kind: Kind, message: String, details: String = "", left: Int = 0) {
            (self.kind, self.message, self.details, self.left) = (kind, message, details, left)
        }

        /// The kind of the core's message (member/src/piv.rs and piv/recovery.rs).
        static func of(message m: String, details: String) -> Failure {
            var f = Failure(kind: .card, message: m, details: details)
            if m.contains("wrong PIN") {
                f = Failure(kind: .wrongPIN, message: m, details: details)
                f.left = Int(m.split(separator: ";").last?.split(separator: " ").first { Int($0) != nil } ?? "") ?? 0
            } else if m.contains("PIN is blocked") {
                f = Failure(kind: .blocked, message: m, details: details)
            } else if m.contains("firmware 5.3") {
                f = Failure(kind: .oldFirmware, message: m, details: details)
            } else if m.contains("holds no recovery key") {
                f = Failure(kind: .noKey, message: m, details: details)
            } else if m.contains("already holds this group's recovery key") {
                f = Failure(kind: .holdsOne, message: m, details: details)
            } else if m.contains("retired PIV slot") {
                f = Failure(kind: .noFreeSlot, message: m, details: details)
            } else if m.contains("two recovery keys") || m.contains("more than one group") {
                f = Failure(kind: .twoSlots, message: m, details: details)
            } else if m.contains("management key") {
                f = Failure(kind: .managementKey, message: m, details: details)
            }
            return f
        }
    }

    /// What sealing did: the retired PIV slot that took the key (0x95 down
    /// to 0x82), and whether the card still has its factory management key,
    /// which cbb uses as it is and never changes.
    public struct Sealed: Decodable, Equatable, Sendable {
        public var slot: Int
        public var defaultKey: Bool

        enum CodingKeys: String, CodingKey {
            case slot, defaultKey = "default_key"
        }
    }

    /// Seals the recovery key's secret onto the card, into the first empty
    /// retired slot: sheet is the sheet's QR code or its text; group is the
    /// group's ID in hex (or its first 16 hex digits), which names the slot.
    public static func seal(_ card: SmartCard, pin: String, sheet: String, group: String) throws -> Sealed {
        struct A: Encodable { var op = "seal", pin: String, recovery: [String: String], group: String }
        return try run(card, A(pin: pin, recovery: ["text": sheet], group: group), as: Sealed.self)
    }

    /// Opens the group's secret after the PIN and a touch, for a change of
    /// root (RecoveryInput.secret); the caller drops it after that one use.
    public static func open(_ card: SmartCard, pin: String, group: String) throws -> Data {
        struct A: Encodable { var op = "open", pin: String, group: String }
        struct R: Decodable { var secret: Data }
        return try run(card, A(pin: pin, group: group), as: R.self).secret
    }

    private struct Reply<R: Decodable>: Decodable {
        var ok: R?
        var error: Refused?
    }

    private struct Refused: Decodable {
        var message: String
        var details: String?
    }

    /// The card of one cbb_piv call, which the core calls during it only.
    fileprivate final class Carrier {
        let card: SmartCard
        init(_ card: SmartCard) { self.card = card }
    }

    private static func run<A: Encodable, R: Decodable>(_ card: SmartCard, _ request: A, as _: R.Type) throws -> R {
        let bytes = try JSONEncoder().encode(request)
        let carrier = Carrier(card)
        var count = 0
        let answer: UnsafeMutablePointer<UInt8>? = withExtendedLifetime(carrier) {
            let raw = Unmanaged.passUnretained(carrier).toOpaque()
            return bytes.withUnsafeBytes { r in
                cbb_piv(r.bindMemory(to: UInt8.self).baseAddress, r.count, recoveryCardTransmit, raw, &count)
            }
        }
        guard let answer else { throw Core.Mismatch(reason: "the core gave no answer to the YubiKey step") }
        defer { cbb_free(answer, count) }
        let reply: Reply<R>
        do {
            reply = try JSONDecoder().decode(Reply<R>.self, from: Data(bytes: answer, count: count))
        } catch {
            throw Core.Mismatch(reason: "the core's answer to the YubiKey step does not read: \(error)")
        }
        if let e = reply.error { throw Failure.of(message: e.message, details: e.details ?? "") }
        guard let ok = reply.ok else { throw Core.Mismatch(reason: "the core's answer to the YubiKey step has neither ok nor error") }
        return ok
    }
}

/// cbb_transmit_fn: one APDU to the card of the call.
private func recoveryCardTransmit(_ ctx: UnsafeMutableRawPointer?, _ apdu: UnsafePointer<UInt8>?, _ len: Int,
                                  _ out: UnsafeMutablePointer<UInt8>?, _ cap: Int, _ outLen: UnsafeMutablePointer<Int>?) -> Int32 {
    guard let ctx, let apdu, let out, let outLen else { return 1 }
    let carrier = Unmanaged<RecoveryCard.Carrier>.fromOpaque(ctx).takeUnretainedValue()
    guard let r = try? carrier.card.transmit(Data(bytes: apdu, count: len)), r.count <= cap else { return 1 }
    r.copyBytes(to: out, count: r.count)
    outLen.pointee = r.count
    return 0
}
