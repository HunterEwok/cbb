// SPDX-License-Identifier: AGPL-3.0-only
//
// A port of internal/third_party/cpace/cpace.go, Copyright 2026 The Go
// Authors, under the BSD-style license in internal/third_party/cpace/LICENSE.

import Crypto
import Foundation

/// The CPace password-authenticated key exchange, suite
/// CPACE-X25519-SHA512 of draft-irtf-cfrg-cpace-21, with explicit key
/// confirmation, as the Go side uses it (docs/protocol.md, section 6).
public struct CPace {
    public enum Role { case initiator, responder }

    public enum Failure: Error, Equatable {
        case alreadyFinished, ownMessage, invalidMessage, lowOrder, notFinished, confirmation
    }

    static let dsi = Array("CPace255".utf8)
    static let dsiISK = Array("CPace255_ISK".utf8)
    static let dsiSID = Array("CPaceSidOutput".utf8)
    static let dsiMac = Array("CPaceMac".utf8)
    static let blockSize = 128 // of SHA-512

    let role: Role
    let sid: [UInt8]
    let ad: [UInt8]
    /// This party's message, Ya or Yb.
    public let message: [UInt8]
    private var scalar: [UInt8]?
    private var tag: [UInt8]?
    private var peerTag: [UInt8]?

    /// Starts an exchange; send `message` with `ad` to the other party.
    public init(role: Role, password: [UInt8], channelID: [UInt8], sessionID: [UInt8], ad: [UInt8]) throws {
        var scalar = [UInt8](repeating: 0, count: 32)
        var rng = SystemRandomNumberGenerator()
        for i in scalar.indices { scalar[i] = UInt8.random(in: .min ... .max, using: &rng) }
        try self.init(role: role, password: password, channelID: channelID, sessionID: sessionID, ad: ad, scalar: scalar)
    }

    /// Starts an exchange with a given secret scalar, for tests.
    init(role: Role, password: [UInt8], channelID: [UInt8], sessionID: [UInt8], ad: [UInt8], scalar: [UInt8]) throws {
        self.role = role
        self.sid = sessionID
        self.ad = ad
        let g = CPace.generator(password: password, channelID: channelID, sessionID: sessionID)
        guard let y = try? CPace.x25519(scalar, g), y != [UInt8](repeating: 0, count: 32) else {
            throw Failure.invalidMessage
        }
        self.message = y
        self.scalar = scalar
    }

    /// Finishes the exchange with the other party's message and AD,
    /// returning the intermediate session key. It works once.
    public mutating func finish(peerMessage msg: [UInt8], peerAD: [UInt8]) throws -> [UInt8] {
        guard let scalar = scalar else { throw Failure.alreadyFinished }
        self.scalar = nil
        if msg == message { throw Failure.ownMessage }
        guard msg.count == 32 else { throw Failure.invalidMessage }
        guard let k = try? CPace.x25519(scalar, msg) else { throw Failure.invalidMessage }
        if k == [UInt8](repeating: 0, count: 32) { throw Failure.lowOrder }

        var (ya, ada, yb, adb) = (message, ad, msg, peerAD)
        if role == .responder { (ya, ada, yb, adb) = (yb, adb, ya, ada) }
        let transcript = CPace.lvCat([ya, ada]) + CPace.lvCat([yb, adb])
        let isk = Array(SHA512.hash(data: CPace.lvCat([CPace.dsiISK, sid, k]) + transcript))
        let macKey = Array(SHA512.hash(data: CPace.dsiMac + sid + isk))
        tag = CPace.mac(macKey, message, ad)
        peerTag = CPace.mac(macKey, msg, peerAD)
        return isk
    }

    /// This party's key confirmation tag, after `finish`.
    public var confirmationTag: [UInt8]? { tag }

    /// Checks the other party's key confirmation tag.
    public func verify(peerTag got: [UInt8]) throws {
        guard let want = peerTag else { throw Failure.notFinished }
        // Constant time: compare every byte.
        var diff: UInt8 = got.count == want.count ? 0 : 1
        for (a, b) in zip(got, want) { diff |= a ^ b }
        if diff != 0 { throw Failure.confirmation }
    }

    static func mac(_ key: [UInt8], _ msg: [UInt8], _ ad: [UInt8]) -> [UInt8] {
        Array(HMAC<SHA512>.authenticationCode(for: lvCat([msg, ad]), using: SymmetricKey(data: key)))
    }

    static func x25519(_ scalar: [UInt8], _ u: [UInt8]) throws -> [UInt8] {
        let priv = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: scalar)
        let pub = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: u)
        let shared = try priv.sharedSecretFromKeyAgreement(with: pub)
        return shared.withUnsafeBytes { Array($0) }
    }

    /// generator_string(DSI, PRS, CI, sid): the zero padding fills SHA-512's
    /// first block, so the bytes hashed do not depend on the password length.
    static func generatorString(password: [UInt8], channelID: [UInt8], sessionID: [UInt8]) -> [UInt8] {
        let b = lvCat([dsi, password])
        let zpad = max(0, blockSize - 1 - b.count)
        return b + lvCat([[UInt8](repeating: 0, count: zpad), channelID, sessionID])
    }

    static func generator(password: [UInt8], channelID: [UInt8], sessionID: [UInt8]) -> [UInt8] {
        let h = Array(SHA512.hash(data: generatorString(password: password, channelID: channelID, sessionID: sessionID)))
        return elligator2(FieldElement(bytes: Array(h[0..<32])))
    }

    /// prepend_len: the length in LEB128, then the bytes.
    static func prependLen(_ v: [UInt8]) -> [UInt8] {
        var out: [UInt8] = []
        var n = v.count
        repeat {
            out.append(n < 128 ? UInt8(n) : UInt8(n & 0x7f) | 0x80)
            n >>= 7
        } while n != 0
        return out + v
    }

    static func lvCat(_ vs: [[UInt8]]) -> [UInt8] { vs.flatMap(prependLen) }
}
