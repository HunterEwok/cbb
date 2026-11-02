// SPDX-License-Identifier: AGPL-3.0-only

#if canImport(CommonCrypto)
import CommonCrypto
#endif
import _CryptoExtras
import Crypto
import Foundation

/// A connection to a smart card, as the app gets one over NFC
/// (NFCISO7816Tag) or USB: transmit sends one APDU and returns the answer
/// with its status word last.
public protocol SmartCard: AnyObject {
    func transmit(_ apdu: Data) throws -> Data
}

/// The group's recovery key on a YubiKey, or another card with the PIV
/// application (docs/protocol.md, section 10, "The recovery key", "On a
/// hardware key"): the root phone has the card make a P-256 key in a free
/// retired slot (82 to 95), where it never leaves the card, and stores the
/// key's admin CA as the slot's certificate; a new phone, as Go's
/// internal/piv on a computer, finds the slot by that certificate and has
/// the card sign. Nothing else on the card is changed: it may be in use for
/// other things. The same as the Kotlin kit's Piv.
public enum Piv {
    public enum Kind: Sendable {
        /// The card has no PIV application.
        case noPIV
        /// The PIN is wrong; Failure.left says how many tries are left.
        case wrongPIN
        /// The PIN is blocked: the card's PUK unblocks it.
        case blocked
        /// The card's management key is not the default one, which making a key needs.
        case managementKey
        /// Every retired slot holds a key or a certificate.
        case noFreeSlot
        /// No retired slot holds a recovery key's certificate.
        case noKey
        /// The card refused, or its answer does not parse.
        case card
    }

    public struct Failure: Error, CustomStringConvertible {
        public let kind: Kind
        public let message: String
        /// The PIN's tries left after .wrongPIN.
        public var left = 0
        public var description: String { message }

        public init(kind: Kind, message: String, left: Int = 0) {
            (self.kind, self.message, self.left) = (kind, message, left)
        }
    }

    /// The retired slots, where the recovery key goes.
    public static let firstSlot: UInt8 = 0x82
    public static let lastSlot: UInt8 = 0x95

    static let aid = Data([0xa0, 0x00, 0x00, 0x03, 0x08])
    static let algP256: UInt8 = 0x11
    static let pinRef: UInt8 = 0x80
    static let managementSlot: UInt8 = 0x9b
    /// The management key a YubiKey has from the factory: 3DES before firmware 5.7, AES-192 from it.
    public static let defaultManagementKey = Data((0..<24).map { UInt8($0 % 8 + 1) })
    /// The recovery key's policies: the PIN and a touch before each signature.
    static let pinAlways: UInt8 = 0x03
    static let touchAlways: UInt8 = 0x02
    static let maxAnswer = 16 << 10

    static func fail(_ kind: Kind, _ message: String) -> Failure { Failure(kind: kind, message: message) }

    static func cardFail(_ what: String, _ sw: UInt16) -> Failure {
        fail(.card, "\(what): the card answered \(String(format: "%04x", sw))")
    }

    /// A certificate object's tag: 5FC10D for slot 82, up to 5FC120 for slot 95.
    static func certObject(_ slot: UInt8) throws -> Data {
        guard slot >= firstSlot, slot <= lastSlot else { throw fail(.card, "not a retired slot") }
        return Data([0x5f, 0xc1, 0x0d + slot - firstSlot])
    }

    /// Sends one command, chaining data longer than 255 bytes and following 61xx with GET RESPONSE.
    static func command(_ card: SmartCard, _ ins: UInt8, _ p1: UInt8, _ p2: UInt8, _ data: Data = Data()) throws -> (Data, UInt16) {
        var rest = data
        while rest.count > 255 {
            let (_, sw) = try transmit(card, Data([0x10, ins, p1, p2, 0xff]) + rest.prefix(255))
            if sw != 0x9000 { return (Data(), sw) }
            rest = Data(rest.dropFirst(255))
        }
        var apdu = Data([0x00, ins, p1, p2])
        if !rest.isEmpty { apdu += Data([UInt8(rest.count)]) + rest }
        return try transmit(card, apdu + Data([0]))
    }

    static func transmit(_ card: SmartCard, _ first: Data) throws -> (Data, UInt16) {
        var apdu = first
        var out = Data()
        while true {
            let r = try card.transmit(apdu)
            guard r.count >= 2 else { throw fail(.card, "the card's answer has no status word") }
            out += r.dropLast(2)
            guard out.count <= maxAnswer else { throw fail(.card, "the card's answer is too long") }
            let sw1 = r[r.endIndex - 2], sw2 = r[r.endIndex - 1]
            if sw1 != 0x61 { return (out, UInt16(sw1) << 8 | UInt16(sw2)) }
            apdu = Data([0x00, 0xc0, 0x00, 0x00, sw2])
        }
    }

    /// Selects the PIV application.
    public static func select(_ card: SmartCard) throws {
        let (_, sw) = try command(card, 0xa4, 0x04, 0x00, aid)
        guard sw == 0x9000 else { throw fail(.noPIV, "this card has no PIV application") }
    }

    /// Checks the PIN, which the card then takes as given for the next signature.
    public static func verify(_ card: SmartCard, pin: String) throws {
        let b = Data(pin.utf8)
        guard (6...8).contains(b.count) else { throw fail(.wrongPIN, "a YubiKey's PIN has 6 to 8 characters") }
        let (_, sw) = try command(card, 0x20, 0x00, pinRef, b + Data(repeating: 0xff, count: 8 - b.count))
        switch sw {
        case 0x9000: return
        case 0x6983, 0x63c0: throw fail(.blocked, "the YubiKey's PIN is blocked: its PUK unblocks it")
        case _ where sw & 0xfff0 == 0x63c0:
            var f = fail(.wrongPIN, "wrong PIN for the YubiKey; \(sw & 0xf) tries left before it is blocked")
            f.left = Int(sw & 0xf)
            throw f
        default: throw cardFail("checking the PIN", sw)
        }
    }

    /// A retired slot's certificate, DER; nil when it holds none.
    public static func certificate(_ card: SmartCard, slot: UInt8) throws -> Data? {
        let (data, sw) = try command(card, 0xcb, 0x3f, 0xff, tlv(0x5c, try certObject(slot)))
        if sw == 0x6a82 { return nil }
        guard sw == 0x9000 else { throw cardFail("reading a certificate", sw) }
        do {
            var obj = TLV(data)
            var t = TLV(try obj.value(0x53))
            let der = try t.value(0x70)
            if !t.done, t.peek == 0x71, let info = try t.value(0x71).first, info != 0 {
                throw fail(.card, "the certificate is compressed")
            }
            return der
        } catch let e as Failure {
            throw e
        } catch {
            throw fail(.card, "the certificate object does not parse")
        }
    }

    /// The recovery keys the card may hold: each retired slot whose
    /// certificate is not its own issuer, as an admin CA under a root is,
    /// with the slot. The certificate of the one the group's records name is
    /// the recovery key's admin CA.
    public static func recoveryKeys(_ card: SmartCard) throws -> [(slot: UInt8, cert: Data)] {
        var out: [(UInt8, Data)] = []
        for slot in firstSlot...lastSlot {
            guard let der = try certificate(card, slot: slot), let info = try? CertificateInfo(der: der),
                  (try? P256.Signing.PublicKey(derRepresentation: info.publicKey)) != nil, !info.selfIssued else { continue }
            out.append((slot, der))
        }
        return out
    }

    /// Whether a slot is free: no key, as the card's metadata says (YubiKey
    /// 5.3 and later), and no certificate. A card without metadata counts a
    /// slot without a certificate as free.
    static func free(_ card: SmartCard, _ slot: UInt8) throws -> Bool {
        if try certificate(card, slot: slot) != nil { return false }
        let (_, sw) = try command(card, 0xf7, 0x00, slot)
        return sw == 0x6a82 || sw == 0x6d00 || sw == 0x6a81
    }

    /// The first free retired slot.
    public static func freeSlot(_ card: SmartCard) throws -> UInt8 {
        for slot in firstSlot...lastSlot where try free(card, slot) { return slot }
        throw fail(.noFreeSlot, "every retired PIV slot of this YubiKey is in use")
    }

    /// Authenticates with the default management key, which making a key
    /// and storing its certificate need; the algorithm is the one the
    /// card's metadata names, 3DES without it.
    public static func authenticate(_ card: SmartCard, key: Data = defaultManagementKey) throws {
        let (meta, msw) = try command(card, 0xf7, 0x00, managementSlot)
        var alg: UInt8 = 0x03
        if msw == 0x9000 {
            var t = TLV(meta)
            while !t.done {
                let tag = t.peek
                guard let v = try? t.value(tag) else { break }
                if tag == 0x01, v.count == 1 { alg = v[v.startIndex] }
            }
        }
        let block: Int
        let keyLength: Int
        switch alg {
        case 0x03: (block, keyLength) = (8, 24)
        case 0x0a: (block, keyLength) = (16, 16)
        case 0x0b: (block, keyLength) = (16, 24)
        case 0x0c: (block, keyLength) = (16, 32)
        default: throw fail(.managementKey, "the YubiKey's management key has an unknown algorithm")
        }
        guard key.count == keyLength else { throw fail(.managementKey, "the YubiKey's management key is not the default one") }

        let (w, sw1) = try command(card, 0x87, alg, managementSlot, tlv(0x7c, tlv(0x80, Data())))
        guard sw1 == 0x9000 else { throw cardFail("starting authentication", sw1) }
        let witness: Data
        do {
            var outer = TLV(w)
            var inner = TLV(try outer.value(0x7c))
            witness = try inner.value(0x80)
        } catch {
            throw fail(.card, "the card's witness does not parse")
        }
        guard witness.count == block else { throw fail(.card, "the card's witness has the wrong size") }
        var challenge = Data(count: block)
        for i in challenge.indices { challenge[i] = UInt8.random(in: 0...255) }
        let decrypted = try crypt(alg, key, witness, encrypt: false)
        let (r, sw2) = try command(card, 0x87, alg, managementSlot, tlv(0x7c, tlv(0x80, decrypted) + tlv(0x81, challenge)))
        if sw2 == 0x6982 || sw2 == 0x6a80 { throw fail(.managementKey, "the YubiKey's management key is not the default one") }
        guard sw2 == 0x9000 else { throw cardFail("authenticating", sw2) }
        let answer: Data
        do {
            var outer = TLV(r)
            var inner = TLV(try outer.value(0x7c))
            answer = try inner.value(0x82)
        } catch {
            throw fail(.card, "the card's answer does not parse")
        }
        guard answer == (try crypt(alg, key, challenge, encrypt: true)) else { throw fail(.card, "the card did not prove the management key") }
    }

    /// One block with the management key: 3DES or AES in ECB.
    static func crypt(_ alg: UInt8, _ key: Data, _ block: Data, encrypt: Bool) throws -> Data {
        #if canImport(CommonCrypto)
        let algorithm = alg == 0x03 ? CCAlgorithm(kCCAlgorithm3DES) : CCAlgorithm(kCCAlgorithmAES)
        var out = Data(count: block.count)
        var moved = 0
        let status = out.withUnsafeMutableBytes { o in
            block.withUnsafeBytes { i in
                key.withUnsafeBytes { k in
                    CCCrypt(CCOperation(encrypt ? kCCEncrypt : kCCDecrypt), algorithm, CCOptions(kCCOptionECBMode),
                            k.baseAddress, key.count, nil, i.baseAddress, block.count, o.baseAddress, block.count, &moved)
                }
            }
        }
        guard status == CCCryptorStatus(kCCSuccess), moved == block.count else { throw fail(.card, "the management key's cipher failed") }
        return out
        #else
        // One block of CBC with a zero IV is ECB; 3DES has no implementation here.
        guard alg != 0x03 else { throw fail(.managementKey, "3DES is not available on this platform") }
        let k = SymmetricKey(data: key)
        let iv = try AES._CBC.IV(ivBytes: [UInt8](repeating: 0, count: 16))
        if encrypt {
            return Data(try AES._CBC.encrypt(block, using: k, iv: iv, noPadding: true))
        }
        return Data(try AES._CBC.decrypt(block, using: k, iv: iv, noPadding: true))
        #endif
    }

    /// Has the card make a P-256 key in slot, which asks for the PIN and a
    /// touch before each signature, and returns its SubjectPublicKeyInfo;
    /// authenticate must come first.
    public static func generate(_ card: SmartCard, slot: UInt8) throws -> Data {
        _ = try certObject(slot)
        let spec = tlv(0xac, tlv(0x80, Data([algP256])) + tlv(0xaa, Data([pinAlways])) + tlv(0xab, Data([touchAlways])))
        let (data, sw) = try command(card, 0x47, 0x00, slot, spec)
        if sw == 0x6982 { throw fail(.managementKey, "the YubiKey wants its management key first") }
        guard sw == 0x9000 else { throw cardFail("making the key", sw) }
        let point: Data
        do {
            var outer = TLV(data)
            var inner = TLV(try outer.value2(0x7f49))
            point = try inner.value(0x86)
        } catch {
            throw fail(.card, "the new key does not parse")
        }
        guard let key = try? P256.Signing.PublicKey(x963Representation: point) else { throw fail(.card, "the new key is not a P-256 key") }
        return key.derRepresentation
    }

    /// Stores cert, DER, as slot's certificate; authenticate must come first.
    public static func putCertificate(_ card: SmartCard, slot: UInt8, cert: Data) throws {
        let obj = tlv(0x53, tlv(0x70, cert) + tlv(0x71, Data([0])) + tlv(0xfe, Data()))
        let (_, sw) = try command(card, 0xdb, 0x3f, 0xff, tlv(0x5c, try certObject(slot)) + obj)
        guard sw == 0x9000 else { throw cardFail("storing the certificate", sw) }
    }

    /// The key in slot as a CertificateSigner, with the public key
    /// publicKeyDER: each signature checks pin first, as the key asks, and
    /// is checked against the public key, so that a card with another key
    /// in the slot never signs what would not verify.
    public final class Signer: CertificateSigner, @unchecked Sendable {
        let card: SmartCard
        let slot: UInt8
        let pin: String
        public let publicKeyDER: Data

        public init(card: SmartCard, slot: UInt8, publicKeyDER: Data, pin: String) {
            (self.card, self.slot, self.publicKeyDER, self.pin) = (card, slot, publicKeyDER, pin)
        }

        public func signature(for data: Data) throws -> Data {
            try Piv.verify(card, pin: pin)
            let digest = Data(SHA256.hash(data: data))
            let (r, sw) = try Piv.command(card, 0x87, Piv.algP256, slot, Piv.tlv(0x7c, Piv.tlv(0x82, Data()) + Piv.tlv(0x81, digest)))
            if sw == 0x6982 { throw Piv.fail(.card, "the YubiKey wants its PIN first") }
            guard sw == 0x9000 else { throw Piv.cardFail("signing", sw) }
            let sig: Data
            do {
                var outer = TLV(r)
                var inner = TLV(try outer.value(0x7c))
                sig = try inner.value(0x82)
            } catch {
                throw Piv.fail(.card, "the signature does not parse")
            }
            guard let pub = try? P256.Signing.PublicKey(derRepresentation: publicKeyDER),
                  let s = try? P256.Signing.ECDSASignature(derRepresentation: sig),
                  pub.isValidSignature(s, for: data) else {
                throw Piv.fail(.card, "the YubiKey's signature does not match its certificate's key")
            }
            return sig
        }
    }

    static func tlv(_ tag: UInt16, _ v: Data) -> Data {
        var out = tag > 0xff ? Data([UInt8(tag >> 8), UInt8(tag & 0xff)]) : Data([UInt8(tag)])
        switch v.count {
        case ..<0x80: out.append(UInt8(v.count))
        case ..<0x100: out += Data([0x81, UInt8(v.count)])
        default: out += Data([0x82, UInt8(v.count >> 8), UInt8(v.count & 0xff)])
        }
        return out + v
    }

    /// Reads BER-TLV values in a row.
    struct TLV {
        struct Malformed: Error {}
        let b: [UInt8]
        var pos = 0
        init(_ d: Data) { b = [UInt8](d) }
        var done: Bool { pos >= b.count }
        var peek: UInt8 { b[pos] }

        /// The value of the next element, whose one-byte tag must be tag.
        mutating func value(_ tag: UInt8) throws -> Data {
            guard !done, b[pos] == tag else { throw Malformed() }
            pos += 1
            return try rest()
        }

        /// The value of the next element, whose two-byte tag must be tag.
        mutating func value2(_ tag: UInt16) throws -> Data {
            guard pos + 1 < b.count, b[pos] == UInt8(tag >> 8), b[pos + 1] == UInt8(tag & 0xff) else { throw Malformed() }
            pos += 2
            return try rest()
        }

        private mutating func rest() throws -> Data {
            guard pos < b.count else { throw Malformed() }
            var n = Int(b[pos])
            pos += 1
            switch n {
            case 0x81:
                guard pos < b.count else { throw Malformed() }
                n = Int(b[pos])
                pos += 1
            case 0x82:
                guard pos + 1 < b.count else { throw Malformed() }
                n = Int(b[pos]) << 8 | Int(b[pos + 1])
                pos += 2
            case 0x80...: throw Malformed()
            default: break
            }
            guard n <= b.count - pos else { throw Malformed() }
            defer { pos += n }
            return Data(b[pos..<pos + n])
        }
    }
}
