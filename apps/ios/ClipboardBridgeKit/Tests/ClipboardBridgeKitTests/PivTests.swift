// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

@testable import ClipboardBridgeKit
import Crypto
import Foundation
import XCTest

/// Plays a YubiKey's PIV application, as the Kotlin kit's FakePivCard and
/// Go's pivtest do: the commands the kit sends, with the default
/// management key (AES-192 as firmware 5.7 has it; alg 0x03 names 3DES, as
/// before, which the kit refuses before it gets so far), answers in parts
/// of 100 bytes and command chaining.
final class FakePivCard: SmartCard {
    struct Slot {
        var key: P256.Signing.PrivateKey?
        var cert: Data?
        var pinPolicy: UInt8 = 0
        var touchPolicy: UInt8 = 0
    }

    let alg: UInt8
    let metadata: Bool
    var slots: [UInt8: Slot] = [:]
    var pin = "123456"
    var tries = 3
    var signed = 0
    var managementKey = Piv.defaultManagementKey
    private var selected = false, verified = false, authenticated = false
    private var witness = Data()
    private var chain = Data()
    private var pending = Data()

    init(alg: UInt8 = 0x0b, metadata: Bool = true) { (self.alg, self.metadata) = (alg, metadata) }

    private func sw(_ d: Data, _ w: UInt16) -> Data { d + Data([UInt8(w >> 8), UInt8(w & 0xff)]) }
    private func sw(_ w: UInt16) -> Data { sw(Data(), w) }

    private func send(_ d: Data) -> Data {
        pending = d
        return next()
    }

    private func next() -> Data {
        let part = pending.prefix(100)
        pending = Data(pending.dropFirst(part.count))
        return pending.isEmpty ? sw(Data(part), 0x9000) : sw(Data(part), 0x6100 | UInt16(min(pending.count, 0xff)))
    }

    private func slot(of object: Data) -> UInt8 { 0x82 + object[object.startIndex + 2] - 0x0d }

    func transmit(_ apdu: Data) throws -> Data {
        let a = [UInt8](apdu)
        let (cla, ins, p2) = (a[0], a[1], a[3])
        var data = a.count > 5 ? Data(a[5..<5 + Int(a[4])]) : Data()
        if ins == 0xc0 { return next() }
        if cla & 0x10 != 0 {
            chain += data
            return sw(0x9000)
        }
        data = chain + data
        chain = Data()
        if ins == 0xa4 {
            guard data == Piv.aid else { return sw(0x6a82) }
            (selected, verified, authenticated) = (true, false, false)
            return sw(0x9000)
        }
        guard selected else { return sw(0x6d00) }
        var t = Piv.TLV(data)
        switch ins {
        case 0xcb:
            guard let c = slots[slot(of: try t.value(0x5c))]?.cert else { return sw(0x6a82) }
            return send(Piv.tlv(0x53, Piv.tlv(0x70, c) + Piv.tlv(0x71, Data([0])) + Piv.tlv(0xfe, Data())))
        case 0xdb:
            guard authenticated else { return sw(0x6982) }
            let s = slot(of: try t.value(0x5c))
            var inner = Piv.TLV(try t.value(0x53))
            slots[s, default: Slot()].cert = try inner.value(0x70)
            return sw(0x9000)
        case 0xf7:
            guard metadata else { return sw(0x6d00) }
            if p2 == 0x9b { return sw(Piv.tlv(0x01, Data([alg])), 0x9000) }
            return slots[p2]?.key == nil ? sw(0x6a82) : sw(Piv.tlv(0x01, Data([0x11])), 0x9000)
        case 0x20:
            guard tries > 0 else { return sw(0x6983) }
            guard String(decoding: data.prefix { $0 != 0xff }, as: UTF8.self) == pin else {
                tries -= 1
                return sw(0x63c0 | UInt16(tries))
            }
            (tries, verified) = (3, true)
            return sw(0x9000)
        case 0x47:
            guard authenticated else { return sw(0x6982) }
            var spec = Piv.TLV(try t.value(0xac))
            XCTAssertEqual(try spec.value(0x80), Data([0x11]))
            let pp = try spec.value(0xaa).first ?? 0, tp = try spec.value(0xab).first ?? 0
            let k = P256.Signing.PrivateKey()
            slots[p2] = Slot(key: k, cert: nil, pinPolicy: pp, touchPolicy: tp)
            let inner = Piv.tlv(0x86, k.publicKey.x963Representation)
            return send(Data([0x7f, 0x49, UInt8(inner.count)]) + inner)
        case 0x87:
            var v = Piv.TLV(try t.value(0x7c))
            if p2 == 0x9b {
                let block = 16
                let first = try v.value(0x80)
                if first.isEmpty {
                    witness = Data((0..<block).map { _ in UInt8.random(in: 0...255) })
                    return send(Piv.tlv(0x7c, Piv.tlv(0x80, try Piv.crypt(managementKey, witness, encrypt: true))))
                }
                guard first == witness else { return sw(0x6982) }
                let challenge = try v.value(0x81)
                authenticated = true
                return send(Piv.tlv(0x7c, Piv.tlv(0x82, try Piv.crypt(managementKey, challenge, encrypt: true))))
            }
            guard let s = slots[p2], let key = s.key else { return sw(0x6a86) }
            guard verified else { return sw(0x6982) }
            if s.pinPolicy == 0x03 { verified = false }
            _ = try v.value(0x82)
            let digest = try v.value(0x81)
            let sig = try key.signature(for: PrehashedDigest(digest)).derRepresentation
            signed += 1
            return send(Piv.tlv(0x7c, Piv.tlv(0x82, sig)))
        default:
            return sw(0x6d00)
        }
    }
}

/// A SHA-256 digest the card got, for P256's signature(for:) over a digest.
struct PrehashedDigest: Digest {
    static let byteCount = 32
    let bytes: [UInt8]
    init(_ d: Data) { bytes = [UInt8](d) }
    func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R { try bytes.withUnsafeBytes(body) }
    var description: String { "digest" }
    func makeIterator() -> Array<UInt8>.Iterator { bytes.makeIterator() }
    func hash(into hasher: inout Hasher) { hasher.combine(bytes) }
}

final class PivTests: XCTestCase {
    let t0 = Date().addingTimeInterval(-100 * 3600)

    func testPutsTheRecoveryKeyOnTheCard() throws {
        do {
            let card = FakePivCard()
            card.slots[0x82] = FakePivCard.Slot(key: P256.Signing.PrivateKey())
            let rootKey = SoftwareSigner()
            var root = try PhoneGroup.create(caSigner: rootKey, memberKey: SoftwareSigner().publicKeyDER, name: "Lost", now: t0)
            root.records.clock = { [t0] in t0 }

            try Piv.select(card)
            try Piv.verify(card, pin: "123456")
            try Piv.authenticate(card)
            let slot = try Piv.freeSlot(card)
            XCTAssertEqual(slot, 0x83, "the first free slot")
            let spki = try Piv.generate(card, slot: slot)
            XCTAssertEqual(card.slots[slot]?.pinPolicy, 0x03, "the PIN before each signature")
            XCTAssertEqual(card.slots[slot]?.touchPolicy, 0x02, "a touch before each signature")
            let (ca, record) = try root.makeRecoveryOnCard(publicKey: spki, rootSigner: rootKey, now: t0)
            try Piv.putCertificate(card, slot: slot, cert: ca)
            XCTAssertTrue(root.records.records.contains { $0.body == record.body })
            XCTAssertEqual(root.records.recovery, try Records.keyHash(cert: ca))

            try Piv.select(card)
            let keys = try Piv.recoveryKeys(card)
            XCTAssertEqual(keys.map(\.slot), [slot])
            let signer = Piv.Signer(card: card, slot: slot, publicKeyDER: try CertificateInfo(der: keys[0].cert).publicKey, pin: "123456")
            let r = try Restore(card: signer, adminCA: keys[0].cert, memberKey: SoftwareSigner().publicKeyDER, now: t0)
            XCTAssertEqual(try GroupCertificates.verifyMember(chain: r.chain, roots: [root.groupCA], now: t0), r.device)
            XCTAssertEqual(card.signed, 1, "the card signed the member certificate")
        }
    }

    func testRefusesWhatDoesNotFit() throws {
        let card = FakePivCard()
        try Piv.select(card)
        do {
            try Piv.verify(card, pin: "654321")
            XCTFail("took a wrong PIN")
        } catch let f as Piv.Failure {
            XCTAssertEqual(f.kind, .wrongPIN)
            XCTAssertEqual(f.left, 2)
        }
        try Piv.verify(card, pin: "123456")

        card.managementKey = Data(repeating: 7, count: 24)
        XCTAssertThrowsError(try Piv.authenticate(card)) { XCTAssertEqual(($0 as? Piv.Failure)?.kind, .managementKey) }
        XCTAssertThrowsError(try Piv.generate(card, slot: 0x83)) { XCTAssertEqual(($0 as? Piv.Failure)?.kind, .managementKey) }
        XCTAssertTrue(try Piv.recoveryKeys(card).isEmpty)

        let full = FakePivCard()
        for s in Piv.firstSlot...Piv.lastSlot { full.slots[s] = FakePivCard.Slot(key: P256.Signing.PrivateKey()) }
        try Piv.select(full)
        XCTAssertThrowsError(try Piv.freeSlot(full)) { XCTAssertEqual(($0 as? Piv.Failure)?.kind, .noFreeSlot) }

        let old = FakePivCard(metadata: false)
        try Piv.select(old)
        XCTAssertEqual(try Piv.freeSlot(old), Piv.firstSlot, "a card without metadata counts a slot without a certificate as free")
        // The kit uses AES only: a 3DES management key, or a card that does not say, is refused.
        try Piv.verify(old, pin: "123456")
        XCTAssertThrowsError(try Piv.authenticate(old)) { XCTAssertEqual(($0 as? Piv.Failure)?.kind, .oldFirmware) }
        let des = FakePivCard(alg: 0x03)
        try Piv.select(des)
        try Piv.verify(des, pin: "123456")
        XCTAssertThrowsError(try Piv.authenticate(des)) { XCTAssertEqual(($0 as? Piv.Failure)?.kind, .oldFirmware) }
    }

    func testSignerChecksTheKey() throws {
        let card = FakePivCard()
        try Piv.select(card)
        try Piv.verify(card, pin: "123456")
        try Piv.authenticate(card)
        let spki = try Piv.generate(card, slot: 0x84)
        let sig = try Piv.Signer(card: card, slot: 0x84, publicKeyDER: spki, pin: "123456").signature(for: Data("data".utf8))
        let pub = try P256.Signing.PublicKey(derRepresentation: spki)
        XCTAssertTrue(pub.isValidSignature(try P256.Signing.ECDSASignature(derRepresentation: sig), for: Data("data".utf8)))
        let other = Piv.Signer(card: card, slot: 0x84, publicKeyDER: SoftwareSigner().publicKeyDER, pin: "123456")
        XCTAssertThrowsError(try other.signature(for: Data("data".utf8)))
    }

    func testTLV() throws {
        for n in [0, 0x7f, 0x80, 0xff, 0x100, 0x1234] {
            var t = Piv.TLV(Piv.tlv(0x53, Data(count: n)) + Data([1]))
            XCTAssertEqual(try t.value(0x53).count, n)
            XCTAssertFalse(t.done)
        }
        for b: [UInt8] in [[0x53], [0x54, 0], [0x53, 0x83, 0, 0, 1], [0x53, 2, 0], [0x53, 0x81], [0x53, 0x82, 1]] {
            var t = Piv.TLV(Data(b))
            XCTAssertThrowsError(try t.value(0x53))
        }
    }
}
