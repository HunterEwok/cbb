// SPDX-License-Identifier: AGPL-3.0-only

@testable import ClipboardBridgeKit
import Foundation
import XCTest

/// The recovery key (docs/protocol.md, section 10, "The recovery key"):
/// the root makes it and its sheet, and the core reads the sheet back.
final class RecoveryTests: XCTestCase {
    let t0 = Date()

    struct Vectors: Decodable {
        struct Sheet: Decodable { var key: Data, cert: Data, group: String, admin: Data, text: String, qr: String }
        struct Refused: Decodable { var text: String, reason: String }
        var sheet: Sheet
        var refused: [Refused]
    }

    func vectors() throws -> Vectors {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { url.deleteLastPathComponent() }
        return try JSONDecoder().decode(Vectors.self, from: Data(contentsOf: url.appendingPathComponent("testdata/interop/recovery-sheet.json")))
    }

    func testVectors() throws {
        let v = try vectors()
        let s = try Core.recoverySheet(key: v.sheet.key, cert: v.sheet.cert, group: v.sheet.group)
        XCTAssertEqual(s, Core.RecoverySheet(qr: v.sheet.qr, text: v.sheet.text, admin: v.sheet.admin))
        guard case let .key(k) = try Core.readRecoverySheet(v.sheet.qr) else { return XCTFail("the QR code is refused") }
        XCTAssertEqual(k.key, v.sheet.key)
        XCTAssertEqual(k.cert, v.sheet.cert)
        XCTAssertEqual(k.group, v.sheet.group)
        XCTAssertEqual(k.admin, v.sheet.admin)
        for c in v.refused {
            guard case let .refused(reason, message) = try Core.readRecoverySheet(c.text) else { return XCTFail("taken: \(c.text)") }
            XCTAssertEqual(reason, c.reason, c.text)
            XCTAssertFalse(message.isEmpty)
        }
        XCTAssertThrowsError(try Core.recoverySheet(key: Data(count: 32), cert: v.sheet.cert, group: v.sheet.group)) {
            XCTAssertEqual(($0 as? Core.Refusal)?.name, "request")
        }
    }

    func testMakeAndRemove() throws {
        let root = SoftwareSigner()
        var g = try PhoneGroup.create(caSigner: root, memberKey: SoftwareSigner().publicKeyDER, now: t0)
        XCTAssertThrowsError(try g.removeRecovery(rootSigner: root, now: t0)) {
            XCTAssertEqual($0 as? PhoneGroup.Failure, .noRecovery)
        }
        let r = try g.makeRecovery(rootSigner: root, now: t0.addingTimeInterval(1))
        XCTAssertTrue(g.records.records.contains(r.record))
        XCTAssertEqual(g.records.recovery, r.sheet.admin)
        XCTAssertEqual(try Records.keyHash(cert: r.adminCA), r.sheet.admin)
        XCTAssertEqual(r.key.count, 32)

        guard case let .key(fromQR) = try Core.readRecoverySheet(r.sheet.qr) else { return XCTFail("the QR code is refused") }
        XCTAssertEqual(fromQR.key, r.key)
        XCTAssertEqual(fromQR.cert, r.adminCA)
        XCTAssertEqual(fromQR.group, g.tag)
        guard case let .key(fromText) = try Core.readRecoverySheet(r.sheet.text.lowercased()) else { return XCTFail("the text is refused") }
        XCTAssertEqual(fromText.key, r.key)
        XCTAssertNil(fromText.cert)

        // A new key replaces the old one.
        let r2 = try g.makeRecovery(rootSigner: root, now: t0.addingTimeInterval(2))
        XCTAssertNotEqual(r2.key, r.key)
        XCTAssertEqual(g.records.recovery, r2.sheet.admin)

        let revoke = try g.removeRecovery(rootSigner: root, now: t0.addingTimeInterval(3))
        XCTAssertTrue(g.records.records.contains(revoke))
        XCTAssertNil(g.records.recovery)
    }
}
