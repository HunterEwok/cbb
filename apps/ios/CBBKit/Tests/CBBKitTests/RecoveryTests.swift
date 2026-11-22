// SPDX-License-Identifier: AGPL-3.0-only

@testable import CBBKit
import Foundation
import XCTest

/// The recovery key's sheet (docs/protocol.md, section 10, "The recovery
/// key"): the core writes it and reads it back.
final class RecoveryTests: XCTestCase {
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
}
