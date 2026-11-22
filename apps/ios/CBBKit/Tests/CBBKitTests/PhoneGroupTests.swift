// SPDX-License-Identifier: AGPL-3.0-only

@testable import CBBKit
import Foundation
import XCTest

/// The phone's note of its group beside the member's folder (PhoneGroup):
/// saved and read back, none without a file, and a group from before 0.6
/// said to be one.
final class PhoneGroupTests: XCTestCase {
    func testCreateSaveLoad() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("cb-\(UUID().uuidString)")
        addTeardownBlock { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appendingPathComponent("group.json")
        XCTAssertNil(try PhoneGroup.load(from: url))
        let group = String(repeating: "ab", count: 16)
        var g = PhoneGroup.of06(device: String(repeating: "01", count: 16), group: group, root: false)
        XCTAssertEqual(g.tag, String(group.prefix(16)))
        XCTAssertFalse(g.isAdmin)
        g.admin06 = true
        XCTAssertTrue(g.isAdmin)
        try g.save(to: url)
        XCTAssertEqual(try PhoneGroup.load(from: url), g)
        XCTAssertTrue(PhoneGroup.of06(device: g.device, group: group, root: true).isAdmin, "the root may add and remove devices")

        // A group of 0.5 named no Group ID.
        try Data(#"{"device":"0101","isRoot":true}"#.utf8).write(to: url)
        XCTAssertThrowsError(try PhoneGroup.load(from: url)) { XCTAssertTrue($0 is PhoneGroup.Before06, "\($0)") }
        XCTAssertTrue(FileManager.default.fileExists(atPath: url.path), "the file stays until the person leaves")
    }

    func testValidName() {
        XCTAssertEqual(PhoneGroup.validName(""), "iPhone")
        XCTAssertEqual(PhoneGroup.validName("a\u{7}b"), "ab")
        XCTAssertEqual(PhoneGroup.validName(String(repeating: "\u{44F}", count: 40)).utf8.count, 64)
    }
}
