// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

@testable import CBBKit
import Foundation
import XCTest

/// The names and the store of the images and files a phone copies
/// (Media, Content), against the vectors in testdata/interop.
final class ContentTests: XCTestCase {
    func testCleanNames() {
        for (given, want) in [("report.pdf", "report.pdf"), ("a/b:c?.txt", "a_b_c_.txt"), ("CON.txt", "CON_.txt"), ("lpt1", "lpt1_"),
                              ("dots...", "dots..._"), ("", "_"), ("..", "_"), ("tab\there", "tab_here"),
                              (String(repeating: "x", count: 800), String(repeating: "x", count: 765)),
                              ("CON." + String(repeating: "a", count: 759) + ".x", "CON_." + String(repeating: "a", count: 759)),
                              (String(repeating: "a", count: 764) + ".", String(repeating: "a", count: 764))] {
            let got = Media.cleanName(given)
            XCTAssertEqual(got, want, given)
            XCTAssertTrue(Media.checkName(got), got)
        }
        let m = Content.files(store: MemoryContent(), files: [("a.txt", Data(count: 1)), ("A.txt", Data(count: 2)), ("a.txt", Data(count: 3)), ("CON", Data())])
        XCTAssertEqual(m.parts.map(\.path), ["a.txt", "A (2).txt", "a (3).txt", "CON_"])
        XCTAssertTrue(m.isValid)
        XCTAssertEqual(m.size, 6)
    }

    /// testdata/interop/media-names.json, as Go's TestNameVectors writes
    /// it: the kit takes the names Go takes, writes the device names of
    /// Windows under Go's names and cleans names as Go does.
    func testNameVectors() throws {
        struct Case: Decodable {
            var name, clean: String
            var valid: Bool
            var save: String?
        }
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { url.deleteLastPathComponent() }
        let cases = try JSONDecoder().decode([Case].self, from: Data(contentsOf: url.appendingPathComponent("testdata/interop/media-names.json")))
        XCTAssertFalse(cases.isEmpty)
        for c in cases {
            XCTAssertEqual(Media.checkName(c.name), c.valid, c.name)
            if c.valid { XCTAssertEqual(Media.saveName(c.name), c.save, c.name) }
            XCTAssertEqual(Media.cleanName(c.name), c.clean, c.name)
        }
    }

    func testMemoryContentKeepsTheNewest() {
        // Twice maxBytes, for a copy's parts and its sealed blob.
        let store = MemoryContent(maxBytes: 10)
        let one = store.put(Data(repeating: 1, count: 6))
        let two = store.put(Data(repeating: 2, count: 6), blob: true)
        let three = store.put(Data(repeating: 3, count: 10))
        XCTAssertNil(store.bytes(sha256: one))
        XCTAssertEqual(store.bytes(sha256: three)?.count, 10)
        // Only blobs are served, never the parts in the open.
        XCTAssertNil(store.open(sha256: three))
        XCTAssertEqual(store.open(sha256: two)?.size, 6)
        // One part over the limit is still kept, alone.
        let big = store.put(Data(count: 40), blob: true)
        XCTAssertNil(store.open(sha256: two))
        XCTAssertEqual(store.open(sha256: big)?.size, 40)
    }
}
