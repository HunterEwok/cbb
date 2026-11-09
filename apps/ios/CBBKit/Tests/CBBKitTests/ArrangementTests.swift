// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import Foundation
import XCTest
@testable import CBBKit

final class ArrangementTests: XCTestCase {
    struct RefJSON: Decodable {
        var device: String?
        var collection: String?
        var ref: Arrangement.Ref { device.map { .device($0) } ?? .collection(collection ?? "") }
    }

    struct OpJSON: Decodable {
        var op: String
        var item: RefJSON?
        var before: RefJSON?
        var device: String?
        var collection: String?
        var name: String?
        var devices: [String]?

        var value: Arrangement.Op? {
            switch op {
            case "move": return item.map { .move($0.ref, before: before?.ref) }
            case "into": return .into(device: device ?? "", collection: collection ?? "")
            case "out": return .out(device: device ?? "")
            case "new": return .new(name: name ?? "", devices: devices ?? [])
            case "rename": return .rename(collection: collection ?? "", name: name ?? "")
            case "ungroup": return .ungroup(collection: collection ?? "")
            case "reset": return .reset
            default: return nil
            }
        }
    }

    /// Each change of testdata/arrangement/vectors.json goes to the member
    /// as the vectors write it, which cbb_core::arrange reads.
    func testChangesAsTheMemberReadsThem() throws {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { url.deleteLastPathComponent() }
        let data = try Data(contentsOf: url.appendingPathComponent("testdata/arrangement/vectors.json"))
        let doc = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        let cases = try XCTUnwrap(doc["cases"] as? [[String: Any]])
        var n = 0
        for c in cases {
            for raw in c["ops"] as? [[String: Any]] ?? [] {
                let parsed = try JSONDecoder().decode(OpJSON.self, from: JSONSerialization.data(withJSONObject: raw))
                guard let op = parsed.value else { continue }
                var want = raw.filter { !($0.value is NSNull) }
                if case .new = op, want["devices"] == nil { want["devices"] = [String]() }
                let got = try XCTUnwrap(JSONSerialization.jsonObject(with: op.data) as? [String: Any])
                XCTAssertEqual(NSDictionary(dictionary: got), NSDictionary(dictionary: want), "\(c["name"] ?? "")")
                n += 1
            }
        }
        XCTAssertGreaterThan(n, 10)
    }

    struct Dev: Decodable, Sendable { var id: String }

    /// The member's view reads as tiles, with its devices in their order.
    func testView() throws {
        let json = #"{"tiles":[{"device":{"id":"s"}},{"collection":{"id":"c1","name":"Desk","devices":[{"id":"a"},{"id":"b"}]}}],"online":1,"others":2,"custom":true}"#
        let v = try JSONDecoder().decode(Arrangement.View<Dev>.self, from: Data(json.utf8))
        XCTAssertEqual(v.devices.map(\.id), ["s", "a", "b"])
        XCTAssertTrue(v.custom)
        XCTAssertEqual(v.online, 1)
        guard case let .collection(id, name, ds) = v.tiles[1] else { return XCTFail("no collection") }
        XCTAssertEqual([id, name], ["c1", "Desk"])
        XCTAssertEqual(ds.count, 2)
    }

    /// A view without its fields reads as no tiles rather than failing: the
    /// member starts a bad arrangement fresh too.
    func testBadJSONStartsFresh() throws {
        let v = try JSONDecoder().decode(Arrangement.View<Dev>.self, from: Data("{}".utf8))
        XCTAssertTrue(v.tiles.isEmpty)
        XCTAssertFalse(v.custom)
    }
}
