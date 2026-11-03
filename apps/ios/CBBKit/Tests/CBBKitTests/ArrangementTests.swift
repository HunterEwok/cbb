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
            case "move": return .move(item!.ref, before: before?.ref)
            case "into": return .into(device: device!, collection: collection!)
            case "out": return .out(device: device!)
            case "new": return .new(name: name!, devices: devices ?? [])
            case "rename": return .rename(collection: collection!, name: name!)
            case "ungroup": return .ungroup(collection: collection!)
            case "reset": return .reset
            default: return nil
            }
        }
    }

    struct Case: Decodable {
        var name: String
        var group: String
        var me: String
        var devices: [String]
        var stored: Arrangement?
        var prune: Bool
        var ops: [OpJSON]
        var error: Bool
        var items: [Arrangement.Item]
        var view: [Arrangement.Item]

        enum CodingKeys: String, CodingKey {
            case name, group, me = "self", devices, stored, prune, ops, error, items, view
        }
    }

    struct Doc: Decodable {
        var cases: [Case]
    }

    /// testdata/arrangement/vectors.json, which the tray app and the Android kit read too.
    func testVectors() throws {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { url.deleteLastPathComponent() }
        let data = try Data(contentsOf: url.appendingPathComponent("testdata/arrangement/vectors.json"))
        let cases = try JSONDecoder().decode(Doc.self, from: data).cases
        XCTAssertFalse(cases.isEmpty)
        for c in cases {
            var a = c.stored.map { Arrangement.decode(try? JSONEncoder().encode($0), group: c.group) } ?? Arrangement(group: c.group)
            if c.prune { a.prune(devices: c.devices) }
            for (i, op) in c.ops.enumerated() {
                let wantError = c.error && i == c.ops.count - 1
                var failed = false
                do {
                    guard let o = op.value else { throw Arrangement.Refused(reason: "no such operation") }
                    try a.apply(o, devices: c.devices, self: c.me)
                } catch is Arrangement.Refused {
                    failed = true
                }
                XCTAssertEqual(failed, wantError, "\(c.name): op \(i)")
            }
            XCTAssertEqual(a.items, c.items, "\(c.name): items")
            XCTAssertEqual(a.view(devices: c.devices, self: c.me), c.view, "\(c.name): view")
            XCTAssertEqual(Arrangement.decode(a.encoded(), group: c.group).items, a.items, "\(c.name): encoded")
        }
    }

    func testBadJSONStartsFresh() {
        XCTAssertEqual(Arrangement.decode(Data("{".utf8), group: "G").items, [])
        XCTAssertEqual(Arrangement.decode(Data(#"{"v":1,"group":"G","items":[{"x":1}]}"#.utf8), group: "G").items, [])
        XCTAssertEqual(Arrangement.decode(nil, group: "G").items, [])
        XCTAssertEqual(Arrangement.decode(Data(#"{"v":1,"group":"old","items":[{"device":"a"}]}"#.utf8), group: "G").items, [])
    }
}
