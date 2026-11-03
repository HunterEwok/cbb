// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

@testable import CBBKit
import Foundation
import XCTest

final class ClockTests: XCTestCase {
    /// The timestamps a clock took do not move how far ahead it takes the
    /// next one (hlc-ahead.json, as Go's TestAheadVectors writes it).
    func testAheadVectors() throws {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { url.deleteLastPathComponent() }
        struct V: Decodable {
            var now: UInt64
            var max_ahead: UInt64
            var accepted: [UInt64]
            var refused: UInt64
        }
        let v = try JSONDecoder().decode(V.self, from: Data(contentsOf: url.appendingPathComponent("testdata/interop/hlc-ahead.json")))
        XCTAssertEqual(v.max_ahead, HybridClock.maxAheadMS)
        let now = v.now
        let c = HybridClock(wallMS: { now })
        for w in v.accepted {
            let ts = Member.Timestamp(wall: w, logical: 0)
            XCTAssertFalse(c.ahead(ts), "\(w) refused")
            c.observe(ts)
        }
        XCTAssertTrue(c.ahead(Member.Timestamp(wall: v.refused, logical: 0)), "taken after a chain of timestamps ahead")
    }
}
