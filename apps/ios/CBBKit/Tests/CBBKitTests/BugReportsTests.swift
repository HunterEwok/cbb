// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

import Foundation
import XCTest

@testable import CBBKit

final class BugReportsTests: XCTestCase {
    /// The kit carries the core's state through a report, and nothing
    /// private leaves the device.
    func testKeepsTheStateThroughAReport() throws {
        var saved: Data?
        var posted: [String] = []
        let bugs = BugReports(load: { saved }, save: { saved = $0 }, post: { url, _ in
            posted.append(url)
            return Data(#"{"fixed_in":"0.6.1"}"#.utf8)
        }, now: { 1_762_646_400_000 })
        var i = BugReports.Input(kind: "panic", code: 5, name: "panic", message: "Something in CBB broke.",
                                 details: "panic: boom at member/src/x.rs:1:2", app: "ios", version: "0.6.0")
        i.log = ["dialed 192.168.0.2:8764 for Pixel"]
        i.names = ["Pixel"]
        let o = try bugs.offer(i)
        XCTAssertEqual(o.report.where, "member/src/x.rs:1:2")
        let log = o.report.log.joined()
        XCTAssertFalse(log.contains("192.168.0.2") || log.contains("Pixel"), log)
        XCTAssertEqual(o.url, BugReports.url)
        XCTAssertFalse(o.offer_always)
        if o.post.isEmpty {
            // This build has no robot key yet: nothing is posted.
            XCTAssertEqual(o.action, "skip")
            XCTAssertNil(bugs.send(o))
            XCTAssertTrue(posted.isEmpty)
        } else {
            XCTAssertEqual(o.action, "ask")
            XCTAssertEqual(bugs.send(o), "0.6.1")
        }
        try bugs.allow(always: false)
        try bugs.allow(always: false)
        XCTAssertEqual(try JSONDecoder().decode(BugReports.State.self, from: XCTUnwrap(saved)).allowed, 2)
        XCTAssertTrue(try bugs.offer(i).offer_always)
        XCTAssertEqual(bugs.resend(), 0)
        XCTAssertFalse(o.report.text.isEmpty)
    }
}
