// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

@testable import CBBKit
import Foundation
import XCTest

final class CoreTests: XCTestCase {
    /// Asks the version, and sees a refusal come back as a Refusal.
    /// A panic in the core's library is an answer, code 5 with what broke
    /// and where, and the core answers again after it.
    func testPanicIsAnAnswer() throws {
        let e = try Core.testPanic()
        XCTAssertEqual(e.code, 5)
        XCTAssertEqual(e.name, "panic")
        XCTAssertTrue(e.details?.contains("cbb_test_panic") ?? false, e.description)
        XCTAssertNotNil(Core.lastPanic())
        XCTAssertEqual(try Core.version().abi, Core.abi)
    }

    func testRun() throws {
        let v = try Core.version()
        XCTAssertEqual(v.abi, Core.abi)
        XCTAssertFalse(v.core.isEmpty)
        XCTAssertTrue(v.line.hasPrefix("core \(v.core), abi 1, source "), v.line)
        XCTAssertThrowsError(try Core.run("no such op", as: Core.Version.self)) { e in
            XCTAssertEqual((e as? Core.Refusal)?.name, "op")
            XCTAssertEqual((e as? Core.Refusal)?.code, 3)
        }
        let empty = try Core.call(Data())
        XCTAssertTrue(String(decoding: empty, as: UTF8.self).contains(#""name":"request""#))
    }

    /// Calls the core from many threads at once, as the member's
    /// connections do.
    func testConcurrent() {
        DispatchQueue.concurrentPerform(iterations: 16) { _ in
            for _ in 0..<20 {
                XCTAssertEqual(try? Core.version().abi, Core.abi)
            }
        }
    }
}
