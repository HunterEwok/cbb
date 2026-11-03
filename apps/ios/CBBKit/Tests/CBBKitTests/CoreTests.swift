// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

@testable import CBBKit
import Foundation
import XCTest

final class CoreTests: XCTestCase {
    /// Evaluates every case of testdata/interop/v2-records.json in the
    /// linked core, which must give its state byte for byte, as Go's
    /// internal/authority does.
    func testVectors() throws {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { url.deleteLastPathComponent() }
        let data = try Data(contentsOf: url.appendingPathComponent("testdata/interop/v2-records.json"))
        let file = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        let cases = try XCTUnwrap(file["cases"] as? [[String: Any]])
        XCTAssertFalse(cases.isEmpty)
        for c in cases {
            let name = try XCTUnwrap(c["name"] as? String)
            let state = try XCTUnwrap(c["state"] as? String)
            var request = Data(#"{"abi":1,"op":"evaluate","args":"#.utf8)
            request += try JSONSerialization.data(withJSONObject: c)
            request += Data("}".utf8)
            let answer = try Core.call(request)
            XCTAssertEqual(String(decoding: answer, as: UTF8.self), #"{"abi":1,"ok":"# + state + "}", name)
        }
    }

    /// Asks the version, and sees a refusal come back as a Refusal.
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
