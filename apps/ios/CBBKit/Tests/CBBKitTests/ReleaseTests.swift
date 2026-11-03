// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

@testable import CBBKit
import Foundation
import XCTest

final class ReleaseTests: XCTestCase {
    /// Reads testdata/interop/go-release.json, from Go's TestReleaseVectors:
    /// which release files a device takes.
    func testGoRelease() throws {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { url.deleteLastPathComponent() }
        struct C: Decodable {
            var name: String
            var keys: Releases.File
            var channel: Releases.File
            var release: Releases.File
            var seen: Releases.Seen
            var ok: Bool
            var version: String?
        }
        struct V: Decodable {
            var roots: [Data]
            var now_ms: Int64
            var channel: String
            var vectors: [C]
        }
        let v = try JSONDecoder().decode(V.self, from: Data(contentsOf: url.appendingPathComponent("testdata/interop/go-release.json")))
        XCTAssertEqual(v.vectors.count, 33)
        for c in v.vectors {
            let got = Result { try Releases.check(keys: c.keys, channel: c.channel, release: c.release, roots: v.roots,
                                                  name: v.channel, nowMS: v.now_ms, seen: c.seen) }
            switch got {
            case let .success((r, next)):
                XCTAssertTrue(c.ok, c.name)
                XCTAssertEqual(r.version, c.version, c.name)
                XCTAssertEqual(next.version, r.version, c.name)
                XCTAssertTrue(r.direct(from: "0.5.3") && !r.direct(from: "0.3.9"), c.name)
            case let .failure(e):
                XCTAssertFalse(c.ok, "\(c.name): \(e)")
            }
        }
    }

    /// The revocation lists of the same file: which attest-status.json a
    /// root takes.
    func testGoStatus() throws {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { url.deleteLastPathComponent() }
        struct C: Decodable {
            var name: String
            var keys: Releases.File
            var status: Releases.File
            var seen: Releases.Seen
            var ok: Bool
            var revoked: [String]?
        }
        struct V: Decodable {
            var roots: [Data]
            var now_ms: Int64
            var status: [C]
        }
        let v = try JSONDecoder().decode(V.self, from: Data(contentsOf: url.appendingPathComponent("testdata/interop/go-release.json")))
        XCTAssertEqual(v.status.count, 18)
        for c in v.status {
            let got = Result { try Releases.checkStatus(keys: c.keys, status: c.status, roots: v.roots, nowMS: v.now_ms, seen: c.seen) }
            switch got {
            case let .success((st, next)):
                XCTAssertTrue(c.ok, c.name)
                XCTAssertEqual(st.android_revoked, c.revoked, c.name)
                XCTAssertEqual(next.status_seq, st.seq, c.name)
            case let .failure(e):
                XCTAssertFalse(c.ok, "\(c.name): \(e)")
            }
        }
    }

    func testCompare() {
        XCTAssertEqual(Releases.compare("0.10.0", "0.9.0"), 1)
        XCTAssertEqual(Releases.compare("0.6.0", "0.6.0"), 0)
        XCTAssertEqual(Releases.compare("0.6.0", "0.6.1"), -1)
        XCTAssertEqual(Releases.compare("v0.6.0", "0.0.0"), -1)
        XCTAssertEqual(Releases.compare("0.06.0", "0.0.0"), -1)
        XCTAssertEqual(Releases.compare("0.6.0-rc.1", "0.6.0"), -1)
        XCTAssertEqual(Releases.compare("0.6.0-rc.2", "0.6.0-rc.10"), -1)
        XCTAssertEqual(Releases.compare("0.6.0-rc.1", "0.5.9"), 1)
        XCTAssertEqual(Releases.compare("0.6.0-rc.0", "0.0.0"), -1)
    }
}
