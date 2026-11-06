// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

@testable import CBBKit
import Foundation
import XCTest

final class EntriesTests: XCTestCase {
    struct C: Decodable {
        var name: String
        var keys: Releases.File
        var entries: Releases.File
    }

    struct V: Decodable {
        var roots: [Data]
        var now_ms: Int64
        var vectors: [C]
    }

    private func vectors() throws -> V {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { url.deleteLastPathComponent() }
        return try JSONDecoder().decode(V.self, from: Data(contentsOf: url.appendingPathComponent("testdata/interop/go-entries.json")))
    }

    private func set(_ v: V, _ name: String) -> Releases.EntriesSet {
        let c = v.vectors.first { $0.name == name }!
        return .init(keys: c.keys, entries: c.entries)
    }

    final class Clock: @unchecked Sendable {
        var ms: Int64
        init(_ ms: Int64) { self.ms = ms }
        var date: Date { Date(timeIntervalSince1970: TimeInterval(ms) / 1000) }
    }

    final class Lines: @unchecked Sendable {
        var lines: [String] = []
    }

    /// The phone keeps the newest list that checks out, across a restart,
    /// and stops using it once it expires.
    func testKeepsTheNewest() throws {
        let v = try vectors()
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appendingPathComponent("entries.json")
        let clock = Clock(v.now_ms)
        let logged = Lines()
        let e = EntriesFile(url: url, roots: v.roots, now: { clock.date }, log: { logged.lines.append($0) })
        XCTAssertNil(e.current)
        XCTAssertNil(e.order)
        XCTAssertNil(e.expires)
        XCTAssertTrue(e.ways(for: HubState.Forwarder.projectHost).isEmpty)

        e.add(set(v, "signed by another key"))
        XCTAssertNil(e.current)
        XCTAssertEqual(logged.lines.count, 1)
        e.add(set(v, "valid"))
        XCTAssertEqual(e.order?.keys, 3)
        XCTAssertEqual(e.order?.seq, 5)
        XCTAssertEqual(e.ways(for: HubState.Forwarder.projectHost),
                       [Releases.EntryVLESS(transport: "xhttp", server_name: "cbb.tools", port: 443, path: "/banMEJvnYJJap8S")])
        XCTAssertTrue(e.ways(for: "example.com:8764").isEmpty)
        // The same list again, or an older one, leaves it as it is.
        e.add(set(v, "the same again"))
        e.add(set(v, "an older list"))
        XCTAssertEqual(e.order?.seq, 5)

        let again = EntriesFile(url: url, roots: v.roots, now: { clock.date })
        XCTAssertEqual(again.current?.seq, 5)
        XCTAssertEqual(again.expires, e.expires)
        clock.ms = 1_900_000_000_000
        XCTAssertNil(again.current)
        XCTAssertNil(again.order)

        // A file that does not check out is logged and dropped.
        let other = Lines()
        XCTAssertNil(EntriesFile(url: url, roots: [], now: { clock.date }, log: { other.lines.append($0) }).current)
        XCTAssertEqual(other.lines.count, 1)

        again.remove()
        XCTAssertFalse(FileManager.default.fileExists(atPath: url.path))
        XCTAssertNil(again.current)
    }

    /// The entries message and the hello's seqs go over the wire and come
    /// back the same.
    func testWire() throws {
        let s = set(try vectors(), "valid")
        let m = try Member.encode(.entries(s))
        XCTAssertEqual(try Member.decode(body: m.dropFirst(4)), .entries(s))
        let hello = Member.Hello(wallMS: 1, entriesSeq: 5, entriesKeysSeq: 3)
        let h = try Member.encode(.hello(.phone, hello))
        XCTAssertEqual(try Member.decode(body: h.dropFirst(4)), .hello(.phone, hello))
        let none = try Member.encode(.hello(.phone, Member.Hello(wallMS: 1)))
        XCTAssertFalse(String(decoding: none.dropFirst(4), as: UTF8.self).contains("entries_seq"))
    }
}
