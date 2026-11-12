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
        // Each case names its files by their index in files.
        struct C: Decodable {
            var name: String
            var keys: Int
            var channel: Int
            var release: Int
            var seen: Releases.Seen
            var ok: Bool
            var version: String?
        }
        struct V: Decodable {
            var roots: [Releases.Key]
            var now_ms: Int64
            var channel: String
            var files: [RawFile]
            var vectors: [C]
            var max_file: Int
        }
        let v = try JSONDecoder().decode(V.self, from: Data(contentsOf: url.appendingPathComponent("testdata/interop/go-release.json")))
        XCTAssertEqual(v.vectors.count, 53)
        // Every reader of release files reads up to the same size.
        XCTAssertEqual(Releases.maxFile, v.max_file)
        for c in v.vectors {
            let file = { (i: Int) in Releases.File(v.files[i].data) }
            let got = Result { try Releases.check(keys: file(c.keys), channel: file(c.channel), release: file(c.release), roots: v.roots,
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
            var keys: Int
            var status: Int
            var seen: Releases.Seen
            var ok: Bool
            var revoked: [String]?
        }
        struct V: Decodable {
            var roots: [Releases.Key]
            var now_ms: Int64
            var files: [RawFile]
            var status: [C]
        }
        let v = try JSONDecoder().decode(V.self, from: Data(contentsOf: url.appendingPathComponent("testdata/interop/go-release.json")))
        XCTAssertEqual(v.status.count, 18)
        for c in v.status {
            let got = Result { try Releases.checkStatus(keys: Releases.File(v.files[c.keys].data), status: Releases.File(v.files[c.status].data),
                                                        roots: v.roots, nowMS: v.now_ms, seen: c.seen) }
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

    /// testdata/interop/go-entries.json, from Go's TestEntriesVectors:
    /// which entries.json a phone takes.
    func testGoEntries() throws {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { url.deleteLastPathComponent() }
        struct C: Decodable {
            var name: String
            var keys: RawFile
            var entries: RawFile
            var seen: Releases.Seen
            var ok: Bool
            var seq: UInt64?
        }
        struct V: Decodable {
            var roots: [Releases.Key]
            var now_ms: Int64
            var vectors: [C]
        }
        let v = try JSONDecoder().decode(V.self, from: Data(contentsOf: url.appendingPathComponent("testdata/interop/go-entries.json")))
        XCTAssertEqual(v.vectors.count, 14)
        for c in v.vectors {
            let got = Result { try Releases.checkEntries(entriesSet(c.keys, c.entries), roots: v.roots, nowMS: v.now_ms, seen: c.seen) }
            switch got {
            case let .success((e, next)):
                XCTAssertTrue(c.ok, c.name)
                XCTAssertEqual(e.seq, c.seq, c.name)
                XCTAssertEqual(next.entries_seq, c.seq, c.name)
                XCTAssertEqual(next.entries_keys_seq, 3, c.name)
                XCTAssertEqual(next.keys_seq, 3, c.name)
            case let .failure(err):
                XCTAssertFalse(c.ok, "\(c.name): \(err)")
            }
        }
    }

    /// testdata/interop/go-release-envelopes.json: each release.json as it
    /// comes, its bytes passed to the core as the kit fetched them, taken
    /// or refused as Go and the core's reader do.
    func testGoEnvelopes() throws {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { url.deleteLastPathComponent() }
        struct C: Decodable {
            var name: String
            var release: Data
            var ok: Bool
        }
        struct V: Decodable {
            var roots: [Releases.Key]
            var now_ms: Int64
            var channel: String
            var keys: RawFile
            var channel_file: RawFile
            var envelopes: [C]
        }
        let v = try JSONDecoder().decode(V.self, from: Data(contentsOf: url.appendingPathComponent("testdata/interop/go-release-envelopes.json")))
        XCTAssertEqual(v.envelopes.count, 44)
        for c in v.envelopes {
            let got = Result { try Releases.check(keys: Releases.File(v.keys.data), channel: Releases.File(v.channel_file.data), release: Releases.File(c.release),
                                                  roots: v.roots, name: v.channel, nowMS: v.now_ms, seen: Releases.Seen()) }
            switch got {
            case .success: XCTAssertTrue(c.ok, c.name)
            case let .failure(e): XCTAssertFalse(c.ok, "\(c.name): \(e)")
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

/// The signed entry points as members pass them, from two files of the
/// vectors.
func entriesSet(_ keys: RawFile, _ entries: RawFile) -> Releases.EntriesSet {
    var d = Data(#"{"keys":"#.utf8)
    d.append(keys.data)
    d.append(Data(#","entries":"#.utf8))
    d.append(entries.data)
    d.append(Data("}".utf8))
    return Releases.EntriesSet(d)
}
