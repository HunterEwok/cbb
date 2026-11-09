// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

@testable import CBBKit
import Crypto
import Foundation
import XCTest

/// Checks the content of images and files against the vectors in
/// testdata/interop and between two nodes.
final class ContentTests: XCTestCase {
    struct Vectors: Decodable {
        struct Chunk: Decodable {
            var sha256: Data
            var offset: Int64
            var data: Data?
            var frame: Data
            var frame_len: Int
        }
        var frames: [MemberTests.AnyJSON]
        var chunks: [Chunk]
    }

    func vectors() throws -> Vectors {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { url.deleteLastPathComponent() }
        return try JSONDecoder().decode(Vectors.self, from: Data(contentsOf: url.appendingPathComponent("testdata/interop/content.json")))
    }

    func testGoFrames() throws {
        var decoded: [Member.Message] = []
        for goFrame in try vectors().frames {
            let m = try Member.decode(body: goFrame.data)
            decoded.append(m)
            let encoded = try Member.encode(m)
            let mine = try JSONSerialization.jsonObject(with: encoded.dropFirst(4)) as! NSDictionary
            XCTAssertEqual(mine, goFrame.value as! NSDictionary)
        }
        let sum = Data(repeating: 7, count: 32)
        XCTAssertEqual(decoded, [
            .get(Member.Get(sha256: sum, offset: 0, length: Member.getWindow)),
            .get(Member.Get(sha256: sum, offset: 3 << 20, length: 12345)),
            .missing(Member.Get(sha256: sum, offset: 0, length: Member.getWindow)),
            .get(Member.Get(sha256: sum, offset: 0, length: 0)),
        ])
    }

    func testGoChunks() throws {
        for c in try vectors().chunks {
            let frame = c.frame + Data(count: c.frame_len - c.frame.count)
            let chunk = Member.Chunk(sha256: c.sha256, offset: c.offset, data: c.data ?? Data())
            XCTAssertEqual(try Member.encode(.chunk(chunk)), frame)
            let (n, binary) = try Member.header(frame.prefix(4))
            XCTAssertTrue(binary)
            XCTAssertEqual(n, frame.count - 4)
            XCTAssertEqual(try Member.decodeChunk(body: frame.dropFirst(4)), chunk)
        }
    }

    func testFrameLimits() throws {
        XCTAssertThrowsError(try Member.header(Data([0x80, 0x04, 0x40, 0x01])))
        XCTAssertEqual(try Member.header(Data([0x80, 0x04, 0x40, 0x00])).length, Member.maxChunkFrame)
        XCTAssertEqual(Member.maxChunkFrame, 278_528)
        XCTAssertThrowsError(try Member.decodeChunk(body: Data(count: 10)))
        var lying = try Member.encode(.chunk(Member.Chunk(sha256: Data(count: 32), offset: 0, data: Data(count: 3))))
            .subdata(in: 4..<(4 + Member.chunkHead + 3))
        lying[Member.chunkHead - 1] = 9
        XCTAssertThrowsError(try Member.decodeChunk(body: lying))
        XCTAssertThrowsError(try Member.encode(.chunk(Member.Chunk(sha256: Data(count: 32), offset: 0, data: Data(count: Member.chunkSize + 1)))))
    }

    /// A phone's picture and files reach the other phone, which fetches
    /// their sealed blob and opens it, each part checked; a copy over the
    /// limit is not fetched, nor one that is no longer the group's.
    func testNodesFetch() async throws {
        let t = try CoreGroup(test: self)
        let (a, b) = (t.phones[0], t.phones[1])
        try await t.connect(1, to: 0)
        // A picture of 5 MiB and a bit, more than a fetch asks for ahead.
        var rng = SystemRandomNumberGenerator()
        let png = Data((0..<(5 << 20 + 1234)).map { _ in UInt8.random(in: 0...255, using: &rng) })
        let sent = try a.member.copyMedia([.data(png, type: "image/png")], board: true)
        XCTAssertEqual(sent.kind, .media)
        XCTAssertEqual(sent.key, "\u{0}image:" + Data(SHA256.hash(data: png)).map { String(format: "%02x", $0) }.joined())
        let got = try await b.next("the picture") { if case let .copy(c) = $0, c.id == sent.id { return c }; return nil }
        XCTAssertEqual(got.media?.parts.first?.type, "image/png")
        XCTAssertEqual(try b.member.waiting()?.id, sent.id)
        let out = FileManager.default.temporaryDirectory.appendingPathComponent("cbb-fetch-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: out, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: out) }
        let parts = try await b.member.fetch(sent.id, max: 64 << 20, into: out.appendingPathComponent("picture"))
        XCTAssertEqual(parts.count, 1)
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: parts[0].file)), png)
        // The phone that shared it sees it was read to the end.
        let (served, size) = try a.member.served(sent.id)
        XCTAssertEqual(served, size)
        XCTAssertEqual(size, Media.blobSize(Int64(png.count)))
        XCTAssertEqual(try a.member.served("no such copy").size, 0)

        // Files and a folder go the same way, with their paths.
        let src = out.appendingPathComponent("src")
        try FileManager.default.createDirectory(at: src, withIntermediateDirectories: true)
        try Data("one".utf8).write(to: src.appendingPathComponent("one.txt"))
        let files = try a.member.copyMedia([.folder(path: "docs"), .file(src.appendingPathComponent("one.txt"), path: "docs/one.txt")])
        _ = try await b.next("the files") { if case let .copy(c) = $0, c.id == files.id { return c }; return nil }
        // Over the limit, nothing is fetched.
        do {
            _ = try await b.member.fetch(files.id, max: 1, into: out.appendingPathComponent("small"))
            XCTFail("fetched a copy over the limit")
        } catch is Core.Refusal {}
        let opened = try await b.member.fetch(files.id, max: 1 << 20, into: out.appendingPathComponent("files"))
        XCTAssertEqual(opened.map(\.path), ["docs", "docs/one.txt"])
        let file = try XCTUnwrap(opened.first { !$0.dir })
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: file.file)), Data("one".utf8))
        // A newer copy makes the files no longer the group's.
        try a.member.copy("newer")
        _ = try await b.copy("newer")
        do {
            _ = try await b.member.fetch(files.id, max: 1 << 20, into: out.appendingPathComponent("gone"))
            XCTFail("fetched a copy that is no longer the group's")
        } catch CoreMember.Failure.gone {}
    }

    func testCleanNames() {
        for (given, want) in [("report.pdf", "report.pdf"), ("a/b:c?.txt", "a_b_c_.txt"), ("CON.txt", "CON_.txt"), ("lpt1", "lpt1_"),
                              ("dots...", "dots..._"), ("", "_"), ("..", "_"), ("tab\there", "tab_here"),
                              (String(repeating: "x", count: 300), String(repeating: "x", count: 255)),
                              ("CON." + String(repeating: "a", count: 249) + ".x", "CON_." + String(repeating: "a", count: 249)),
                              (String(repeating: "a", count: 254) + ".", String(repeating: "a", count: 254))] {
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

    func waitUntil(_ cond: @escaping () async -> Bool) async throws {
        for _ in 0..<500 {
            if await cond() { return }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        XCTFail("timed out")
    }
}

final class Events: @unchecked Sendable {
    private let lock = NSLock()
    private var events: [Member.Event] = []
    func add(_ e: Member.Event) { lock.withLock { events.append(e) } }
    var all: [Member.Event] { lock.withLock { events } }
}
