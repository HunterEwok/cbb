// SPDX-License-Identifier: AGPL-3.0-only

@testable import ClipboardBridgeKit
import Foundation
import XCTest

/// testdata/interop/strict.json, from the Go tests: the kit takes exactly
/// the commands and manifests the Go member does. Record bodies are the
/// Rust core's to check (check_body).
final class StrictTests: XCTestCase {
    struct Vectors: Decodable {
        struct Case: Decodable {
            var name: String
            var body: Data
            var valid: Bool
        }

        var records, commands, manifests: [Case]
    }

    func vectors() throws -> Vectors {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { url.deleteLastPathComponent() }
        let v = try JSONDecoder().decode(Vectors.self, from: Data(contentsOf: url.appendingPathComponent("testdata/interop/strict.json")))
        XCTAssertFalse(v.records.isEmpty || v.commands.isEmpty || v.manifests.isEmpty)
        return v
    }

    struct BodyArgs: Encodable { var body: Data }
    struct BodyAnswer: Decodable {}

    /// Whether the core's check_body takes a record body.
    func takes(_ body: Data) -> Bool {
        (try? Core.run("check_body", BodyArgs(body: body), as: BodyAnswer.self)) != nil
    }

    /// Well-formed record bodies of version 2: the records of the cases of
    /// testdata/interop/v2-records.json that hold only good records.
    func goodBodies() throws -> [Data] {
        struct V: Decodable {
            struct Case: Decodable { var name: String, records: [Member.Record] }
            var cases: [Case]
        }
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { url.deleteLastPathComponent() }
        let v = try JSONDecoder().decode(V.self, from: Data(contentsOf: url.appendingPathComponent("testdata/interop/v2-records.json")))
        let good = ["basic", "powers", "hubs table", "freeze and thaw", "claim waits and takes effect"]
        let bodies = v.cases.filter { c in good.contains { c.name.hasPrefix($0) } }.flatMap(\.records).map(\.body)
        XCTAssertFalse(bodies.isEmpty)
        return bodies
    }

    /// Record bodies of version 2 go through the core's check_body: each
    /// good body passes, and the same body with a field the rows do not
    /// have, its keys out of order or a space in front does not.
    func testRecords() throws {
        for body in try goodBodies() {
            XCTAssertTrue(takes(body), String(decoding: body, as: UTF8.self))
            let text = String(decoding: body, as: UTF8.self)
            let bad = ["{\"zz\":1," + text.dropFirst(), " " + text, "{\"a\":1," + text.dropFirst()]
            for b in bad { XCTAssertFalse(takes(Data(b.utf8)), b) }
            let obj = try XCTUnwrap(JSONSerialization.jsonObject(with: body) as? [String: Any])
            let reordered = try JSONSerialization.data(withJSONObject: obj, options: [])
            if reordered != body { XCTAssertFalse(takes(reordered), String(decoding: reordered, as: UTF8.self)) }
        }
    }

    func testCommands() throws {
        for c in try vectors().commands {
            XCTAssertEqual((try? Commands.parse(c.body)) != nil, c.valid, "command \(c.name)")
        }
    }

    func testManifests() throws {
        for c in try vectors().manifests {
            // The frames' decoder, Member.decode, runs the same scan first.
            let m = Strict.integersOnly(c.body) ? try? JSONDecoder().decode(Media.Manifest.self, from: c.body) : nil
            XCTAssertEqual(m?.isValid ?? false, c.valid, "manifest \(c.name)")
        }
    }

    /// testdata/interop/strict-generated-*.json, from the tables of
    /// docs/protocol.md: the kit takes exactly the bodies the tables take,
    /// and says which row it reads otherwise.
    func testGenerated() throws {
        struct Case: Decodable {
            var name, rule: String
            var valid: Bool
            var body: Data
            var pad_at, pad: Int?

            var full: Data {
                guard let pad, let pad_at else { return body }
                return body.prefix(pad_at) + Data(repeating: UInt8(ascii: "a"), count: pad) + body.dropFirst(pad_at)
            }
        }
        struct Vectors: Decodable { var records, commands, manifests: [Case] }
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { url.deleteLastPathComponent() }
        var v = Vectors(records: [], commands: [], manifests: [])
        for i in 1... {
            let file = url.appendingPathComponent("testdata/interop/strict-generated-\(i).json")
            guard FileManager.default.fileExists(atPath: file.path) else { break }
            let part = try JSONDecoder().decode(Vectors.self, from: Data(contentsOf: file))
            v.records += part.records
            v.commands += part.commands
            v.manifests += part.manifests
        }
        var wrong: [String] = []
        let kinds: [(String, [Case], (Data) -> Bool)] = [
            // Record bodies are the core's to check.
            ("records", v.records, { (b: Data) in self.takes(b) }),
            ("commands", v.commands, { (b: Data) in (try? Commands.parse(b)) != nil }),
            ("manifests", v.manifests, { (b: Data) in
                (Strict.integersOnly(b) ? try? JSONDecoder().decode(Media.Manifest.self, from: b) : nil)?.isValid ?? false
            }),
        ]
        for (kind, cases, take) in kinds {
            XCTAssertFalse(cases.isEmpty, "no \(kind)")
            for c in cases where take(c.full) != c.valid {
                wrong.append("\(kind) \(c.name) (\(c.rule)): valid \(c.valid)")
            }
        }
        XCTAssert(wrong.isEmpty, "\(wrong.count) vectors read otherwise:\n" + wrong.joined(separator: "\n"))
    }

    /// Mutants of good record bodies of version 2, each refused by the
    /// core: a field every record has dropped, a version or an alg it does not know, a
    /// number written as a float or with a sign, a duplicate key, a null.
    func testMutants() throws {
        var n = 0
        var wrong: [String] = []
        for body in try goodBodies() {
            let text = String(decoding: body, as: UTF8.self)
            let obj = try XCTUnwrap(JSONSerialization.jsonObject(with: body) as? [String: Any])
            var mutants: [String] = []
            for key in ["v", "alg", "type", "signer", "time_ms", "group", "seq"] where obj[key] != nil {
                var o = obj
                o[key] = nil
                if let d = try? JSONSerialization.data(withJSONObject: o, options: [.sortedKeys, .withoutEscapingSlashes]) {
                    mutants.append(String(decoding: d, as: UTF8.self))
                }
            }
            mutants.append(text.replacingOccurrences(of: "\"v\":2", with: "\"v\":3"))
            mutants.append(text.replacingOccurrences(of: "\"alg\":\"es256\"", with: "\"alg\":\"rs256\""))
            mutants.append(text.replacingOccurrences(of: "\"v\":2", with: "\"v\":2.0"))
            mutants.append(text.replacingOccurrences(of: "\"v\":2", with: "\"v\":+2"))
            mutants.append(text.replacingOccurrences(of: "\"v\":2", with: "\"v\":2,\"v\":2"))
            mutants.append(text.replacingOccurrences(of: "\"v\":2", with: "\"v\":null"))
            for m in mutants where m != text {
                n += 1
                if takes(Data(m.utf8)) { wrong.append(m) }
            }
        }
        XCTAssertGreaterThan(n, 0, "no mutants")
        XCTAssert(wrong.isEmpty, "\(wrong.count) mutants taken:\n" + wrong.joined(separator: "\n"))
    }

    /// strict-files.json: the server credentials and release files, as Go's
    /// TestStrictGeneratedFiles writes them.
    func testGeneratedFiles() throws {
        struct Case: Decodable {
            var name, rule, kind: String
            var valid: Bool
            var body: Data
            var pad_at, pad: Int?

            var full: Data {
                guard let pad, let pad_at else { return body }
                return body.prefix(pad_at) + Data(repeating: UInt8(ascii: "a"), count: pad) + body.dropFirst(pad_at)
            }
        }
        struct Vectors: Decodable { var credentials, releases: [Case] }
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { url.deleteLastPathComponent() }
        let v = try JSONDecoder().decode(Vectors.self, from: Data(contentsOf: url.appendingPathComponent("testdata/interop/strict-files.json")))
        XCTAssertFalse(v.credentials.isEmpty)
        XCTAssertFalse(v.releases.isEmpty)
        var wrong: [String] = []
        for c in v.credentials where ((try? ServerCredentials.Body.parse(c.full)) != nil) != c.valid {
            wrong.append("credentials \(c.name) (\(c.rule)): valid \(c.valid)")
        }
        for c in v.releases {
            let b = c.full
            var taken = b.count <= Releases.maxBody
            if taken {
                switch c.kind {
                case "keys": taken = (try? Releases.decodeKeys(b)) != nil
                case "release": taken = (try? Releases.decodeRelease(b)) != nil
                case "channel": taken = (try? Releases.decodeChannel(b)) != nil
                case "attest-status": taken = (try? Releases.decodeStatus(b)) != nil
                default: XCTFail("unknown kind \(c.kind)")
                }
            }
            if taken != c.valid { wrong.append("releases \(c.name) (\(c.rule)): valid \(c.valid)") }
        }
        XCTAssert(wrong.isEmpty, "\(wrong.count) vectors read otherwise:\n" + wrong.joined(separator: "\n"))
    }
}
