// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

@testable import CBBKit
import Crypto
import Foundation
import XCTest

// The verdicts' fields (docs/differential.md), outside the test class, whose
// methods Objective-C sees on macOS, where the two hex overloads would clash.
private func hex(_ d: Data?) -> String { (d ?? Data()).map { String(format: "%02x", $0) }.joined() }
private func hex(_ s: String?) -> String { hex(Data((s ?? "").utf8)) }
private func hashes(_ l: [Data]?) -> String { (l ?? []).map { hex($0) }.joined(separator: ".") }
private func bit(_ b: Bool) -> String { b ? "1" : "0" }
private func sha(_ d: Data) -> Data { Data(SHA256.hash(data: d)) }
private func taken(_ pairs: [(String, String)]) -> String { "taken" + pairs.map { " \($0.0)=\($0.1)" }.joined() }

/// The kit's verdicts on a corpus of tools/difffuzz (docs/differential.md):
/// one line per case, which the comparison checks against the other
/// implementations' lines. It runs on the corpus that CBB_VERDICTS names and
/// writes to CBB_VERDICTS_OUT; without them, on a corpus of its own.
final class VerdictTests: XCTestCase {
    struct Case: Decodable {
        var kind: String
        var body: Data?
        var ca: Data?
        var records: [Member.Record]?
        var keys: [Data]?
    }

    /// A reader refuses with its own error; any other is a verdict of its
    /// own, which no other reader gives.
    func refused(_ f: () throws -> String) -> String {
        do { return try f() } catch is Commands.Refused { return "refused" } catch is ServerCredentials.Refused {
            return "refused"
        } catch is Releases.Refused { return "refused" } catch { return "threw \(type(of: error))" }
    }

    func verdict(_ c: Case) -> String {
        let body = c.body ?? Data()
        switch c.kind {
        case "record", "set":
            // The phones read records v2 only through the Rust core
            // (docs/core-api.md), which the comparison reads as rust: the
            // kit's own reader of version 1 has no verdict on them.
            return "skip"
        case "command":
            return refused {
                let b = try Commands.parse(body)
                return taken([
                    ("type", hex(b.type)), ("group", hex(b.group)), ("by", hex(b.by)), ("to", hex(b.to)), ("id", hex(b.id)),
                    ("time_ms", String(b.time_ms)), ("expires_ms", String(b.expires_ms)), ("mode", hex(b.mode)),
                    ("enter", bit(b.enter ?? false)), ("kind", hex(b.kind)), ("text", hex(sha(Data((b.text ?? "").utf8)))),
                    ("action", hex(b.action)),
                ])
            }
        case "credential":
            return refused {
                let b = try ServerCredentials.Body.parse(body)
                return taken([
                    ("type", hex(b.type)), ("group", hex(b.group)), ("version", String(b.version)),
                    ("expires_ms", String(b.expires_ms)), ("tag", hex(b.tag)), ("key", hex(b.key)), ("hubs", hashes(b.hubs)),
                    ("admins", hashes(b.admins)), ("members", hashes(b.members)),
                ])
            }
        case "manifest":
            return Media.Manifest.parse(body) != nil ? "taken" : "refused"
        case "keys", "release", "channel", "attest-status":
            // The core reads release files for the kit (docs/core-api.md).
            return Core.bodyRefusal(c.kind, body) == nil ? "taken" : "refused"
        default:
            XCTFail("unknown kind \(c.kind)")
            return ""
        }
    }

    func testVerdicts() throws {
        let env = ProcessInfo.processInfo.environment
        let input = env["CBB_VERDICTS"].flatMap { $0.isEmpty ? nil : $0 }
        let text = try input.map { try String(contentsOfFile: $0, encoding: .utf8) }
            ?? "{\"kind\":\"record\",\"body\":\"e30=\"}\n{\"kind\":\"keys\",\"body\":\"e30=\"}\n"
        var out = ""
        for line in text.split(separator: "\n") where !line.isEmpty {
            out += verdict(try JSONDecoder().decode(Case.self, from: Data(line.utf8))) + "\n"
        }
        if input != nil {
            try out.write(toFile: env["CBB_VERDICTS_OUT"]!, atomically: true, encoding: .utf8)
        } else {
            XCTAssertEqual(out, "skip\nrefused\n")
        }
    }
}
