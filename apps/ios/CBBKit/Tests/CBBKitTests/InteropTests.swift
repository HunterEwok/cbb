// SPDX-License-Identifier: AGPL-3.0-only

@testable import CBBKit
import Foundation
import XCTest

/// Checks CBBKit against the vectors that the Go tests write to
/// testdata/interop (go test ./internal/pair ./internal/phone -update).
final class InteropTests: XCTestCase {
    func vectors(_ name: String) throws -> Data {
        // Tests/CBBKitTests/InteropTests.swift, up to the repository root.
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { url.deleteLastPathComponent() }
        return try Data(contentsOf: url.appendingPathComponent("testdata/interop/\(name)"))
    }

    struct PairingVectors: Decodable {
        var member_cert: Data
        var joiner_cert: Data
        var channel_id: String
        var fingerprint: String
        var frames: [AnyJSON]
    }

    /// Keeps a JSON value as Foundation objects, to compare encodings.
    struct AnyJSON: Decodable {
        let value: Any
        init(from decoder: Decoder) throws {
            let c = try decoder.singleValueContainer()
            if let o = try? c.decode([String: AnyJSON].self) {
                value = o.mapValues(\.value)
            } else if let a = try? c.decode([AnyJSON].self) {
                value = a.map(\.value)
            } else if let b = try? c.decode(Bool.self) {
                value = b
            } else if let s = try? c.decode(String.self) {
                value = s
            } else {
                value = NSNull()
            }
        }
    }

    func testPairing() throws {
        let v = try JSONDecoder().decode(PairingVectors.self, from: vectors("pairing.json"))
        XCTAssertEqual(hex(Pairing.channelID(memberCert: v.member_cert, joinerCert: v.joiner_cert)), v.channel_id)
        XCTAssertEqual(Pairing.fingerprint(cert: v.joiner_cert), v.fingerprint)
        for goFrame in v.frames {
            let goJSON = try JSONSerialization.data(withJSONObject: goFrame.value)
            let frame = try Pairing.decode(body: goJSON)
            // Encoding it again gives the same JSON object as Go's.
            let encoded = try Pairing.encode(frame)
            XCTAssertEqual(try Pairing.length(header: encoded.prefix(4)), encoded.count - 4)
            let mine = try JSONSerialization.jsonObject(with: encoded.dropFirst(4)) as! NSDictionary
            XCTAssertEqual(mine, goFrame.value as! NSDictionary)
        }
        let first = try Pairing.decode(body: JSONSerialization.data(withJSONObject: v.frames[0].value))
        XCTAssertEqual(try JSONDecoder().decode(Pairing.Info.self, from: first.ad!), Pairing.Info(name: "laptop", os: "linux"))
    }

    struct JoinQRVector: Decodable {
        struct Want: Decodable {
            var Code: String
            var Addrs: [String]?
            var Fingerprint: String
        }
        var text: String
        var want: Want?
    }

    func testJoinQR() throws {
        let vs = try JSONDecoder().decode([JoinQRVector].self, from: vectors("joinqr.json"))
        XCTAssertFalse(vs.isEmpty)
        for v in vs {
            let got = JoinCode(qr: v.text)
            guard let want = v.want else {
                XCTAssertNil(got, v.text)
                continue
            }
            XCTAssertEqual(got, JoinCode(code: want.Code, addrs: want.Addrs ?? [], fingerprint: want.Fingerprint), v.text)
        }
    }
}
