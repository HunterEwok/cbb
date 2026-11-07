// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

@testable import CBBKit
import Foundation
import XCTest

final class AndroidAttestationTests: XCTestCase {
    /// Reads testdata/interop/go-attest.json, from Go's TestAttestVectors.
    func testGoAttest() throws {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { url.deleteLastPathComponent() }
        struct Challenge: Decodable {
            var group_tag: String
            var member_key: Data?
            var salt: Data
            var challenge: Data
        }
        struct C: Decodable {
            var name: String
            var chain: [Data]
            var spki: Data
            var challenge: Data
            var roots: [Data]?
            var strict: Bool?
            var revoked: [String]?
            var ok: Bool
            var store: String?
            var kind: String?
            var rkp: Bool?
            var serials: [String]?
        }
        struct V: Decodable {
            var google_roots: [Data]
            var challenges: [Challenge]
            var vectors: [C]
        }
        let v = try JSONDecoder().decode(V.self, from: Data(contentsOf: url.appendingPathComponent("testdata/interop/go-attest.json")))
        XCTAssertEqual(v.google_roots, AndroidAttestation.googleRoots)
        for c in v.challenges {
            XCTAssertEqual(try Attestation.challenge(groupTag: c.group_tag, memberKey: c.member_key ?? Data(), salt: c.salt), c.challenge, c.group_tag)
        }
        XCTAssertEqual(v.vectors.count, 30)
        for c in v.vectors {
            let policy = AndroidAttestation.Policy(strict: c.strict ?? false, revoked: Set(c.revoked ?? []), roots: c.roots)
            let got = Result { try AndroidAttestation.check(chain: c.chain, spki: c.spki, challenge: c.challenge, policy: policy) }
            switch got {
            case let .success(r):
                XCTAssertTrue(c.ok, c.name)
                XCTAssertEqual(r.store, c.store, c.name)
                XCTAssertEqual(r.kind, c.kind ?? "", c.name)
                XCTAssertEqual(r.rkp, c.rkp ?? false, c.name)
                XCTAssertEqual(r.serials, c.serials, c.name)
                XCTAssertEqual(r.store == Records.proven, r.why.isEmpty, c.name)
            case let .failure(e):
                XCTAssertFalse(c.ok, "\(c.name): \(e)")
                XCTAssertTrue(e is AndroidAttestation.Invalid, "\(c.name): \(e)")
            }
        }
        XCTAssertThrowsError(try Attestation.challenge(groupTag: "", memberKey: Data(), salt: Data(count: 15)))
    }

    /// The root phone records a phone whose evidence proves its member key
    /// as proven, once (section 17, "Evidence").
    func testRootRecordsEvidence() throws {
        var url = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 { url.deleteLastPathComponent() }
        struct E: Decodable { var salt: Data; var chain: [Data]; var root: Data }
        struct V: Decodable { var evidence: E }
        let e = try JSONDecoder().decode(V.self, from: Data(contentsOf: url.appendingPathComponent("testdata/interop/go-attest.json"))).evidence
        let evidence = Member.Evidence(format: Member.Evidence.android, key: Member.Evidence.member, groupTag: nil, salt: e.salt, chain: e.chain)
        let now = Date()
        let ca = SoftwareSigner()
        var g = try PhoneGroup.create(caSigner: ca, memberKey: SoftwareSigner().publicKeyDER, now: now)
        // The leaf certifies the phone's member key; it stands in for the member certificate here.
        let phone = Member.newID()
        _ = try g.record(device: phone, name: "Pixel", role: "phone", os: "android", key: try Records.keyHash(cert: e.chain[0]),
                         store: Records.hardware, caSigner: ca, now: now)
        XCTAssertNil(try g.evidence(device: Member.newID(), chain: [e.chain[0]], evidence, rootSigner: ca, now: now, roots: [e.root]))
        XCTAssertNotNil(try g.evidence(device: phone, chain: [e.chain[0]], evidence, rootSigner: ca, now: now.addingTimeInterval(1), roots: [e.root]))
        let d = try XCTUnwrap(g.devices.first { $0.id == phone })
        XCTAssertEqual(d.store, Records.proven)
        XCTAssertEqual(d.kind, AndroidAttestation.kindTEE)
        XCTAssertEqual(d.proof?.count, 64)
        XCTAssertNil(try g.evidence(device: phone, chain: [e.chain[0]], evidence, rootSigner: ca, now: now.addingTimeInterval(2), roots: [e.root]))
        _ = try g.rename(device: phone, to: "Pixel 9", caSigner: ca, now: now.addingTimeInterval(3))
        XCTAssertEqual(g.devices.first { $0.id == phone }?.store, Records.proven)
        var other = evidence
        other.groupTag = "another"
        XCTAssertThrowsError(try g.evidence(device: phone, chain: [e.chain[0]], other, rootSigner: ca, now: now, roots: [e.root]))
        // Google revokes the attestation key: the phone's keys count as only
        // in hardware.
        let challenge = try Attestation.challenge(groupTag: "", memberKey: Data(), salt: e.salt)
        let spki = try CertificateInfo(der: e.chain[0]).publicKey
        let serials = try AndroidAttestation.check(chain: e.chain, spki: spki, challenge: challenge,
                                                   policy: AndroidAttestation.Policy(roots: [e.root])).serials
        let revoked: Set<String> = [serials[1]]
        XCTAssertNotNil(try g.evidence(device: phone, chain: [e.chain[0]], evidence, rootSigner: ca, now: now.addingTimeInterval(4),
                                       roots: [e.root], revoked: revoked))
        let after = try XCTUnwrap(g.devices.first { $0.id == phone })
        XCTAssertEqual(after.store, Records.hardware)
        XCTAssertEqual(after.kind, AndroidAttestation.kindTEE)
        XCTAssertNil(after.proof)
        XCTAssertNil(try g.evidence(device: phone, chain: [e.chain[0]], evidence, rootSigner: ca, now: now.addingTimeInterval(5),
                                    roots: [e.root], revoked: revoked))
    }
}
