// SPDX-License-Identifier: AGPL-3.0-only

@testable import CBBKit
import Foundation
import XCTest

final class RecordsTests: XCTestCase {
    /// A phone's group with a computer, then the computer removed.
    func makeGroup() throws -> (PhoneGroup, SoftwareSigner, String) {
        let now = Date()
        let ca = SoftwareSigner()
        var g = try PhoneGroup.create(caSigner: ca, memberKey: SoftwareSigner().publicKeyDER, name: "My\u{7}iPhone", now: now)
        let pc = Member.newID()
        let cert = try GroupCertificates.member(device: pc, publicKey: SoftwareSigner().publicKeyDER, ca: g.groupCA, caSigner: ca, now: now)
        g.computers.append(.init(device: pc, name: "pi", os: "linux", cert: cert, admitted: now))
        _ = try g.record(device: pc, name: "pi", role: "member", caps: Records.caps, key: Records.keyHash(cert: cert), caSigner: ca, now: now)
        return (g, ca, pc)
    }

    func testDevicesAndRevoke() throws {
        var (g, ca, pc) = try makeGroup()
        XCTAssertEqual(g.devices.map(\.name), ["MyiPhone", "pi"])
        XCTAssertEqual(g.devices.first { $0.id == g.device }?.role, "phone")
        let digest = g.records.digest
        XCTAssertNotNil(digest)
        XCTAssertThrowsError(try g.revoke(device: g.device, caSigner: ca, now: Date()))
        XCTAssertThrowsError(try g.revoke(device: Member.newID(), caSigner: ca, now: Date()))
        _ = try g.revoke(device: pc, caSigner: ca, now: Date())
        XCTAssertEqual(g.devices.map(\.id), [g.device])
        XCTAssertTrue(g.computers.isEmpty)
        XCTAssertNotEqual(g.records.digest, digest)
    }

    /// A device ID whose records name two keys stays listed while either is
    /// not revoked, and removing it revokes both, as Go's
    /// TestDeviceWithTwoKeys.
    func testDeviceWithTwoKeys() throws {
        var (g, ca, pc) = try makeGroup()
        let second = try GroupCertificates.member(device: pc, publicKey: SoftwareSigner().publicKeyDER, ca: g.groupCA, caSigner: ca,
                                                  now: Date().addingTimeInterval(1))
        _ = try g.record(device: pc, name: "pi", role: "member", caps: Records.caps, key: Records.keyHash(cert: second), caSigner: ca, now: Date().addingTimeInterval(1))
        XCTAssertTrue(g.records.knows(pc))
        XCTAssertEqual(g.devices.first { $0.id == pc }?.keys.count, 2)
        _ = try g.revoke(device: pc, caSigner: ca, now: Date())
        XCTAssertEqual(g.devices.map(\.id), [g.device])
    }

    func testRefused() throws {
        let (g, _, _) = try makeGroup()
        var set = RecordSet()
        let good = try XCTUnwrap(g.records.records.first { String(decoding: $0.body, as: UTF8.self).contains(#""role":"phone""#) })
        var forged = good
        forged.sig = Data(forged.sig.reversed())
        var tampered = good
        tampered.body = Data(String(decoding: good.body, as: UTF8.self).replacingOccurrences(of: "phone", with: "full").utf8)
        var chained = good
        chained.chain = [Data([1])]
        for (name, r) in [("forged", forged), ("tampered", tampered), ("chained", chained)] {
            XCTAssertFalse(set.add(r, groupCA: g.groupCA), name)
        }
        let other = try PhoneGroup.create(caSigner: SoftwareSigner(), memberKey: SoftwareSigner().publicKeyDER, now: Date())
        var otherSet = RecordSet()
        XCTAssertFalse(otherSet.add(good, groupCA: other.groupCA), "a record of another group")
        XCTAssertTrue(set.add(good, groupCA: g.groupCA))
        XCTAssertFalse(set.add(good, groupCA: g.groupCA), "a known record is not new")
    }

    /// Writes signed records for the Go side (internal/group,
    /// TestSwiftRecords) when CBB_INTEROP_OUT names a directory, as
    /// CI does; testdata/interop keeps a copy for local runs.
    func testRecordsForGo() throws {
        guard let dir = ProcessInfo.processInfo.environment["CBB_INTEROP_OUT"] else { return }
        var (g, ca, pc) = try makeGroup()
        _ = try g.revoke(device: pc, caSigner: ca, now: Date())
        struct Out: Encodable {
            var group_ca: Data
            var records: [Member.Record]
            var digest: String
            var devices: [String]
            var revoked: [Data]
        }
        let out = Out(group_ca: g.groupCA, records: g.records.records, digest: g.records.digest!,
                      devices: g.devices.map(\.id), revoked: Array(g.records.revoked))
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        try (enc.encode(out) + Data("\n".utf8)).write(to: URL(fileURLWithPath: dir).appendingPathComponent("swift-records.json"))
    }

    /// Records the app's root key signs go to the connected peers at once,
    /// and a peer's app reads them from its member.
    func testNodesExchangeRecords() async throws {
        var t = try CoreGroup(test: self)
        let (phone, peer) = (t.phones[0], t.phones[1])
        try await t.connect(1, to: 0)
        XCTAssertEqual(Set(try peer.member.records().map(\.body)), Set(t.g.records.records.map(\.body)))
        let r = try t.g.rename(device: peer.device, to: "Kitchen phone", caSigner: t.ca, now: Date())
        try phone.member.addRecords([r])
        try await peer.until("the new record") { try peer.member.records().contains(r) }
        var set = RecordSet()
        _ = set.addAll(try peer.member.records(), groupCA: t.g.groupCA)
        XCTAssertEqual(set.devices.first { $0.id == peer.device }?.name, "Kitchen phone")
        XCTAssertEqual(phone.member.connected(), [peer.device])
    }
}
