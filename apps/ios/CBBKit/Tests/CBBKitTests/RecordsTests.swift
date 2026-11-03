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
        let pc = SyncEngine.newID()
        let cert = try GroupCertificates.member(device: pc, publicKey: SoftwareSigner().publicKeyDER, ca: g.groupCA, caSigner: ca, now: now)
        g.computers.append(.init(device: pc, name: "pi", os: "linux", cert: cert, admitted: now))
        _ = try g.record(device: pc, name: "pi", role: "full", key: Records.keyHash(cert: cert), caSigner: ca, now: now)
        return (g, ca, pc)
    }

    func testDevicesAndRevoke() throws {
        var (g, ca, pc) = try makeGroup()
        XCTAssertEqual(g.devices.map(\.name), ["MyiPhone", "pi"])
        XCTAssertEqual(g.devices.first { $0.id == g.device }?.role, "phone")
        let digest = g.records.digest
        XCTAssertNotNil(digest)
        XCTAssertThrowsError(try g.revoke(device: g.device, caSigner: ca, now: Date()))
        XCTAssertThrowsError(try g.revoke(device: SyncEngine.newID(), caSigner: ca, now: Date()))
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
        _ = try g.record(device: pc, name: "pi", role: "full", key: Records.keyHash(cert: second), caSigner: ca, now: Date().addingTimeInterval(1))
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

    /// A RecordStore over a RecordSet.
    final class Store: RecordStore, @unchecked Sendable {
        let lock = NSLock()
        var set = RecordSet()
        let groupCA: Data
        init(groupCA: Data, set: RecordSet = RecordSet()) { (self.groupCA, self.set) = (groupCA, set) }
        var digest: String? { lock.withLock { set.digest } }
        var all: [Member.Record] { lock.withLock { set.records } }
        func add(_ rs: [Member.Record]) -> [Member.Record] {
            lock.withLock { rs.filter { set.add($0, groupCA: groupCA) } }
        }
    }

    func testNodesExchangeRecords() async throws {
        var (g, ca, pc) = try makeGroup()
        let phoneStore = Store(groupCA: g.groupCA, set: g.records)
        let peerStore = Store(groupCA: g.groupCA)
        let phone = MemberNode(engine: SyncEngine(device: g.device, clock: HybridClock()), name: "iPhone", records: phoneStore)
        let peer = MemberNode(engine: SyncEngine(device: pc, clock: HybridClock()), name: "pi", role: .full, records: peerStore)
        let (a, b) = Pipe.pair()
        let ta = Task { try await phone.serve(a, peer: pc) }
        let tb = Task { try await peer.serve(b) }
        // The hello's digest differs, so the phone sends its records.
        for _ in 0..<200 where peerStore.digest != phoneStore.digest { try await Task.sleep(nanoseconds: 10_000_000) }
        XCTAssertEqual(peerStore.digest, phoneStore.digest)
        // A revocation made later is sent at once.
        let r = try g.revoke(device: pc, caSigner: ca, now: Date())
        _ = phoneStore.add([r])
        await phone.sendRecords([r])
        for _ in 0..<200 where peerStore.digest != phoneStore.digest { try await Task.sleep(nanoseconds: 10_000_000) }
        XCTAssertEqual(peerStore.set.revoked.count, 1)
        let connected = await phone.connected
        XCTAssertEqual(connected, [pc])
        await phone.close(peer: pc)
        try await ta.value
        try await tb.value
    }
}
