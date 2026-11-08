// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

#if canImport(Network)
@testable import CBBKit
import Foundation
import XCTest

/// Making a group, joining it and admitting a device through the Rust core
/// (CorePairing), as the apps do.
final class CorePairingTests: XCTestCase {
    /// A root phone: the group the core made with its root key, and its
    /// member running.
    struct Root {
        let root: SoftwareSigner
        let group: PhoneGroup
        let member: CoreMember
    }

    func root() throws -> Root {
        let root = SoftwareSigner(), key = SoftwareSigner()
        let made = try CorePairing.newGroup(name: "Root phone", store: Records.hardware, rootPublic: root.publicKeyDER, publicKey: key.publicKeyDER,
                                            seal: try Core.sealPublic(CoreGroup.seal)) { try root.signature(digest: $0) }
        let g = PhoneGroup.of(made, root: true)
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("cbb-core-pairing-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: dir) }
        let m = try CoreMember(.init(dir: dir, name: "Root phone", device: g.device, publicKeyDER: key.publicKeyDER, seal: CoreGroup.seal,
                                     cert: g.memberCert, issuer: nil, groupCA: g.groupCA, roots: g.trusted)) { try key.signature(digest: $0) }
        addTeardownBlock { m.stop() }
        try m.addRecords(g.records.records)
        return Root(root: root, group: g, member: m)
    }

    func testNewGroupHasTheRootAndItsPhone() throws {
        let r = try root()
        XCTAssertTrue(r.group.isRoot)
        XCTAssertNil(r.group.adminCA)
        XCTAssertEqual(r.group.devices.map(\.id), [r.group.device])
        XCTAssertEqual(r.group.devices.first?.role, "phone")
        // The member certificate comes from the group's root, whose key signed it.
        XCTAssertEqual(try CertificateInfo(der: r.group.groupCA).publicKey, r.root.publicKeyDER)
    }

    private final class Saved: @unchecked Sendable {
        let lock = NSLock()
        var groups: [CorePairing.Group] = []
    }

    /// A phone listens with its QR code, the root scans it and admits it;
    /// with offer, it asks to be an admin, which makeAdmin grants.
    func joinAndAdmit(_ r: Root, code: String = "", typed: String? = nil, offer: Bool = false, makeAdmin: Bool = false) async throws
        -> (Result<CorePairing.Group, Error>, Result<CorePairing.Admitted, Error>) {
        let listener = try CorePairing.Listener(loopback: true)
        let port = try await listener.start()
        let key = SoftwareSigner()
        let admin = offer ? SoftwareSigner() : nil
        let joining = try CorePairing.Joining(name: "Second phone", publicKey: key.publicKeyDER, seal: try Core.sealPublic(CoreGroup.seal),
                                              addrs: ["127.0.0.1:\(port)"], sign: { try key.signature(digest: $0) },
                                              adminPublic: admin?.publicKeyDER, signAdmin: admin.map { a in { try a.signature(digest: $0) } },
                                              code: code)
        let saved = Saved()
        let joined = Task { () throws -> CorePairing.Group in
            defer { listener.stop() }
            guard let c = await listener.next() else { throw CorePairing.Closed() }
            defer { c.close() }
            return try await joining.attempt(c) { g in
                saved.lock.withLock { saved.groups.append(g) }
                return true
            }
        }
        // The QR code a user scanned; a test that types another code changes it there.
        let qr = typed.map { joining.qr.replacingOccurrences(of: "code=\(joining.code)", with: "code=\($0)") } ?? joining.qr
        let admitted: Result<CorePairing.Admitted, Error>
        do {
            let a = try CorePairing.Admitting(member: r.member, qr: qr, publicKey: r.root.publicKeyDER, adminCA: nil, makeAdmin: makeAdmin) {
                try r.root.signature(digest: $0)
            }
            defer { a.close() }
            let addr = try XCTUnwrap(a.addrs.first)
            let (host, p) = try XCTUnwrap(JoinCode.split(addr))
            let c = CorePairing.Connection(host: host, port: p)
            defer { c.close() }
            try await c.start()
            admitted = .success(try await a.admit(c))
        } catch {
            admitted = .failure(error)
        }
        // A joiner that failed waits for another connection: the listener's end stops it.
        let stop = Task {
            try await Task.sleep(for: .seconds(5))
            listener.stop()
        }
        let j = await joined.result
        stop.cancel()
        joining.close()
        if case let .success(g) = j { XCTAssertEqual(saved.lock.withLock { saved.groups.map(\.device) }, [g.device]) }
        return (j, admitted)
    }

    func testRootAdmitsAPhoneThatListens() async throws {
        let r = try root()
        let (j, a) = try await joinAndAdmit(r)
        let group = try j.get(), admitted = try a.get()
        XCTAssertEqual(admitted.device, group.device)
        XCTAssertEqual(admitted.name, "Second phone")
        XCTAssertEqual(admitted.role, "phone")
        XCTAssertTrue(admitted.confirmed, "the joiner said it stored its identity")
        XCTAssertFalse(admitted.admin)
        let p = PhoneGroup.of(group, root: false)
        XCTAssertEqual(p.groupCA, r.group.groupCA)
        XCTAssertFalse(p.isRoot)
        XCTAssertNil(p.adminCA)
        // The joiner's certificate names it and comes from the group's root.
        XCTAssertEqual(try CertificateInfo(der: group.cert).commonName, group.device)
        // Its record is in the root's member at once, and in the records the joiner took.
        var rs = RecordSet.fromFile(groupCA: r.group.groupCA, file: Data())
        _ = rs.addAll(try r.member.records(), groupCA: r.group.groupCA)
        XCTAssertTrue(rs.devices.contains { $0.id == group.device && $0.role == "phone" }, "the root's records list the new phone")
        XCTAssertTrue(p.devices.contains { $0.id == r.group.device }, "the joiner's records list the root phone")
    }

    func testRootMakesAPhoneThatAsksAnAdmin() async throws {
        let r = try root()
        let (j, a) = try await joinAndAdmit(r, offer: true, makeAdmin: true)
        let group = try j.get()
        XCTAssertTrue(try a.get().admin)
        let ca = try XCTUnwrap(group.adminCA, "the joiner got its admin CA")
        let p = PhoneGroup.of(group, root: false)
        XCTAssertTrue(p.isAdmin)
        XCTAssertEqual(p.adminCA, ca)
    }

    /// A phone that asks to be an admin joins only where the root chose to
    /// make one (docs/protocol.md, section 6).
    func testAPhoneThatAsksIsRefusedWithoutMakeAdmin() async throws {
        let r = try root()
        let (j, a) = try await joinAndAdmit(r, offer: true, makeAdmin: false)
        XCTAssertThrowsError(try a.get()) { e in
            let f = e as? CorePairing.Failure
            XCTAssertTrue(f?.message.contains("add it as an admin") == true, "\(e)")
        }
        XCTAssertThrowsError(try j.get(), "the phone did not join")
    }

    func testAWrongCodeFailsBothSides() async throws {
        let r = try root()
        let (j, a) = try await joinAndAdmit(r, code: "123456", typed: "654321")
        XCTAssertThrowsError(try a.get()) { e in
            XCTAssertTrue((e as? CorePairing.Failure)?.wrongCode == true, "the admin's side says the code was wrong: \(e)")
        }
        XCTAssertThrowsError(try j.get(), "the joiner did not join")
        // Nothing reached the records.
        var rs = RecordSet.fromFile(groupCA: r.group.groupCA, file: Data())
        _ = rs.addAll(try r.member.records(), groupCA: r.group.groupCA)
        XCTAssertEqual(rs.devices.map(\.id), [r.group.device])
    }
}
#endif
