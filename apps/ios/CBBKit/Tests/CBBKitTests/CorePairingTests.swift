// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

#if canImport(Network)
@testable import CBBKit
import Foundation
import XCTest

/// Making a group through the Rust core (CorePairing), as the apps do;
/// joining by a pairing window is in the window's tests.
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
}
#endif
