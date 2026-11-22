// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

#if canImport(Network)
@testable import CBBKit
import Foundation
import XCTest

/// Making a group through the Rust core (CorePairing), as the apps do;
/// joining by a pairing window is in the window's tests.
final class CorePairingTests: XCTestCase {
    func testNewGroupHasTheRootAndItsPhone() throws {
        let root = SoftwareSigner(), key = SoftwareSigner()
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("cbb-core-pairing-\(UUID().uuidString)")
        addTeardownBlock { try? FileManager.default.removeItem(at: dir) }
        let made = try CorePairing.newGroup(dir: dir, name: "Root phone", store: Records.hardware, rootPublic: root.publicKeyDER,
                                            publicKey: key.publicKeyDER) { try root.signature(digest: $0) }
        let m = try CoreMember(.init(dir: dir, name: "Root phone", device: made.device, publicKeyDER: key.publicKeyDER)) {
            try key.signature(digest: $0)
        }
        addTeardownBlock { m.stop() }
        let g = try m.group()
        XCTAssertEqual(g.rootDevice, made.device)
        XCTAssertTrue(g.isRoot)
        XCTAssertEqual(g.devices.map(\.device), [made.device])
        XCTAssertEqual(g.devices.first?.role, "phone")
        XCTAssertEqual(g.keyLevel, Records.hardware)
    }
}
#endif
