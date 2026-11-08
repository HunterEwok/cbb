// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 HunterEwok

@testable import CBBKit
import XCTest

final class HubKindTests: XCTestCase {
    /// A computer that only passes the copies on may be a hub, and no copy
    /// is sealed to it from then on; an admin cannot be one.
    func testForwardOnlyHub() throws {
        let now = Date()
        let ca = SoftwareSigner(), ka = SoftwareSigner(), kb = SoftwareSigner()
        let sa = Data((0..<32).map { _ in UInt8.random(in: 0...255) }), sb = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        var g = try PhoneGroup.create(caSigner: ca, memberKey: ka.publicKeyDER, seal: try Core.sealPublic(sa), now: now)
        let pc = Member.newID()
        _ = try g.record(device: pc, name: "pi", role: "member", caps: Records.caps, os: "linux", key: Records.keyHash(spki: kb.publicKeyDER),
                         store: Records.file, seal: try Core.sealPublic(sb), caSigner: ca, now: now)
        XCTAssertFalse(g.records.mayHost(pc))
        let set = { g.records }
        let keys = CopyKeys(device: g.device, cert: g.memberCert, issuer: nil, signer: ka, secret: sa, records: set)
        let e = Member.Event(id: Member.newID(), origin: g.device, time: HybridClock().now(), kind: .text, text: "before")
        XCTAssertTrue(try keys.seal(e, key: nil, blob: nil).wraps.contains { $0.to == pc })

        XCTAssertNotNil(try g.markForwardOnly(device: pc, caSigner: ca, now: now))
        XCTAssertEqual(g.devices.first { $0.id == pc }?.forwardOnly, true)
        XCTAssertTrue(g.records.mayHost(pc))
        XCTAssertNil(try g.markForwardOnly(device: pc, caSigner: ca, now: now))
        let after = CopyKeys(device: g.device, cert: g.memberCert, issuer: nil, signer: ka, secret: sa, records: { g.records })
        XCTAssertFalse(try after.seal(e, key: nil, blob: nil).wraps.contains { $0.to == pc })
        // A rename keeps it.
        _ = try g.rename(device: pc, to: "router", caSigner: ca, now: now)
        XCTAssertEqual(g.devices.first { $0.id == pc }?.forwardOnly, true)
        // The root's own device reads the copies.
        XCTAssertThrowsError(try g.markForwardOnly(device: g.device, caSigner: ca, now: now))
    }
}
